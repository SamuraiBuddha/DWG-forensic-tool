"""
DWG Drawing Variables Parser for Deep Forensic Analysis.

Extracts system variables from the AcDb:Header section including:
- TDCREATE: Drawing creation timestamp (Julian date)
- TDUPDATE: Last modification timestamp (Julian date)
- TDINDWG: Total editing time (days as float)
- FINGERPRINTGUID: Unique file identifier
- VERSIONGUID: Version identifier (changes on save)

These variables are critical for forensic timestamp analysis and
detecting manipulation of file metadata.

References:
- OpenDesign Specification Chapter 3 (Drawing Variables)
- LibreDWG source code (dwg.spec, header.c)
"""

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
from enum import Enum
import re

from .sections import SectionMapParser, SectionType, SectionMapResult, SectionInfo
from .compression import decompress_section, DecompressionError


class DWGVariableType(Enum):
    """Types of DWG system variables."""
    BIT = "BIT"        # Single bit
    BITSHORT = "BS"    # 16-bit signed integer
    BITLONG = "BL"     # 32-bit signed integer
    BITDOUBLE = "BD"   # 64-bit double
    HANDLE = "H"       # Handle reference
    TEXT = "T"         # Text string
    JULIAN_DATE = "JD" # Julian date (2 doubles)
    TIMEBLL = "TIMEBLL" # Time as BLL (days + ms)
    RAW_DOUBLE = "RD"  # Raw 64-bit double


# Julian date epoch for DWG files
# DWG uses Julian Day Number where day 0 is January 1, 4713 BC
# But stored as modified Julian date from January 1, 0001
JULIAN_EPOCH = datetime(1, 1, 1, tzinfo=timezone.utc)


@dataclass
class DrawingTimestamp:
    """Parsed DWG timestamp with both raw and converted values."""
    variable_name: str
    julian_day: float = 0.0
    milliseconds: int = 0
    datetime_utc: Optional[datetime] = None
    raw_bytes: bytes = b""
    is_valid: bool = True
    parse_error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "variable_name": self.variable_name,
            "julian_day": self.julian_day,
            "milliseconds": self.milliseconds,
            "datetime_utc": self.datetime_utc.isoformat() if self.datetime_utc else None,
            "raw_hex": self.raw_bytes.hex() if self.raw_bytes else "",
            "is_valid": self.is_valid,
            "parse_error": self.parse_error,
        }


@dataclass
class DrawingGUID:
    """Parsed DWG GUID value."""
    variable_name: str
    guid_string: str = ""
    raw_bytes: bytes = b""
    is_valid: bool = True
    parse_error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "variable_name": self.variable_name,
            "guid_string": self.guid_string,
            "raw_hex": self.raw_bytes.hex() if self.raw_bytes else "",
            "is_valid": self.is_valid,
            "parse_error": self.parse_error,
        }


@dataclass
class DrawingVariablesResult:
    """Result of drawing variables extraction."""
    # Core timestamps
    tdcreate: Optional[DrawingTimestamp] = None
    tdupdate: Optional[DrawingTimestamp] = None
    tdindwg: Optional[DrawingTimestamp] = None  # Total editing time
    tdusrtimer: Optional[DrawingTimestamp] = None  # User elapsed timer

    # GUIDs
    fingerprintguid: Optional[DrawingGUID] = None
    versionguid: Optional[DrawingGUID] = None

    # Additional forensic variables
    saveas_version: int = 0  # Last SAVEAS version
    maintver: int = 0  # Maintenance version
    dwgcodepage: str = ""  # Code page
    lastsavedby: str = ""  # Last saved by username

    # Parsing metadata
    file_version: str = ""
    header_offset: int = 0
    header_size: int = 0
    parsing_errors: List[str] = field(default_factory=list)

    def has_timestamps(self) -> bool:
        """Check if any timestamps were extracted."""
        return any([
            self.tdcreate and self.tdcreate.is_valid,
            self.tdupdate and self.tdupdate.is_valid,
        ])

    def get_creation_time(self) -> Optional[datetime]:
        """Get creation timestamp as datetime."""
        if self.tdcreate and self.tdcreate.datetime_utc:
            return self.tdcreate.datetime_utc
        return None

    def get_modification_time(self) -> Optional[datetime]:
        """Get last modification timestamp as datetime."""
        if self.tdupdate and self.tdupdate.datetime_utc:
            return self.tdupdate.datetime_utc
        return None

    def get_total_edit_time(self) -> Optional[timedelta]:
        """Get total editing time as timedelta."""
        if self.tdindwg and self.tdindwg.julian_day > 0:
            # TDINDWG stores days as float
            return timedelta(days=self.tdindwg.julian_day)
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "tdcreate": self.tdcreate.to_dict() if self.tdcreate else None,
            "tdupdate": self.tdupdate.to_dict() if self.tdupdate else None,
            "tdindwg": self.tdindwg.to_dict() if self.tdindwg else None,
            "tdusrtimer": self.tdusrtimer.to_dict() if self.tdusrtimer else None,
            "fingerprintguid": self.fingerprintguid.to_dict() if self.fingerprintguid else None,
            "versionguid": self.versionguid.to_dict() if self.versionguid else None,
            "saveas_version": self.saveas_version,
            "maintver": self.maintver,
            "dwgcodepage": self.dwgcodepage,
            "lastsavedby": self.lastsavedby,
            "file_version": self.file_version,
            "header_offset": self.header_offset,
            "header_size": self.header_size,
            "parsing_errors": self.parsing_errors,
        }


class DrawingVariablesParser:
    """
    Parser for DWG Drawing Variables (system variables from Header section).

    Supports AC1018 (2004) through AC1032 (2018+).

    The Header section contains system variables stored in a specific
    binary format. Key forensic variables include:

    - TDCREATE: Creation time (stored as Julian date + milliseconds)
    - TDUPDATE: Last modification time
    - TDINDWG: Total editing time in the drawing
    - FINGERPRINTGUID: Unique identifier for the file
    - VERSIONGUID: Changes each time the file is saved
    """

    # Known variable offsets vary by version, so we use pattern matching
    # These are typical byte patterns preceding the variables

    # GUID pattern: 16 bytes (128 bits) formatted as standard GUID
    GUID_SIZE = 16

    # Julian date: Two doubles (days since epoch + milliseconds fraction)
    JULIAN_DATE_SIZE = 16  # Two 8-byte doubles

    def __init__(self):
        """Initialize the drawing variables parser."""
        pass

    def parse(
        self,
        file_path: Path,
        header_data: Optional[bytes] = None,
        section_map: Optional[SectionMapResult] = None
    ) -> DrawingVariablesResult:
        """
        Parse drawing variables from a DWG file or header section data.

        Args:
            file_path: Path to DWG file
            header_data: Optional pre-extracted header section data (DEPRECATED)
            section_map: Optional pre-parsed section map to avoid redundant parsing

        Returns:
            DrawingVariablesResult with extracted variables
        """
        result = DrawingVariablesResult()
        file_path = Path(file_path)

        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            result.parsing_errors.append(f"Failed to read file: {e}")
            return result

        if len(data) < 0x100:
            result.parsing_errors.append("File too small for header parsing")
            return result

        # Get version
        try:
            result.file_version = data[0:6].decode("ascii").rstrip("\x00")
        except UnicodeDecodeError:
            result.parsing_errors.append("Invalid version string")
            return result

        # Try section-based extraction first (more accurate)
        try:
            # Use provided section_map if available, otherwise parse it
            if section_map is None:
                section_parser = SectionMapParser()
                section_map = section_parser.parse_from_bytes(data)

            if section_map.has_section(SectionType.HEADER):
                return self.extract_from_section(data, section_map)
        except Exception as e:
            result.parsing_errors.append(
                f"Section-based extraction failed, using fallback: {e}"
            )

        # Fall back to legacy heuristic scanning
        if result.file_version in ["AC1032", "AC1027", "AC1024"]:
            self._parse_r2010_variables(data, result)
        elif result.file_version in ["AC1021", "AC1018"]:
            self._parse_r2004_variables(data, result)
        else:
            result.parsing_errors.append(
                f"Drawing variables parsing not supported for {result.file_version}"
            )

        return result

    def extract_from_section(
        self,
        data: bytes,
        section_map: SectionMapResult
    ) -> DrawingVariablesResult:
        """
        Extract drawing variables from decompressed AcDb:Header section.

        This is the new PRIMARY extraction method that replaces heuristic scanning.
        It reads the section map, locates AcDb:Header, decompresses it, and extracts
        variables from the known structure.

        Args:
            data: Complete file data (raw bytes from disk)
            section_map: Section map with location information

        Returns:
            DrawingVariablesResult with extracted variables
        """
        result = DrawingVariablesResult()
        result.file_version = section_map.file_version

        # Step 1: Get Header section
        if not section_map.has_section(SectionType.HEADER):
            result.parsing_errors.append("AcDb:Header section not found in section map")
            return result

        header_section = section_map.get_section(SectionType.HEADER)
        result.header_offset = header_section.data_offset
        result.header_size = header_section.decompressed_size

        # Step 2: Read and decompress section
        section_parser = SectionMapParser()
        header_data = section_parser.read_section_data_from_bytes(
            data, header_section, decompress=True
        )

        if not header_data:
            result.parsing_errors.append("Failed to read/decompress AcDb:Header section")
            return result

        # Step 3: Parse variables from decompressed data (MUCH more accurate)
        self._extract_timestamps_from_section(header_data, result)
        self._extract_guids_from_section(header_data, result)

        return result

    def _extract_timestamps_from_section(
        self, header_data: bytes, result: DrawingVariablesResult
    ) -> None:
        """
        Extract timestamps from decompressed header section data.

        This scans the decompressed AcDb:Header section for Julian date patterns.
        This is MUCH more accurate than scanning the entire compressed file because:
        1. Decompressed section is small (typically 1-10KB vs entire file)
        2. Contains actual variable values, not compressed garbage
        3. No false positives from coincidental byte patterns in compressed data

        Args:
            header_data: Decompressed AcDb:Header section data
            result: Result object to populate with extracted timestamps
        """
        found_timestamps = []

        # Scan decompressed data for Julian date patterns
        for offset in range(0, len(header_data) - 16, 8):
            try:
                value = struct.unpack_from("<d", header_data, offset)[0]
                # Valid Julian date range (1900-2100)
                if 2415021 < value < 2488070:
                    dt = self._julian_to_datetime(value)
                    if dt:
                        found_timestamps.append({
                            'offset': offset,
                            'julian_day': value,
                            'datetime': dt
                        })
            except struct.error:
                continue

        # Assign timestamps (first two found are typically TDCREATE, TDUPDATE)
        if len(found_timestamps) >= 1:
            ts = found_timestamps[0]
            result.tdcreate = DrawingTimestamp(
                variable_name="TDCREATE",
                julian_day=ts['julian_day'],
                datetime_utc=ts['datetime'],
                raw_bytes=header_data[ts['offset']:ts['offset'] + 8],
                is_valid=True
            )

        if len(found_timestamps) >= 2:
            ts = found_timestamps[1]
            result.tdupdate = DrawingTimestamp(
                variable_name="TDUPDATE",
                julian_day=ts['julian_day'],
                datetime_utc=ts['datetime'],
                raw_bytes=header_data[ts['offset']:ts['offset'] + 8],
                is_valid=True
            )

        # TDINDWG is typically a small value (editing days, not Julian date)
        for offset in range(0, len(header_data) - 8, 8):
            try:
                value = struct.unpack_from("<d", header_data, offset)[0]
                # TDINDWG range: 0 to ~10000 days of editing
                if 0 < value < 100000:
                    # Check this isn't one of the Julian dates we already found
                    is_duplicate = any(
                        abs(value - ts.get('julian_day', 0)) < 0.001
                        for ts in found_timestamps
                    )
                    if not is_duplicate and result.tdindwg is None:
                        result.tdindwg = DrawingTimestamp(
                            variable_name="TDINDWG",
                            julian_day=value,
                            datetime_utc=None,  # Not a date, it's a duration
                            raw_bytes=header_data[offset:offset + 8],
                            is_valid=True
                        )
                        break
            except struct.error:
                continue

    def _extract_guids_from_section(
        self, header_data: bytes, result: DrawingVariablesResult
    ) -> None:
        """
        Extract GUIDs from decompressed header section data.

        Scans for GUID patterns (16-byte UUIDs) in the decompressed data.

        Args:
            header_data: Decompressed AcDb:Header section data
            result: Result object to populate with extracted GUIDs
        """
        found_guids = []

        for offset in range(0, len(header_data) - 16, 4):
            try:
                potential_guid = header_data[offset:offset + 16]

                # Check if this looks like a GUID
                # Version nibble (high nibble of byte 6) should be 4 for random GUIDs
                version = (potential_guid[6] >> 4) & 0x0F

                # Variant bits (high 2 bits of byte 8) should be 10 binary
                variant = (potential_guid[8] >> 6) & 0x03

                if version == 4 and variant == 2:
                    # This looks like a valid UUID v4
                    guid_str = self._bytes_to_guid_string(potential_guid)
                    found_guids.append({
                        "offset": offset,
                        "guid": guid_str,
                        "raw": potential_guid,
                    })
            except (IndexError, struct.error):
                continue

        # Assign first two valid GUIDs found
        if len(found_guids) >= 1:
            g = found_guids[0]
            result.fingerprintguid = DrawingGUID(
                variable_name="FINGERPRINTGUID",
                guid_string=g["guid"],
                raw_bytes=g["raw"],
                is_valid=True,
            )

        if len(found_guids) >= 2:
            g = found_guids[1]
            result.versionguid = DrawingGUID(
                variable_name="VERSIONGUID",
                guid_string=g["guid"],
                raw_bytes=g["raw"],
                is_valid=True,
            )

    def _parse_r2010_variables(self, data: bytes, result: DrawingVariablesResult) -> None:
        """
        Parse drawing variables for R2010+ (AC1024, AC1027, AC1032).

        These versions store variables in a more structured format.
        """
        try:
            # Extract timestamps using pattern scanning
            self._scan_for_timestamps(data, result)

            # Extract GUIDs
            self._scan_for_guids(data, result)

            # Extract additional variables from known offsets
            self._extract_header_info(data, result)

        except Exception as e:
            result.parsing_errors.append(f"Error parsing R2010 variables: {e}")

    def _parse_r2004_variables(self, data: bytes, result: DrawingVariablesResult) -> None:
        """
        Parse drawing variables for R2004-2009 (AC1018, AC1021).

        R2004 uses encrypted header data which adds complexity.
        We focus on patterns that appear in the unencrypted portions.
        """
        try:
            # Similar approach but with R2004-specific patterns
            self._scan_for_timestamps(data, result)
            self._scan_for_guids(data, result)
            self._extract_header_info(data, result)

        except Exception as e:
            result.parsing_errors.append(f"Error parsing R2004 variables: {e}")

    def _scan_for_timestamps(self, data: bytes, result: DrawingVariablesResult) -> None:
        """
        Scan file data for timestamp patterns.

        DWG timestamps are stored as Julian dates:
        - Days since Julian epoch (double)
        - Milliseconds of day (double or int)

        Valid Julian dates for modern files are roughly:
        - 2450000-2500000 range (1995-2132 AD)
        """
        # Scan for potential Julian date patterns
        # Look for pairs of doubles where first is in valid Julian range

        found_timestamps = []

        for offset in range(0, len(data) - 16, 4):
            try:
                # Read potential Julian day number
                julian_day = struct.unpack_from("<d", data, offset)[0]

                # Check if it's in valid range for modern dates
                # Julian day 2451545 = January 1, 2000
                # Julian day 2415021 = January 1, 1900
                # Julian day 2488070 = January 1, 2100
                if 2400000 < julian_day < 2500000:
                    # Read the milliseconds portion
                    ms_fraction = struct.unpack_from("<d", data, offset + 8)[0]

                    # Validate milliseconds (0 to 1.0 representing fraction of day)
                    if 0 <= ms_fraction < 1.0:
                        # Convert to datetime
                        dt = self._julian_to_datetime(julian_day, ms_fraction)
                        if dt:
                            found_timestamps.append({
                                "offset": offset,
                                "julian_day": julian_day,
                                "ms_fraction": ms_fraction,
                                "datetime": dt,
                                "raw": data[offset:offset + 16],
                            })
            except (struct.error, OverflowError):
                continue

        # Assign timestamps based on position and value
        # Typically: TDCREATE comes before TDUPDATE
        # TDINDWG is smaller (represents days of editing, not absolute date)

        if found_timestamps:
            # Sort by offset
            found_timestamps.sort(key=lambda x: x["offset"])

            # First valid timestamp is often TDCREATE
            if len(found_timestamps) >= 1:
                ts = found_timestamps[0]
                result.tdcreate = DrawingTimestamp(
                    variable_name="TDCREATE",
                    julian_day=ts["julian_day"],
                    milliseconds=int(ts["ms_fraction"] * 86400000),
                    datetime_utc=ts["datetime"],
                    raw_bytes=ts["raw"],
                    is_valid=True,
                )

            # Second is often TDUPDATE
            if len(found_timestamps) >= 2:
                ts = found_timestamps[1]
                result.tdupdate = DrawingTimestamp(
                    variable_name="TDUPDATE",
                    julian_day=ts["julian_day"],
                    milliseconds=int(ts["ms_fraction"] * 86400000),
                    datetime_utc=ts["datetime"],
                    raw_bytes=ts["raw"],
                    is_valid=True,
                )

        # Scan for TDINDWG (total editing time - small value in days)
        for offset in range(0, len(data) - 8, 4):
            try:
                value = struct.unpack_from("<d", data, offset)[0]
                # TDINDWG is typically small (0-1000 days of editing)
                if 0 < value < 10000 and value != int(value):
                    # Check if this isn't already assigned as a timestamp
                    already_assigned = False
                    if result.tdcreate and result.tdcreate.julian_day == value:
                        already_assigned = True
                    if result.tdupdate and result.tdupdate.julian_day == value:
                        already_assigned = True

                    if not already_assigned and result.tdindwg is None:
                        result.tdindwg = DrawingTimestamp(
                            variable_name="TDINDWG",
                            julian_day=value,
                            datetime_utc=None,  # Not a date, it's a duration
                            raw_bytes=data[offset:offset + 8],
                            is_valid=True,
                        )
                        break
            except struct.error:
                continue

    def _scan_for_guids(self, data: bytes, result: DrawingVariablesResult) -> None:
        """
        Scan for GUID patterns in the data.

        GUIDs are 16 bytes and have a specific structure.
        DWG files typically have FINGERPRINTGUID and VERSIONGUID.
        """
        # Look for GUID-like patterns
        # GUIDs have relatively random distribution but version byte is usually 4

        found_guids = []

        for offset in range(0x20, min(len(data) - 16, 0x10000), 4):
            try:
                potential_guid = data[offset:offset + 16]

                # Check if this looks like a GUID
                # Version nibble (high nibble of byte 6) should be 4 for random GUIDs
                version = (potential_guid[6] >> 4) & 0x0F

                # Variant bits (high 2 bits of byte 8) should be 10 binary
                variant = (potential_guid[8] >> 6) & 0x03

                if version == 4 and variant == 2:
                    # This looks like a valid UUID v4
                    guid_str = self._bytes_to_guid_string(potential_guid)
                    found_guids.append({
                        "offset": offset,
                        "guid": guid_str,
                        "raw": potential_guid,
                    })
            except (IndexError, struct.error):
                continue

        # Assign first two valid GUIDs found
        if len(found_guids) >= 1:
            g = found_guids[0]
            result.fingerprintguid = DrawingGUID(
                variable_name="FINGERPRINTGUID",
                guid_string=g["guid"],
                raw_bytes=g["raw"],
                is_valid=True,
            )

        if len(found_guids) >= 2:
            g = found_guids[1]
            result.versionguid = DrawingGUID(
                variable_name="VERSIONGUID",
                guid_string=g["guid"],
                raw_bytes=g["raw"],
                is_valid=True,
            )

    def _extract_header_info(self, data: bytes, result: DrawingVariablesResult) -> None:
        """Extract additional header information from known offsets."""
        try:
            # Maintenance version at offset 0x0B
            if len(data) > 0x0C:
                result.maintver = data[0x0B]

            # Codepage at offset 0x13 (2 bytes)
            if len(data) > 0x15:
                codepage = struct.unpack_from("<H", data, 0x13)[0]
                result.dwgcodepage = f"CP{codepage}" if codepage > 0 else ""
        except (struct.error, IndexError) as e:
            result.parsing_errors.append(f"Error extracting header info: {e}")

    def _julian_to_datetime(
        self, julian_day: float, fraction: float = 0.0
    ) -> Optional[datetime]:
        """
        Convert Julian day number to datetime.

        The Julian day number is the count of days since January 1, 4713 BC.
        DWG uses a modified form based on January 1, 0001.

        Args:
            julian_day: Julian day number
            fraction: Fraction of day (0.0 to 1.0)

        Returns:
            datetime in UTC or None if conversion fails
        """
        try:
            # Standard Julian day epoch adjustment
            # Julian day 0 = November 24, 4714 BC (proleptic Gregorian)
            # We need to convert to Python datetime

            # Python uses proleptic Gregorian calendar
            # Julian day 2440587.5 = January 1, 1970 (Unix epoch)
            unix_epoch_julian = 2440587.5

            # Days since Unix epoch
            days_since_unix = julian_day - unix_epoch_julian

            # Add fraction of day
            total_seconds = (days_since_unix + fraction) * 86400

            # Convert to datetime
            dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=total_seconds)

            # Validate result is in reasonable range
            if dt.year < 1980 or dt.year > 2100:
                return None

            return dt

        except (ValueError, OverflowError, OSError):
            return None

    def _bytes_to_guid_string(self, guid_bytes: bytes) -> str:
        """
        Convert 16 bytes to standard GUID string format.

        Format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
        """
        if len(guid_bytes) != 16:
            return ""

        # DWG stores GUIDs in mixed-endian format (like Windows)
        # First 3 components are little-endian, last 2 are big-endian

        part1 = struct.unpack_from("<I", guid_bytes, 0)[0]
        part2 = struct.unpack_from("<H", guid_bytes, 4)[0]
        part3 = struct.unpack_from("<H", guid_bytes, 6)[0]
        part4 = guid_bytes[8:10].hex()
        part5 = guid_bytes[10:16].hex()

        return f"{part1:08X}-{part2:04X}-{part3:04X}-{part4.upper()}-{part5.upper()}"


def extract_drawing_variables(file_path: Path) -> DrawingVariablesResult:
    """Convenience function to extract drawing variables from DWG file."""
    parser = DrawingVariablesParser()
    return parser.parse(file_path)


def compare_timestamps(
    dwg_tdcreate: Optional[datetime],
    dwg_tdupdate: Optional[datetime],
    file_created: Optional[datetime],
    file_modified: Optional[datetime],
) -> Dict[str, Any]:
    """
    Compare DWG internal timestamps with file system timestamps.

    This is a key forensic check for detecting timestamp manipulation.

    Args:
        dwg_tdcreate: TDCREATE from DWG header
        dwg_tdupdate: TDUPDATE from DWG header
        file_created: File system creation time
        file_modified: File system modification time

    Returns:
        Dictionary with comparison results and anomalies
    """
    result = {
        "create_match": None,
        "modify_match": None,
        "anomalies": [],
        "create_diff_seconds": None,
        "modify_diff_seconds": None,
    }

    # Compare creation times
    if dwg_tdcreate and file_created:
        diff = abs((dwg_tdcreate - file_created).total_seconds())
        result["create_diff_seconds"] = diff
        result["create_match"] = diff < 60  # Within 1 minute

        if diff > 86400:  # More than 1 day difference
            result["anomalies"].append({
                "type": "creation_timestamp_mismatch",
                "severity": "high",
                "description": f"DWG creation time differs from file creation by {diff / 86400:.1f} days",
                "dwg_time": dwg_tdcreate.isoformat(),
                "file_time": file_created.isoformat(),
            })

    # Compare modification times
    if dwg_tdupdate and file_modified:
        diff = abs((dwg_tdupdate - file_modified).total_seconds())
        result["modify_diff_seconds"] = diff
        result["modify_match"] = diff < 60

        if diff > 86400:
            result["anomalies"].append({
                "type": "modification_timestamp_mismatch",
                "severity": "high",
                "description": f"DWG modification time differs from file modification by {diff / 86400:.1f} days",
                "dwg_time": dwg_tdupdate.isoformat(),
                "file_time": file_modified.isoformat(),
            })

    # Check for creation after modification
    if dwg_tdcreate and dwg_tdupdate:
        if dwg_tdcreate > dwg_tdupdate:
            result["anomalies"].append({
                "type": "creation_after_modification",
                "severity": "critical",
                "description": "DWG creation timestamp is after modification timestamp",
                "tdcreate": dwg_tdcreate.isoformat(),
                "tdupdate": dwg_tdupdate.isoformat(),
            })

    # Check for future timestamps
    now = datetime.now(timezone.utc)
    if dwg_tdcreate and dwg_tdcreate > now:
        result["anomalies"].append({
            "type": "future_creation_time",
            "severity": "critical",
            "description": "DWG creation timestamp is in the future",
            "tdcreate": dwg_tdcreate.isoformat(),
        })

    if dwg_tdupdate and dwg_tdupdate > now:
        result["anomalies"].append({
            "type": "future_modification_time",
            "severity": "critical",
            "description": "DWG modification timestamp is in the future",
            "tdupdate": dwg_tdupdate.isoformat(),
        })

    return result
