"""Modified Julian Date timestamp and GUID parser for DWG files.

This module extracts timestamp system variables and GUIDs from DWG file headers
for forensic timestamp manipulation detection:

Timestamps (stored as Modified Julian Date):
- TDCREATE: Local creation date/time
- TDUPDATE: Local last-save date/time
- TDUCREATE: UTC creation time
- TDUUPDATE: UTC last-save time
- TDINDWG: Cumulative editing time (critical - cannot exceed calendar span)
- TDUSRTIMER: User-resettable timer

GUIDs:
- FINGERPRINTGUID: Unique file ID that persists across copies
- VERSIONGUID: Changes with each save operation

User Identity:
- LOGINNAME: Windows username who last saved
- Educational Version watermark detection

MJD Format:
    Modified Julian Date stores timestamps as double-precision floats.
    Integer part = days since November 17, 1858
    Fractional part = fraction of the day elapsed
"""

import struct
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Dict, Any

from dwg_forensic.utils.exceptions import ParseError


# Modified Julian Date epoch: November 17, 1858 00:00:00 UTC
MJD_EPOCH = datetime(1858, 11, 17, 0, 0, 0, tzinfo=timezone.utc)

# Seconds per day for MJD fraction conversion
SECONDS_PER_DAY = 86400.0


def mjd_to_datetime(mjd: float) -> datetime:
    """Convert Modified Julian Date to datetime.

    MJD format: integer part = days since Nov 17, 1858
                fractional part = fraction of day elapsed

    Args:
        mjd: Modified Julian Date value (double-precision float)

    Returns:
        datetime object in UTC timezone
    """
    if mjd <= 0:
        return MJD_EPOCH

    days = int(mjd)
    fraction = mjd - days

    # Convert fractional day to seconds
    seconds = fraction * SECONDS_PER_DAY

    result = MJD_EPOCH + timedelta(days=days, seconds=seconds)
    return result


def datetime_to_mjd(dt: datetime) -> float:
    """Convert datetime to Modified Julian Date.

    Args:
        dt: datetime object (timezone-aware or naive, treated as UTC if naive)

    Returns:
        MJD value as double-precision float
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    # Convert to UTC
    dt_utc = dt.astimezone(timezone.utc)

    delta = dt_utc - MJD_EPOCH
    return delta.total_seconds() / SECONDS_PER_DAY


@dataclass
class TimestampData:
    """Container for extracted DWG timestamp and GUID data.

    All MJD values are stored as raw floats for forensic analysis.
    Use helper methods to convert to datetime objects.
    """

    # MJD Timestamps (raw values)
    tdcreate: Optional[float] = None
    tdupdate: Optional[float] = None
    tducreate: Optional[float] = None
    tduupdate: Optional[float] = None
    tdindwg: Optional[float] = None
    tdusrtimer: Optional[float] = None

    # GUIDs
    fingerprint_guid: Optional[str] = None
    version_guid: Optional[str] = None

    # User Identity
    login_name: Optional[str] = None
    educational_watermark: bool = False

    # Extraction metadata
    extraction_success: bool = False
    extraction_errors: list = field(default_factory=list)

    def get_tdcreate_datetime(self) -> Optional[datetime]:
        """Convert TDCREATE MJD to datetime."""
        if self.tdcreate is not None and self.tdcreate > 0:
            return mjd_to_datetime(self.tdcreate)
        return None

    def get_tdupdate_datetime(self) -> Optional[datetime]:
        """Convert TDUPDATE MJD to datetime."""
        if self.tdupdate is not None and self.tdupdate > 0:
            return mjd_to_datetime(self.tdupdate)
        return None

    def get_tducreate_datetime(self) -> Optional[datetime]:
        """Convert TDUCREATE (UTC) MJD to datetime."""
        if self.tducreate is not None and self.tducreate > 0:
            return mjd_to_datetime(self.tducreate)
        return None

    def get_tduupdate_datetime(self) -> Optional[datetime]:
        """Convert TDUUPDATE (UTC) MJD to datetime."""
        if self.tduupdate is not None and self.tduupdate > 0:
            return mjd_to_datetime(self.tduupdate)
        return None

    def get_tdindwg_hours(self) -> Optional[float]:
        """Get TDINDWG as hours.

        TDINDWG is stored as MJD fraction (days), multiply by 24 for hours.
        """
        if self.tdindwg is not None:
            return self.tdindwg * 24.0
        return None

    def get_tdindwg_days(self) -> Optional[float]:
        """Get TDINDWG as days (raw MJD fraction)."""
        return self.tdindwg

    def get_tdusrtimer_hours(self) -> Optional[float]:
        """Get TDUSRTIMER as hours."""
        if self.tdusrtimer is not None:
            return self.tdusrtimer * 24.0
        return None

    def get_calendar_span_days(self) -> Optional[float]:
        """Calculate calendar span between TDCREATE and TDUPDATE in days.

        This is used to detect TDINDWG manipulation - if TDINDWG exceeds
        the calendar span, timestamps have been manipulated.
        """
        tdcreate = self.get_tdcreate_datetime()
        tdupdate = self.get_tdupdate_datetime()

        if tdcreate and tdupdate:
            span = (tdupdate - tdcreate).total_seconds() / SECONDS_PER_DAY
            return max(0, span)  # Ensure non-negative
        return None

    def get_timezone_offset_hours(self) -> Optional[float]:
        """Calculate timezone offset from local vs UTC creation timestamps.

        Returns the difference in hours between TDCREATE (local) and
        TDUCREATE (UTC). Valid offsets are -14 to +14 hours.
        """
        if self.tdcreate is not None and self.tducreate is not None:
            # Both are MJD, so difference in days * 24 = hours
            offset_days = self.tdcreate - self.tducreate
            return offset_days * 24.0
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "tdcreate": self.tdcreate,
            "tdupdate": self.tdupdate,
            "tducreate": self.tducreate,
            "tduupdate": self.tduupdate,
            "tdindwg": self.tdindwg,
            "tdusrtimer": self.tdusrtimer,
            "fingerprint_guid": self.fingerprint_guid,
            "version_guid": self.version_guid,
            "login_name": self.login_name,
            "educational_watermark": self.educational_watermark,
            "tdcreate_datetime": (
                self.get_tdcreate_datetime().isoformat()
                if self.get_tdcreate_datetime()
                else None
            ),
            "tdupdate_datetime": (
                self.get_tdupdate_datetime().isoformat()
                if self.get_tdupdate_datetime()
                else None
            ),
            "tdindwg_hours": self.get_tdindwg_hours(),
            "calendar_span_days": self.get_calendar_span_days(),
            "timezone_offset_hours": self.get_timezone_offset_hours(),
        }


class TimestampParser:
    """Parser for DWG timestamp system variables and GUIDs.

    Timestamps are stored in the AcDb:Header section as 8-byte
    IEEE 754 double-precision floating point values in MJD format.

    GUIDs are stored as 16-byte binary values in little-endian format.

    Note: The exact byte offsets vary by DWG version and may need
    empirical validation with real DWG files.
    """

    # Educational version watermark markers
    EDUCATIONAL_MARKERS = [
        b"EDUCATIONAL VERSION",
        b"PRODUCED BY AN AUTODESK STUDENT VERSION",
        b"STUDENT VERSION",
    ]

    # Login name marker
    LOGINNAME_MARKER = b"LOGINNAME"

    # Minimum file size for timestamp extraction
    MIN_FILE_SIZE = 256

    # Known valid MJD range (roughly 1900-2100)
    MIN_VALID_MJD = 15000.0  # ~1900
    MAX_VALID_MJD = 88000.0  # ~2100

    def __init__(self):
        """Initialize the timestamp parser."""
        pass

    def parse(
        self, file_path: Path, version_string: Optional[str] = None
    ) -> TimestampData:
        """Parse timestamp data from DWG file.

        Uses multiple strategies to locate and extract timestamps:
        1. Search for known marker patterns
        2. Scan for valid MJD values in expected ranges
        3. Extract GUIDs from header area

        Args:
            file_path: Path to DWG file
            version_string: DWG version (e.g., 'AC1032'), optional

        Returns:
            TimestampData with extracted values

        Raises:
            ParseError: If file cannot be read
        """
        file_path = Path(file_path)
        result = TimestampData()

        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except IOError as e:
            raise ParseError(f"Failed to read file: {e}")

        if len(data) < self.MIN_FILE_SIZE:
            result.extraction_errors.append("File too small for timestamp extraction")
            return result

        # Detect version if not provided
        if version_string is None:
            version_string = self._detect_version(data)

        # Extract timestamps using pattern scanning
        self._extract_timestamps(data, result, version_string)

        # Extract GUIDs
        self._extract_guids(data, result)

        # Extract login name
        result.login_name = self._extract_login_name(data)

        # Check for educational watermark
        result.educational_watermark = self._detect_educational_watermark(data)

        # Mark extraction as successful if we got at least one timestamp
        result.extraction_success = any([
            result.tdcreate is not None,
            result.tdupdate is not None,
            result.tdindwg is not None,
        ])

        return result

    def _detect_version(self, data: bytes) -> Optional[str]:
        """Detect DWG version from file header."""
        if len(data) < 6:
            return None

        try:
            version_bytes = data[0:6]
            version_string = version_bytes.decode("ascii").rstrip("\x00")
            if version_string.startswith("AC"):
                return version_string
        except UnicodeDecodeError:
            pass

        return None

    def _extract_timestamps(
        self,
        data: bytes,
        result: TimestampData,
        version_string: Optional[str],
    ) -> None:
        """Extract MJD timestamps from file data.

        Uses pattern scanning to find valid MJD values. DWG files store
        timestamps as sequences of 8-byte doubles in the header area.

        Args:
            data: File data bytes
            result: TimestampData to populate
            version_string: DWG version for version-specific handling
        """
        # Scan the first 4KB for valid MJD sequences
        # Timestamps are typically stored consecutively
        scan_range = min(4096, len(data))

        found_mjds = []

        # Scan for valid MJD values
        for offset in range(0, scan_range - 8, 8):
            try:
                value = struct.unpack_from("<d", data, offset)[0]

                # Check if this is a valid MJD value
                if self._is_valid_mjd(value):
                    found_mjds.append((offset, value))

            except struct.error:
                continue

        # Look for consecutive pairs/sequences of valid MJDs
        # (timestamps are typically stored together)
        if len(found_mjds) >= 2:
            # Find clusters of consecutive timestamps
            clusters = self._find_timestamp_clusters(found_mjds)

            if clusters:
                # Use the first valid cluster
                self._assign_timestamps_from_cluster(clusters[0], result)

        # Also scan for small MJD fractions (TDINDWG, TDUSRTIMER)
        # These are typically < 365 days (1 year of editing)
        for offset in range(0, scan_range - 8, 8):
            try:
                value = struct.unpack_from("<d", data, offset)[0]

                # TDINDWG/TDUSRTIMER are small positive fractions
                if 0.0 < value < 365.0 and result.tdindwg is None:
                    # Could be TDINDWG - validate it makes sense
                    if self._could_be_editing_time(value, result):
                        result.tdindwg = value

            except struct.error:
                continue

    def _is_valid_mjd(self, value: float) -> bool:
        """Check if a value is a valid MJD timestamp.

        Valid MJD range is approximately 15000 (1900) to 88000 (2100).
        """
        if not isinstance(value, (int, float)):
            return False

        # Check for NaN or infinity
        if value != value or abs(value) == float("inf"):
            return False

        return self.MIN_VALID_MJD <= value <= self.MAX_VALID_MJD

    def _could_be_editing_time(self, value: float, result: TimestampData) -> bool:
        """Check if a value could plausibly be TDINDWG.

        TDINDWG should be positive and ideally less than the calendar span.
        """
        if value <= 0:
            return False

        calendar_span = result.get_calendar_span_days()
        if calendar_span is not None:
            # TDINDWG shouldn't be massively larger than calendar span
            # (though detecting when it exceeds is the point of forensics)
            if value > calendar_span * 10:
                return False

        return True

    def _find_timestamp_clusters(
        self, found_mjds: list
    ) -> list:
        """Find clusters of consecutive MJD values.

        Timestamps are typically stored consecutively in the header.
        Look for groups of 2+ valid MJDs at consecutive offsets.
        """
        if not found_mjds:
            return []

        clusters = []
        current_cluster = [found_mjds[0]]

        for i in range(1, len(found_mjds)):
            prev_offset = found_mjds[i - 1][0]
            curr_offset = found_mjds[i][0]

            # Check if consecutive (8 bytes apart)
            if curr_offset - prev_offset == 8:
                current_cluster.append(found_mjds[i])
            else:
                if len(current_cluster) >= 2:
                    clusters.append(current_cluster)
                current_cluster = [found_mjds[i]]

        if len(current_cluster) >= 2:
            clusters.append(current_cluster)

        return clusters

    def _assign_timestamps_from_cluster(
        self, cluster: list, result: TimestampData
    ) -> None:
        """Assign timestamp values from a cluster of MJD values.

        DWG typically stores timestamps in order:
        TDCREATE, TDUPDATE, TDUCREATE, TDUUPDATE, TDINDWG, TDUSRTIMER
        """
        values = [item[1] for item in cluster]

        # Sort cluster by value to identify pairs
        # Creation times should be <= update times
        sorted_values = sorted(values)

        if len(values) >= 2:
            # First two valid MJDs are likely TDCREATE and TDUPDATE
            result.tdcreate = sorted_values[0]
            result.tdupdate = sorted_values[-1] if len(sorted_values) > 1 else None

        if len(values) >= 4:
            # If we have 4+, second pair might be UTC versions
            result.tducreate = sorted_values[0]  # Same as local roughly
            result.tduupdate = sorted_values[-1]

    def _extract_guids(self, data: bytes, result: TimestampData) -> None:
        """Extract FINGERPRINTGUID and VERSIONGUID from file data.

        GUIDs are 16-byte binary values. We search for likely GUID
        patterns in the header area.
        """
        # Scan the first 1KB for potential GUIDs
        scan_range = min(1024, len(data) - 16)

        potential_guids = []

        for offset in range(0, scan_range, 4):  # 4-byte aligned
            try:
                guid_bytes = data[offset : offset + 16]
                if len(guid_bytes) == 16:
                    # Check if this looks like a valid GUID (not all zeros or ones)
                    if self._is_likely_guid(guid_bytes):
                        guid_str = self._bytes_to_guid_string(guid_bytes)
                        if guid_str:
                            potential_guids.append((offset, guid_str))
            except Exception:
                continue

        # Assign first two unique GUIDs found
        unique_guids = []
        for offset, guid in potential_guids:
            if guid not in unique_guids:
                unique_guids.append(guid)

        if len(unique_guids) >= 1:
            result.fingerprint_guid = unique_guids[0]
        if len(unique_guids) >= 2:
            result.version_guid = unique_guids[1]

    def _is_likely_guid(self, guid_bytes: bytes) -> bool:
        """Check if bytes could be a valid GUID.

        Excludes all-zeros, all-ones, and repeated patterns.
        """
        if len(guid_bytes) != 16:
            return False

        # Check for all zeros
        if guid_bytes == b"\x00" * 16:
            return False

        # Check for all ones
        if guid_bytes == b"\xff" * 16:
            return False

        # Check for simple repeated patterns
        unique_bytes = set(guid_bytes)
        if len(unique_bytes) < 4:
            return False

        return True

    def _bytes_to_guid_string(self, guid_bytes: bytes) -> Optional[str]:
        """Convert 16-byte GUID to standard string format."""
        try:
            # DWG uses little-endian GUID format
            guid = uuid.UUID(bytes_le=guid_bytes)
            return str(guid)
        except (ValueError, struct.error):
            return None

    def _extract_login_name(self, data: bytes) -> Optional[str]:
        """Extract LOGINNAME from file data.

        LOGINNAME is typically stored as a null-terminated string
        following a marker pattern.
        """
        for marker in [self.LOGINNAME_MARKER, b"LoginName", b"ACAD_LOGIN"]:
            idx = data.find(marker)
            if idx == -1:
                continue

            # Skip marker and any null padding
            start = idx + len(marker)
            while start < len(data) and data[start] == 0:
                start += 1

            # Read until null terminator or control character
            end = start
            while end < len(data) and end < start + 256:
                byte = data[end]
                if byte == 0 or byte < 32:
                    break
                end += 1

            if end > start:
                try:
                    name = data[start:end].decode("utf-8", errors="ignore")
                    if name and len(name) >= 2:
                        return name.strip()
                except Exception:
                    continue

        return None

    def _detect_educational_watermark(self, data: bytes) -> bool:
        """Detect Educational Version watermark in file data.

        The educational watermark is a string marker embedded in DWG
        files created with student/educational versions of AutoCAD.
        This watermark "infects" any file that receives content from
        an educational version file.
        """
        for marker in self.EDUCATIONAL_MARKERS:
            if marker in data:
                return True
        return False

    def has_timestamp_support(self, version_string: str) -> bool:
        """Check if a version supports timestamp extraction.

        All DWG versions from AC1015 (2000) onwards store timestamps,
        though the exact offsets may vary.

        Args:
            version_string: DWG version code (e.g., 'AC1032')

        Returns:
            True if version supports timestamp extraction
        """
        supported = [
            "AC1015",  # 2000
            "AC1018",  # 2004
            "AC1021",  # 2007
            "AC1024",  # 2010
            "AC1027",  # 2013
            "AC1032",  # 2018+
        ]
        return version_string in supported
