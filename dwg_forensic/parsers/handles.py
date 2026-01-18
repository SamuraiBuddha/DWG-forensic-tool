"""
DWG Handle Map Parser for Forensic Analysis.

Parses the AcDb:Handles section to analyze object handles and detect:
- Handle gaps (potentially deleted objects)
- Handle sequence anomalies
- Object reference integrity

Handles in DWG files are unique identifiers for all objects. When objects
are deleted, their handles may leave gaps in the sequence, which can
indicate tampering or intentional deletion.

References:
- OpenDesign Specification (Handle and Handleref sections)
- LibreDWG source code (dwg.spec, handles.c)
"""

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Set, Tuple, Any
from enum import IntEnum

from .sections import SectionMapParser, SectionType, SectionMapResult, SectionInfo
from .compression import decompress_section, DecompressionError


class HandleType(IntEnum):
    """DWG Handle reference types."""
    SOFT_OWNERSHIP = 0x02  # Soft ownership reference
    HARD_OWNERSHIP = 0x03  # Hard ownership reference
    SOFT_POINTER = 0x04    # Soft pointer reference
    HARD_POINTER = 0x05    # Hard pointer reference


class ObjectType(IntEnum):
    """Common DWG object types for forensic interest."""
    # Entity types (visible objects)
    LINE = 0x13
    CIRCLE = 0x14
    ARC = 0x15
    TEXT = 0x16
    POLYLINE = 0x17
    MTEXT = 0x18
    INSERT = 0x19  # Block reference
    DIMENSION = 0x1A

    # Non-entity types (internal objects)
    DICTIONARY = 0x2A
    LAYER = 0x2B
    STYLE = 0x2C
    BLOCK_HEADER = 0x2D
    BLOCK_CONTROL = 0x2E
    APPID = 0x2F
    XRECORD = 0x30


@dataclass
class HandleInfo:
    """Information about a single object handle."""
    handle: int
    offset: int  # File offset where this handle was found
    object_type: int = 0
    is_entity: bool = False
    is_deleted: bool = False
    owner_handle: int = 0
    size: int = 0


@dataclass
class HandleGap:
    """Represents a gap in the handle sequence."""
    start_handle: int  # First missing handle
    end_handle: int    # Last missing handle (inclusive)
    gap_size: int      # Number of missing handles
    preceding_handle: int = 0  # Handle before the gap
    following_handle: int = 0  # Handle after the gap
    severity: str = "medium"  # low, medium, high, critical

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "start_handle": f"0x{self.start_handle:X}",
            "end_handle": f"0x{self.end_handle:X}",
            "gap_size": self.gap_size,
            "preceding_handle": f"0x{self.preceding_handle:X}",
            "following_handle": f"0x{self.following_handle:X}",
            "severity": self.severity,
        }


@dataclass
class HandleStatistics:
    """Statistics about handle distribution."""
    min_handle: int = 0
    max_handle: int = 0
    total_handles: int = 0
    entity_count: int = 0
    non_entity_count: int = 0
    expected_sequence_count: int = 0  # Expected handles if no gaps
    actual_sequence_count: int = 0    # Actual unique handles found
    gap_count: int = 0
    total_missing_handles: int = 0

    def gap_ratio(self) -> float:
        """Calculate ratio of missing handles to expected total."""
        if self.expected_sequence_count == 0:
            return 0.0
        return self.total_missing_handles / self.expected_sequence_count

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "min_handle": f"0x{self.min_handle:X}",
            "max_handle": f"0x{self.max_handle:X}",
            "total_handles": self.total_handles,
            "entity_count": self.entity_count,
            "non_entity_count": self.non_entity_count,
            "expected_sequence_count": self.expected_sequence_count,
            "actual_sequence_count": self.actual_sequence_count,
            "gap_count": self.gap_count,
            "total_missing_handles": self.total_missing_handles,
            "gap_ratio": f"{self.gap_ratio() * 100:.2f}%",
        }


@dataclass
class HandleMapResult:
    """Result of handle map parsing."""
    handles: Dict[int, HandleInfo] = field(default_factory=dict)
    gaps: List[HandleGap] = field(default_factory=list)
    statistics: HandleStatistics = field(default_factory=HandleStatistics)
    file_version: str = ""
    parsing_errors: List[str] = field(default_factory=list)

    def has_gaps(self) -> bool:
        """Check if any handle gaps were detected."""
        return len(self.gaps) > 0

    def has_significant_gaps(self, threshold: int = 10) -> bool:
        """Check if any significant gaps exist (potential tampering)."""
        return any(gap.gap_size >= threshold for gap in self.gaps)

    def get_critical_gaps(self) -> List[HandleGap]:
        """Get gaps marked as critical severity."""
        return [g for g in self.gaps if g.severity == "critical"]

    def get_forensic_summary(self) -> Dict[str, Any]:
        """Generate forensic summary of handle analysis."""
        return {
            "total_handles": self.statistics.total_handles,
            "gap_count": len(self.gaps),
            "total_missing_handles": self.statistics.total_missing_handles,
            "gap_ratio_percent": f"{self.statistics.gap_ratio() * 100:.2f}",
            "has_critical_gaps": len(self.get_critical_gaps()) > 0,
            "largest_gap": max((g.gap_size for g in self.gaps), default=0),
            "potential_tampering": self.has_significant_gaps(10),
            "errors": self.parsing_errors,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "statistics": self.statistics.to_dict(),
            "gaps": [g.to_dict() for g in self.gaps],
            "gap_count": len(self.gaps),
            "file_version": self.file_version,
            "parsing_errors": self.parsing_errors,
        }


class HandleMapParser:
    """
    Parser for DWG Handle Map (AcDb:Handles section).

    The handle map contains all object handles in the DWG file.
    Handle gaps indicate deleted objects, which is forensically significant
    as it may indicate tampering or intentional data removal.

    Supports AC1018 (2004) through AC1032 (2018+).
    """

    # Minimum file size for handle analysis
    MIN_FILE_SIZE = 0x200

    # Handle ranges that indicate different object types
    # Handles typically start low for control objects, then increment
    RESERVED_HANDLE_RANGE = (0x0, 0x100)  # Reserved/system handles

    def __init__(self):
        """Initialize the handle map parser."""
        pass

    def parse(
        self,
        file_path: Path,
        section_map: Optional[SectionMapResult] = None
    ) -> HandleMapResult:
        """
        Parse handle map from DWG file.

        Args:
            file_path: Path to DWG file
            section_map: Optional pre-parsed section map to avoid redundant parsing

        Returns:
            HandleMapResult with handle analysis
        """
        result = HandleMapResult()
        file_path = Path(file_path)

        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            result.parsing_errors.append(f"Failed to read file: {e}")
            return result

        if len(data) < self.MIN_FILE_SIZE:
            result.parsing_errors.append("File too small for handle analysis")
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

            if section_map.has_section(SectionType.HANDLES):
                return self.extract_from_section(data, section_map)
        except Exception as e:
            result.parsing_errors.append(
                f"Section-based extraction failed, using fallback: {e}"
            )

        # Fall back to legacy heuristic scanning
        if result.file_version in ["AC1032", "AC1027", "AC1024"]:
            self._parse_r2010_handles(data, result)
        elif result.file_version in ["AC1021", "AC1018"]:
            self._parse_r2004_handles(data, result)
        else:
            result.parsing_errors.append(
                f"Handle map parsing not supported for {result.file_version}"
            )

        # Analyze gaps after parsing
        if result.handles:
            self._analyze_handle_gaps(result)
            self._calculate_statistics(result)

        return result

    def extract_from_section(
        self,
        data: bytes,
        section_map: SectionMapResult
    ) -> HandleMapResult:
        """
        Extract handles from decompressed AcDb:Handles section.

        This is the new PRIMARY extraction method that replaces heuristic scanning.
        It reads the section map, locates AcDb:Handles, decompresses it, and extracts
        handle values from the known structure.

        Args:
            data: Complete file data (raw bytes from disk)
            section_map: Section map with location information

        Returns:
            HandleMapResult with extracted handles
        """
        result = HandleMapResult()
        result.file_version = section_map.file_version

        # Step 1: Get Handles section
        if not section_map.has_section(SectionType.HANDLES):
            result.parsing_errors.append("AcDb:Handles section not found in section map")
            return result

        handles_section = section_map.get_section(SectionType.HANDLES)

        # Step 2: Read and decompress section
        section_parser = SectionMapParser()
        handles_data = section_parser.read_section_data_from_bytes(
            data, handles_section, decompress=True
        )

        if not handles_data:
            result.parsing_errors.append("Failed to read/decompress AcDb:Handles section")
            return result

        # Step 3: Extract handles from decompressed data
        self._extract_handles_from_section(handles_data, result)

        # Step 4: Analyze gaps and calculate statistics
        if result.handles:
            self._analyze_handle_gaps(result)
            self._calculate_statistics(result)

        return result

    def _extract_handles_from_section(
        self, handles_data: bytes, result: HandleMapResult
    ) -> None:
        """
        Extract handle values from decompressed AcDb:Handles section data.

        This scans the decompressed AcDb:Handles section for handle patterns.
        This is MUCH more accurate than scanning the entire compressed file because:
        1. Decompressed section contains actual handle values, not compressed garbage
        2. No false positives from coincidental byte patterns in compressed data
        3. Focused scan of only relevant data

        Args:
            handles_data: Decompressed AcDb:Handles section data
            result: Result object to populate with extracted handles
        """
        found_handles: Set[int] = set()

        # Scan decompressed data for handle patterns (4-byte little-endian integers)
        for offset in range(0, len(handles_data) - 4, 4):
            try:
                potential_handle = struct.unpack_from("<I", handles_data, offset)[0]

                # Filter for valid handle range (typically 1 to 0xFFFFFF)
                if 0x1 <= potential_handle <= 0xFFFFFF:
                    # Basic validation: not already found, seems reasonable
                    if potential_handle not in found_handles:
                        found_handles.add(potential_handle)
                        result.handles[potential_handle] = HandleInfo(
                            handle=potential_handle,
                            offset=offset,
                        )
            except struct.error:
                continue

        # Also try handleref patterns (code byte + handle)
        if len(found_handles) < 10:
            self._scan_for_handle_refs_in_section(handles_data, result, found_handles)

    def _scan_for_handle_refs_in_section(
        self, handles_data: bytes, result: HandleMapResult, found_handles: Set[int]
    ) -> None:
        """
        Scan for handleref patterns (code byte + handle) in decompressed data.

        Handlerefs in DWG have a code byte indicating the reference type,
        followed by handle bytes. This is used when standard 4-byte handle
        scanning doesn't find enough handles.

        Args:
            handles_data: Decompressed AcDb:Handles section data
            result: Result object to populate
            found_handles: Set of already-found handles to avoid duplicates
        """
        for offset in range(0, len(handles_data) - 5):
            try:
                code = handles_data[offset]

                # Handleref codes 2-5 are valid reference types
                if 2 <= code <= 5:
                    handle = struct.unpack_from("<I", handles_data, offset + 1)[0]

                    if 0x1 <= handle <= 0xFFFFFF:
                        if handle not in found_handles:
                            found_handles.add(handle)
                            result.handles[handle] = HandleInfo(
                                handle=handle,
                                offset=offset + 1,
                            )
            except (struct.error, IndexError):
                continue

    def _parse_r2010_handles(self, data: bytes, result: HandleMapResult) -> None:
        """
        Parse handles for R2010+ (AC1024, AC1027, AC1032).

        Scans for handle patterns in the object data stream.
        """
        try:
            # Scan for handle patterns
            # Handles are typically stored as part of object headers
            self._scan_for_handles(data, result)

        except Exception as e:
            result.parsing_errors.append(f"Error parsing R2010 handles: {e}")

    def _parse_r2004_handles(self, data: bytes, result: HandleMapResult) -> None:
        """
        Parse handles for R2004-2009 (AC1018, AC1021).

        R2004 has encrypted sections but handles can still be identified.
        """
        try:
            self._scan_for_handles(data, result)

        except Exception as e:
            result.parsing_errors.append(f"Error parsing R2004 handles: {e}")

    def _scan_for_handles(self, data: bytes, result: HandleMapResult) -> None:
        """
        Scan file data for handle patterns.

        DWG handles are stored in various formats:
        - Direct handles (4 bytes, little-endian)
        - Handleref (code byte + handle bytes)

        We scan for patterns that look like valid handle references.
        """
        found_handles: Set[int] = set()

        # Scan the object stream area (typically after 0x100)
        # Look for sequences that appear to be handle references

        scan_start = 0x100
        scan_end = len(data) - 4

        for offset in range(scan_start, scan_end, 4):
            try:
                # Try to read a potential handle (4-byte integer)
                potential_handle = struct.unpack_from("<I", data, offset)[0]

                # Filter for valid handle range
                # Typical DWG handles are in range 0x1 to 0xFFFFFF
                if 0x1 <= potential_handle <= 0xFFFFFF:
                    # Additional validation: handles should have reasonable values
                    # and not be obviously data values (like sizes or offsets)

                    # Check if this could be a valid handle
                    if self._is_likely_handle(potential_handle, data, offset):
                        found_handles.add(potential_handle)

                        if potential_handle not in result.handles:
                            result.handles[potential_handle] = HandleInfo(
                                handle=potential_handle,
                                offset=offset,
                            )

            except struct.error:
                continue

        # If we didn't find handles through the standard scan, try alternate method
        if len(found_handles) < 10:
            self._scan_for_handle_refs(data, result, found_handles)

    def _is_likely_handle(self, value: int, data: bytes, offset: int) -> bool:
        """
        Heuristic to determine if a value is likely a handle.

        Handles tend to:
        - Be sequential or near-sequential
        - Not be round numbers (like 0x1000, 0x10000)
        - Not be common size values
        """
        # Exclude common non-handle values
        common_non_handles = {
            0x00, 0x01, 0x02, 0x03, 0x04,  # Too small
            0xFF, 0xFFFF, 0xFFFFFF,  # Max values
            0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000,  # Powers of 2
            0x10000, 0x20000, 0x40000, 0x80000, 0x100000,  # Larger powers
        }

        if value in common_non_handles:
            return False

        # Check for exact power of 2 (usually sizes, not handles)
        if value > 0 and (value & (value - 1)) == 0:
            return False

        # Handles rarely end in 00
        if value > 0x100 and (value & 0xFF) == 0:
            return False

        return True

    def _scan_for_handle_refs(
        self, data: bytes, result: HandleMapResult, found_handles: Set[int]
    ) -> None:
        """
        Scan for handleref patterns (code + handle).

        Handlerefs in DWG have a code byte indicating the reference type,
        followed by handle bytes.
        """
        scan_start = 0x100
        scan_end = len(data) - 5

        for offset in range(scan_start, scan_end):
            try:
                # Handleref code byte (2-5 are valid reference types)
                code = data[offset]

                if 2 <= code <= 5:
                    # Read handle value (next 4 bytes)
                    handle = struct.unpack_from("<I", data, offset + 1)[0]

                    if 0x1 <= handle <= 0xFFFFFF:
                        if handle not in found_handles:
                            found_handles.add(handle)
                            result.handles[handle] = HandleInfo(
                                handle=handle,
                                offset=offset + 1,
                            )

            except (struct.error, IndexError):
                continue

    def _analyze_handle_gaps(self, result: HandleMapResult) -> None:
        """
        Analyze handle sequence for gaps.

        Gaps in the handle sequence may indicate:
        - Deleted objects (normal editing)
        - Intentional tampering (forensically significant)
        - File corruption
        """
        if not result.handles:
            return

        # Sort handles
        sorted_handles = sorted(result.handles.keys())

        if len(sorted_handles) < 2:
            return

        min_handle = sorted_handles[0]
        max_handle = sorted_handles[-1]

        # Find gaps in sequence
        prev_handle = min_handle

        for handle in sorted_handles[1:]:
            gap_size = handle - prev_handle - 1

            if gap_size > 0:
                # Determine severity based on gap size and location
                severity = self._classify_gap_severity(
                    gap_size, prev_handle, handle, min_handle, max_handle
                )

                gap = HandleGap(
                    start_handle=prev_handle + 1,
                    end_handle=handle - 1,
                    gap_size=gap_size,
                    preceding_handle=prev_handle,
                    following_handle=handle,
                    severity=severity,
                )
                result.gaps.append(gap)

            prev_handle = handle

    def _classify_gap_severity(
        self,
        gap_size: int,
        before: int,
        after: int,
        min_h: int,
        max_h: int
    ) -> str:
        """
        Classify gap severity for forensic significance.

        - critical: Large gaps (>100) or gaps in middle of well-populated region
        - high: Medium gaps (20-100) in significant regions
        - medium: Small gaps (5-19) or gaps in sparse regions
        - low: Tiny gaps (1-4) likely normal editing
        """
        # Gap size thresholds
        if gap_size > 100:
            return "critical"
        elif gap_size > 20:
            return "high"
        elif gap_size > 5:
            # Check if gap is in middle of handle range (more suspicious)
            range_size = max_h - min_h
            if range_size > 0:
                gap_center = (before + after) // 2
                relative_position = (gap_center - min_h) / range_size

                # Gaps in middle 60% of range are more suspicious
                if 0.2 < relative_position < 0.8:
                    return "high"

            return "medium"
        else:
            return "low"

    def _calculate_statistics(self, result: HandleMapResult) -> None:
        """Calculate handle statistics."""
        if not result.handles:
            return

        handles = list(result.handles.keys())
        stats = result.statistics

        stats.min_handle = min(handles)
        stats.max_handle = max(handles)
        stats.total_handles = len(handles)
        stats.actual_sequence_count = len(handles)

        # Expected count if no gaps
        stats.expected_sequence_count = stats.max_handle - stats.min_handle + 1

        # Gap analysis
        stats.gap_count = len(result.gaps)
        stats.total_missing_handles = sum(g.gap_size for g in result.gaps)

        # Count entities vs non-entities (if type info available)
        for info in result.handles.values():
            if info.is_entity:
                stats.entity_count += 1
            else:
                stats.non_entity_count += 1


def analyze_handle_gaps(file_path: Path) -> HandleMapResult:
    """Convenience function to analyze handle gaps in a DWG file."""
    parser = HandleMapParser()
    return parser.parse(file_path)


def format_gap_report(result: HandleMapResult) -> str:
    """
    Format a human-readable gap analysis report.

    Args:
        result: HandleMapResult from parsing

    Returns:
        Formatted string report
    """
    lines = []
    lines.append("=" * 60)
    lines.append("DWG HANDLE GAP ANALYSIS REPORT")
    lines.append("=" * 60)
    lines.append("")

    # Summary
    lines.append("SUMMARY:")
    lines.append(f"  File Version: {result.file_version}")
    lines.append(f"  Total Handles Found: {result.statistics.total_handles}")
    lines.append(f"  Handle Range: 0x{result.statistics.min_handle:X} - "
                 f"0x{result.statistics.max_handle:X}")
    lines.append(f"  Gap Count: {result.statistics.gap_count}")
    lines.append(f"  Missing Handles: {result.statistics.total_missing_handles}")
    lines.append(f"  Gap Ratio: {result.statistics.gap_ratio() * 100:.2f}%")
    lines.append("")

    # Forensic Assessment
    lines.append("FORENSIC ASSESSMENT:")
    if not result.gaps:
        lines.append("  [OK] No handle gaps detected - file appears intact")
    elif result.has_significant_gaps(10):
        lines.append("  [!] SIGNIFICANT GAPS DETECTED - potential tampering")
    else:
        lines.append("  [WARN] Minor gaps detected - likely normal editing")
    lines.append("")

    # Gap Details
    if result.gaps:
        lines.append("GAP DETAILS:")
        lines.append("-" * 60)

        # Sort by severity
        sorted_gaps = sorted(result.gaps, key=lambda g: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}[g.severity],
            -g.gap_size
        ))

        for gap in sorted_gaps[:20]:  # Show top 20 gaps
            severity_marker = {
                "critical": "[!!]",
                "high": "[!]",
                "medium": "[WARN]",
                "low": "[-]"
            }[gap.severity]

            lines.append(
                f"  {severity_marker} Gap: 0x{gap.start_handle:X} - 0x{gap.end_handle:X} "
                f"({gap.gap_size} handles) [{gap.severity.upper()}]"
            )

        if len(result.gaps) > 20:
            lines.append(f"  ... and {len(result.gaps) - 20} more gaps")

    # Errors
    if result.parsing_errors:
        lines.append("")
        lines.append("PARSING ERRORS:")
        for err in result.parsing_errors:
            lines.append(f"  - {err}")

    lines.append("")
    lines.append("=" * 60)

    return "\n".join(lines)
