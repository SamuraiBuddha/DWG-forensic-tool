"""DWG file parsers for forensic analysis.

This package provides binary parsers for different components of DWG files,
supporting AutoCAD versions from AC1018 (2004) through current (AC1032+).

Includes:
- Header parsing with version detection
- CRC validation
- TrustedDWG watermark detection
- Timestamp extraction and validation
- Section map parsing for deep analysis
- Drawing variables extraction (TDCREATE, TDUPDATE, GUIDs)
- NTFS timestamp parsing for cross-validation forensic analysis
"""

from dwg_forensic.parsers.header import HeaderParser
from dwg_forensic.parsers.crc import CRCValidator
from dwg_forensic.parsers.watermark import WatermarkDetector
from dwg_forensic.parsers.timestamp import (
    TimestampParser,
    TimestampData,
    mjd_to_datetime,
    datetime_to_mjd,
)
from dwg_forensic.parsers.ntfs import (
    NTFSTimestampParser,
    NTFSForensicData,
    NTFSTimestamps,
    get_ntfs_timestamps,
)
from dwg_forensic.parsers.sections import (
    SectionType,
    SectionInfo,
    SectionMapResult,
    SectionMapParser,
    get_section_map,
)
from dwg_forensic.parsers.drawing_vars import (
    DrawingTimestamp,
    DrawingGUID,
    DrawingVariablesResult,
    DrawingVariablesParser,
    extract_drawing_variables,
    compare_timestamps,
)
from dwg_forensic.parsers.handles import (
    HandleType,
    HandleInfo,
    HandleGap,
    HandleStatistics,
    HandleMapResult,
    HandleMapParser,
    analyze_handle_gaps,
    format_gap_report,
)

__all__ = [
    # Header and core parsers
    "HeaderParser",
    "CRCValidator",
    "WatermarkDetector",
    # Timestamp parsing
    "TimestampParser",
    "TimestampData",
    "mjd_to_datetime",
    "datetime_to_mjd",
    # NTFS parsing
    "NTFSTimestampParser",
    "NTFSForensicData",
    "NTFSTimestamps",
    "get_ntfs_timestamps",
    # Section map parsing (deep analysis)
    "SectionType",
    "SectionInfo",
    "SectionMapResult",
    "SectionMapParser",
    "get_section_map",
    # Drawing variables (deep analysis)
    "DrawingTimestamp",
    "DrawingGUID",
    "DrawingVariablesResult",
    "DrawingVariablesParser",
    "extract_drawing_variables",
    "compare_timestamps",
    # Handle gap analysis (deep analysis)
    "HandleType",
    "HandleInfo",
    "HandleGap",
    "HandleStatistics",
    "HandleMapResult",
    "HandleMapParser",
    "analyze_handle_gaps",
    "format_gap_report",
]
