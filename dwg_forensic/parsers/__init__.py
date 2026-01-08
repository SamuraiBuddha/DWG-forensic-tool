"""DWG file parsers for forensic analysis.

This package provides binary parsers for different components of DWG files,
supporting AutoCAD versions from R13 (AC1012) through current (AC1032+).
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

__all__ = [
    "HeaderParser",
    "CRCValidator",
    "WatermarkDetector",
    "TimestampParser",
    "TimestampData",
    "mjd_to_datetime",
    "datetime_to_mjd",
]
