"""DWG file parsers for forensic analysis.

This package provides binary parsers for different components of DWG files,
supporting AutoCAD R18+ versions (2010 and later).
"""

from dwg_forensic.parsers.header import HeaderParser
from dwg_forensic.parsers.crc import CRCValidator
from dwg_forensic.parsers.watermark import WatermarkDetector

__all__ = [
    "HeaderParser",
    "CRCValidator",
    "WatermarkDetector",
]
