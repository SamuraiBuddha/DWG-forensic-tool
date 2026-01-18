"""
Diagnostic logging for DWG parsing failures.

Provides detailed context when parsing fails to help both debugging
and LLM-based forensic reasoning.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Tuple


@dataclass
class ParseDiagnostics:
    """Comprehensive diagnostic data for parse failure analysis.

    Captures the full context of parsing attempts including:
    - File version and basic properties
    - Section map detection attempts
    - Sections found vs expected
    - Encryption/compression status
    - Timestamp extraction methods tried
    - Raw header data for manual inspection
    """

    # Basic file information
    version: str
    file_size: int

    # Section map detection
    section_map_address: Optional[int] = None
    section_map_found: bool = False

    # Section analysis
    sections_found: List[str] = field(default_factory=list)
    sections_missing: List[str] = field(default_factory=list)

    # Encryption/compression status
    decryption_applied: bool = False
    compression_errors: List[str] = field(default_factory=list)

    # Timestamp extraction diagnostics
    timestamp_extraction_method: str = "failed"  # "section", "offset", "heuristic", "failed"
    timestamp_scan_regions: List[Tuple[int, int]] = field(default_factory=list)  # (start, end) offsets tried

    # Revit detection (common issue)
    revit_detected: bool = False

    # Raw data for manual debugging
    raw_header_hex: str = ""  # First 256 bytes as hex

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "version": self.version,
            "file_size": self.file_size,
            "section_map_address": self.section_map_address,
            "section_map_found": self.section_map_found,
            "sections_found": self.sections_found,
            "sections_missing": self.sections_missing,
            "decryption_applied": self.decryption_applied,
            "compression_errors": self.compression_errors,
            "timestamp_extraction_method": self.timestamp_extraction_method,
            "timestamp_scan_regions": [
                {"start": start, "end": end}
                for start, end in self.timestamp_scan_regions
            ],
            "revit_detected": self.revit_detected,
            "raw_header_hex": self.raw_header_hex,
        }

    def add_scan_region(self, start: int, end: int) -> None:
        """Add a timestamp scan region that was attempted."""
        self.timestamp_scan_regions.append((start, end))

    def add_compression_error(self, error: str) -> None:
        """Add a compression error message."""
        self.compression_errors.append(error)

    def mark_section_found(self, section_name: str) -> None:
        """Mark a section as successfully located."""
        if section_name not in self.sections_found:
            self.sections_found.append(section_name)

    def mark_section_missing(self, section_name: str) -> None:
        """Mark a section as missing."""
        if section_name not in self.sections_missing:
            self.sections_missing.append(section_name)
