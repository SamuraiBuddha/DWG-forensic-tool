"""
Tests for parsing diagnostics functionality.
"""

import pytest
from pathlib import Path

from dwg_forensic.utils.diagnostics import ParseDiagnostics
from dwg_forensic.parsers.drawing_vars import DrawingVariablesParser


def test_parse_diagnostics_creation():
    """Test creation of ParseDiagnostics dataclass."""
    diagnostics = ParseDiagnostics(
        version="AC1032",
        file_size=1024000
    )

    assert diagnostics.version == "AC1032"
    assert diagnostics.file_size == 1024000
    assert diagnostics.section_map_found is False
    assert diagnostics.timestamp_extraction_method == "failed"
    assert len(diagnostics.sections_found) == 0
    assert len(diagnostics.sections_missing) == 0
    assert len(diagnostics.compression_errors) == 0


def test_parse_diagnostics_methods():
    """Test ParseDiagnostics helper methods."""
    diagnostics = ParseDiagnostics(
        version="AC1027",
        file_size=2048000,
        raw_header_hex="414331303237"
    )

    # Test add_scan_region
    diagnostics.add_scan_region(0, 1000)
    diagnostics.add_scan_region(5000, 6000)
    assert len(diagnostics.timestamp_scan_regions) == 2
    assert diagnostics.timestamp_scan_regions[0] == (0, 1000)
    assert diagnostics.timestamp_scan_regions[1] == (5000, 6000)

    # Test add_compression_error
    diagnostics.add_compression_error("LZ77 decompression failed")
    diagnostics.add_compression_error("Invalid page header")
    assert len(diagnostics.compression_errors) == 2
    assert "LZ77" in diagnostics.compression_errors[0]

    # Test mark_section_found
    diagnostics.mark_section_found("AcDb:Header")
    diagnostics.mark_section_found("AcDb:Classes")
    assert len(diagnostics.sections_found) == 2
    assert "AcDb:Header" in diagnostics.sections_found

    # Test mark_section_missing
    diagnostics.mark_section_missing("AcDb:Handles")
    assert len(diagnostics.sections_missing) == 1
    assert "AcDb:Handles" in diagnostics.sections_missing


def test_parse_diagnostics_to_dict():
    """Test ParseDiagnostics serialization to dictionary."""
    diagnostics = ParseDiagnostics(
        version="AC1024",
        file_size=512000,
        raw_header_hex="414331303234"
    )

    diagnostics.section_map_address = 0x1234
    diagnostics.section_map_found = True
    diagnostics.decryption_applied = True
    diagnostics.timestamp_extraction_method = "section"
    diagnostics.add_scan_region(0, 500)
    diagnostics.mark_section_found("AcDb:Header")
    diagnostics.mark_section_missing("AcDb:Handles")
    diagnostics.add_compression_error("Test error")

    result = diagnostics.to_dict()

    assert result["version"] == "AC1024"
    assert result["file_size"] == 512000
    assert result["section_map_address"] == 0x1234
    assert result["section_map_found"] is True
    assert result["decryption_applied"] is True
    assert result["timestamp_extraction_method"] == "section"
    assert len(result["timestamp_scan_regions"]) == 1
    assert result["timestamp_scan_regions"][0]["start"] == 0
    assert result["timestamp_scan_regions"][0]["end"] == 500
    assert "AcDb:Header" in result["sections_found"]
    assert "AcDb:Handles" in result["sections_missing"]
    assert len(result["compression_errors"]) == 1
    assert result["raw_header_hex"] == "414331303234"


def test_drawing_variables_result_includes_diagnostics():
    """Test that DrawingVariablesResult includes diagnostics field."""
    from dwg_forensic.parsers.drawing_vars import DrawingVariablesResult

    result = DrawingVariablesResult()
    assert hasattr(result, "diagnostics")
    assert result.diagnostics is None

    # Test with diagnostics populated
    diagnostics = ParseDiagnostics(version="AC1032", file_size=1000000)
    result.diagnostics = diagnostics

    result_dict = result.to_dict()
    assert "diagnostics" in result_dict
    assert result_dict["diagnostics"]["version"] == "AC1032"


def test_section_map_result_includes_tried_offsets():
    """Test that SectionMapResult includes tried_offsets field."""
    from dwg_forensic.parsers.sections import SectionMapResult

    result = SectionMapResult()
    assert hasattr(result, "tried_offsets")
    assert hasattr(result, "successful_offset")
    assert result.successful_offset is None
    assert len(result.tried_offsets) == 0

    # Test with offsets populated
    result.tried_offsets = [0x20, 0x40, 0x80]
    result.successful_offset = 0x80

    assert len(result.tried_offsets) == 3
    assert result.successful_offset == 0x80
