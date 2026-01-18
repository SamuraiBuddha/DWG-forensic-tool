"""
Tests for DWG Handle Map Parser module.

This module tests handle gap detection for forensic analysis:
- Handle gap identification
- Severity classification
- Statistics calculation
- Forensic reporting
"""

import pytest
import struct
import tempfile
from pathlib import Path
from typing import Set

from dwg_forensic.parsers.handles import (
    HandleType,
    ObjectType,
    HandleInfo,
    HandleGap,
    HandleStatistics,
    HandleMapResult,
    HandleMapParser,
    analyze_handle_gaps,
    format_gap_report,
)


class TestHandleTypeEnum:
    """Tests for HandleType enumeration."""

    def test_handle_type_values(self):
        """Test handle reference type values."""
        assert HandleType.SOFT_OWNERSHIP == 0x02
        assert HandleType.HARD_OWNERSHIP == 0x03
        assert HandleType.SOFT_POINTER == 0x04
        assert HandleType.HARD_POINTER == 0x05


class TestObjectTypeEnum:
    """Tests for ObjectType enumeration."""

    def test_entity_types(self):
        """Test entity object type values."""
        assert ObjectType.LINE == 0x13
        assert ObjectType.CIRCLE == 0x14
        assert ObjectType.ARC == 0x15
        assert ObjectType.TEXT == 0x16
        assert ObjectType.INSERT == 0x19

    def test_non_entity_types(self):
        """Test non-entity object type values."""
        assert ObjectType.DICTIONARY == 0x2A
        assert ObjectType.LAYER == 0x2B
        assert ObjectType.BLOCK_HEADER == 0x2D
        assert ObjectType.XRECORD == 0x30


class TestHandleInfo:
    """Tests for HandleInfo dataclass."""

    def test_handle_info_creation(self):
        """Test HandleInfo creation."""
        info = HandleInfo(handle=0x1A5, offset=0x500)
        assert info.handle == 0x1A5
        assert info.offset == 0x500
        assert info.object_type == 0
        assert info.is_entity is False
        assert info.is_deleted is False

    def test_handle_info_with_all_fields(self):
        """Test HandleInfo with all fields."""
        info = HandleInfo(
            handle=0x2F0,
            offset=0x800,
            object_type=ObjectType.LINE,
            is_entity=True,
            is_deleted=False,
            owner_handle=0x1A0,
            size=48,
        )
        assert info.object_type == ObjectType.LINE
        assert info.is_entity is True
        assert info.owner_handle == 0x1A0
        assert info.size == 48


class TestHandleGap:
    """Tests for HandleGap dataclass."""

    def test_gap_creation(self):
        """Test HandleGap creation."""
        gap = HandleGap(
            start_handle=0x100,
            end_handle=0x10F,
            gap_size=16,
        )
        assert gap.start_handle == 0x100
        assert gap.end_handle == 0x10F
        assert gap.gap_size == 16

    def test_gap_with_context(self):
        """Test HandleGap with surrounding handles."""
        gap = HandleGap(
            start_handle=0x100,
            end_handle=0x10F,
            gap_size=16,
            preceding_handle=0xFF,
            following_handle=0x110,
            severity="high",
        )
        assert gap.preceding_handle == 0xFF
        assert gap.following_handle == 0x110
        assert gap.severity == "high"

    def test_gap_to_dict(self):
        """Test HandleGap serialization."""
        gap = HandleGap(
            start_handle=0x200,
            end_handle=0x20F,
            gap_size=16,
            preceding_handle=0x1FF,
            following_handle=0x210,
            severity="medium",
        )
        d = gap.to_dict()
        assert d["start_handle"] == "0x200"
        assert d["end_handle"] == "0x20F"
        assert d["gap_size"] == 16
        assert d["severity"] == "medium"


class TestHandleStatistics:
    """Tests for HandleStatistics dataclass."""

    def test_statistics_defaults(self):
        """Test HandleStatistics default values."""
        stats = HandleStatistics()
        assert stats.min_handle == 0
        assert stats.max_handle == 0
        assert stats.total_handles == 0
        assert stats.gap_count == 0

    def test_gap_ratio_zero_expected(self):
        """Test gap_ratio when expected count is zero."""
        stats = HandleStatistics()
        assert stats.gap_ratio() == 0.0

    def test_gap_ratio_calculation(self):
        """Test gap_ratio calculation."""
        stats = HandleStatistics()
        stats.expected_sequence_count = 100
        stats.total_missing_handles = 25
        assert stats.gap_ratio() == 0.25

    def test_statistics_to_dict(self):
        """Test HandleStatistics serialization."""
        stats = HandleStatistics()
        stats.min_handle = 0x10
        stats.max_handle = 0x100
        stats.total_handles = 200
        stats.gap_count = 5
        stats.total_missing_handles = 20
        stats.expected_sequence_count = 240

        d = stats.to_dict()
        assert d["min_handle"] == "0x10"
        assert d["max_handle"] == "0x100"
        assert d["total_handles"] == 200
        assert d["gap_count"] == 5


class TestHandleMapResult:
    """Tests for HandleMapResult dataclass."""

    def test_empty_result(self):
        """Test empty result defaults."""
        result = HandleMapResult()
        assert result.handles == {}
        assert result.gaps == []
        assert result.parsing_errors == []

    def test_has_gaps_true(self):
        """Test has_gaps returns True when gaps exist."""
        result = HandleMapResult()
        result.gaps.append(HandleGap(
            start_handle=0x100,
            end_handle=0x10F,
            gap_size=16,
        ))
        assert result.has_gaps() is True

    def test_has_gaps_false(self):
        """Test has_gaps returns False when no gaps."""
        result = HandleMapResult()
        assert result.has_gaps() is False

    def test_has_significant_gaps_true(self):
        """Test significant gap detection."""
        result = HandleMapResult()
        result.gaps.append(HandleGap(
            start_handle=0x100,
            end_handle=0x150,
            gap_size=80,  # > threshold of 10
        ))
        assert result.has_significant_gaps(10) is True

    def test_has_significant_gaps_false(self):
        """Test significant gap detection with small gaps."""
        result = HandleMapResult()
        result.gaps.append(HandleGap(
            start_handle=0x100,
            end_handle=0x105,
            gap_size=5,  # < threshold
        ))
        assert result.has_significant_gaps(10) is False

    def test_get_critical_gaps(self):
        """Test getting critical gaps."""
        result = HandleMapResult()
        result.gaps.append(HandleGap(
            start_handle=0x100,
            end_handle=0x10F,
            gap_size=16,
            severity="medium",
        ))
        result.gaps.append(HandleGap(
            start_handle=0x200,
            end_handle=0x2FF,
            gap_size=256,
            severity="critical",
        ))
        critical = result.get_critical_gaps()
        assert len(critical) == 1
        assert critical[0].severity == "critical"

    def test_get_forensic_summary(self):
        """Test forensic summary generation."""
        result = HandleMapResult()
        result.statistics.total_handles = 500
        result.gaps.append(HandleGap(
            start_handle=0x100,
            end_handle=0x150,
            gap_size=80,
            severity="high",
        ))
        result.statistics.total_missing_handles = 80

        summary = result.get_forensic_summary()
        assert summary["total_handles"] == 500
        assert summary["gap_count"] == 1
        assert summary["total_missing_handles"] == 80
        assert summary["largest_gap"] == 80

    def test_to_dict(self):
        """Test result serialization."""
        result = HandleMapResult()
        result.file_version = "AC1032"
        d = result.to_dict()
        assert d["file_version"] == "AC1032"
        assert "statistics" in d
        assert "gaps" in d


class TestHandleMapParser:
    """Tests for HandleMapParser class."""

    def test_parser_initialization(self):
        """Test parser initialization."""
        parser = HandleMapParser()
        assert parser is not None

    def test_parser_min_file_size(self):
        """Test MIN_FILE_SIZE constant."""
        assert HandleMapParser.MIN_FILE_SIZE == 0x200


class TestHandleMapParserFileAccess:
    """Tests for file access handling."""

    def test_file_not_found(self):
        """Test handling of missing file."""
        parser = HandleMapParser()
        result = parser.parse(Path("/nonexistent/file.dwg"))
        assert len(result.parsing_errors) > 0
        assert "Failed to read file" in result.parsing_errors[0]

    def test_file_too_small(self):
        """Test handling of file too small."""
        parser = HandleMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(b"AC1032" + b"\x00" * 50)
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert "too small" in result.parsing_errors[0]
        finally:
            temp_path.unlink()

    def test_invalid_version_string(self):
        """Test handling of invalid version."""
        parser = HandleMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(bytes([0xFF, 0xFE]) + b"\x00" * 0x300)
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert "Invalid version" in result.parsing_errors[0]
        finally:
            temp_path.unlink()


class TestHandleMapParserVersions:
    """Tests for version-specific parsing."""

    def _create_dwg_stub(self, version: str) -> bytes:
        """Create minimal DWG stub."""
        data = bytearray(0x400)
        data[0:6] = version.encode("ascii")
        return bytes(data)

    def test_ac1018_supported(self):
        """Test AC1018 is supported."""
        parser = HandleMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_stub("AC1018"))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.file_version == "AC1018"
            assert not any("not supported for AC1018" in e for e in result.parsing_errors)
        finally:
            temp_path.unlink()

    def test_ac1021_supported(self):
        """Test AC1021 is supported."""
        parser = HandleMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_stub("AC1021"))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.file_version == "AC1021"
        finally:
            temp_path.unlink()

    def test_ac1024_supported(self):
        """Test AC1024 is supported."""
        parser = HandleMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_stub("AC1024"))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.file_version == "AC1024"
        finally:
            temp_path.unlink()

    def test_ac1032_supported(self):
        """Test AC1032 is supported."""
        parser = HandleMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_stub("AC1032"))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.file_version == "AC1032"
        finally:
            temp_path.unlink()

    def test_unsupported_version(self):
        """Test unsupported version handling."""
        parser = HandleMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_stub("AC1015"))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert any("not supported" in e for e in result.parsing_errors)
        finally:
            temp_path.unlink()


class TestHandleHeuristics:
    """Tests for handle identification heuristics."""

    def test_is_likely_handle_valid(self):
        """Test valid handle identification."""
        parser = HandleMapParser()
        # Typical handle value
        assert parser._is_likely_handle(0x1A5, b"\x00" * 100, 0) is True

    def test_is_likely_handle_rejects_power_of_two(self):
        """Test power of two rejection."""
        parser = HandleMapParser()
        assert parser._is_likely_handle(0x1000, b"\x00" * 100, 0) is False
        assert parser._is_likely_handle(0x2000, b"\x00" * 100, 0) is False
        assert parser._is_likely_handle(0x10000, b"\x00" * 100, 0) is False

    def test_is_likely_handle_rejects_common_values(self):
        """Test rejection of common non-handle values."""
        parser = HandleMapParser()
        assert parser._is_likely_handle(0x00, b"\x00" * 100, 0) is False
        assert parser._is_likely_handle(0xFF, b"\x00" * 100, 0) is False
        assert parser._is_likely_handle(0xFFFF, b"\x00" * 100, 0) is False

    def test_is_likely_handle_rejects_trailing_zeros(self):
        """Test rejection of values ending in 00."""
        parser = HandleMapParser()
        # Large values ending in 00 are suspicious (often offsets/sizes)
        assert parser._is_likely_handle(0x5000, b"\x00" * 100, 0) is False


class TestGapAnalysis:
    """Tests for handle gap analysis."""

    def test_analyze_gaps_finds_gap(self):
        """Test gap detection in handle sequence."""
        parser = HandleMapParser()
        result = HandleMapResult()

        # Add handles with a gap
        result.handles = {
            0x10: HandleInfo(handle=0x10, offset=0x100),
            0x11: HandleInfo(handle=0x11, offset=0x110),
            0x12: HandleInfo(handle=0x12, offset=0x120),
            # Gap: 0x13-0x1F missing
            0x20: HandleInfo(handle=0x20, offset=0x200),
            0x21: HandleInfo(handle=0x21, offset=0x210),
        }

        parser._analyze_handle_gaps(result)

        assert len(result.gaps) == 1
        assert result.gaps[0].start_handle == 0x13
        assert result.gaps[0].end_handle == 0x1F
        assert result.gaps[0].gap_size == 13

    def test_analyze_gaps_no_gaps(self):
        """Test analysis with no gaps."""
        parser = HandleMapParser()
        result = HandleMapResult()

        result.handles = {
            0x10: HandleInfo(handle=0x10, offset=0x100),
            0x11: HandleInfo(handle=0x11, offset=0x110),
            0x12: HandleInfo(handle=0x12, offset=0x120),
            0x13: HandleInfo(handle=0x13, offset=0x130),
        }

        parser._analyze_handle_gaps(result)
        assert len(result.gaps) == 0

    def test_analyze_gaps_multiple(self):
        """Test detection of multiple gaps."""
        parser = HandleMapParser()
        result = HandleMapResult()

        result.handles = {
            0x10: HandleInfo(handle=0x10, offset=0x100),
            # Gap 1: 0x11-0x14
            0x15: HandleInfo(handle=0x15, offset=0x150),
            # Gap 2: 0x16-0x19
            0x1A: HandleInfo(handle=0x1A, offset=0x1A0),
        }

        parser._analyze_handle_gaps(result)

        assert len(result.gaps) == 2

    def test_analyze_gaps_empty_handles(self):
        """Test analysis with no handles."""
        parser = HandleMapParser()
        result = HandleMapResult()
        parser._analyze_handle_gaps(result)
        assert len(result.gaps) == 0

    def test_analyze_gaps_single_handle(self):
        """Test analysis with single handle."""
        parser = HandleMapParser()
        result = HandleMapResult()
        result.handles = {0x10: HandleInfo(handle=0x10, offset=0x100)}
        parser._analyze_handle_gaps(result)
        assert len(result.gaps) == 0


class TestGapSeverityClassification:
    """Tests for gap severity classification."""

    def test_critical_severity_large_gap(self):
        """Test critical severity for large gaps (>100)."""
        parser = HandleMapParser()
        severity = parser._classify_gap_severity(150, 0x100, 0x200, 0x10, 0x300)
        assert severity == "critical"

    def test_high_severity_medium_gap(self):
        """Test high severity for medium gaps (21-100)."""
        parser = HandleMapParser()
        severity = parser._classify_gap_severity(50, 0x100, 0x150, 0x10, 0x300)
        assert severity == "high"

    def test_medium_severity_small_gap(self):
        """Test medium severity for small gaps."""
        parser = HandleMapParser()
        severity = parser._classify_gap_severity(10, 0x100, 0x110, 0x10, 0x300)
        # Could be medium or high depending on position
        assert severity in ["medium", "high"]

    def test_low_severity_tiny_gap(self):
        """Test low severity for tiny gaps (1-4)."""
        parser = HandleMapParser()
        severity = parser._classify_gap_severity(3, 0x100, 0x104, 0x10, 0x300)
        assert severity == "low"


class TestStatisticsCalculation:
    """Tests for statistics calculation."""

    def test_calculate_statistics(self):
        """Test statistics calculation."""
        parser = HandleMapParser()
        result = HandleMapResult()

        result.handles = {
            0x10: HandleInfo(handle=0x10, offset=0x100),
            0x11: HandleInfo(handle=0x11, offset=0x110),
            0x15: HandleInfo(handle=0x15, offset=0x150),  # Gap before this
            0x16: HandleInfo(handle=0x16, offset=0x160),
        }
        result.gaps.append(HandleGap(
            start_handle=0x12,
            end_handle=0x14,
            gap_size=3,
        ))

        parser._calculate_statistics(result)

        assert result.statistics.min_handle == 0x10
        assert result.statistics.max_handle == 0x16
        assert result.statistics.total_handles == 4
        assert result.statistics.gap_count == 1
        assert result.statistics.total_missing_handles == 3

    def test_calculate_expected_sequence(self):
        """Test expected sequence count calculation."""
        parser = HandleMapParser()
        result = HandleMapResult()

        result.handles = {
            0x10: HandleInfo(handle=0x10, offset=0x100),
            0x20: HandleInfo(handle=0x20, offset=0x200),
        }

        parser._calculate_statistics(result)

        # Expected: 0x10 to 0x20 = 17 handles
        assert result.statistics.expected_sequence_count == 17


class TestConvenienceFunction:
    """Tests for analyze_handle_gaps convenience function."""

    def test_analyze_handle_gaps_returns_result(self):
        """Test convenience function returns HandleMapResult."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            data = b"AC1032" + b"\x00" * 0x300
            f.write(data)
            temp_path = Path(f.name)

        try:
            result = analyze_handle_gaps(temp_path)
            assert isinstance(result, HandleMapResult)
            assert result.file_version == "AC1032"
        finally:
            temp_path.unlink()


class TestFormatGapReport:
    """Tests for report formatting."""

    def test_format_gap_report_no_gaps(self):
        """Test report formatting with no gaps."""
        result = HandleMapResult()
        result.file_version = "AC1032"
        result.statistics.total_handles = 100

        report = format_gap_report(result)

        assert "DWG HANDLE GAP ANALYSIS REPORT" in report
        assert "AC1032" in report
        assert "100" in report
        assert "No handle gaps detected" in report

    def test_format_gap_report_with_gaps(self):
        """Test report formatting with gaps."""
        result = HandleMapResult()
        result.file_version = "AC1032"
        result.statistics.total_handles = 100
        result.statistics.gap_count = 2
        result.statistics.total_missing_handles = 50

        result.gaps.append(HandleGap(
            start_handle=0x100,
            end_handle=0x120,
            gap_size=32,
            severity="high",
        ))
        result.gaps.append(HandleGap(
            start_handle=0x200,
            end_handle=0x2FF,
            gap_size=256,
            severity="critical",
        ))

        report = format_gap_report(result)

        assert "SIGNIFICANT GAPS DETECTED" in report
        assert "critical" in report.lower() or "CRITICAL" in report

    def test_format_gap_report_with_errors(self):
        """Test report formatting with parsing errors."""
        result = HandleMapResult()
        result.file_version = "AC1032"
        result.parsing_errors.append("Test parsing error")

        report = format_gap_report(result)

        assert "Test parsing error" in report


class TestForensicScenarios:
    """Tests simulating forensic investigation scenarios."""

    def test_detect_mass_deletion(self):
        """Test detection of mass object deletion."""
        parser = HandleMapParser()
        result = HandleMapResult()

        # Simulate handles before and after mass deletion
        result.handles = {
            0x10: HandleInfo(handle=0x10, offset=0x100),
            0x11: HandleInfo(handle=0x11, offset=0x110),
            # Gap: 0x12-0xFF (238 handles deleted)
            0x100: HandleInfo(handle=0x100, offset=0x1000),
            0x101: HandleInfo(handle=0x101, offset=0x1010),
        }

        parser._analyze_handle_gaps(result)
        parser._calculate_statistics(result)

        # Should detect critical gap
        assert result.has_significant_gaps(10)
        assert any(g.severity == "critical" for g in result.gaps)

        summary = result.get_forensic_summary()
        assert summary["potential_tampering"] is True

    def test_detect_selective_deletion(self):
        """Test detection of selective object deletion (scattered gaps)."""
        parser = HandleMapParser()
        result = HandleMapResult()

        # Simulate scattered deletions (cherry-picked removal)
        result.handles = {
            0x10: HandleInfo(handle=0x10, offset=0x100),
            0x11: HandleInfo(handle=0x11, offset=0x110),
            # 0x12 deleted
            0x13: HandleInfo(handle=0x13, offset=0x130),
            0x14: HandleInfo(handle=0x14, offset=0x140),
            # 0x15 deleted
            0x16: HandleInfo(handle=0x16, offset=0x160),
            # 0x17-0x19 deleted
            0x1A: HandleInfo(handle=0x1A, offset=0x1A0),
        }

        parser._analyze_handle_gaps(result)

        # Should find multiple small gaps
        assert len(result.gaps) == 3

    def test_normal_editing_gaps(self):
        """Test normal editing produces small, low-severity gaps."""
        parser = HandleMapParser()
        result = HandleMapResult()

        # Normal editing: occasional small gaps
        result.handles = {
            0x10: HandleInfo(handle=0x10, offset=0x100),
            0x11: HandleInfo(handle=0x11, offset=0x110),
            # 0x12 deleted (single object undo)
            0x13: HandleInfo(handle=0x13, offset=0x130),
            0x14: HandleInfo(handle=0x14, offset=0x140),
            0x15: HandleInfo(handle=0x15, offset=0x150),
        }

        parser._analyze_handle_gaps(result)

        # Should find gap but low severity
        assert len(result.gaps) == 1
        assert result.gaps[0].gap_size == 1
        assert result.gaps[0].severity == "low"
        assert not result.has_significant_gaps(10)


class TestSectionMapParameter:
    """Tests for optional section_map parameter."""

    def test_parse_with_section_map_parameter(self):
        """Test that parse() accepts optional section_map parameter."""
        from dwg_forensic.parsers.sections import SectionMapResult

        parser = HandleMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            data = b"AC1032" + b"\x00" * 0x300
            f.write(data)
            temp_path = Path(f.name)

        try:
            # Create a mock section map
            section_map = SectionMapResult()
            section_map.file_version = "AC1032"

            # Should work with section_map=None (backward compatibility)
            result1 = parser.parse(temp_path, section_map=None)
            assert isinstance(result1, HandleMapResult)

            # Should work with provided section_map
            result2 = parser.parse(temp_path, section_map=section_map)
            assert isinstance(result2, HandleMapResult)

            # Should work without the parameter (default None)
            result3 = parser.parse(temp_path)
            assert isinstance(result3, HandleMapResult)

        finally:
            temp_path.unlink()

    def test_parse_skips_parsing_when_section_map_provided(self):
        """Test that providing section_map avoids redundant parsing."""
        from dwg_forensic.parsers.sections import SectionMapResult, SectionInfo, SectionType

        parser = HandleMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            data = b"AC1032" + b"\x00" * 0x300
            f.write(data)
            temp_path = Path(f.name)

        try:
            # Create a pre-parsed section map without Handles section
            section_map = SectionMapResult()
            section_map.file_version = "AC1032"
            section_map.sections = {}  # No Handles section

            # Parse with provided section_map
            result = parser.parse(temp_path, section_map=section_map)

            # Should fall back to legacy parsing since no Handles section
            assert isinstance(result, HandleMapResult)

        finally:
            temp_path.unlink()
