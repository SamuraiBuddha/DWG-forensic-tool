"""Tests for DWG file comparison module.

Tests basic comparison functionality for Phase 3.1.
Deep structure comparison will be tested in Phase 3.2.
"""

import pytest
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from dwg_forensic.analysis.comparator import (
    DWGComparator,
    ComparisonResult,
    compare_dwg_files,
)
from dwg_forensic.models import (
    ForensicAnalysis,
    FileInfo,
    HeaderAnalysis,
    CRCValidation,
    RiskAssessment,
    RiskLevel,
    DWGMetadata,
)


@pytest.fixture
def mock_analysis1():
    """Create a mock ForensicAnalysis for file 1."""
    return ForensicAnalysis(
        file_info=FileInfo(
            filename="file1.dwg",
            sha256="a" * 64,
            file_size_bytes=1024,
            intake_timestamp=datetime(2024, 1, 1, 10, 0, 0),
        ),
        header_analysis=HeaderAnalysis(
            version_string="AC1032",
            version_name="AutoCAD 2018+",
            maintenance_version=0,
            codepage=30,
            is_supported=True,
        ),
        crc_validation=CRCValidation(
            header_crc_stored="0x12345678",
            header_crc_calculated="0x12345678",
            is_valid=True,
        ),
        metadata=DWGMetadata(
            author="Alice",
            last_saved_by="Alice",
            created_date=datetime(2024, 1, 1, 10, 0, 0),
            modified_date=datetime(2024, 1, 1, 12, 0, 0),
            revision_number=5,
        ),
        risk_assessment=RiskAssessment(
            overall_risk=RiskLevel.LOW,
            factors=["No anomalies detected"],
            recommendation="File appears genuine",
        ),
        analyzer_version="0.1.0",
    )


@pytest.fixture
def mock_analysis2():
    """Create a mock ForensicAnalysis for file 2."""
    return ForensicAnalysis(
        file_info=FileInfo(
            filename="file2.dwg",
            sha256="b" * 64,
            file_size_bytes=2048,
            intake_timestamp=datetime(2024, 1, 2, 10, 0, 0),
        ),
        header_analysis=HeaderAnalysis(
            version_string="AC1032",
            version_name="AutoCAD 2018+",
            maintenance_version=0,
            codepage=30,
            is_supported=True,
        ),
        crc_validation=CRCValidation(
            header_crc_stored="0x87654321",
            header_crc_calculated="0x87654321",
            is_valid=True,
        ),
        metadata=DWGMetadata(
            author="Alice",
            last_saved_by="Bob",
            created_date=datetime(2024, 1, 2, 10, 0, 0),
            modified_date=datetime(2024, 1, 2, 14, 0, 0),
            revision_number=6,
        ),
        risk_assessment=RiskAssessment(
            overall_risk=RiskLevel.MEDIUM,
            factors=["Minor anomaly detected"],
            recommendation="Review recommended",
        ),
        analyzer_version="0.1.0",
    )


class TestDWGComparator:
    """Tests for DWGComparator class."""

    def test_initialization(self):
        """Test DWGComparator initialization."""
        comparator = DWGComparator()
        assert comparator.analyzer is not None

    def test_compare_files_nonexistent(self):
        """Test comparing non-existent files raises ValueError."""
        comparator = DWGComparator()

        with pytest.raises(ValueError, match="File does not exist"):
            comparator.compare_files(Path("/nonexistent1.dwg"), Path("/nonexistent2.dwg"))

    @patch("dwg_forensic.core.analyzer.ForensicAnalyzer")
    def test_compare_files_basic(
        self, mock_analyzer_class, mock_analysis1, mock_analysis2, tmp_path
    ):
        """Test basic file comparison."""
        # Create fake DWG files
        file1 = tmp_path / "file1.dwg"
        file2 = tmp_path / "file2.dwg"
        file1.write_bytes(b"fake dwg 1")
        file2.write_bytes(b"fake dwg 2")

        # Mock analyzer to return our test analyses
        instance = mock_analyzer_class.return_value
        instance.analyze.side_effect = [mock_analysis1, mock_analysis2]

        comparator = DWGComparator()
        result = comparator.compare_files(file1, file2)

        assert isinstance(result, ComparisonResult)
        assert result.file1_analysis == mock_analysis1
        assert result.file2_analysis == mock_analysis2

    @patch("dwg_forensic.core.analyzer.ForensicAnalyzer")
    def test_timestamp_delta_calculation(
        self, mock_analyzer_class, mock_analysis1, mock_analysis2, tmp_path
    ):
        """Test timestamp delta calculation."""
        file1 = tmp_path / "file1.dwg"
        file2 = tmp_path / "file2.dwg"
        file1.write_bytes(b"fake dwg 1")
        file2.write_bytes(b"fake dwg 2")

        instance = mock_analyzer_class.return_value
        instance.analyze.side_effect = [mock_analysis1, mock_analysis2]

        comparator = DWGComparator()
        result = comparator.compare_files(file1, file2)

        # File 2 created 1 day after file 1
        assert result.timestamp_delta_seconds == 86400  # 1 day in seconds

    @patch("dwg_forensic.core.analyzer.ForensicAnalyzer")
    def test_modification_delta_calculation(
        self, mock_analyzer_class, mock_analysis1, mock_analysis2, tmp_path
    ):
        """Test modification timestamp delta calculation."""
        file1 = tmp_path / "file1.dwg"
        file2 = tmp_path / "file2.dwg"
        file1.write_bytes(b"fake dwg 1")
        file2.write_bytes(b"fake dwg 2")

        instance = mock_analyzer_class.return_value
        instance.analyze.side_effect = [mock_analysis1, mock_analysis2]

        comparator = DWGComparator()
        result = comparator.compare_files(file1, file2)

        # File 2 modified ~2 hours after file 1
        # File 1: Jan 1 12:00, File 2: Jan 2 14:00 = 26 hours
        expected_delta = 86400 + 7200  # 1 day + 2 hours
        assert result.modification_delta_seconds == expected_delta

    @patch("dwg_forensic.core.analyzer.ForensicAnalyzer")
    def test_metadata_changes_detection(
        self, mock_analyzer_class, mock_analysis1, mock_analysis2, tmp_path
    ):
        """Test detection of metadata changes."""
        file1 = tmp_path / "file1.dwg"
        file2 = tmp_path / "file2.dwg"
        file1.write_bytes(b"fake dwg 1")
        file2.write_bytes(b"fake dwg 2")

        instance = mock_analyzer_class.return_value
        instance.analyze.side_effect = [mock_analysis1, mock_analysis2]

        comparator = DWGComparator()
        result = comparator.compare_files(file1, file2)

        # Should detect last_saved_by change (Alice -> Bob)
        # and revision number increase (5 -> 6)
        assert len(result.metadata_changes) >= 2
        assert any("Last saved by" in change for change in result.metadata_changes)
        assert any("Revision number" in change for change in result.metadata_changes)

    @patch("dwg_forensic.core.analyzer.ForensicAnalyzer")
    def test_risk_level_change_detection(
        self, mock_analyzer_class, mock_analysis1, mock_analysis2, tmp_path
    ):
        """Test detection of risk level changes."""
        file1 = tmp_path / "file1.dwg"
        file2 = tmp_path / "file2.dwg"
        file1.write_bytes(b"fake dwg 1")
        file2.write_bytes(b"fake dwg 2")

        instance = mock_analyzer_class.return_value
        instance.analyze.side_effect = [mock_analysis1, mock_analysis2]

        comparator = DWGComparator()
        result = comparator.compare_files(file1, file2)

        # Risk level changed from LOW to MEDIUM
        assert result.risk_level_change == "LOW -> MEDIUM"

    @patch("dwg_forensic.core.analyzer.ForensicAnalyzer")
    def test_comparison_summary_generation(
        self, mock_analyzer_class, mock_analysis1, mock_analysis2, tmp_path
    ):
        """Test generation of comparison summary."""
        file1 = tmp_path / "file1.dwg"
        file2 = tmp_path / "file2.dwg"
        file1.write_bytes(b"fake dwg 1")
        file2.write_bytes(b"fake dwg 2")

        instance = mock_analyzer_class.return_value
        instance.analyze.side_effect = [mock_analysis1, mock_analysis2]

        comparator = DWGComparator()
        result = comparator.compare_files(file1, file2)

        assert result.comparison_summary
        assert "file1.dwg" in result.comparison_summary.lower()
        assert "file2.dwg" in result.comparison_summary.lower()
        assert "Risk Level Change" in result.comparison_summary

    @patch("dwg_forensic.core.analyzer.ForensicAnalyzer")
    def test_structure_changes_placeholder(
        self, mock_analyzer_class, mock_analysis1, mock_analysis2, tmp_path
    ):
        """Test that structure changes field exists (Phase 3.2 placeholder)."""
        file1 = tmp_path / "file1.dwg"
        file2 = tmp_path / "file2.dwg"
        file1.write_bytes(b"fake dwg 1")
        file2.write_bytes(b"fake dwg 2")

        instance = mock_analyzer_class.return_value
        instance.analyze.side_effect = [mock_analysis1, mock_analysis2]

        comparator = DWGComparator()
        result = comparator.compare_files(file1, file2)

        # Should have structure_changes dict (placeholder for Phase 3.2)
        assert isinstance(result.structure_changes, dict)
        assert "note" in result.structure_changes
        assert "Phase 3.2" in result.structure_changes["note"]


class TestComparisonHelpers:
    """Tests for comparison helper functions."""

    @patch("dwg_forensic.analysis.comparator.DWGComparator")
    def test_compare_dwg_files_convenience_function(self, mock_comparator_class, tmp_path):
        """Test compare_dwg_files convenience function."""
        file1 = tmp_path / "file1.dwg"
        file2 = tmp_path / "file2.dwg"
        file1.write_bytes(b"fake dwg 1")
        file2.write_bytes(b"fake dwg 2")

        # Mock comparator
        mock_result = Mock(spec=ComparisonResult)
        mock_comparator_class.return_value.compare_files.return_value = mock_result

        result = compare_dwg_files(file1, file2)

        assert result == mock_result
        mock_comparator_class.return_value.compare_files.assert_called_once_with(file1, file2)
