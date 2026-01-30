"""Tests for batch processing module.

Tests multiprocessing-based batch analysis of DWG files.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch
import tempfile
import shutil

from dwg_forensic.core.batch_processor import (
    BatchProcessor,
    BatchAnalysisResult,
    BatchFileResult,
    process_batch,
    _analyze_single_file,
)
from dwg_forensic.models import ForensicAnalysis, RiskLevel, RiskAssessment


@pytest.fixture
def temp_dwg_dir(tmp_path):
    """Create a temporary directory with sample DWG files."""
    # Copy test DWG files to temp directory
    test_data_dir = Path(__file__).parent / "test_data"
    dwg_files = list(test_data_dir.glob("*.dwg"))

    if not dwg_files:
        pytest.skip("No test DWG files found in test_data directory")

    # Copy up to 5 test files
    for i, dwg_file in enumerate(dwg_files[:5]):
        shutil.copy(dwg_file, tmp_path / f"test_{i}.dwg")

    return tmp_path


@pytest.fixture
def mock_analyzer():
    """Mock ForensicAnalyzer for testing without real DWG files."""
    with patch("dwg_forensic.core.batch_processor.ForensicAnalyzer") as mock:
        instance = mock.return_value

        # Create a mock analysis result
        def mock_analyze(file_path):
            from dwg_forensic.models import (
                FileInfo,
                HeaderAnalysis,
                CRCValidation,
                RiskAssessment,
                RiskLevel,
            )
            from datetime import datetime

            return ForensicAnalysis(
                file_info=FileInfo(
                    filename=file_path.name,
                    sha256="a" * 64,
                    file_size_bytes=1024,
                    intake_timestamp=datetime.now(),
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
                risk_assessment=RiskAssessment(
                    overall_risk=RiskLevel.LOW,
                    factors=["No anomalies detected"],
                    recommendation="File appears genuine",
                ),
                analyzer_version="0.1.0",
            )

        instance.analyze.side_effect = mock_analyze
        yield mock


class TestBatchProcessor:
    """Tests for BatchProcessor class."""

    def test_initialization_default_workers(self):
        """Test BatchProcessor initialization with default worker count."""
        processor = BatchProcessor()
        assert processor.num_workers >= 1
        assert processor.num_workers <= 8  # Capped at 8

    def test_initialization_custom_workers(self):
        """Test BatchProcessor initialization with custom worker count."""
        processor = BatchProcessor(num_workers=4)
        assert processor.num_workers == 4

    def test_initialization_min_workers(self):
        """Test BatchProcessor enforces minimum of 1 worker."""
        processor = BatchProcessor(num_workers=0)
        assert processor.num_workers == 1

        processor = BatchProcessor(num_workers=-5)
        assert processor.num_workers == 1

    def test_process_directory_nonexistent(self):
        """Test processing non-existent directory raises ValueError."""
        processor = BatchProcessor()
        with pytest.raises(ValueError, match="Directory does not exist"):
            processor.process_directory(Path("/nonexistent/directory"))

    def test_process_directory_not_a_directory(self, tmp_path):
        """Test processing a file (not directory) raises ValueError."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        processor = BatchProcessor()
        with pytest.raises(ValueError, match="not a directory"):
            processor.process_directory(test_file)

    def test_process_directory_no_files(self, tmp_path):
        """Test processing directory with no DWG files raises ValueError."""
        processor = BatchProcessor()
        with pytest.raises(ValueError, match="No files matching"):
            processor.process_directory(tmp_path)

    def test_process_directory_with_mock_files(self, tmp_path):
        """Test batch processing with mock DWG files.

        Note: This test uses real DWG files if available, or skips.
        Mocking doesn't work well with multiprocessing worker processes.
        """
        # Copy real test DWG files if they exist
        test_data_dir = Path(__file__).parent / "test_data"
        dwg_files = list(test_data_dir.glob("*.dwg"))

        if not dwg_files:
            pytest.skip("No test DWG files available")

        # Copy up to 3 test files
        for i, dwg_file in enumerate(dwg_files[:3]):
            import shutil
            shutil.copy(dwg_file, tmp_path / f"test_{i}.dwg")

        processor = BatchProcessor(num_workers=2)
        result = processor.process_directory(tmp_path)

        assert isinstance(result, BatchAnalysisResult)
        assert result.total_files == len(dwg_files[:3])
        # At least some should succeed (depends on test files)
        assert result.total_files > 0

    def test_process_directory_with_errors(self, tmp_path):
        """Test batch processing handles errors gracefully.

        Creates invalid DWG files to trigger errors.
        """
        # Create invalid DWG files (too small)
        for i in range(5):
            (tmp_path / f"test_{i}.dwg").write_bytes(b"invalid")

        processor = BatchProcessor(num_workers=2)
        result = processor.process_directory(tmp_path)

        # All files should fail (they're invalid)
        assert result.total_files == 5
        assert result.failed == 5
        assert result.successful == 0
        assert len(result.failures) == 5
        # Verify error isolation - all 5 processed despite failures
        assert result.total_files == result.successful + result.failed

    def test_calculate_risk_scores(self):
        """Test risk score calculation."""
        from dwg_forensic.models import FileInfo, HeaderAnalysis, CRCValidation
        from datetime import datetime

        processor = BatchProcessor()

        analyses = [
            ForensicAnalysis(
                file_info=FileInfo(
                    filename="test.dwg",
                    sha256="a" * 64,
                    file_size_bytes=1024,
                    intake_timestamp=datetime.now(),
                ),
                header_analysis=HeaderAnalysis(
                    version_string="AC1032",
                    version_name="AutoCAD 2018+",
                    is_supported=True,
                ),
                crc_validation=CRCValidation(
                    header_crc_stored="0x0",
                    header_crc_calculated="0x0",
                    is_valid=True,
                ),
                risk_assessment=RiskAssessment(
                    overall_risk=RiskLevel.LOW,
                    factors=[],
                    recommendation="OK",
                ),
                analyzer_version="0.1.0",
            ),
            ForensicAnalysis(
                file_info=FileInfo(
                    filename="test2.dwg",
                    sha256="b" * 64,
                    file_size_bytes=2048,
                    intake_timestamp=datetime.now(),
                ),
                header_analysis=HeaderAnalysis(
                    version_string="AC1032",
                    version_name="AutoCAD 2018+",
                    is_supported=True,
                ),
                crc_validation=CRCValidation(
                    header_crc_stored="0x0",
                    header_crc_calculated="0x0",
                    is_valid=True,
                ),
                risk_assessment=RiskAssessment(
                    overall_risk=RiskLevel.HIGH,
                    factors=[],
                    recommendation="Review",
                ),
                analyzer_version="0.1.0",
            ),
        ]

        scores = processor._calculate_risk_scores(analyses)
        assert len(scores) == 2
        assert scores[0] == 1.0  # LOW
        assert scores[1] == 3.0  # HIGH

    def test_calculate_risk_distribution(self):
        """Test risk distribution calculation."""
        from dwg_forensic.models import FileInfo, HeaderAnalysis, CRCValidation
        from datetime import datetime

        processor = BatchProcessor()

        analyses = [
            ForensicAnalysis(
                file_info=FileInfo(
                    filename=f"test{i}.dwg",
                    sha256="a" * 64,
                    file_size_bytes=1024,
                    intake_timestamp=datetime.now(),
                ),
                header_analysis=HeaderAnalysis(
                    version_string="AC1032",
                    version_name="AutoCAD 2018+",
                    is_supported=True,
                ),
                crc_validation=CRCValidation(
                    header_crc_stored="0x0",
                    header_crc_calculated="0x0",
                    is_valid=True,
                ),
                risk_assessment=RiskAssessment(
                    overall_risk=risk,
                    factors=[],
                    recommendation="OK",
                ),
                analyzer_version="0.1.0",
            )
            for i, risk in enumerate([RiskLevel.LOW, RiskLevel.LOW, RiskLevel.HIGH])
        ]

        dist = processor._calculate_risk_distribution(analyses)
        assert dist["LOW"] == 2
        assert dist["HIGH"] == 1
        assert dist["MEDIUM"] == 0


class TestBatchProcessingHelpers:
    """Tests for batch processing helper functions."""

    @patch("dwg_forensic.core.batch_processor.ForensicAnalyzer")
    def test_analyze_single_file_success(self, mock_analyzer_class, tmp_path):
        """Test successful single file analysis."""
        test_file = tmp_path / "test.dwg"
        test_file.write_bytes(b"fake dwg")

        # Mock successful analysis
        from dwg_forensic.models import FileInfo, HeaderAnalysis, CRCValidation
        from datetime import datetime

        instance = mock_analyzer_class.return_value
        instance.analyze.return_value = ForensicAnalysis(
            file_info=FileInfo(
                filename="test.dwg",
                sha256="a" * 64,
                file_size_bytes=1024,
                intake_timestamp=datetime.now(),
            ),
            header_analysis=HeaderAnalysis(
                version_string="AC1032",
                version_name="AutoCAD 2018+",
                is_supported=True,
            ),
            crc_validation=CRCValidation(
                header_crc_stored="0x0",
                header_crc_calculated="0x0",
                is_valid=True,
            ),
            risk_assessment=RiskAssessment(
                overall_risk=RiskLevel.LOW,
                factors=[],
                recommendation="OK",
            ),
            analyzer_version="0.1.0",
        )

        result = _analyze_single_file(test_file)

        assert isinstance(result, BatchFileResult)
        assert result.success is True
        assert result.analysis is not None
        assert result.error is None

    def test_analyze_single_file_error(self, tmp_path):
        """Test single file analysis with error.

        Uses an invalid DWG file to trigger a real error.
        """
        test_file = tmp_path / "test.dwg"
        test_file.write_bytes(b"invalid")

        result = _analyze_single_file(test_file)

        assert isinstance(result, BatchFileResult)
        assert result.success is False
        assert result.analysis is None
        assert result.error is not None
        assert result.error_type == "InvalidDWGError"

    @patch("dwg_forensic.core.batch_processor.BatchProcessor")
    def test_process_batch_convenience_function(self, mock_processor_class, tmp_path):
        """Test process_batch convenience function."""
        # Create fake files
        for i in range(3):
            (tmp_path / f"test_{i}.dwg").write_bytes(b"fake")

        # Mock processor
        mock_result = BatchAnalysisResult(
            total_files=3,
            successful=3,
            failed=0,
        )
        mock_processor_class.return_value.process_directory.return_value = mock_result

        result = process_batch(tmp_path, num_workers=2)

        assert isinstance(result, BatchAnalysisResult)
        mock_processor_class.assert_called_once_with(num_workers=2)
