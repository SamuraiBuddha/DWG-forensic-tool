"""
Tests for Batch LLM Processing (Phase 4.4)

Validates:
- Risk-based sampling logic
- Async inference (with mock Ollama)
- Batch result aggregation
- Error handling
- Edge cases
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import List

from dwg_forensic.llm.batch_processor import (
    BatchLLMProcessor,
    BatchLLMResult,
    _calculate_risk_score,
    _classify_file_type,
    process_batch_llm,
)
from dwg_forensic.models import (
    ForensicAnalysis,
    FileInfo,
    HeaderAnalysis,
    CRCValidation,
    RiskAssessment,
    RiskLevel,
    ApplicationFingerprint,
)
from datetime import datetime


@pytest.fixture
def mock_ollama_client():
    """Mock Ollama client for testing."""
    client = Mock()
    client.is_available.return_value = True
    client.model = "mistral"
    return client


@pytest.fixture
def sample_analysis(tmp_path) -> ForensicAnalysis:
    """Create a sample ForensicAnalysis for testing."""
    return ForensicAnalysis(
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
            header_crc_stored="0x12345678",
            header_crc_calculated="0x12345678",
            is_valid=True,
        ),
        risk_assessment=RiskAssessment(
            overall_risk=RiskLevel.MEDIUM,
            factors=["Test factor"],
            recommendation="Review",
        ),
        analyzer_version="1.0.0",
    )


@pytest.fixture
def sample_analyses(tmp_path) -> List[ForensicAnalysis]:
    """Create multiple sample analyses with varying risk levels."""
    analyses = []

    # Create 5 analyses with different risk levels
    risk_levels = [
        RiskLevel.INFO,
        RiskLevel.LOW,
        RiskLevel.MEDIUM,
        RiskLevel.HIGH,
        RiskLevel.CRITICAL,
    ]

    for i, risk in enumerate(risk_levels):
        analysis = ForensicAnalysis(
            file_info=FileInfo(
                filename=f"test_{i}.dwg",
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
                header_crc_stored="0x12345678",
                header_crc_calculated="0x12345678",
                is_valid=True,
            ),
            risk_assessment=RiskAssessment(
                overall_risk=risk,
                factors=["Test factor"],
                recommendation="Review",
            ),
            analyzer_version="1.0.0",
        )
        analyses.append(analysis)

    return analyses


class TestRiskScoring:
    """Test risk score calculation."""

    def test_calculate_risk_score_info(self, sample_analysis):
        """Test INFO risk level scoring."""
        sample_analysis.risk_assessment.overall_risk = RiskLevel.INFO
        score = _calculate_risk_score(sample_analysis)
        assert score == 0.0

    def test_calculate_risk_score_low(self, sample_analysis):
        """Test LOW risk level scoring."""
        sample_analysis.risk_assessment.overall_risk = RiskLevel.LOW
        score = _calculate_risk_score(sample_analysis)
        assert score == 1.0

    def test_calculate_risk_score_medium(self, sample_analysis):
        """Test MEDIUM risk level scoring."""
        sample_analysis.risk_assessment.overall_risk = RiskLevel.MEDIUM
        score = _calculate_risk_score(sample_analysis)
        assert score == 2.0

    def test_calculate_risk_score_high(self, sample_analysis):
        """Test HIGH risk level scoring."""
        sample_analysis.risk_assessment.overall_risk = RiskLevel.HIGH
        score = _calculate_risk_score(sample_analysis)
        assert score == 3.0

    def test_calculate_risk_score_critical(self, sample_analysis):
        """Test CRITICAL risk level scoring."""
        sample_analysis.risk_assessment.overall_risk = RiskLevel.CRITICAL
        score = _calculate_risk_score(sample_analysis)
        assert score == 4.0


class TestFileTypeClassification:
    """Test file type classification for grouping."""

    def test_classify_autocad(self, sample_analysis):
        """Test AutoCAD file classification."""
        sample_analysis.application_fingerprint = ApplicationFingerprint(
            detected_application="AutoCAD",
            confidence=1.0,
            is_autodesk=True,
        )
        file_type = _classify_file_type(sample_analysis)
        assert file_type == "autocad"

    def test_classify_revit(self, sample_analysis):
        """Test Revit export classification."""
        sample_analysis.revit_detection = {"is_revit": True}
        file_type = _classify_file_type(sample_analysis)
        assert file_type == "revit"

    def test_classify_bricscad(self, sample_analysis):
        """Test BricsCAD file classification."""
        sample_analysis.application_fingerprint = ApplicationFingerprint(
            detected_application="BricsCAD",
            confidence=0.9,
            is_autodesk=False,
        )
        file_type = _classify_file_type(sample_analysis)
        assert file_type == "bricscad"

    def test_classify_default(self, sample_analysis):
        """Test default classification when no fingerprint."""
        file_type = _classify_file_type(sample_analysis)
        assert file_type == "autocad"


class TestRiskBasedFiltering:
    """Test risk-based sampling logic."""

    def test_filter_by_risk_threshold_03(self, sample_analyses, tmp_path):
        """Test filtering with threshold 0.3 (skip INFO, include LOW and above)."""
        processor = BatchLLMProcessor()
        file_paths = [tmp_path / f"test_{i}.dwg" for i in range(len(sample_analyses))]

        filtered = processor._filter_by_risk(sample_analyses, file_paths, 0.3)

        # Using >= comparison, so includes LOW (1.0), MEDIUM (2.0), HIGH (3.0), CRITICAL (4.0)
        # Excludes INFO (0.0)
        assert len(filtered) == 4

    def test_filter_by_risk_threshold_20(self, sample_analyses, tmp_path):
        """Test filtering with threshold 2.0 (include MEDIUM and above)."""
        processor = BatchLLMProcessor()
        file_paths = [tmp_path / f"test_{i}.dwg" for i in range(len(sample_analyses))]

        filtered = processor._filter_by_risk(sample_analyses, file_paths, 2.0)

        # Using >= comparison, so includes MEDIUM (2.0), HIGH (3.0), CRITICAL (4.0)
        # Excludes INFO (0.0), LOW (1.0)
        assert len(filtered) == 3

    def test_filter_by_risk_threshold_zero(self, sample_analyses, tmp_path):
        """Test filtering with threshold 0.0 (include all)."""
        processor = BatchLLMProcessor()
        file_paths = [tmp_path / f"test_{i}.dwg" for i in range(len(sample_analyses))]

        filtered = processor._filter_by_risk(sample_analyses, file_paths, 0.0)

        # Should include all 5 files
        assert len(filtered) == 5

    def test_filter_by_risk_threshold_high(self, sample_analyses, tmp_path):
        """Test filtering with very high threshold (exclude most)."""
        processor = BatchLLMProcessor()
        file_paths = [tmp_path / f"test_{i}.dwg" for i in range(len(sample_analyses))]

        filtered = processor._filter_by_risk(sample_analyses, file_paths, 4.0)

        # Should only include CRITICAL (4.0)
        assert len(filtered) == 1


class TestFileTypeGrouping:
    """Test file type grouping logic."""

    def test_group_by_type_mixed(self, sample_analyses, tmp_path):
        """Test grouping with mixed file types."""
        processor = BatchLLMProcessor()

        # Assign different app fingerprints
        sample_analyses[0].application_fingerprint = ApplicationFingerprint(
            detected_application="AutoCAD", confidence=1.0, is_autodesk=True
        )
        sample_analyses[1].application_fingerprint = ApplicationFingerprint(
            detected_application="BricsCAD", confidence=0.9, is_autodesk=False
        )
        sample_analyses[2].revit_detection = {"is_revit": True}

        file_paths = [tmp_path / f"test_{i}.dwg" for i in range(3)]
        pairs = list(zip(sample_analyses[:3], file_paths))

        groups = processor._group_by_type(pairs)

        # Should have 3 groups: autocad, bricscad, revit
        assert len(groups) == 3
        assert "autocad" in groups
        assert "bricscad" in groups
        assert "revit" in groups

    def test_group_by_type_all_autocad(self, sample_analyses, tmp_path):
        """Test grouping when all files are AutoCAD."""
        processor = BatchLLMProcessor()

        file_paths = [tmp_path / f"test_{i}.dwg" for i in range(len(sample_analyses))]
        pairs = list(zip(sample_analyses, file_paths))

        groups = processor._group_by_type(pairs)

        # Should have 1 group: autocad (default)
        assert len(groups) == 1
        assert "autocad" in groups
        assert len(groups["autocad"]) == len(sample_analyses)


class TestBatchProcessing:
    """Test batch LLM processing."""

    @patch('dwg_forensic.llm.batch_processor.ForensicNarrator')
    def test_process_batch_success(self, mock_narrator_class, sample_analyses, tmp_path, mock_ollama_client):
        """Test successful batch processing."""
        # Mock narrator
        mock_narrator = Mock()
        mock_narrator.generate_narrative.return_value = "Test narrative"
        mock_narrator_class.return_value = mock_narrator

        processor = BatchLLMProcessor(ollama_client=mock_ollama_client)
        file_paths = [tmp_path / f"test_{i}.dwg" for i in range(len(sample_analyses))]

        result = processor.process_batch(sample_analyses, file_paths, risk_threshold=0.3)

        # Should process 4 files (LOW, MEDIUM, HIGH, CRITICAL) with threshold 0.3 (using >=)
        assert result.total_files == len(sample_analyses)
        assert result.processed_files == 4
        assert result.skipped_files == 1  # Only INFO is skipped
        assert len(result.narratives) == 4

    @patch('dwg_forensic.llm.batch_processor.ForensicNarrator')
    def test_process_batch_ollama_unavailable(self, mock_narrator_class, sample_analyses, tmp_path):
        """Test batch processing when Ollama is unavailable."""
        mock_client = Mock()
        mock_client.is_available.return_value = False

        processor = BatchLLMProcessor(ollama_client=mock_client)
        file_paths = [tmp_path / f"test_{i}.dwg" for i in range(len(sample_analyses))]

        result = processor.process_batch(sample_analyses, file_paths)

        # Should skip all LLM processing
        assert result.processed_files == 0
        assert len(result.narratives) == 0

    @patch('dwg_forensic.llm.batch_processor.ForensicNarrator')
    def test_process_batch_narrative_failure(self, mock_narrator_class, sample_analyses, tmp_path, mock_ollama_client):
        """Test batch processing with some narrative generation failures."""
        # Mock narrator that fails for some files
        mock_narrator = Mock()
        call_count = [0]

        def generate_narrative_side_effect(analysis):
            call_count[0] += 1
            if call_count[0] == 2:
                raise Exception("Generation failed")
            return "Test narrative"

        mock_narrator.generate_narrative.side_effect = generate_narrative_side_effect
        mock_narrator_class.return_value = mock_narrator

        processor = BatchLLMProcessor(ollama_client=mock_ollama_client)
        file_paths = [tmp_path / f"test_{i}.dwg" for i in range(len(sample_analyses))]

        result = processor.process_batch(sample_analyses, file_paths, risk_threshold=0.3)

        # Should process 4 files (LOW, MEDIUM, HIGH, CRITICAL), but 1 fails
        assert result.total_files == len(sample_analyses)
        assert result.processed_files == 3  # 3 succeed, 1 fails
        assert result.failed_files == 1

    def test_process_batch_mismatched_lengths(self, sample_analyses, tmp_path):
        """Test batch processing with mismatched input lengths."""
        processor = BatchLLMProcessor()
        file_paths = [tmp_path / "test.dwg"]  # Only 1 path, but 5 analyses

        with pytest.raises(ValueError, match="same length"):
            processor.process_batch(sample_analyses, file_paths)


class TestConvenienceFunction:
    """Test convenience function."""

    @patch('dwg_forensic.llm.batch_processor.BatchLLMProcessor')
    def test_process_batch_llm_function(self, mock_processor_class, sample_analyses, tmp_path):
        """Test process_batch_llm convenience function."""
        mock_processor = Mock()
        mock_result = BatchLLMResult(total_files=5, processed_files=3)
        mock_processor.process_batch.return_value = mock_result
        mock_processor_class.return_value = mock_processor

        file_paths = [tmp_path / f"test_{i}.dwg" for i in range(len(sample_analyses))]

        result = process_batch_llm(
            sample_analyses,
            file_paths,
            risk_threshold=0.5,
            model="llama3",
            max_concurrent=3,
        )

        # Verify processor was created with correct params
        mock_processor_class.assert_called_once_with(model="llama3", max_concurrent=3)

        # Verify process_batch was called
        mock_processor.process_batch.assert_called_once_with(
            sample_analyses,
            file_paths,
            0.5,
        )

        assert result.total_files == 5
        assert result.processed_files == 3


class TestBatchLLMResult:
    """Test BatchLLMResult data structure."""

    def test_batch_llm_result_creation(self):
        """Test creating BatchLLMResult."""
        result = BatchLLMResult(
            narratives={"test.dwg": "narrative"},
            total_files=10,
            processed_files=7,
            skipped_files=2,
            failed_files=1,
            processing_time_seconds=30.5,
            model_used="mistral",
        )

        assert len(result.narratives) == 1
        assert result.total_files == 10
        assert result.processed_files == 7
        assert result.skipped_files == 2
        assert result.failed_files == 1
        assert result.processing_time_seconds == 30.5
        assert result.model_used == "mistral"

    def test_batch_llm_result_defaults(self):
        """Test BatchLLMResult default values."""
        result = BatchLLMResult()

        assert result.narratives == {}
        assert result.total_files == 0
        assert result.processed_files == 0
        assert result.skipped_files == 0
        assert result.failed_files == 0
        assert result.processing_time_seconds == 0.0
        assert result.model_used == ""
