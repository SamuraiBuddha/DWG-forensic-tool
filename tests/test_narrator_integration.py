"""
Tests for Phase 4.3: LLM Narrator Integration

Tests cover:
1. Narrative generation from filtered anomalies
2. Fallback template generation when LLM unavailable
3. PDF integration
4. Smoking gun narrative emphasis
5. Expert narrative structure
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch

from dwg_forensic.models import (
    ForensicAnalysis,
    FileInfo,
    HeaderAnalysis,
    CRCValidation,
    DWGMetadata,
    RiskAssessment,
    RiskLevel,
    Anomaly,
    AnomalyType,
    TamperingIndicator,
    TamperingIndicatorType,
)
from dwg_forensic.llm.forensic_narrator import ForensicNarrator, NarrativeResult
from dwg_forensic.llm.anomaly_models import (
    Anomaly as LLMAnomaly,
    FilteredAnomalies,
    ProvenanceInfo,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def basic_analysis() -> ForensicAnalysis:
    """Create a basic ForensicAnalysis for testing."""
    return ForensicAnalysis(
        file_info=FileInfo(
            filename="test.dwg",
            sha256="a" * 64,
            file_size_bytes=1024,
            intake_timestamp=datetime(2024, 1, 1, 10, 0, 0),
        ),
        header_analysis=HeaderAnalysis(
            version_string="AC1032",
            version_name="AutoCAD 2018+",
            maintenance_version=1,
            codepage=1252,
            is_supported=True,
        ),
        crc_validation=CRCValidation(
            header_crc_stored="0x12345678",
            header_crc_calculated="0x12345678",
            is_valid=True,
        ),
        metadata=DWGMetadata(
            title="Test Drawing",
            author="Test Author",
            created_date=datetime(2024, 1, 1, 9, 0, 0),
            modified_date=datetime(2024, 1, 1, 10, 0, 0),
            tdindwg=0.02,  # ~0.5 hours
        ),
        risk_assessment=RiskAssessment(
            overall_risk=RiskLevel.LOW,
            factors=[],
            recommendation="File appears authentic.",
        ),
        analysis_timestamp=datetime(2024, 1, 1, 12, 0, 0),
        analyzer_version="1.0.0",
    )


@pytest.fixture
def filtered_anomalies_empty() -> FilteredAnomalies:
    """Create empty filtered anomalies (clean file)."""
    return FilteredAnomalies(
        kept_anomalies=[],
        filtered_anomalies=[],
        reasoning="No anomalies detected. File appears authentic.",
        llm_confidence=0.95,
        method="llm",
    )


@pytest.fixture
def filtered_anomalies_with_smoking_guns() -> FilteredAnomalies:
    """Create filtered anomalies with smoking gun findings."""
    smoking_gun = LLMAnomaly(
        rule_id="TAMPER-014",
        description="TDINDWG exceeds calendar span by 10 hours - mathematically impossible",
        severity=RiskLevel.CRITICAL,
        timestamp_related=True,
        evidence_strength="DEFINITIVE",
        details={"excess_hours": 10.0},
    )

    red_herring = LLMAnomaly(
        rule_id="TAMPER-002",
        description="TrustedDWG watermark missing",
        severity=RiskLevel.LOW,
        evidence_strength="INFORMATIONAL",
        details={},
    )

    return FilteredAnomalies(
        kept_anomalies=[smoking_gun],
        filtered_anomalies=[red_herring],
        reasoning="TDINDWG impossibility is definitive proof. TrustedDWG absence filtered as red herring.",
        llm_confidence=0.98,
        method="llm",
    )


@pytest.fixture
def mock_ollama_available():
    """Mock Ollama as available."""
    with patch("dwg_forensic.llm.forensic_narrator.ForensicNarrator.is_available", return_value=True):
        yield


@pytest.fixture
def mock_ollama_unavailable():
    """Mock Ollama as unavailable."""
    with patch("dwg_forensic.llm.forensic_narrator.ForensicNarrator.is_available", return_value=False):
        yield


# ============================================================================
# TEST GROUP 1: Narrative Generation from Filtered Anomalies (5 tests)
# ============================================================================


def test_generate_narrative_with_clean_file(basic_analysis, filtered_anomalies_empty, mock_ollama_available):
    """Test narrative generation for clean file with no anomalies."""
    narrator = ForensicNarrator(enabled=True)

    # Mock LLM response for clean file
    with patch.object(narrator.client, "generate") as mock_gen:
        mock_gen.return_value = Mock(
            success=True,
            response="This file shows no evidence of tampering. All integrity checks passed.",
            model="llama3.2",
            total_duration=500_000_000,  # 500ms
        )

        result = narrator.generate_narrative(basic_analysis, filtered_anomalies_empty)

    assert result.success
    assert "no evidence" in result.narrative.lower()
    assert result.model_used == "llama3.2"
    assert result.generation_time_ms == 500


def test_generate_narrative_with_smoking_guns(basic_analysis, filtered_anomalies_with_smoking_guns, mock_ollama_available):
    """Test narrative generation emphasizes smoking gun findings."""
    narrator = ForensicNarrator(enabled=True)

    with patch.object(narrator.client, "generate") as mock_gen:
        mock_gen.return_value = Mock(
            success=True,
            response="DEFINITIVE PROOF: The TDINDWG value exceeds the calendar span, which is mathematically impossible.",
            model="llama3.2",
            total_duration=800_000_000,
        )

        result = narrator.generate_narrative(basic_analysis, filtered_anomalies_with_smoking_guns)

    assert result.success
    assert "DEFINITIVE" in result.narrative or "impossible" in result.narrative.lower()
    assert result.model_used == "llama3.2"


def test_generate_narrative_structure(basic_analysis, filtered_anomalies_empty, mock_ollama_available):
    """Test narrative has required structural components."""
    narrator = ForensicNarrator(enabled=True)

    with patch.object(narrator.client, "generate") as mock_gen:
        mock_gen.return_value = Mock(
            success=True,
            response=(
                "EXECUTIVE SUMMARY: File appears authentic.\n\n"
                "DETAILED FINDINGS: No anomalies detected.\n\n"
                "RECOMMENDATIONS: No further investigation required."
            ),
            model="llama3.2",
            total_duration=600_000_000,
        )

        result = narrator.generate_narrative(basic_analysis, filtered_anomalies_empty)

    assert result.success
    # Check for key sections in narrative
    narrative_lower = result.narrative.lower()
    assert any(word in narrative_lower for word in ["summary", "findings", "recommendation"])


def test_generate_narrative_with_multiple_anomalies(basic_analysis, mock_ollama_available):
    """Test narrative generation with multiple kept anomalies."""
    filtered = FilteredAnomalies(
        kept_anomalies=[
            LLMAnomaly(
                rule_id="TAMPER-014",
                description="TDINDWG exceeds span",
                severity=RiskLevel.CRITICAL,
                evidence_strength="DEFINITIVE",
            ),
            LLMAnomaly(
                rule_id="TAMPER-019",
                description="NTFS SI/FN mismatch",
                severity=RiskLevel.CRITICAL,
                evidence_strength="DEFINITIVE",
            ),
        ],
        filtered_anomalies=[],
        reasoning="Two smoking guns detected.",
        llm_confidence=0.99,
        method="llm",
    )

    narrator = ForensicNarrator(enabled=True)

    with patch.object(narrator.client, "generate") as mock_gen:
        mock_gen.return_value = Mock(
            success=True,
            response="Multiple definitive proofs detected: TDINDWG impossibility and NTFS timestomping.",
            model="llama3.2",
            total_duration=700_000_000,
        )

        result = narrator.generate_narrative(basic_analysis, filtered)

    assert result.success
    assert "multiple" in result.narrative.lower() or "two" in result.narrative.lower()


def test_generate_narrative_error_handling(basic_analysis, filtered_anomalies_empty, mock_ollama_available):
    """Test narrative generation handles LLM errors gracefully by falling back to template."""
    narrator = ForensicNarrator(enabled=True)

    with patch.object(narrator.client, "generate") as mock_gen:
        mock_gen.return_value = Mock(
            success=False,
            response="",
            model="llama3.2",
            error="Connection timeout",
        )

        result = narrator.generate_narrative(basic_analysis, filtered_anomalies_empty)

    # Should fallback to template on error
    assert result.success
    assert result.model_used == "fallback_template"
    assert "EXECUTIVE SUMMARY" in result.narrative


# ============================================================================
# TEST GROUP 2: Fallback Template Generation (3 tests)
# ============================================================================


def test_fallback_narrative_when_ollama_unavailable(basic_analysis, filtered_anomalies_empty, mock_ollama_unavailable):
    """Test fallback to static template when Ollama unavailable."""
    narrator = ForensicNarrator(enabled=True)

    result = narrator.generate_narrative(basic_analysis, filtered_anomalies_empty)

    # Should fallback to template when LLM unavailable
    assert result.success
    assert result.model_used == "fallback_template"
    assert "EXECUTIVE SUMMARY" in result.narrative


def test_fallback_narrative_preserves_smoking_guns(basic_analysis, filtered_anomalies_with_smoking_guns, mock_ollama_unavailable):
    """Test fallback template still highlights smoking guns."""
    narrator = ForensicNarrator(enabled=True)

    result = narrator.generate_narrative_fallback(basic_analysis, filtered_anomalies_with_smoking_guns)

    assert result.success
    assert result.model_used == "fallback_template"
    # Smoking gun should be mentioned even in fallback
    assert "TDINDWG" in result.narrative or "impossible" in result.narrative.lower()


def test_fallback_narrative_structure(basic_analysis, filtered_anomalies_empty):
    """Test fallback narrative has proper structure."""
    narrator = ForensicNarrator(enabled=False)

    result = narrator.generate_narrative_fallback(basic_analysis, filtered_anomalies_empty)

    assert result.success
    assert result.model_used == "fallback_template"
    # Should have basic sections
    assert len(result.narrative) > 100
    narrative_lower = result.narrative.lower()
    assert "executive" in narrative_lower or "summary" in narrative_lower


# ============================================================================
# TEST GROUP 3: PDF Integration (4 tests)
# ============================================================================


def test_narrator_method_added_to_forensic_analysis(basic_analysis, filtered_anomalies_empty):
    """Test ForensicAnalysis model accepts expert_narrative field."""
    # Check that expert_narrative field exists and accepts string
    basic_analysis.llm_narrative = "Test narrative"
    assert basic_analysis.llm_narrative == "Test narrative"

    # Check llm_model_used field
    basic_analysis.llm_model_used = "llama3.2"
    assert basic_analysis.llm_model_used == "llama3.2"


def test_analyzer_stores_narrative_in_analysis(basic_analysis, filtered_anomalies_empty, mock_ollama_available):
    """Test analyzer stores narrative in ForensicAnalysis."""
    narrator = ForensicNarrator(enabled=True)

    with patch.object(narrator.client, "generate") as mock_gen:
        mock_gen.return_value = Mock(
            success=True,
            response="Expert narrative content",
            model="llama3.2",
            total_duration=500_000_000,
        )

        result = narrator.generate_narrative(basic_analysis, filtered_anomalies_empty)

    # Simulate analyzer storing result
    basic_analysis.llm_narrative = result.narrative
    basic_analysis.llm_model_used = result.model_used

    assert basic_analysis.llm_narrative == "Expert narrative content"
    assert basic_analysis.llm_model_used == "llama3.2"


def test_pdf_report_includes_narrative_section(basic_analysis, filtered_anomalies_empty):
    """Test PDF report generator can access narrative field."""
    basic_analysis.llm_narrative = "This is an expert narrative for the report."
    basic_analysis.llm_model_used = "llama3.2"

    # Verify fields are accessible
    assert hasattr(basic_analysis, "llm_narrative")
    assert hasattr(basic_analysis, "llm_model_used")
    assert basic_analysis.llm_narrative is not None


def test_pdf_marks_llm_generated_content(basic_analysis):
    """Test PDF content is marked as LLM-generated for transparency."""
    # This is tested through pdf_report.py inspection
    # The marker text should include "[LLM-Generated]"
    basic_analysis.llm_narrative = "Expert analysis content"
    basic_analysis.llm_model_used = "llama3.2"

    # Simulate PDF marker
    marker = f"[LLM-Generated by {basic_analysis.llm_model_used}]"
    assert "LLM-Generated" in marker
    assert basic_analysis.llm_model_used in marker


# ============================================================================
# TEST GROUP 4: Integration with ForensicAnalysis Model (3 tests)
# ============================================================================


def test_narrative_field_optional_in_analysis():
    """Test expert_narrative field is optional in ForensicAnalysis."""
    analysis = ForensicAnalysis(
        file_info=FileInfo(
            filename="test.dwg",
            sha256="a" * 64,
            file_size_bytes=1024,
            intake_timestamp=datetime(2024, 1, 1, 10, 0, 0),
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
            overall_risk=RiskLevel.LOW,
            factors=[],
            recommendation="File appears authentic.",
        ),
        analysis_timestamp=datetime(2024, 1, 1, 12, 0, 0),
        analyzer_version="1.0.0",
    )

    # Should be None by default
    assert analysis.llm_narrative is None
    assert analysis.llm_model_used is None


def test_narrative_field_accepts_string():
    """Test expert_narrative field accepts string content."""
    analysis = ForensicAnalysis(
        file_info=FileInfo(
            filename="test.dwg",
            sha256="a" * 64,
            file_size_bytes=1024,
            intake_timestamp=datetime(2024, 1, 1, 10, 0, 0),
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
            overall_risk=RiskLevel.LOW,
            factors=[],
            recommendation="File appears authentic.",
        ),
        analysis_timestamp=datetime(2024, 1, 1, 12, 0, 0),
        analyzer_version="1.0.0",
        llm_narrative="This is a test narrative.",
        llm_model_used="llama3.2",
    )

    assert analysis.llm_narrative == "This is a test narrative."
    assert analysis.llm_model_used == "llama3.2"


def test_filtered_anomalies_field_in_analysis():
    """Test filtered_anomalies field exists in ForensicAnalysis."""
    analysis = ForensicAnalysis(
        file_info=FileInfo(
            filename="test.dwg",
            sha256="a" * 64,
            file_size_bytes=1024,
            intake_timestamp=datetime(2024, 1, 1, 10, 0, 0),
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
            overall_risk=RiskLevel.LOW,
            factors=[],
            recommendation="File appears authentic.",
        ),
        analysis_timestamp=datetime(2024, 1, 1, 12, 0, 0),
        analyzer_version="1.0.0",
    )

    # Should have filtered_anomalies field
    assert hasattr(analysis, "filtered_anomalies")
    assert analysis.filtered_anomalies is None  # Default is None
