"""
Tests for LLM module (Ollama client and Forensic Narrator).

This module tests the LLM integration components used for generating
forensic analysis narratives.
"""

import json
import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, patch, MagicMock
from urllib.error import URLError, HTTPError

from dwg_forensic.llm.ollama_client import OllamaClient, OllamaResponse
from dwg_forensic.llm.forensic_narrator import (
    ForensicNarrator,
    NarrativeResult,
    FORENSIC_EXPERT_SYSTEM_PROMPT_TEMPLATE,
    FULL_ANALYSIS_PROMPT,
)
from dwg_forensic.models import (
    ForensicAnalysis,
    FileInfo,
    HeaderAnalysis,
    CRCValidation,
    TrustedDWGAnalysis,
    RiskAssessment,
    RiskLevel,
    DWGMetadata,
    NTFSTimestampAnalysis,
    Anomaly,
    AnomalyType,
    TamperingIndicator,
    TamperingIndicatorType,
)


# =============================================================================
# OllamaResponse Tests
# =============================================================================


class TestOllamaResponse:
    """Tests for OllamaResponse dataclass."""

    def test_default_values(self):
        """Test OllamaResponse with minimal required fields."""
        response = OllamaResponse(
            response="Test response",
            model="phi4",
        )
        assert response.response == "Test response"
        assert response.model == "phi4"
        assert response.total_duration is None
        assert response.eval_count is None
        assert response.success is True
        assert response.error is None

    def test_all_fields(self):
        """Test OllamaResponse with all fields populated."""
        response = OllamaResponse(
            response="Analysis complete",
            model="phi4:latest",
            total_duration=5000000000,
            eval_count=150,
            success=True,
            error=None,
        )
        assert response.response == "Analysis complete"
        assert response.model == "phi4:latest"
        assert response.total_duration == 5000000000
        assert response.eval_count == 150
        assert response.success is True

    def test_error_response(self):
        """Test OllamaResponse with error state."""
        response = OllamaResponse(
            response="",
            model="phi4",
            success=False,
            error="Connection refused",
        )
        assert response.response == ""
        assert response.success is False
        assert response.error == "Connection refused"


# =============================================================================
# OllamaClient Tests
# =============================================================================


class TestOllamaClientInit:
    """Tests for OllamaClient initialization."""

    def test_default_initialization(self):
        """Test OllamaClient with default settings."""
        client = OllamaClient()
        assert client.base_url == "http://127.0.0.1:11434"
        assert client.model == "phi4"
        assert client.timeout == 120

    def test_custom_base_url(self):
        """Test OllamaClient with custom base URL."""
        client = OllamaClient(base_url="http://localhost:8080")
        assert client.base_url == "http://localhost:8080"

    def test_base_url_trailing_slash_removed(self):
        """Test that trailing slashes are removed from base URL."""
        client = OllamaClient(base_url="http://localhost:8080/")
        assert client.base_url == "http://localhost:8080"

    def test_custom_model(self):
        """Test OllamaClient with custom model."""
        client = OllamaClient(model="llama3.2")
        assert client.model == "llama3.2"

    def test_custom_timeout(self):
        """Test OllamaClient with custom timeout."""
        client = OllamaClient(timeout=300)
        assert client.timeout == 300


class TestOllamaClientIsAvailable:
    """Tests for OllamaClient.is_available method."""

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_is_available_success(self, mock_urlopen):
        """Test is_available returns True when Ollama responds."""
        mock_response = Mock()
        mock_response.status = 200
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = OllamaClient()
        assert client.is_available() is True

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_is_available_url_error(self, mock_urlopen):
        """Test is_available returns False on URLError."""
        mock_urlopen.side_effect = URLError("Connection refused")

        client = OllamaClient()
        assert client.is_available() is False

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_is_available_http_error(self, mock_urlopen):
        """Test is_available returns False on HTTPError."""
        mock_urlopen.side_effect = HTTPError(
            url="http://test", code=500, msg="Server Error", hdrs={}, fp=None
        )

        client = OllamaClient()
        assert client.is_available() is False

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_is_available_timeout(self, mock_urlopen):
        """Test is_available returns False on timeout."""
        mock_urlopen.side_effect = TimeoutError()

        client = OllamaClient()
        assert client.is_available() is False


class TestOllamaClientGetVersion:
    """Tests for OllamaClient.get_version method."""

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_get_version_success(self, mock_urlopen):
        """Test get_version returns version string."""
        mock_response = Mock()
        mock_response.read.return_value = json.dumps({"version": "0.3.12"}).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = OllamaClient()
        assert client.get_version() == "0.3.12"

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_get_version_connection_error(self, mock_urlopen):
        """Test get_version returns None on connection error."""
        mock_urlopen.side_effect = URLError("Connection refused")

        client = OllamaClient()
        assert client.get_version() is None

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_get_version_invalid_json(self, mock_urlopen):
        """Test get_version returns None on invalid JSON."""
        mock_response = Mock()
        mock_response.read.return_value = b"not json"
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = OllamaClient()
        assert client.get_version() is None


class TestOllamaClientListModels:
    """Tests for OllamaClient.list_models method."""

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_list_models_success(self, mock_urlopen):
        """Test list_models returns model names."""
        mock_response = Mock()
        mock_response.read.return_value = json.dumps({
            "models": [
                {"name": "phi4:latest"},
                {"name": "llama3.2:latest"},
                {"name": "mistral:7b"},
            ]
        }).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = OllamaClient()
        models = client.list_models()
        assert "phi4:latest" in models
        assert "llama3.2:latest" in models
        assert "mistral:7b" in models

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_list_models_empty(self, mock_urlopen):
        """Test list_models returns empty list when no models."""
        mock_response = Mock()
        mock_response.read.return_value = json.dumps({"models": []}).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = OllamaClient()
        models = client.list_models()
        assert models == []

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_list_models_connection_error(self, mock_urlopen):
        """Test list_models returns empty list on error."""
        mock_urlopen.side_effect = URLError("Connection refused")

        client = OllamaClient()
        models = client.list_models()
        assert models == []


class TestOllamaClientIsModelAvailable:
    """Tests for OllamaClient.is_model_available method."""

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_model_available_exact_match(self, mock_urlopen):
        """Test model availability with exact name match."""
        mock_response = Mock()
        mock_response.read.return_value = json.dumps({
            "models": [{"name": "phi4:latest"}]
        }).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = OllamaClient()
        assert client.is_model_available("phi4:latest") is True

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_model_available_base_name_match(self, mock_urlopen):
        """Test model availability with base name matching tag version."""
        mock_response = Mock()
        mock_response.read.return_value = json.dumps({
            "models": [{"name": "phi4:latest"}]
        }).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = OllamaClient()
        assert client.is_model_available("phi4") is True

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_model_not_available(self, mock_urlopen):
        """Test model availability when model not found."""
        mock_response = Mock()
        mock_response.read.return_value = json.dumps({
            "models": [{"name": "llama3.2:latest"}]
        }).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = OllamaClient()
        assert client.is_model_available("phi4") is False

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_model_available_uses_default(self, mock_urlopen):
        """Test is_model_available uses default model when none specified."""
        mock_response = Mock()
        mock_response.read.return_value = json.dumps({
            "models": [{"name": "phi4:latest"}]
        }).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = OllamaClient(model="phi4")
        assert client.is_model_available() is True


class TestOllamaClientGenerate:
    """Tests for OllamaClient.generate method."""

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_generate_success(self, mock_urlopen):
        """Test successful text generation."""
        mock_response = Mock()
        mock_response.read.return_value = json.dumps({
            "response": "This is the generated analysis.",
            "model": "phi4",
            "total_duration": 5000000000,
            "eval_count": 150,
        }).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = OllamaClient()
        result = client.generate("Analyze this data")

        assert result.success is True
        assert result.response == "This is the generated analysis."
        assert result.model == "phi4"
        assert result.total_duration == 5000000000
        assert result.eval_count == 150

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_generate_with_system_prompt(self, mock_urlopen):
        """Test generation with system prompt."""
        mock_response = Mock()
        mock_response.read.return_value = json.dumps({
            "response": "Expert analysis here.",
            "model": "phi4",
        }).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = OllamaClient()
        result = client.generate(
            prompt="Analyze CRC",
            system_prompt="You are a forensic expert.",
        )

        assert result.success is True
        assert result.response == "Expert analysis here."

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_generate_with_custom_model(self, mock_urlopen):
        """Test generation with custom model override."""
        mock_response = Mock()
        mock_response.read.return_value = json.dumps({
            "response": "Analysis result",
            "model": "llama3.2",
        }).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = OllamaClient(model="phi4")
        result = client.generate(
            prompt="Test",
            model="llama3.2",
        )

        assert result.success is True
        assert result.model == "llama3.2"

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_generate_http_error(self, mock_urlopen):
        """Test generate handles HTTP errors."""
        mock_urlopen.side_effect = HTTPError(
            url="http://test",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=None,
        )

        client = OllamaClient()
        result = client.generate("Test prompt")

        assert result.success is False
        assert result.response == ""
        assert "HTTP error 500" in result.error

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_generate_connection_error(self, mock_urlopen):
        """Test generate handles connection errors."""
        mock_urlopen.side_effect = URLError("Connection refused")

        client = OllamaClient()
        result = client.generate("Test prompt")

        assert result.success is False
        assert result.response == ""
        assert "Connection error" in result.error

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_generate_timeout(self, mock_urlopen):
        """Test generate handles timeout."""
        mock_urlopen.side_effect = TimeoutError()

        client = OllamaClient(timeout=30)
        result = client.generate("Test prompt")

        assert result.success is False
        assert "timed out" in result.error

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_generate_invalid_json(self, mock_urlopen):
        """Test generate handles invalid JSON response."""
        mock_response = Mock()
        mock_response.read.return_value = b"not valid json"
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = OllamaClient()
        result = client.generate("Test")

        assert result.success is False
        assert "Invalid JSON" in result.error

    @patch("dwg_forensic.llm.ollama_client.urlopen")
    def test_generate_with_max_tokens(self, mock_urlopen):
        """Test generation with max_tokens parameter."""
        mock_response = Mock()
        mock_response.read.return_value = json.dumps({
            "response": "Short response",
            "model": "phi4",
        }).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = OllamaClient()
        result = client.generate(
            prompt="Test",
            max_tokens=100,
        )

        assert result.success is True


# =============================================================================
# NarrativeResult Tests
# =============================================================================


class TestNarrativeResult:
    """Tests for NarrativeResult dataclass."""

    def test_successful_result(self):
        """Test NarrativeResult for successful generation."""
        result = NarrativeResult(
            narrative="Full forensic analysis narrative here.",
            success=True,
            model_used="phi4",
            generation_time_ms=5000,
        )
        assert result.narrative == "Full forensic analysis narrative here."
        assert result.success is True
        assert result.model_used == "phi4"
        assert result.generation_time_ms == 5000
        assert result.error is None

    def test_failed_result(self):
        """Test NarrativeResult for failed generation."""
        result = NarrativeResult(
            narrative="",
            success=False,
            model_used="phi4",
            error="Ollama not available",
        )
        assert result.narrative == ""
        assert result.success is False
        assert result.error == "Ollama not available"


# =============================================================================
# ForensicNarrator Tests
# =============================================================================


def create_mock_analysis() -> ForensicAnalysis:
    """Create a mock ForensicAnalysis for testing."""
    return ForensicAnalysis(
        file_info=FileInfo(
            filename="test_drawing.dwg",
            file_size_bytes=102400,
            sha256="abc123def456789012345678901234567890123456789012345678901234abcd",
            intake_timestamp=datetime.now(timezone.utc),
        ),
        header_analysis=HeaderAnalysis(
            version_string="AC1032",
            version_name="AutoCAD 2018",
            maintenance_version=3,
            codepage=30,
            preview_address=0,
            is_supported=True,
        ),
        crc_validation=CRCValidation(
            header_crc_stored="0x12345678",
            header_crc_calculated="0x12345678",
            is_valid=True,
        ),
        trusted_dwg=TrustedDWGAnalysis(
            watermark_present=True,
            watermark_valid=True,
            watermark_text="Autodesk DWG",
            application_origin="AutoCAD 2024",
        ),
        risk_assessment=RiskAssessment(
            overall_risk=RiskLevel.LOW,
            factors=["File integrity verified"],
            recommendation="File appears authentic",
        ),
        anomalies=[],
        tampering_indicators=[],
        analysis_timestamp=datetime.now(timezone.utc),
        analyzer_version="1.0.0-test",
    )


def create_mock_analysis_with_tampering() -> ForensicAnalysis:
    """Create a mock ForensicAnalysis with tampering indicators."""
    analysis = create_mock_analysis()
    analysis.crc_validation.is_valid = False
    analysis.crc_validation.header_crc_calculated = "0xDEADBEEF"
    analysis.risk_assessment.overall_risk = RiskLevel.HIGH
    analysis.risk_assessment.factors = ["CRC mismatch detected"]
    analysis.tampering_indicators = [
        TamperingIndicator(
            indicator_type=TamperingIndicatorType.CRC_MODIFIED,
            description="Header CRC does not match calculated value",
            confidence=1.0,
            evidence="Stored: 0x12345678, Calculated: 0xDEADBEEF",
        )
    ]
    analysis.anomalies = [
        Anomaly(
            anomaly_type=AnomalyType.CRC_MISMATCH,
            description="CRC validation failed",
            severity=RiskLevel.CRITICAL,
            details={"stored": "0x12345678", "calculated": "0xDEADBEEF"},
        )
    ]
    return analysis


class TestForensicNarratorInit:
    """Tests for ForensicNarrator initialization."""

    def test_default_initialization(self):
        """Test ForensicNarrator with default settings."""
        narrator = ForensicNarrator()
        assert narrator.enabled is True
        assert narrator.client is not None
        assert narrator._ollama_available is None

    def test_disabled_narrator(self):
        """Test ForensicNarrator when disabled."""
        narrator = ForensicNarrator(enabled=False)
        assert narrator.enabled is False

    def test_custom_client(self):
        """Test ForensicNarrator with custom client."""
        custom_client = OllamaClient(model="llama3.2")
        narrator = ForensicNarrator(ollama_client=custom_client)
        assert narrator.client is custom_client

    def test_custom_model(self):
        """Test ForensicNarrator with custom model."""
        narrator = ForensicNarrator(model="llama3.2")
        assert narrator.client.model == "llama3.2"

    def test_custom_expert_name(self):
        """Test ForensicNarrator with custom expert name."""
        narrator = ForensicNarrator(expert_name="Jordan P Ehrig, Sr.")
        assert narrator.expert_name == "Jordan P Ehrig, Sr."

    def test_default_expert_name(self):
        """Test ForensicNarrator uses default expert name."""
        narrator = ForensicNarrator()
        assert narrator.expert_name == "Digital Forensics Expert"

    def test_get_system_prompt_uses_expert_name(self):
        """Test _get_system_prompt includes the expert name."""
        narrator = ForensicNarrator(expert_name="Jordan P Ehrig, Sr.")
        system_prompt = narrator._get_system_prompt()
        assert "Jordan P Ehrig, Sr." in system_prompt
        assert "{expert_name}" not in system_prompt


class TestForensicNarratorIsAvailable:
    """Tests for ForensicNarrator.is_available method."""

    def test_not_available_when_disabled(self):
        """Test is_available returns False when disabled."""
        narrator = ForensicNarrator(enabled=False)
        assert narrator.is_available() is False

    @patch.object(OllamaClient, "is_available", return_value=True)
    def test_available_when_ollama_running(self, mock_is_available):
        """Test is_available returns True when Ollama is running."""
        narrator = ForensicNarrator()
        assert narrator.is_available() is True

    @patch.object(OllamaClient, "is_available", return_value=False)
    def test_not_available_when_ollama_not_running(self, mock_is_available):
        """Test is_available returns False when Ollama is not running."""
        narrator = ForensicNarrator()
        assert narrator.is_available() is False

    @patch.object(OllamaClient, "is_available", return_value=True)
    def test_is_available_cached(self, mock_is_available):
        """Test that is_available result is cached."""
        narrator = ForensicNarrator()
        narrator.is_available()
        narrator.is_available()
        narrator.is_available()
        # Should only call once due to caching
        assert mock_is_available.call_count == 1


class TestForensicNarratorGenerateFullAnalysis:
    """Tests for ForensicNarrator.generate_full_analysis method."""

    def test_not_available_returns_failure(self):
        """Test generate returns failure when LLM not available."""
        narrator = ForensicNarrator(enabled=False)
        analysis = create_mock_analysis()

        result = narrator.generate_full_analysis(analysis)

        assert result.success is False
        assert "not available" in result.narrative
        assert result.model_used == "none"

    @patch.object(OllamaClient, "is_available", return_value=True)
    @patch.object(OllamaClient, "generate")
    def test_successful_generation(self, mock_generate, mock_is_available):
        """Test successful full analysis generation."""
        mock_generate.return_value = OllamaResponse(
            response="Comprehensive forensic analysis narrative.",
            model="phi4",
            total_duration=5000000000,
            success=True,
        )

        narrator = ForensicNarrator()
        analysis = create_mock_analysis()

        result = narrator.generate_full_analysis(analysis)

        assert result.success is True
        assert "forensic analysis" in result.narrative
        assert result.model_used == "phi4"
        assert result.generation_time_ms == 5000

    @patch.object(OllamaClient, "is_available", return_value=True)
    @patch.object(OllamaClient, "generate")
    def test_generation_with_tampering(self, mock_generate, mock_is_available):
        """Test full analysis with tampering indicators."""
        mock_generate.return_value = OllamaResponse(
            response="DEFINITIVE PROOF OF TAMPERING detected.",
            model="phi4",
            total_duration=6000000000,
            success=True,
        )

        narrator = ForensicNarrator()
        analysis = create_mock_analysis_with_tampering()

        result = narrator.generate_full_analysis(analysis)

        assert result.success is True
        assert "TAMPERING" in result.narrative

    @patch.object(OllamaClient, "is_available", return_value=True)
    @patch.object(OllamaClient, "generate")
    def test_generation_failure(self, mock_generate, mock_is_available):
        """Test handling of generation failure."""
        mock_generate.return_value = OllamaResponse(
            response="",
            model="phi4",
            success=False,
            error="Model overloaded",
        )

        narrator = ForensicNarrator()
        analysis = create_mock_analysis()

        result = narrator.generate_full_analysis(analysis)

        assert result.success is False
        assert result.error == "Model overloaded"

    @patch.object(OllamaClient, "is_available", return_value=True)
    @patch.object(OllamaClient, "generate")
    def test_empty_response_handled(self, mock_generate, mock_is_available):
        """Test handling of empty response."""
        mock_generate.return_value = OllamaResponse(
            response="   ",
            model="phi4",
            success=True,
        )

        narrator = ForensicNarrator()
        analysis = create_mock_analysis()

        result = narrator.generate_full_analysis(analysis)

        # Empty response after strip should be treated as failure
        assert result.success is False


class TestForensicNarratorGenerateSectionAnalysis:
    """Tests for ForensicNarrator.generate_section_analysis method."""

    def test_section_not_available_returns_failure(self):
        """Test section analysis returns failure when LLM not available."""
        narrator = ForensicNarrator(enabled=False)
        analysis = create_mock_analysis()

        result = narrator.generate_section_analysis(analysis, "crc")

        assert result.success is False

    @patch.object(OllamaClient, "is_available", return_value=True)
    @patch.object(OllamaClient, "generate")
    def test_crc_section_analysis(self, mock_generate, mock_is_available):
        """Test CRC section analysis."""
        mock_generate.return_value = OllamaResponse(
            response="CRC validation analysis shows integrity verified.",
            model="phi4",
            success=True,
        )

        narrator = ForensicNarrator()
        analysis = create_mock_analysis()

        result = narrator.generate_section_analysis(analysis, "crc")

        assert result.success is True
        assert "CRC" in result.narrative

    @patch.object(OllamaClient, "is_available", return_value=True)
    @patch.object(OllamaClient, "generate")
    def test_watermark_section_analysis(self, mock_generate, mock_is_available):
        """Test watermark section analysis."""
        mock_generate.return_value = OllamaResponse(
            response="TrustedDWG watermark is present and valid.",
            model="phi4",
            success=True,
        )

        narrator = ForensicNarrator()
        analysis = create_mock_analysis()

        result = narrator.generate_section_analysis(analysis, "watermark")

        assert result.success is True
        assert "watermark" in result.narrative.lower()

    @patch.object(OllamaClient, "is_available", return_value=True)
    @patch.object(OllamaClient, "generate")
    def test_timestamps_section_analysis(self, mock_generate, mock_is_available):
        """Test timestamps section analysis."""
        mock_generate.return_value = OllamaResponse(
            response="Timestamp analysis reveals no anomalies.",
            model="phi4",
            success=True,
        )

        narrator = ForensicNarrator()
        analysis = create_mock_analysis()

        result = narrator.generate_section_analysis(analysis, "timestamps")

        assert result.success is True
        assert "Timestamp" in result.narrative

    @patch.object(OllamaClient, "is_available", return_value=True)
    @patch.object(OllamaClient, "generate")
    def test_summary_section_analysis(self, mock_generate, mock_is_available):
        """Test summary section analysis."""
        mock_generate.return_value = OllamaResponse(
            response="Executive summary: File integrity confirmed.",
            model="phi4",
            success=True,
        )

        narrator = ForensicNarrator()
        analysis = create_mock_analysis()

        result = narrator.generate_section_analysis(analysis, "summary")

        assert result.success is True
        assert "summary" in result.narrative.lower()

    @patch.object(OllamaClient, "is_available", return_value=True)
    @patch.object(OllamaClient, "generate")
    def test_unknown_section_handled(self, mock_generate, mock_is_available):
        """Test unknown section name is handled."""
        mock_generate.return_value = OllamaResponse(
            response="Analysis of unknown section.",
            model="phi4",
            success=True,
        )

        narrator = ForensicNarrator()
        analysis = create_mock_analysis()

        result = narrator.generate_section_analysis(analysis, "unknown_section")

        assert result.success is True


class TestForensicNarratorBuildPrompt:
    """Tests for ForensicNarrator._build_full_analysis_prompt method."""

    def test_prompt_contains_file_info(self):
        """Test that prompt contains file information."""
        narrator = ForensicNarrator()
        analysis = create_mock_analysis()

        prompt = narrator._build_full_analysis_prompt(analysis)

        assert "test_drawing.dwg" in prompt
        assert "102400" in prompt or "102,400" in prompt
        assert "abc123def456" in prompt

    def test_prompt_contains_header_info(self):
        """Test that prompt contains header information."""
        narrator = ForensicNarrator()
        analysis = create_mock_analysis()

        prompt = narrator._build_full_analysis_prompt(analysis)

        assert "AC1032" in prompt
        assert "AutoCAD 2018" in prompt

    def test_prompt_contains_crc_info(self):
        """Test that prompt contains CRC information."""
        narrator = ForensicNarrator()
        analysis = create_mock_analysis()

        prompt = narrator._build_full_analysis_prompt(analysis)

        assert "0x12345678" in prompt
        assert "MATCH" in prompt

    def test_prompt_contains_watermark_info(self):
        """Test that prompt contains watermark information."""
        narrator = ForensicNarrator()
        analysis = create_mock_analysis()

        prompt = narrator._build_full_analysis_prompt(analysis)

        assert "Autodesk DWG" in prompt
        assert "AutoCAD 2024" in prompt

    def test_prompt_with_metadata(self):
        """Test prompt with metadata present."""
        narrator = ForensicNarrator()
        analysis = create_mock_analysis()
        analysis.metadata = DWGMetadata(
            author="John Doe",
            last_saved_by="Jane Smith",
            title="Test Drawing",
            created_date=datetime(2024, 1, 1, 10, 0, 0),
            modified_date=datetime(2024, 1, 15, 15, 30, 0),
            tdindwg=0.5,  # 12 hours
            fingerprint_guid="{12345678-1234-1234-1234-123456789ABC}",
            version_guid="{ABCDEF00-1234-1234-1234-123456789ABC}",
        )

        prompt = narrator._build_full_analysis_prompt(analysis)

        assert "John Doe" in prompt
        assert "Jane Smith" in prompt
        assert "12345678" in prompt

    def test_prompt_with_network_paths(self):
        """Test prompt with network paths detected."""
        narrator = ForensicNarrator()
        analysis = create_mock_analysis()
        analysis.metadata = DWGMetadata(
            network_paths_detected=["\\\\server\\share\\file.dwg"],
        )

        prompt = narrator._build_full_analysis_prompt(analysis)

        assert "server" in prompt
        assert "share" in prompt

    def test_prompt_with_anomalies(self):
        """Test prompt with anomalies detected."""
        narrator = ForensicNarrator()
        analysis = create_mock_analysis_with_tampering()

        prompt = narrator._build_full_analysis_prompt(analysis)

        assert "CRC" in prompt
        assert "CRITICAL" in prompt

    def test_prompt_with_ntfs_analysis(self):
        """Test prompt with NTFS analysis data."""
        narrator = ForensicNarrator()
        analysis = create_mock_analysis()
        analysis.ntfs_analysis = NTFSTimestampAnalysis(
            si_created=datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
            si_modified=datetime(2024, 1, 15, 15, 30, 0, tzinfo=timezone.utc),
            si_created_nanoseconds=123456789,
            si_modified_nanoseconds=987654321,
            fn_created=datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
            timestomping_detected=False,
            nanosecond_truncation=False,
        )

        prompt = narrator._build_full_analysis_prompt(analysis)

        assert "2024-01-01" in prompt
        assert "2024-01-15" in prompt


class TestSystemPrompts:
    """Tests for system prompts and constants."""

    def test_forensic_expert_prompt_template_has_placeholder(self):
        """Test that expert prompt template has expert_name placeholder."""
        assert "{expert_name}" in FORENSIC_EXPERT_SYSTEM_PROMPT_TEMPLATE
        assert "Digital Forensics Expert" in FORENSIC_EXPERT_SYSTEM_PROMPT_TEMPLATE

    def test_forensic_expert_prompt_template_can_be_formatted(self):
        """Test that expert prompt template can be formatted with a name."""
        formatted = FORENSIC_EXPERT_SYSTEM_PROMPT_TEMPLATE.format(
            expert_name="Jordan P Ehrig, Sr."
        )
        assert "Jordan P Ehrig, Sr." in formatted
        assert "{expert_name}" not in formatted

    def test_forensic_expert_prompt_contains_methodology(self):
        """Test that expert prompt contains methodology."""
        assert "CROSS-VALIDATION" in FORENSIC_EXPERT_SYSTEM_PROMPT_TEMPLATE
        assert "EVIDENCE INVENTORY" in FORENSIC_EXPERT_SYSTEM_PROMPT_TEMPLATE
        assert "REASONING CHAIN" in FORENSIC_EXPERT_SYSTEM_PROMPT_TEMPLATE

    def test_forensic_expert_prompt_contains_rules(self):
        """Test that expert prompt contains rules."""
        assert "ABSOLUTE RULES" in FORENSIC_EXPERT_SYSTEM_PROMPT_TEMPLATE
        assert "SHOW YOUR WORK" in FORENSIC_EXPERT_SYSTEM_PROMPT_TEMPLATE

    def test_forensic_expert_prompt_contains_dwg_knowledge(self):
        """Test that expert prompt contains DWG knowledge."""
        assert "CRC" in FORENSIC_EXPERT_SYSTEM_PROMPT_TEMPLATE
        assert "TrustedDWG" in FORENSIC_EXPERT_SYSTEM_PROMPT_TEMPLATE
        assert "TDINDWG" in FORENSIC_EXPERT_SYSTEM_PROMPT_TEMPLATE
        assert "TDCREATE" in FORENSIC_EXPERT_SYSTEM_PROMPT_TEMPLATE

    def test_forensic_expert_prompt_contains_ntfs_knowledge(self):
        """Test that expert prompt contains NTFS knowledge."""
        assert "$STANDARD_INFORMATION" in FORENSIC_EXPERT_SYSTEM_PROMPT_TEMPLATE
        assert "$FILE_NAME" in FORENSIC_EXPERT_SYSTEM_PROMPT_TEMPLATE
        assert "timestomping" in FORENSIC_EXPERT_SYSTEM_PROMPT_TEMPLATE.lower()

    def test_full_analysis_prompt_contains_placeholders(self):
        """Test that analysis prompt has all placeholders."""
        placeholders = [
            "{filename}",
            "{file_size}",
            "{sha256}",
            "{version_string}",
            "{stored_crc}",
            "{calculated_crc}",
            "{watermark_present}",
            "{risk_level}",
        ]
        for placeholder in placeholders:
            assert placeholder in FULL_ANALYSIS_PROMPT


class TestEdgeCases:
    """Edge case tests for LLM module."""

    def test_narrator_with_minimal_analysis(self):
        """Test narrator with minimal analysis data."""
        narrator = ForensicNarrator(enabled=False)
        analysis = ForensicAnalysis(
            file_info=FileInfo(
                filename="minimal.dwg",
                file_size_bytes=1000,
                sha256="abc123def456789012345678901234567890123456789012345678901234abcd",
                intake_timestamp=datetime.now(timezone.utc),
            ),
            header_analysis=HeaderAnalysis(
                version_string="AC1024",
                version_name="AutoCAD 2010",
                maintenance_version=0,
                codepage=0,
                preview_address=0,
                is_supported=True,
            ),
            crc_validation=CRCValidation(
                header_crc_stored="0x0",
                header_crc_calculated="0x0",
                is_valid=True,
            ),
            trusted_dwg=TrustedDWGAnalysis(
                watermark_present=False,
                watermark_valid=False,
            ),
            risk_assessment=RiskAssessment(
                overall_risk=RiskLevel.LOW,
                factors=[],
                recommendation="Minimal analysis",
            ),
            anomalies=[],
            tampering_indicators=[],
            analysis_timestamp=datetime.now(timezone.utc),
            analyzer_version="1.0.0-test",
        )

        result = narrator.generate_full_analysis(analysis)
        assert result.success is False  # Because narrator is disabled

    @patch.object(OllamaClient, "is_available", return_value=True)
    @patch.object(OllamaClient, "generate")
    def test_prompt_handles_none_metadata(self, mock_generate, mock_is_available):
        """Test prompt handles None metadata gracefully."""
        mock_generate.return_value = OllamaResponse(
            response="Analysis complete.",
            model="phi4",
            success=True,
        )

        narrator = ForensicNarrator()
        analysis = create_mock_analysis()
        analysis.metadata = None

        # Should not raise an exception
        result = narrator.generate_full_analysis(analysis)
        assert result.success is True

    @patch.object(OllamaClient, "is_available", return_value=True)
    @patch.object(OllamaClient, "generate")
    def test_prompt_handles_empty_anomalies(self, mock_generate, mock_is_available):
        """Test prompt handles empty anomalies list."""
        mock_generate.return_value = OllamaResponse(
            response="No anomalies detected.",
            model="phi4",
            success=True,
        )

        narrator = ForensicNarrator()
        analysis = create_mock_analysis()
        analysis.anomalies = []

        result = narrator.generate_full_analysis(analysis)
        assert result.success is True
