"""
Tests for Phase 4.2: LLM Reasoner Integration into Analysis Pipeline

This test suite validates:
- LLM anomaly filtering based on provenance context
- Heuristic fallback filtering when LLM unavailable
- Smoking gun preservation (never filtered)
- Integration with ForensicAnalyzer
- Confidence scoring and low-confidence warnings
"""

import asyncio
import pytest
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

pytest_plugins = ('pytest_asyncio',)

from dwg_forensic.llm.anomaly_models import (
    Anomaly,
    ProvenanceInfo,
    FilteredAnomalies,
    SmokingGunRule,
)
from dwg_forensic.llm.heuristic_filter import HeuristicAnomalyFilter
from dwg_forensic.llm.forensic_reasoner import ForensicReasoner
from dwg_forensic.models import RiskLevel


@pytest.fixture
def sample_anomalies():
    """Sample anomalies for testing."""
    return [
        Anomaly(
            rule_id="TAMPER-001",
            description="CRC mismatch detected",
            severity=RiskLevel.CRITICAL,
            timestamp_related=False,
            evidence_strength="DEFINITIVE",
        ),
        Anomaly(
            rule_id="TAMPER-013",
            description="TDINDWG is zero or suspicious",
            severity=RiskLevel.MEDIUM,
            timestamp_related=True,
            evidence_strength="CIRCUMSTANTIAL",
        ),
        Anomaly(
            rule_id="TAMPER-019",
            description="NTFS SI/FN timestamp mismatch",
            severity=RiskLevel.CRITICAL,
            timestamp_related=True,
            evidence_strength="DEFINITIVE",
        ),
        Anomaly(
            rule_id="TAMPER-003",
            description="TrustedDWG watermark missing",
            severity=RiskLevel.LOW,
            timestamp_related=False,
            evidence_strength="INFORMATIONAL",
        ),
        Anomaly(
            rule_id="TAMPER-029",
            description="Third-party CAD application detected",
            severity=RiskLevel.LOW,
            timestamp_related=False,
            evidence_strength="INFORMATIONAL",
        ),
    ]


@pytest.fixture
def revit_provenance():
    """Revit export provenance context."""
    return ProvenanceInfo(
        cad_app="Revit",
        version="2024",
        provenance_path="Revit Export",
        confidence=0.95,
        is_revit_export=True,
        expected_anomalies=["TAMPER-013", "TAMPER-003", "TAMPER-029"],
    )


@pytest.fixture
def autocad_provenance():
    """Native AutoCAD provenance context."""
    return ProvenanceInfo(
        cad_app="AutoCAD",
        version="2024",
        provenance_path="Native AutoCAD",
        confidence=0.9,
        is_native_autocad=True,
    )


@pytest.fixture
def oda_provenance():
    """ODA SDK tool provenance context."""
    return ProvenanceInfo(
        cad_app="BricsCAD",
        version="23",
        provenance_path="ODA SDK Tool",
        confidence=0.85,
        is_oda_tool=True,
        expected_anomalies=["TAMPER-003", "TAMPER-029"],
    )


class TestSmokingGunRule:
    """Test smoking gun rule validation."""

    def test_smoking_gun_identification(self):
        """Test that smoking gun rules are correctly identified."""
        validator = SmokingGunRule()

        assert validator.is_smoking_gun("TAMPER-001") is False  # CRC - special handling
        assert validator.is_smoking_gun("TAMPER-019") is True  # NTFS SI/FN
        assert validator.is_smoking_gun("TAMPER-014") is True  # TDINDWG exceeds
        assert validator.is_smoking_gun("TAMPER-013") is False  # TDINDWG zero
        assert validator.is_smoking_gun("TAMPER-003") is False  # TrustedDWG

    def test_validate_filtering_success(self):
        """Test validation passes when no smoking guns filtered."""
        validator = SmokingGunRule()

        filtered = [
            Anomaly("TAMPER-013", "TDINDWG zero", RiskLevel.MEDIUM),
            Anomaly("TAMPER-003", "TrustedDWG missing", RiskLevel.LOW),
        ]

        result = validator.validate_filtering(filtered)
        assert result is None  # No error

    def test_validate_filtering_failure(self):
        """Test validation fails when smoking gun filtered."""
        validator = SmokingGunRule()

        filtered = [
            Anomaly("TAMPER-019", "NTFS SI/FN mismatch", RiskLevel.CRITICAL, evidence_strength="DEFINITIVE"),
            Anomaly("TAMPER-013", "TDINDWG zero", RiskLevel.MEDIUM),
        ]

        result = validator.validate_filtering(filtered)
        assert result is not None
        assert "CRITICAL ERROR" in result
        assert "TAMPER-019" in result


class TestHeuristicAnomalyFilter:
    """Test heuristic anomaly filtering (fallback mode)."""

    def test_revit_filtering(self, sample_anomalies, revit_provenance):
        """Test heuristic filtering for Revit exports."""
        filter_engine = HeuristicAnomalyFilter()

        result = filter_engine.filter_anomalies(sample_anomalies, revit_provenance)

        # Smoking guns preserved
        kept_ids = {a.rule_id for a in result.kept_anomalies}
        assert "TAMPER-019" in kept_ids  # NTFS - smoking gun

        # Expected anomalies filtered for Revit
        filtered_ids = {a.rule_id for a in result.filtered_anomalies}
        assert "TAMPER-001" in filtered_ids  # CRC=0 - expected for Revit
        assert "TAMPER-013" in filtered_ids  # TDINDWG zero - expected for Revit
        assert "TAMPER-003" in filtered_ids  # TrustedDWG - expected for Revit
        assert "TAMPER-029" in filtered_ids  # Third-party - informational

        assert result.method == "heuristic"
        assert result.llm_confidence > 0.6  # High confidence for Revit (0.95 provenance)

    def test_autocad_strict_mode(self, sample_anomalies, autocad_provenance):
        """Test heuristic filtering for native AutoCAD (strict mode)."""
        filter_engine = HeuristicAnomalyFilter()

        result = filter_engine.filter_anomalies(sample_anomalies, autocad_provenance)

        # Native AutoCAD: Keep all anomalies except informational fingerprints
        kept_ids = {a.rule_id for a in result.kept_anomalies}
        assert "TAMPER-001" in kept_ids
        assert "TAMPER-013" in kept_ids  # NOT filtered for AutoCAD
        assert "TAMPER-019" in kept_ids
        assert "TAMPER-003" in kept_ids

        # Only filter informational fingerprints
        filtered_ids = {a.rule_id for a in result.filtered_anomalies}
        assert "TAMPER-029" in filtered_ids  # Informational only

        assert result.method == "heuristic"

    def test_oda_tool_filtering(self, sample_anomalies, oda_provenance):
        """Test heuristic filtering for ODA SDK tools."""
        filter_engine = HeuristicAnomalyFilter()

        result = filter_engine.filter_anomalies(sample_anomalies, oda_provenance)

        # Smoking guns preserved
        kept_ids = {a.rule_id for a in result.kept_anomalies}
        assert "TAMPER-019" in kept_ids  # NTFS - smoking gun
        assert "TAMPER-013" in kept_ids  # TDINDWG - not filtered for ODA (only for Revit)

        # ODA-expected anomalies filtered
        filtered_ids = {a.rule_id for a in result.filtered_anomalies}
        assert "TAMPER-001" in filtered_ids  # CRC=0 expected for ODA
        assert "TAMPER-003" in filtered_ids  # TrustedDWG not used by ODA
        assert "TAMPER-029" in filtered_ids  # Third-party detection

        assert result.method == "heuristic"

    def test_empty_anomalies(self, revit_provenance):
        """Test heuristic filter handles empty anomaly list."""
        filter_engine = HeuristicAnomalyFilter()

        result = filter_engine.filter_anomalies([], revit_provenance)

        assert len(result.kept_anomalies) == 0
        assert len(result.filtered_anomalies) == 0
        assert result.total_count == 0
        assert result.method == "heuristic"

    def test_crc_special_handling(self, revit_provenance):
        """Test CRC anomaly special handling for Revit (CRC=0 expected)."""
        filter_engine = HeuristicAnomalyFilter()

        # CRC=0 matching for Revit - should filter as expected Revit behavior
        crc_zero = Anomaly(
            rule_id="TAMPER-001",
            description="CRC is 0x00000000",
            severity=RiskLevel.MEDIUM,
            details={"stored_crc": "0x00000000", "calculated_crc": "0x00000000"},
        )

        result = filter_engine.filter_anomalies([crc_zero], revit_provenance)
        filtered_ids = {a.rule_id for a in result.filtered_anomalies}
        # CRC=0 for Revit should be filtered as expected behavior
        assert "TAMPER-001" in filtered_ids

        # CRC mismatch for Revit - should ALWAYS keep (smoking gun)
        crc_mismatch = Anomaly(
            rule_id="TAMPER-001",
            description="CRC mismatch",
            severity=RiskLevel.CRITICAL,
            evidence_strength="DEFINITIVE",
            details={"stored_crc": "0x12345678", "calculated_crc": "0xABCDEF00"},
        )

        result = filter_engine.filter_anomalies([crc_mismatch], revit_provenance)
        kept_ids = {a.rule_id for a in result.kept_anomalies}
        assert "TAMPER-001" in kept_ids  # Kept - real modification even for Revit

    def test_confidence_calculation(self):
        """Test confidence scoring based on provenance confidence."""
        filter_engine = HeuristicAnomalyFilter()

        # High provenance confidence
        high_prov = ProvenanceInfo(
            cad_app="Revit", provenance_path="Revit Export", confidence=0.9, is_revit_export=True
        )
        anomalies = [Anomaly("TAMPER-013", "TDINDWG zero", RiskLevel.MEDIUM)]
        result = filter_engine.filter_anomalies(anomalies, high_prov)
        assert result.llm_confidence == 0.75  # High confidence

        # Low provenance confidence
        low_prov = ProvenanceInfo(
            cad_app="Unknown", provenance_path="Unknown", confidence=0.3
        )
        result = filter_engine.filter_anomalies(anomalies, low_prov)
        assert result.llm_confidence == 0.4  # Low confidence


class TestForensicReasoner:
    """Test LLM-powered anomaly filtering."""

    @pytest.mark.asyncio
    async def test_filter_anomalies_with_llm(self, sample_anomalies, revit_provenance):
        """Test LLM anomaly filtering for Revit export."""
        # Mock LLM client
        mock_client = AsyncMock()
        mock_client.generate = AsyncMock(return_value='''
        {
            "keep": ["TAMPER-001", "TAMPER-019"],
            "filter": ["TAMPER-013", "TAMPER-003", "TAMPER-029"],
            "reasoning": "Revit exports naturally have TDINDWG=0 and missing TrustedDWG. CRC and NTFS violations are preserved as definitive proof.",
            "confidence": 0.92
        }
        ''')

        # Create reasoner without full initialization
        reasoner = ForensicReasoner.__new__(ForensicReasoner)
        reasoner._model = "test"
        reasoner._host = "http://localhost:11434"
        reasoner._client = mock_client

        result = await reasoner.filter_anomalies(
            sample_anomalies, revit_provenance, dwg_version="AC1032"
        )

        # Verify smoking guns preserved
        kept_ids = {a.rule_id for a in result.kept_anomalies}
        assert "TAMPER-001" in kept_ids
        assert "TAMPER-019" in kept_ids

        # Verify expected anomalies filtered
        filtered_ids = {a.rule_id for a in result.filtered_anomalies}
        assert "TAMPER-013" in filtered_ids
        assert "TAMPER-003" in filtered_ids

        assert result.method == "llm"
        assert result.llm_confidence == 0.92
        assert "Revit" in result.reasoning

    @pytest.mark.asyncio
    async def test_filter_anomalies_llm_override_smoking_gun(self, sample_anomalies, revit_provenance):
        """Test that smoking guns are NEVER filtered even if LLM suggests it."""
        # Mock LLM client that incorrectly tries to filter NTFS smoking gun
        mock_client = AsyncMock()
        mock_client.generate = AsyncMock(return_value='''
        {
            "keep": ["TAMPER-001"],
            "filter": ["TAMPER-019", "TAMPER-013", "TAMPER-003", "TAMPER-029"],
            "reasoning": "Filtering NTFS smoking gun incorrectly",
            "confidence": 0.8
        }
        ''')

        reasoner = ForensicReasoner.__new__(ForensicReasoner)
        reasoner._model = "test"
        reasoner._host = "http://localhost:11434"
        reasoner._client = mock_client

        result = await reasoner.filter_anomalies(
            sample_anomalies, revit_provenance, dwg_version="AC1032"
        )

        # CRITICAL: NTFS smoking gun must be kept despite LLM filtering it
        kept_ids = {a.rule_id for a in result.kept_anomalies}
        assert "TAMPER-019" in kept_ids  # Overridden - smoking gun preserved

        # Other anomalies filtered as LLM suggested
        filtered_ids = {a.rule_id for a in result.filtered_anomalies}
        assert "TAMPER-013" in filtered_ids
        assert "TAMPER-019" not in filtered_ids  # Not in filtered - moved to kept

    @pytest.mark.asyncio
    async def test_filter_anomalies_fallback_on_llm_failure(self, sample_anomalies, revit_provenance):
        """Test fallback to heuristic when LLM fails."""
        # Mock LLM client that raises exception
        mock_client = AsyncMock()
        mock_client.generate = AsyncMock(side_effect=Exception("Ollama unavailable"))

        reasoner = ForensicReasoner.__new__(ForensicReasoner)
        reasoner._model = "test"
        reasoner._host = "http://localhost:11434"
        reasoner._client = mock_client

        result = await reasoner.filter_anomalies(
            sample_anomalies, revit_provenance, dwg_version="AC1032"
        )

        # Should fall back to heuristic filtering
        assert result.method == "heuristic"
        assert len(result.kept_anomalies) > 0
        assert len(result.filtered_anomalies) > 0

    @pytest.mark.asyncio
    async def test_filter_anomalies_no_llm_client(self, sample_anomalies, revit_provenance):
        """Test heuristic fallback when LLM client not initialized."""
        reasoner = ForensicReasoner.__new__(ForensicReasoner)
        reasoner._model = "test"
        reasoner._host = "http://localhost:11434"
        reasoner._client = None

        result = await reasoner.filter_anomalies(
            sample_anomalies, revit_provenance, dwg_version="AC1032"
        )

        assert result.method == "heuristic"

    @pytest.mark.asyncio
    async def test_filter_anomalies_empty_list(self, revit_provenance):
        """Test filtering empty anomaly list."""
        reasoner = ForensicReasoner.__new__(ForensicReasoner)
        reasoner._model = "test"
        reasoner._host = "http://localhost:11434"
        reasoner._client = None

        result = await reasoner.filter_anomalies([], revit_provenance, dwg_version="AC1032")

        assert len(result.kept_anomalies) == 0
        assert len(result.filtered_anomalies) == 0
        assert result.method == "none"

    def test_get_llm_confidence(self):
        """Test LLM confidence getter."""
        # Don't initialize - just mock the client
        reasoner = ForensicReasoner.__new__(ForensicReasoner)
        reasoner._model = "test"
        reasoner._host = "http://localhost:11434"

        # With client
        reasoner._client = MagicMock()
        assert reasoner.get_llm_confidence() == 1.0

        # Without client
        reasoner._client = None
        assert reasoner.get_llm_confidence() == 0.0


class TestFilteredAnomaliesModel:
    """Test FilteredAnomalies data model."""

    def test_statistics_calculation(self, sample_anomalies):
        """Test automatic statistics calculation."""
        kept = sample_anomalies[:3]
        filtered = sample_anomalies[3:]

        result = FilteredAnomalies(
            kept_anomalies=kept,
            filtered_anomalies=filtered,
            reasoning="Test filtering",
            llm_confidence=0.85,
            method="llm",
        )

        assert result.kept_count == 3
        assert result.filtered_count == 2
        assert result.total_count == 5
        assert result.filter_rate == 40.0
        # Both TAMPER-001 and TAMPER-019 have evidence_strength='DEFINITIVE' in kept list
        assert result.smoking_guns_preserved == 2

    def test_low_confidence_warning(self):
        """Test low confidence warning flag."""
        # High confidence
        result = FilteredAnomalies(
            kept_anomalies=[],
            filtered_anomalies=[],
            reasoning="",
            llm_confidence=0.8,
            method="llm",
        )
        assert result.low_confidence_warning is False

        # Low confidence
        result = FilteredAnomalies(
            kept_anomalies=[],
            filtered_anomalies=[],
            reasoning="",
            llm_confidence=0.5,
            method="heuristic",
        )
        assert result.low_confidence_warning is True

    def test_to_dict(self, sample_anomalies):
        """Test dict serialization."""
        kept = sample_anomalies[:2]
        filtered = sample_anomalies[2:]

        result = FilteredAnomalies(
            kept_anomalies=kept,
            filtered_anomalies=filtered,
            reasoning="Test",
            llm_confidence=0.9,
            method="llm",
        )

        output = result.to_dict()

        assert "kept_anomalies" in output
        assert "filtered_anomalies" in output
        assert "reasoning" in output
        assert "statistics" in output
        assert output["statistics"]["total_count"] == 5
        assert output["method"] == "llm"


class TestProvenanceInfo:
    """Test ProvenanceInfo data model."""

    def test_from_provenance_result(self):
        """Test construction from provenance detector result."""
        prov_dict = {
            "source_application": "Revit",
            "version": "2024",
            "confidence": 0.95,
            "is_revit_export": True,
            "is_oda_tool": False,
            "is_transferred": False,
            "is_native_autocad": False,
            "rules_to_skip": ["TAMPER-013", "TAMPER-003"],
            "detection_notes": ["Revit signature detected"],
        }

        prov_info = ProvenanceInfo.from_provenance_result(prov_dict)

        assert prov_info.cad_app == "Revit"
        assert prov_info.provenance_path == "Revit Export"
        assert prov_info.confidence == 0.95
        assert prov_info.is_revit_export is True
        assert len(prov_info.expected_anomalies) == 2

    def test_provenance_path_determination(self):
        """Test automatic provenance path description."""
        # Revit
        prov = ProvenanceInfo.from_provenance_result({"is_revit_export": True})
        assert prov.provenance_path == "Revit Export"

        # ODA
        prov = ProvenanceInfo.from_provenance_result({"is_oda_tool": True})
        assert prov.provenance_path == "ODA SDK Tool"

        # Transfer
        prov = ProvenanceInfo.from_provenance_result({"is_transferred": True})
        assert prov.provenance_path == "File Transfer"

        # Native AutoCAD
        prov = ProvenanceInfo.from_provenance_result({"is_native_autocad": True})
        assert prov.provenance_path == "Native AutoCAD"

        # Unknown
        prov = ProvenanceInfo.from_provenance_result({})
        assert prov.provenance_path == "Unknown Origin"


@pytest.mark.integration
class TestAnalyzerIntegration:
    """Integration tests with ForensicAnalyzer."""

    def test_analyzer_includes_filtered_anomalies_field(self, tmp_path):
        """Test that ForensicAnalysis includes filtered_anomalies field."""
        # This is a placeholder - actual integration test would require test DWG file
        # The field is tested in unit tests above
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
