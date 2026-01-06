"""Tests for core forensic analyzer."""

import pytest

from dwg_forensic.core.analyzer import ForensicAnalyzer, analyze_file
from dwg_forensic.models import (
    AnomalyType,
    ForensicAnalysis,
    RiskLevel,
    TamperingIndicatorType,
)
from dwg_forensic.utils.exceptions import UnsupportedVersionError


class TestForensicAnalyzer:
    """Tests for ForensicAnalyzer class."""

    def test_analyze_valid_file(self, valid_dwg_ac1032):
        """Test analyzing a valid DWG file."""
        analyzer = ForensicAnalyzer()
        result = analyzer.analyze(valid_dwg_ac1032)

        assert isinstance(result, ForensicAnalysis)
        assert result.file_info.filename == "valid_ac1032.dwg"
        assert result.header_analysis.version_string == "AC1032"
        assert result.header_analysis.is_supported is True

    def test_analyze_collects_sha256(self, valid_dwg_ac1032):
        """Test that SHA-256 is calculated."""
        analyzer = ForensicAnalyzer()
        result = analyzer.analyze(valid_dwg_ac1032)

        assert len(result.file_info.sha256) == 64
        assert all(c in "0123456789abcdef" for c in result.file_info.sha256)

    def test_analyze_unsupported_version(self, unsupported_dwg_ac1015):
        """Test that unsupported versions raise error."""
        analyzer = ForensicAnalyzer()

        with pytest.raises(UnsupportedVersionError):
            analyzer.analyze(unsupported_dwg_ac1015)

    def test_crc_validation_included(self, valid_dwg_ac1032):
        """Test that CRC validation is included."""
        analyzer = ForensicAnalyzer()
        result = analyzer.analyze(valid_dwg_ac1032)

        assert result.crc_validation is not None
        assert result.crc_validation.is_valid is True

    def test_watermark_analysis_included(self, valid_dwg_ac1032):
        """Test that watermark analysis is included."""
        analyzer = ForensicAnalyzer()
        result = analyzer.analyze(valid_dwg_ac1032)

        assert result.trusted_dwg is not None
        # The fixture includes a watermark
        assert result.trusted_dwg.watermark_present is True

    def test_risk_assessment_included(self, valid_dwg_ac1032):
        """Test that risk assessment is included."""
        analyzer = ForensicAnalyzer()
        result = analyzer.analyze(valid_dwg_ac1032)

        assert result.risk_assessment is not None
        assert result.risk_assessment.overall_risk in RiskLevel

    def test_analyze_detects_crc_anomaly(self, corrupted_crc_dwg):
        """Test that CRC mismatch creates anomaly."""
        analyzer = ForensicAnalyzer()
        result = analyzer.analyze(corrupted_crc_dwg)

        # Should have a CRC mismatch anomaly
        crc_anomalies = [
            a for a in result.anomalies if a.anomaly_type == AnomalyType.CRC_MISMATCH
        ]
        assert len(crc_anomalies) > 0

    def test_analyze_detects_tampering_indicator(self, corrupted_crc_dwg):
        """Test that CRC mismatch creates tampering indicator."""
        analyzer = ForensicAnalyzer()
        result = analyzer.analyze(corrupted_crc_dwg)

        # Should have a CRC modified tampering indicator
        crc_indicators = [
            i
            for i in result.tampering_indicators
            if i.indicator_type == TamperingIndicatorType.CRC_MODIFIED
        ]
        assert len(crc_indicators) > 0

    def test_high_risk_for_crc_mismatch(self, corrupted_crc_dwg):
        """Test that CRC mismatch results in high or critical risk.

        Note: Phase 3 analysis detects multiple issues (CRC mismatch, missing
        watermark, failed tampering rules) which accumulate to a higher risk
        score, potentially reaching CRITICAL level.
        """
        analyzer = ForensicAnalyzer()
        result = analyzer.analyze(corrupted_crc_dwg)

        # CRC mismatch with other issues should be HIGH or CRITICAL
        assert result.risk_assessment.overall_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]

    def test_low_risk_for_valid_file(self, valid_dwg_ac1032):
        """Test that valid file has low or medium risk.

        Note: Phase 3 analysis may detect minor anomalies even in valid test
        files (e.g., structural anomalies due to minimal test file content),
        which can result in MEDIUM rather than LOW risk.
        """
        analyzer = ForensicAnalyzer()
        result = analyzer.analyze(valid_dwg_ac1032)

        # With valid CRC and watermark, risk should be LOW or at most MEDIUM
        # (not HIGH or CRITICAL)
        assert result.risk_assessment.overall_risk in [RiskLevel.LOW, RiskLevel.MEDIUM]

    def test_analyzer_version_set(self, valid_dwg_ac1032):
        """Test that analyzer version is set."""
        analyzer = ForensicAnalyzer()
        result = analyzer.analyze(valid_dwg_ac1032)

        assert result.analyzer_version is not None
        assert len(result.analyzer_version) > 0


class TestAnalyzeFileFunction:
    """Tests for analyze_file convenience function."""

    def test_analyze_file_returns_analysis(self, valid_dwg_ac1032):
        """Test that analyze_file returns ForensicAnalysis."""
        result = analyze_file(valid_dwg_ac1032)
        assert isinstance(result, ForensicAnalysis)

    def test_analyze_file_same_as_analyzer(self, valid_dwg_ac1032):
        """Test that analyze_file produces same result as ForensicAnalyzer."""
        func_result = analyze_file(valid_dwg_ac1032)
        analyzer = ForensicAnalyzer()
        analyzer_result = analyzer.analyze(valid_dwg_ac1032)

        # SHA256 should match
        assert func_result.file_info.sha256 == analyzer_result.file_info.sha256
        # Header analysis should match
        assert func_result.header_analysis.version_string == analyzer_result.header_analysis.version_string
