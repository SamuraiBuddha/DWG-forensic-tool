"""
Comprehensive unit tests for the Phase 3 Analysis modules.

Tests cover:
- AnomalyDetector (timestamp, version, structural anomaly detection)
- TamperingRuleEngine (12 built-in rules + custom rules)
- RiskScorer (weighted scoring algorithm)
"""

import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from dwg_forensic.analysis import (
    AnomalyDetector,
    TamperingRuleEngine,
    RiskScorer,
    TamperingReport,
    RuleSeverity,
    RuleStatus,
)
from dwg_forensic.models import (
    Anomaly,
    AnomalyType,
    RiskLevel,
    HeaderAnalysis,
    CRCValidation,
    TrustedDWGAnalysis,
    DWGMetadata,
    TamperingIndicator,
    TamperingIndicatorType,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def temp_dwg_file(tmp_path):
    """Create a minimal DWG-like file for testing."""
    test_file = tmp_path / "test.dwg"
    # AC1032 magic bytes + padding to meet minimum size
    test_file.write_bytes(b"AC1032" + b"\x00" * 200)
    return test_file


@pytest.fixture
def valid_header():
    """Create a valid HeaderAnalysis object."""
    return HeaderAnalysis(
        version_string="AC1032",
        version_name="AutoCAD 2018",
        maintenance_version=0,
        codepage=0,
        security_flags=0,
        summary_info_address=0,
        vba_project_address=0,
        preview_address=0,
        header_size=108,
        is_supported=True,
    )


@pytest.fixture
def valid_crc():
    """Create a valid CRCValidation object."""
    return CRCValidation(
        header_crc_stored="0xABCD1234",
        header_crc_calculated="0xABCD1234",
        is_valid=True,
    )


@pytest.fixture
def invalid_crc():
    """Create an invalid CRCValidation object."""
    return CRCValidation(
        header_crc_stored="0xABCD1234",
        header_crc_calculated="0xDEADBEEF",
        is_valid=False,
    )


@pytest.fixture
def valid_watermark():
    """Create a valid TrustedDWGAnalysis object."""
    return TrustedDWGAnalysis(
        watermark_present=True,
        watermark_valid=True,
        watermark_text="Autodesk DWG",
        watermark_offset=0x100,
        is_autodesk_generated=True,
        application_origin="AutoCAD 2018",
    )


@pytest.fixture
def missing_watermark():
    """Create a TrustedDWGAnalysis with missing watermark."""
    return TrustedDWGAnalysis(
        watermark_present=False,
        watermark_valid=False,
        watermark_text=None,
        is_autodesk_generated=False,
    )


@pytest.fixture
def valid_metadata():
    """Create valid DWGMetadata."""
    now = datetime.now(timezone.utc)
    return DWGMetadata(
        title="Test Drawing",
        subject="Test Subject",
        author="Test Author",
        created_date=now - timedelta(days=30),
        modified_date=now - timedelta(hours=1),
        total_editing_time_hours=10.0,
    )


# ============================================================================
# AnomalyDetector Tests
# ============================================================================

class TestAnomalyDetector:
    """Test AnomalyDetector functionality."""

    def test_init_creates_instance(self):
        """Test that AnomalyDetector can be initialized."""
        detector = AnomalyDetector()
        assert detector is not None

    def test_detect_version_anomalies_valid(self, valid_header, temp_dwg_file):
        """Test version anomaly detection with valid header."""
        detector = AnomalyDetector()
        anomalies = detector.detect_version_anomalies(valid_header, temp_dwg_file)
        # Should not detect version anomalies for valid supported version
        version_anomalies = [a for a in anomalies if a.anomaly_type == AnomalyType.VERSION_MISMATCH]
        # May have some anomalies but not critical version issues
        assert all(a.severity != RiskLevel.CRITICAL for a in version_anomalies)

    def test_detect_version_anomalies_unsupported(self, temp_dwg_file):
        """Test version anomaly detection with unsupported version."""
        detector = AnomalyDetector()
        unsupported_header = HeaderAnalysis(
            version_string="AC1015",
            version_name="AutoCAD 2000",
            maintenance_version=0,
            codepage=0,
            security_flags=0,
            summary_info_address=0,
            vba_project_address=0,
            preview_address=0,
            header_size=108,
            is_supported=False,
        )
        anomalies = detector.detect_version_anomalies(unsupported_header, temp_dwg_file)
        # Should detect unsupported version
        assert any(a.anomaly_type == AnomalyType.VERSION_MISMATCH for a in anomalies)

    def test_detect_structural_anomalies_valid(self, temp_dwg_file):
        """Test structural anomaly detection with valid file."""
        detector = AnomalyDetector()
        anomalies = detector.detect_structural_anomalies(temp_dwg_file)
        # Should not detect critical structural issues
        critical = [a for a in anomalies if a.severity == RiskLevel.CRITICAL]
        assert len(critical) == 0

    def test_detect_structural_anomalies_small_file(self, tmp_path):
        """Test structural anomaly detection with too-small file."""
        small_file = tmp_path / "small.dwg"
        small_file.write_bytes(b"AC1032")  # Only 6 bytes

        detector = AnomalyDetector()
        anomalies = detector.detect_structural_anomalies(small_file)

        # Should detect file too small
        assert any(
            a.severity == RiskLevel.CRITICAL and "too small" in a.description.lower()
            for a in anomalies
        )


# ============================================================================
# TamperingRuleEngine Tests
# ============================================================================

class TestTamperingRuleEngine:
    """Test TamperingRuleEngine functionality."""

    def test_init_loads_builtin_rules(self):
        """Test that engine loads 16 built-in rules (12 original + 4 advanced)."""
        engine = TamperingRuleEngine()
        rules = engine.get_builtin_rules()
        assert len(rules) == 16

    def test_builtin_rule_ids(self):
        """Test that all 16 TAMPER rules exist."""
        engine = TamperingRuleEngine()
        rules = engine.get_builtin_rules()
        rule_ids = [r.rule_id for r in rules]

        for i in range(1, 17):
            expected_id = f"TAMPER-{i:03d}"
            assert expected_id in rule_ids, f"Missing rule {expected_id}"

    def test_evaluate_header_crc_valid(self, valid_crc):
        """Test TAMPER-001 passes with valid CRC."""
        engine = TamperingRuleEngine()
        context = {
            "crc": {
                "is_valid": True,
                "header_crc_stored": "0xABCD1234",
                "header_crc_calculated": "0xABCD1234",
            }
        }
        results = engine.evaluate_all(context)
        crc_result = next(r for r in results if r.rule_id == "TAMPER-001")
        assert crc_result.status == RuleStatus.PASSED

    def test_evaluate_header_crc_invalid(self):
        """Test TAMPER-001 fails with invalid CRC."""
        engine = TamperingRuleEngine()
        context = {
            "crc": {
                "is_valid": False,
                "header_crc_stored": "0xABCD1234",
                "header_crc_calculated": "0xDEADBEEF",
            }
        }
        results = engine.evaluate_all(context)
        crc_result = next(r for r in results if r.rule_id == "TAMPER-001")
        assert crc_result.status == RuleStatus.FAILED

    def test_evaluate_missing_watermark(self):
        """Test TAMPER-003 fails with missing watermark."""
        engine = TamperingRuleEngine()
        context = {
            "watermark": {"present": False, "valid": False},
            "header": {"version_string": "AC1032"},
        }
        results = engine.evaluate_all(context)
        wm_result = next(r for r in results if r.rule_id == "TAMPER-003")
        assert wm_result.status == RuleStatus.FAILED

    def test_evaluate_valid_watermark(self):
        """Test TAMPER-003 passes with valid watermark."""
        engine = TamperingRuleEngine()
        context = {
            "watermark": {"present": True, "valid": True},
            "header": {"version_string": "AC1032"},
        }
        results = engine.evaluate_all(context)
        wm_result = next(r for r in results if r.rule_id == "TAMPER-003")
        assert wm_result.status == RuleStatus.PASSED

    def test_get_failed_rules(self):
        """Test get_failed_rules returns only failed rules."""
        engine = TamperingRuleEngine()
        context = {
            "crc": {"is_valid": False},
            "watermark": {"present": True, "valid": True},
            "header": {"version_string": "AC1032"},
        }
        results = engine.evaluate_all(context)
        failed = engine.get_failed_rules(results)

        assert all(r.status == RuleStatus.FAILED for r in failed)

    def test_custom_rules_loading(self, tmp_path):
        """Test loading custom rules from YAML."""
        rules_file = tmp_path / "custom_rules.yaml"
        rules_file.write_text("""
rules:
  - id: CUSTOM-001
    name: Custom Test Rule
    severity: warning
    description: A custom test rule
    enabled: true
    condition:
      field: test.value
      operator: equals
      value: expected
""")
        engine = TamperingRuleEngine()
        engine.load_rules(rules_file)

        # Should have 17 rules now (16 built-in + 1 custom)
        assert len(engine.rules) == 17


# ============================================================================
# RiskScorer Tests
# ============================================================================

class TestRiskScorer:
    """Test RiskScorer functionality."""

    def test_init_creates_instance(self):
        """Test that RiskScorer can be initialized."""
        scorer = RiskScorer()
        assert scorer is not None

    def test_calculate_score_empty(self):
        """Test score calculation with no findings."""
        scorer = RiskScorer()
        score = scorer.calculate_score([], [], [])
        assert score == 0

    def test_calculate_score_with_anomalies(self):
        """Test score calculation with anomalies."""
        scorer = RiskScorer()
        anomalies = [
            Anomaly(
                anomaly_type=AnomalyType.CRC_MISMATCH,
                description="CRC mismatch",
                severity=RiskLevel.HIGH,
                details={},
            )
        ]
        score = scorer.calculate_score(anomalies, [], [])
        assert score > 0

    def test_score_to_risk_level_low(self):
        """Test score 0 maps to LOW risk."""
        scorer = RiskScorer()
        assert scorer.score_to_risk_level(0) == RiskLevel.LOW

    def test_score_to_risk_level_medium(self):
        """Test score 2 maps to MEDIUM risk."""
        scorer = RiskScorer()
        assert scorer.score_to_risk_level(2) == RiskLevel.MEDIUM

    def test_score_to_risk_level_high(self):
        """Test score 5 maps to HIGH risk."""
        scorer = RiskScorer()
        assert scorer.score_to_risk_level(5) == RiskLevel.HIGH

    def test_score_to_risk_level_critical(self):
        """Test score 10 maps to CRITICAL risk."""
        scorer = RiskScorer()
        assert scorer.score_to_risk_level(10) == RiskLevel.CRITICAL

    def test_generate_factors_with_valid_data(self, valid_crc, valid_watermark):
        """Test factor generation with valid data."""
        scorer = RiskScorer()
        factors = scorer.generate_factors(
            anomalies=[],
            rule_failures=[],
            tampering_indicators=[],
            crc_validation=valid_crc,
            trusted_dwg=valid_watermark,
        )

        # Should contain OK status markers
        assert any("[OK]" in f for f in factors)

    def test_generate_factors_with_failures(self, invalid_crc, missing_watermark):
        """Test factor generation with failures."""
        scorer = RiskScorer()
        factors = scorer.generate_factors(
            anomalies=[],
            rule_failures=[{"rule_id": "TAMPER-001", "severity": "CRITICAL"}],
            tampering_indicators=[],
            crc_validation=invalid_crc,
            trusted_dwg=missing_watermark,
        )

        # Should contain failure indicators
        assert any("[FAIL]" in f or "[WARN]" in f for f in factors)

    def test_generate_recommendation_low(self):
        """Test recommendation for low risk."""
        scorer = RiskScorer()
        rec = scorer.generate_recommendation(RiskLevel.LOW, 0)
        assert "authentic" in rec.lower() or "standard" in rec.lower()

    def test_generate_recommendation_critical(self):
        """Test recommendation for critical risk."""
        scorer = RiskScorer()
        rec = scorer.generate_recommendation(RiskLevel.CRITICAL, 10)
        assert "critical" in rec.lower() or "expert" in rec.lower()


# ============================================================================
# Integration Tests
# ============================================================================

class TestPhase3Integration:
    """Integration tests for Phase 3 modules working together."""

    def test_full_tampering_analysis_flow(self, valid_header, valid_crc, valid_watermark, temp_dwg_file):
        """Test complete tampering analysis workflow."""
        # Initialize components
        detector = AnomalyDetector()
        engine = TamperingRuleEngine()
        scorer = RiskScorer()

        # Detect anomalies
        version_anomalies = detector.detect_version_anomalies(valid_header, temp_dwg_file)
        structural_anomalies = detector.detect_structural_anomalies(temp_dwg_file)
        all_anomalies = version_anomalies + structural_anomalies

        # Evaluate rules
        # Derive is_autodesk from watermark validity (valid watermark = Autodesk origin)
        is_autodesk = valid_watermark.watermark_present and valid_watermark.watermark_valid
        context = {
            "crc": {
                "is_valid": valid_crc.is_valid,
                "header_crc_stored": valid_crc.header_crc_stored,
                "header_crc_calculated": valid_crc.header_crc_calculated,
            },
            "watermark": {
                "present": valid_watermark.watermark_present,
                "valid": valid_watermark.watermark_valid,
                "is_autodesk": is_autodesk,
            },
            "header": {
                "version_string": valid_header.version_string,
            },
        }
        rule_results = engine.evaluate_all(context)
        failed_rules = engine.get_failed_rules(rule_results)

        # Calculate score
        failed_dicts = [
            {"rule_id": r.rule_id, "severity": r.severity.value}
            for r in failed_rules
        ]
        score = scorer.calculate_score(all_anomalies, failed_dicts, [])
        risk_level = scorer.score_to_risk_level(score)

        # Valid file should have low risk
        assert risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM]

    def test_tampering_detected_workflow(self, valid_header, invalid_crc, missing_watermark, temp_dwg_file):
        """Test workflow when tampering indicators are present."""
        detector = AnomalyDetector()
        engine = TamperingRuleEngine()
        scorer = RiskScorer()

        # Build context with invalid CRC and missing watermark
        context = {
            "crc": {
                "is_valid": False,
                "header_crc_stored": "0xABCD",
                "header_crc_calculated": "0xDEAD",
            },
            "watermark": {
                "present": False,
                "valid": False,
            },
            "header": {
                "version_string": "AC1032",
            },
        }

        rule_results = engine.evaluate_all(context)
        failed_rules = engine.get_failed_rules(rule_results)

        # Should have failures
        assert len(failed_rules) > 0

        # Calculate risk
        failed_dicts = [
            {"rule_id": r.rule_id, "severity": r.severity.value}
            for r in failed_rules
        ]
        score = scorer.calculate_score([], failed_dicts, [])
        risk_level = scorer.score_to_risk_level(score)

        # Invalid file should have elevated risk
        assert risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]


# ============================================================================
# RuleResult Tests
# ============================================================================

class TestRuleResult:
    """Test RuleResult model."""

    def test_rule_result_creation(self):
        """Test creating a RuleResult."""
        from dwg_forensic.analysis.rules import RuleResult

        result = RuleResult(
            rule_id="TAMPER-001",
            rule_name="CRC Header Mismatch",
            status=RuleStatus.PASSED,
            severity=RuleSeverity.CRITICAL,
            description="[OK] CRC valid",
        )

        assert result.rule_id == "TAMPER-001"
        assert result.status == RuleStatus.PASSED

    def test_rule_result_with_details(self):
        """Test RuleResult with details."""
        from dwg_forensic.analysis.rules import RuleResult

        result = RuleResult(
            rule_id="TAMPER-001",
            rule_name="CRC Header Mismatch",
            status=RuleStatus.FAILED,
            severity=RuleSeverity.CRITICAL,
            description="[FAIL] CRC mismatch",
            expected="0xABCD",
            found="0xDEAD",
            details={"tampering_indicator": True},
        )

        assert result.expected == "0xABCD"
        assert result.found == "0xDEAD"
        assert result.details["tampering_indicator"] is True


# ============================================================================
# TamperingReport Tests
# ============================================================================

class TestTamperingReport:
    """Test TamperingReport model."""

    def test_tampering_report_creation(self):
        """Test creating a TamperingReport."""
        report = TamperingReport(
            file_path="/path/to/file.dwg",
            risk_level=RiskLevel.LOW,
            risk_score=0,
            confidence=0.9,
        )

        assert report.file_path == "/path/to/file.dwg"
        assert report.risk_level == RiskLevel.LOW
        assert report.confidence == 0.9

    def test_tampering_report_with_findings(self):
        """Test TamperingReport with anomalies and indicators."""
        anomaly = Anomaly(
            anomaly_type=AnomalyType.CRC_MISMATCH,
            description="CRC mismatch detected",
            severity=RiskLevel.HIGH,
            details={},
        )

        report = TamperingReport(
            file_path="/path/to/file.dwg",
            risk_level=RiskLevel.HIGH,
            risk_score=5,
            confidence=0.85,
            anomaly_count=1,
            anomalies=[anomaly],
            factors=["[FAIL] CRC validation failed"],
            recommendation="File may have been modified.",
        )

        assert report.anomaly_count == 1
        assert len(report.anomalies) == 1
        assert len(report.factors) == 1
