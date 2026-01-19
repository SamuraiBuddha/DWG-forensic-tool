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
        """Test that engine loads 38 built-in rules (10 basic + 6 advanced + 10 NTFS + 7 CAD fingerprinting + 5 deep parsing)."""
        engine = TamperingRuleEngine()
        rules = engine.get_builtin_rules()
        assert len(rules) == 38

    def test_builtin_rule_ids(self):
        """Test that all 38 TAMPER rules exist (excludes TAMPER-003 and TAMPER-004)."""
        engine = TamperingRuleEngine()
        rules = engine.get_builtin_rules()
        rule_ids = [r.rule_id for r in rules]

        # TAMPER-003 and TAMPER-004 were removed (TrustedDWG watermark rules)
        excluded_rules = {"TAMPER-003", "TAMPER-004"}
        for i in range(1, 41):
            expected_id = f"TAMPER-{i:03d}"
            if expected_id in excluded_rules:
                assert expected_id not in rule_ids, f"Rule {expected_id} should be removed"
            else:
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

    def test_get_failed_rules(self):
        """Test get_failed_rules returns only failed rules."""
        engine = TamperingRuleEngine()
        context = {
            "crc": {"is_valid": False},
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

        # Should have 39 rules now (38 built-in + 1 custom)
        assert len(engine.rules) == 39


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

    def test_generate_factors_with_valid_data(self, valid_crc):
        """Test factor generation with valid data."""
        scorer = RiskScorer()
        factors = scorer.generate_factors(
            anomalies=[],
            rule_failures=[],
            tampering_indicators=[],
            crc_validation=valid_crc,
        )

        # Should contain OK status markers
        assert any("[OK]" in f for f in factors)

    def test_generate_factors_with_failures(self, invalid_crc):
        """Test factor generation with failures."""
        scorer = RiskScorer()
        factors = scorer.generate_factors(
            anomalies=[],
            rule_failures=[{"rule_id": "TAMPER-001", "severity": "CRITICAL"}],
            tampering_indicators=[],
            crc_validation=invalid_crc,
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

    def test_calculate_score_with_risklevel_severity(self):
        """Test score calculation with RiskLevel severity object (not string)."""
        scorer = RiskScorer()
        # Rule failure with RiskLevel object instead of string
        rule_failures = [
            {"rule_id": "TEST-001", "severity": RiskLevel.HIGH}
        ]
        score = scorer.calculate_score([], rule_failures, [])
        assert score > 0

    def test_calculate_confidence_with_metadata(self):
        """Test confidence calculation with metadata present."""
        scorer = RiskScorer()
        header = HeaderAnalysis(
            version_string="AC1032",
            version_name="AutoCAD 2018+",
            is_supported=True,
            maintenance_version=3,
            preview_address=0x100,
            codepage=30,
        )
        crc = CRCValidation(
            header_crc_stored="0x12345678",
            header_crc_calculated="0x12345678",
            is_valid=True,
        )
        metadata = DWGMetadata(
            created_date=None,
            modified_date=None,
        )

        confidence = scorer.calculate_confidence(header, crc, metadata, 0)

        # With supported version, CRC, and metadata, confidence should be high
        assert confidence >= 0.8

    def test_calculate_confidence_with_many_anomalies(self):
        """Test confidence calculation with more than 3 anomalies."""
        scorer = RiskScorer()
        header = HeaderAnalysis(
            version_string="AC1032",
            version_name="AutoCAD 2018+",
            is_supported=True,
            maintenance_version=3,
            preview_address=0x100,
            codepage=30,
        )

        confidence = scorer.calculate_confidence(header, None, None, 5)

        # With 5 anomalies, should get the +0.05 bonus
        assert confidence >= 0.75

    def test_generate_factors_with_critical_anomalies(self):
        """Test factor generation with critical anomalies."""
        scorer = RiskScorer()
        anomalies = [
            Anomaly(
                anomaly_type=AnomalyType.CRC_MISMATCH,
                description="CRC mismatch",
                severity=RiskLevel.CRITICAL,
                details={},
            ),
            Anomaly(
                anomaly_type=AnomalyType.TIMESTAMP_ANOMALY,
                description="Timestamp anomaly",
                severity=RiskLevel.CRITICAL,
                details={},
            ),
        ]

        factors = scorer.generate_factors(
            anomalies=anomalies,
            rule_failures=[],
            tampering_indicators=[],
            crc_validation=None,
        )

        # Should have CRITICAL factor
        assert any("[CRITICAL]" in f for f in factors)

    def test_generate_factors_empty_no_issues(self):
        """Test factor generation when all data is None and no issues."""
        scorer = RiskScorer()

        factors = scorer.generate_factors(
            anomalies=[],
            rule_failures=[],
            tampering_indicators=[],
            crc_validation=None,
        )

        # Should have "[OK] No significant issues detected"
        assert any("No significant issues detected" in f for f in factors)


# ============================================================================
# Integration Tests
# ============================================================================

class TestPhase3Integration:
    """Integration tests for Phase 3 modules working together."""

    def test_full_tampering_analysis_flow(self, valid_header, valid_crc, temp_dwg_file):
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
        context = {
            "crc": {
                "is_valid": valid_crc.is_valid,
                "header_crc_stored": valid_crc.header_crc_stored,
                "header_crc_calculated": valid_crc.header_crc_calculated,
            },
            "watermark": {
                "present": True,
                "valid": True,
                "is_autodesk": True,
            },
            "header": {
                "version_string": valid_header.version_string,
            },
            # Provide metadata for CAD fingerprinting rules (TAMPER-029 to TAMPER-035)
            "metadata": {
                "fingerprintguid": "{12345678-1234-1234-1234-123456789012}",
                "versionguid": "{87654321-4321-4321-4321-210987654321}",
                "tdcreate": 2459000.5,  # Non-zero timestamp
                "tdupdate": 2459001.5,  # Different from tdcreate
                "tdindwg": 1.5,         # Non-zero editing time
            },
            "timestamp_anomalies": {
                "detected": False,
                "patterns": [],
                "likely_third_party": False,
            },
            "cad_fingerprint": {
                "detected_application": "autocad",
                "is_oda_based": False,
            },
            "oda_detection": {
                "is_oda_based": False,
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

    def test_tampering_detected_workflow(self, valid_header, invalid_crc, temp_dwg_file):
        """Test workflow when tampering indicators are present."""
        detector = AnomalyDetector()
        engine = TamperingRuleEngine()
        scorer = RiskScorer()

        # Build context with invalid CRC
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


# ============================================================================
# Additional AnomalyDetector Coverage Tests
# ============================================================================

class TestAnomalyDetectorTimestamps:
    """Test timestamp anomaly detection in AnomalyDetector."""

    def test_created_after_modified(self, temp_dwg_file):
        """Test detection of created date after modified date."""
        detector = AnomalyDetector()
        now = datetime.now(timezone.utc)
        metadata = DWGMetadata(
            created_date=now,  # Created now
            modified_date=now - timedelta(days=5),  # Modified 5 days ago (before creation)
        )

        anomalies = detector.detect_timestamp_anomalies(metadata, temp_dwg_file)

        # Should detect created > modified anomaly
        assert any(
            a.anomaly_type == AnomalyType.TIMESTAMP_ANOMALY and
            "later than modified" in a.description.lower()
            for a in anomalies
        )

    def test_modified_in_future(self, temp_dwg_file):
        """Test detection of modified date in the future."""
        detector = AnomalyDetector()
        now = datetime.now(timezone.utc)
        metadata = DWGMetadata(
            modified_date=now + timedelta(days=10),  # 10 days in future
        )

        anomalies = detector.detect_timestamp_anomalies(metadata, temp_dwg_file)

        # Should detect future timestamp
        assert any(
            a.anomaly_type == AnomalyType.TIMESTAMP_ANOMALY and
            "future" in a.description.lower()
            for a in anomalies
        )

    def test_editing_time_exceeds_span(self, temp_dwg_file):
        """Test detection of editing time exceeding time span."""
        detector = AnomalyDetector()
        now = datetime.now(timezone.utc)
        metadata = DWGMetadata(
            created_date=now - timedelta(hours=10),  # 10 hours ago
            modified_date=now,
            total_editing_time_hours=100.0,  # 100 hours editing in 10 hours
        )

        anomalies = detector.detect_timestamp_anomalies(metadata, temp_dwg_file)

        # Should detect excessive editing time
        assert any(
            a.anomaly_type == AnomalyType.SUSPICIOUS_EDIT_TIME
            for a in anomalies
        )

    def test_filesystem_vs_internal_mismatch(self, tmp_path):
        """Test detection of filesystem vs internal timestamp mismatch."""
        # Create file with specific modification time
        test_file = tmp_path / "test_mismatch.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)

        detector = AnomalyDetector()
        # Internal date way off from filesystem date
        metadata = DWGMetadata(
            modified_date=datetime(2010, 1, 1, tzinfo=timezone.utc),
        )

        anomalies = detector.detect_timestamp_anomalies(metadata, test_file)

        # Should detect mismatch
        assert any(
            a.anomaly_type == AnomalyType.TIMESTAMP_ANOMALY and
            "filesystem" in a.description.lower()
            for a in anomalies
        )

    def test_naive_datetime_handling(self, temp_dwg_file):
        """Test handling of naive (timezone-unaware) datetimes."""
        detector = AnomalyDetector()
        # Create naive datetimes
        created = datetime(2020, 1, 1, 12, 0)  # No timezone
        modified = datetime(2019, 1, 1, 12, 0)  # No timezone, before created
        metadata = DWGMetadata(
            created_date=created,
            modified_date=modified,
        )

        anomalies = detector.detect_timestamp_anomalies(metadata, temp_dwg_file)

        # Should handle naive datetimes and detect created > modified
        assert any(
            a.anomaly_type == AnomalyType.TIMESTAMP_ANOMALY
            for a in anomalies
        )


class TestAnomalyDetectorVersionMarkers:
    """Test version marker detection."""

    def test_multiple_version_markers(self, tmp_path):
        """Test detection of multiple version markers."""
        # Create file with multiple version markers
        test_file = tmp_path / "multi_version.dwg"
        data = b"AC1032" + b"\x00" * 100 + b"AC1027" + b"\x00" * 100
        test_file.write_bytes(data)

        detector = AnomalyDetector()
        header = HeaderAnalysis(
            version_string="AC1032",
            version_name="AutoCAD 2018",
            maintenance_version=0,
            codepage=0,
            preview_address=0,
            is_supported=True,
        )

        anomalies = detector.detect_version_anomalies(header, test_file)

        # Should detect multiple version markers
        assert any(
            a.anomaly_type == AnomalyType.VERSION_MISMATCH and
            "multiple" in a.description.lower()
            for a in anomalies
        )


class TestAnomalyDetectorStructural:
    """Test structural anomaly detection."""

    def test_detect_all_method(self, temp_dwg_file, valid_header, valid_metadata):
        """Test detect_all orchestrator method."""
        detector = AnomalyDetector()

        anomalies = detector.detect_all(valid_header, valid_metadata, temp_dwg_file)

        # Should return a list (may be empty for valid files)
        assert isinstance(anomalies, list)

    def test_detect_all_without_metadata(self, temp_dwg_file, valid_header):
        """Test detect_all with no metadata."""
        detector = AnomalyDetector()

        anomalies = detector.detect_all(valid_header, None, temp_dwg_file)

        # Should work without metadata
        assert isinstance(anomalies, list)

    def test_calculate_null_ratio_empty_data(self):
        """Test _calculate_null_ratio with empty data."""
        detector = AnomalyDetector()

        ratio = detector._calculate_null_ratio(b"")

        assert ratio == 0.0

    def test_check_slack_space_repeated_pattern(self, tmp_path):
        """Test detection of unusual repeated patterns in slack space."""
        # Create file with long repeated non-null, non-FF sequence
        repeated_byte = b"\x55"  # Not 0x00 or 0xFF
        data = b"AC1032" + b"\x00" * 50 + (repeated_byte * 150) + b"\x00" * 50
        test_file = tmp_path / "repeated.dwg"
        test_file.write_bytes(data)

        detector = AnomalyDetector()
        anomalies = detector.detect_structural_anomalies(test_file)

        # Should detect unusual repeated pattern
        assert any(
            "repeated" in a.description.lower() or "pattern" in a.description.lower()
            for a in anomalies
        )


class TestTimezoneDiscrepancyEdgeCases:
    """Test timezone discrepancy edge cases."""

    def test_non_standard_timezone_offset(self):
        """Test detection of non-standard timezone offset."""
        from dwg_forensic.parsers.timestamp import TimestampData

        detector = AnomalyDetector()
        # Create data with odd timezone offset (not on 30-min boundary)
        # offset_hours = (tdcreate - tducreate) * 24
        # For offset of 2.25 hours (2h15m, not standard):
        data = TimestampData(
            tdcreate=60000.5,  # Noon local
            tducreate=60000.5 - (2.25 / 24),  # UTC is 2.25 hours earlier
        )

        anomalies = detector.detect_timezone_discrepancy(data)

        # Should detect non-standard offset
        non_standard = [
            a for a in anomalies
            if "non-standard" in a.description.lower() or "30-minute" in a.description.lower()
        ]
        assert len(non_standard) >= 1


class TestVersionAnachronismEdgeCases:
    """Test version anachronism edge cases."""

    def test_anachronism_invalid_mjd(self):
        """Test version anachronism with invalid MJD value."""
        from dwg_forensic.parsers.timestamp import TimestampData

        detector = AnomalyDetector()
        # Create data with invalid MJD that would cause overflow
        data = TimestampData(
            tdcreate=float("inf"),  # Invalid MJD
        )

        anomalies = detector.detect_version_anachronism("AC1024", data)

        # Should handle gracefully (no crash, empty list)
        assert isinstance(anomalies, list)


# ============================================================================
# Additional TamperingRuleEngine Coverage Tests
# ============================================================================

class TestRuleEngineLoadRules:
    """Test rule loading functionality."""

    def test_load_rules_with_none(self):
        """Test load_rules with None path."""
        engine = TamperingRuleEngine()
        initial_count = len(engine.rules)

        engine.load_rules(None)

        # Should remain unchanged
        assert len(engine.rules) == initial_count

    def test_load_rules_missing_file(self, tmp_path):
        """Test load_rules with missing file."""
        engine = TamperingRuleEngine()

        with pytest.raises(FileNotFoundError):
            engine.load_rules(tmp_path / "nonexistent.yaml")

    def test_load_rules_json_format(self, tmp_path):
        """Test loading rules from JSON file."""
        rules_file = tmp_path / "rules.json"
        rules_file.write_text('{"rules": [{"id": "CUSTOM-001", "name": "Test", "severity": "warning", "description": "Test rule", "enabled": true}]}')

        engine = TamperingRuleEngine()
        engine.load_rules(rules_file)

        assert any(r.rule_id == "CUSTOM-001" for r in engine.rules)

    def test_load_rules_unsupported_format(self, tmp_path):
        """Test load_rules with unsupported format."""
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text("some content")

        engine = TamperingRuleEngine()

        with pytest.raises(ValueError) as exc_info:
            engine.load_rules(rules_file)

        assert "Unsupported format" in str(exc_info.value)

    def test_load_rules_invalid_structure(self, tmp_path):
        """Test load_rules with invalid structure (no 'rules' key)."""
        rules_file = tmp_path / "invalid.yaml"
        rules_file.write_text("some_key: value")

        engine = TamperingRuleEngine()

        with pytest.raises(ValueError) as exc_info:
            engine.load_rules(rules_file)

        assert "rules" in str(exc_info.value).lower()


class TestRuleEngineEvaluation:
    """Test rule evaluation functionality."""

    def test_evaluate_disabled_rule(self):
        """Test that disabled rules return INCONCLUSIVE."""
        from dwg_forensic.analysis.rules import TamperingRule, RuleSeverity, RuleStatus

        engine = TamperingRuleEngine()

        disabled_rule = TamperingRule(
            rule_id="TEST-001",
            name="Disabled Rule",
            severity=RuleSeverity.WARNING,
            description="A disabled test rule",
            enabled=False,
        )

        result = engine.evaluate_rule(disabled_rule, {})

        assert result.status == RuleStatus.INCONCLUSIVE
        assert "disabled" in result.description.lower()

    def test_evaluate_custom_rule_with_condition(self):
        """Test evaluation of custom rule with condition."""
        from dwg_forensic.analysis.rules import TamperingRule, RuleSeverity, RuleCondition, RuleStatus

        engine = TamperingRuleEngine()

        custom_rule = TamperingRule(
            rule_id="CUSTOM-001",
            name="Custom Condition Rule",
            severity=RuleSeverity.WARNING,
            description="Tests custom condition",
            condition=RuleCondition(
                field="test.value",
                operator="equals",
                value="expected",
            ),
        )

        # Should pass when condition met
        context_pass = {"test": {"value": "expected"}}
        result = engine.evaluate_rule(custom_rule, context_pass)
        assert result.status == RuleStatus.PASSED

        # Should fail when condition not met
        context_fail = {"test": {"value": "wrong"}}
        result = engine.evaluate_rule(custom_rule, context_fail)
        assert result.status == RuleStatus.FAILED

    def test_evaluate_unknown_rule_id(self):
        """Test evaluation of rule with unknown ID."""
        from dwg_forensic.analysis.rules import TamperingRule, RuleSeverity, RuleStatus

        engine = TamperingRuleEngine()

        unknown_rule = TamperingRule(
            rule_id="UNKNOWN-999",
            name="Unknown Rule",
            severity=RuleSeverity.WARNING,
            description="Unknown rule ID",
        )

        result = engine.evaluate_rule(unknown_rule, {})

        assert result.status == RuleStatus.INCONCLUSIVE
        assert "not found" in result.description.lower()


class TestConditionEvaluation:
    """Test _evaluate_condition method."""

    def test_condition_not_equals(self):
        """Test not_equals condition."""
        from dwg_forensic.analysis.rules import RuleCondition

        engine = TamperingRuleEngine()

        condition = RuleCondition(field="status", operator="not_equals", value="bad")
        assert engine._evaluate_condition(condition, {"status": "good"}) is True
        assert engine._evaluate_condition(condition, {"status": "bad"}) is False

    def test_condition_greater_than(self):
        """Test greater_than condition."""
        from dwg_forensic.analysis.rules import RuleCondition

        engine = TamperingRuleEngine()

        condition = RuleCondition(field="count", operator="greater_than", value=5)
        assert engine._evaluate_condition(condition, {"count": 10}) is True
        assert engine._evaluate_condition(condition, {"count": 3}) is False

    def test_condition_less_than(self):
        """Test less_than condition."""
        from dwg_forensic.analysis.rules import RuleCondition

        engine = TamperingRuleEngine()

        condition = RuleCondition(field="count", operator="less_than", value=5)
        assert engine._evaluate_condition(condition, {"count": 3}) is True
        assert engine._evaluate_condition(condition, {"count": 10}) is False

    def test_condition_contains(self):
        """Test contains condition."""
        from dwg_forensic.analysis.rules import RuleCondition

        engine = TamperingRuleEngine()

        condition = RuleCondition(field="text", operator="contains", value="hello")
        assert engine._evaluate_condition(condition, {"text": "hello world"}) is True
        assert engine._evaluate_condition(condition, {"text": "goodbye"}) is False

    def test_condition_not_contains(self):
        """Test not_contains condition."""
        from dwg_forensic.analysis.rules import RuleCondition

        engine = TamperingRuleEngine()

        condition = RuleCondition(field="text", operator="not_contains", value="bad")
        assert engine._evaluate_condition(condition, {"text": "good text"}) is True
        assert engine._evaluate_condition(condition, {"text": "bad text"}) is False

    def test_condition_exists(self):
        """Test exists condition."""
        from dwg_forensic.analysis.rules import RuleCondition

        engine = TamperingRuleEngine()

        condition = RuleCondition(field="data", operator="exists", value=None)
        assert engine._evaluate_condition(condition, {"data": "something"}) is True
        assert engine._evaluate_condition(condition, {"data": None}) is False

    def test_condition_not_exists(self):
        """Test not_exists condition."""
        from dwg_forensic.analysis.rules import RuleCondition

        engine = TamperingRuleEngine()

        condition = RuleCondition(field="data", operator="not_exists", value=None)
        assert engine._evaluate_condition(condition, {"data": None}) is True
        assert engine._evaluate_condition(condition, {"data": "something"}) is False

    def test_condition_nested_field(self):
        """Test condition with nested field path."""
        from dwg_forensic.analysis.rules import RuleCondition

        engine = TamperingRuleEngine()

        condition = RuleCondition(field="level1.level2.value", operator="equals", value="target")
        context = {"level1": {"level2": {"value": "target"}}}
        assert engine._evaluate_condition(condition, context) is True

    def test_condition_invalid_path(self):
        """Test condition with invalid field path."""
        from dwg_forensic.analysis.rules import RuleCondition

        engine = TamperingRuleEngine()

        condition = RuleCondition(field="missing.path", operator="equals", value="x")
        assert engine._evaluate_condition(condition, {}) is False


class TestSectionCRCRule:
    """Test TAMPER-002 section CRC rule."""

    def test_section_crc_failure(self):
        """Test section CRC failure detection."""
        engine = TamperingRuleEngine()
        context = {
            "crc": {
                "is_valid": True,
                "section_results": [
                    {"section_name": "Objects", "is_valid": False},
                    {"section_name": "Header", "is_valid": True},
                ],
            }
        }

        results = engine.evaluate_all(context)
        section_result = next(r for r in results if r.rule_id == "TAMPER-002")

        assert section_result.status == RuleStatus.FAILED
        assert "Objects" in section_result.description


class TestTimestampRules:
    """Test timestamp-related rules."""

    def test_timestamp_reversal_with_strings(self):
        """Test TAMPER-005 with ISO string timestamps."""
        engine = TamperingRuleEngine()
        context = {
            "metadata": {
                "created_date": "2025-01-01T12:00:00Z",
                "modified_date": "2020-01-01T12:00:00Z",  # Before creation
            }
        }

        results = engine.evaluate_all(context)
        ts_result = next(r for r in results if r.rule_id == "TAMPER-005")

        assert ts_result.status == RuleStatus.FAILED

    def test_future_timestamp_with_string(self):
        """Test TAMPER-006 with ISO string timestamp."""
        engine = TamperingRuleEngine()
        # Far future date
        context = {
            "metadata": {
                "modified_date": "2099-01-01T12:00:00Z",
            }
        }

        results = engine.evaluate_all(context)
        future_result = next(r for r in results if r.rule_id == "TAMPER-006")

        assert future_result.status == RuleStatus.FAILED

    def test_edit_time_mismatch_with_strings(self):
        """Test TAMPER-007 with ISO string timestamps and excessive edit time."""
        engine = TamperingRuleEngine()
        context = {
            "metadata": {
                "created_date": "2024-01-01T12:00:00Z",
                "modified_date": "2024-01-02T12:00:00Z",  # 24 hours later
                "total_editing_time_hours": 100.0,  # 100 hours in 24 hour span
            }
        }

        results = engine.evaluate_all(context)
        edit_result = next(r for r in results if r.rule_id == "TAMPER-007")

        assert edit_result.status == RuleStatus.FAILED


class TestVersionDowngradeRule:
    """Test TAMPER-008 version downgrade rule."""

    def test_version_downgrade_detection(self):
        """Test version downgrade detection via anomalies."""
        engine = TamperingRuleEngine()
        context = {
            "anomalies": [
                {"description": "Version downgrade detected"},
            ]
        }

        results = engine.evaluate_all(context)
        downgrade_result = next(r for r in results if r.rule_id == "TAMPER-008")

        assert downgrade_result.status == RuleStatus.FAILED


class TestNonAutodeskRule:
    """Test TAMPER-010 non-Autodesk origin rule."""

    def test_non_autodesk_origin(self):
        """Test non-Autodesk origin detection."""
        engine = TamperingRuleEngine()
        context = {
            "application_fingerprint": {
                "is_autodesk": False,
                "detected_application": "LibreCAD",
            }
        }

        results = engine.evaluate_all(context)
        origin_result = next(r for r in results if r.rule_id == "TAMPER-010")

        assert origin_result.status == RuleStatus.FAILED
        assert "LibreCAD" in origin_result.found


class TestOrphanedObjectsRule:
    """Test TAMPER-011 orphaned objects rule."""

    def test_orphaned_objects_detection(self):
        """Test orphaned objects detection via anomalies."""
        engine = TamperingRuleEngine()
        context = {
            "anomalies": [
                {"description": "Orphan object found at handle 0x123"},
            ]
        }

        results = engine.evaluate_all(context)
        orphan_result = next(r for r in results if r.rule_id == "TAMPER-011")

        assert orphan_result.status == RuleStatus.FAILED


class TestSlackSpaceRule:
    """Test TAMPER-012 slack space rule."""

    def test_slack_space_detection(self):
        """Test unusual slack space detection via anomalies."""
        engine = TamperingRuleEngine()
        context = {
            "anomalies": [
                {"description": "Unusual padding detected"},
            ]
        }

        results = engine.evaluate_all(context)
        slack_result = next(r for r in results if r.rule_id == "TAMPER-012")

        assert slack_result.status == RuleStatus.FAILED


class TestTDINDWGRule:
    """Test TAMPER-013 TDINDWG manipulation rule."""

    def test_tdindwg_manipulation_from_anomaly(self):
        """Test TDINDWG manipulation detection from anomaly."""
        engine = TamperingRuleEngine()
        context = {
            "anomalies": [
                {
                    "anomaly_type": "TDINDWG_EXCEEDS_SPAN",
                    "details": {
                        "calendar_span_days": 2.0,
                        "tdindwg_days": 5.0,
                    },
                },
            ]
        }

        results = engine.evaluate_all(context)
        tdindwg_result = next(r for r in results if r.rule_id == "TAMPER-013")

        assert tdindwg_result.status == RuleStatus.FAILED

    def test_tdindwg_manipulation_from_data(self):
        """Test TDINDWG manipulation detection from raw data."""
        engine = TamperingRuleEngine()
        context = {
            "timestamp_data": {
                "tdindwg": 10.0,  # 10 days editing
                "calendar_span_days": 5.0,  # Only 5 days elapsed
            }
        }

        results = engine.evaluate_all(context)
        tdindwg_result = next(r for r in results if r.rule_id == "TAMPER-013")

        assert tdindwg_result.status == RuleStatus.FAILED


class TestVersionAnachronismRule:
    """Test TAMPER-014 version anachronism rule."""

    def test_version_anachronism_from_anomaly(self):
        """Test version anachronism detection from anomaly."""
        engine = TamperingRuleEngine()
        context = {
            "anomalies": [
                {
                    "anomaly_type": "VERSION_ANACHRONISM",
                    "details": {
                        "version_name": "AutoCAD 2010",
                        "claimed_creation_date": "2008-01-01",
                        "version_release_date": "2009-03-01",
                    },
                },
            ]
        }

        results = engine.evaluate_all(context)
        anachronism_result = next(r for r in results if r.rule_id == "TAMPER-014")

        assert anachronism_result.status == RuleStatus.FAILED


class TestTimezoneDiscrepancyRule:
    """Test TAMPER-015 timezone discrepancy rule."""

    def test_timezone_discrepancy_from_anomaly(self):
        """Test timezone discrepancy detection from anomaly."""
        engine = TamperingRuleEngine()
        context = {
            "anomalies": [
                {
                    "anomaly_type": "TIMEZONE_DISCREPANCY",
                    "details": {"offset_hours": 20.0},
                },
            ]
        }

        results = engine.evaluate_all(context)
        tz_result = next(r for r in results if r.rule_id == "TAMPER-015")

        assert tz_result.status == RuleStatus.FAILED

    def test_timezone_discrepancy_from_data(self):
        """Test timezone discrepancy detection from raw data."""
        engine = TamperingRuleEngine()
        context = {
            "timestamp_data": {
                "timezone_offset_hours": -15.0,  # Invalid offset
            }
        }

        results = engine.evaluate_all(context)
        tz_result = next(r for r in results if r.rule_id == "TAMPER-015")

        assert tz_result.status == RuleStatus.FAILED


class TestEducationalWatermarkRule:
    """Test TAMPER-016 educational watermark rule."""

    def test_educational_watermark_detection(self):
        """Test educational watermark detection."""
        engine = TamperingRuleEngine()
        context = {
            "timestamp_data": {
                "educational_watermark": True,
            }
        }

        results = engine.evaluate_all(context)
        edu_result = next(r for r in results if r.rule_id == "TAMPER-016")

        assert edu_result.status == RuleStatus.FAILED
        assert "Educational" in edu_result.description


class TestTamperingScore:
    """Test get_tampering_score method."""

    def test_tampering_score_no_results(self):
        """Test tampering score with no results."""
        engine = TamperingRuleEngine()
        engine.results = []

        score = engine.get_tampering_score()

        assert score == 0.0

    def test_tampering_score_with_failures(self):
        """Test tampering score with failures."""
        from dwg_forensic.analysis.rules import RuleResult, RuleSeverity, RuleStatus

        engine = TamperingRuleEngine()
        engine.results = [
            RuleResult(
                rule_id="TEST-001",
                rule_name="Test",
                status=RuleStatus.FAILED,
                severity=RuleSeverity.CRITICAL,
                description="Failed",
                confidence=1.0,
            ),
            RuleResult(
                rule_id="TEST-002",
                rule_name="Test 2",
                status=RuleStatus.PASSED,
                severity=RuleSeverity.WARNING,
                description="Passed",
                confidence=1.0,
            ),
        ]

        score = engine.get_tampering_score()

        assert score > 0.0
        assert score <= 1.0


class TestTDUSRTIMERResetRule:
    """Test TAMPER-017 TDUSRTIMER reset rule."""

    def test_tdusrtimer_reset_detection(self):
        """Test TDUSRTIMER reset detection when significantly less than TDINDWG."""
        engine = TamperingRuleEngine()
        context = {
            "timestamp_data": {
                "tdindwg": 1.0,  # 1 day = 24 hours editing time
                "tdusrtimer": 0.1,  # 0.1 day = 2.4 hours (only 10%)
            }
        }

        results = engine.evaluate_all(context)
        reset_result = next(r for r in results if r.rule_id == "TAMPER-017")

        assert reset_result.status == RuleStatus.FAILED
        assert "reset" in reset_result.description.lower()

    def test_tdusrtimer_consistent(self):
        """Test TDUSRTIMER passes when consistent with TDINDWG."""
        engine = TamperingRuleEngine()
        context = {
            "timestamp_data": {
                "tdindwg": 1.0,  # 1 day = 24 hours
                "tdusrtimer": 0.95,  # 0.95 day = ~23 hours (within 10%)
            }
        }

        results = engine.evaluate_all(context)
        reset_result = next(r for r in results if r.rule_id == "TAMPER-017")

        assert reset_result.status == RuleStatus.PASSED

    def test_tdusrtimer_minimal_editing(self):
        """Test TDUSRTIMER passes with minimal editing time."""
        engine = TamperingRuleEngine()
        context = {
            "timestamp_data": {
                "tdindwg": 0.001,  # Very small editing time
                "tdusrtimer": 0.0,
            }
        }

        results = engine.evaluate_all(context)
        reset_result = next(r for r in results if r.rule_id == "TAMPER-017")

        assert reset_result.status == RuleStatus.PASSED
        assert "minimal" in reset_result.description.lower()

    def test_tdusrtimer_from_metadata(self):
        """Test TDUSRTIMER detection from metadata when timestamp_data missing."""
        engine = TamperingRuleEngine()
        context = {
            "metadata": {
                "tdindwg": 2.0,  # 48 hours
                "tdusrtimer": 0.1,  # 2.4 hours (5%)
            }
        }

        results = engine.evaluate_all(context)
        reset_result = next(r for r in results if r.rule_id == "TAMPER-017")

        assert reset_result.status == RuleStatus.FAILED

    def test_tdusrtimer_inconclusive_no_data(self):
        """Test TDUSRTIMER inconclusive when data missing."""
        engine = TamperingRuleEngine()
        context = {}

        results = engine.evaluate_all(context)
        reset_result = next(r for r in results if r.rule_id == "TAMPER-017")

        assert reset_result.status == RuleStatus.INCONCLUSIVE


class TestNetworkPathLeakageRule:
    """Test TAMPER-018 network path leakage rule."""

    def test_unc_path_detection(self):
        """Test detection of UNC paths."""
        engine = TamperingRuleEngine()
        context = {
            "metadata": {
                "network_paths_detected": [
                    "\\\\SERVER01\\Projects\\CAD\\drawing.dwg",
                    "\\\\FILESERVER\\Engineering\\ref.dwg",
                ]
            }
        }

        results = engine.evaluate_all(context)
        path_result = next(r for r in results if r.rule_id == "TAMPER-018")

        assert path_result.status == RuleStatus.FAILED
        assert "SERVER01" in path_result.description or "FILESERVER" in path_result.description
        assert path_result.details["path_count"] == 2
        assert "SERVER01" in path_result.details["servers_detected"]

    def test_url_path_detection(self):
        """Test detection of URL paths."""
        engine = TamperingRuleEngine()
        context = {
            "metadata": {
                "network_paths_detected": [
                    "https://cdn.company.com/assets/drawing.dwg",
                    "http://internal.corp/files/ref.dwg",
                ]
            }
        }

        results = engine.evaluate_all(context)
        path_result = next(r for r in results if r.rule_id == "TAMPER-018")

        assert path_result.status == RuleStatus.FAILED
        assert "cdn.company.com" in path_result.details["servers_detected"]
        assert "internal.corp" in path_result.details["servers_detected"]

    def test_no_network_paths(self):
        """Test passes when no network paths present."""
        engine = TamperingRuleEngine()
        context = {
            "metadata": {
                "network_paths_detected": []
            }
        }

        results = engine.evaluate_all(context)
        path_result = next(r for r in results if r.rule_id == "TAMPER-018")

        assert path_result.status == RuleStatus.PASSED

    def test_xref_paths_extraction(self):
        """Test extraction of network paths from xref_paths when network_paths_detected empty."""
        engine = TamperingRuleEngine()
        context = {
            "metadata": {
                "xref_paths": [
                    "\\\\CADSERVER\\xrefs\\floor_plan.dwg",
                    "C:\\Local\\reference.dwg",  # Local path, should be ignored
                ],
                "network_paths_detected": [],
            }
        }

        results = engine.evaluate_all(context)
        path_result = next(r for r in results if r.rule_id == "TAMPER-018")

        assert path_result.status == RuleStatus.FAILED
        assert "CADSERVER" in path_result.description

    def test_network_path_inconclusive_no_metadata(self):
        """Test passes when metadata is None (no paths to check)."""
        engine = TamperingRuleEngine()
        context = {}

        results = engine.evaluate_all(context)
        path_result = next(r for r in results if r.rule_id == "TAMPER-018")

        # With no metadata, there are no network paths, so it passes
        assert path_result.status == RuleStatus.PASSED


# ============================================================================
# NTFS Cross-Validation Rules Tests (TAMPER-019 through TAMPER-028)
# ============================================================================

class TestNTFSTimestompingRule:
    """Test TAMPER-019 NTFS Timestomping Detection rule."""

    def test_timestomping_detected(self):
        """Test detection of NTFS timestomping via SI/FN mismatch."""
        engine = TamperingRuleEngine()
        context = {
            "ntfs_data": {
                "si_fn_mismatch": True,  # Correct field name
                "mismatch_details": "SI created 2020-01-01, FN created 2024-06-15",
            }
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-019")

        assert result.status == RuleStatus.FAILED
        assert result.severity.value == "critical"
        assert "DEFINITIVE" in result.description or "TIMESTOMPING" in result.description

    def test_no_timestomping(self):
        """Test passes when no timestomping detected."""
        engine = TamperingRuleEngine()
        context = {
            "ntfs_data": {
                "si_fn_mismatch": False,
            }
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-019")

        assert result.status == RuleStatus.PASSED


class TestNTFSNanosecondTruncationRule:
    """Test TAMPER-020 NTFS Nanosecond Truncation rule."""

    def test_nanosecond_truncation_detected(self):
        """Test detection of nanosecond truncation (tool signature)."""
        engine = TamperingRuleEngine()
        context = {
            "ntfs_data": {
                "nanoseconds_truncated": True,  # Correct field name
                "truncation_details": "All timestamps end in .0000000",
            }
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-020")

        assert result.status == RuleStatus.FAILED
        assert "TOOL" in result.description or "truncat" in result.description.lower()

    def test_no_nanosecond_truncation(self):
        """Test passes when nanoseconds are normal."""
        engine = TamperingRuleEngine()
        context = {
            "ntfs_data": {
                "nanoseconds_truncated": False,
            }
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-020")

        assert result.status == RuleStatus.PASSED


class TestNTFSImpossibleTimestampRule:
    """Test TAMPER-021 NTFS Creation After Modification rule (now INFORMATIONAL)."""

    def test_impossible_timestamp_detected(self):
        """Test that creation_after_modification is now INFORMATIONAL (normal copy behavior).

        IMPORTANT: This test has been updated to reflect the corrected behavior.
        When a file is COPIED on Windows, the NTFS Created timestamp is set to the
        time of copy, but Modified is PRESERVED from the source. This results in
        Created > Modified, which is NORMAL Windows behavior, NOT tampering.
        """
        engine = TamperingRuleEngine()
        context = {
            "ntfs_data": {
                "creation_after_modification": True,  # Correct field name
                "si_created": "2024-06-15T10:00:00",
                "si_modified": "2024-01-01T10:00:00",
            }
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-021")

        # Changed from FAILED to PASSED - this is normal copy behavior
        assert result.status == RuleStatus.PASSED
        # Check for informational messaging about file copy
        assert "copied" in result.description.lower() or "info" in result.description.lower()

    def test_no_impossible_timestamps(self):
        """Test passes when timestamps are logically consistent."""
        engine = TamperingRuleEngine()
        context = {
            "ntfs_data": {
                "creation_after_modification": False,
            }
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-021")

        assert result.status == RuleStatus.PASSED


class TestDWGNTFSCreationContradictionRule:
    """Test TAMPER-022 DWG/NTFS Creation Contradiction rule."""

    def test_creation_contradiction_detected(self):
        """Test detection of DWG creation predating filesystem creation (now NORMAL for transfers)."""
        engine = TamperingRuleEngine()
        context = {
            "ntfs_contradictions": {
                "creation_time_difference": True,  # Renamed from creation_contradiction
                "creation_details": {
                    "dwg_created": "2020-01-01T10:00:00",
                    "ntfs_created": "2024-06-15T10:00:00",
                    "forensic_note": "DWG internal creation timestamp predates NTFS filesystem timestamp. This is EXPECTED for files that were copied or transferred.",
                    "is_normal_for_transferred_files": True,
                },
            }
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-022")

        # This is now informational - PASSED status indicates normal file transfer
        assert result.status == RuleStatus.PASSED
        assert "transfer" in result.description.lower() or "normal" in result.description.lower()

    def test_no_creation_contradiction(self):
        """Test passes when DWG and NTFS creation times are consistent."""
        engine = TamperingRuleEngine()
        context = {
            "ntfs_data": {
                "si_created": "2024-01-01T10:00:00",
            },
            "ntfs_contradictions": {
                "creation_time_difference": False,  # Renamed from creation_contradiction
            },
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-022")

        # Returns PASSED when we have ntfs_data and no time difference
        assert result.status == RuleStatus.PASSED


class TestDWGNTFSModificationContradictionRule:
    """Test TAMPER-023 DWG/NTFS Modification Contradiction rule."""

    def test_modification_contradiction_detected(self):
        """Test detection of DWG modification predating filesystem creation."""
        engine = TamperingRuleEngine()
        context = {
            "ntfs_contradictions": {
                "modification_contradiction": True,
                "modification_details": {
                    "dwg_modified": "2019-06-15T10:00:00",
                    "ntfs_created": "2024-06-15T10:00:00",
                    "forensic_conclusion": "DWG claims modification 5 years before file existed",
                },
            }
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-023")

        assert result.status == RuleStatus.FAILED

    def test_no_modification_contradiction(self):
        """Test passes when DWG and NTFS modification times are consistent."""
        engine = TamperingRuleEngine()
        context = {
            "ntfs_data": {
                "si_modified": "2024-06-15T10:00:00",
            },
            "ntfs_contradictions": {
                "modification_contradiction": False,
            },
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-023")

        # Returns PASSED when we have ntfs_data and no contradiction
        assert result.status == RuleStatus.PASSED


class TestZeroEditTimeRule:
    """Test TAMPER-024 Zero Edit Time rule."""

    def test_zero_edit_time_detected(self):
        """Test detection of zero or near-zero editing time."""
        engine = TamperingRuleEngine()
        context = {
            "timestamp_data": {
                "tdindwg": 0.00001,  # Near-zero editing time
            }
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-024")

        assert result.status == RuleStatus.FAILED

    def test_normal_edit_time(self):
        """Test passes when editing time is reasonable."""
        engine = TamperingRuleEngine()
        context = {
            "timestamp_data": {
                "tdindwg": 0.5,  # 12 hours of editing time
            }
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-024")

        assert result.status == RuleStatus.PASSED


class TestImplausibleEditRatioRule:
    """Test TAMPER-025 Implausible Edit Ratio rule."""

    def test_implausible_ratio_detected(self):
        """Test detection of implausible edit time to file size ratio."""
        engine = TamperingRuleEngine()
        context = {
            "timestamp_data": {
                "tdindwg": 0.0001,  # Very little editing time
            },
            "file": {
                "size": 10_000_000,  # 10 MB file
            }
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-025")

        assert result.status == RuleStatus.FAILED

    def test_plausible_ratio(self):
        """Test passes when edit ratio is reasonable."""
        engine = TamperingRuleEngine()
        context = {
            "timestamp_data": {
                "tdindwg": 1.0,  # 24 hours of editing
            },
            "file": {
                "size": 100_000,  # 100 KB file
            }
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-025")

        assert result.status == RuleStatus.PASSED


class TestThirdPartyToolRule:
    """Test TAMPER-026 Third-Party Tool Detection rule."""

    def test_third_party_tool_detected(self):
        """Test detection of known third-party tools returns PASSED (not tampering).

        Legitimate third-party CAD software (LibreCAD, BricsCAD, etc.) creates valid
        DWG files. Detecting their use is informational, not evidence of tampering.
        """
        engine = TamperingRuleEngine()
        context = {
            "application_fingerprint": {
                "is_autodesk": False,
                "is_oda_based": False,
                "detected_application": "LibreCAD",  # Known legitimate third-party tool
            }
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-026")

        # Legitimate third-party CAD software is not tampering
        assert result.status == RuleStatus.PASSED

    def test_autodesk_tool(self):
        """Test passes with valid Autodesk application fingerprint."""
        engine = TamperingRuleEngine()
        context = {
            "application_fingerprint": {
                "is_autodesk": True,
                "is_oda_based": False,
                "detected_application": "Autodesk AutoCAD 2024",
            }
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-026")

        assert result.status == RuleStatus.PASSED


class TestCompoundTimestampAnomalyRule:
    """Test TAMPER-027 Compound Timestamp Anomaly rule."""

    def test_compound_anomaly_detected(self):
        """Test detection of multiple timestamp anomalies."""
        engine = TamperingRuleEngine()
        context = {
            "anomalies": [
                {"anomaly_type": "TIMESTAMP_ANOMALY", "description": "Created after modified"},
                {"anomaly_type": "TDINDWG_EXCEEDS_SPAN", "description": "Edit time exceeds span"},
                {"anomaly_type": "NTFS_SI_FN_MISMATCH", "description": "SI/FN mismatch"},
            ],
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-027")

        assert result.status == RuleStatus.FAILED
        assert "COMPOUND" in result.description

    def test_no_compound_anomalies(self):
        """Test passes when only one anomaly present."""
        engine = TamperingRuleEngine()
        context = {
            "anomalies": [
                {"anomaly_type": "TIMESTAMP_ANOMALY", "description": "Single anomaly"},
            ],
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-027")

        assert result.status == RuleStatus.PASSED


class TestForensicImpossibilityScoreRule:
    """Test TAMPER-028 Forensic Impossibility Score rule."""

    def test_high_impossibility_score(self):
        """Test detection of high forensic impossibility score."""
        engine = TamperingRuleEngine()
        context = {
            "ntfs_data": {
                "si_fn_mismatch": True,  # +40 points (impossible condition)
                "creation_after_modification": True,  # +30 points (impossible condition)
                "nanoseconds_truncated": True,  # +10 points (strong indicator)
            },
            "ntfs_contradictions": {
                "creation_contradiction": True,  # +20 points (impossible condition)
            },
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-028")

        # With multiple impossible conditions, should fail
        assert result.status == RuleStatus.FAILED
        # Should be definitive with this many impossible conditions
        assert "DEFINITIVE" in result.description or "STRONG" in result.description or "SUBSTANTIAL" in result.description

    def test_low_impossibility_score(self):
        """Test passes with low impossibility score."""
        engine = TamperingRuleEngine()
        context = {
            "ntfs_data": {
                "si_fn_mismatch": False,
                "creation_after_modification": False,
                "nanoseconds_truncated": False,
            },
            "ntfs_contradictions": {
                "creation_contradiction": False,
                "modification_contradiction": False,
            },
        }

        results = engine.evaluate_all(context)
        result = next(r for r in results if r.rule_id == "TAMPER-028")

        assert result.status == RuleStatus.PASSED
