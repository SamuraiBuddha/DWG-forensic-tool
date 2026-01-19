"""Tests for fingerprinting rules (TAMPER-029 to TAMPER-035)."""

import pytest
from dwg_forensic.analysis.rules.rules_fingerprint import FingerprintRulesMixin
from dwg_forensic.analysis.rules.models import TamperingRule, RuleResult, RuleStatus, RuleSeverity


class TestFingerprintRulesMixin:
    """Test the FingerprintRulesMixin class."""

    def setup_method(self):
        """Set up test fixtures."""
        class TestEngine(FingerprintRulesMixin):
            pass
        self.engine = TestEngine()

    def _make_rule(self, rule_id: str) -> TamperingRule:
        """Create a mock rule for testing."""
        return TamperingRule(
            rule_id=rule_id,
            name=f"Test {rule_id}",
            description="Test rule",
            severity=RuleSeverity.INFO,
        )


class TestHelperMethods(TestFingerprintRulesMixin):
    """Tests for helper methods."""

    def test_get_forensic_meta_returns_dict(self):
        """Test _get_forensic_meta returns empty dict when missing."""
        context = {}
        result = self.engine._get_forensic_meta(context)
        assert result == {}

    def test_get_forensic_meta_returns_data(self):
        """Test _get_forensic_meta returns data when present."""
        context = {"forensic_meta": {"app_info": {"product_name": "Test"}}}
        result = self.engine._get_forensic_meta(context)
        assert result["app_info"]["product_name"] == "Test"

    def test_check_trusted_dwg_false_when_missing(self):
        """Test _check_trusted_dwg_authenticity returns False when missing."""
        context = {}
        result = self.engine._check_trusted_dwg_authenticity(context)
        assert result is False

    def test_check_trusted_dwg_true_when_autodesk(self):
        """Test _check_trusted_dwg_authenticity returns True for Autodesk."""
        context = {"forensic_meta": {"trusted_dwg": {"autodesk_app": True}}}
        result = self.engine._check_trusted_dwg_authenticity(context)
        assert result is True


class TestODAArtifacts(TestFingerprintRulesMixin):
    """Tests for TAMPER-029: ODA SDK Artifact Detection."""

    def test_detects_oda_from_fingerprint(self):
        """Test detection when cad_fingerprint.is_oda_based is True."""
        context = {
            "cad_fingerprint": {"is_oda_based": True},
            "oda_detection": {"is_oda_based": True, "detected_applications": ["bricscad"]},
        }
        rule = self._make_rule("TAMPER-029")
        result = self.engine._check_oda_sdk_artifacts(rule, context)
        assert result.status == RuleStatus.FAILED
        assert "ODA" in result.description

    def test_detects_oda_from_forensic_meta_bricscad(self):
        """Test detection from forensic_meta for BricsCAD."""
        context = {
            "cad_fingerprint": {},
            "oda_detection": {},
            "forensic_meta": {
                "app_info": {"product_name": "BricsCAD V24"}
            }
        }
        rule = self._make_rule("TAMPER-029")
        result = self.engine._check_oda_sdk_artifacts(rule, context)
        assert result.status == RuleStatus.FAILED

    def test_detects_oda_from_forensic_meta_nanocad(self):
        """Test detection from forensic_meta for NanoCAD."""
        context = {
            "cad_fingerprint": {},
            "oda_detection": {},
            "forensic_meta": {
                "app_info": {"product_name": "nanoCAD Plus 23.0"}
            }
        }
        rule = self._make_rule("TAMPER-029")
        result = self.engine._check_oda_sdk_artifacts(rule, context)
        assert result.status == RuleStatus.FAILED

    def test_no_oda_for_autocad(self):
        """Test no ODA detection for AutoCAD."""
        context = {
            "cad_fingerprint": {"is_oda_based": False},
            "oda_detection": {"is_oda_based": False},
            "forensic_meta": {
                "app_info": {"product_name": "AutoCAD 2024"},
                "trusted_dwg": {"autodesk_app": True}
            }
        }
        rule = self._make_rule("TAMPER-029")
        result = self.engine._check_oda_sdk_artifacts(rule, context)
        assert result.status == RuleStatus.PASSED

    def test_no_detection_empty_context(self):
        """Test no detection with empty context."""
        context = {"cad_fingerprint": {}, "oda_detection": {}}
        rule = self._make_rule("TAMPER-029")
        result = self.engine._check_oda_sdk_artifacts(rule, context)
        assert result.status == RuleStatus.PASSED


class TestBricsCADSignature(TestFingerprintRulesMixin):
    """Tests for TAMPER-030: BricsCAD Signature Detection."""

    def test_detects_bricscad_from_fingerprint(self):
        """Test detection from cad_fingerprint."""
        context = {
            "cad_fingerprint": {"detected_application": "bricscad"}
        }
        rule = self._make_rule("TAMPER-030")
        result = self.engine._check_bricscad_signature(rule, context)
        assert result.status == RuleStatus.FAILED
        assert "BricsCAD" in result.description

    def test_detects_bricscad_from_forensic_meta(self):
        """Test detection from forensic_meta."""
        context = {
            "cad_fingerprint": {"detected_application": "unknown"},
            "forensic_meta": {
                "app_info": {"product_name": "BricsCAD V24.2"}
            }
        }
        rule = self._make_rule("TAMPER-030")
        result = self.engine._check_bricscad_signature(rule, context)
        assert result.status == RuleStatus.FAILED

    def test_detects_bricsys_from_forensic_meta(self):
        """Test detection of Bricsys in product name."""
        context = {
            "cad_fingerprint": {"detected_application": ""},
            "forensic_meta": {
                "app_info": {"product_name": "Bricsys 24/7 Edition"}
            }
        }
        rule = self._make_rule("TAMPER-030")
        result = self.engine._check_bricscad_signature(rule, context)
        assert result.status == RuleStatus.FAILED

    def test_no_detection_for_autocad(self):
        """Test no detection for AutoCAD."""
        context = {
            "cad_fingerprint": {"detected_application": "autocad"},
            "forensic_meta": {"app_info": {"product_name": "AutoCAD 2024"}}
        }
        rule = self._make_rule("TAMPER-030")
        result = self.engine._check_bricscad_signature(rule, context)
        assert result.status == RuleStatus.PASSED


class TestNanoCADSignature(TestFingerprintRulesMixin):
    """Tests for TAMPER-031: NanoCAD Signature Detection."""

    def test_detects_nanocad_from_fingerprint(self):
        """Test detection from cad_fingerprint."""
        context = {
            "cad_fingerprint": {"detected_application": "nanocad"},
            "metadata": {}
        }
        rule = self._make_rule("TAMPER-031")
        result = self.engine._check_nanocad_signature(rule, context)
        assert result.status == RuleStatus.FAILED

    def test_detects_nanocad_from_forensic_meta(self):
        """Test detection from forensic_meta."""
        context = {
            "cad_fingerprint": {"detected_application": "unknown"},
            "metadata": {},
            "forensic_meta": {
                "app_info": {"product_name": "nanoCAD Plus 23.0"}
            }
        }
        rule = self._make_rule("TAMPER-031")
        result = self.engine._check_nanocad_signature(rule, context)
        assert result.status == RuleStatus.FAILED

    def test_detects_cyrillic_codepage(self):
        """Test detection from CP1251 Cyrillic codepage."""
        context = {
            "cad_fingerprint": {"detected_application": ""},
            "metadata": {"codepage": 1251}
        }
        rule = self._make_rule("TAMPER-031")
        result = self.engine._check_nanocad_signature(rule, context)
        assert result.status == RuleStatus.FAILED

    def test_no_detection_for_autocad(self):
        """Test no detection for AutoCAD."""
        context = {
            "cad_fingerprint": {"detected_application": "autocad"},
            "metadata": {"codepage": 1252}  # Western codepage
        }
        rule = self._make_rule("TAMPER-031")
        result = self.engine._check_nanocad_signature(rule, context)
        assert result.status == RuleStatus.PASSED


class TestDraftSightSignature(TestFingerprintRulesMixin):
    """Tests for TAMPER-032: DraftSight Signature Detection."""

    def test_detects_draftsight_from_fingerprint(self):
        """Test detection from cad_fingerprint."""
        context = {
            "cad_fingerprint": {"detected_application": "draftsight"},
            "metadata": {}
        }
        rule = self._make_rule("TAMPER-032")
        result = self.engine._check_draftsight_signature(rule, context)
        assert result.status == RuleStatus.FAILED

    def test_detects_draftsight_from_forensic_meta(self):
        """Test detection from forensic_meta."""
        context = {
            "cad_fingerprint": {"detected_application": "unknown"},
            "metadata": {},
            "forensic_meta": {
                "app_info": {"product_name": "DraftSight 2023"}
            }
        }
        rule = self._make_rule("TAMPER-032")
        result = self.engine._check_draftsight_signature(rule, context)
        assert result.status == RuleStatus.FAILED

    def test_detects_dassault_from_forensic_meta(self):
        """Test detection of Dassault in product name."""
        context = {
            "cad_fingerprint": {"detected_application": ""},
            "metadata": {},
            "forensic_meta": {
                "app_info": {"product_name": "Dassault CAD Suite"}
            }
        }
        rule = self._make_rule("TAMPER-032")
        result = self.engine._check_draftsight_signature(rule, context)
        assert result.status == RuleStatus.FAILED

    def test_no_detection_for_autocad(self):
        """Test no detection for AutoCAD."""
        context = {
            "cad_fingerprint": {"detected_application": "autocad"},
            "metadata": {}
        }
        rule = self._make_rule("TAMPER-032")
        result = self.engine._check_draftsight_signature(rule, context)
        assert result.status == RuleStatus.PASSED


class TestZeroTimestampPattern(TestFingerprintRulesMixin):
    """Tests for TAMPER-034: Zero Timestamp Pattern Detection."""

    def test_detects_zero_timestamps(self):
        """Test detection of zero timestamps."""
        context = {
            "timestamp_data": {"tdcreate": 0, "tdupdate": 0},
            "metadata": {},
            "timestamp_anomalies": {}
        }
        rule = self._make_rule("TAMPER-034")
        result = self.engine._check_zero_timestamp_pattern(rule, context)
        assert result.status == RuleStatus.FAILED

    def test_detects_identical_with_zero_tdindwg(self):
        """Test detection of identical timestamps with zero TDINDWG."""
        context = {
            "timestamp_data": {"tdcreate": 2460000.5, "tdupdate": 2460000.5, "tdindwg": 0},
            "metadata": {},
            "timestamp_anomalies": {}
        }
        rule = self._make_rule("TAMPER-034")
        result = self.engine._check_zero_timestamp_pattern(rule, context)
        assert result.status == RuleStatus.FAILED

    def test_no_detection_for_valid_timestamps(self):
        """Test no detection for valid timestamps."""
        context = {
            "timestamp_data": {"tdcreate": 2460000.5, "tdupdate": 2460001.5, "tdindwg": 0.04},
            "metadata": {},
            "timestamp_anomalies": {}
        }
        rule = self._make_rule("TAMPER-034")
        result = self.engine._check_zero_timestamp_pattern(rule, context)
        assert result.status == RuleStatus.PASSED


class TestMissingAutoCADIdentifiers(TestFingerprintRulesMixin):
    """Tests for TAMPER-035: Missing AutoCAD Identifiers Detection."""

    def test_detects_missing_guids(self):
        """Test detection of missing GUIDs."""
        context = {
            "metadata": {"some_field": "value"},
            "timestamp_anomalies": {}
        }
        rule = self._make_rule("TAMPER-035")
        result = self.engine._check_missing_autocad_identifiers(rule, context)
        assert result.status == RuleStatus.FAILED

    def test_passes_with_valid_guids(self):
        """Test passing when GUIDs are present."""
        context = {
            "metadata": {
                "fingerprintguid": "{12345678-1234-1234-1234-123456789012}",
                "versionguid": "{87654321-4321-4321-4321-210987654321}"
            },
            "timestamp_anomalies": {}
        }
        rule = self._make_rule("TAMPER-035")
        result = self.engine._check_missing_autocad_identifiers(rule, context)
        assert result.status == RuleStatus.PASSED

    def test_detects_null_guids(self):
        """Test detection of null GUIDs."""
        context = {
            "metadata": {
                "fingerprintguid": "{00000000-0000-0000-0000-000000000000}",
                "versionguid": "{00000000-0000-0000-0000-000000000000}"
            },
            "timestamp_anomalies": {}
        }
        rule = self._make_rule("TAMPER-035")
        result = self.engine._check_missing_autocad_identifiers(rule, context)
        assert result.status == RuleStatus.FAILED

    def test_critical_when_trusted_dwg_says_autodesk(self):
        """Test CRITICAL detection when TrustedDWG confirms Autodesk but GUIDs missing."""
        context = {
            "metadata": {"some_field": "value"},
            "timestamp_anomalies": {},
            "forensic_meta": {"trusted_dwg": {"autodesk_app": True}}
        }
        rule = self._make_rule("TAMPER-035")
        result = self.engine._check_missing_autocad_identifiers(rule, context)
        assert result.status == RuleStatus.FAILED
        assert "CRITICAL" in result.description
        assert result.confidence > 0.9

    def test_no_detection_with_empty_metadata(self):
        """Test that empty metadata returns PASSED (cannot determine)."""
        context = {"metadata": {}, "timestamp_anomalies": {}}
        rule = self._make_rule("TAMPER-035")
        result = self.engine._check_missing_autocad_identifiers(rule, context)
        assert result.status == RuleStatus.PASSED
