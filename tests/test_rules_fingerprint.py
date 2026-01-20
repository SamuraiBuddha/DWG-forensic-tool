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
    """Tests for TAMPER-029: ODA SDK Artifact Detection.

    NOTE: ODA SDK-based tools are LEGITIMATE software. Detection returns
    PASSED status (informational) - not FAILED. This is intentional behavior.
    """

    def test_detects_oda_from_fingerprint(self):
        """Test detection when cad_fingerprint.is_oda_based is True.

        ODA detection returns PASSED because ODA SDK tools are legitimate.
        """
        context = {
            "cad_fingerprint": {"is_oda_based": True},
            "oda_detection": {"is_oda_based": True, "detected_applications": ["bricscad"]},
        }
        rule = self._make_rule("TAMPER-029")
        result = self.engine._check_oda_sdk_artifacts(rule, context)
        # ODA tools are legitimate - detection is informational, not a failure
        assert result.status == RuleStatus.PASSED
        assert "ODA" in result.description
        assert result.details.get("is_oda_based") is True

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
        # BricsCAD is legitimate ODA-based software - passes
        assert result.status == RuleStatus.PASSED

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
        # NanoCAD is legitimate ODA-based software - passes
        assert result.status == RuleStatus.PASSED

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
    """Tests for TAMPER-030: BricsCAD Signature Detection.

    NOTE: BricsCAD is LEGITIMATE software. Detection returns PASSED status
    (informational) - not FAILED. This is intentional behavior.
    """

    def test_detects_bricscad_from_fingerprint(self):
        """Test detection from cad_fingerprint.

        BricsCAD detection returns PASSED because it's legitimate software.
        """
        context = {
            "cad_fingerprint": {"detected_application": "bricscad"}
        }
        rule = self._make_rule("TAMPER-030")
        result = self.engine._check_bricscad_signature(rule, context)
        # BricsCAD is legitimate - detection is informational, not a failure
        assert result.status == RuleStatus.PASSED
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
        # BricsCAD is legitimate software - passes
        assert result.status == RuleStatus.PASSED

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
        # Bricsys products are legitimate - passes
        assert result.status == RuleStatus.PASSED

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
    """Tests for TAMPER-031: NanoCAD Signature Detection.

    NOTE: NanoCAD is LEGITIMATE software. Detection returns PASSED status
    (informational) - not FAILED. This is intentional behavior.
    """

    def test_detects_nanocad_from_fingerprint(self):
        """Test detection from cad_fingerprint.

        NanoCAD detection returns PASSED because it's legitimate software.
        """
        context = {
            "cad_fingerprint": {"detected_application": "nanocad"},
            "metadata": {}
        }
        rule = self._make_rule("TAMPER-031")
        result = self.engine._check_nanocad_signature(rule, context)
        # NanoCAD is legitimate - detection is informational, not a failure
        assert result.status == RuleStatus.PASSED

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
        # NanoCAD is legitimate software - passes
        assert result.status == RuleStatus.PASSED

    def test_detects_cyrillic_codepage(self):
        """Test detection from CP1251 Cyrillic codepage.

        Cyrillic codepage suggests NanoCAD but is not definitive evidence.
        """
        context = {
            "cad_fingerprint": {"detected_application": ""},
            "metadata": {"codepage": 1251}
        }
        rule = self._make_rule("TAMPER-031")
        result = self.engine._check_nanocad_signature(rule, context)
        # NanoCAD indication via codepage - passes as legitimate
        assert result.status == RuleStatus.PASSED

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
    """Tests for TAMPER-032: DraftSight Signature Detection.

    NOTE: DraftSight is LEGITIMATE software. Detection returns PASSED status
    (informational) - not FAILED. This is intentional behavior.
    """

    def test_detects_draftsight_from_fingerprint(self):
        """Test detection from cad_fingerprint.

        DraftSight detection returns PASSED because it's legitimate software.
        """
        context = {
            "cad_fingerprint": {"detected_application": "draftsight"},
            "metadata": {}
        }
        rule = self._make_rule("TAMPER-032")
        result = self.engine._check_draftsight_signature(rule, context)
        # DraftSight is legitimate - detection is informational, not a failure
        assert result.status == RuleStatus.PASSED

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
        # DraftSight is legitimate software - passes
        assert result.status == RuleStatus.PASSED

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
        # Dassault products (DraftSight) are legitimate software - passes
        assert result.status == RuleStatus.PASSED

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

    def test_revit_export_passes_missing_identifiers(self):
        """Test that Revit exports pass even with missing identifiers."""
        context = {
            "metadata": {
                "fingerprintguid": "30314341-3233-0000-0000-000003c00100",
                "some_field": "value"
            },
            "timestamp_anomalies": {},
        }
        rule = self._make_rule("TAMPER-035")
        result = self.engine._check_missing_autocad_identifiers(rule, context)
        assert result.status == RuleStatus.PASSED
        assert "Revit" in result.description or result.details.get("is_revit_export")


class TestRevitExportDetection(TestFingerprintRulesMixin):
    """Tests for TAMPER-041: Revit Export Signature Detection."""

    def test_detects_revit_from_guid_pattern(self):
        """Test detection from GUID prefix 30314341 (ASCII '01CA')."""
        context = {
            "metadata": {"fingerprintguid": "30314341-3233-0000-0000-000003c00100"},
        }
        rule = self._make_rule("TAMPER-041")
        result = self.engine._check_revit_export_signature(rule, context)
        assert result.status == RuleStatus.PASSED
        assert "Revit" in result.description or result.details.get("is_revit_export")

    def test_detects_revit_from_revit_detection_context(self):
        """Test detection from revit_detection context."""
        context = {
            "metadata": {},
            "revit_detection": {"is_revit_export": True, "confidence_score": 0.85},
        }
        rule = self._make_rule("TAMPER-041")
        result = self.engine._check_revit_export_signature(rule, context)
        assert result.status == RuleStatus.PASSED
        assert result.details.get("is_revit_export")

    def test_detects_revit_from_crc_flag(self):
        """Test detection from CRC validation Revit flag."""
        context = {
            "metadata": {},
            "crc_validation": {"is_revit_export": True},
        }
        rule = self._make_rule("TAMPER-041")
        result = self.engine._check_revit_export_signature(rule, context)
        assert result.status == RuleStatus.PASSED

    def test_no_detection_for_autocad(self):
        """Test no detection for AutoCAD files."""
        context = {
            "metadata": {
                "fingerprintguid": "{12345678-1234-1234-1234-123456789012}",
                "versionguid": "{87654321-4321-4321-4321-210987654321}"
            },
            "crc_validation": {"is_valid": True},
        }
        rule = self._make_rule("TAMPER-041")
        result = self.engine._check_revit_export_signature(rule, context)
        assert result.status == RuleStatus.PASSED
        assert not result.details or not result.details.get("is_revit_export")

    def test_helper_method_check_revit_export(self):
        """Test the _check_revit_export helper method."""
        # Test with Revit GUID pattern
        context = {
            "metadata": {"fingerprintguid": "30314341-3233-0000-0000-000003c00100"},
        }
        result = self.engine._check_revit_export(context)
        assert result["is_revit"]
        assert result["confidence"] >= 0.9
        assert "guid_01ca_pattern" in result["indicators"]

        # Test with revit_detection context
        context = {
            "metadata": {},
            "revit_detection": {"is_revit_export": True, "confidence_score": 0.85},
        }
        result = self.engine._check_revit_export(context)
        assert result["is_revit"]

        # Test with no Revit indicators
        context = {
            "metadata": {"fingerprintguid": "{12345678-1234-1234-1234-123456789012}"},
        }
        result = self.engine._check_revit_export(context)
        assert not result["is_revit"]


class TestZeroTimestampWithRevit(TestFingerprintRulesMixin):
    """Tests for TAMPER-034 with Revit export handling."""

    def test_revit_export_passes_zero_timestamps(self):
        """Test that Revit exports pass even with zero timestamps."""
        context = {
            "metadata": {"fingerprintguid": "30314341-3233-0000-0000-000003c00100"},
            "timestamp_data": {"tdcreate": 0, "tdupdate": 0, "tdindwg": 0},
            "timestamp_anomalies": {},
        }
        rule = self._make_rule("TAMPER-034")
        result = self.engine._check_zero_timestamp_pattern(rule, context)
        assert result.status == RuleStatus.PASSED
        assert "Revit" in result.description or result.details.get("is_revit_export")
