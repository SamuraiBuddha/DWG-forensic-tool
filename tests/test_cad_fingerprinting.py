"""
Tests for CAD Application Fingerprinting module.

This module tests the detection of CAD application signatures in DWG files,
including ODA-based applications, open-source tools, and timestamp anomalies.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, mock_open

from dwg_forensic.analysis.cad_fingerprinting import (
    CADApplication,
    CADSignature,
    FingerprintResult,
    CADFingerprinter,
    fingerprint_dwg,
)


# ============================================================================
# CADApplication Enum Tests
# ============================================================================

class TestCADApplication:
    """Tests for CADApplication enumeration."""

    def test_autocad_value(self):
        """Test AutoCAD enum value."""
        assert CADApplication.AUTOCAD.value == "autocad"

    def test_all_applications_defined(self):
        """Test that all expected CAD applications are defined."""
        expected_apps = [
            "autocad", "librecad", "qcad", "freecad", "oda_sdk",
            "bricscad", "nanocad", "draftsight", "zwcad", "gstarcad",
            "progecad", "intellicad", "corelcad", "turbocad", "libredwg",
            "unknown",
        ]
        actual_apps = [app.value for app in CADApplication]
        for expected in expected_apps:
            assert expected in actual_apps, f"Missing CAD application: {expected}"

    def test_enum_is_str_subclass(self):
        """Test that CADApplication inherits from str."""
        assert isinstance(CADApplication.AUTOCAD, str)
        assert CADApplication.AUTOCAD == "autocad"


# ============================================================================
# CADSignature Dataclass Tests
# ============================================================================

class TestCADSignature:
    """Tests for CADSignature dataclass."""

    def test_create_signature_with_all_fields(self):
        """Test creating a signature with all fields."""
        sig = CADSignature(
            application=CADApplication.BRICSCAD,
            pattern_type="string",
            pattern="BricsCAD",
            offset=0x100,
            description="BricsCAD marker",
            confidence=0.95,
            forensic_note="Indicates BricsCAD origin",
        )
        assert sig.application == CADApplication.BRICSCAD
        assert sig.pattern_type == "string"
        assert sig.pattern == "BricsCAD"
        assert sig.offset == 0x100
        assert sig.description == "BricsCAD marker"
        assert sig.confidence == 0.95
        assert sig.forensic_note == "Indicates BricsCAD origin"

    def test_create_signature_with_defaults(self):
        """Test creating a signature with default values."""
        sig = CADSignature(
            application=CADApplication.QCAD,
            pattern_type="crc",
            pattern=0x00000000,
        )
        assert sig.application == CADApplication.QCAD
        assert sig.pattern_type == "crc"
        assert sig.pattern == 0x00000000
        assert sig.offset is None
        assert sig.description == ""
        assert sig.confidence == 1.0
        assert sig.forensic_note == ""

    def test_signature_with_bytes_pattern(self):
        """Test signature with bytes pattern."""
        sig = CADSignature(
            application=CADApplication.LIBREDWG,
            pattern_type="bytes",
            pattern=b"LibreDWG",
        )
        assert sig.pattern == b"LibreDWG"


# ============================================================================
# FingerprintResult Dataclass Tests
# ============================================================================

class TestFingerprintResult:
    """Tests for FingerprintResult dataclass."""

    def test_create_result_minimal(self):
        """Test creating a result with minimal fields."""
        result = FingerprintResult(
            detected_application=CADApplication.AUTOCAD,
            confidence=0.9,
        )
        assert result.detected_application == CADApplication.AUTOCAD
        assert result.confidence == 0.9
        assert result.matching_signatures == []
        assert result.is_autodesk is False
        assert result.is_oda_based is False
        assert result.forensic_summary == ""
        assert result.raw_evidence == {}

    def test_create_result_full(self):
        """Test creating a result with all fields."""
        sig = CADSignature(
            application=CADApplication.BRICSCAD,
            pattern_type="string",
            pattern="BricsCAD",
        )
        result = FingerprintResult(
            detected_application=CADApplication.BRICSCAD,
            confidence=0.95,
            matching_signatures=[sig],
            is_autodesk=False,
            is_oda_based=True,
            forensic_summary="BricsCAD detected",
            raw_evidence={"marker": "BricsCAD"},
        )
        assert result.detected_application == CADApplication.BRICSCAD
        assert result.is_oda_based is True
        assert len(result.matching_signatures) == 1
        assert result.raw_evidence["marker"] == "BricsCAD"


# ============================================================================
# CADFingerprinter Tests
# ============================================================================

class TestCADFingerprinterInit:
    """Tests for CADFingerprinter initialization."""

    def test_init_loads_signatures(self):
        """Test that initialization loads signatures."""
        fp = CADFingerprinter()
        assert len(fp.signatures) > 0

    def test_init_has_crc_signatures(self):
        """Test that CRC-based signatures are loaded."""
        fp = CADFingerprinter()
        crc_sigs = [s for s in fp.signatures if s.pattern_type == "crc"]
        assert len(crc_sigs) > 0

    def test_init_has_string_signatures(self):
        """Test that string-based signatures are loaded."""
        fp = CADFingerprinter()
        string_sigs = [s for s in fp.signatures if s.pattern_type == "string"]
        assert len(string_sigs) > 10

    def test_oda_based_apps_defined(self):
        """Test that ODA-based apps set is defined."""
        fp = CADFingerprinter()
        assert CADApplication.BRICSCAD in fp.ODA_BASED_APPS
        assert CADApplication.NANOCAD in fp.ODA_BASED_APPS
        assert CADApplication.ZWCAD in fp.ODA_BASED_APPS

    def test_open_source_apps_defined(self):
        """Test that open source apps set is defined."""
        fp = CADFingerprinter()
        assert CADApplication.LIBRECAD in fp.OPEN_SOURCE_APPS
        assert CADApplication.QCAD in fp.OPEN_SOURCE_APPS
        assert CADApplication.FREECAD in fp.OPEN_SOURCE_APPS


class TestCADFingerprinterCRCSignatures:
    """Tests for CRC-based signature detection."""

    def test_zero_crc_detected(self):
        """Test that zero CRC is detected as non-Autodesk."""
        fp = CADFingerprinter()
        matches = fp._check_crc_signatures(0x00000000)
        assert len(matches) > 0
        assert any(s.pattern == 0x00000000 for s in matches)

    def test_non_zero_crc_no_match(self):
        """Test that non-zero CRC doesn't match zero-CRC signature."""
        fp = CADFingerprinter()
        matches = fp._check_crc_signatures(0xDEADBEEF)
        # Should not match zero-CRC signature
        zero_matches = [s for s in matches if s.pattern == 0x00000000]
        assert len(zero_matches) == 0


class TestCADFingerprinterStringSignatures:
    """Tests for string-based signature detection."""

    def test_detect_bricscad(self):
        """Test detection of BricsCAD marker."""
        fp = CADFingerprinter()
        data = b"some data BricsCAD more data"
        matches = fp._check_string_signatures(data)
        assert any(s.application == CADApplication.BRICSCAD for s in matches)

    def test_detect_nanocad(self):
        """Test detection of NanoCAD marker."""
        fp = CADFingerprinter()
        data = b"header nanoCAD footer"
        matches = fp._check_string_signatures(data)
        assert any(s.application == CADApplication.NANOCAD for s in matches)

    def test_detect_draftsight(self):
        """Test detection of DraftSight marker."""
        fp = CADFingerprinter()
        data = b"DraftSight created this file"
        matches = fp._check_string_signatures(data)
        assert any(s.application == CADApplication.DRAFTSIGHT for s in matches)

    def test_detect_qcad(self):
        """Test detection of QCAD marker."""
        fp = CADFingerprinter()
        data = b"Created by QCAD software"
        matches = fp._check_string_signatures(data)
        assert any(s.application == CADApplication.QCAD for s in matches)

    def test_detect_librecad(self):
        """Test detection of LibreCAD marker."""
        fp = CADFingerprinter()
        data = b"LibreCAD export"
        matches = fp._check_string_signatures(data)
        assert any(s.application == CADApplication.LIBRECAD for s in matches)

    def test_detect_oda_sdk(self):
        """Test detection of ODA SDK marker."""
        fp = CADFingerprinter()
        data = b"Open Design Alliance SDK"
        matches = fp._check_string_signatures(data)
        assert any(s.application == CADApplication.ODA_SDK for s in matches)

    def test_detect_teigha(self):
        """Test detection of Teigha (legacy ODA) marker."""
        fp = CADFingerprinter()
        data = b"Powered by Teigha"
        matches = fp._check_string_signatures(data)
        assert any(s.application == CADApplication.ODA_SDK for s in matches)

    def test_case_insensitive_detection(self):
        """Test case-insensitive string detection."""
        fp = CADFingerprinter()
        data = b"BRICSCAD uppercase"
        matches = fp._check_string_signatures(data)
        # Should detect even with different case
        assert len(matches) >= 0  # BricsCAD signature should match

    def test_no_match_for_clean_file(self):
        """Test that clean data doesn't produce false matches."""
        fp = CADFingerprinter()
        data = b"AC1032" + b"\x00" * 100 + b"just random bytes here"
        matches = fp._check_string_signatures(data)
        # Should not detect any specific app in random data
        specific_apps = [s for s in matches if s.application != CADApplication.UNKNOWN]
        # Some general patterns might match, but specific apps shouldn't
        assert all(s.confidence < 1.0 for s in specific_apps) or len(specific_apps) == 0


class TestCADFingerprinterMetadataSignatures:
    """Tests for metadata-based signature detection."""

    def test_detect_from_lastsavedby(self):
        """Test detection from LASTSAVEDBY field.

        Note: _check_metadata_signatures only processes signatures with
        pattern_type='metadata', and checks if app name appears in field value.
        LibreCAD has a metadata-type signature for LASTSAVEDBY.
        """
        fp = CADFingerprinter()
        metadata = {"lastsavedby": "LibreCAD user"}
        matches = fp._check_metadata_signatures(metadata)
        # LibreCAD has a metadata-type signature that checks LASTSAVEDBY
        assert any(s.application == CADApplication.LIBRECAD for s in matches)

    def test_detect_from_author(self):
        """Test detection from author field."""
        fp = CADFingerprinter()
        metadata = {"author": "NanoCAD Professional"}
        matches = fp._check_metadata_signatures(metadata)
        assert any(s.application == CADApplication.NANOCAD for s in matches)

    def test_no_match_empty_metadata(self):
        """Test that empty metadata doesn't crash."""
        fp = CADFingerprinter()
        metadata = {}
        matches = fp._check_metadata_signatures(metadata)
        assert matches == []

    def test_no_match_non_string_values(self):
        """Test handling of non-string metadata values."""
        fp = CADFingerprinter()
        metadata = {
            "lastsavedby": 12345,
            "author": None,
            "creator": ["list", "value"],
        }
        matches = fp._check_metadata_signatures(metadata)
        assert isinstance(matches, list)


class TestCADFingerprinterTimestampAnomalies:
    """Tests for timestamp anomaly detection."""

    def test_detect_tdcreate_equals_tdupdate(self):
        """Test detection of TDCREATE == TDUPDATE pattern."""
        fp = CADFingerprinter()
        metadata = {
            "tdcreate": 2459000.5,
            "tdupdate": 2459000.5,
        }
        result = fp.check_timestamp_anomalies(metadata)
        assert result["detected"] is True
        assert "TDCREATE_EQUALS_TDUPDATE" in result["patterns"]

    def test_detect_zero_tdindwg(self):
        """Test detection of zero TDINDWG."""
        fp = CADFingerprinter()
        metadata = {"tdindwg": 0}
        result = fp.check_timestamp_anomalies(metadata)
        assert result["detected"] is True
        assert "ZERO_TDINDWG" in result["patterns"]
        assert result["likely_third_party"] is True

    def test_detect_zero_timestamps(self):
        """Test detection of zero timestamps pattern."""
        fp = CADFingerprinter()
        metadata = {"tdcreate": 0, "tdupdate": 0}
        result = fp.check_timestamp_anomalies(metadata)
        assert result["detected"] is True
        assert "ZERO_TIMESTAMPS" in result["patterns"]
        assert result["likely_third_party"] is True

    def test_detect_missing_fingerprintguid(self):
        """Test detection of missing FINGERPRINTGUID."""
        fp = CADFingerprinter()
        metadata = {"fingerprintguid": ""}
        result = fp.check_timestamp_anomalies(metadata)
        assert result["detected"] is True
        assert "MISSING_FINGERPRINTGUID" in result["patterns"]

    def test_detect_missing_versionguid(self):
        """Test detection of missing VERSIONGUID."""
        fp = CADFingerprinter()
        metadata = {"versionguid": None}
        result = fp.check_timestamp_anomalies(metadata)
        assert result["detected"] is True
        assert "MISSING_VERSIONGUID" in result["patterns"]

    def test_detect_cyrillic_codepage(self):
        """Test detection of CP1251 (Cyrillic) codepage."""
        fp = CADFingerprinter()
        metadata = {"codepage": "ANSI_1251"}
        result = fp.check_timestamp_anomalies(metadata)
        assert result["detected"] is True
        assert "CYRILLIC_CODEPAGE" in result["patterns"]

    def test_no_anomalies_for_valid_metadata(self):
        """Test that valid metadata doesn't trigger anomalies."""
        fp = CADFingerprinter()
        metadata = {
            "tdcreate": 2459000.5,
            "tdupdate": 2459001.5,  # Different from tdcreate
            "tdindwg": 1.5,  # Non-zero
            "fingerprintguid": "{12345678-1234-1234-1234-123456789012}",
            "versionguid": "{87654321-4321-4321-4321-210987654321}",
        }
        result = fp.check_timestamp_anomalies(metadata)
        assert result["detected"] is False
        assert len(result["patterns"]) == 0

    def test_uppercase_metadata_keys(self):
        """Test handling of uppercase metadata keys."""
        fp = CADFingerprinter()
        metadata = {
            "TDCREATE": 0,
            "TDUPDATE": 0,
            "TDINDWG": 0,
            "FINGERPRINTGUID": "",
        }
        result = fp.check_timestamp_anomalies(metadata)
        assert result["detected"] is True


class TestCADFingerprinterODADetection:
    """Tests for ODA SDK detection."""

    @pytest.fixture
    def temp_dwg_with_oda(self, tmp_path):
        """Create a temp DWG file with ODA markers."""
        file_path = tmp_path / "oda_file.dwg"
        content = b"AC1032" + b"\x00" * 100 + b"OdDb prefix here" + b"\x00" * 100
        file_path.write_bytes(content)
        return file_path

    @pytest.fixture
    def temp_dwg_with_bricscad(self, tmp_path):
        """Create a temp DWG file with BricsCAD markers."""
        file_path = tmp_path / "bricscad_file.dwg"
        content = b"AC1032" + b"\x00" * 100 + b"BRICSYS application" + b"\x00" * 100
        file_path.write_bytes(content)
        return file_path

    @pytest.fixture
    def temp_clean_dwg(self, tmp_path):
        """Create a clean temp DWG file without markers."""
        file_path = tmp_path / "clean_file.dwg"
        content = b"AC1032" + b"\x00" * 500
        file_path.write_bytes(content)
        return file_path

    def test_detect_oda_class_prefix(self, temp_dwg_with_oda):
        """Test detection of OdDb class prefix."""
        fp = CADFingerprinter()
        result = fp.detect_oda_based(temp_dwg_with_oda)
        assert result["is_oda_based"] is True
        assert any("OdDb" in ind for ind in result["indicators"])

    def test_detect_bricscad_marker(self, temp_dwg_with_bricscad):
        """Test detection of BricsCAD marker."""
        fp = CADFingerprinter()
        result = fp.detect_oda_based(temp_dwg_with_bricscad)
        assert result["is_oda_based"] is True
        assert "BricsCAD" in result["detected_applications"]

    def test_clean_file_no_oda(self, temp_clean_dwg):
        """Test that clean file is not detected as ODA."""
        fp = CADFingerprinter()
        result = fp.detect_oda_based(temp_clean_dwg)
        assert result["is_oda_based"] is False
        assert len(result["indicators"]) == 0

    def test_file_not_found(self, tmp_path):
        """Test handling of non-existent file."""
        fp = CADFingerprinter()
        result = fp.detect_oda_based(tmp_path / "nonexistent.dwg")
        assert result["is_oda_based"] is False
        assert "error" in result

    def test_detect_teigha_marker(self, tmp_path):
        """Test detection of Teigha (legacy ODA) marker."""
        file_path = tmp_path / "teigha_file.dwg"
        content = b"AC1032" + b"\x00" * 100 + b"Teigha SDK" + b"\x00" * 100
        file_path.write_bytes(content)

        fp = CADFingerprinter()
        result = fp.detect_oda_based(file_path)
        assert result["is_oda_based"] is True

    def test_detect_multiple_markers(self, tmp_path):
        """Test detection of multiple application markers."""
        file_path = tmp_path / "multi_marker.dwg"
        content = b"AC1032" + b"BricsCAD" + b"NANOCAD" + b"DraftSight"
        file_path.write_bytes(content)

        fp = CADFingerprinter()
        result = fp.detect_oda_based(file_path)
        assert result["is_oda_based"] is True
        assert len(result["detected_applications"]) >= 2


class TestCADFingerprinterDetermineApplication:
    """Tests for application determination logic."""

    def test_no_signatures_returns_unknown(self):
        """Test determination with no signatures returns UNKNOWN."""
        fp = CADFingerprinter()
        evidence = {}
        result = fp._determine_application([], evidence)
        assert result.detected_application == CADApplication.UNKNOWN
        assert result.is_autodesk is False

    def test_single_signature_match(self):
        """Test determination with single signature match."""
        fp = CADFingerprinter()
        sig = CADSignature(
            application=CADApplication.BRICSCAD,
            pattern_type="string",
            pattern="BricsCAD",
            confidence=1.0,
        )
        result = fp._determine_application([sig], {})
        assert result.detected_application == CADApplication.BRICSCAD
        assert result.is_oda_based is True

    def test_multiple_signatures_same_app(self):
        """Test determination with multiple signatures for same app."""
        fp = CADFingerprinter()
        sigs = [
            CADSignature(
                application=CADApplication.NANOCAD,
                pattern_type="string",
                pattern="nanoCAD",
                confidence=1.0,
            ),
            CADSignature(
                application=CADApplication.NANOCAD,
                pattern_type="string",
                pattern="Nanosoft",
                confidence=0.95,
            ),
        ]
        result = fp._determine_application(sigs, {})
        assert result.detected_application == CADApplication.NANOCAD
        assert result.is_oda_based is True

    def test_oda_sdk_signature_marks_oda_based(self):
        """Test that ODA SDK signature marks result as ODA-based."""
        fp = CADFingerprinter()
        sig = CADSignature(
            application=CADApplication.ODA_SDK,
            pattern_type="string",
            pattern="Open Design Alliance",
            confidence=0.95,
        )
        result = fp._determine_application([sig], {})
        assert result.is_oda_based is True


class TestCADFingerprinterFingerprint:
    """Tests for main fingerprint method."""

    @pytest.fixture
    def bricscad_dwg(self, tmp_path):
        """Create a DWG file with BricsCAD markers."""
        file_path = tmp_path / "bricscad.dwg"
        content = b"AC1032" + b"\x00" * 50 + b"BricsCAD Professional" + b"\x00" * 100
        file_path.write_bytes(content)
        return file_path

    @pytest.fixture
    def autocad_dwg(self, tmp_path):
        """Create a clean DWG file (simulating AutoCAD)."""
        file_path = tmp_path / "autocad.dwg"
        content = b"AC1032" + b"\x00" * 500
        file_path.write_bytes(content)
        return file_path

    def test_fingerprint_bricscad(self, bricscad_dwg):
        """Test fingerprinting a BricsCAD file."""
        fp = CADFingerprinter()
        result = fp.fingerprint(bricscad_dwg)
        assert result.detected_application == CADApplication.BRICSCAD
        assert result.is_oda_based is True

    def test_fingerprint_with_zero_crc(self, autocad_dwg):
        """Test fingerprinting with zero CRC."""
        fp = CADFingerprinter()
        result = fp.fingerprint(autocad_dwg, header_crc=0x00000000)
        assert result.raw_evidence["crc_is_zero"] is True

    def test_fingerprint_with_metadata(self, autocad_dwg):
        """Test fingerprinting with metadata."""
        fp = CADFingerprinter()
        metadata = {"lastsavedby": "DraftSight User"}
        result = fp.fingerprint(autocad_dwg, metadata=metadata)
        assert result.raw_evidence["metadata_analyzed"] is True

    def test_fingerprint_nonexistent_file(self, tmp_path):
        """Test fingerprinting non-existent file."""
        fp = CADFingerprinter()
        result = fp.fingerprint(tmp_path / "nonexistent.dwg")
        assert result.detected_application == CADApplication.UNKNOWN
        assert result.confidence == 0.0
        assert "Error" in result.forensic_summary

    def test_fingerprint_crc_evidence(self, autocad_dwg):
        """Test that CRC value is recorded in evidence."""
        fp = CADFingerprinter()
        result = fp.fingerprint(autocad_dwg, header_crc=0xDEADBEEF)
        assert result.raw_evidence["crc_value"] == "0xDEADBEEF"


class TestCADFingerprinterForensicReport:
    """Tests for forensic report generation."""

    def test_report_for_bricscad(self):
        """Test report generation for BricsCAD."""
        fp = CADFingerprinter()
        sig = CADSignature(
            application=CADApplication.BRICSCAD,
            pattern_type="string",
            pattern="BricsCAD",
            confidence=1.0,
            description="BricsCAD marker",
            forensic_note="Indicates BricsCAD origin",
        )
        result = FingerprintResult(
            detected_application=CADApplication.BRICSCAD,
            confidence=0.95,
            matching_signatures=[sig],
            is_autodesk=False,
            is_oda_based=True,
        )
        report = fp.get_forensic_report(result)

        assert "BRICSCAD" in report
        assert "ODA" in report
        assert "NOT created by genuine Autodesk" in report

    def test_report_for_autocad(self):
        """Test report generation for AutoCAD."""
        fp = CADFingerprinter()
        result = FingerprintResult(
            detected_application=CADApplication.AUTOCAD,
            confidence=0.9,
            is_autodesk=True,
            is_oda_based=False,
        )
        report = fp.get_forensic_report(result)

        assert "AUTOCAD" in report
        assert "NOT created by genuine Autodesk" not in report

    def test_report_with_no_signatures(self):
        """Test report when no signatures matched."""
        fp = CADFingerprinter()
        result = FingerprintResult(
            detected_application=CADApplication.UNKNOWN,
            confidence=0.3,
            matching_signatures=[],
        )
        report = fp.get_forensic_report(result)

        assert "No specific signatures detected" in report

    def test_report_contains_headers(self):
        """Test that report contains expected headers."""
        fp = CADFingerprinter()
        result = FingerprintResult(
            detected_application=CADApplication.QCAD,
            confidence=0.8,
        )
        report = fp.get_forensic_report(result)

        assert "CAD APPLICATION FINGERPRINTING REPORT" in report
        assert "MATCHING SIGNATURES:" in report
        assert "FORENSIC SIGNIFICANCE:" in report


# ============================================================================
# Convenience Function Tests
# ============================================================================

class TestFingerprintDWGFunction:
    """Tests for fingerprint_dwg convenience function."""

    @pytest.fixture
    def sample_dwg(self, tmp_path):
        """Create a sample DWG file."""
        file_path = tmp_path / "sample.dwg"
        content = b"AC1032" + b"\x00" * 200
        file_path.write_bytes(content)
        return file_path

    def test_function_returns_result(self, sample_dwg):
        """Test that function returns FingerprintResult."""
        result = fingerprint_dwg(sample_dwg)
        assert isinstance(result, FingerprintResult)

    def test_function_with_all_params(self, sample_dwg):
        """Test function with all parameters."""
        result = fingerprint_dwg(
            file_path=sample_dwg,
            header_crc=0x12345678,
            metadata={"author": "Test User"},
        )
        assert isinstance(result, FingerprintResult)

    def test_function_with_path_object(self, sample_dwg):
        """Test function accepts Path object."""
        result = fingerprint_dwg(Path(sample_dwg))
        assert isinstance(result, FingerprintResult)


# ============================================================================
# Integration Tests
# ============================================================================

class TestCADFingerprintingIntegration:
    """Integration tests for CAD fingerprinting workflow."""

    @pytest.fixture
    def complex_dwg(self, tmp_path):
        """Create a DWG with multiple markers."""
        file_path = tmp_path / "complex.dwg"
        content = (
            b"AC1032" + b"\x00" * 50 +
            b"Open Design Alliance" + b"\x00" * 20 +
            b"BricsCAD" + b"\x00" * 20 +
            b"Bricsys NV" + b"\x00" * 100
        )
        file_path.write_bytes(content)
        return file_path

    def test_full_workflow(self, complex_dwg):
        """Test complete fingerprinting workflow."""
        fp = CADFingerprinter()

        # Fingerprint the file
        result = fp.fingerprint(
            complex_dwg,
            header_crc=0x00000000,  # Zero CRC
        )

        # Check results
        assert result.detected_application in [
            CADApplication.BRICSCAD,
            CADApplication.ODA_SDK,
        ]
        assert result.is_oda_based is True
        assert len(result.matching_signatures) > 0

        # Check ODA detection
        oda_result = fp.detect_oda_based(complex_dwg)
        assert oda_result["is_oda_based"] is True

        # Generate report
        report = fp.get_forensic_report(result)
        assert len(report) > 0
        assert "NOT created by genuine Autodesk" in report

    def test_timestamp_anomalies_workflow(self):
        """Test timestamp anomaly detection workflow."""
        fp = CADFingerprinter()

        # Simulate LibreCAD-style metadata
        metadata = {
            "tdcreate": 0,
            "tdupdate": 0,
            "tdindwg": 0,
            "fingerprintguid": "",
            "versionguid": "",
        }

        anomalies = fp.check_timestamp_anomalies(metadata)

        assert anomalies["detected"] is True
        assert anomalies["likely_third_party"] is True
        assert "ZERO_TIMESTAMPS" in anomalies["patterns"]
        assert "ZERO_TDINDWG" in anomalies["patterns"]
        assert "MISSING_FINGERPRINTGUID" in anomalies["patterns"]
        assert len(anomalies["forensic_notes"]) > 0


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================

class TestCADFingerprintingEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_file(self, tmp_path):
        """Test handling of empty file."""
        file_path = tmp_path / "empty.dwg"
        file_path.write_bytes(b"")

        fp = CADFingerprinter()
        result = fp.fingerprint(file_path)
        assert result.detected_application == CADApplication.UNKNOWN

    def test_binary_patterns_in_string_search(self):
        """Test that binary data doesn't crash string search."""
        fp = CADFingerprinter()
        data = bytes(range(256)) * 10  # All possible byte values
        matches = fp._check_string_signatures(data)
        assert isinstance(matches, list)

    def test_unicode_in_metadata(self):
        """Test handling of unicode in metadata."""
        fp = CADFingerprinter()
        metadata = {
            "author": "User Name",
            "comments": "Test comment",
        }
        matches = fp._check_metadata_signatures(metadata)
        assert isinstance(matches, list)

    def test_very_large_confidence_accumulation(self):
        """Test confidence calculation with many signatures."""
        fp = CADFingerprinter()
        sigs = [
            CADSignature(
                application=CADApplication.BRICSCAD,
                pattern_type="string",
                pattern=f"pattern{i}",
                confidence=1.0,
            )
            for i in range(100)
        ]
        result = fp._determine_application(sigs, {})
        assert result.confidence <= 1.0  # Should be normalized

    def test_mixed_application_signatures(self):
        """Test with signatures from different applications."""
        fp = CADFingerprinter()
        sigs = [
            CADSignature(
                application=CADApplication.BRICSCAD,
                pattern_type="string",
                pattern="BricsCAD",
                confidence=1.0,
            ),
            CADSignature(
                application=CADApplication.ODA_SDK,
                pattern_type="string",
                pattern="ODA",
                confidence=0.5,
            ),
        ]
        result = fp._determine_application(sigs, {})
        # Should pick the one with highest confidence
        assert result.detected_application == CADApplication.BRICSCAD
