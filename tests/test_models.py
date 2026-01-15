"""Tests for Pydantic data models."""

from datetime import datetime

import pytest
from pydantic import ValidationError

from dwg_forensic.models import (
    Anomaly,
    AnomalyType,
    CRCValidation,
    FileInfo,
    ForensicAnalysis,
    HeaderAnalysis,
    RiskAssessment,
    RiskLevel,
    TamperingIndicator,
    TamperingIndicatorType,
)


class TestFileInfo:
    """Tests for FileInfo model."""

    def test_valid_file_info(self):
        """Test creating a valid FileInfo."""
        info = FileInfo(
            filename="test.dwg",
            sha256="a" * 64,
            file_size_bytes=1024,
            intake_timestamp=datetime.now(),
        )
        assert info.filename == "test.dwg"
        assert info.sha256 == "a" * 64
        assert info.file_size_bytes == 1024

    def test_sha256_normalization(self):
        """Test that SHA-256 is normalized to lowercase."""
        info = FileInfo(
            filename="test.dwg",
            sha256="A" * 64,
            file_size_bytes=1024,
            intake_timestamp=datetime.now(),
        )
        assert info.sha256 == "a" * 64

    def test_invalid_sha256_length(self):
        """Test that invalid SHA-256 length raises error."""
        with pytest.raises(ValidationError):
            FileInfo(
                filename="test.dwg",
                sha256="abc",  # Too short
                file_size_bytes=1024,
                intake_timestamp=datetime.now(),
            )

    def test_invalid_sha256_characters(self):
        """Test that invalid SHA-256 characters raise error."""
        with pytest.raises(ValidationError):
            FileInfo(
                filename="test.dwg",
                sha256="g" * 64,  # 'g' is not hex
                file_size_bytes=1024,
                intake_timestamp=datetime.now(),
            )


class TestHeaderAnalysis:
    """Tests for HeaderAnalysis model."""

    def test_valid_header_analysis(self):
        """Test creating a valid HeaderAnalysis."""
        header = HeaderAnalysis(
            version_string="AC1032",
            version_name="AutoCAD 2018+",
            maintenance_version=3,
            preview_address=0x1000,
            codepage=30,
            is_supported=True,
        )
        assert header.version_string == "AC1032"
        assert header.is_supported is True


class TestCRCValidation:
    """Tests for CRCValidation model."""

    def test_valid_crc(self):
        """Test creating a valid CRCValidation."""
        crc = CRCValidation(
            header_crc_stored="0x12345678",
            header_crc_calculated="0x12345678",
            is_valid=True,
        )
        assert crc.is_valid is True

    def test_invalid_crc(self):
        """Test creating a CRCValidation with mismatch."""
        crc = CRCValidation(
            header_crc_stored="0x12345678",
            header_crc_calculated="0xDEADBEEF",
            is_valid=False,
        )
        assert crc.is_valid is False


class TestAnomaly:
    """Tests for Anomaly model."""

    def test_create_anomaly(self):
        """Test creating an Anomaly."""
        anomaly = Anomaly(
            anomaly_type=AnomalyType.CRC_MISMATCH,
            description="CRC mismatch detected",
            severity=RiskLevel.HIGH,
            details={"stored": "0x12345678", "calculated": "0xDEADBEEF"},
        )
        assert anomaly.anomaly_type == AnomalyType.CRC_MISMATCH
        assert anomaly.severity == RiskLevel.HIGH


class TestTamperingIndicator:
    """Tests for TamperingIndicator model."""

    def test_create_tampering_indicator(self):
        """Test creating a TamperingIndicator."""
        indicator = TamperingIndicator(
            indicator_type=TamperingIndicatorType.CRC_MODIFIED,
            description="File may have been modified",
            confidence=0.9,
            evidence="CRC mismatch",
        )
        assert indicator.confidence == 0.9

    def test_confidence_bounds(self):
        """Test confidence must be between 0 and 1."""
        with pytest.raises(ValidationError):
            TamperingIndicator(
                indicator_type=TamperingIndicatorType.CRC_MODIFIED,
                description="Test",
                confidence=1.5,  # Invalid
                evidence="Test",
            )


class TestRiskAssessment:
    """Tests for RiskAssessment model."""

    def test_create_risk_assessment(self):
        """Test creating a RiskAssessment."""
        assessment = RiskAssessment(
            overall_risk=RiskLevel.LOW,
            factors=["CRC valid", "Watermark valid"],
            recommendation="File appears authentic",
        )
        assert assessment.overall_risk == RiskLevel.LOW
        assert len(assessment.factors) == 2
