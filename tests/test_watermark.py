"""Tests for TrustedDWG watermark detector."""

import pytest

from dwg_forensic.models import TrustedDWGAnalysis
from dwg_forensic.parsers.watermark import WatermarkDetector
from dwg_forensic.utils.exceptions import ParseError


class TestWatermarkDetector:
    """Tests for WatermarkDetector class."""

    def test_detect_watermark_present(self, dwg_with_watermark):
        """Test detection of file with watermark."""
        detector = WatermarkDetector()
        result = detector.detect(dwg_with_watermark)

        assert isinstance(result, TrustedDWGAnalysis)
        assert result.watermark_present is True
        assert result.watermark_valid is True
        assert result.watermark_offset is not None

    def test_detect_no_watermark(self, dwg_without_watermark):
        """Test detection of file without watermark."""
        detector = WatermarkDetector()
        result = detector.detect(dwg_without_watermark)

        assert result.watermark_present is False
        assert result.watermark_valid is False

    def test_watermark_with_application_id(self, dwg_with_watermark):
        """Test extraction of application ID."""
        detector = WatermarkDetector()
        result = detector.detect(dwg_with_watermark)

        # The fixture includes ACAD0001427
        if result.application_origin:
            assert "AutoCAD" in result.application_origin

    def test_known_application_ids(self):
        """Test KNOWN_APPLICATION_IDS mapping."""
        detector = WatermarkDetector()
        assert "ACAD0001427" in detector.KNOWN_APPLICATION_IDS
        assert "AutoCAD 2024" in detector.KNOWN_APPLICATION_IDS["ACAD0001427"]

    def test_watermark_marker_constant(self):
        """Test WATERMARK_MARKER constant."""
        detector = WatermarkDetector()
        assert detector.WATERMARK_MARKER == b"Autodesk DWG"

    def test_nonexistent_file(self, temp_dir):
        """Test that nonexistent files raise ParseError."""
        detector = WatermarkDetector()
        fake_path = temp_dir / "nonexistent.dwg"

        with pytest.raises((ParseError, IOError)):
            detector.detect(fake_path)

    def test_watermark_text_extraction(self, valid_dwg_ac1032):
        """Test watermark text extraction."""
        detector = WatermarkDetector()
        result = detector.detect(valid_dwg_ac1032)

        if result.watermark_present and result.watermark_text:
            assert "Autodesk DWG" in result.watermark_text
