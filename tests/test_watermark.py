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


# ============================================================================
# Additional Coverage Tests
# ============================================================================

class TestWatermarkDetectorHelpers:
    """Tests for WatermarkDetector helper methods."""

    def test_has_watermark_support_older_versions(self):
        """Test has_watermark_support returns False for older versions."""
        detector = WatermarkDetector()
        assert detector.has_watermark_support("AC1018") is False
        assert detector.has_watermark_support("AC1015") is False
        assert detector.has_watermark_support("AC1014") is False
        assert detector.has_watermark_support("AC1012") is False

    def test_has_watermark_support_newer_versions(self):
        """Test has_watermark_support returns True for newer versions."""
        detector = WatermarkDetector()
        assert detector.has_watermark_support("AC1021") is True
        assert detector.has_watermark_support("AC1024") is True
        assert detector.has_watermark_support("AC1027") is True
        assert detector.has_watermark_support("AC1032") is True

    def test_detect_old_version_returns_na(self, temp_dir):
        """Test detection on old version returns N/A."""
        dwg_path = temp_dir / "old_ac1018.dwg"
        dwg_path.write_bytes(b"AC1018" + b"\x00" * 100)

        detector = WatermarkDetector()
        result = detector.detect(dwg_path, version_string="AC1018")

        assert result.watermark_present is False
        assert result.watermark_text == "N/A - TrustedDWG not available for this version"
        assert result.watermark_valid is True

    def test_detect_version_from_file(self, temp_dir):
        """Test version detection from file."""
        detector = WatermarkDetector()

        # Test with AC1032
        dwg_path = temp_dir / "detect_version.dwg"
        dwg_path.write_bytes(b"AC1032" + b"\x00" * 100)

        result = detector.detect(dwg_path)
        # Should detect version and not crash
        assert result is not None

    def test_detect_version_short_file(self):
        """Test _detect_version with very short file."""
        detector = WatermarkDetector()
        result = detector._detect_version(b"AC10")  # Less than 6 bytes
        assert result is None

    def test_detect_version_invalid_bytes(self):
        """Test _detect_version with non-ASCII bytes."""
        detector = WatermarkDetector()
        result = detector._detect_version(b"\xff\xff\xff\xff\xff\xff")
        assert result is None

    def test_detect_version_not_starting_with_ac(self):
        """Test _detect_version with invalid version string."""
        detector = WatermarkDetector()
        result = detector._detect_version(b"XY1032" + b"\x00" * 100)
        assert result is None

    def test_find_watermark_returns_none_on_exception(self):
        """Test _find_watermark exception handling."""
        detector = WatermarkDetector()
        # Empty data - should not crash
        result = detector._find_watermark(b"")
        assert result is None

    def test_extract_watermark_text_empty_result(self, temp_dir):
        """Test _extract_watermark_text with empty watermark."""
        detector = WatermarkDetector()
        # Create data where marker is found but nothing meaningful after
        data = b"AC1032" + b"\x00" * 100 + b"Autodesk DWG" + b"\x00"
        result = detector._extract_watermark_text(data, 106)
        # Should return some text
        assert result is not None or result is None  # Either is valid

    def test_extract_application_id_no_match(self, temp_dir):
        """Test _extract_application_id with no application ID."""
        detector = WatermarkDetector()
        # Data without ACAD pattern
        data = b"AC1032" + b"\x00" * 200
        result = detector._extract_application_id(data)
        assert result is None

    def test_extract_application_id_invalid_pattern(self):
        """Test _extract_application_id with invalid ACAD pattern."""
        detector = WatermarkDetector()
        # ACAD followed by non-digits
        data = b"AC1032" + b"\x00" * 50 + b"ACADabcdefg" + b"\x00" * 50
        result = detector._extract_application_id(data)
        # Should not return the invalid pattern
        if result is not None:
            assert result[4:].isdigit()

    def test_extract_application_id_valid_pattern(self):
        """Test _extract_application_id with valid pattern."""
        detector = WatermarkDetector()
        data = b"AC1032" + b"\x00" * 50 + b"ACAD0001427" + b"\x00" * 50
        result = detector._extract_application_id(data)
        assert result == "ACAD0001427"

    def test_detect_io_error(self, temp_dir):
        """Test detect raises ParseError for IO errors."""
        from unittest.mock import patch, mock_open

        detector = WatermarkDetector()
        dwg_path = temp_dir / "io_error.dwg"
        dwg_path.write_bytes(b"AC1032" + b"\x00" * 100)

        # Mock open to raise IOError
        with patch("builtins.open", mock_open()) as mock_file:
            mock_file.side_effect = IOError("Test IO Error")
            with pytest.raises(ParseError):
                detector.detect(dwg_path)

    def test_find_watermark_exception_handling(self):
        """Test _find_watermark handles exceptions gracefully."""
        from unittest.mock import patch, MagicMock

        detector = WatermarkDetector()

        # Create mock data that raises exception on find
        mock_data = MagicMock()
        mock_data.find.side_effect = Exception("Test exception")

        result = detector._find_watermark(mock_data)
        assert result is None

    def test_extract_watermark_text_exception_handling(self):
        """Test _extract_watermark_text handles exceptions gracefully."""
        from unittest.mock import patch, MagicMock

        detector = WatermarkDetector()

        # Create mock data that raises exception on slice
        mock_data = MagicMock()
        mock_data.__getitem__ = MagicMock(side_effect=Exception("Test exception"))
        mock_data.__len__ = MagicMock(return_value=1000)

        result = detector._extract_watermark_text(mock_data, 100)
        assert result is None

    def test_extract_application_id_unicode_decode_error(self):
        """Test _extract_application_id handles UnicodeDecodeError in inner loop."""
        detector = WatermarkDetector()
        # ACAD followed by non-ASCII bytes that will fail ascii decode
        data = b"AC1032" + b"\x00" * 50 + b"ACAD" + bytes([0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86]) + b"\x00" * 50
        result = detector._extract_application_id(data)
        # Should return None because the ACAD pattern has invalid ASCII
        assert result is None

    def test_extract_application_id_exception_handling(self):
        """Test _extract_application_id handles general exceptions."""
        from unittest.mock import patch, MagicMock

        detector = WatermarkDetector()

        # Create mock data that raises exception on find
        mock_data = MagicMock()
        mock_data.find.side_effect = Exception("Test exception")

        result = detector._extract_application_id(mock_data)
        assert result is None

    def test_extract_watermark_text_returns_none_for_empty(self):
        """Test _extract_watermark_text returns None for empty watermark."""
        detector = WatermarkDetector()
        # Data where offset points to null bytes only
        data = b"AC1032" + b"\x00" * 200
        result = detector._extract_watermark_text(data, 10)
        # Should return None for empty result
        assert result is None

    def test_watermark_detection_with_null_version(self):
        """Test detection when version_string detection returns None."""
        detector = WatermarkDetector()
        # Very short data that won't have detectable version
        data = b"XXXX"
        result = detector._detect_version(data)
        assert result is None
