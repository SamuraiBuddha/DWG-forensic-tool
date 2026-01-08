"""Tests for CRC validator."""

import pytest

from dwg_forensic.models import CRCValidation
from dwg_forensic.parsers.crc import CRCValidator
from dwg_forensic.utils.exceptions import InvalidDWGError


class TestCRCValidator:
    """Tests for CRCValidator class."""

    def test_valid_crc(self, valid_dwg_ac1032):
        """Test validation of file with correct CRC."""
        validator = CRCValidator()
        result = validator.validate_header_crc(valid_dwg_ac1032)

        assert isinstance(result, CRCValidation)
        assert result.is_valid is True
        assert result.header_crc_stored == result.header_crc_calculated

    def test_invalid_crc(self, corrupted_crc_dwg):
        """Test validation of file with incorrect CRC."""
        validator = CRCValidator()
        result = validator.validate_header_crc(corrupted_crc_dwg)

        assert result.is_valid is False
        assert result.header_crc_stored != result.header_crc_calculated

    def test_crc_hex_format(self, valid_dwg_ac1032):
        """Test that CRC values are formatted as hex strings."""
        validator = CRCValidator()
        result = validator.validate_header_crc(valid_dwg_ac1032)

        assert result.header_crc_stored.startswith("0x")
        assert result.header_crc_calculated.startswith("0x")
        assert len(result.header_crc_stored) == 10  # "0x" + 8 hex digits

    def test_too_small_file(self, too_small_file):
        """Test that files too small raise InvalidDWGError."""
        validator = CRCValidator()

        with pytest.raises(InvalidDWGError):
            validator.validate_header_crc(too_small_file)

    def test_nonexistent_file(self, temp_dir):
        """Test that nonexistent files raise InvalidDWGError."""
        validator = CRCValidator()
        fake_path = temp_dir / "nonexistent.dwg"

        with pytest.raises(InvalidDWGError):
            validator.validate_header_crc(fake_path)

    def test_version_crc_info(self):
        """Test VERSION_CRC_INFO contains expected versions."""
        validator = CRCValidator()
        # R24+ versions
        assert "AC1032" in validator.VERSION_CRC_INFO
        assert "AC1027" in validator.VERSION_CRC_INFO
        assert "AC1024" in validator.VERSION_CRC_INFO
        # R21
        assert "AC1021" in validator.VERSION_CRC_INFO
        # R18 and R15
        assert "AC1018" in validator.VERSION_CRC_INFO
        assert "AC1015" in validator.VERSION_CRC_INFO

    def test_no_crc_versions(self):
        """Test NO_CRC_VERSIONS contains expected versions."""
        validator = CRCValidator()
        assert "AC1012" in validator.NO_CRC_VERSIONS
        assert "AC1014" in validator.NO_CRC_VERSIONS

    def test_has_crc_support(self):
        """Test has_crc_support method."""
        validator = CRCValidator()
        # Versions with CRC support
        assert validator.has_crc_support("AC1032") is True
        assert validator.has_crc_support("AC1024") is True
        assert validator.has_crc_support("AC1015") is True
        # Versions without CRC support
        assert validator.has_crc_support("AC1012") is False
        assert validator.has_crc_support("AC1014") is False

    def test_crc_na_for_old_versions(self, temp_dir):
        """Test that older versions return N/A for CRC."""
        validator = CRCValidator()

        # Create an AC1014 file
        dwg_path = temp_dir / "old_r14.dwg"
        header = bytearray(32)
        header[0:6] = b"AC1014"
        dwg_path.write_bytes(bytes(header))

        result = validator.validate_header_crc(dwg_path, version_string="AC1014")
        assert result.header_crc_stored == "N/A"
        assert result.header_crc_calculated == "N/A"
        assert result.is_valid is True  # Not a failure, just not available


# ============================================================================
# Additional Coverage Tests
# ============================================================================

class TestCRCValidatorEdgeCases:
    """Test CRC validator edge cases and error handling."""

    def test_unknown_version_returns_na(self, temp_dir):
        """Test that unknown versions return N/A for CRC (no CRC support)."""
        validator = CRCValidator()

        # Create file with unknown version
        dwg_path = temp_dir / "unknown.dwg"
        header = bytearray(200)
        header[0:6] = b"AC9999"  # Unknown version
        dwg_path.write_bytes(bytes(header))

        # Unknown versions are not in VERSION_CRC_INFO, so has_crc_support returns False
        result = validator.validate_header_crc(dwg_path, version_string="AC9999")

        # Should return N/A since unknown versions are treated as not having CRC support
        assert result.header_crc_stored == "N/A"
        assert result.header_crc_calculated == "N/A"
        assert result.is_valid is True  # Not a failure, just not available

    def test_permission_error(self, temp_dir):
        """Test that PermissionError raises InvalidDWGError."""
        from unittest.mock import patch, mock_open

        validator = CRCValidator()
        dwg_path = temp_dir / "permission.dwg"
        dwg_path.write_bytes(b"AC1032" + b"\x00" * 200)

        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            with pytest.raises(InvalidDWGError):
                validator.validate_header_crc(dwg_path)

    def test_os_error(self, temp_dir):
        """Test that general OSError raises InvalidDWGError."""
        from unittest.mock import patch

        validator = CRCValidator()
        dwg_path = temp_dir / "os_error.dwg"
        dwg_path.write_bytes(b"AC1032" + b"\x00" * 200)

        with patch("builtins.open", side_effect=OSError("IO Error")):
            with pytest.raises(InvalidDWGError):
                validator.validate_header_crc(dwg_path)

    def test_detect_version_file_too_small(self, temp_dir):
        """Test _detect_version with file too small."""
        validator = CRCValidator()
        dwg_path = temp_dir / "tiny.dwg"
        dwg_path.write_bytes(b"AC10")  # Less than 6 bytes

        with pytest.raises(InvalidDWGError) as excinfo:
            validator.validate_header_crc(dwg_path)
        assert "too small" in str(excinfo.value).lower()

    def test_detect_version_unicode_error(self, temp_dir):
        """Test _detect_version with non-ASCII bytes."""
        validator = CRCValidator()
        dwg_path = temp_dir / "binary.dwg"
        # Non-ASCII bytes that will fail decode
        dwg_path.write_bytes(b"\xff\xff\xff\xff\xff\xff" + b"\x00" * 200)

        with pytest.raises(InvalidDWGError) as excinfo:
            validator.validate_header_crc(dwg_path)
        assert "decode" in str(excinfo.value).lower()

    def test_read_stored_crc_insufficient_bytes(self, temp_dir):
        """Test _read_stored_crc when file is truncated."""
        validator = CRCValidator()

        # Create file that's just big enough for version but not CRC
        dwg_path = temp_dir / "truncated.dwg"
        header = bytearray(0x6A)  # Just past CRC offset but not enough data
        header[0:6] = b"AC1032"
        # Truncate the file right at CRC location
        dwg_path.write_bytes(bytes(header[:0x6A]))

        # File size check should catch this first
        with pytest.raises(InvalidDWGError):
            validator.validate_header_crc(dwg_path)

    def test_calculate_header_crc_insufficient_bytes(self, temp_dir):
        """Test CRC calculation with incomplete header."""
        from unittest.mock import patch, MagicMock
        import io

        validator = CRCValidator()
        dwg_path = temp_dir / "incomplete.dwg"
        # Create file with incomplete header data
        header = bytearray(200)
        header[0:6] = b"AC1032"
        dwg_path.write_bytes(bytes(header))

        # Mock the file to return incomplete data during CRC calculation
        with pytest.raises(InvalidDWGError):
            # Create a mock file that returns less bytes than expected
            mock_file = MagicMock()
            mock_file.read.side_effect = [b"AC1032", b"", bytes(header[:0x50])]
            mock_file.seek.return_value = None
            mock_file.tell.return_value = 200
            mock_file.__enter__ = MagicMock(return_value=mock_file)
            mock_file.__exit__ = MagicMock(return_value=False)

            with patch("builtins.open", return_value=mock_file):
                validator.validate_header_crc(dwg_path)

    def test_has_crc_support_unknown_version(self):
        """Test has_crc_support for unknown versions."""
        validator = CRCValidator()
        # Unknown version not in either list
        assert validator.has_crc_support("AC9999") is False

    def test_ac1009_no_crc_support(self):
        """Test AC1009 has no CRC support."""
        validator = CRCValidator()
        assert validator.has_crc_support("AC1009") is False

    def test_ac1006_no_crc_support(self):
        """Test AC1006 has no CRC support."""
        validator = CRCValidator()
        assert validator.has_crc_support("AC1006") is False
