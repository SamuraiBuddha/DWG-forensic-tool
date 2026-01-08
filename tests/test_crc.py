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
