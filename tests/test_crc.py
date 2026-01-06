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

    def test_header_crc_offset_constant(self):
        """Test HEADER_CRC_OFFSET constant."""
        validator = CRCValidator()
        assert validator.HEADER_CRC_OFFSET == 0x68

    def test_header_length_constant(self):
        """Test HEADER_LENGTH constant."""
        validator = CRCValidator()
        assert validator.HEADER_LENGTH == 0x68
