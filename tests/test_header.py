"""Tests for DWG header parser."""

import pytest

from dwg_forensic.models import HeaderAnalysis
from dwg_forensic.parsers.header import HeaderParser
from dwg_forensic.utils.exceptions import InvalidDWGError, UnsupportedVersionError, ParseError


class TestHeaderParser:
    """Tests for HeaderParser class."""

    def test_parse_ac1032(self, valid_dwg_ac1032):
        """Test parsing AC1032 (AutoCAD 2018+) file."""
        parser = HeaderParser()
        result = parser.parse(valid_dwg_ac1032)

        assert isinstance(result, HeaderAnalysis)
        assert result.version_string == "AC1032"
        assert "2018" in result.version_name
        assert result.is_supported is True
        assert result.maintenance_version == 3

    def test_parse_ac1027(self, valid_dwg_ac1027):
        """Test parsing AC1027 (AutoCAD 2013-2017) file."""
        parser = HeaderParser()
        result = parser.parse(valid_dwg_ac1027)

        assert result.version_string == "AC1027"
        assert "2013" in result.version_name
        assert result.is_supported is True

    def test_parse_ac1024(self, valid_dwg_ac1024):
        """Test parsing AC1024 (AutoCAD 2010-2012) file."""
        parser = HeaderParser()
        result = parser.parse(valid_dwg_ac1024)

        assert result.version_string == "AC1024"
        assert "2010" in result.version_name
        assert result.is_supported is True

    def test_legacy_version_ac1015(self, unsupported_dwg_ac1015):
        """Test parsing AC1015 (AutoCAD 2000) file with limited support."""
        parser = HeaderParser()
        result = parser.parse(unsupported_dwg_ac1015)

        assert result.version_string == "AC1015"
        assert "2000" in result.version_name
        # AC1015 is supported but with limited analysis
        assert result.is_supported is False  # Not full support

    def test_truly_unsupported_version(self, temp_dir):
        """Test that truly unsupported versions (R10/R11) raise UnsupportedVersionError."""
        parser = HeaderParser()

        # Create an AC1009 (R11-R12) file which is truly unsupported
        dwg_path = temp_dir / "old_r11.dwg"
        header = bytearray(32)
        header[0:6] = b"AC1009"  # R11-R12 version
        dwg_path.write_bytes(bytes(header))

        with pytest.raises(UnsupportedVersionError) as exc_info:
            parser.parse(dwg_path)

        assert exc_info.value.version == "AC1009"

    def test_invalid_file(self, invalid_file):
        """Test that invalid files raise InvalidDWGError."""
        parser = HeaderParser()

        with pytest.raises(InvalidDWGError):
            parser.parse(invalid_file)

    def test_too_small_file(self, too_small_file):
        """Test that files too small raise InvalidDWGError."""
        parser = HeaderParser()

        with pytest.raises(InvalidDWGError) as exc_info:
            parser.parse(too_small_file)

        assert "too small" in str(exc_info.value).lower()

    def test_nonexistent_file(self, temp_dir):
        """Test that nonexistent files raise FileNotFoundError."""
        parser = HeaderParser()
        fake_path = temp_dir / "nonexistent.dwg"

        with pytest.raises(FileNotFoundError):
            parser.parse(fake_path)

    def test_supported_versions_constant(self):
        """Test SUPPORTED_VERSIONS contains expected versions."""
        parser = HeaderParser()
        # Full support versions
        assert "AC1024" in parser.FULL_SUPPORT_VERSIONS
        assert "AC1027" in parser.FULL_SUPPORT_VERSIONS
        assert "AC1032" in parser.FULL_SUPPORT_VERSIONS
        # Limited support versions (now supported)
        assert "AC1015" in parser.SUPPORTED_VERSIONS
        assert "AC1018" in parser.SUPPORTED_VERSIONS
        assert "AC1021" in parser.SUPPORTED_VERSIONS
        assert "AC1012" in parser.SUPPORTED_VERSIONS
        assert "AC1014" in parser.SUPPORTED_VERSIONS
        # Unsupported versions
        assert "AC1009" not in parser.SUPPORTED_VERSIONS
        assert "AC1006" not in parser.SUPPORTED_VERSIONS

    def test_dwg_versions_mapping(self):
        """Test DWG_VERSIONS mapping is correct."""
        parser = HeaderParser()
        assert "AC1032" in parser.DWG_VERSIONS
        assert "2018" in parser.DWG_VERSIONS["AC1032"]

    def test_parse_directory_raises_error(self, temp_dir):
        """Test parsing a directory raises InvalidDWGError."""
        parser = HeaderParser()

        with pytest.raises(InvalidDWGError) as exc_info:
            parser.parse(temp_dir)

        assert "not a file" in str(exc_info.value).lower()

    def test_parse_ac1021(self, temp_dir):
        """Test parsing AC1021 (AutoCAD 2007) file."""
        parser = HeaderParser()

        # Create AC1021 file with proper header size
        dwg_path = temp_dir / "r21.dwg"
        header = bytearray(128)
        header[0:6] = b"AC1021"
        # Set maintenance version at R21 offset
        header[0x07] = 2
        dwg_path.write_bytes(bytes(header))

        result = parser.parse(dwg_path)

        assert result.version_string == "AC1021"
        assert "2007" in result.version_name
        assert result.is_supported is False  # Limited support

    def test_parse_ac1018(self, temp_dir):
        """Test parsing AC1018 (AutoCAD 2004) file."""
        parser = HeaderParser()

        # Create AC1018 file with proper header size (96 bytes for R18)
        dwg_path = temp_dir / "r18.dwg"
        header = bytearray(96)
        header[0:6] = b"AC1018"
        dwg_path.write_bytes(bytes(header))

        result = parser.parse(dwg_path)

        assert result.version_string == "AC1018"
        assert "2004" in result.version_name

    def test_parse_ac1014(self, temp_dir):
        """Test parsing AC1014 (AutoCAD R14) file."""
        parser = HeaderParser()

        # Create AC1014 file
        dwg_path = temp_dir / "r14.dwg"
        header = bytearray(48)
        header[0:6] = b"AC1014"
        dwg_path.write_bytes(bytes(header))

        result = parser.parse(dwg_path)

        assert result.version_string == "AC1014"
        assert "R14" in result.version_name or "14" in result.version_name

    def test_parse_ac1012(self, temp_dir):
        """Test parsing AC1012 (AutoCAD R13) file."""
        parser = HeaderParser()

        # Create AC1012 file
        dwg_path = temp_dir / "r13.dwg"
        header = bytearray(48)
        header[0:6] = b"AC1012"
        dwg_path.write_bytes(bytes(header))

        result = parser.parse(dwg_path)

        assert result.version_string == "AC1012"
        assert "R13" in result.version_name or "13" in result.version_name

    def test_get_min_header_size_full_support(self):
        """Test _get_min_header_size for full support versions."""
        parser = HeaderParser()

        assert parser._get_min_header_size("AC1032") == parser.MIN_HEADER_SIZE_R24
        assert parser._get_min_header_size("AC1027") == parser.MIN_HEADER_SIZE_R24
        assert parser._get_min_header_size("AC1024") == parser.MIN_HEADER_SIZE_R24

    def test_get_min_header_size_legacy(self):
        """Test _get_min_header_size for legacy versions."""
        parser = HeaderParser()

        assert parser._get_min_header_size("AC1021") == parser.MIN_HEADER_SIZE_R21
        assert parser._get_min_header_size("AC1018") == parser.MIN_HEADER_SIZE_R18
        assert parser._get_min_header_size("AC1015") == parser.MIN_HEADER_SIZE_R15
        assert parser._get_min_header_size("AC1012") == parser.MIN_HEADER_SIZE_R13
        assert parser._get_min_header_size("AC1014") == parser.MIN_HEADER_SIZE_R13

    def test_get_min_header_size_unknown(self):
        """Test _get_min_header_size for unknown version."""
        parser = HeaderParser()

        # Unknown version should return minimum size
        assert parser._get_min_header_size("AC9999") == parser.MIN_HEADER_SIZE

    def test_read_version_string(self):
        """Test _read_version_string extracts version correctly."""
        parser = HeaderParser()

        data = b"AC1032" + b"\x00" * 100
        result = parser._read_version_string(data)

        assert result == "AC1032"

    def test_read_version_string_with_null(self):
        """Test _read_version_string handles null padding."""
        parser = HeaderParser()

        data = b"AC1015\x00\x00" + b"\x00" * 100
        result = parser._read_version_string(data)

        assert result == "AC1015"

    def test_validate_version_supported(self):
        """Test _validate_version accepts supported versions."""
        parser = HeaderParser()

        # Should not raise for supported versions
        parser._validate_version("AC1032", "/path/to/file.dwg")
        parser._validate_version("AC1015", "/path/to/file.dwg")

    def test_validate_version_unsupported(self):
        """Test _validate_version rejects unsupported versions."""
        parser = HeaderParser()

        with pytest.raises(UnsupportedVersionError):
            parser._validate_version("AC1009", "/path/to/file.dwg")

    def test_validate_version_invalid(self):
        """Test _validate_version rejects invalid version strings."""
        parser = HeaderParser()

        # Invalid version strings are treated as unsupported versions
        with pytest.raises(UnsupportedVersionError):
            parser._validate_version("XXXXXX", "/path/to/file.dwg")

    def test_read_byte(self):
        """Test _read_byte extracts single byte."""
        parser = HeaderParser()

        data = b"\x00\x01\x02\x03\xFF"
        assert parser._read_byte(data, 0) == 0
        assert parser._read_byte(data, 1) == 1
        assert parser._read_byte(data, 4) == 255

    def test_read_uint16(self):
        """Test _read_uint16 extracts little-endian uint16."""
        parser = HeaderParser()

        data = b"\x01\x00\xFF\xFF"
        assert parser._read_uint16(data, 0) == 1
        assert parser._read_uint16(data, 2) == 65535

    def test_read_uint32(self):
        """Test _read_uint32 extracts little-endian uint32."""
        parser = HeaderParser()

        data = b"\x01\x00\x00\x00\xFF\xFF\xFF\xFF"
        assert parser._read_uint32(data, 0) == 1
        assert parser._read_uint32(data, 4) == 4294967295

    def test_parse_version_specific_unknown(self, temp_dir):
        """Test parsing with unknown version falls back gracefully."""
        parser = HeaderParser()

        # Create a file that looks like DWG but unknown version
        # Note: This requires the version to pass validation first
        # We'll test the internal method directly
        data = b"AC9999" + b"\x00" * 100

        # Call internal method directly
        result = parser._parse_version_specific(data, "AC1015")

        assert result.version_string == "AC1015"
        assert result.is_supported is False

    def test_file_too_small_for_version_header(self, temp_dir):
        """Test error when file is valid header but too small for version."""
        parser = HeaderParser()

        # Create AC1032 file but with smaller data than R24 requires
        dwg_path = temp_dir / "small_r24.dwg"
        # AC1032 needs MIN_HEADER_SIZE_R24 bytes, give it less
        header = bytearray(32)  # Only 32 bytes
        header[0:6] = b"AC1032"
        dwg_path.write_bytes(bytes(header))

        with pytest.raises(InvalidDWGError) as exc_info:
            parser.parse(dwg_path)

        assert "too small" in str(exc_info.value).lower()

    def test_read_byte_out_of_bounds(self):
        """Test _read_byte raises ParseError when offset is out of bounds."""
        parser = HeaderParser()

        data = b"\x01\x02\x03"
        with pytest.raises(ParseError) as exc_info:
            parser._read_byte(data, 10)

        assert "Cannot read byte" in str(exc_info.value)
        assert exc_info.value.offset == 10

    def test_read_uint16_out_of_bounds(self):
        """Test _read_uint16 raises ParseError when offset is out of bounds."""
        parser = HeaderParser()

        data = b"\x01\x02"
        with pytest.raises(ParseError) as exc_info:
            parser._read_uint16(data, 10)

        assert "Cannot read uint16" in str(exc_info.value)
        assert exc_info.value.offset == 10

        # Also test partial bounds (offset+2 > len)
        with pytest.raises(ParseError) as exc_info:
            parser._read_uint16(data, 1)

        assert "Cannot read uint16" in str(exc_info.value)
        assert exc_info.value.offset == 1

    def test_read_uint32_out_of_bounds(self):
        """Test _read_uint32 raises ParseError when offset is out of bounds."""
        parser = HeaderParser()

        data = b"\x01\x02\x03"
        with pytest.raises(ParseError) as exc_info:
            parser._read_uint32(data, 10)

        assert "Cannot read uint32" in str(exc_info.value)
        assert exc_info.value.offset == 10

        # Also test partial bounds (offset+4 > len)
        with pytest.raises(ParseError) as exc_info:
            parser._read_uint32(data, 1)

        assert "Cannot read uint32" in str(exc_info.value)
        assert exc_info.value.offset == 1

    def test_parse_version_specific_unknown_fallback(self):
        """Test _parse_version_specific uses fallback for truly unknown versions."""
        parser = HeaderParser()

        # Call with a version that's not in any known list
        data = b"AC9999" + b"\x00" * 100

        # This tests lines 232-234 (fallback branch)
        result = parser._parse_version_specific(data, "AC9999")

        assert result.version_string == "AC9999"
        # Unknown versions should return None, not 0, to indicate unavailable data
        assert result.maintenance_version is None
        assert result.preview_address is None
        assert result.codepage is None

    def test_read_version_string_invalid_prefix(self):
        """Test _read_version_string raises error for non-AC prefix."""
        parser = HeaderParser()

        # Create data with invalid version prefix
        data = b"XX1032" + b"\x00" * 100

        with pytest.raises(InvalidDWGError) as exc_info:
            parser._read_version_string(data)

        assert "Invalid DWG version string" in str(exc_info.value)

    def test_read_version_string_decode_error(self):
        """Test _read_version_string handles decode error."""
        parser = HeaderParser()

        # Create data with invalid ASCII bytes
        data = b"\xff\xfe\xfd\xfc\xfb\xfa" + b"\x00" * 100

        with pytest.raises(InvalidDWGError) as exc_info:
            parser._read_version_string(data)

        assert "Cannot decode" in str(exc_info.value)

    def test_get_crc_offset_full_support_versions(self):
        """Test get_crc_offset returns correct offset for full support versions."""
        parser = HeaderParser()

        # All full support versions should return R24 offset
        for version in ["AC1024", "AC1027", "AC1032"]:
            offset = parser.get_crc_offset(version)
            assert offset == parser.OFFSET_CRC32_R24

    def test_get_crc_offset_ac1021(self):
        """Test get_crc_offset returns correct offset for AC1021."""
        parser = HeaderParser()

        offset = parser.get_crc_offset("AC1021")
        assert offset == parser.OFFSET_CRC32_R21

    def test_get_crc_offset_ac1018(self):
        """Test get_crc_offset returns correct offset for AC1018."""
        parser = HeaderParser()

        offset = parser.get_crc_offset("AC1018")
        assert offset == parser.OFFSET_CRC32_R18

    def test_get_crc_offset_ac1015(self):
        """Test get_crc_offset returns correct offset for AC1015."""
        parser = HeaderParser()

        offset = parser.get_crc_offset("AC1015")
        assert offset == parser.OFFSET_CRC32_R15

    def test_get_crc_offset_r13_returns_none(self):
        """Test get_crc_offset returns None for R13/R14 versions."""
        parser = HeaderParser()

        assert parser.get_crc_offset("AC1012") is None
        assert parser.get_crc_offset("AC1014") is None
        assert parser.get_crc_offset("AC9999") is None

    def test_has_full_support(self):
        """Test has_full_support returns correct values."""
        parser = HeaderParser()

        # Full support versions
        assert parser.has_full_support("AC1024") is True
        assert parser.has_full_support("AC1027") is True
        assert parser.has_full_support("AC1032") is True

        # Limited support versions
        assert parser.has_full_support("AC1021") is False
        assert parser.has_full_support("AC1018") is False
        assert parser.has_full_support("AC1015") is False
        assert parser.has_full_support("AC1012") is False

    def test_has_crc_support(self):
        """Test has_crc_support returns correct values."""
        parser = HeaderParser()

        # Versions with CRC support
        assert parser.has_crc_support("AC1032") is True
        assert parser.has_crc_support("AC1027") is True
        assert parser.has_crc_support("AC1024") is True
        assert parser.has_crc_support("AC1021") is True
        assert parser.has_crc_support("AC1018") is True
        assert parser.has_crc_support("AC1015") is True

        # Versions without CRC support
        assert parser.has_crc_support("AC1012") is False
        assert parser.has_crc_support("AC1014") is False

    def test_has_watermark_support(self):
        """Test has_watermark_support returns correct values."""
        parser = HeaderParser()

        # Versions with TrustedDWG support (AC1021+)
        assert parser.has_watermark_support("AC1032") is True
        assert parser.has_watermark_support("AC1027") is True
        assert parser.has_watermark_support("AC1024") is True
        assert parser.has_watermark_support("AC1021") is True

        # Versions without TrustedDWG support
        assert parser.has_watermark_support("AC1018") is False
        assert parser.has_watermark_support("AC1015") is False
        assert parser.has_watermark_support("AC1012") is False
