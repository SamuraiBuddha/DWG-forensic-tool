"""Tests for DWG header parser."""

import pytest

from dwg_forensic.models import HeaderAnalysis
from dwg_forensic.parsers.header import HeaderParser
from dwg_forensic.utils.exceptions import InvalidDWGError, UnsupportedVersionError


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
