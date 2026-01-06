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

    def test_unsupported_version(self, unsupported_dwg_ac1015):
        """Test that unsupported versions raise UnsupportedVersionError."""
        parser = HeaderParser()

        with pytest.raises(UnsupportedVersionError) as exc_info:
            parser.parse(unsupported_dwg_ac1015)

        assert exc_info.value.version == "AC1015"
        assert "AC1024" in exc_info.value.min_supported

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
        assert "AC1024" in parser.SUPPORTED_VERSIONS
        assert "AC1027" in parser.SUPPORTED_VERSIONS
        assert "AC1032" in parser.SUPPORTED_VERSIONS
        assert "AC1015" not in parser.SUPPORTED_VERSIONS

    def test_dwg_versions_mapping(self):
        """Test DWG_VERSIONS mapping is correct."""
        parser = HeaderParser()
        assert "AC1032" in parser.DWG_VERSIONS
        assert "2018" in parser.DWG_VERSIONS["AC1032"]
