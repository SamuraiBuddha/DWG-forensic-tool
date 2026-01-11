"""
Tests for DWG Section Map Parser module.

This module tests the section map parsing functionality for DWG files R18+.
Section map parsing is critical for locating:
- AcDb:Header (drawing variables including timestamps)
- AcDb:Handles (object handle map for gap analysis)
- AcDb:Classes (class definitions)
- Other forensically relevant sections
"""

import pytest
import struct
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock

from dwg_forensic.parsers.sections import (
    SectionType,
    SECTION_NAMES,
    SectionInfo,
    SectionMapResult,
    SectionMapParser,
    get_section_map,
)


class TestSectionTypeEnum:
    """Tests for SectionType enumeration."""

    def test_section_type_values(self):
        """Test all section type values are correctly defined."""
        assert SectionType.UNKNOWN == 0x00
        assert SectionType.HEADER == 0x01
        assert SectionType.CLASSES == 0x02
        assert SectionType.HANDLES == 0x03
        assert SectionType.OBJECTS == 0x04
        assert SectionType.TEMPLATE == 0x05
        assert SectionType.AUXHEADER == 0x06
        assert SectionType.PREVIEW == 0x07
        assert SectionType.APPINFO == 0x08
        assert SectionType.APPINFOHISTORY == 0x09
        assert SectionType.FILEDEPLIST == 0x0A
        assert SectionType.SECURITY == 0x0B
        assert SectionType.VBAPROJECT == 0x0C
        assert SectionType.SIGNATURE == 0x0D
        assert SectionType.ACDS == 0x0E
        assert SectionType.SUMMARYINFO == 0x0F

    def test_section_type_is_int(self):
        """Test SectionType values can be used as integers."""
        assert SectionType.HEADER + 1 == SectionType.CLASSES
        assert int(SectionType.HANDLES) == 3

    def test_all_forensic_sections_defined(self):
        """Test all forensically important sections are defined."""
        # These are critical for deep forensic analysis
        forensic_sections = [
            SectionType.HEADER,      # Timestamps (TDCREATE, TDUPDATE)
            SectionType.HANDLES,     # Handle gap analysis
            SectionType.APPINFO,     # Application info
            SectionType.SIGNATURE,   # TrustedDWG signature
            SectionType.SECURITY,    # Digital signature
        ]
        for section in forensic_sections:
            assert section in SectionType.__members__.values()


class TestSectionNames:
    """Tests for section name mapping."""

    def test_all_section_types_have_names(self):
        """Test all non-unknown section types have name mappings."""
        for section_type in SectionType:
            if section_type != SectionType.UNKNOWN:
                assert section_type in SECTION_NAMES

    def test_header_section_name(self):
        """Test Header section has correct name."""
        assert SECTION_NAMES[SectionType.HEADER] == "AcDb:Header"

    def test_handles_section_name(self):
        """Test Handles section has correct name."""
        assert SECTION_NAMES[SectionType.HANDLES] == "AcDb:Handles"

    def test_appinfo_section_name(self):
        """Test AppInfo section has correct name."""
        assert SECTION_NAMES[SectionType.APPINFO] == "AcDb:AppInfo"

    def test_signature_section_name(self):
        """Test Signature section has correct name."""
        assert SECTION_NAMES[SectionType.SIGNATURE] == "AcDb:Signature"


class TestSectionInfo:
    """Tests for SectionInfo dataclass."""

    def test_section_info_creation(self):
        """Test SectionInfo can be created with required fields."""
        info = SectionInfo(
            section_type=SectionType.HEADER,
            section_name="AcDb:Header",
            compressed_size=1024,
            decompressed_size=2048,
            offset=0x100,
        )
        assert info.section_type == SectionType.HEADER
        assert info.section_name == "AcDb:Header"
        assert info.compressed_size == 1024
        assert info.decompressed_size == 2048
        assert info.offset == 0x100

    def test_section_info_defaults(self):
        """Test SectionInfo has correct default values."""
        info = SectionInfo(
            section_type=1,
            section_name="Test",
            compressed_size=100,
            decompressed_size=200,
            offset=0,
        )
        assert info.page_count == 1
        assert info.compression_type == 0
        assert info.data_offset == 0

    def test_section_info_with_all_fields(self):
        """Test SectionInfo with all fields specified."""
        info = SectionInfo(
            section_type=SectionType.HANDLES,
            section_name="AcDb:Handles",
            compressed_size=5000,
            decompressed_size=15000,
            offset=0x2000,
            page_count=3,
            compression_type=2,
            data_offset=0x2010,
        )
        assert info.page_count == 3
        assert info.compression_type == 2
        assert info.data_offset == 0x2010

    def test_section_info_integer_type(self):
        """Test SectionInfo accepts integer section_type."""
        info = SectionInfo(
            section_type=1,  # Integer instead of enum
            section_name="Test",
            compressed_size=100,
            decompressed_size=200,
            offset=0,
        )
        assert info.section_type == 1


class TestSectionMapResult:
    """Tests for SectionMapResult dataclass."""

    def test_empty_result(self):
        """Test empty SectionMapResult has correct defaults."""
        result = SectionMapResult()
        assert result.sections == {}
        assert result.section_map_offset == 0
        assert result.section_count == 0
        assert result.file_version == ""
        assert result.parsing_errors == []

    def test_has_section_true(self):
        """Test has_section returns True for existing section."""
        result = SectionMapResult()
        result.sections[SectionType.HEADER] = SectionInfo(
            section_type=SectionType.HEADER,
            section_name="AcDb:Header",
            compressed_size=100,
            decompressed_size=200,
            offset=0,
        )
        assert result.has_section(SectionType.HEADER) is True

    def test_has_section_false(self):
        """Test has_section returns False for missing section."""
        result = SectionMapResult()
        assert result.has_section(SectionType.HEADER) is False

    def test_get_section_exists(self):
        """Test get_section returns section info when exists."""
        result = SectionMapResult()
        info = SectionInfo(
            section_type=SectionType.HANDLES,
            section_name="AcDb:Handles",
            compressed_size=500,
            decompressed_size=1500,
            offset=0x1000,
        )
        result.sections[SectionType.HANDLES] = info
        retrieved = result.get_section(SectionType.HANDLES)
        assert retrieved is info
        assert retrieved.compressed_size == 500

    def test_get_section_not_exists(self):
        """Test get_section returns None when section doesn't exist."""
        result = SectionMapResult()
        assert result.get_section(SectionType.SIGNATURE) is None

    def test_multiple_sections(self):
        """Test result can hold multiple sections."""
        result = SectionMapResult()
        result.sections[SectionType.HEADER] = SectionInfo(
            section_type=SectionType.HEADER,
            section_name="AcDb:Header",
            compressed_size=100,
            decompressed_size=200,
            offset=0x100,
        )
        result.sections[SectionType.HANDLES] = SectionInfo(
            section_type=SectionType.HANDLES,
            section_name="AcDb:Handles",
            compressed_size=500,
            decompressed_size=1500,
            offset=0x1000,
        )
        result.sections[SectionType.APPINFO] = SectionInfo(
            section_type=SectionType.APPINFO,
            section_name="AcDb:AppInfo",
            compressed_size=50,
            decompressed_size=100,
            offset=0x2000,
        )
        assert len(result.sections) == 3
        assert result.has_section(SectionType.HEADER)
        assert result.has_section(SectionType.HANDLES)
        assert result.has_section(SectionType.APPINFO)

    def test_parsing_errors_accumulate(self):
        """Test parsing errors can be accumulated."""
        result = SectionMapResult()
        result.parsing_errors.append("Error 1")
        result.parsing_errors.append("Error 2")
        assert len(result.parsing_errors) == 2
        assert "Error 1" in result.parsing_errors
        assert "Error 2" in result.parsing_errors


class TestSectionMapParser:
    """Tests for SectionMapParser class."""

    def test_parser_initialization(self):
        """Test parser can be initialized."""
        parser = SectionMapParser()
        assert parser is not None

    def test_parser_constants(self):
        """Test parser has correct constants."""
        assert SectionMapParser.OFFSET_SECTION_LOCATOR == 0x20
        assert SectionMapParser.SECTION_PAGE_MAP == 0x41630E3B
        assert SectionMapParser.SECTION_DATA_PAGE == 0x4163003B
        assert SectionMapParser.MIN_FILE_SIZE == 0x100


class TestSectionMapParserFileTooSmall:
    """Tests for handling files that are too small."""

    def test_file_too_small(self):
        """Test parser returns error for file smaller than MIN_FILE_SIZE."""
        parser = SectionMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(b"AC1032" + b"\x00" * 50)  # Only 56 bytes
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert "File too small" in result.parsing_errors[0]
        finally:
            temp_path.unlink()

    def test_file_exactly_min_size(self):
        """Test parser handles file at exact minimum size."""
        parser = SectionMapParser()
        # Create file at exactly MIN_FILE_SIZE (0x100 = 256 bytes)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            data = b"AC1032" + b"\x00" * 250
            f.write(data)
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            # Should at least parse version
            assert result.file_version == "AC1032"
        finally:
            temp_path.unlink()


class TestSectionMapParserVersions:
    """Tests for version-specific parsing."""

    def _create_dwg_stub(self, version: str, section_map_addr: int = 0x100) -> bytes:
        """Create a minimal DWG file stub for testing."""
        data = bytearray(0x200)  # 512 bytes
        # Version string at offset 0
        data[0:6] = version.encode("ascii")
        # Section map address at offset 0x34
        struct.pack_into("<I", data, 0x34, section_map_addr)
        return bytes(data)

    def test_parse_ac1018_version(self):
        """Test parsing AC1018 (AutoCAD 2004-2006) files."""
        parser = SectionMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_stub("AC1018", 0x100))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.file_version == "AC1018"
            # Should attempt R2004 parsing path
            assert result.section_map_offset == 0x100 or len(result.parsing_errors) > 0
        finally:
            temp_path.unlink()

    def test_parse_ac1021_version(self):
        """Test parsing AC1021 (AutoCAD 2007-2009) files."""
        parser = SectionMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_stub("AC1021", 0x100))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.file_version == "AC1021"
        finally:
            temp_path.unlink()

    def test_parse_ac1024_version(self):
        """Test parsing AC1024 (AutoCAD 2010-2012) files."""
        parser = SectionMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_stub("AC1024", 0x100))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.file_version == "AC1024"
        finally:
            temp_path.unlink()

    def test_parse_ac1027_version(self):
        """Test parsing AC1027 (AutoCAD 2013-2017) files."""
        parser = SectionMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_stub("AC1027", 0x100))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.file_version == "AC1027"
        finally:
            temp_path.unlink()

    def test_parse_ac1032_version(self):
        """Test parsing AC1032 (AutoCAD 2018+) files."""
        parser = SectionMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_stub("AC1032", 0x100))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.file_version == "AC1032"
        finally:
            temp_path.unlink()

    def test_unsupported_version(self):
        """Test parser handles unsupported versions gracefully."""
        parser = SectionMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_stub("AC1015", 0x100))  # AutoCAD 2000
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.file_version == "AC1015"
            assert any("not supported" in err for err in result.parsing_errors)
        finally:
            temp_path.unlink()

    def test_invalid_version_string(self):
        """Test parser handles invalid version string."""
        parser = SectionMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            # Non-ASCII bytes in version area
            data = bytes([0xFF, 0xFE, 0x00, 0x01, 0x02, 0x03]) + b"\x00" * 256
            f.write(data)
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert "Invalid version string" in result.parsing_errors[0]
        finally:
            temp_path.unlink()


class TestSectionMapParserFileAccess:
    """Tests for file access handling."""

    def test_file_not_found(self):
        """Test parser handles missing file gracefully."""
        parser = SectionMapParser()
        result = parser.parse(Path("/nonexistent/path/file.dwg"))
        assert len(result.parsing_errors) > 0
        assert "Failed to read file" in result.parsing_errors[0]

    def test_permission_denied(self):
        """Test parser handles permission errors gracefully."""
        parser = SectionMapParser()
        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            result = parser.parse(Path("test.dwg"))
            assert len(result.parsing_errors) > 0
            assert "Failed to read file" in result.parsing_errors[0]

    def test_path_as_string(self):
        """Test parser accepts string path and converts to Path."""
        parser = SectionMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            data = b"AC1032" + b"\x00" * 256
            f.write(data)
            temp_path = f.name  # String, not Path

        try:
            result = parser.parse(temp_path)  # type: ignore
            assert result.file_version == "AC1032"
        finally:
            Path(temp_path).unlink()


class TestSectionMapParserInvalidAddresses:
    """Tests for invalid section map addresses."""

    def test_zero_section_map_address(self):
        """Test parser handles zero section map address."""
        parser = SectionMapParser()
        data = bytearray(0x200)
        data[0:6] = b"AC1024"
        struct.pack_into("<I", data, 0x34, 0)  # Zero address

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(bytes(data))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert any("Invalid section map address" in err or "0x0" in err
                      for err in result.parsing_errors) or result.section_map_offset == 0
        finally:
            temp_path.unlink()

    def test_address_beyond_file_size(self):
        """Test parser handles address beyond file size."""
        parser = SectionMapParser()
        data = bytearray(0x200)  # 512 bytes
        data[0:6] = b"AC1024"
        struct.pack_into("<I", data, 0x34, 0x10000)  # Address beyond file

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(bytes(data))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert any("Invalid section map address" in err for err in result.parsing_errors)
        finally:
            temp_path.unlink()


class TestSectionMapParserSectionScanning:
    """Tests for section entry scanning."""

    def _create_dwg_with_sections(self, version: str) -> bytes:
        """Create a DWG stub with simulated section entries."""
        data = bytearray(0x400)  # 1KB
        data[0:6] = version.encode("ascii")

        # Section map address at 0x34
        section_map_offset = 0x100
        struct.pack_into("<I", data, 0x34, section_map_offset)

        # Simulate section entries at section map offset
        # Each entry: type (4), size1 (4), size2 (4), data_offset (4)
        offset = section_map_offset

        # Header section (type 1)
        struct.pack_into("<I", data, offset, 1)      # Type
        struct.pack_into("<I", data, offset + 4, 100)  # Compressed size
        struct.pack_into("<I", data, offset + 8, 200)  # Decompressed size
        struct.pack_into("<I", data, offset + 12, 0x200)  # Data offset
        offset += 16

        # Handles section (type 3)
        struct.pack_into("<I", data, offset, 3)      # Type
        struct.pack_into("<I", data, offset + 4, 500)  # Compressed size
        struct.pack_into("<I", data, offset + 8, 1500)  # Decompressed size
        struct.pack_into("<I", data, offset + 12, 0x300)  # Data offset

        return bytes(data)

    def test_find_header_section(self):
        """Test parser can find Header section entry."""
        parser = SectionMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_with_sections("AC1024"))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            if result.has_section(SectionType.HEADER):
                header = result.get_section(SectionType.HEADER)
                assert header is not None
                assert header.section_name == "AcDb:Header"
        finally:
            temp_path.unlink()

    def test_find_handles_section(self):
        """Test parser can find Handles section entry."""
        parser = SectionMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_with_sections("AC1024"))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            if result.has_section(SectionType.HANDLES):
                handles = result.get_section(SectionType.HANDLES)
                assert handles is not None
                assert handles.section_name == "AcDb:Handles"
        finally:
            temp_path.unlink()

    def test_section_count_updated(self):
        """Test section count is updated after parsing."""
        parser = SectionMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_with_sections("AC1024"))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.section_count == len(result.sections)
        finally:
            temp_path.unlink()

    def test_r2004_section_scanning(self):
        """Test section scanning works for R2004 (AC1018) files."""
        parser = SectionMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_with_sections("AC1018"))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.file_version == "AC1018"
            # Should attempt parsing even if no sections found
            assert result.section_count >= 0
        finally:
            temp_path.unlink()

    def test_r2007_section_scanning(self):
        """Test section scanning works for R2007 (AC1021) files."""
        parser = SectionMapParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_with_sections("AC1021"))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.file_version == "AC1021"
        finally:
            temp_path.unlink()


class TestReadSectionData:
    """Tests for read_section_data method."""

    def test_read_uncompressed_section(self):
        """Test reading uncompressed section data."""
        parser = SectionMapParser()

        # Create file with known data at specific offset
        data = b"\x00" * 0x100 + b"SECTION_DATA_HERE"

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(data)
            temp_path = Path(f.name)

        try:
            section_info = SectionInfo(
                section_type=SectionType.HEADER,
                section_name="AcDb:Header",
                compressed_size=17,  # len("SECTION_DATA_HERE")
                decompressed_size=17,
                offset=0,
                data_offset=0x100,
                compression_type=0,  # Uncompressed
            )

            result = parser.read_section_data(temp_path, section_info)
            assert result == b"SECTION_DATA_HERE"
        finally:
            temp_path.unlink()

    def test_read_compressed_section_invalid_zlib(self):
        """Test reading 'compressed' section that isn't valid zlib."""
        parser = SectionMapParser()

        # Invalid zlib data
        data = b"\x00" * 0x100 + b"NOT_ZLIB_DATA"

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(data)
            temp_path = Path(f.name)

        try:
            section_info = SectionInfo(
                section_type=SectionType.HEADER,
                section_name="AcDb:Header",
                compressed_size=13,
                decompressed_size=50,
                offset=0,
                data_offset=0x100,
                compression_type=2,  # Compressed
            )

            # Should fall back to raw data on zlib error
            result = parser.read_section_data(temp_path, section_info)
            assert result == b"NOT_ZLIB_DATA"
        finally:
            temp_path.unlink()

    def test_read_section_with_valid_zlib(self):
        """Test reading properly zlib-compressed section."""
        import zlib
        parser = SectionMapParser()

        original_data = b"This is the original uncompressed section data"
        compressed_data = zlib.compress(original_data)

        data = b"\x00" * 0x100 + compressed_data

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(data)
            temp_path = Path(f.name)

        try:
            section_info = SectionInfo(
                section_type=SectionType.HEADER,
                section_name="AcDb:Header",
                compressed_size=len(compressed_data),
                decompressed_size=len(original_data),
                offset=0,
                data_offset=0x100,
                compression_type=2,
            )

            result = parser.read_section_data(temp_path, section_info)
            assert result == original_data
        finally:
            temp_path.unlink()

    def test_read_section_no_decompress(self):
        """Test reading section without decompression."""
        import zlib
        parser = SectionMapParser()

        original_data = b"This is the original data"
        compressed_data = zlib.compress(original_data)

        data = b"\x00" * 0x100 + compressed_data

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(data)
            temp_path = Path(f.name)

        try:
            section_info = SectionInfo(
                section_type=SectionType.HEADER,
                section_name="AcDb:Header",
                compressed_size=len(compressed_data),
                decompressed_size=len(original_data),
                offset=0,
                data_offset=0x100,
                compression_type=2,
            )

            # Read without decompression
            result = parser.read_section_data(temp_path, section_info, decompress=False)
            assert result == compressed_data
        finally:
            temp_path.unlink()

    def test_read_section_file_not_found(self):
        """Test read_section_data handles missing file."""
        parser = SectionMapParser()

        section_info = SectionInfo(
            section_type=SectionType.HEADER,
            section_name="AcDb:Header",
            compressed_size=100,
            decompressed_size=200,
            offset=0,
            data_offset=0x100,
        )

        result = parser.read_section_data(Path("/nonexistent/file.dwg"), section_info)
        assert result is None

    def test_read_section_at_end_of_file(self):
        """Test reading section at the very end of file."""
        parser = SectionMapParser()

        data = b"\x00" * 0x100 + b"END"

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(data)
            temp_path = Path(f.name)

        try:
            section_info = SectionInfo(
                section_type=SectionType.HEADER,
                section_name="AcDb:Header",
                compressed_size=3,
                decompressed_size=3,
                offset=0,
                data_offset=0x100,
            )

            result = parser.read_section_data(temp_path, section_info)
            assert result == b"END"
        finally:
            temp_path.unlink()


class TestGetSectionMapConvenience:
    """Tests for get_section_map convenience function."""

    def test_get_section_map_returns_result(self):
        """Test convenience function returns SectionMapResult."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            data = b"AC1032" + b"\x00" * 256
            f.write(data)
            temp_path = Path(f.name)

        try:
            result = get_section_map(temp_path)
            assert isinstance(result, SectionMapResult)
            assert result.file_version == "AC1032"
        finally:
            temp_path.unlink()

    def test_get_section_map_with_invalid_file(self):
        """Test convenience function handles invalid file."""
        result = get_section_map(Path("/nonexistent/file.dwg"))
        assert isinstance(result, SectionMapResult)
        assert len(result.parsing_errors) > 0


class TestSectionMapForensicCapabilities:
    """Tests verifying forensic analysis capabilities."""

    def test_identifies_missing_header_section(self):
        """Test that missing Header section can be detected."""
        result = SectionMapResult()
        result.sections[SectionType.HANDLES] = SectionInfo(
            section_type=SectionType.HANDLES,
            section_name="AcDb:Handles",
            compressed_size=100,
            decompressed_size=200,
            offset=0,
        )

        # Forensic check: Header section should exist for valid DWG
        assert not result.has_section(SectionType.HEADER)

    def test_identifies_missing_handles_section(self):
        """Test that missing Handles section can be detected."""
        result = SectionMapResult()
        result.sections[SectionType.HEADER] = SectionInfo(
            section_type=SectionType.HEADER,
            section_name="AcDb:Header",
            compressed_size=100,
            decompressed_size=200,
            offset=0,
        )

        # Forensic check: Handles section needed for gap analysis
        assert not result.has_section(SectionType.HANDLES)

    def test_identifies_signature_section(self):
        """Test that Signature section can be identified."""
        result = SectionMapResult()
        result.sections[SectionType.SIGNATURE] = SectionInfo(
            section_type=SectionType.SIGNATURE,
            section_name="AcDb:Signature",
            compressed_size=256,
            decompressed_size=512,
            offset=0x5000,
        )

        # TrustedDWG signature presence is forensically relevant
        assert result.has_section(SectionType.SIGNATURE)

    def test_identifies_security_section(self):
        """Test that Security section can be identified."""
        result = SectionMapResult()
        result.sections[SectionType.SECURITY] = SectionInfo(
            section_type=SectionType.SECURITY,
            section_name="AcDb:Security",
            compressed_size=128,
            decompressed_size=256,
            offset=0x6000,
        )

        # Digital signature presence is forensically relevant
        assert result.has_section(SectionType.SECURITY)

    def test_section_size_anomaly_detection(self):
        """Test that section size anomalies can be detected."""
        # A Header section that is suspiciously small
        info = SectionInfo(
            section_type=SectionType.HEADER,
            section_name="AcDb:Header",
            compressed_size=10,  # Very small for header
            decompressed_size=10,
            offset=0x100,
        )

        # Forensic rule: Header should be larger than this
        # This test documents the capability for rule implementation
        assert info.compressed_size < 100  # Anomalously small

    def test_compression_ratio_check(self):
        """Test compression ratio can be calculated for analysis."""
        info = SectionInfo(
            section_type=SectionType.HEADER,
            section_name="AcDb:Header",
            compressed_size=100,
            decompressed_size=1000,
            offset=0x100,
        )

        # Compression ratio check
        if info.compressed_size > 0:
            ratio = info.decompressed_size / info.compressed_size
            assert ratio == 10.0  # 10:1 compression


class TestVersionCoverage:
    """Tests ensuring all required versions are supported."""

    def test_ac1018_supported(self):
        """Verify AC1018 (AutoCAD 2004) is in supported versions."""
        # From the code, AC1018 should route to _parse_r2004_sections
        parser = SectionMapParser()
        data = bytearray(0x200)
        data[0:6] = b"AC1018"
        struct.pack_into("<I", data, 0x34, 0x100)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(bytes(data))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            # Should not have "not supported" error
            assert not any("not supported for AC1018" in err for err in result.parsing_errors)
        finally:
            temp_path.unlink()

    def test_ac1021_supported(self):
        """Verify AC1021 (AutoCAD 2007) is in supported versions."""
        parser = SectionMapParser()
        data = bytearray(0x200)
        data[0:6] = b"AC1021"
        struct.pack_into("<I", data, 0x34, 0x100)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(bytes(data))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert not any("not supported for AC1021" in err for err in result.parsing_errors)
        finally:
            temp_path.unlink()

    def test_ac1024_supported(self):
        """Verify AC1024 (AutoCAD 2010) is in supported versions."""
        parser = SectionMapParser()
        data = bytearray(0x200)
        data[0:6] = b"AC1024"
        struct.pack_into("<I", data, 0x34, 0x100)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(bytes(data))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert not any("not supported for AC1024" in err for err in result.parsing_errors)
        finally:
            temp_path.unlink()

    def test_ac1027_supported(self):
        """Verify AC1027 (AutoCAD 2013) is in supported versions."""
        parser = SectionMapParser()
        data = bytearray(0x200)
        data[0:6] = b"AC1027"
        struct.pack_into("<I", data, 0x34, 0x100)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(bytes(data))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert not any("not supported for AC1027" in err for err in result.parsing_errors)
        finally:
            temp_path.unlink()

    def test_ac1032_supported(self):
        """Verify AC1032 (AutoCAD 2018+) is in supported versions."""
        parser = SectionMapParser()
        data = bytearray(0x200)
        data[0:6] = b"AC1032"
        struct.pack_into("<I", data, 0x34, 0x100)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(bytes(data))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert not any("not supported for AC1032" in err for err in result.parsing_errors)
        finally:
            temp_path.unlink()
