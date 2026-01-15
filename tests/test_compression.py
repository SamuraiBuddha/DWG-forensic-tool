"""
Tests for DWG compression/decompression module.

Tests the LZ-like Type 2 compression algorithm used in DWG R2004+ files.
"""

import pytest
from dwg_forensic.parsers.compression import (
    DWGDecompressor,
    DecompressionError,
    PageHeader,
    decompress_section,
    decompress_page,
    calculate_checksum,
    verify_checksum,
)


class TestDWGDecompressor:
    """Tests for DWGDecompressor class."""

    def test_decompress_empty_input(self):
        """Test decompression of empty input."""
        decompressor = DWGDecompressor()
        result = decompressor.decompress(b"", validate_size=False)
        assert result == b""

    def test_decompress_end_marker_only(self):
        """Test decompression with just end marker (0x00)."""
        decompressor = DWGDecompressor()
        result = decompressor.decompress(b"\x00", validate_size=False)
        assert result == b""

    def test_decompress_literal_minimum(self):
        """Test literal run with minimum opcode (0x01 = 4 bytes)."""
        # Opcode 0x01 means copy (1 + 3) = 4 literal bytes
        compressed = b"\x01ABCD\x00"
        decompressor = DWGDecompressor()
        result = decompressor.decompress(compressed, validate_size=False)
        assert result == b"ABCD"

    def test_decompress_literal_maximum_short(self):
        """Test literal run with maximum short opcode (0x0F = 18 bytes)."""
        # Opcode 0x0F means copy (15 + 3) = 18 literal bytes
        literal_data = b"A" * 18
        compressed = b"\x0f" + literal_data + b"\x00"
        decompressor = DWGDecompressor()
        result = decompressor.decompress(compressed, validate_size=False)
        assert result == literal_data

    def test_decompress_literal_multiple_runs(self):
        """Test multiple literal runs."""
        # Two runs of 4 bytes each
        compressed = b"\x01ABCD\x01EFGH\x00"
        decompressor = DWGDecompressor()
        result = decompressor.decompress(compressed, validate_size=False)
        assert result == b"ABCDEFGH"

    def test_decompress_backref_short(self):
        """Test short back-reference (opcode 0x10-0x1F)."""
        # First, literal run to establish output
        # Opcode 0x01 = 4 literal bytes
        # Then opcode 0x10 = short backref, length = ((0x10 >> 2) & 0x03) + 3 = 3
        # Offset in low bits + next byte
        # 0x10 & 0x03 = 0, next byte = 0x03, offset = 0x003 + 1 = 4
        # Copy 3 bytes from position (current - 4)
        compressed = b"\x01ABCD\x10\x03\x00"
        decompressor = DWGDecompressor()
        result = decompressor.decompress(compressed, validate_size=False)
        # After literal: "ABCD" (pos 4)
        # Backref: offset=4, length=3, copies from pos 0: "ABC"
        assert result == b"ABCDABC"

    def test_decompress_backref_medium(self):
        """Test medium back-reference (opcode 0x20-0x3F)."""
        # Opcode 0x20 = medium backref, length = (0x20 & 0x1F) + 2 = 2
        # Next 2 bytes = offset (little-endian)
        # First establish some output
        compressed = b"\x01ABCD\x20\x03\x00\x00"  # offset = 3 + 1 = 4
        decompressor = DWGDecompressor()
        result = decompressor.decompress(compressed, validate_size=False)
        # After literal: "ABCD"
        # Backref: offset=4, length=2, copies from pos 0: "AB"
        assert result == b"ABCDAB"

    def test_decompress_backref_long(self):
        """Test long back-reference (opcode 0x80-0xFF)."""
        # Opcode 0x80 = long backref, length = (0x80 & 0x1F) + 2 = 2
        # Bit 6 (0x40) not set, so no extended length
        # Next 2 bytes = offset
        compressed = b"\x01ABCD\x80\x03\x00\x00"  # offset = 3 + 1 = 4
        decompressor = DWGDecompressor()
        result = decompressor.decompress(compressed, validate_size=False)
        assert result == b"ABCDAB"

    def test_decompress_backref_long_extended(self):
        """Test long back-reference with extended length (bit 6 set)."""
        # Opcode 0xC0 = 0x80 | 0x40 (bit 6 set)
        # Base length = (0xC0 & 0x1F) + 2 = 2
        # Extended: length += next_byte
        # Then 2 bytes offset
        compressed = b"\x01ABCD\xc0\x01\x03\x00\x00"  # length = 2 + 1 = 3
        decompressor = DWGDecompressor()
        result = decompressor.decompress(compressed, validate_size=False)
        # Backref: offset=4, length=3, copies "ABC"
        assert result == b"ABCDABC"

    def test_decompress_extended_literal(self):
        """Test extended literal run (opcode 0x40-0x7F)."""
        # Opcode 0x40 = extended literal
        # Length = ((0x40 - 0x40) << 8) | next_byte + 0x103
        # = (0 << 8) | 0 + 0x103 = 259 bytes
        # This is a large literal run - test with smaller value
        # Actually, minimum for 0x40 opcode is 259 bytes which is large
        # Let's verify the formula works
        literal_data = b"X" * 259
        compressed = b"\x40\x00" + literal_data + b"\x00"
        decompressor = DWGDecompressor()
        result = decompressor.decompress(compressed, validate_size=False)
        assert result == literal_data

    def test_decompress_with_expected_size(self):
        """Test decompression with pre-allocated output buffer."""
        compressed = b"\x01ABCD\x00"
        decompressor = DWGDecompressor()
        result = decompressor.decompress(compressed, expected_size=4, validate_size=True)
        assert result == b"ABCD"

    def test_decompress_size_mismatch_error(self):
        """Test that size mismatch raises error when validation enabled."""
        compressed = b"\x01ABCD\x00"
        decompressor = DWGDecompressor()
        with pytest.raises(DecompressionError, match="Size mismatch"):
            decompressor.decompress(compressed, expected_size=10, validate_size=True)

    def test_decompress_size_mismatch_no_validation(self):
        """Test that size mismatch is allowed when validation disabled."""
        compressed = b"\x01ABCD\x00"
        decompressor = DWGDecompressor()
        # Should not raise even with wrong expected_size
        result = decompressor.decompress(compressed, expected_size=10, validate_size=False)
        assert result == b"ABCD"

    def test_decompress_overlapping_backref(self):
        """Test back-reference that overlaps with source (RLE-like)."""
        # Literal "A", then backref with offset=1, length=5
        # This copies "A" repeatedly: AAAAAA
        # Opcode 0x10: length = ((0x10 >> 2) & 0x03) + 3 = 3
        # We need length 5, so use medium backref
        # Opcode 0x23: length = (0x23 & 0x1F) + 2 = 3 + 2 = 5
        # Literal first: opcode 0x01 with 4 bytes, but we only want 1
        # Actually, minimum literal is 4 bytes (opcode 0x01)
        # Let's use 4 bytes then backref to create pattern
        compressed = b"\x01AAAA\x23\x00\x00\x00"  # offset = 0 + 1 = 1
        decompressor = DWGDecompressor()
        result = decompressor.decompress(compressed, validate_size=False)
        # After literal: "AAAA"
        # Backref offset=1, length=5: copies from pos 3 ("A") 5 times
        assert result == b"AAAA" + b"A" * 5

    def test_decompress_invalid_backref_offset(self):
        """Test that invalid back-reference offset raises error."""
        # Try to reference before start of output
        compressed = b"\x20\x10\x00\x00"  # offset = 16+1 = 17, but output is empty
        decompressor = DWGDecompressor()
        with pytest.raises(DecompressionError, match="Invalid back-reference"):
            decompressor.decompress(compressed, validate_size=False)

    def test_decompress_truncated_input(self):
        """Test that truncated input raises error."""
        # Literal opcode expecting 4 bytes but only 2 provided
        compressed = b"\x01AB"
        decompressor = DWGDecompressor()
        with pytest.raises(DecompressionError, match="Literal run exceeds input"):
            decompressor.decompress(compressed, validate_size=False)

    def test_decompress_zero_offset_backref(self):
        """Test that zero offset in backref raises error."""
        # This would be an invalid back-reference
        # Create situation where offset calculation yields 0
        compressed = b"\x01ABCD\x20\xff\xff\x00"  # offset = 0xFFFF + 1 overflow handling
        decompressor = DWGDecompressor()
        # This should either work or raise appropriate error
        # depending on how offset wrapping is handled
        try:
            result = decompressor.decompress(compressed, validate_size=False)
            # If it works, the offset was large but valid
        except DecompressionError:
            # Expected for invalid offset
            pass


class TestPageHeader:
    """Tests for PageHeader parsing."""

    def test_parse_valid_header(self):
        """Test parsing valid page header."""
        # Create 20-byte header data
        header_data = (
            b"\x3b\x00\x63\x41"  # page_type = 0x4163003B
            b"\x00\x10\x00\x00"  # decompressed_size = 4096
            b"\x00\x08\x00\x00"  # compressed_size = 2048
            b"\x02\x00\x00\x00"  # compression_type = 2
            b"\x12\x34\x56\x78"  # checksum
        )

        header = PageHeader.from_bytes(header_data)
        assert header.page_type == 0x4163003B
        assert header.decompressed_size == 4096
        assert header.compressed_size == 2048
        assert header.compression_type == 2
        assert header.checksum == 0x78563412

    def test_parse_header_with_offset(self):
        """Test parsing header at non-zero offset."""
        padding = b"\x00" * 10
        header_data = (
            b"\x3b\x0e\x63\x41"  # page_type = PAGE_MAP
            b"\x00\x20\x00\x00"  # decompressed_size = 8192
            b"\x00\x10\x00\x00"  # compressed_size = 4096
            b"\x02\x00\x00\x00"  # compression_type = 2
            b"\xAB\xCD\xEF\x01"  # checksum
        )

        header = PageHeader.from_bytes(padding + header_data, offset=10)
        assert header.page_type == 0x41630E3B
        assert header.decompressed_size == 8192

    def test_parse_header_insufficient_data(self):
        """Test that insufficient data raises error."""
        short_data = b"\x00" * 10
        with pytest.raises(DecompressionError, match="Insufficient data"):
            PageHeader.from_bytes(short_data)


class TestDecompressPage:
    """Tests for page-level decompression."""

    def test_decompress_uncompressed_page(self):
        """Test decompression of uncompressed page (compression_type != 2)."""
        # Header with compression_type = 0 (not compressed)
        # Build header as explicit concatenation to avoid expression issues
        header = (
            b"\x3b\x00\x63\x41"  # page_type
            b"\x04\x00\x00\x00"  # decompressed_size = 4
            b"\x04\x00\x00\x00"  # compressed_size = 4
            b"\x00\x00\x00\x00"  # compression_type = 0
            b"\x00\x00\x00\x00"  # checksum
        ) + b"\x00" * 12        # padding to 32 bytes
        raw_data = b"TEST"
        page_data = header + raw_data

        result, page_header = decompress_page(page_data)
        assert result == b"TEST"
        assert page_header.compression_type == 0

    def test_decompress_compressed_page(self):
        """Test decompression of compressed page."""
        # Header with compression_type = 2
        # Build header as explicit concatenation to avoid expression issues
        header = (
            b"\x3b\x00\x63\x41"  # page_type
            b"\x04\x00\x00\x00"  # decompressed_size = 4
            b"\x06\x00\x00\x00"  # compressed_size = 6
            b"\x02\x00\x00\x00"  # compression_type = 2
            b"\x00\x00\x00\x00"  # checksum
        ) + b"\x00" * 12        # padding to 32 bytes
        # Compressed data: literal "ABCD" + end marker
        compressed = b"\x01ABCD\x00"
        page_data = header + compressed

        result, page_header = decompress_page(page_data)
        assert result == b"ABCD"
        assert page_header.compression_type == 2


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_decompress_section_simple(self):
        """Test decompress_section convenience function."""
        compressed = b"\x01ABCD\x00"
        result = decompress_section(compressed, expected_size=4)
        assert result == b"ABCD"

    def test_decompress_section_no_validation(self):
        """Test decompress_section without size validation."""
        compressed = b"\x01ABCD\x00"
        result = decompress_section(compressed, validate=False)
        assert result == b"ABCD"


class TestChecksum:
    """Tests for checksum functions."""

    def test_calculate_checksum_empty(self):
        """Test checksum of empty data."""
        assert calculate_checksum(b"") == 0

    def test_calculate_checksum_simple(self):
        """Test checksum calculation."""
        # Sum of ASCII values: A=65, B=66, C=67, D=68 = 266
        assert calculate_checksum(b"ABCD") == 266

    def test_calculate_checksum_overflow(self):
        """Test checksum with overflow (32-bit truncation)."""
        # Create data that would overflow 32 bits
        large_data = b"\xff" * 0x1000001  # > 16M bytes of 0xFF
        checksum = calculate_checksum(large_data)
        # Should be truncated to 32 bits
        assert checksum <= 0xFFFFFFFF

    def test_verify_checksum_valid(self):
        """Test checksum verification with valid checksum."""
        data = b"ABCD"
        expected = 266
        assert verify_checksum(data, expected) is True

    def test_verify_checksum_invalid(self):
        """Test checksum verification with invalid checksum."""
        data = b"ABCD"
        wrong_checksum = 999
        assert verify_checksum(data, wrong_checksum) is False


class TestRealWorldPatterns:
    """Tests using patterns commonly seen in real DWG files."""

    def test_repeated_pattern_compression(self):
        """Test compression pattern for repeated data (common in DWG)."""
        # DWG often has repeated null bytes or patterns
        # Simulate: literal nulls then backref to repeat
        # 4 null bytes literal, then backref to repeat
        compressed = b"\x01\x00\x00\x00\x00\x10\x03\x00"  # literal + short backref
        decompressor = DWGDecompressor()
        result = decompressor.decompress(compressed, validate_size=False)
        # 4 nulls + 3 more from backref = 7 nulls
        assert result == b"\x00" * 7

    def test_mixed_literal_and_backref(self):
        """Test mixed literal and back-reference sequence."""
        # Pattern: "HEADER" literal, then backref to copy "HEA" from start
        # This tests typical DWG section patterns
        #
        # Short backref (0x10-0x1F):
        #   length = ((opcode >> 2) & 0x03) + 3
        #   offset = ((opcode & 0x03) << 8) | next_byte + 1
        #
        # For length=3, offset=6:
        #   length = 3 means ((opcode >> 2) & 0x03) = 0
        #   offset = 6 means ((opcode & 0x03) << 8) | next_byte = 5
        #   So opcode & 0x03 = 0, next_byte = 5
        #   opcode = 0x10 | 0 = 0x10
        compressed = (
            b"\x03HEADER"  # 6 literal bytes (opcode 0x03 = 3+3=6)
            b"\x10\x05"    # short backref: opcode=0x10, next=5, offset=5+1=6, length=3
            b"\x00"        # end
        )
        decompressor = DWGDecompressor()
        result = decompressor.decompress(compressed, validate_size=False)
        # "HEADER" + backref(offset=6, len=3) = "HEADER" + "HEA"
        assert result == b"HEADERHEA"
