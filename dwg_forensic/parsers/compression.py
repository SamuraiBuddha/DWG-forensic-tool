"""
DWG Section Decompression Module.

Implements the LZ-like compression algorithm used in DWG R2004+ files.
This is a custom compression scheme (Type 2) that differs from standard zlib.

References:
- LibreDWG decode_r2004.c, bits.c
- OpenDesign Specification section on compression

The algorithm uses a series of opcodes to encode:
- Literal byte runs (copy bytes directly from input)
- Back-references (copy from previously decompressed output)
"""

import struct
from dataclasses import dataclass
from typing import Optional, Tuple


class DecompressionError(Exception):
    """Raised when decompression fails."""
    pass


@dataclass
class PageHeader:
    """DWG Section Page Header (32 bytes)."""
    page_type: int
    decompressed_size: int
    compressed_size: int
    compression_type: int
    checksum: int

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "PageHeader":
        """Parse page header from bytes."""
        if len(data) < offset + 20:
            raise DecompressionError("Insufficient data for page header")

        return cls(
            page_type=struct.unpack_from("<I", data, offset)[0],
            decompressed_size=struct.unpack_from("<I", data, offset + 4)[0],
            compressed_size=struct.unpack_from("<I", data, offset + 8)[0],
            compression_type=struct.unpack_from("<I", data, offset + 12)[0],
            checksum=struct.unpack_from("<I", data, offset + 16)[0],
        )


class DWGDecompressor:
    """
    Decompressor for DWG Type 2 compression.

    The compression algorithm uses opcodes to signal:
    - Literal runs: Copy N bytes directly from input
    - Back-references: Copy N bytes from position (current - offset) in output

    Opcode ranges:
    - 0x00: End of compressed data
    - 0x01-0x0F: Literal run of (opcode + 3) bytes
    - 0x10-0x1F: Short back-reference
    - 0x20-0x3F: Medium back-reference
    - 0x40-0x7F: Extended literal run
    - 0x80-0xFF: Long back-reference
    """

    # Page type markers
    PAGE_MAP = 0x41630E3B
    DATA_PAGE = 0x4163003B

    def __init__(self):
        """Initialize decompressor."""
        self._input: bytes = b""
        self._input_pos: int = 0
        self._output: bytearray = bytearray()

    def decompress(
        self,
        data: bytes,
        expected_size: Optional[int] = None,
        validate_size: bool = True
    ) -> bytes:
        """
        Decompress DWG compressed data.

        Args:
            data: Compressed input bytes
            expected_size: Expected decompressed size (for validation)
            validate_size: Whether to validate output size

        Returns:
            Decompressed bytes

        Raises:
            DecompressionError: If decompression fails
        """
        self._input = data
        self._input_pos = 0
        self._output = bytearray()

        if expected_size:
            self._output = bytearray(expected_size)
            output_pos = 0
        else:
            output_pos = 0

        try:
            while self._input_pos < len(self._input):
                opcode = self._read_byte()

                if opcode == 0x00:
                    # End of stream
                    break

                if opcode < 0x10:
                    # Literal run: copy (opcode + 3) bytes from input
                    length = opcode + 3
                    output_pos = self._copy_literal(output_pos, length, expected_size)

                elif opcode < 0x20:
                    # Short back-reference
                    # Length: ((opcode >> 2) & 0x03) + 3 = bits 2-3 + 3
                    # Offset: ((opcode & 0x03) << 8) | next_byte + 1
                    length = ((opcode >> 2) & 0x03) + 3
                    offset = ((opcode & 0x03) << 8) | self._read_byte()
                    output_pos = self._copy_backref(output_pos, offset + 1, length, expected_size)

                elif opcode < 0x40:
                    # Medium back-reference
                    # Length: (opcode & 0x1F) + 2
                    # Offset: next 2 bytes (little-endian) + 1
                    length = (opcode & 0x1F) + 2
                    offset = self._read_uint16()
                    output_pos = self._copy_backref(output_pos, offset + 1, length, expected_size)

                elif opcode < 0x80:
                    # Extended literal run
                    # Length: ((opcode - 0x40) << 8) | next_byte + 0x103
                    next_byte = self._read_byte()
                    length = ((opcode - 0x40) << 8) | next_byte
                    length += 0x103  # Add base offset
                    output_pos = self._copy_literal(output_pos, length, expected_size)

                else:
                    # Long back-reference (0x80-0xFF)
                    # Length base: (opcode & 0x1F) + 2
                    # If bit 6 set: length += next_byte
                    # Offset: next 2 bytes + 1
                    length = (opcode & 0x1F) + 2

                    if opcode & 0x40:
                        # Extended length
                        length += self._read_byte()

                    offset = self._read_uint16()
                    output_pos = self._copy_backref(output_pos, offset + 1, length, expected_size)

        except IndexError as e:
            raise DecompressionError(f"Unexpected end of input at position {self._input_pos}") from e

        # Get final output
        if expected_size:
            result = bytes(self._output[:output_pos])
        else:
            result = bytes(self._output)

        # Validate size if requested
        if validate_size and expected_size and len(result) != expected_size:
            raise DecompressionError(
                f"Size mismatch: expected {expected_size}, got {len(result)}"
            )

        return result

    def _read_byte(self) -> int:
        """Read single byte from input."""
        if self._input_pos >= len(self._input):
            raise IndexError("Input buffer exhausted")
        byte = self._input[self._input_pos]
        self._input_pos += 1
        return byte

    def _read_uint16(self) -> int:
        """Read little-endian uint16 from input."""
        if self._input_pos + 2 > len(self._input):
            raise IndexError("Input buffer exhausted")
        value = struct.unpack_from("<H", self._input, self._input_pos)[0]
        self._input_pos += 2
        return value

    def _copy_literal(
        self,
        output_pos: int,
        length: int,
        expected_size: Optional[int]
    ) -> int:
        """Copy literal bytes from input to output."""
        if self._input_pos + length > len(self._input):
            raise DecompressionError(
                f"Literal run exceeds input: need {length} bytes at pos {self._input_pos}"
            )

        literal_data = self._input[self._input_pos:self._input_pos + length]
        self._input_pos += length

        if expected_size:
            # Pre-allocated output
            end_pos = output_pos + length
            if end_pos > expected_size:
                raise DecompressionError(
                    f"Output overflow: {end_pos} exceeds expected {expected_size}"
                )
            self._output[output_pos:end_pos] = literal_data
        else:
            # Dynamic output
            self._output.extend(literal_data)

        return output_pos + length

    def _copy_backref(
        self,
        output_pos: int,
        offset: int,
        length: int,
        expected_size: Optional[int]
    ) -> int:
        """Copy bytes from earlier in output (back-reference)."""
        if offset > output_pos:
            raise DecompressionError(
                f"Invalid back-reference: offset {offset} exceeds output position {output_pos}"
            )

        if offset == 0:
            raise DecompressionError("Zero offset in back-reference")

        src_pos = output_pos - offset

        if expected_size:
            # Pre-allocated output
            end_pos = output_pos + length
            if end_pos > expected_size:
                raise DecompressionError(
                    f"Output overflow: {end_pos} exceeds expected {expected_size}"
                )

            # Copy byte-by-byte to handle overlapping regions
            for i in range(length):
                self._output[output_pos + i] = self._output[src_pos + i]
        else:
            # Dynamic output - copy byte-by-byte for overlapping support
            for i in range(length):
                self._output.append(self._output[src_pos + i])

        return output_pos + length


def decompress_section(
    data: bytes,
    expected_size: Optional[int] = None,
    validate: bool = True
) -> bytes:
    """
    Convenience function to decompress DWG section data.

    Args:
        data: Compressed section data
        expected_size: Expected decompressed size
        validate: Whether to validate output size

    Returns:
        Decompressed bytes
    """
    decompressor = DWGDecompressor()
    return decompressor.decompress(data, expected_size, validate)


def decompress_page(data: bytes, offset: int = 0) -> Tuple[bytes, PageHeader]:
    """
    Decompress a single section page including header.

    Args:
        data: Raw page data (including 32-byte header)
        offset: Offset to page start

    Returns:
        Tuple of (decompressed_data, page_header)

    Raises:
        DecompressionError: If decompression fails
    """
    header = PageHeader.from_bytes(data, offset)

    # Check if compression is used
    if header.compression_type != 2:
        # Not compressed, return raw data
        raw_start = offset + 32  # Skip header
        raw_data = data[raw_start:raw_start + header.decompressed_size]
        return raw_data, header

    # Get compressed data (after 32-byte header)
    compressed_start = offset + 32
    compressed_data = data[compressed_start:compressed_start + header.compressed_size]

    # Decompress
    decompressor = DWGDecompressor()
    decompressed = decompressor.decompress(
        compressed_data,
        header.decompressed_size,
        validate_size=True
    )

    return decompressed, header


def calculate_checksum(data: bytes) -> int:
    """
    Calculate DWG section checksum.

    Simple sum of all bytes, truncated to 32 bits.

    Args:
        data: Data to checksum

    Returns:
        32-bit checksum value
    """
    checksum = 0
    for byte in data:
        checksum = (checksum + byte) & 0xFFFFFFFF
    return checksum


def verify_checksum(data: bytes, expected: int) -> bool:
    """
    Verify data matches expected checksum.

    Args:
        data: Data to verify
        expected: Expected checksum value

    Returns:
        True if checksum matches
    """
    return calculate_checksum(data) == expected
