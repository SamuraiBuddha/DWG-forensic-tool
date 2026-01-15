"""Pytest configuration and shared fixtures for DWG Forensic Tool tests."""

import os
import struct
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def valid_dwg_ac1032(temp_dir):
    """Create a minimal valid AC1032 (AutoCAD 2018+) DWG file."""
    file_path = temp_dir / "valid_ac1032.dwg"

    # Build a minimal DWG header
    header = bytearray(108)  # Minimum header size

    # Version string at 0x00 (6 bytes)
    header[0:6] = b"AC1032"

    # Zero bytes at 0x06 (5 bytes)
    header[6:11] = b"\x00\x00\x00\x00\x00"

    # Maintenance version at 0x0B (1 byte)
    header[11] = 0x03

    # Preview address at 0x0D (4 bytes, little-endian)
    struct.pack_into("<I", header, 0x0D, 0x1000)

    # Codepage at 0x13 (2 bytes, little-endian)
    struct.pack_into("<H", header, 0x13, 0x001E)  # ANSI_1252

    # Pad to ensure we have enough data
    header.extend(b"\x00" * 500)

    # Calculate CRC32 over first 104 bytes
    import zlib
    crc = zlib.crc32(bytes(header[:0x68])) & 0xFFFFFFFF
    struct.pack_into("<I", header, 0x68, crc)

    with open(file_path, "wb") as f:
        f.write(header)

    return file_path


@pytest.fixture
def valid_dwg_ac1027(temp_dir):
    """Create a minimal valid AC1027 (AutoCAD 2013-2017) DWG file."""
    file_path = temp_dir / "valid_ac1027.dwg"

    header = bytearray(108)
    header[0:6] = b"AC1027"
    header[6:11] = b"\x00\x00\x00\x00\x00"
    header[11] = 0x01
    struct.pack_into("<I", header, 0x0D, 0x0800)
    struct.pack_into("<H", header, 0x13, 0x001E)

    header.extend(b"\x00" * 500)

    import zlib
    crc = zlib.crc32(bytes(header[:0x68])) & 0xFFFFFFFF
    struct.pack_into("<I", header, 0x68, crc)

    with open(file_path, "wb") as f:
        f.write(header)

    return file_path


@pytest.fixture
def valid_dwg_ac1024(temp_dir):
    """Create a minimal valid AC1024 (AutoCAD 2010-2012) DWG file."""
    file_path = temp_dir / "valid_ac1024.dwg"

    header = bytearray(108)
    header[0:6] = b"AC1024"
    header[6:11] = b"\x00\x00\x00\x00\x00"
    header[11] = 0x00
    struct.pack_into("<I", header, 0x0D, 0x0400)
    struct.pack_into("<H", header, 0x13, 0x001E)

    header.extend(b"\x00" * 500)

    import zlib
    crc = zlib.crc32(bytes(header[:0x68])) & 0xFFFFFFFF
    struct.pack_into("<I", header, 0x68, crc)

    with open(file_path, "wb") as f:
        f.write(header)

    return file_path


@pytest.fixture
def unsupported_dwg_ac1015(temp_dir):
    """Create an unsupported AC1015 (AutoCAD 2000) DWG file."""
    file_path = temp_dir / "unsupported_ac1015.dwg"

    header = bytearray(108)
    header[0:6] = b"AC1015"
    header[6:11] = b"\x00\x00\x00\x00\x00"
    header.extend(b"\x00" * 500)

    with open(file_path, "wb") as f:
        f.write(header)

    return file_path


@pytest.fixture
def corrupted_crc_dwg(temp_dir):
    """Create a DWG file with invalid CRC."""
    file_path = temp_dir / "corrupted_crc.dwg"

    header = bytearray(108)
    header[0:6] = b"AC1032"
    header[6:11] = b"\x00\x00\x00\x00\x00"
    header[11] = 0x00
    struct.pack_into("<I", header, 0x0D, 0x1000)
    struct.pack_into("<H", header, 0x13, 0x001E)

    # Set an incorrect CRC
    struct.pack_into("<I", header, 0x68, 0xDEADBEEF)

    header.extend(b"\x00" * 500)

    with open(file_path, "wb") as f:
        f.write(header)

    return file_path


@pytest.fixture
def invalid_file(temp_dir):
    """Create an invalid (non-DWG) file."""
    file_path = temp_dir / "invalid.dwg"
    with open(file_path, "wb") as f:
        f.write(b"This is not a DWG file")
    return file_path


@pytest.fixture
def too_small_file(temp_dir):
    """Create a file that is too small to be a valid DWG."""
    file_path = temp_dir / "too_small.dwg"
    with open(file_path, "wb") as f:
        f.write(b"AC1032")  # Only 6 bytes
    return file_path
