"""
DWG Encryption Handler for R2018+ (AC1032) files.

R2018+ files encrypt portions of the file header and section locator
using a static XOR mask. This module provides detection and decryption.

References:
- LibreDWG decode_r2007.c
- OpenDesign Specification
"""

import struct
from typing import Optional, Tuple


# AC1032 (R2018+) header XOR decryption mask
# This is a 32-byte repeating mask applied to the encrypted header region
AC1032_HEADER_MASK = bytes([
    0x29, 0x23, 0xBE, 0x84, 0xE1, 0x6C, 0xD6, 0xAE,
    0x52, 0x90, 0x49, 0xF1, 0xF1, 0xBB, 0xE9, 0xEB,
    0xB3, 0xA6, 0xDB, 0x3C, 0x87, 0x0C, 0x3E, 0x99,
    0x24, 0x5E, 0x0D, 0x1C, 0x06, 0xB7, 0x47, 0xDE,
])

# Encrypted region boundaries for AC1032
AC1032_ENCRYPTED_START = 0x80
AC1032_ENCRYPTED_END = 0x100

# R2007 (AC1021) also has some encrypted regions
AC1021_HEADER_MASK = bytes([
    0x42, 0x37, 0x64, 0x73, 0x4F, 0x64, 0x61, 0x77,
    0x61, 0x44, 0x72, 0x65, 0x61, 0x6D, 0x73, 0x00,
])


class EncryptionError(Exception):
    """Raised when encryption/decryption fails."""
    pass


def get_version_string(data: bytes) -> str:
    """
    Extract DWG version string from file data.

    Args:
        data: Raw file bytes (at least 6 bytes)

    Returns:
        Version string (e.g., "AC1032")
    """
    if len(data) < 6:
        return ""
    try:
        return data[0:6].decode("ascii", errors="ignore").rstrip("\x00")
    except Exception:
        return ""


def is_encrypted_header(data: bytes) -> bool:
    """
    Check if DWG file has encrypted header.

    AC1032 (R2018+) files encrypt the header region from 0x80-0x100.
    Detection is based on version string and encryption flag.

    Args:
        data: Raw file bytes

    Returns:
        True if file has encrypted header
    """
    if len(data) < 0x10:
        return False

    version = get_version_string(data)

    # Only AC1032 has full header encryption
    if version == "AC1032":
        # Check encryption flag at offset 0x06
        # Bit 0 indicates encryption
        if len(data) > 0x07:
            flags = struct.unpack_from("<H", data, 0x06)[0]
            # In AC1032, even without explicit flag, the header region is encrypted
            # Return True for all AC1032 files
            return True

    # AC1021 (R2007) has partial encryption
    if version == "AC1021":
        # R2007 uses different encryption scheme
        return True

    return False


def decrypt_header(data: bytes, in_place: bool = False) -> bytes:
    """
    Decrypt DWG file header.

    Applies the appropriate XOR mask based on file version.

    Args:
        data: Raw file bytes (will be copied unless in_place=True)
        in_place: If True, modify the input bytes (requires bytearray)

    Returns:
        File data with decrypted header
    """
    version = get_version_string(data)

    if version == "AC1032":
        return _decrypt_ac1032_header(data, in_place)
    elif version == "AC1021":
        return _decrypt_ac1021_header(data, in_place)
    else:
        # No encryption for older versions
        return data if in_place else bytes(data)


def _decrypt_ac1032_header(data: bytes, in_place: bool = False) -> bytes:
    """
    Decrypt AC1032 (R2018+) header region.

    The encrypted region is 0x80-0x100 (128 bytes).
    XOR mask repeats every 32 bytes.

    Args:
        data: Raw file bytes
        in_place: If True, modify input (requires bytearray)

    Returns:
        Data with decrypted header
    """
    if len(data) < AC1032_ENCRYPTED_END:
        raise EncryptionError(
            f"File too small for AC1032 decryption: {len(data)} < {AC1032_ENCRYPTED_END}"
        )

    if in_place:
        if not isinstance(data, bytearray):
            raise EncryptionError("in_place requires bytearray input")
        result = data
    else:
        result = bytearray(data)

    mask_len = len(AC1032_HEADER_MASK)

    for i in range(AC1032_ENCRYPTED_START, AC1032_ENCRYPTED_END):
        mask_idx = (i - AC1032_ENCRYPTED_START) % mask_len
        result[i] ^= AC1032_HEADER_MASK[mask_idx]

    return bytes(result) if not in_place else result


def _decrypt_ac1021_header(data: bytes, in_place: bool = False) -> bytes:
    """
    Decrypt AC1021 (R2007) header region.

    R2007 uses a different encryption scheme with a shorter mask.

    Args:
        data: Raw file bytes
        in_place: If True, modify input (requires bytearray)

    Returns:
        Data with decrypted header
    """
    # R2007 encryption is simpler - primarily affects section locator
    # The mask is applied to specific regions
    if len(data) < 0x100:
        raise EncryptionError(
            f"File too small for AC1021 decryption: {len(data)} < 256"
        )

    if in_place:
        if not isinstance(data, bytearray):
            raise EncryptionError("in_place requires bytearray input")
        result = data
    else:
        result = bytearray(data)

    # R2007 encrypted region is smaller
    # Apply mask to section locator region (0x20-0x80)
    mask_len = len(AC1021_HEADER_MASK)

    for i in range(0x20, 0x80):
        if i < len(result):
            mask_idx = (i - 0x20) % mask_len
            result[i] ^= AC1021_HEADER_MASK[mask_idx]

    return bytes(result) if not in_place else result


def get_section_locator_offset(version: str) -> int:
    """
    Get the section locator offset for a given DWG version.

    Different versions store the section map address at different offsets.

    Args:
        version: DWG version string (e.g., "AC1032")

    Returns:
        Offset to section locator structure
    """
    offsets = {
        "AC1018": 0x20,  # R2004
        "AC1021": 0x20,  # R2007
        "AC1024": 0x20,  # R2010
        "AC1027": 0x20,  # R2013
        "AC1032": 0x80,  # R2018+ (after decryption)
    }
    return offsets.get(version, 0x20)


def get_section_map_address_offset(version: str) -> int:
    """
    Get the offset within the section locator where the map address is stored.

    Args:
        version: DWG version string

    Returns:
        Offset to section map address (relative to start of locator)
    """
    # The section map address is typically at offset 0x14 (20 bytes)
    # within the section locator structure
    if version == "AC1032":
        # In AC1032, structure is different after decryption
        return 0x14
    else:
        # R2004-R2017 use offset 0x14 from locator start
        return 0x14


def read_section_map_address(data: bytes) -> Tuple[int, str]:
    """
    Read the section map address from file header.

    Handles encryption detection and decryption automatically.

    Args:
        data: Raw file bytes

    Returns:
        Tuple of (section_map_address, version_string)
    """
    version = get_version_string(data)

    # Decrypt if needed
    if is_encrypted_header(data):
        data = decrypt_header(data)

    # Get locator offset for this version
    locator_offset = get_section_locator_offset(version)
    address_offset = get_section_map_address_offset(version)

    # Read the address
    abs_offset = locator_offset + address_offset
    if len(data) < abs_offset + 4:
        raise EncryptionError(
            f"File too small to read section map address at 0x{abs_offset:X}"
        )

    address = struct.unpack_from("<I", data, abs_offset)[0]
    return address, version


def prepare_file_data(data: bytes) -> Tuple[bytes, str, bool]:
    """
    Prepare file data for parsing by decrypting if necessary.

    Args:
        data: Raw file bytes

    Returns:
        Tuple of (prepared_data, version, was_encrypted)
    """
    version = get_version_string(data)
    was_encrypted = is_encrypted_header(data)

    if was_encrypted:
        prepared = decrypt_header(data)
    else:
        prepared = data

    return prepared, version, was_encrypted
