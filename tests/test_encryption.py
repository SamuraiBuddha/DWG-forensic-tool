"""
Tests for DWG encryption/decryption module.

Tests R2018+ (AC1032) and R2007 (AC1021) header encryption handling.
"""

import pytest
from dwg_forensic.parsers.encryption import (
    EncryptionError,
    AC1032_HEADER_MASK,
    AC1032_ENCRYPTED_START,
    AC1032_ENCRYPTED_END,
    get_version_string,
    is_encrypted_header,
    decrypt_header,
    _decrypt_ac1032_header,
    _decrypt_ac1021_header,
    get_section_locator_offset,
    get_section_map_address_offset,
    read_section_map_address,
    prepare_file_data,
)


class TestVersionDetection:
    """Tests for version string extraction."""

    def test_get_version_ac1032(self):
        """Test AC1032 version detection."""
        data = b"AC1032" + b"\x00" * 100
        assert get_version_string(data) == "AC1032"

    def test_get_version_ac1027(self):
        """Test AC1027 version detection."""
        data = b"AC1027" + b"\x00" * 100
        assert get_version_string(data) == "AC1027"

    def test_get_version_ac1024(self):
        """Test AC1024 version detection."""
        data = b"AC1024" + b"\x00" * 100
        assert get_version_string(data) == "AC1024"

    def test_get_version_ac1021(self):
        """Test AC1021 version detection."""
        data = b"AC1021" + b"\x00" * 100
        assert get_version_string(data) == "AC1021"

    def test_get_version_ac1018(self):
        """Test AC1018 version detection."""
        data = b"AC1018" + b"\x00" * 100
        assert get_version_string(data) == "AC1018"

    def test_get_version_short_data(self):
        """Test with data too short for version."""
        data = b"AC10"
        assert get_version_string(data) == ""

    def test_get_version_empty(self):
        """Test with empty data."""
        assert get_version_string(b"") == ""

    def test_get_version_with_nulls(self):
        """Test version string with trailing nulls."""
        data = b"AC1032\x00\x00" + b"\x00" * 100
        assert get_version_string(data) == "AC1032"


class TestEncryptionDetection:
    """Tests for encryption detection."""

    def test_is_encrypted_ac1032(self):
        """Test that AC1032 is detected as encrypted."""
        data = b"AC1032" + b"\x00" * 256
        assert is_encrypted_header(data) is True

    def test_is_encrypted_ac1021(self):
        """Test that AC1021 is detected as encrypted."""
        data = b"AC1021" + b"\x00" * 256
        assert is_encrypted_header(data) is True

    def test_not_encrypted_ac1024(self):
        """Test that AC1024 is not detected as encrypted."""
        data = b"AC1024" + b"\x00" * 256
        assert is_encrypted_header(data) is False

    def test_not_encrypted_ac1027(self):
        """Test that AC1027 is not detected as encrypted."""
        data = b"AC1027" + b"\x00" * 256
        assert is_encrypted_header(data) is False

    def test_not_encrypted_ac1018(self):
        """Test that AC1018 is not detected as encrypted."""
        data = b"AC1018" + b"\x00" * 256
        assert is_encrypted_header(data) is False

    def test_short_data_not_encrypted(self):
        """Test that short data is not detected as encrypted."""
        data = b"AC1032"
        assert is_encrypted_header(data) is False


class TestAC1032Decryption:
    """Tests for AC1032 header decryption."""

    def test_decrypt_identity(self):
        """Test that decrypting twice returns original (XOR property)."""
        # Create test data with encrypted region
        data = b"AC1032" + b"\x00" * (AC1032_ENCRYPTED_END + 50)

        # Decrypt once
        decrypted = decrypt_header(data)

        # Decrypt again - should return close to original
        # (not exact because first 6 bytes are version, not affected)
        double_decrypted = decrypt_header(decrypted)

        # The encrypted region should match original
        assert data[AC1032_ENCRYPTED_START:AC1032_ENCRYPTED_END] == \
               double_decrypted[AC1032_ENCRYPTED_START:AC1032_ENCRYPTED_END]

    def test_decrypt_modifies_encrypted_region(self):
        """Test that decryption modifies the encrypted region."""
        # Create test data with non-zero encrypted region
        data = bytearray(b"AC1032" + b"\x00" * AC1032_ENCRYPTED_END)
        for i in range(AC1032_ENCRYPTED_START, AC1032_ENCRYPTED_END):
            data[i] = 0xFF  # Set to non-zero

        decrypted = decrypt_header(bytes(data))

        # Encrypted region should be modified
        assert decrypted[AC1032_ENCRYPTED_START:AC1032_ENCRYPTED_END] != \
               data[AC1032_ENCRYPTED_START:AC1032_ENCRYPTED_END]

    def test_decrypt_preserves_header(self):
        """Test that decryption preserves the unencrypted header region."""
        data = b"AC1032" + b"\x12\x34" + b"\x00" * (AC1032_ENCRYPTED_END + 50)

        decrypted = decrypt_header(data)

        # First 8 bytes should be unchanged
        assert decrypted[:8] == data[:8]

    def test_decrypt_preserves_tail(self):
        """Test that decryption preserves data after encrypted region."""
        tail_data = b"TAILDATA"
        data = b"AC1032" + b"\x00" * (AC1032_ENCRYPTED_END - 6) + tail_data

        decrypted = decrypt_header(data)

        # Tail should be unchanged
        assert decrypted[AC1032_ENCRYPTED_END:] == tail_data

    def test_decrypt_too_small_raises(self):
        """Test that decrypting too-small data raises error."""
        data = b"AC1032" + b"\x00" * 10  # Too small

        with pytest.raises(EncryptionError, match="too small"):
            _decrypt_ac1032_header(data)

    def test_decrypt_in_place(self):
        """Test in-place decryption with bytearray."""
        data = bytearray(b"AC1032" + b"\x00" * AC1032_ENCRYPTED_END)
        for i in range(AC1032_ENCRYPTED_START, AC1032_ENCRYPTED_END):
            data[i] = 0xFF

        original_id = id(data)
        result = _decrypt_ac1032_header(data, in_place=True)

        # Should return same object
        assert id(result) == original_id

    def test_decrypt_in_place_requires_bytearray(self):
        """Test that in-place decryption requires bytearray."""
        data = b"AC1032" + b"\x00" * AC1032_ENCRYPTED_END

        with pytest.raises(EncryptionError, match="bytearray"):
            _decrypt_ac1032_header(data, in_place=True)


class TestAC1021Decryption:
    """Tests for AC1021 (R2007) header decryption."""

    def test_decrypt_ac1021(self):
        """Test AC1021 decryption."""
        data = b"AC1021" + b"\x00" * 256

        decrypted = decrypt_header(data)

        # Should return data (possibly modified)
        assert len(decrypted) == len(data)
        assert decrypted[:6] == b"AC1021"

    def test_decrypt_ac1021_too_small(self):
        """Test AC1021 decryption with too-small data."""
        data = b"AC1021" + b"\x00" * 10

        with pytest.raises(EncryptionError, match="too small"):
            _decrypt_ac1021_header(data)


class TestSectionLocatorOffsets:
    """Tests for section locator offset calculations."""

    def test_ac1032_offset(self):
        """Test AC1032 locator offset."""
        assert get_section_locator_offset("AC1032") == 0x80

    def test_ac1027_offset(self):
        """Test AC1027 locator offset."""
        assert get_section_locator_offset("AC1027") == 0x20

    def test_ac1024_offset(self):
        """Test AC1024 locator offset."""
        assert get_section_locator_offset("AC1024") == 0x20

    def test_ac1021_offset(self):
        """Test AC1021 locator offset."""
        assert get_section_locator_offset("AC1021") == 0x20

    def test_ac1018_offset(self):
        """Test AC1018 locator offset."""
        assert get_section_locator_offset("AC1018") == 0x20

    def test_unknown_version_offset(self):
        """Test unknown version defaults to 0x20."""
        assert get_section_locator_offset("AC9999") == 0x20

    def test_section_map_address_offset(self):
        """Test section map address offset within locator."""
        assert get_section_map_address_offset("AC1032") == 0x14
        assert get_section_map_address_offset("AC1024") == 0x14


class TestPrepareFileData:
    """Tests for prepare_file_data convenience function."""

    def test_prepare_ac1032(self):
        """Test preparing AC1032 file data."""
        data = b"AC1032" + b"\x00" * 300

        prepared, version, was_encrypted = prepare_file_data(data)

        assert version == "AC1032"
        assert was_encrypted is True
        assert len(prepared) == len(data)

    def test_prepare_ac1024(self):
        """Test preparing AC1024 file data (no encryption)."""
        data = b"AC1024" + b"\x00" * 300

        prepared, version, was_encrypted = prepare_file_data(data)

        assert version == "AC1024"
        assert was_encrypted is False
        assert prepared == data

    def test_prepare_preserves_data(self):
        """Test that prepare doesn't modify original data."""
        original = b"AC1032" + b"\x00" * 300
        data = bytes(original)

        prepared, _, _ = prepare_file_data(data)

        # Original should be unchanged
        assert data == original


class TestMaskProperties:
    """Tests for encryption mask properties."""

    def test_mask_length(self):
        """Test that AC1032 mask is 32 bytes."""
        assert len(AC1032_HEADER_MASK) == 32

    def test_encrypted_region_size(self):
        """Test encrypted region size."""
        region_size = AC1032_ENCRYPTED_END - AC1032_ENCRYPTED_START
        assert region_size == 128  # 0x100 - 0x80 = 128 bytes

    def test_mask_is_non_trivial(self):
        """Test that mask contains non-zero values."""
        assert any(b != 0 for b in AC1032_HEADER_MASK)

    def test_mask_not_all_same(self):
        """Test that mask is not all the same value."""
        assert len(set(AC1032_HEADER_MASK)) > 1
