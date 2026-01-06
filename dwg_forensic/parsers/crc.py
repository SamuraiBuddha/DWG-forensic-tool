"""CRC32 validation for DWG file headers.

This module provides CRC32 validation for R18+ DWG files (AC1024, AC1027, AC1032).
The header CRC is stored at offset 0x68 and is calculated over the first 104 bytes
of the file header.
"""

import zlib
from pathlib import Path
from typing import BinaryIO

from dwg_forensic.models import CRCValidation
from dwg_forensic.utils.exceptions import InvalidDWGError


class CRCValidator:
    """Validates CRC32 checksums in DWG file headers.

    For R18+ DWG files (AC1024, AC1027, AC1032), the header contains a CRC32
    checksum to verify header integrity.

    Attributes:
        HEADER_CRC_OFFSET: Byte offset where the CRC32 value is stored (0x68).
        HEADER_LENGTH: Number of bytes to include in CRC calculation (0x68 = 104 bytes).
    """

    HEADER_CRC_OFFSET = 0x68
    HEADER_LENGTH = 0x68  # 104 bytes to hash

    def validate_header_crc(self, file_path: Path) -> CRCValidation:
        """Validate the header CRC32 checksum for a DWG file.

        Reads the stored CRC value from the header and compares it against
        a calculated CRC32 over the first 104 bytes of the file.

        Args:
            file_path: Path to the DWG file to validate.

        Returns:
            CRCValidation object containing validation results.

        Raises:
            InvalidDWGError: If the file is too small or cannot be read.
        """
        file_path = Path(file_path)

        try:
            with open(file_path, "rb") as f:
                # Check if file is large enough to contain header and CRC
                f.seek(0, 2)  # Seek to end
                file_size = f.tell()

                if file_size < self.HEADER_CRC_OFFSET + 4:
                    raise InvalidDWGError(
                        str(file_path),
                        f"File is too small ({file_size} bytes). "
                        f"Expected at least {self.HEADER_CRC_OFFSET + 4} bytes."
                    )

                # Read stored CRC and calculate expected CRC
                stored_crc = self._read_stored_crc(f)
                calculated_crc = self._calculate_header_crc(f)

                # Format CRC values as hex strings with 0x prefix
                stored_hex = f"0x{stored_crc:08X}"
                calculated_hex = f"0x{calculated_crc:08X}"

                return CRCValidation(
                    header_crc_stored=stored_hex,
                    header_crc_calculated=calculated_hex,
                    is_valid=(stored_crc == calculated_crc),
                    section_results=[],
                )

        except FileNotFoundError:
            raise InvalidDWGError(str(file_path), "File not found")
        except PermissionError:
            raise InvalidDWGError(str(file_path), "Permission denied")
        except OSError as e:
            raise InvalidDWGError(str(file_path), f"Error reading file: {e}")

    def _read_stored_crc(self, f: BinaryIO) -> int:
        """Read the stored CRC32 value from the file header.

        Args:
            f: Open file handle positioned at any location.

        Returns:
            The stored CRC32 value as an integer.
        """
        f.seek(self.HEADER_CRC_OFFSET)
        crc_bytes = f.read(4)

        if len(crc_bytes) != 4:
            raise InvalidDWGError(
                reason=f"Could not read CRC value at offset {self.HEADER_CRC_OFFSET}"
            )

        # CRC is stored as little-endian 32-bit integer
        return int.from_bytes(crc_bytes, byteorder="little", signed=False)

    def _calculate_header_crc(self, f: BinaryIO) -> int:
        """Calculate CRC32 over the first 104 bytes of the file header.

        Args:
            f: Open file handle positioned at any location.

        Returns:
            The calculated CRC32 value as an integer.
        """
        f.seek(0)
        header_data = f.read(self.HEADER_LENGTH)

        if len(header_data) != self.HEADER_LENGTH:
            raise InvalidDWGError(
                reason=f"Could not read {self.HEADER_LENGTH} bytes for CRC calculation. "
                f"Only read {len(header_data)} bytes."
            )

        # Calculate CRC32 using zlib
        # zlib.crc32 returns a signed 32-bit integer on some platforms,
        # so we mask it to get unsigned value
        crc_value = zlib.crc32(header_data) & 0xFFFFFFFF

        return crc_value
