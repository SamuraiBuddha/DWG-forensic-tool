"""CRC32 validation for DWG file headers.

This module provides CRC32 validation for DWG files. CRC validation is available
for AC1015+ versions (AutoCAD 2000 and later).

Supported versions:
    - AC1032 (AutoCAD 2018+): CRC at offset 0x68
    - AC1027 (AutoCAD 2013-2017): CRC at offset 0x68
    - AC1024 (AutoCAD 2010-2012): CRC at offset 0x68
    - AC1021 (AutoCAD 2007-2009): CRC at offset 0x68
    - AC1018 (AutoCAD 2004-2006): CRC at offset 0x5C
    - AC1015 (AutoCAD 2000-2002): CRC at offset 0x5C

Unsupported versions (no CRC validation):
    - AC1014 (AutoCAD R14)
    - AC1012 (AutoCAD R13)
"""

import zlib
from pathlib import Path
from typing import BinaryIO, Optional

from dwg_forensic.models import CRCValidation
from dwg_forensic.utils.exceptions import InvalidDWGError


class CRCValidator:
    """Validates CRC32 checksums in DWG file headers.

    CRC32 validation is available for AutoCAD 2000 and later versions.
    Earlier versions (R13, R14) do not have a header CRC in the same format.
    """

    # CRC offset and header length by version
    VERSION_CRC_INFO = {
        # R24+ versions: CRC at 0x68, header length 0x68
        "AC1032": {"offset": 0x68, "length": 0x68},
        "AC1027": {"offset": 0x68, "length": 0x68},
        "AC1024": {"offset": 0x68, "length": 0x68},
        # R21: Same as R24+
        "AC1021": {"offset": 0x68, "length": 0x68},
        # R18 (2004-2006): CRC at 0x5C, header length 0x5C
        "AC1018": {"offset": 0x5C, "length": 0x5C},
        # R15 (2000-2002): CRC at 0x5C, header length 0x5C
        "AC1015": {"offset": 0x5C, "length": 0x5C},
    }

    # Versions without CRC support
    NO_CRC_VERSIONS = ["AC1012", "AC1014", "AC1009", "AC1006"]

    def validate_header_crc(
        self, file_path: Path, version_string: Optional[str] = None
    ) -> CRCValidation:
        """Validate the header CRC32 checksum for a DWG file.

        Reads the stored CRC value from the header and compares it against
        a calculated CRC32 over the header bytes.

        Args:
            file_path: Path to the DWG file to validate.
            version_string: DWG version string (e.g., 'AC1032'). If None,
                           will be detected from the file.

        Returns:
            CRCValidation object containing validation results. For versions
            without CRC support, returns a result with is_valid=True and
            "N/A" for CRC values.

        Raises:
            InvalidDWGError: If the file is too small or cannot be read.
        """
        file_path = Path(file_path)

        try:
            with open(file_path, "rb") as f:
                # Detect version if not provided
                if version_string is None:
                    version_string = self._detect_version(f)

                # Check if version supports CRC validation
                if not self.has_crc_support(version_string):
                    return CRCValidation(
                        header_crc_stored="N/A",
                        header_crc_calculated="N/A",
                        is_valid=True,  # Not a failure, just not available
                        section_results=[],
                    )

                # Get version-specific CRC info
                crc_info = self.VERSION_CRC_INFO.get(version_string)
                if crc_info is None:
                    # Unknown version, use default R24+ offsets
                    crc_info = {"offset": 0x68, "length": 0x68}

                crc_offset = crc_info["offset"]
                header_length = crc_info["length"]

                # Check if file is large enough
                f.seek(0, 2)  # Seek to end
                file_size = f.tell()

                if file_size < crc_offset + 4:
                    raise InvalidDWGError(
                        str(file_path),
                        f"File is too small ({file_size} bytes). "
                        f"Expected at least {crc_offset + 4} bytes for {version_string}."
                    )

                # Read stored CRC and calculate expected CRC
                stored_crc = self._read_stored_crc(f, crc_offset)
                calculated_crc = self._calculate_header_crc(f, header_length)

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

    def has_crc_support(self, version_string: str) -> bool:
        """Check if a version supports CRC validation.

        Args:
            version_string: DWG version string.

        Returns:
            True if version supports CRC validation.
        """
        if version_string in self.NO_CRC_VERSIONS:
            return False
        return version_string in self.VERSION_CRC_INFO

    def _detect_version(self, f: BinaryIO) -> str:
        """Detect DWG version from file header.

        Args:
            f: Open file handle.

        Returns:
            Version string (e.g., 'AC1032').
        """
        f.seek(0)
        version_bytes = f.read(6)

        if len(version_bytes) < 6:
            raise InvalidDWGError(reason="File too small to detect version")

        try:
            return version_bytes.decode("ascii").rstrip("\x00")
        except UnicodeDecodeError:
            raise InvalidDWGError(reason="Cannot decode version string")

    def _read_stored_crc(self, f: BinaryIO, offset: int) -> int:
        """Read the stored CRC32 value from the file header.

        Args:
            f: Open file handle.
            offset: Byte offset where CRC is stored.

        Returns:
            The stored CRC32 value as an integer.
        """
        f.seek(offset)
        crc_bytes = f.read(4)

        if len(crc_bytes) != 4:
            raise InvalidDWGError(
                reason=f"Could not read CRC value at offset {offset}"
            )

        # CRC is stored as little-endian 32-bit integer
        return int.from_bytes(crc_bytes, byteorder="little", signed=False)

    def _calculate_header_crc(self, f: BinaryIO, header_length: int) -> int:
        """Calculate CRC32 over the header bytes.

        Args:
            f: Open file handle.
            header_length: Number of bytes to include in CRC calculation.

        Returns:
            The calculated CRC32 value as an integer.
        """
        f.seek(0)
        header_data = f.read(header_length)

        if len(header_data) != header_length:
            raise InvalidDWGError(
                reason=f"Could not read {header_length} bytes for CRC calculation. "
                f"Only read {len(header_data)} bytes."
            )

        # Calculate CRC32 using zlib
        # zlib.crc32 returns a signed 32-bit integer on some platforms,
        # so we mask it to get unsigned value
        crc_value = zlib.crc32(header_data) & 0xFFFFFFFF

        return crc_value
