"""Binary header parser for DWG files (R18+ versions only).

This module provides parsing functionality for DWG file headers, supporting
AutoCAD versions from 2010 onwards (AC1024/R2010 and later).
"""

import struct
from pathlib import Path

from dwg_forensic.models import HeaderAnalysis
from dwg_forensic.utils.exceptions import InvalidDWGError, UnsupportedVersionError


class HeaderParser:
    """Parser for DWG file headers supporting R18+ versions.

    Supported Versions:
        - AC1024: AutoCAD 2010-2012 (R2010)
        - AC1027: AutoCAD 2013-2017 (R2013)
        - AC1032: AutoCAD 2018+ (R2018)

    Header Structure (R18+):
        - Offset 0x00, Length 6: Version string
        - Offset 0x06, Length 5: Zero bytes
        - Offset 0x0B, Length 1: Maintenance version
        - Offset 0x0D, Length 4: Preview address (little-endian)
        - Offset 0x13, Length 2: Codepage (little-endian)
        - Offset 0x68, Length 4: CRC32 (little-endian)
    """

    # Version string to human-readable name mapping
    DWG_VERSIONS = {
        "AC1024": "AutoCAD 2010-2012",
        "AC1027": "AutoCAD 2013-2017",
        "AC1032": "AutoCAD 2018+",
        # Legacy versions (not supported but recognized)
        "AC1006": "AutoCAD R10",
        "AC1009": "AutoCAD R11-R12",
        "AC1012": "AutoCAD R13",
        "AC1014": "AutoCAD R14",
        "AC1015": "AutoCAD 2000-2002",
        "AC1018": "AutoCAD 2004-2006",
        "AC1021": "AutoCAD 2007-2009",
    }

    # Supported versions (R18+ only)
    SUPPORTED_VERSIONS = ["AC1024", "AC1027", "AC1032"]

    # Header field offsets
    OFFSET_VERSION = 0x00
    OFFSET_ZERO_BYTES = 0x06
    OFFSET_MAINTENANCE = 0x0B
    OFFSET_PREVIEW_ADDR = 0x0D
    OFFSET_CODEPAGE = 0x13
    OFFSET_CRC32 = 0x68

    # Minimum header size required for R18+ parsing
    MIN_HEADER_SIZE = 0x6C  # 108 bytes

    def parse(self, file_path: Path) -> HeaderAnalysis:
        """Parse DWG file header and extract metadata.

        Args:
            file_path: Path to the DWG file to parse

        Returns:
            HeaderAnalysis model containing parsed header data

        Raises:
            InvalidDWGError: If file is not a valid DWG file
            UnsupportedVersionError: If DWG version is below R18
            FileNotFoundError: If file does not exist
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"DWG file not found: {file_path}")

        if not file_path.is_file():
            raise InvalidDWGError(str(file_path), "Path is not a file")

        try:
            with open(file_path, "rb") as f:
                header_data = f.read(self.MIN_HEADER_SIZE)
        except PermissionError as e:
            raise PermissionError(f"Cannot read file: {file_path}") from e
        except Exception as e:
            raise InvalidDWGError(str(file_path), f"Error reading file: {e}") from e

        if len(header_data) < self.MIN_HEADER_SIZE:
            raise InvalidDWGError(
                str(file_path),
                f"File too small to be a valid DWG file "
                f"(expected at least {self.MIN_HEADER_SIZE} bytes, got {len(header_data)})"
            )

        # Parse header fields
        version_string = self._read_version_string(header_data)
        self._validate_version(version_string, str(file_path))

        maintenance_version = self._read_maintenance_version(header_data)
        preview_address = self._read_preview_address(header_data)
        codepage = self._read_codepage(header_data)

        return HeaderAnalysis(
            version_string=version_string,
            version_name=self.DWG_VERSIONS.get(version_string, "Unknown"),
            maintenance_version=maintenance_version,
            preview_address=preview_address,
            codepage=codepage,
            is_supported=version_string in self.SUPPORTED_VERSIONS,
        )

    def _read_version_string(self, data: bytes) -> str:
        """Read version string from header.

        Args:
            data: Raw header data

        Returns:
            Version string (e.g., 'AC1032')

        Raises:
            InvalidDWGError: If version string is invalid
        """
        try:
            version_bytes = data[self.OFFSET_VERSION:self.OFFSET_VERSION + 6]
            version_string = version_bytes.decode("ascii").rstrip("\x00")

            if not version_string.startswith("AC"):
                raise InvalidDWGError(
                    reason=f"Invalid DWG version string: {version_string!r} (expected format: 'ACxxxx')"
                )

            return version_string
        except UnicodeDecodeError as e:
            raise InvalidDWGError(reason=f"Cannot decode version string: {e}") from e

    def _validate_version(self, version_string: str, file_path: str) -> None:
        """Validate that version is supported (R18+).

        Args:
            version_string: Version string to validate
            file_path: Path to file for error context

        Raises:
            UnsupportedVersionError: If version is below R18
        """
        if version_string not in self.SUPPORTED_VERSIONS:
            version_name = self.DWG_VERSIONS.get(version_string, "Unknown version")
            raise UnsupportedVersionError(
                version=version_string,
                version_name=version_name,
                file_path=file_path,
            )

    def _read_maintenance_version(self, data: bytes) -> int:
        """Read maintenance version from header.

        Args:
            data: Raw header data

        Returns:
            Maintenance version as unsigned byte
        """
        return struct.unpack_from("B", data, self.OFFSET_MAINTENANCE)[0]

    def _read_preview_address(self, data: bytes) -> int:
        """Read preview image address from header.

        Args:
            data: Raw header data

        Returns:
            Preview address as little-endian unsigned 32-bit integer
        """
        return struct.unpack_from("<I", data, self.OFFSET_PREVIEW_ADDR)[0]

    def _read_codepage(self, data: bytes) -> int:
        """Read codepage from header.

        Args:
            data: Raw header data

        Returns:
            Codepage as little-endian unsigned 16-bit integer
        """
        return struct.unpack_from("<H", data, self.OFFSET_CODEPAGE)[0]

    def _read_stored_crc(self, data: bytes) -> int:
        """Read CRC32 checksum from header.

        Args:
            data: Raw header data

        Returns:
            CRC32 as little-endian unsigned 32-bit integer
        """
        return struct.unpack_from("<I", data, self.OFFSET_CRC32)[0]
