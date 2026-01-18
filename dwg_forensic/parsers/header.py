"""Binary header parser for DWG files.

This module provides parsing functionality for DWG file headers, supporting
AutoCAD versions from R13 (AC1012) onwards with varying levels of analysis.

Full analysis support: AC1024+ (AutoCAD 2010+)
Limited analysis support: AC1012-AC1021 (AutoCAD R13 through 2009)
"""

import struct
from pathlib import Path
from typing import Optional

from dwg_forensic.models import HeaderAnalysis
from dwg_forensic.utils.exceptions import InvalidDWGError, UnsupportedVersionError, ParseError


class HeaderParser:
    """Parser for DWG file headers supporting multiple version families.

    Full Support (R24+):
        - AC1024: AutoCAD 2010-2012 (R2010)
        - AC1027: AutoCAD 2013-2017 (R2013)
        - AC1032: AutoCAD 2018+ (R2018)

    Limited Support (R13-R21):
        - AC1012: AutoCAD R13
        - AC1014: AutoCAD R14
        - AC1015: AutoCAD 2000-2002 (R15)
        - AC1018: AutoCAD 2004-2006 (R18)
        - AC1021: AutoCAD 2007-2009 (R21)

    Header Structure varies by version family:
        R13-R14: Simpler structure, different offsets
        R15-R18: Transitional structure
        R21+: Modern structure with TrustedDWG support
    """

    # Version string to human-readable name mapping
    DWG_VERSIONS = {
        "AC1032": "AutoCAD 2018+",
        "AC1027": "AutoCAD 2013-2017",
        "AC1024": "AutoCAD 2010-2012",
        "AC1021": "AutoCAD 2007-2009",
        "AC1018": "AutoCAD 2004-2006",
        "AC1015": "AutoCAD 2000-2002",
        "AC1014": "AutoCAD R14",
        "AC1012": "AutoCAD R13",
        "AC1009": "AutoCAD R11-R12",
        "AC1006": "AutoCAD R10",
    }

    # Versions with full analysis support (CRC32, TrustedDWG, etc.)
    FULL_SUPPORT_VERSIONS = ["AC1024", "AC1027", "AC1032"]

    # Versions with limited analysis support (basic header parsing only)
    LIMITED_SUPPORT_VERSIONS = ["AC1012", "AC1014", "AC1015", "AC1018", "AC1021"]

    # All supported versions
    SUPPORTED_VERSIONS = FULL_SUPPORT_VERSIONS + LIMITED_SUPPORT_VERSIONS

    # Unsupported legacy versions (too old)
    UNSUPPORTED_VERSIONS = ["AC1006", "AC1009"]

    # Header field offsets for R24+ (AC1024+)
    OFFSET_VERSION = 0x00
    OFFSET_ZERO_BYTES = 0x06
    OFFSET_MAINTENANCE_R24 = 0x0B
    OFFSET_PREVIEW_ADDR_R24 = 0x0D
    OFFSET_CODEPAGE_R24 = 0x13
    OFFSET_CRC32_R24 = 0x68

    # Header field offsets for R21 (AC1021)
    OFFSET_MAINTENANCE_R21 = 0x0B
    OFFSET_PREVIEW_ADDR_R21 = 0x0D
    OFFSET_CODEPAGE_R21 = 0x13
    OFFSET_CRC32_R21 = 0x68

    # Header field offsets for R18 (AC1018)
    OFFSET_MAINTENANCE_R18 = 0x0B
    OFFSET_PREVIEW_ADDR_R18 = 0x0D
    OFFSET_CODEPAGE_R18 = 0x13
    OFFSET_CRC32_R18 = 0x5C

    # Header field offsets for R15 (AC1015)
    OFFSET_MAINTENANCE_R15 = 0x0B
    OFFSET_PREVIEW_ADDR_R15 = 0x0D
    OFFSET_CODEPAGE_R15 = 0x13
    OFFSET_CRC32_R15 = 0x5C

    # Header field offsets for R13-R14 (AC1012-AC1014)
    OFFSET_MAINTENANCE_R13 = 0x0B
    OFFSET_PREVIEW_ADDR_R13 = 0x0D
    OFFSET_CODEPAGE_R13 = 0x13

    # Minimum header sizes by version family
    MIN_HEADER_SIZE_R24 = 0x6C  # 108 bytes
    MIN_HEADER_SIZE_R21 = 0x6C  # 108 bytes
    MIN_HEADER_SIZE_R18 = 0x60  # 96 bytes
    MIN_HEADER_SIZE_R15 = 0x60  # 96 bytes
    MIN_HEADER_SIZE_R13 = 0x20  # 32 bytes (minimal for basic parsing)

    # Minimum header size for version detection
    MIN_HEADER_SIZE = 0x20  # 32 bytes minimum to read version

    def parse(self, file_path: Path) -> HeaderAnalysis:
        """Parse DWG file header and extract metadata.

        Args:
            file_path: Path to the DWG file to parse

        Returns:
            HeaderAnalysis model containing parsed header data

        Raises:
            InvalidDWGError: If file is not a valid DWG file
            UnsupportedVersionError: If DWG version is not supported (R10/R11-R12)
            FileNotFoundError: If file does not exist
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"DWG file not found: {file_path}")

        if not file_path.is_file():
            raise InvalidDWGError(str(file_path), "Path is not a file")

        # First read minimal header to detect version
        try:
            with open(file_path, "rb") as f:
                initial_data = f.read(self.MIN_HEADER_SIZE)
        except PermissionError as e:
            raise PermissionError(f"Cannot read file: {file_path}") from e
        except Exception as e:
            raise InvalidDWGError(str(file_path), f"Error reading file: {e}") from e

        if len(initial_data) < self.MIN_HEADER_SIZE:
            raise InvalidDWGError(
                str(file_path),
                f"File too small to be a valid DWG file "
                f"(expected at least {self.MIN_HEADER_SIZE} bytes, got {len(initial_data)})"
            )

        # Detect version first
        version_string = self._read_version_string(initial_data)
        self._validate_version(version_string, str(file_path))

        # Get required header size for this version
        required_size = self._get_min_header_size(version_string)

        # Read full header if needed
        if required_size > len(initial_data):
            try:
                with open(file_path, "rb") as f:
                    header_data = f.read(required_size)
            except Exception as e:
                raise InvalidDWGError(str(file_path), f"Error reading file: {e}") from e

            if len(header_data) < required_size:
                raise InvalidDWGError(
                    str(file_path),
                    f"File too small for {version_string} header "
                    f"(expected {required_size} bytes, got {len(header_data)})"
                )
        else:
            header_data = initial_data

        # Parse using version-appropriate method
        return self._parse_version_specific(header_data, version_string)

    def _get_min_header_size(self, version_string: str) -> int:
        """Get minimum header size required for a specific version.

        Args:
            version_string: DWG version string (e.g., 'AC1032')

        Returns:
            Minimum header size in bytes
        """
        if version_string in self.FULL_SUPPORT_VERSIONS:
            return self.MIN_HEADER_SIZE_R24
        elif version_string == "AC1021":
            return self.MIN_HEADER_SIZE_R21
        elif version_string == "AC1018":
            return self.MIN_HEADER_SIZE_R18
        elif version_string == "AC1015":
            return self.MIN_HEADER_SIZE_R15
        elif version_string in ["AC1012", "AC1014"]:
            return self.MIN_HEADER_SIZE_R13
        else:
            return self.MIN_HEADER_SIZE

    def _parse_version_specific(self, data: bytes, version_string: str) -> HeaderAnalysis:
        """Parse header using version-specific offsets and logic.

        Args:
            data: Raw header data
            version_string: DWG version string

        Returns:
            HeaderAnalysis with parsed data
        """
        is_full_support = version_string in self.FULL_SUPPORT_VERSIONS

        if version_string in self.FULL_SUPPORT_VERSIONS:
            # R24+ (AC1024, AC1027, AC1032)
            maintenance = self._read_byte(data, self.OFFSET_MAINTENANCE_R24)
            preview_addr = self._read_uint32(data, self.OFFSET_PREVIEW_ADDR_R24)
            codepage = self._read_uint16(data, self.OFFSET_CODEPAGE_R24)
        elif version_string == "AC1021":
            # R21 (AutoCAD 2007-2009)
            maintenance = self._read_byte(data, self.OFFSET_MAINTENANCE_R21)
            preview_addr = self._read_uint32(data, self.OFFSET_PREVIEW_ADDR_R21)
            codepage = self._read_uint16(data, self.OFFSET_CODEPAGE_R21)
        elif version_string == "AC1018":
            # R18 (AutoCAD 2004-2006)
            maintenance = self._read_byte(data, self.OFFSET_MAINTENANCE_R18)
            preview_addr = self._read_uint32(data, self.OFFSET_PREVIEW_ADDR_R18)
            codepage = self._read_uint16(data, self.OFFSET_CODEPAGE_R18)
        elif version_string == "AC1015":
            # R15 (AutoCAD 2000-2002)
            maintenance = self._read_byte(data, self.OFFSET_MAINTENANCE_R15)
            preview_addr = self._read_uint32(data, self.OFFSET_PREVIEW_ADDR_R15)
            codepage = self._read_uint16(data, self.OFFSET_CODEPAGE_R15)
        elif version_string in ["AC1012", "AC1014"]:
            # R13-R14 (simpler structure)
            maintenance = self._read_byte(data, self.OFFSET_MAINTENANCE_R13)
            preview_addr = self._read_uint32(data, self.OFFSET_PREVIEW_ADDR_R13)
            codepage = self._read_uint16(data, self.OFFSET_CODEPAGE_R13)
        else:
            # Fallback for unknown versions
            maintenance = 0
            preview_addr = 0
            codepage = 0

        return HeaderAnalysis(
            version_string=version_string,
            version_name=self.DWG_VERSIONS.get(version_string, "Unknown"),
            maintenance_version=maintenance,
            preview_address=preview_addr,
            codepage=codepage,
            is_supported=is_full_support,
        )

    def _read_byte(self, data: bytes, offset: int) -> int:
        """Read unsigned byte from data at offset."""
        if offset >= len(data):
            raise ParseError(
                f"Cannot read byte at offset 0x{offset:X}: insufficient data "
                f"(file size: {len(data)} bytes)",
                offset=offset
            )
        return struct.unpack_from("B", data, offset)[0]

    def _read_uint16(self, data: bytes, offset: int) -> int:
        """Read little-endian unsigned 16-bit integer from data at offset."""
        if offset + 2 > len(data):
            raise ParseError(
                f"Cannot read uint16 at offset 0x{offset:X}: insufficient data "
                f"(file size: {len(data)} bytes, need {offset + 2} bytes)",
                offset=offset
            )
        return struct.unpack_from("<H", data, offset)[0]

    def _read_uint32(self, data: bytes, offset: int) -> int:
        """Read little-endian unsigned 32-bit integer from data at offset."""
        if offset + 4 > len(data):
            raise ParseError(
                f"Cannot read uint32 at offset 0x{offset:X}: insufficient data "
                f"(file size: {len(data)} bytes, need {offset + 4} bytes)",
                offset=offset
            )
        return struct.unpack_from("<I", data, offset)[0]

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
        """Validate that version is supported.

        Args:
            version_string: Version string to validate
            file_path: Path to file for error context

        Raises:
            UnsupportedVersionError: If version is too old (R10/R11-R12) or unknown
        """
        if version_string in self.UNSUPPORTED_VERSIONS:
            version_name = self.DWG_VERSIONS.get(version_string, "Unknown version")
            raise UnsupportedVersionError(
                version=version_string,
                version_name=version_name,
                file_path=file_path,
            )

        if version_string not in self.SUPPORTED_VERSIONS:
            # Unknown version - still raise error
            raise UnsupportedVersionError(
                version=version_string,
                version_name="Unknown version",
                file_path=file_path,
            )

    def get_crc_offset(self, version_string: str) -> Optional[int]:
        """Get CRC offset for a specific version.

        Args:
            version_string: DWG version string

        Returns:
            CRC offset in bytes, or None if CRC not available for this version
        """
        if version_string in self.FULL_SUPPORT_VERSIONS:
            return self.OFFSET_CRC32_R24
        elif version_string == "AC1021":
            return self.OFFSET_CRC32_R21
        elif version_string == "AC1018":
            return self.OFFSET_CRC32_R18
        elif version_string == "AC1015":
            return self.OFFSET_CRC32_R15
        else:
            # R13-R14 don't have reliable CRC in the same location
            return None

    def has_full_support(self, version_string: str) -> bool:
        """Check if version has full analysis support.

        Args:
            version_string: DWG version string

        Returns:
            True if version has full CRC and TrustedDWG support
        """
        return version_string in self.FULL_SUPPORT_VERSIONS

    def has_crc_support(self, version_string: str) -> bool:
        """Check if version supports CRC validation.

        Args:
            version_string: DWG version string

        Returns:
            True if version supports CRC validation
        """
        return self.get_crc_offset(version_string) is not None

    def has_watermark_support(self, version_string: str) -> bool:
        """Check if version supports TrustedDWG watermark.

        TrustedDWG was introduced in AutoCAD 2007 (AC1021).

        Args:
            version_string: DWG version string

        Returns:
            True if version supports TrustedDWG watermark
        """
        # TrustedDWG available from AC1021 onwards
        watermark_versions = ["AC1021", "AC1024", "AC1027", "AC1032"]
        return version_string in watermark_versions
