"""
DWG Section Map Parser for Deep Forensic Analysis.

Parses the R18+ (AC1024+) section map to locate all file sections
for deeper analysis. Section map is critical for locating:
- AcDb:Header (drawing variables including timestamps)
- AcDb:Classes (class definitions)
- AcDb:Handles (object handle map for gap analysis)
- AcDb:Objects (main object stream)
- AcDb:AppInfo (application information)
- AcDb:FileDepList (external file dependencies)

References:
- OpenDesign Specification
- LibreDWG source code (decode_r2004.c, decode_r2007.c)
"""

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from enum import IntEnum

from .compression import (
    DWGDecompressor,
    DecompressionError,
    decompress_section,
    PageHeader,
)
from .encryption import (
    is_encrypted_header,
    decrypt_header,
    get_section_locator_offset,
    prepare_file_data,
)


class SectionType(IntEnum):
    """DWG Section Types (R18+)."""
    UNKNOWN = 0x00
    HEADER = 0x01  # AcDb:Header - Drawing variables
    CLASSES = 0x02  # AcDb:Classes - Class definitions
    HANDLES = 0x03  # AcDb:Handles - Object handle map
    OBJECTS = 0x04  # AcDb:ObjFreeSpace
    TEMPLATE = 0x05  # AcDb:Template
    AUXHEADER = 0x06  # AcDb:AuxHeader - Auxiliary header
    PREVIEW = 0x07  # AcDb:Preview - Thumbnail
    APPINFO = 0x08  # AcDb:AppInfo - Application info
    APPINFOHISTORY = 0x09  # AcDb:AppInfoHistory
    FILEDEPLIST = 0x0A  # AcDb:FileDepList - External dependencies
    SECURITY = 0x0B  # AcDb:Security - Digital signature
    VBAPROJECT = 0x0C  # AcDb:VBAProject - VBA macros
    SIGNATURE = 0x0D  # AcDb:Signature - TrustedDWG signature
    ACDS = 0x0E  # AcDs data
    SUMMARYINFO = 0x0F  # Summary Info stream


# Section type names for display
SECTION_NAMES = {
    SectionType.HEADER: "AcDb:Header",
    SectionType.CLASSES: "AcDb:Classes",
    SectionType.HANDLES: "AcDb:Handles",
    SectionType.OBJECTS: "AcDb:ObjFreeSpace",
    SectionType.TEMPLATE: "AcDb:Template",
    SectionType.AUXHEADER: "AcDb:AuxHeader",
    SectionType.PREVIEW: "AcDb:Preview",
    SectionType.APPINFO: "AcDb:AppInfo",
    SectionType.APPINFOHISTORY: "AcDb:AppInfoHistory",
    SectionType.FILEDEPLIST: "AcDb:FileDepList",
    SectionType.SECURITY: "AcDb:Security",
    SectionType.VBAPROJECT: "AcDb:VBAProject",
    SectionType.SIGNATURE: "AcDb:Signature",
    SectionType.ACDS: "AcDs",
    SectionType.SUMMARYINFO: "SummaryInfo",
}


@dataclass
class SectionInfo:
    """Information about a DWG file section."""
    section_type: int
    section_name: str
    compressed_size: int
    decompressed_size: int
    offset: int
    page_count: int = 1
    compression_type: int = 0  # 0=none, 2=compressed
    data_offset: int = 0  # Offset to actual data within section
    encrypted: bool = False  # Whether section data is encrypted


@dataclass
class SectionMapResult:
    """Result of section map parsing."""
    sections: Dict[int, SectionInfo] = field(default_factory=dict)
    section_map_offset: int = 0
    section_count: int = 0
    file_version: str = ""
    was_encrypted: bool = False
    parsing_errors: List[str] = field(default_factory=list)

    def has_section(self, section_type: SectionType) -> bool:
        """Check if a section exists."""
        return section_type in self.sections

    def get_section(self, section_type: SectionType) -> Optional[SectionInfo]:
        """Get section info by type."""
        return self.sections.get(section_type)


class SectionMapParser:
    """
    Parser for DWG Section Map (R18+ / AC1024+).

    The section map is located via an address stored in the file header
    and contains entries for all sections in the file.

    Key Forensic Uses:
    - Locate Header section for timestamp extraction
    - Locate Handles section for handle gap analysis
    - Identify missing or unexpected sections
    - Detect section size anomalies
    """

    # R2004+ (AC1018) section page type markers
    SECTION_PAGE_MAP = 0x41630E3B  # "System Section Page Map" marker
    SECTION_DATA_PAGE = 0x4163003B  # Data page marker

    # Minimum file size to have valid sections
    MIN_FILE_SIZE = 0x100

    # Section locator offsets by version
    VERSION_LOCATOR_OFFSETS = {
        "AC1018": 0x20,  # R2004
        "AC1021": 0x20,  # R2007 (after decryption)
        "AC1024": 0x20,  # R2010
        "AC1027": 0x20,  # R2013
        "AC1032": 0x80,  # R2018+ (after decryption)
    }

    # Section map address offset within locator structure
    SECTION_MAP_ADDR_OFFSET = 0x14  # 20 bytes into locator

    def __init__(self):
        """Initialize section map parser."""
        self._decompressor = DWGDecompressor()

    def parse(self, file_path: Path) -> SectionMapResult:
        """
        Parse section map from DWG file.

        Args:
            file_path: Path to DWG file

        Returns:
            SectionMapResult with all located sections
        """
        file_path = Path(file_path)
        result = SectionMapResult()

        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            result.parsing_errors.append(f"Failed to read file: {e}")
            return result

        return self.parse_from_bytes(data, result)

    def parse_from_bytes(
        self,
        data: bytes,
        result: Optional[SectionMapResult] = None
    ) -> SectionMapResult:
        """
        Parse section map from raw bytes.

        Args:
            data: Raw file bytes
            result: Optional existing result to populate

        Returns:
            SectionMapResult with all located sections
        """
        if result is None:
            result = SectionMapResult()

        if len(data) < self.MIN_FILE_SIZE:
            result.parsing_errors.append("File too small for section analysis")
            return result

        # Get version and decrypt if needed
        try:
            prepared_data, version, was_encrypted = prepare_file_data(data)
            result.file_version = version
            result.was_encrypted = was_encrypted
        except Exception as e:
            result.parsing_errors.append(f"Failed to prepare file data: {e}")
            # Try to get version anyway
            try:
                result.file_version = data[0:6].decode("ascii").rstrip("\x00")
            except UnicodeDecodeError:
                result.parsing_errors.append("Invalid version string")
                return result
            prepared_data = data

        # Different parsing based on version
        if result.file_version in ["AC1024", "AC1027", "AC1032"]:
            self._parse_r2010_sections(prepared_data, data, result)
        elif result.file_version in ["AC1018", "AC1021"]:
            self._parse_r2004_sections(prepared_data, data, result)
        else:
            result.parsing_errors.append(
                f"Section map parsing not supported for {result.file_version}"
            )

        return result

    def _get_section_locator_offset(self, version: str) -> int:
        """Get section locator offset for version."""
        return self.VERSION_LOCATOR_OFFSETS.get(version, 0x20)

    def _parse_r2010_sections(
        self,
        prepared_data: bytes,
        original_data: bytes,
        result: SectionMapResult
    ) -> None:
        """
        Parse section map for R2010+ (AC1024, AC1027, AC1032).

        The section locator record contains:
        - Section page map record number (RL at +0x00)
        - Section page map size (RL at +0x04)
        - Page count (RL at +0x08)
        - Section maximum size (RL at +0x0C)
        - Unknown (RL at +0x10)
        - Section page map address (RL at +0x14)
        """
        try:
            # Get version-specific locator offset
            locator_base = self._get_section_locator_offset(result.file_version)

            if len(prepared_data) < locator_base + 0x20:
                result.parsing_errors.append(
                    f"File too small for section locator at 0x{locator_base:X}"
                )
                return

            # Read section locator structure
            section_record_num = struct.unpack_from("<I", prepared_data, locator_base + 0x00)[0]
            section_size_encoded = struct.unpack_from("<I", prepared_data, locator_base + 0x04)[0]
            page_count = struct.unpack_from("<I", prepared_data, locator_base + 0x08)[0]
            max_section_size = struct.unpack_from("<I", prepared_data, locator_base + 0x0C)[0]
            unknown = struct.unpack_from("<I", prepared_data, locator_base + 0x10)[0]
            section_map_addr = struct.unpack_from("<I", prepared_data, locator_base + 0x14)[0]

            result.section_map_offset = section_map_addr

            # Validate section map address
            if section_map_addr == 0:
                result.parsing_errors.append("Section map address is zero")
                return

            if section_map_addr >= len(original_data):
                result.parsing_errors.append(
                    f"Section map address 0x{section_map_addr:X} exceeds file size {len(original_data)}"
                )
                return

            # Parse section page map from original (unencrypted for body) data
            self._parse_section_pages(original_data, section_map_addr, result)

        except Exception as e:
            result.parsing_errors.append(f"Error parsing R2010 sections: {e}")

    def _parse_r2004_sections(
        self,
        prepared_data: bytes,
        original_data: bytes,
        result: SectionMapResult
    ) -> None:
        """
        Parse section map for R2004-2009 (AC1018, AC1021).

        Similar structure to R2010 but R2007 has encrypted header.
        """
        try:
            locator_base = self._get_section_locator_offset(result.file_version)

            if len(prepared_data) < locator_base + 0x20:
                result.parsing_errors.append("File too small for section locator")
                return

            # Read section map address
            section_map_addr = struct.unpack_from("<I", prepared_data, locator_base + 0x14)[0]

            if section_map_addr > 0 and section_map_addr < len(original_data):
                result.section_map_offset = section_map_addr
                self._parse_section_pages(original_data, section_map_addr, result)
            else:
                result.parsing_errors.append(
                    f"Invalid section map address: 0x{section_map_addr:X}"
                )

        except Exception as e:
            result.parsing_errors.append(f"Error parsing R2004 sections: {e}")

    def _parse_section_pages(
        self,
        data: bytes,
        map_offset: int,
        result: SectionMapResult
    ) -> None:
        """
        Parse section page entries from section map.

        The section map is a compressed page containing section descriptors.
        Each descriptor includes section type, sizes, and page locations.
        """
        try:
            # First, check if there's a page header at this location
            if map_offset + 32 > len(data):
                result.parsing_errors.append("Section map offset too close to end of file")
                return

            # Check for page header marker
            page_marker = struct.unpack_from("<I", data, map_offset)[0]

            if page_marker == self.SECTION_PAGE_MAP:
                # This is a section page map - parse the page header
                self._parse_section_page_map(data, map_offset, result)
            elif page_marker == self.SECTION_DATA_PAGE:
                # Data page - might need different parsing
                self._parse_section_page_map(data, map_offset, result)
            else:
                # No recognizable marker - try heuristic scanning
                self._parse_sections_heuristic(data, map_offset, result)

        except Exception as e:
            result.parsing_errors.append(f"Error parsing section pages: {e}")

    def _parse_section_page_map(
        self,
        data: bytes,
        page_offset: int,
        result: SectionMapResult
    ) -> None:
        """
        Parse a section page map page.

        Page structure:
        - Page header (32 bytes)
        - Section descriptors (variable)
        """
        try:
            # Parse page header
            header = PageHeader.from_bytes(data, page_offset)

            # Skip page header
            content_offset = page_offset + 32

            # Get page content
            if header.compression_type == 2:
                # Compressed - decompress
                compressed_data = data[content_offset:content_offset + header.compressed_size]
                try:
                    page_content = decompress_section(
                        compressed_data,
                        header.decompressed_size
                    )
                except DecompressionError as e:
                    result.parsing_errors.append(f"Failed to decompress section map: {e}")
                    # Fall back to heuristic
                    self._parse_sections_heuristic(data, page_offset, result)
                    return
            else:
                # Not compressed
                page_content = data[content_offset:content_offset + header.decompressed_size]

            # Parse section descriptors from decompressed content
            self._parse_section_descriptors(page_content, data, result)

        except DecompressionError as e:
            result.parsing_errors.append(f"Decompression error: {e}")
            self._parse_sections_heuristic(data, page_offset, result)
        except Exception as e:
            result.parsing_errors.append(f"Error parsing section page map: {e}")
            self._parse_sections_heuristic(data, page_offset, result)

    def _parse_section_descriptors(
        self,
        content: bytes,
        original_data: bytes,
        result: SectionMapResult
    ) -> None:
        """
        Parse section descriptors from decompressed section map content.

        Each section descriptor contains:
        - Section type (4 bytes)
        - Decompressed size (4 bytes)
        - Compressed size (4 bytes)
        - Compression type (4 bytes)
        - Section checksum (4 bytes)
        ... additional fields vary by section type
        """
        offset = 0
        max_sections = 20  # Safety limit

        while offset + 20 <= len(content) and len(result.sections) < max_sections:
            try:
                section_type = struct.unpack_from("<I", content, offset)[0]

                # Check if this is a valid section type
                if section_type == 0 or section_type > 0x20:
                    # End of descriptors or invalid
                    offset += 4
                    continue

                # Read descriptor fields
                decompressed_size = struct.unpack_from("<I", content, offset + 4)[0]
                compressed_size = struct.unpack_from("<I", content, offset + 8)[0]
                compression_type = struct.unpack_from("<I", content, offset + 12)[0]
                section_checksum = struct.unpack_from("<I", content, offset + 16)[0]

                # Validate sizes
                if decompressed_size > len(original_data) * 4:
                    offset += 4
                    continue

                if compressed_size > len(original_data):
                    offset += 4
                    continue

                # Create section info
                section_info = SectionInfo(
                    section_type=section_type,
                    section_name=SECTION_NAMES.get(section_type, f"Unknown_{section_type}"),
                    compressed_size=compressed_size,
                    decompressed_size=decompressed_size,
                    offset=offset,
                    compression_type=compression_type,
                    data_offset=0,  # Will be determined when reading section
                )

                result.sections[section_type] = section_info
                offset += 20  # Move to next descriptor

            except Exception:
                offset += 4
                continue

        result.section_count = len(result.sections)

    def _parse_sections_heuristic(
        self,
        data: bytes,
        start_offset: int,
        result: SectionMapResult
    ) -> None:
        """
        Fallback heuristic parsing when structured parsing fails.

        Scans for section type markers and attempts to identify sections.
        """
        max_scan = min(start_offset + 0x2000, len(data) - 20)
        scan_pos = start_offset
        found_sections = 0

        while scan_pos < max_scan and found_sections < 20:
            try:
                marker = struct.unpack_from("<I", data, scan_pos)[0]

                # Check if this looks like a valid section type
                if 1 <= marker <= 15:
                    section_type = marker

                    # Read potential section info
                    if scan_pos + 24 <= len(data):
                        size1 = struct.unpack_from("<I", data, scan_pos + 4)[0]
                        size2 = struct.unpack_from("<I", data, scan_pos + 8)[0]
                        data_offset = struct.unpack_from("<I", data, scan_pos + 12)[0]

                        # Validate sizes
                        if size1 < len(data) and size2 < len(data) * 2:
                            section_info = SectionInfo(
                                section_type=section_type,
                                section_name=SECTION_NAMES.get(
                                    section_type, f"Unknown_{section_type}"
                                ),
                                compressed_size=size1,
                                decompressed_size=size2,
                                offset=scan_pos,
                                data_offset=data_offset,
                            )

                            result.sections[section_type] = section_info
                            found_sections += 1

                scan_pos += 4

            except Exception:
                scan_pos += 4
                continue

        result.section_count = len(result.sections)

        if found_sections == 0:
            result.parsing_errors.append(
                "No sections found via heuristic scanning"
            )

    def read_section_data(
        self,
        file_path: Path,
        section_info: SectionInfo,
        decompress: bool = True
    ) -> Optional[bytes]:
        """
        Read and optionally decompress section data.

        Args:
            file_path: Path to DWG file
            section_info: Section info from parse()
            decompress: Whether to decompress data

        Returns:
            Section data bytes or None on error
        """
        try:
            with open(file_path, "rb") as f:
                f.seek(section_info.data_offset)
                data = f.read(section_info.compressed_size)

            if decompress and section_info.compression_type == 2:
                try:
                    data = decompress_section(
                        data,
                        section_info.decompressed_size,
                        validate=False
                    )
                except DecompressionError:
                    # Decompression failed, return raw data
                    pass

            return data

        except Exception:
            return None

    def read_section_data_from_bytes(
        self,
        data: bytes,
        section_info: SectionInfo,
        decompress: bool = True
    ) -> Optional[bytes]:
        """
        Read and optionally decompress section data from bytes.

        Args:
            data: Full file data
            section_info: Section info from parse()
            decompress: Whether to decompress data

        Returns:
            Section data bytes or None on error
        """
        try:
            if section_info.data_offset + section_info.compressed_size > len(data):
                return None

            section_data = data[
                section_info.data_offset:
                section_info.data_offset + section_info.compressed_size
            ]

            if decompress and section_info.compression_type == 2:
                try:
                    section_data = decompress_section(
                        section_data,
                        section_info.decompressed_size,
                        validate=False
                    )
                except DecompressionError:
                    pass

            return section_data

        except Exception:
            return None


def get_section_map(file_path: Path) -> SectionMapResult:
    """Convenience function to get section map from DWG file."""
    parser = SectionMapParser()
    return parser.parse(file_path)


def get_section_map_from_bytes(data: bytes) -> SectionMapResult:
    """Convenience function to get section map from bytes."""
    parser = SectionMapParser()
    return parser.parse_from_bytes(data)
