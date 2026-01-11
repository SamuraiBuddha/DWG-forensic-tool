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
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, List
from enum import IntEnum


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


@dataclass
class SectionMapResult:
    """Result of section map parsing."""
    sections: Dict[int, SectionInfo] = field(default_factory=dict)
    section_map_offset: int = 0
    section_count: int = 0
    file_version: str = ""
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

    # Header offset to section map address (R18+)
    # The section locator info starts at 0x20 in R2004+
    OFFSET_SECTION_LOCATOR = 0x20

    # R2004+ (AC1018) section page type
    SECTION_PAGE_MAP = 0x41630E3B  # "System Section Page Map" marker
    SECTION_DATA_PAGE = 0x4163003B  # Data page marker

    # Minimum file size to have valid sections
    MIN_FILE_SIZE = 0x100

    def __init__(self):
        """Initialize section map parser."""
        pass

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

        if len(data) < self.MIN_FILE_SIZE:
            result.parsing_errors.append("File too small for section analysis")
            return result

        # Get version
        try:
            result.file_version = data[0:6].decode("ascii").rstrip("\x00")
        except UnicodeDecodeError:
            result.parsing_errors.append("Invalid version string")
            return result

        # Different parsing based on version
        if result.file_version in ["AC1024", "AC1027", "AC1032"]:
            self._parse_r2010_sections(data, result)
        elif result.file_version in ["AC1018", "AC1021"]:
            self._parse_r2004_sections(data, result)
        else:
            result.parsing_errors.append(
                f"Section map parsing not supported for {result.file_version}"
            )

        return result

    def _parse_r2010_sections(self, data: bytes, result: SectionMapResult) -> None:
        """
        Parse section map for R2010+ (AC1024, AC1027, AC1032).

        The section locator record at offset 0x20 contains:
        - Section page map record number (RL)
        - Section page map size (RL)
        - Page count (RL)
        - Section maximum size (RL)
        - Unknown (RL)
        - Section page map address (RL)
        """
        try:
            # Read section locator info at 0x20
            if len(data) < 0x40:
                result.parsing_errors.append("File too small for section locator")
                return

            # Section locator structure (R2010+)
            # Offset 0x20: Section page map info
            section_record_num = struct.unpack_from("<I", data, 0x20)[0]
            section_size_encoded = struct.unpack_from("<I", data, 0x24)[0]
            page_count = struct.unpack_from("<I", data, 0x28)[0]
            max_section_size = struct.unpack_from("<I", data, 0x2C)[0]
            unknown = struct.unpack_from("<I", data, 0x30)[0]
            section_map_addr = struct.unpack_from("<I", data, 0x34)[0]

            result.section_map_offset = section_map_addr

            if section_map_addr == 0 or section_map_addr >= len(data):
                result.parsing_errors.append(
                    f"Invalid section map address: 0x{section_map_addr:X}"
                )
                return

            # Parse section page map
            self._parse_section_pages(data, section_map_addr, result)

        except Exception as e:
            result.parsing_errors.append(f"Error parsing R2010 sections: {e}")

    def _parse_r2004_sections(self, data: bytes, result: SectionMapResult) -> None:
        """
        Parse section map for R2004-2009 (AC1018, AC1021).

        Similar structure to R2010 but with some offset differences.
        """
        try:
            # R2004 has encrypted section locator - more complex
            # For now, try similar approach to R2010
            if len(data) < 0x40:
                result.parsing_errors.append("File too small for section locator")
                return

            # Try to locate section map via file scan
            # R2004+ files have recognizable page markers
            section_map_addr = struct.unpack_from("<I", data, 0x34)[0]

            if section_map_addr > 0 and section_map_addr < len(data):
                result.section_map_offset = section_map_addr
                self._parse_section_pages(data, section_map_addr, result)
            else:
                result.parsing_errors.append("Could not locate section map (R2004)")

        except Exception as e:
            result.parsing_errors.append(f"Error parsing R2004 sections: {e}")

    def _parse_section_pages(
        self, data: bytes, map_offset: int, result: SectionMapResult
    ) -> None:
        """
        Parse section page entries from section map.

        Each section in the map has:
        - Section type (int)
        - Data size (int)
        - Page count (int)
        - Max decompressed size per page (int)
        - Compressed (bool)
        - Section ID (int)
        - Encrypted (bool)
        - Name (string)
        """
        try:
            offset = map_offset

            # Read number of sections
            if offset + 4 > len(data):
                return

            # Section map typically starts with page header
            # Look for recognizable section entries

            # Scan for section entries
            # Each section entry has a type marker and size info
            max_scan = min(offset + 0x2000, len(data) - 20)

            found_sections = 0
            scan_pos = offset

            while scan_pos < max_scan and found_sections < 20:
                # Try to identify section type markers
                try:
                    marker = struct.unpack_from("<I", data, scan_pos)[0]

                    # Check if this looks like a valid section type
                    if 1 <= marker <= 15:
                        # Potential section entry
                        section_type = marker

                        # Read section info
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
                    "No sections found - may need alternative parsing"
                )

        except Exception as e:
            result.parsing_errors.append(f"Error parsing section pages: {e}")

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
                    data = zlib.decompress(data)
                except zlib.error:
                    # May not be zlib-compressed, try as-is
                    pass

            return data

        except Exception:
            return None


def get_section_map(file_path: Path) -> SectionMapResult:
    """Convenience function to get section map from DWG file."""
    parser = SectionMapParser()
    return parser.parse(file_path)
