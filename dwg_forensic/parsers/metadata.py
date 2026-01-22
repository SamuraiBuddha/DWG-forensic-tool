"""Forensic metadata extraction from DWG files.

This module extracts forensic-relevant metadata from DWG files WITHOUT requiring
full decompression. It works by directly parsing:
- Header information (version, codepage, app version)
- AppInfo section (application fingerprints, version strings)
- TrustedDWG watermarks
- Section markers (DATA_PAGE, PAGE_MAP)

Supported versions: AC1015 (R15/2000) through AC1032 (R2018+)
"""

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union


# Page marker constants for R2004+ files
PAGE_MAP_MARKER = 0x41630E3B
DATA_PAGE_MARKER = 0x4163003B


@dataclass
class AppInfoMetadata:
    """Application information from DWG AppInfo section."""

    # Application version string (e.g., "22.0.48.M.294")
    version_string: Optional[str] = None

    # Build version (extracted from XML if present)
    build_version: Optional[str] = None

    # Product name (e.g., "AutoCAD 2018", "Civil 3D 2025")
    product_name: Optional[str] = None

    # Registry version
    registry_version: Optional[str] = None

    # Offset where AppInfo was found
    offset: int = 0


@dataclass
class TrustedDWGInfo:
    """TrustedDWG watermark information."""

    # Whether file has TrustedDWG watermark
    is_trusted: bool = False

    # Full message text
    message: Optional[str] = None

    # Whether saved by Autodesk application
    autodesk_app: bool = False

    # Offset where marker was found
    offset: int = 0


@dataclass
class PageMarkerInfo:
    """Information about a page marker (DATA_PAGE or PAGE_MAP)."""

    marker_type: str  # "DATA_PAGE" or "PAGE_MAP"
    offset: int
    decompressed_size: int
    compressed_size: int
    compression_type: int
    checksum: int


@dataclass
class ForensicMetadata:
    """Complete forensic metadata extracted from a DWG file."""

    # File information
    file_path: Optional[str] = None
    file_size: int = 0

    # Version information from header
    version_string: str = ""  # e.g., "AC1032"
    maintenance_version: int = 0
    app_version: int = 0
    codepage: int = 0

    # R2007+ specific
    encrypted_header: bool = False
    security_flags: int = 0

    # Header offsets
    preview_address: int = 0
    summary_info_address: int = 0
    vba_project_address: int = 0

    # R2007+ section info from header
    section_map_address: int = 0  # Actually points to AppInfo
    section_page_id: int = 0

    # Extracted metadata
    app_info: Optional[AppInfoMetadata] = None
    trusted_dwg: Optional[TrustedDWGInfo] = None

    # Page markers found
    page_markers: list = field(default_factory=list)

    # Extraction warnings/notes
    warnings: list = field(default_factory=list)


class ForensicMetadataExtractor:
    """Extract forensic metadata from DWG files without full decompression.

    This extractor focuses on metadata that can be extracted from:
    1. The file header (0x00-0x7F)
    2. The AppInfo section (address from header 0x30 for R2007+)
    3. Page markers near the end of file

    It does NOT require decompressing the actual DWG object data.
    """

    # AppInfo section magic header (first 32 bytes, encrypted/obfuscated)
    APPINFO_MAGIC = bytes([
        0x53, 0xDE, 0x38, 0x1D, 0xEC, 0x43, 0x21, 0xCA,
        0x96, 0x19, 0xE1, 0xE2, 0x17, 0x1A, 0x2A, 0x67,
        0x3B, 0xD9, 0x7F, 0xF7, 0x3C, 0xBB, 0xCE, 0x08,
        0xA0, 0x53, 0xD8, 0xED, 0xD2, 0x8D, 0xC5, 0xC7,
    ])

    def __init__(self, data: bytes):
        """Initialize extractor with file data."""
        self.data = data
        self._result = ForensicMetadata(file_size=len(data))

    def extract(self) -> ForensicMetadata:
        """Extract all forensic metadata from the file."""
        self._parse_header()
        self._find_app_info()
        self._find_trusted_dwg()
        self._find_page_markers()
        return self._result

    def _parse_header(self) -> None:
        """Parse the DWG file header."""
        if len(self.data) < 0x80:
            self._result.warnings.append("File too small for header")
            return

        # Version string (first 6 bytes)
        self._result.version_string = self.data[:6].decode('ascii', errors='ignore')

        # Standard header fields (common to all versions)
        self._result.maintenance_version = self.data[0x0B]
        self._result.preview_address = struct.unpack_from("<I", self.data, 0x0D)[0]
        self._result.app_version = self.data[0x11]
        self._result.codepage = struct.unpack_from("<H", self.data, 0x13)[0]

        # R2004+ specific fields
        if self._result.version_string >= "AC1018":
            if len(self.data) >= 0x30:
                self._result.security_flags = struct.unpack_from("<I", self.data, 0x18)[0]

            # Check for encrypted header section
            if len(self.data) >= 0x100:
                # The header at 0x80-0xFF is typically encrypted
                self._result.encrypted_header = True

            # R2007+ section info from header (0x2C-0x4C)
            if len(self.data) >= 0x40:
                self._result.section_page_id = struct.unpack_from("<I", self.data, 0x2C)[0]
                self._result.section_map_address = struct.unpack_from("<I", self.data, 0x30)[0]

        # R2000/R2002 fields
        if self._result.version_string in ("AC1014", "AC1015"):
            if len(self.data) >= 0x24:
                self._result.summary_info_address = struct.unpack_from("<I", self.data, 0x20)[0]

    def _find_app_info(self) -> None:
        """Find and parse AppInfo section."""
        if self._result.version_string < "AC1018":
            # AppInfo not available in older formats
            return

        # Try header-indicated address first
        addr = self._result.section_map_address
        if addr > 0 and addr + 64 < len(self.data):
            # Check for AppInfo magic
            if self.data[addr:addr + 32] == self.APPINFO_MAGIC:
                self._parse_app_info_at(addr)
                return

        # Search for AppInfoDataList marker (UTF-16LE)
        marker = b'A\x00p\x00p\x00I\x00n\x00f\x00o\x00D\x00a\x00t\x00a\x00L\x00i\x00s\x00t\x00'
        pos = self.data.find(marker)
        if pos >= 0:
            # AppInfo starts 32 bytes before the marker (magic header)
            app_info_start = max(0, pos - 64)
            self._parse_app_info_at(app_info_start, marker_pos=pos)

    def _parse_app_info_at(self, offset: int, marker_pos: int = 0) -> None:
        """Parse AppInfo section at given offset."""
        app_info = AppInfoMetadata(offset=offset)

        # Search for version strings in the region
        search_start = offset
        search_end = min(offset + 2000, len(self.data))
        region = self.data[search_start:search_end]

        # Look for version pattern in UTF-16LE (e.g., "22.0.48.M.294")
        # Pattern: digits.digit.digits[.optional][.optional]
        version_patterns = [
            # Major.Minor.Patch.Letter.Build (e.g., "22.0.48.M.294")
            rb'(\d)\x00(\d)\x00\.\x00(\d)\x00\.\x00(\d)\x00(\d)*\x00\.\x00([A-Z])\x00\.\x00(\d)+',
            # Major.Minor.Patch.Patch.Patch (e.g., "24.0.46.0.101")
            rb'(\d)\x00(\d)\x00\.\x00(\d)\x00\.\x00(\d)\x00(\d)*\x00\.\x00(\d)\x00\.\x00(\d)+',
            # Simpler: Major.Minor.Patch.Build (e.g., "17.1.43.300")
            rb'(\d)\x00(\d)\x00\.\x00(\d)\x00\.\x00(\d)\x00(\d)*\x00\.\x00(\d)+',
        ]

        for pattern in version_patterns:
            for match in re.finditer(pattern, region):
                # Extract and decode the version string
                start = match.start()
                # Read forward to get the complete version string
                end = min(start + 60, len(region))
                ver_bytes = region[start:end]
                try:
                    ver = ver_bytes.decode('utf-16-le', errors='ignore')
                    # Clean up - extract only version characters
                    clean = ""
                    for c in ver:
                        if c.isdigit() or c in '.M':
                            clean += c
                        elif len(clean) > 5:
                            # Stop at first non-version char after getting some digits
                            break
                    # Validate it looks like a version (has multiple dots)
                    if clean and clean.count('.') >= 2 and len(clean) >= 7:
                        app_info.version_string = clean
                        break
                except (UnicodeDecodeError, ValueError):
                    continue
            if app_info.version_string:
                break

        # Look for product name (e.g., "AutoCAD 2018")
        product_patterns = [
            (b'A\x00u\x00t\x00o\x00C\x00A\x00D\x00 \x00\x32\x00', 'AutoCAD'),  # "AutoCAD 2"
            (b'C\x00i\x00v\x00i\x00l\x00 \x003\x00D\x00', 'Civil 3D'),
            (b'R\x00e\x00v\x00i\x00t\x00', 'Revit'),
        ]

        for pattern, product_type in product_patterns:
            idx = region.find(pattern)
            if idx >= 0:
                # Read the full product name
                end = min(idx + 50, len(region))
                name_bytes = region[idx:end]
                try:
                    name = name_bytes.decode('utf-16-le', errors='ignore')
                    # Clean up - extract just product name with year
                    clean = ""
                    for c in name:
                        if ord(c) < 32:
                            break
                        # Stop at XML or special characters
                        if c in '<>"\\':
                            break
                        if ord(c) < 128:
                            clean += c
                    if clean:
                        # Trim trailing whitespace and common suffixes
                        clean = clean.strip()
                        # Keep just "AutoCAD 2018" or "Civil 3D 2025"
                        parts = clean.split('<')[0].split('"')[0].strip()
                        if parts:
                            app_info.product_name = parts[:40]
                            break
                except (UnicodeDecodeError, ValueError):
                    continue

        # Look for build_version in XML format (AutoCAD\s+build_version=\"...)
        xml_pattern = rb'build_version=\\"([^"\\]+)'
        match = re.search(xml_pattern, region)
        if match:
            try:
                app_info.build_version = match.group(1).decode('utf-8', errors='ignore')
            except (UnicodeDecodeError, ValueError):
                pass

        self._result.app_info = app_info

    def _find_trusted_dwg(self) -> None:
        """Find and parse TrustedDWG watermark."""
        # Search for "Trusted DWG" in UTF-16LE
        marker = b'T\x00r\x00u\x00s\x00t\x00e\x00d\x00 \x00D\x00W\x00G\x00'
        pos = self.data.find(marker)

        if pos < 0:
            self._result.trusted_dwg = TrustedDWGInfo(is_trusted=False)
            return

        trusted = TrustedDWGInfo(is_trusted=True, offset=pos)

        # Extract the full message
        end = min(pos + 400, len(self.data))
        msg_bytes = self.data[pos:end]
        try:
            msg = msg_bytes.decode('utf-16-le', errors='ignore')
            # Clean up - find end of message
            clean = ""
            for c in msg:
                if ord(c) < 32 and c not in '\t\n\r':
                    break
                if ord(c) < 128:
                    clean += c
            trusted.message = clean[:200] if clean else None
        except (UnicodeDecodeError, ValueError):
            pass

        # Check for Autodesk application mention
        if trusted.message:
            trusted.autodesk_app = "Autodesk" in trusted.message

        self._result.trusted_dwg = trusted

    def _find_page_markers(self) -> None:
        """Find DATA_PAGE and PAGE_MAP markers in the file."""
        if self._result.version_string < "AC1018":
            # Page markers not used in older formats
            return

        # Scan for markers (typically near end of file for R2007+)
        # Start scanning from 0x100 to skip header
        for i in range(0x100, len(self.data) - 32, 4):
            marker = struct.unpack_from("<I", self.data, i)[0]

            if marker == DATA_PAGE_MARKER or marker == PAGE_MAP_MARKER:
                decomp = struct.unpack_from("<I", self.data, i + 4)[0]
                comp = struct.unpack_from("<I", self.data, i + 8)[0]
                comp_type = struct.unpack_from("<I", self.data, i + 12)[0]
                checksum = struct.unpack_from("<I", self.data, i + 16)[0]

                marker_info = PageMarkerInfo(
                    marker_type="PAGE_MAP" if marker == PAGE_MAP_MARKER else "DATA_PAGE",
                    offset=i,
                    decompressed_size=decomp,
                    compressed_size=comp,
                    compression_type=comp_type,
                    checksum=checksum,
                )
                self._result.page_markers.append(marker_info)


def extract_forensic_metadata(
    source: Union[str, Path, bytes]
) -> ForensicMetadata:
    """Extract forensic metadata from a DWG file.

    Args:
        source: File path or bytes data

    Returns:
        ForensicMetadata with extracted information

    This function extracts metadata WITHOUT decompressing the full DWG
    object data, making it fast and reliable for forensic analysis.
    """
    if isinstance(source, (str, Path)):
        path = Path(source)
        with open(path, "rb") as f:
            data = f.read()
        result = ForensicMetadataExtractor(data).extract()
        result.file_path = str(path)
    else:
        data = source
        result = ForensicMetadataExtractor(data).extract()

    return result


def format_forensic_report(metadata: ForensicMetadata) -> str:
    """Format forensic metadata as a human-readable report."""
    lines = []

    lines.append("=" * 70)
    lines.append("DWG FORENSIC METADATA REPORT")
    lines.append("=" * 70)

    if metadata.file_path:
        lines.append(f"File: {metadata.file_path}")
    lines.append(f"Size: {metadata.file_size:,} bytes")
    lines.append("")

    lines.append("HEADER INFORMATION")
    lines.append("-" * 40)
    lines.append(f"  Version: {metadata.version_string}")
    lines.append(f"  Maintenance version: {metadata.maintenance_version}")
    lines.append(f"  App version: {metadata.app_version}")
    lines.append(f"  Codepage: {metadata.codepage}")
    if metadata.encrypted_header:
        lines.append(f"  Security flags: 0x{metadata.security_flags:08X}")
    lines.append("")

    if metadata.app_info:
        lines.append("APPLICATION INFO")
        lines.append("-" * 40)
        if metadata.app_info.version_string:
            lines.append(f"  Version string: {metadata.app_info.version_string}")
        if metadata.app_info.product_name:
            lines.append(f"  Product: {metadata.app_info.product_name}")
        if metadata.app_info.build_version:
            lines.append(f"  Build version: {metadata.app_info.build_version}")
        lines.append(f"  AppInfo offset: 0x{metadata.app_info.offset:05X}")
        lines.append("")

    if metadata.trusted_dwg:
        lines.append("TRUSTED DWG WATERMARK")
        lines.append("-" * 40)
        if metadata.trusted_dwg.is_trusted:
            lines.append("  [OK] TrustedDWG watermark present")
            if metadata.trusted_dwg.autodesk_app:
                lines.append("  [OK] Saved by Autodesk application")
            if metadata.trusted_dwg.message:
                # Wrap long messages
                msg = metadata.trusted_dwg.message
                if len(msg) > 60:
                    msg = msg[:60] + "..."
                lines.append(f"  Message: {msg}")
        else:
            lines.append("  [!] No TrustedDWG watermark found")
        lines.append("")

    if metadata.page_markers:
        lines.append("PAGE MARKERS")
        lines.append("-" * 40)
        for pm in metadata.page_markers[:10]:  # Limit to first 10
            lines.append(
                f"  0x{pm.offset:05X}: {pm.marker_type} "
                f"decomp={pm.decompressed_size}, comp={pm.compressed_size}"
            )
        if len(metadata.page_markers) > 10:
            lines.append(f"  ... and {len(metadata.page_markers) - 10} more")
        lines.append("")

    if metadata.warnings:
        lines.append("WARNINGS")
        lines.append("-" * 40)
        for w in metadata.warnings:
            lines.append(f"  [WARN] {w}")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)
