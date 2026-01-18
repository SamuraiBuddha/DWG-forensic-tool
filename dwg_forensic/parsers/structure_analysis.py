"""
DWG Structure Analysis - Detects non-standard or stripped DWG files.

This module identifies DWG files that lack standard internal sections,
which may indicate:
1. Non-AutoCAD creation (ODA SDK, LibreDWG, third-party tools)
2. Metadata stripping/sanitization
3. Corrupted or truncated files
4. Export from applications that don't write full DWG structure

Copyright (c) 2025. All rights reserved.
"""

import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class DWGStructureType(Enum):
    """Classification of DWG file structure."""
    STANDARD = "standard"           # Full AutoCAD structure with all sections
    MINIMAL = "minimal"             # Valid DWG but missing optional sections
    STRIPPED = "stripped"           # Appears to have had metadata removed
    NON_AUTOCAD = "non_autocad"     # Created by third-party tool
    CORRUPTED = "corrupted"         # Structure is damaged/invalid
    UNKNOWN = "unknown"             # Cannot determine structure type


@dataclass
class StructureAnalysisResult:
    """Results from DWG structure analysis."""

    structure_type: DWGStructureType = DWGStructureType.UNKNOWN
    confidence: float = 0.0  # 0.0 to 1.0

    # Section presence flags
    has_header_section: bool = False
    has_classes_section: bool = False
    has_handles_section: bool = False
    has_objects_section: bool = False
    has_appinfo_section: bool = False
    has_preview_section: bool = False

    # Structure metrics
    total_sections_expected: int = 6  # Standard DWG has 6+ sections
    total_sections_found: int = 0
    section_map_valid: bool = False
    acfs_header_valid: bool = False

    # Tool detection
    detected_tool: Optional[str] = None
    tool_signatures: List[str] = field(default_factory=list)

    # Forensic indicators
    forensic_notes: List[str] = field(default_factory=list)
    is_forensically_significant: bool = False

    # Raw data for further analysis
    section_map_address: int = 0
    acfs_offset: int = 0
    data_offset: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "structure_type": self.structure_type.value,
            "confidence": self.confidence,
            "sections": {
                "header": self.has_header_section,
                "classes": self.has_classes_section,
                "handles": self.has_handles_section,
                "objects": self.has_objects_section,
                "appinfo": self.has_appinfo_section,
                "preview": self.has_preview_section,
            },
            "metrics": {
                "expected_sections": self.total_sections_expected,
                "found_sections": self.total_sections_found,
                "section_map_valid": self.section_map_valid,
                "acfs_header_valid": self.acfs_header_valid,
            },
            "tool_detection": {
                "detected_tool": self.detected_tool,
                "signatures": self.tool_signatures,
            },
            "forensic": {
                "notes": self.forensic_notes,
                "is_significant": self.is_forensically_significant,
            },
            "offsets": {
                "section_map_address": hex(self.section_map_address),
                "acfs_offset": hex(self.acfs_offset),
                "data_offset": hex(self.data_offset),
            },
        }


class DWGStructureAnalyzer:
    """
    Analyzes DWG file structure to detect non-standard or stripped files.

    This is forensically significant because:
    - Standard AutoCAD files have predictable section structure
    - Missing sections may indicate tampering or metadata stripping
    - Third-party tools often create minimal/non-standard structures
    - The creation tool itself may be evidence in litigation
    """

    # Known tool signatures
    TOOL_SIGNATURES = {
        b"ODA": "Open Design Alliance SDK",
        b"Od": "Open Design Alliance (short)",
        b"LibreDWG": "LibreDWG",
        b"ACAD": "AutoCAD",
        b"Autodesk": "Autodesk Product",
        b"Revit": "Autodesk Revit",
        b"Civil 3D": "AutoCAD Civil 3D",
        b"BricsCAD": "BricsCAD",
        b"DraftSight": "DraftSight",
        b"ZWCAD": "ZWCAD",
        b"GstarCAD": "GstarCAD",
        b"progeCAD": "progeCAD",
        b"TurboCAD": "TurboCAD",
    }

    # Required sections for standard DWG
    REQUIRED_SECTIONS = [
        b"AcDb:Header",
        b"AcDb:Classes",
        b"AcDb:Handles",
        b"AcDb:ObjFreeSpace",
        b"AcDb:Template",
    ]

    # Optional but common sections
    OPTIONAL_SECTIONS = [
        b"AcDb:Preview",
        b"AcDb:AppInfo",
        b"AcDb:AppInfoHistory",
        b"AcDb:FileDepList",
        b"AcDb:RevHistory",
        b"AcDb:Security",
        b"AcDb:AcDbObjects",
        b"AcDb:SummaryInfo",
    ]

    def __init__(self):
        self.result = StructureAnalysisResult()

    def analyze(self, data: bytes, version: str = "") -> StructureAnalysisResult:
        """
        Perform comprehensive structure analysis on DWG file data.

        Args:
            data: Raw DWG file bytes
            version: DWG version string (e.g., "AC1032")

        Returns:
            StructureAnalysisResult with detailed findings
        """
        self.result = StructureAnalysisResult()

        if len(data) < 128:
            self.result.structure_type = DWGStructureType.CORRUPTED
            self.result.forensic_notes.append("File too small to be valid DWG")
            self.result.is_forensically_significant = True
            return self.result

        # Step 1: Parse header offsets
        self._parse_header_offsets(data)

        # Step 2: Check for AcFs header
        self._check_acfs_header(data)

        # Step 3: Scan for section signatures
        self._scan_for_sections(data)

        # Step 4: Detect creation tool
        self._detect_creation_tool(data)

        # Step 5: Classify structure type
        self._classify_structure()

        # Step 6: Generate forensic notes
        self._generate_forensic_notes(version)

        return self.result

    def _parse_header_offsets(self, data: bytes) -> None:
        """Parse key offsets from DWG header."""
        try:
            # R2004+ header structure at offset 0x20
            if len(data) >= 0x28:
                # These offsets are version-dependent but provide useful info
                self.result.acfs_offset = struct.unpack_from("<I", data, 0x28)[0]

            if len(data) >= 0x2C:
                self.result.data_offset = struct.unpack_from("<I", data, 0x2C)[0]

            # Section map address typically at 0x34 for AC1032
            if len(data) >= 0x38:
                self.result.section_map_address = struct.unpack_from("<I", data, 0x34)[0]

                # Validate section map address
                if 0 < self.result.section_map_address < len(data):
                    self.result.section_map_valid = True

        except struct.error:
            logger.debug("Could not parse header offsets")

    def _check_acfs_header(self, data: bytes) -> None:
        """Check for valid AcFs (AutoCAD File System) header."""
        # AcFs header starts with "AcFs" signature
        acfs_signature = b"AcFs"

        # Check at expected offset
        if self.result.acfs_offset > 0 and self.result.acfs_offset + 4 <= len(data):
            if data[self.result.acfs_offset:self.result.acfs_offset + 4] == acfs_signature:
                self.result.acfs_header_valid = True
                return

        # Scan for AcFs signature
        pos = data.find(acfs_signature)
        if pos != -1:
            self.result.acfs_header_valid = True
            self.result.acfs_offset = pos

    def _scan_for_sections(self, data: bytes) -> None:
        """Scan file for section signatures."""
        sections_found = 0

        # Check required sections
        if data.find(b"AcDb:Header") != -1:
            self.result.has_header_section = True
            sections_found += 1

        if data.find(b"AcDb:Classes") != -1:
            self.result.has_classes_section = True
            sections_found += 1

        if data.find(b"AcDb:Handles") != -1:
            self.result.has_handles_section = True
            sections_found += 1

        if data.find(b"AcDb:AcDbObjects") != -1 or data.find(b"AcDb:ObjFreeSpace") != -1:
            self.result.has_objects_section = True
            sections_found += 1

        # Check optional sections
        if data.find(b"AcDb:AppInfo") != -1 or data.find(b"AppInfoDataList") != -1:
            self.result.has_appinfo_section = True
            sections_found += 1

        if data.find(b"AcDb:Preview") != -1:
            self.result.has_preview_section = True
            sections_found += 1

        self.result.total_sections_found = sections_found

    def _detect_creation_tool(self, data: bytes) -> None:
        """Detect what tool created the DWG file."""
        detected_tools = []

        for signature, tool_name in self.TOOL_SIGNATURES.items():
            if data.find(signature) != -1:
                detected_tools.append(tool_name)
                self.result.tool_signatures.append(signature.decode('utf-8', errors='replace'))

        # Determine primary tool
        if detected_tools:
            # Prioritize more specific detections
            if "Autodesk Revit" in detected_tools:
                self.result.detected_tool = "Autodesk Revit"
            elif "AutoCAD" in detected_tools or "Autodesk Product" in detected_tools:
                self.result.detected_tool = "AutoCAD or Autodesk Product"
            elif "Open Design Alliance SDK" in detected_tools or "Open Design Alliance (short)" in detected_tools:
                self.result.detected_tool = "Open Design Alliance SDK"
            else:
                self.result.detected_tool = detected_tools[0]

        # Check for AppInfoDataList which suggests ODA-based tool
        if data.find(b"AppInfoDataList") != -1:
            if not self.result.detected_tool:
                self.result.detected_tool = "ODA-based application (unidentified)"
            self.result.tool_signatures.append("AppInfoDataList")

    def _classify_structure(self) -> None:
        """Classify the DWG structure type based on findings."""
        # Count critical sections
        critical_present = sum([
            self.result.has_header_section,
            self.result.has_classes_section,
            self.result.has_handles_section,
        ])

        # Standard: All critical sections present
        if critical_present == 3 and self.result.section_map_valid:
            self.result.structure_type = DWGStructureType.STANDARD
            self.result.confidence = 0.95

        # Minimal: Has some sections but not all
        elif critical_present >= 1:
            self.result.structure_type = DWGStructureType.MINIMAL
            self.result.confidence = 0.7 + (critical_present * 0.1)

        # Non-AutoCAD: No critical sections but has AppInfo (ODA signature)
        elif self.result.has_appinfo_section and critical_present == 0:
            self.result.structure_type = DWGStructureType.NON_AUTOCAD
            self.result.confidence = 0.85
            self.result.is_forensically_significant = True

        # Stripped: Valid DWG header but no sections
        elif self.result.acfs_header_valid and critical_present == 0:
            self.result.structure_type = DWGStructureType.STRIPPED
            self.result.confidence = 0.75
            self.result.is_forensically_significant = True

        # Corrupted: Nothing valid found
        elif not self.result.acfs_header_valid and critical_present == 0:
            self.result.structure_type = DWGStructureType.CORRUPTED
            self.result.confidence = 0.6
            self.result.is_forensically_significant = True

        else:
            self.result.structure_type = DWGStructureType.UNKNOWN
            self.result.confidence = 0.3
            self.result.is_forensically_significant = True

    def _generate_forensic_notes(self, version: str) -> None:
        """Generate forensic notes based on findings."""
        notes = []

        # Structure type notes
        if self.result.structure_type == DWGStructureType.STRIPPED:
            notes.append(
                "FILE APPEARS STRIPPED: Standard DWG sections are missing. "
                "This may indicate the file was processed by a metadata removal tool "
                "or exported in a minimal format."
            )

        elif self.result.structure_type == DWGStructureType.NON_AUTOCAD:
            notes.append(
                f"NON-AUTOCAD CREATION: File appears to have been created by "
                f"'{self.result.detected_tool or 'unknown third-party tool'}'. "
                "Standard AutoCAD sections are absent."
            )

        elif self.result.structure_type == DWGStructureType.CORRUPTED:
            notes.append(
                "FILE STRUCTURE CORRUPTED: Cannot locate valid DWG sections. "
                "File may be damaged, truncated, or intentionally modified."
            )

        # Missing section notes
        missing = []
        if not self.result.has_header_section:
            missing.append("AcDb:Header (contains timestamps, GUIDs)")
        if not self.result.has_classes_section:
            missing.append("AcDb:Classes (object type definitions)")
        if not self.result.has_handles_section:
            missing.append("AcDb:Handles (object reference map)")

        if missing:
            notes.append(f"MISSING CRITICAL SECTIONS: {', '.join(missing)}")

        # Tool detection notes
        if self.result.detected_tool and "ODA" in self.result.detected_tool:
            notes.append(
                "ODA SDK SIGNATURE DETECTED: File may have been created or processed "
                "by Open Design Alliance-based software. ODA tools may not write "
                "full AutoCAD-compatible section structures."
            )

        # Section map notes
        if not self.result.section_map_valid:
            notes.append(
                "INVALID SECTION MAP: Section map address points to invalid location. "
                "Standard section-based parsing will fail."
            )

        # Evidence implications
        if self.result.is_forensically_significant:
            notes.append(
                "FORENSIC SIGNIFICANCE: The non-standard structure of this file "
                "may be relevant to determining file origin, authenticity, or "
                "whether the file has been modified/processed after original creation."
            )

        self.result.forensic_notes = notes


def analyze_dwg_structure(data: bytes, version: str = "") -> StructureAnalysisResult:
    """
    Convenience function to analyze DWG structure.

    Args:
        data: Raw DWG file bytes
        version: DWG version string

    Returns:
        StructureAnalysisResult with analysis findings
    """
    analyzer = DWGStructureAnalyzer()
    return analyzer.analyze(data, version)
