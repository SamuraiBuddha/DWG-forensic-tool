"""
Revit DWG Detection and Forensic Analysis.

This module provides specialized detection for DWG files exported from Autodesk Revit.
Revit DWG files have unique characteristics that differ from standard AutoCAD files
and may trigger false positives in standard tampering detection.

Key Characteristics of Revit DWG Files:
- Export-generated rather than natively edited
- May have atypical CRC patterns due to export process
- Different internal structure patterns
- Specific application signatures in AppInfo sections

Forensic Implications:
- Revit exports should be flagged as "export-generated"
- Tampering rules should be adjusted for export artifacts
- Timeline analysis must account for export date vs creation date
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, List, Tuple
import struct


class RevitExportType(Enum):
    """Types of Revit DWG exports."""
    UNKNOWN = "UNKNOWN"
    REVIT_2D = "REVIT_2D"  # 2D export from Revit
    REVIT_3D = "REVIT_3D"  # 3D export from Revit
    REVIT_LINK = "REVIT_LINK"  # Linked DWG from Revit
    NOT_REVIT = "NOT_REVIT"  # Not a Revit export


@dataclass
class RevitSignature:
    """Signatures that identify Revit-generated DWG files."""
    signature_type: str  # Type of signature found
    location: str  # Where in file signature was found
    confidence: float  # Confidence level (0.0 to 1.0)
    details: str  # Additional details about the signature


@dataclass
class RevitDetectionResult:
    """Result of Revit DWG detection analysis."""
    is_revit_export: bool
    export_type: RevitExportType
    confidence_score: float  # Overall confidence (0.0 to 1.0)
    signatures: List[RevitSignature]
    revit_version: Optional[str] = None  # Detected Revit version if available
    export_timestamp: Optional[str] = None  # Export timestamp if available
    forensic_notes: List[str] = None  # Forensic observations

    def __post_init__(self):
        """Initialize mutable default."""
        if self.forensic_notes is None:
            self.forensic_notes = []


class RevitDetector:
    """
    Detector for Revit-exported DWG files.

    Uses multiple heuristics to identify Revit exports:
    1. Application signature strings in header
    2. Specific object patterns in sections
    3. Drawing variables unique to Revit exports
    4. Structural patterns in section maps
    5. FINGERPRINTGUID pattern "30314341-" (ASCII "01CA") - Revit/ODA signature
    6. Header structure: Preview Addr = 0x120, null Summary/VBA addresses
    """

    # Known Revit signature strings
    REVIT_SIGNATURES = [
        b"Autodesk Revit",
        b"REVIT",
        b"RevitLinkType",
        b"AcDbRevitVariables",
    ]

    # Application info markers
    REVIT_APP_MARKERS = [
        b"Revit Architecture",
        b"Revit Structure",
        b"Revit MEP",
        b"Revit LT",
    ]

    # GUID prefix that indicates Revit/ODA export
    # "30314341" = ASCII "01CA" (Autodesk export signature)
    REVIT_GUID_PREFIX = b"30314341-"
    REVIT_GUID_PREFIX_STR = "30314341-"

    # Header structure constants for Revit exports
    # Revit uses Preview Addr = 0x120 (instead of AutoCAD's 0x1C0)
    REVIT_PREVIEW_ADDRESS = 0x120

    def __init__(self):
        """Initialize Revit detector."""
        self._signatures_found: List[RevitSignature] = []

    def detect(self, file_path: Path, file_data: Optional[bytes] = None) -> RevitDetectionResult:
        """
        Detect if a DWG file is a Revit export.

        Args:
            file_path: Path to DWG file
            file_data: Optional pre-read file data

        Returns:
            RevitDetectionResult with detection findings
        """
        self._signatures_found = []

        # Read file data if not provided
        if file_data is None:
            try:
                with open(file_path, "rb") as f:
                    file_data = f.read()
            except Exception:
                return self._create_failure_result("Failed to read file")

        # Perform detection checks
        self._check_header_signatures(file_data)
        self._check_application_markers(file_data)
        self._check_object_patterns(file_data)
        self._check_header_structure(file_data)
        self._check_guid_pattern(file_data)

        # Calculate confidence and determine result
        confidence = self._calculate_confidence()
        is_revit = confidence > 0.5
        export_type = self._determine_export_type() if is_revit else RevitExportType.NOT_REVIT

        # Extract Revit version if detected
        revit_version = self._extract_revit_version(file_data) if is_revit else None

        # Build forensic notes
        forensic_notes = self._build_forensic_notes(is_revit, confidence)

        return RevitDetectionResult(
            is_revit_export=is_revit,
            export_type=export_type,
            confidence_score=confidence,
            signatures=self._signatures_found.copy(),
            revit_version=revit_version,
            forensic_notes=forensic_notes,
        )

    def _check_header_signatures(self, data: bytes) -> None:
        """
        Check for Revit signatures in file header.

        Scans the first 4KB of the file for known Revit strings.
        """
        header_region = data[:4096]

        for signature in self.REVIT_SIGNATURES:
            if signature in header_region:
                offset = header_region.find(signature)
                self._signatures_found.append(
                    RevitSignature(
                        signature_type="HEADER_STRING",
                        location=f"Header at offset 0x{offset:X}",
                        confidence=0.8,
                        details=f"Found signature: {signature.decode('ascii', errors='ignore')}",
                    )
                )

    def _check_application_markers(self, data: bytes) -> None:
        """
        Check for Revit application markers throughout the file.

        These markers typically appear in AppInfo sections.
        """
        # Scan larger portion of file for app markers
        search_region = data[:65536]  # First 64KB

        for marker in self.REVIT_APP_MARKERS:
            if marker in search_region:
                offset = search_region.find(marker)
                self._signatures_found.append(
                    RevitSignature(
                        signature_type="APP_MARKER",
                        location=f"Application info at offset 0x{offset:X}",
                        confidence=0.9,
                        details=f"Found marker: {marker.decode('ascii', errors='ignore')}",
                    )
                )

    def _check_object_patterns(self, data: bytes) -> None:
        """
        Check for Revit-specific object patterns.

        Revit exports often contain specific object class definitions
        that are unique to the Revit-to-DWG export process.
        """
        # Look for Revit-specific class names
        revit_classes = [
            b"AcDbRevitEntity",
            b"AcDbRevitRoom",
            b"AcDbRevitWall",
        ]

        search_region = data[:131072]  # First 128KB

        for class_name in revit_classes:
            if class_name in search_region:
                offset = search_region.find(class_name)
                self._signatures_found.append(
                    RevitSignature(
                        signature_type="OBJECT_CLASS",
                        location=f"Class definition at offset 0x{offset:X}",
                        confidence=0.95,
                        details=f"Found Revit class: {class_name.decode('ascii', errors='ignore')}",
                    )
                )

    def _check_header_structure(self, data: bytes) -> None:
        """
        Check for Revit-specific header structure patterns.

        Revit exports have distinctive header values:
        - Preview Address = 0x120 (instead of AutoCAD's 0x1C0)
        - Summary Info Address = 0x00000000 (null)
        - VBA Project Address = 0x00000000 (null)

        This pattern is highly reliable for detecting Revit exports.
        """
        if len(data) < 0x24:  # Need at least 36 bytes for header
            return

        # DWG R18+ header structure (AC1024, AC1027, AC1032):
        # Offset 0x0D (13): Preview Image Address (4 bytes, little-endian)
        # Offset 0x13 (19): Summary Info Address (4 bytes, little-endian)
        # Offset 0x17 (23): VBA Project Address (4 bytes, little-endian)

        # Check version string first (must be AC1024, AC1027, or AC1032)
        version = data[:6]
        if version not in [b"AC1024", b"AC1027", b"AC1032"]:
            return  # Only check R18+ files

        try:
            preview_addr = struct.unpack_from("<I", data, 0x0D)[0]
            summary_addr = struct.unpack_from("<I", data, 0x13)[0]
            vba_addr = struct.unpack_from("<I", data, 0x17)[0]

            # Revit export detection based on header structure
            # Primary indicator: Preview Address = 0x120 (Revit uses this, AutoCAD uses 0x1C0)
            # Secondary: Summary and VBA addresses may be 0 or small values

            is_revit_preview = preview_addr == self.REVIT_PREVIEW_ADDRESS

            if is_revit_preview:
                # Calculate confidence based on additional indicators
                confidence = 0.85  # Base confidence for Preview=0x120
                details_parts = [f"Preview=0x{preview_addr:X} (Revit signature)"]

                if summary_addr == 0:
                    confidence = min(confidence + 0.05, 0.95)
                    details_parts.append(f"Summary=0x{summary_addr:X} (null)")
                else:
                    details_parts.append(f"Summary=0x{summary_addr:X}")

                if vba_addr == 0:
                    confidence = min(confidence + 0.03, 0.95)
                    details_parts.append(f"VBA=0x{vba_addr:X} (null)")
                else:
                    details_parts.append(f"VBA=0x{vba_addr:X}")

                self._signatures_found.append(
                    RevitSignature(
                        signature_type="HEADER_STRUCTURE",
                        location="DWG Header (offsets 0x0D-0x1A)",
                        confidence=confidence,
                        details=(
                            f"Revit export header: {', '.join(details_parts)}. "
                            "Preview Address 0x120 is distinctive for Revit DWG exports "
                            "(AutoCAD uses 0x1C0). Zero CRC and missing timestamps are "
                            "EXPECTED behavior for these files."
                        ),
                    )
                )
        except struct.error:
            pass  # Header too short or malformed

    def _check_guid_pattern(self, data: bytes) -> None:
        """
        Check for Revit/ODA GUID pattern in FINGERPRINTGUID.

        FINGERPRINTGUID prefix "30314341-" = ASCII "01CA" which is a known
        signature for Autodesk Revit and ODA SDK exports. This is one of
        the most reliable indicators of a Revit export.

        The GUID is typically stored in the drawing variables section or
        may appear as a string pattern in the file.
        """
        # Search for the GUID pattern in the file
        # The GUID typically appears as ASCII text in the file
        search_region = data[:262144]  # Search first 256KB

        # Check for ASCII GUID pattern
        if self.REVIT_GUID_PREFIX in search_region:
            offset = search_region.find(self.REVIT_GUID_PREFIX)
            self._signatures_found.append(
                RevitSignature(
                    signature_type="GUID_PATTERN",
                    location=f"FINGERPRINTGUID at offset 0x{offset:X}",
                    confidence=0.93,
                    details=(
                        f"FINGERPRINTGUID starts with '30314341-' (ASCII '01CA'). "
                        "This is an Autodesk Revit/ODA export signature. Files with "
                        "this pattern have zero CRC and missing timestamps by design."
                    ),
                )
            )

    def _calculate_confidence(self) -> float:
        """
        Calculate overall confidence score based on signatures found.

        Uses weighted average of signature confidences.

        Returns:
            Confidence score from 0.0 to 1.0
        """
        if not self._signatures_found:
            return 0.0

        # Weight by signature type
        weights = {
            "OBJECT_CLASS": 2.0,  # Strongest indicator (Revit class names)
            "GUID_PATTERN": 2.0,  # Very strong - "30314341-" prefix
            "HEADER_STRUCTURE": 1.8,  # Strong - Preview=0x120 pattern
            "APP_MARKER": 1.5,
            "HEADER_STRING": 1.0,
        }

        total_weighted_confidence = 0.0
        total_weight = 0.0

        for sig in self._signatures_found:
            weight = weights.get(sig.signature_type, 1.0)
            total_weighted_confidence += sig.confidence * weight
            total_weight += weight

        return min(total_weighted_confidence / total_weight, 1.0)

    def _determine_export_type(self) -> RevitExportType:
        """
        Determine the type of Revit export based on signatures.

        Returns:
            RevitExportType enum value
        """
        # Check signature details for export type clues (case-insensitive)
        for sig in self._signatures_found:
            details_lower = sig.details.lower()
            if "3d" in details_lower:
                return RevitExportType.REVIT_3D
            if "link" in details_lower:
                return RevitExportType.REVIT_LINK

        # Default to 2D export if no specific type found
        return RevitExportType.REVIT_2D

    def _extract_revit_version(self, data: bytes) -> Optional[str]:
        """
        Attempt to extract Revit version from file.

        Args:
            data: File data bytes

        Returns:
            Revit version string if found, None otherwise
        """
        # Look for version strings like "Revit 2022", "Revit 2023", etc.
        search_region = data[:65536]

        # Pattern: "Revit " followed by 4-digit year
        for i in range(len(search_region) - 11):  # "Revit 2023" = 11 chars
            if search_region[i:i+6] == b"Revit ":
                # Check for year immediately after
                potential_year = search_region[i+6:i+10]
                try:
                    year_str = potential_year.decode('ascii')
                    if year_str.isdigit() and len(year_str) == 4:
                        year = int(year_str)
                        if 2010 <= year <= 2030:
                            return f"Revit {year}"
                except UnicodeDecodeError:
                    continue

        return None

    def _build_forensic_notes(self, is_revit: bool, confidence: float) -> List[str]:
        """
        Build forensic notes based on detection results.

        Args:
            is_revit: Whether file is identified as Revit export
            confidence: Confidence score

        Returns:
            List of forensic observation strings
        """
        notes = []

        if is_revit:
            notes.append(
                f"File identified as Revit export with {confidence*100:.1f}% confidence"
            )
            notes.append(
                "Revit exports may have atypical CRC patterns due to export process"
            )
            notes.append(
                "Timeline analysis should account for export date vs creation date"
            )

            if confidence < 0.7:
                notes.append(
                    "CAUTION: Low confidence detection - verify manually"
                )
        else:
            if self._signatures_found:
                notes.append(
                    "Some Revit signatures found but below confidence threshold"
                )

        return notes

    def _create_failure_result(self, reason: str) -> RevitDetectionResult:
        """
        Create a failure result with error notes.

        Args:
            reason: Reason for detection failure

        Returns:
            RevitDetectionResult indicating failure
        """
        return RevitDetectionResult(
            is_revit_export=False,
            export_type=RevitExportType.UNKNOWN,
            confidence_score=0.0,
            signatures=[],
            forensic_notes=[f"Detection failed: {reason}"],
        )


def detect_revit_export(file_path: Path, file_data: Optional[bytes] = None) -> RevitDetectionResult:
    """
    Convenience function to detect Revit DWG exports.

    Args:
        file_path: Path to DWG file
        file_data: Optional pre-read file data

    Returns:
        RevitDetectionResult with detection findings
    """
    detector = RevitDetector()
    return detector.detect(file_path, file_data)
