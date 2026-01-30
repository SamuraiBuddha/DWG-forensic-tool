"""
DWG File Provenance Detector

This module identifies the origin and creation context of DWG files BEFORE
tampering rules are applied. It prevents false positives by recognizing
legitimate file characteristics such as Revit exports, ODA SDK tools, and
file transfers.

Forensic Significance:
- Revit exports naturally have CRC=0 and missing timestamps
- ODA SDK tools (BricsCAD, NanoCAD) have different fingerprints
- File transfers show NTFS created > modified pattern
- Native AutoCAD files have proper CRC and timestamp patterns

This detector runs BEFORE the rule engine to set context for rule evaluation.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from dwg_forensic.parsers.header import HeaderParser
from dwg_forensic.parsers.crc import CRCValidator
from dwg_forensic.parsers.ntfs import NTFSTimestampParser
from dwg_forensic.parsers.revit_detection import RevitDetector
from dwg_forensic.analysis.cad_fingerprinting import CADFingerprinter, CADApplication


@dataclass
class FileProvenance:
    """
    Result of file provenance detection.

    This data structure captures the origin and context of a DWG file,
    which is used to adjust tampering rule evaluation and prevent false positives.
    """
    source_application: str = "Unknown"
    is_export: bool = False
    is_transferred: bool = False
    confidence: float = 0.0
    rules_to_skip: List[str] = field(default_factory=list)
    detection_notes: List[str] = field(default_factory=list)

    # Detailed detection results
    is_revit_export: bool = False
    is_oda_tool: bool = False
    is_native_autocad: bool = False

    # Additional metadata for forensic context
    revit_confidence: float = 0.0
    fingerprint_confidence: float = 0.0
    transfer_indicators: List[str] = field(default_factory=list)


class ProvenanceDetector:
    """
    Detects file origin and creation context before tampering analysis.

    Detection Order:
    1. Revit export detection (highest priority - specific patterns)
    2. CAD application fingerprinting (ODA tools, BricsCAD, etc.)
    3. File transfer detection (NTFS timestamp patterns)
    4. Native AutoCAD detection (default if no other patterns match)

    This detector ensures that legitimate file characteristics are not
    misinterpreted as tampering indicators.
    """

    # Rules to skip for Revit exports
    REVIT_SKIP_RULES = [
        "TAMPER-001",  # CRC Header Mismatch - Revit has CRC=0 by design
        "TAMPER-002",  # CRC Section Mismatch
        "TAMPER-003",  # TrustedDWG Missing - Revit doesn't use TrustedDWG
        "TAMPER-004",  # Watermark Missing
    ]

    # Rules to skip for ODA SDK tools
    ODA_SKIP_RULES = [
        "TAMPER-001",  # CRC may be 0 for ODA tools
        "TAMPER-003",  # TrustedDWG not applicable
    ]

    # Rules to adjust for file transfers
    TRANSFER_ADJUST_RULES = [
        "TAMPER-019",  # NTFS Creation After Modification (expected for transfers)
        "TAMPER-020",  # DWG-NTFS Creation Contradiction
    ]

    def __init__(self):
        """Initialize the provenance detector."""
        self.revit_detector = RevitDetector()
        self.cad_fingerprinter = CADFingerprinter()
        self.header_parser = HeaderParser()
        self.crc_validator = CRCValidator()

    def detect(self, file_path: Path) -> FileProvenance:
        """
        Detect the provenance of a DWG file.

        Args:
            file_path: Path to the DWG file to analyze

        Returns:
            FileProvenance object with detection results

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file is not readable
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Read file data once for all detectors
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
        except Exception as e:
            raise ValueError(f"Failed to read file: {e}")

        # Initialize provenance result
        provenance = FileProvenance()

        # Step 1: Check for Revit export (highest priority)
        revit_result = self._detect_revit(file_path, file_data)
        if revit_result:
            self._apply_revit_provenance(provenance, revit_result)
            # Calculate confidence before early return
            provenance.confidence = self._calculate_confidence(provenance)
            return provenance  # Early return for Revit exports

        # Step 2: Fingerprint CAD application
        fingerprint_result = self._fingerprint_application(file_path, file_data)
        if fingerprint_result:
            self._apply_fingerprint_provenance(provenance, fingerprint_result)

        # Step 3: Detect file transfer patterns
        transfer_detected = self._detect_file_transfer(file_path)
        if transfer_detected:
            self._apply_transfer_provenance(provenance, transfer_detected)

        # Step 4: Check for native AutoCAD characteristics
        if provenance.source_application == "Unknown":
            autocad_detected = self._detect_native_autocad(file_path, file_data)
            if autocad_detected:
                self._apply_autocad_provenance(provenance)

        # Calculate final confidence score
        provenance.confidence = self._calculate_confidence(provenance)

        return provenance

    def _detect_revit(
        self,
        file_path: Path,
        file_data: bytes
    ) -> Optional[object]:
        """
        Detect if file is a Revit export.

        Uses RevitDetector to check for:
        - FINGERPRINTGUID starting with "30314341-"
        - Header structure (Preview Addr = 0x120)
        - Revit-specific signatures

        Args:
            file_path: Path to DWG file
            file_data: File binary data

        Returns:
            RevitDetectionResult if Revit export detected, None otherwise
        """
        result = self.revit_detector.detect(file_path, file_data)

        # Consider it a Revit export if confidence > 0.5
        if result.is_revit_export and result.confidence_score > 0.5:
            return result

        return None

    def _fingerprint_application(
        self,
        file_path: Path,
        file_data: bytes
    ) -> Optional[object]:
        """
        Fingerprint the CAD application that created the file.

        Uses CADFingerprinter to identify:
        - ODA SDK-based tools (BricsCAD, NanoCAD, DraftSight)
        - Open source tools (LibreCAD, QCAD)
        - Native AutoCAD

        Args:
            file_path: Path to DWG file
            file_data: File binary data

        Returns:
            FingerprintResult if application identified, None otherwise
        """
        # Extract header CRC from file_data (at offset 0x68 for R18+)
        # Format: 4 bytes, little-endian unsigned int
        header_crc = None
        if len(file_data) >= 0x6C:
            import struct
            header_crc = struct.unpack("<I", file_data[0x68:0x6C])[0]

        # Call fingerprint with proper parameters
        result = self.cad_fingerprinter.fingerprint(file_path, header_crc=header_crc)

        # Return result if confidence is reasonable
        if result and result.confidence > 0.3:
            return result

        return None

    def _detect_file_transfer(self, file_path: Path) -> Optional[dict]:
        """
        Detect if file shows NTFS patterns indicating file transfer.

        File transfers typically show:
        - NTFS Created timestamp > NTFS Modified timestamp
        - This is EXPECTED behavior when copying files
        - Should NOT trigger TAMPER-019 or TAMPER-020

        Args:
            file_path: Path to DWG file

        Returns:
            Dict with transfer indicators if detected, None otherwise
        """
        try:
            ntfs_parser = NTFSTimestampParser()
            ntfs_data = ntfs_parser.parse(file_path)

            if not ntfs_data or not ntfs_data.si_timestamps:
                return None

            indicators = []

            # Check for created > modified pattern (file copy)
            created = ntfs_data.si_timestamps.get("created")
            modified = ntfs_data.si_timestamps.get("modified")

            if created and modified and created > modified:
                indicators.append(
                    f"NTFS Created ({created}) > Modified ({modified}) - "
                    "Indicates file copy/transfer"
                )

            # Check for SI/FN timestamp differences (normal for transfers)
            if ntfs_data.fn_timestamps:
                si_created = ntfs_data.si_timestamps.get("created")
                fn_created = ntfs_data.fn_timestamps.get("created")

                if si_created and fn_created and si_created != fn_created:
                    delta = abs((si_created - fn_created).total_seconds())
                    if delta > 1:  # More than 1 second difference
                        indicators.append(
                            f"SI/FN timestamp difference: {delta:.1f} seconds - "
                            "Normal for file transfers"
                        )

            if indicators:
                return {
                    "indicators": indicators,
                    "ntfs_data": ntfs_data
                }

        except Exception:
            # NTFS parsing may fail on non-Windows or for various reasons
            pass

        return None

    def _detect_native_autocad(
        self,
        file_path: Path,
        file_data: bytes
    ) -> bool:
        """
        Detect if file is native AutoCAD (not export or third-party).

        Native AutoCAD files typically have:
        - Non-zero CRC32 checksum
        - Proper FINGERPRINTGUID (not starting with "30314341-")
        - Standard header structure (Preview Addr = 0x1C0 or similar)

        Args:
            file_path: Path to DWG file
            file_data: File binary data

        Returns:
            True if native AutoCAD detected, False otherwise
        """
        try:
            # Parse header
            header = self.header_parser.parse(file_path)

            # Skip unsupported versions
            if not header.is_supported:
                return False

            # Validate CRC
            crc_result = self.crc_validator.validate(file_path)

            # Native AutoCAD typically has:
            # 1. Non-zero CRC (though not always - Civil 3D can have CRC=0)
            # 2. Valid header structure
            # 3. No Revit or ODA signatures

            # This is a weak indicator - we only use it as a fallback
            has_nonzero_crc = (
                crc_result.header_crc_stored != "0x00000000" and
                crc_result.header_crc_calculated != "0x00000000"
            )

            # For now, just return True if we have a valid header
            # This is intentionally permissive - we want to avoid
            # false negatives for legitimate AutoCAD files
            return True

        except Exception:
            return False

    def _apply_revit_provenance(
        self,
        provenance: FileProvenance,
        revit_result: object
    ) -> None:
        """
        Apply Revit export provenance to result.

        Args:
            provenance: FileProvenance object to update
            revit_result: RevitDetectionResult from detector
        """
        provenance.source_application = "Revit"
        provenance.is_export = True
        provenance.is_revit_export = True
        provenance.revit_confidence = revit_result.confidence_score

        # Add Revit-specific rules to skip
        provenance.rules_to_skip.extend(self.REVIT_SKIP_RULES)

        # Add detection notes
        provenance.detection_notes.append(
            f"Revit export detected (confidence: {revit_result.confidence_score:.2f})"
        )
        provenance.detection_notes.append(
            "CRC=0 and missing timestamps are EXPECTED for Revit exports"
        )

        if revit_result.revit_version:
            provenance.detection_notes.append(
                f"Revit version: {revit_result.revit_version}"
            )

    def _apply_fingerprint_provenance(
        self,
        provenance: FileProvenance,
        fingerprint_result: object
    ) -> None:
        """
        Apply CAD fingerprint provenance to result.

        Args:
            provenance: FileProvenance object to update
            fingerprint_result: FingerprintResult from fingerprinter
        """
        app = fingerprint_result.detected_application
        provenance.source_application = app.value if hasattr(app, 'value') else str(app)
        provenance.fingerprint_confidence = fingerprint_result.confidence

        # Check if it's an ODA-based tool
        provenance.is_oda_tool = fingerprint_result.is_oda_based

        # For ODA tools, add rules to skip
        if provenance.is_oda_tool:
            provenance.is_export = True  # ODA tools create exports
            provenance.rules_to_skip.extend(self.ODA_SKIP_RULES)
            provenance.detection_notes.append(
                f"ODA SDK-based tool detected: {provenance.source_application}"
            )
            provenance.detection_notes.append(
                "CRC=0 may be normal for ODA tools"
            )

        # Add general fingerprint note
        provenance.detection_notes.append(
            f"Application fingerprinted as: {provenance.source_application} "
            f"(confidence: {fingerprint_result.confidence:.2f})"
        )

    def _apply_transfer_provenance(
        self,
        provenance: FileProvenance,
        transfer_data: dict
    ) -> None:
        """
        Apply file transfer provenance to result.

        Args:
            provenance: FileProvenance object to update
            transfer_data: Dict with transfer indicators
        """
        provenance.is_transferred = True
        provenance.transfer_indicators = transfer_data["indicators"]

        # Add transfer-adjusted rules
        for rule_id in self.TRANSFER_ADJUST_RULES:
            if rule_id not in provenance.rules_to_skip:
                provenance.rules_to_skip.append(rule_id)

        # Add detection notes
        provenance.detection_notes.append(
            "File transfer detected (NTFS timestamps indicate copy/move operation)"
        )

        for indicator in transfer_data["indicators"]:
            provenance.detection_notes.append(f"  - {indicator}")

    def _apply_autocad_provenance(
        self,
        provenance: FileProvenance
    ) -> None:
        """
        Apply native AutoCAD provenance to result.

        Args:
            provenance: FileProvenance object to update
        """
        provenance.source_application = "AutoCAD"
        provenance.is_native_autocad = True
        provenance.detection_notes.append(
            "Detected as native AutoCAD file"
        )

    def _calculate_confidence(self, provenance: FileProvenance) -> float:
        """
        Calculate overall confidence score for provenance detection.

        Args:
            provenance: FileProvenance object

        Returns:
            Confidence score from 0.0 to 1.0
        """
        # Start with base confidence
        confidence = 0.0

        # Revit detection has highest confidence
        if provenance.is_revit_export:
            confidence = max(confidence, provenance.revit_confidence)

        # Fingerprint detection adds to confidence
        if provenance.fingerprint_confidence > 0:
            confidence = max(confidence, provenance.fingerprint_confidence)

        # File transfer detection is high confidence for that specific aspect
        if provenance.is_transferred:
            confidence = max(confidence, 0.85)

        # Native AutoCAD is low confidence (fallback)
        if provenance.is_native_autocad and confidence == 0.0:
            confidence = 0.5

        return min(confidence, 1.0)


def detect_provenance(file_path: Path) -> FileProvenance:
    """
    Convenience function to detect file provenance.

    Args:
        file_path: Path to DWG file

    Returns:
        FileProvenance object with detection results
    """
    detector = ProvenanceDetector()
    return detector.detect(file_path)
