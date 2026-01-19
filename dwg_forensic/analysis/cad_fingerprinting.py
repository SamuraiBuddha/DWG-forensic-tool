"""
DWG Forensic Tool - CAD Application Fingerprinting

This module identifies the CAD application that created or modified a DWG file
by analyzing binary artifacts, metadata patterns, and signatures left by different
CAD software implementations.

Supported detection for:
- LibreCAD (open source, DXF-only, uses LibreDWG for conversion)
- QCAD (open source, uses dxflib)
- FreeCAD (open source, uses ODA or LibreDWG)
- ODA SDK/Teigha (foundation for many CAD applications)
- BricsCAD (commercial, ODA-based)
- NanoCAD (commercial, Russian origin)
- DraftSight (commercial, Dassault Systemes)

Forensic significance:
- Identifying authoring software helps corroborate or contradict timestamp claims
- Third-party tools may not properly maintain Autodesk timestamp integrity
- CRC patterns and metadata artifacts reveal true file origin
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


class CADApplication(str, Enum):
    """Known CAD applications that produce DWG files."""
    AUTOCAD = "autocad"
    AUTOCAD_CIVIL3D = "autocad_civil3d"
    REVIT_EXPORT = "revit_export"
    LIBRECAD = "librecad"
    QCAD = "qcad"
    FREECAD = "freecad"
    ODA_SDK = "oda_sdk"
    BRICSCAD = "bricscad"
    NANOCAD = "nanocad"
    DRAFTSIGHT = "draftsight"
    ZWCAD = "zwcad"
    GSTARCAD = "gstarcad"
    PROGECAD = "progecad"
    INTELLICAD = "intellicad"
    CORELCAD = "corelcad"
    TURBOCAD = "turbocad"
    LIBREDWG = "libredwg"
    UNKNOWN = "unknown"


@dataclass
class CADSignature:
    """Signature pattern for identifying a CAD application."""
    application: CADApplication
    pattern_type: str  # "bytes", "string", "crc", "metadata", "xdata"
    pattern: bytes | str | int | None
    offset: Optional[int] = None  # Byte offset, if applicable
    description: str = ""
    confidence: float = 1.0  # 0.0-1.0 confidence level
    forensic_note: str = ""


@dataclass
class FingerprintResult:
    """Result of CAD application fingerprinting analysis."""
    detected_application: CADApplication
    confidence: float
    matching_signatures: List[CADSignature] = field(default_factory=list)
    is_autodesk: bool = False
    is_oda_based: bool = False
    forensic_summary: str = ""
    raw_evidence: Dict[str, Any] = field(default_factory=dict)


class CADFingerprinter:
    """
    Fingerprints DWG files to identify the CAD application that created them.

    This is forensically significant because:
    1. Third-party CAD tools may not maintain Autodesk timestamp integrity
    2. Application-specific artifacts reveal true authoring software
    3. Header field patterns (Preview Addr, Summary Info) differ by application

    IMPORTANT FINDINGS (2026-01-11):
    - CRC = 0x00000000 is NOT a reliable indicator - genuine Autodesk products
      (Civil 3D 2025, Revit 2024) also produce CRC=0
    - Embedded path strings and application markers are more reliable indicators
    """

    # ODA-based applications (use Open Design Alliance SDK)
    ODA_BASED_APPS = {
        CADApplication.BRICSCAD,
        CADApplication.NANOCAD,
        CADApplication.ZWCAD,
        CADApplication.GSTARCAD,
        CADApplication.PROGECAD,
        CADApplication.INTELLICAD,
        CADApplication.CORELCAD,
        CADApplication.TURBOCAD,
    }

    # Open source applications
    OPEN_SOURCE_APPS = {
        CADApplication.LIBRECAD,
        CADApplication.QCAD,
        CADApplication.FREECAD,
        CADApplication.LIBREDWG,
    }

    def __init__(self):
        """Initialize with known CAD signatures."""
        self.signatures: List[CADSignature] = []
        self._load_signatures()

    def _load_signatures(self) -> None:
        """Load all known CAD application signatures."""
        # =================================================================
        # CRC-BASED SIGNATURES (LIMITED RELIABILITY - see notes)
        # =================================================================

        # IMPORTANT: CRC=0 does NOT reliably indicate non-Autodesk origin!
        # Testing with genuine Civil 3D 2025 and Revit 2024 exports shows they
        # also produce CRC=0x00000000. This signature has been demoted to LOW
        # confidence and should only be used in combination with other markers.
        self.signatures.append(CADSignature(
            application=CADApplication.UNKNOWN,
            pattern_type="crc",
            pattern=0x00000000,
            description="Zero CRC32 - Inconclusive (see notes)",
            confidence=0.20,  # LOW - not reliable alone
            forensic_note=(
                "NOTE: CRC32 = 0x00000000 was previously thought to indicate non-Autodesk "
                "origin, but testing shows genuine Civil 3D 2025 and Revit 2024 exports "
                "also have CRC=0. This marker should NOT be used alone for origin detection. "
                "Use embedded path strings, application markers, and header field patterns "
                "for more reliable fingerprinting."
            ),
        ))

        # =================================================================
        # LIBRECAD SIGNATURES
        # =================================================================

        # LibreCAD primarily exports DXF, requires converter for DWG
        # When converted, files often have characteristic artifacts
        self.signatures.append(CADSignature(
            application=CADApplication.LIBRECAD,
            pattern_type="string",
            pattern="LibreCAD",
            description="LibreCAD application name in metadata",
            confidence=1.0,
            forensic_note="Direct evidence of LibreCAD origin",
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.LIBRECAD,
            pattern_type="metadata",
            pattern="$LASTSAVEDBY containing 'librecad'",
            description="LibreCAD user marker in LASTSAVEDBY",
            confidence=0.9,
            forensic_note="LibreCAD often leaves application name in LASTSAVEDBY field",
        ))

        # =================================================================
        # QCAD SIGNATURES
        # =================================================================

        self.signatures.append(CADSignature(
            application=CADApplication.QCAD,
            pattern_type="string",
            pattern="QCAD",
            description="QCAD application name in metadata",
            confidence=1.0,
            forensic_note="Direct evidence of QCAD origin",
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.QCAD,
            pattern_type="string",
            pattern="RibbonSoft",
            description="RibbonSoft (QCAD developer) in metadata",
            confidence=0.95,
            forensic_note="RibbonSoft is the developer of QCAD",
        ))

        # dxflib signature (library used by QCAD)
        self.signatures.append(CADSignature(
            application=CADApplication.QCAD,
            pattern_type="string",
            pattern="dxflib",
            description="dxflib library marker",
            confidence=0.85,
            forensic_note="dxflib is the DXF library used by QCAD",
        ))

        # =================================================================
        # FREECAD SIGNATURES
        # =================================================================

        self.signatures.append(CADSignature(
            application=CADApplication.FREECAD,
            pattern_type="string",
            pattern="FreeCAD",
            description="FreeCAD application name",
            confidence=1.0,
            forensic_note="Direct evidence of FreeCAD origin",
        ))

        # =================================================================
        # ODA SDK / TEIGHA SIGNATURES
        # =================================================================

        # ODA SDK markers
        self.signatures.append(CADSignature(
            application=CADApplication.ODA_SDK,
            pattern_type="string",
            pattern="Open Design Alliance",
            description="ODA SDK marker",
            confidence=0.95,
            forensic_note=(
                "Open Design Alliance SDK is used by many non-Autodesk CAD applications. "
                "Its presence indicates the file was not created by genuine AutoCAD."
            ),
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.ODA_SDK,
            pattern_type="string",
            pattern="Teigha",
            description="Teigha (former ODA SDK name) marker",
            confidence=0.95,
            forensic_note="Teigha was the former name of ODA SDK",
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.ODA_SDK,
            pattern_type="string",
            pattern="DWGdirect",
            description="DWGdirect (ODA library) marker",
            confidence=0.9,
            forensic_note="DWGdirect is part of the ODA SDK",
        ))

        # =================================================================
        # BRICSCAD SIGNATURES
        # =================================================================

        self.signatures.append(CADSignature(
            application=CADApplication.BRICSCAD,
            pattern_type="string",
            pattern="BricsCAD",
            description="BricsCAD application name",
            confidence=1.0,
            forensic_note="Direct evidence of BricsCAD origin (ODA-based)",
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.BRICSCAD,
            pattern_type="string",
            pattern="Bricsys",
            description="Bricsys (BricsCAD developer) marker",
            confidence=0.95,
            forensic_note="Bricsys is the developer of BricsCAD",
        ))

        # =================================================================
        # NANOCAD SIGNATURES
        # =================================================================

        self.signatures.append(CADSignature(
            application=CADApplication.NANOCAD,
            pattern_type="string",
            pattern="nanoCAD",
            description="nanoCAD application name",
            confidence=1.0,
            forensic_note="Direct evidence of nanoCAD origin (Russian, ODA-based)",
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.NANOCAD,
            pattern_type="string",
            pattern="Nanosoft",
            description="Nanosoft (nanoCAD developer) marker",
            confidence=0.95,
            forensic_note="Nanosoft is the Russian developer of nanoCAD",
        ))

        # =================================================================
        # DRAFTSIGHT SIGNATURES
        # =================================================================

        self.signatures.append(CADSignature(
            application=CADApplication.DRAFTSIGHT,
            pattern_type="string",
            pattern="DraftSight",
            description="DraftSight application name",
            confidence=1.0,
            forensic_note="Direct evidence of DraftSight origin (Dassault Systemes)",
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.DRAFTSIGHT,
            pattern_type="string",
            pattern="Dassault",
            description="Dassault Systemes marker",
            confidence=0.8,
            forensic_note="Dassault Systemes develops DraftSight",
        ))

        # =================================================================
        # OTHER CAD APPLICATIONS
        # =================================================================

        self.signatures.append(CADSignature(
            application=CADApplication.ZWCAD,
            pattern_type="string",
            pattern="ZWCAD",
            description="ZWCAD application name",
            confidence=1.0,
            forensic_note="ZWCAD is a Chinese ODA-based CAD application",
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.GSTARCAD,
            pattern_type="string",
            pattern="GstarCAD",
            description="GstarCAD application name",
            confidence=1.0,
            forensic_note="GstarCAD is a Chinese ODA-based CAD application",
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.PROGECAD,
            pattern_type="string",
            pattern="progeCAD",
            description="progeCAD application name",
            confidence=1.0,
            forensic_note="progeCAD is an Italian IntelliCAD-based application",
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.INTELLICAD,
            pattern_type="string",
            pattern="IntelliCAD",
            description="IntelliCAD application name",
            confidence=1.0,
            forensic_note="IntelliCAD is an ODA-based CAD platform",
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.CORELCAD,
            pattern_type="string",
            pattern="CorelCAD",
            description="CorelCAD application name",
            confidence=1.0,
            forensic_note="CorelCAD is Corel's ODA-based CAD application",
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.TURBOCAD,
            pattern_type="string",
            pattern="TurboCAD",
            description="TurboCAD application name",
            confidence=1.0,
            forensic_note="TurboCAD is an IMSI Design CAD application",
        ))

        # =================================================================
        # LIBREDWG SIGNATURES (used by multiple open-source apps)
        # =================================================================

        self.signatures.append(CADSignature(
            application=CADApplication.LIBREDWG,
            pattern_type="string",
            pattern="LibreDWG",
            description="LibreDWG library marker",
            confidence=0.95,
            forensic_note=(
                "LibreDWG is an open-source DWG library used by LibreCAD and others. "
                "Its presence indicates the file was processed by open-source software."
            ),
        ))

        # =================================================================
        # LIBREDWG ANALYSIS-BASED SIGNATURES (discovered 2026-01-11)
        # =================================================================
        # These signatures were discovered by analyzing files with LibreDWG's
        # dwgread tool and comparing forensic header variables.

        # LibreDWG FINGERPRINTGUID contains "DEAD" - placeholder/test value
        self.signatures.append(CADSignature(
            application=CADApplication.LIBREDWG,
            pattern_type="guid",
            pattern="DEAD",  # FDEAD578 pattern in GUID
            description="LibreDWG placeholder GUID containing 'DEAD'",
            confidence=0.98,
            forensic_note=(
                "LibreDWG-created files contain 'DEAD' in the FINGERPRINTGUID "
                "(e.g., FDEAD578-...). This is a placeholder/test value that clearly "
                "identifies LibreDWG-created files. Genuine AutoCAD generates random GUIDs."
            ),
        ))

        # =================================================================
        # REVIT EXPORT SIGNATURES (discovered 2026-01-11)
        # =================================================================
        # Revit DWG exports have unique patterns in TDINDWG, HANDSEED, and class counts.

        self.signatures.append(CADSignature(
            application=CADApplication.REVIT_EXPORT,
            pattern_type="tdindwg",
            pattern="near_zero",  # TDINDWG < 2000 (< 0.03 minutes)
            description="Near-zero TDINDWG editing time (Revit export signature)",
            confidence=0.90,
            forensic_note=(
                "Revit exports have TDINDWG near-zero (~1000 = ~0.016 minutes). This indicates "
                "the file was exported from Revit, not edited in AutoCAD. Genuine AutoCAD "
                "files accumulate editing time during interactive use."
            ),
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.REVIT_EXPORT,
            pattern_type="handseed",
            pattern=3,  # HANDSEED[1] = 3 (others use 2)
            description="HANDSEED[1]=3 (Revit export handle allocation pattern)",
            confidence=0.85,
            forensic_note=(
                "Revit exports have HANDSEED second element = 3, while other applications "
                "(AutoCAD, Civil 3D, LibreDWG) use 2. This is a reliable Revit identifier."
            ),
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.REVIT_EXPORT,
            pattern_type="class_count",
            pattern="very_low",  # <= 15 classes
            description="Very low class count (Revit export pattern)",
            confidence=0.80,
            forensic_note=(
                "Revit exports have very few classes (typically ~10), while native AutoCAD "
                "files have 90-100+ classes and Civil 3D files have 600+ classes. This is "
                "because Revit only exports basic DWG entities without AEC extensions."
            ),
        ))

        # =================================================================
        # CIVIL 3D SIGNATURES (discovered 2026-01-11)
        # =================================================================

        self.signatures.append(CADSignature(
            application=CADApplication.AUTOCAD_CIVIL3D,
            pattern_type="class_count",
            pattern="very_high",  # >= 400 classes
            description="Very high class count (Civil 3D/AEC pattern)",
            confidence=0.85,
            forensic_note=(
                "Civil 3D and AEC applications have very high class counts (600+ classes) "
                "due to specialized civil engineering object types. This indicates genuine "
                "Autodesk AEC product origin."
            ),
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.AUTOCAD_CIVIL3D,
            pattern_type="string",
            pattern="AeccDb",
            description="Civil 3D AeccDb class prefix",
            confidence=0.95,
            forensic_note=(
                "AeccDb prefix indicates Civil 3D-specific classes (AutoCAD Civil 3D Database). "
                "Presence of these classes confirms genuine Civil 3D origin."
            ),
        ))

        # =================================================================
        # AUTODESK PATH SIGNATURES (Reliable for genuine Autodesk detection)
        # =================================================================
        # These embedded paths prove the file was created/edited by genuine
        # Autodesk software. Found in AC1018 and earlier unencrypted files.

        self.signatures.append(CADSignature(
            application=CADApplication.AUTOCAD,
            pattern_type="string",
            pattern="\\Autodesk\\AutoCAD",
            description="Embedded AutoCAD installation path",
            confidence=0.95,
            forensic_note=(
                "Embedded path containing '\\Autodesk\\AutoCAD' proves the file was "
                "created or last saved by genuine AutoCAD. This path is embedded in "
                "plot style references and other file metadata."
            ),
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.AUTOCAD,
            pattern_type="string",
            pattern="Plot Styles",
            description="AutoCAD Plot Styles reference",
            confidence=0.7,
            forensic_note=(
                "Reference to 'Plot Styles' directory indicates genuine AutoCAD. "
                "Third-party tools typically don't reference Autodesk installation paths."
            ),
        ))

        # =================================================================
        # ADVANCED SIGNATURES FROM RESEARCH
        # =================================================================

        # APPID-based signatures (embedded in DWG object tables)
        self.signatures.append(CADSignature(
            application=CADApplication.BRICSCAD,
            pattern_type="xdata",
            pattern="BRICSYS",
            description="BRICSYS APPID registration",
            confidence=1.0,
            forensic_note=(
                "BRICSYS APPID registration is definitive proof of BricsCAD origin. "
                "BricsCAD is ODA-based and may handle DWG metadata differently than AutoCAD."
            ),
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.NANOCAD,
            pattern_type="xdata",
            pattern="NANOCAD",
            description="NANOCAD APPID registration",
            confidence=1.0,
            forensic_note=(
                "NANOCAD APPID registration proves NanoCAD origin (Russian developer). "
                "Look for CP1251 codepage indicating Cyrillic text support."
            ),
        ))

        self.signatures.append(CADSignature(
            application=CADApplication.DRAFTSIGHT,
            pattern_type="xdata",
            pattern="DRAFTSIGHT",
            description="DRAFTSIGHT APPID registration",
            confidence=1.0,
            forensic_note=(
                "DRAFTSIGHT APPID registration proves DraftSight origin. "
                "DraftSight transitioned from free to paid in 2019."
            ),
        ))

        # DraftSight custom property
        self.signatures.append(CADSignature(
            application=CADApplication.DRAFTSIGHT,
            pattern_type="metadata",
            pattern="DS_LICENSE_TYPE",
            description="DraftSight license type custom property",
            confidence=0.95,
            forensic_note=(
                "DS_LICENSE_TYPE custom property indicates DraftSight edition: "
                "Standard, Professional, Premium, or Enterprise."
            ),
        ))

        # BricsCAD dictionary entry
        self.signatures.append(CADSignature(
            application=CADApplication.BRICSCAD,
            pattern_type="string",
            pattern="ACAD_BRICSCAD_INFO",
            description="BricsCAD-specific dictionary entry",
            confidence=1.0,
            forensic_note=(
                "ACAD_BRICSCAD_INFO dictionary entry is unique to BricsCAD. "
                "Contains version information and application metadata."
            ),
        ))

        # NanoCAD codepage signature
        self.signatures.append(CADSignature(
            application=CADApplication.NANOCAD,
            pattern_type="metadata",
            pattern="CP1251",
            description="Cyrillic codepage (Russian origin indicator)",
            confidence=0.7,
            forensic_note=(
                "CP1251 codepage indicates Cyrillic text support. "
                "Combined with other NanoCAD markers, confirms Russian CAD software."
            ),
        ))

        # ODA SDK XDATA prefixes
        self.signatures.append(CADSignature(
            application=CADApplication.ODA_SDK,
            pattern_type="string",
            pattern="OdDb",
            description="ODA SDK class name prefix",
            confidence=0.85,
            forensic_note=(
                "OdDb prefix in class names indicates ODA SDK usage. "
                "AutoCAD uses 'AcDb' prefix instead."
            ),
        ))

        # ezdxf library marker (FreeCAD, open source tools)
        self.signatures.append(CADSignature(
            application=CADApplication.FREECAD,
            pattern_type="string",
            pattern="ezdxf",
            description="ezdxf Python library marker",
            confidence=0.9,
            forensic_note=(
                "ezdxf is a Python DXF library used by FreeCAD and other tools. "
                "Files with ezdxf markers were created programmatically."
            ),
        ))

        # libdxfrw library marker (QCAD, LibreCAD)
        self.signatures.append(CADSignature(
            application=CADApplication.LIBRECAD,
            pattern_type="string",
            pattern="libdxfrw",
            description="libdxfrw library marker (LibreCAD/QCAD)",
            confidence=0.9,
            forensic_note=(
                "libdxfrw is the DXF reading/writing library used by LibreCAD. "
                "Its presence indicates open-source CAD tool origin."
            ),
        ))

    def fingerprint(
        self,
        file_path: Path,
        header_crc: Optional[Union[int, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> FingerprintResult:
        """
        Fingerprint a DWG file to identify the authoring CAD application.

        Args:
            file_path: Path to the DWG file
            header_crc: Pre-extracted header CRC value (int or hex string like "0x12345678")
            metadata: Pre-extracted metadata dictionary

        Returns:
            FingerprintResult with detected application and confidence
        """
        file_path = Path(file_path)
        matching_signatures: List[CADSignature] = []
        evidence: Dict[str, Any] = {}

        # Convert header_crc from string to int if needed
        crc_int: Optional[int] = None
        if header_crc is not None:
            if isinstance(header_crc, str):
                # Handle hex string like "0x12345678" or "12345678"
                try:
                    crc_int = int(header_crc, 16) if header_crc.startswith("0x") else int(header_crc, 16)
                except ValueError:
                    crc_int = None
            else:
                crc_int = header_crc

        # Read file content for pattern matching
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            return FingerprintResult(
                detected_application=CADApplication.UNKNOWN,
                confidence=0.0,
                forensic_summary=f"Error reading file: {e}",
            )

        # Check CRC-based signatures
        if crc_int is not None:
            crc_matches = self._check_crc_signatures(crc_int)
            matching_signatures.extend(crc_matches)
            evidence["crc_value"] = f"0x{crc_int:08X}"
            evidence["crc_is_zero"] = crc_int == 0

        # Check string-based signatures
        string_matches = self._check_string_signatures(data)
        matching_signatures.extend(string_matches)

        # Check metadata patterns
        if metadata:
            metadata_matches = self._check_metadata_signatures(metadata)
            matching_signatures.extend(metadata_matches)
            evidence["metadata_analyzed"] = True

        # Determine most likely application
        result = self._determine_application(matching_signatures, evidence)
        result.raw_evidence = evidence

        return result

    def _check_crc_signatures(self, crc: int) -> List[CADSignature]:
        """Check CRC value against known signatures."""
        matches = []
        for sig in self.signatures:
            if sig.pattern_type == "crc" and sig.pattern == crc:
                matches.append(sig)
        return matches

    def _check_string_signatures(self, data: bytes) -> List[CADSignature]:
        """Search for string patterns in file data."""
        matches = []
        for sig in self.signatures:
            if sig.pattern_type == "string" and isinstance(sig.pattern, str):
                # Search for pattern (case-insensitive)
                pattern_bytes = sig.pattern.encode("utf-8", errors="ignore")
                pattern_lower = sig.pattern.lower().encode("utf-8", errors="ignore")

                if pattern_bytes in data or pattern_lower in data.lower():
                    matches.append(sig)
        return matches

    def _check_metadata_signatures(
        self, metadata: Dict[str, Any]
    ) -> List[CADSignature]:
        """Check metadata fields for application signatures."""
        matches = []

        # Fields to check
        check_fields = [
            "lastsavedby",
            "last_saved_by",
            "author",
            "creator",
            "producer",
            "application",
            "comments",
        ]

        for sig in self.signatures:
            if sig.pattern_type == "metadata" and isinstance(sig.pattern, str):
                for field_name in check_fields:
                    field_value = metadata.get(field_name, "")
                    if isinstance(field_value, str):
                        # Check if any app name appears in the field
                        app_name = sig.application.value.lower()
                        if app_name in field_value.lower():
                            matches.append(sig)
                            break

        return matches

    def detect_revit_export(self, file_path: Path) -> Dict[str, Any]:
        """
        Detect if file is a Revit DWG export based on header field patterns.

        Revit exports have unique header signatures discovered through testing:
        - Preview Address: 0x00000120 (others use 0x000001C0)
        - Summary Info Address: 0x00000000 (others use 0x20000000)
        - VBA Project Address: 0x00000000 (others use 0x00000001)

        Args:
            file_path: Path to the DWG file

        Returns:
            Dictionary with detection results
        """
        import struct

        try:
            with open(file_path, "rb") as f:
                header = f.read(0x30)  # Read first 48 bytes
        except Exception as e:
            return {"error": str(e), "is_revit_export": False}

        if len(header) < 0x26:
            return {"error": "Header too short", "is_revit_export": False}

        # Parse header fields
        version = header[0:6].decode('ascii', errors='replace')
        preview_addr = struct.unpack('<I', header[0x0D:0x11])[0]
        summary_addr = struct.unpack('<I', header[0x1D:0x21])[0]
        vba_addr = struct.unpack('<I', header[0x21:0x25])[0]

        # Revit export signature
        is_revit = (
            preview_addr == 0x120 and
            summary_addr == 0x00000000 and
            vba_addr == 0x00000000
        )

        # Additional check: version should be AC1032 (Revit uses 2018+ format)
        is_revit = is_revit and version.startswith("AC1032")

        return {
            "is_revit_export": is_revit,
            "version": version,
            "preview_address": f"0x{preview_addr:08X}",
            "summary_info_address": f"0x{summary_addr:08X}",
            "vba_project_address": f"0x{vba_addr:08X}",
            "header_signature": {
                "preview_is_revit_pattern": preview_addr == 0x120,
                "summary_is_null": summary_addr == 0x00000000,
                "vba_is_null": vba_addr == 0x00000000,
            },
            "forensic_note": (
                "File has Revit DWG export header signature. Revit exports use "
                "Preview Addr=0x120 and null Summary/VBA addresses, unlike "
                "AutoCAD and other applications which use Preview=0x1C0."
            ) if is_revit else None,
        }

    def detect_autocad_origin(self, file_path: Path) -> Dict[str, Any]:
        """
        Detect if file has genuine AutoCAD origin markers.

        This method looks for embedded Autodesk installation paths which are
        strong evidence of genuine AutoCAD origin (found in AC1018 files).

        Args:
            file_path: Path to the DWG file

        Returns:
            Dictionary with detection results
        """
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            return {"error": str(e), "has_autocad_markers": False}

        markers = []

        # Check for Autodesk path strings
        if b"\\Autodesk\\AutoCAD" in data:
            markers.append("Embedded AutoCAD installation path")

        if b"Plot Styles" in data:
            markers.append("AutoCAD Plot Styles reference")

        if b"Autodesk" in data.lower():
            count = data.lower().count(b"autodesk")
            markers.append(f"'Autodesk' string appears {count} time(s)")

        if b"autocad" in data.lower():
            count = data.lower().count(b"autocad")
            markers.append(f"'AutoCAD' string appears {count} time(s)")

        has_markers = len(markers) > 0

        return {
            "has_autocad_markers": has_markers,
            "markers_found": markers,
            "confidence": 0.95 if "installation path" in str(markers) else (
                0.7 if markers else 0.0
            ),
            "forensic_note": (
                "File contains embedded Autodesk/AutoCAD markers which indicate "
                "genuine Autodesk software origin. These paths are embedded in "
                "plot style references and other file metadata."
            ) if has_markers else None,
        }

    def check_timestamp_anomalies(
        self, metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Detect timestamp patterns that indicate third-party CAD tools.

        These patterns are forensically significant because:
        1. TDCREATE == TDUPDATE with zero TDINDWG indicates batch/programmatic creation
        2. Missing FINGERPRINTGUID/VERSIONGUID indicates non-AutoCAD origin
        3. Sequential handle allocation differs from AutoCAD's pattern

        Args:
            metadata: Extracted DWG metadata dictionary

        Returns:
            Dictionary with detected anomalies and forensic significance
        """
        anomalies = {
            "detected": False,
            "patterns": [],
            "likely_third_party": False,
            "forensic_notes": [],
        }

        # Check for TDCREATE == TDUPDATE pattern (QCAD, batch tools)
        tdcreate = metadata.get("tdcreate", metadata.get("TDCREATE"))
        tdupdate = metadata.get("tdupdate", metadata.get("TDUPDATE"))

        if tdcreate is not None and tdupdate is not None:
            if tdcreate == tdupdate and tdcreate != 0:
                anomalies["detected"] = True
                anomalies["patterns"].append("TDCREATE_EQUALS_TDUPDATE")
                anomalies["forensic_notes"].append(
                    "TDCREATE equals TDUPDATE - indicates batch/programmatic creation "
                    "rather than interactive CAD editing (common in QCAD, LibreCAD conversions)"
                )

        # Check for zero TDINDWG (no editing time)
        tdindwg = metadata.get("tdindwg", metadata.get("TDINDWG"))
        if tdindwg is not None and tdindwg == 0:
            anomalies["detected"] = True
            anomalies["patterns"].append("ZERO_TDINDWG")
            anomalies["likely_third_party"] = True
            anomalies["forensic_notes"].append(
                "Zero TDINDWG (editing time) indicates non-interactive file generation - genuine CAD editing "
                "always accumulates time. Common in LibreCAD, QCAD, and converted files."
            )

        # Check for zero timestamps (LibreCAD pattern)
        if tdcreate == 0 and tdupdate == 0:
            anomalies["detected"] = True
            anomalies["patterns"].append("ZERO_TIMESTAMPS")
            anomalies["likely_third_party"] = True
            anomalies["forensic_notes"].append(
                "Both TDCREATE and TDUPDATE are zero - strong indicator of LibreCAD "
                "or other open-source tool that doesn't properly set timestamps."
            )

        # Check for missing GUIDs (QCAD, some ODA-based apps)
        fingerprintguid = metadata.get("fingerprintguid", metadata.get("FINGERPRINTGUID"))
        versionguid = metadata.get("versionguid", metadata.get("VERSIONGUID"))

        if fingerprintguid is None or fingerprintguid == "":
            anomalies["detected"] = True
            anomalies["patterns"].append("MISSING_FINGERPRINTGUID")
            anomalies["forensic_notes"].append(
                "Missing FINGERPRINTGUID - AutoCAD always generates this identifier. "
                "Absence indicates third-party CAD tool origin."
            )

        if versionguid is None or versionguid == "":
            anomalies["detected"] = True
            anomalies["patterns"].append("MISSING_VERSIONGUID")
            anomalies["forensic_notes"].append(
                "Missing VERSIONGUID - AutoCAD always generates version tracking. "
                "Absence indicates third-party tool or programmatic creation."
            )

        # Check codepage for NanoCAD indicator
        codepage = metadata.get("codepage", metadata.get("$DWGCODEPAGE"))
        if codepage and "1251" in str(codepage):
            anomalies["detected"] = True
            anomalies["patterns"].append("CYRILLIC_CODEPAGE")
            anomalies["forensic_notes"].append(
                "CP1251 (Cyrillic) codepage detected - common in NanoCAD files "
                "from Russian developers."
            )

        return anomalies

    def analyze_drawing_variables(
        self, drawing_vars: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze drawing variables extracted from LibreDWG for fingerprinting.

        This method uses data from LibreDWG's dwgread tool to identify the
        authoring application based on forensic header variables.

        Args:
            drawing_vars: Dictionary containing drawing header variables
                         (FINGERPRINTGUID, TDINDWG, HANDSEED, etc.)

        Returns:
            Dictionary with fingerprinting results and forensic notes

        Discovered patterns (2026-01-11):
        - LibreDWG: FINGERPRINTGUID contains "DEAD" (e.g., FDEAD578-...)
        - Revit: TDINDWG near-zero, HANDSEED[1]=3, very few classes
        - Civil 3D: Very high class count (600+), AeccDb classes
        """
        results = {
            "detected_signatures": [],
            "likely_application": None,
            "confidence": 0.0,
            "forensic_notes": [],
            "raw_values": {},
        }

        # =================================================================
        # Check FINGERPRINTGUID for LibreDWG "DEAD" pattern
        # =================================================================
        fingerprint_guid = drawing_vars.get("FINGERPRINTGUID", "")
        if fingerprint_guid:
            results["raw_values"]["FINGERPRINTGUID"] = fingerprint_guid
            if "DEAD" in fingerprint_guid.upper():
                results["detected_signatures"].append("LIBREDWG_DEAD_GUID")
                results["likely_application"] = CADApplication.LIBREDWG
                results["confidence"] = 0.98
                results["forensic_notes"].append(
                    f"FINGERPRINTGUID '{fingerprint_guid}' contains 'DEAD' pattern - "
                    "this is a LibreDWG placeholder value indicating the file was "
                    "created by LibreDWG library."
                )

        # =================================================================
        # Check TDINDWG for Revit export pattern (near-zero editing time)
        # =================================================================
        tdindwg = drawing_vars.get("TDINDWG")
        if tdindwg is not None:
            # TDINDWG is often [days, seconds] or just seconds
            if isinstance(tdindwg, list) and len(tdindwg) >= 2:
                edit_time = tdindwg[1]  # Seconds component
            else:
                edit_time = tdindwg

            results["raw_values"]["TDINDWG"] = tdindwg

            if isinstance(edit_time, (int, float)) and edit_time < 2000:
                # Less than 2000 seconds (~33 minutes) indicates automated generation
                # Revit exports have ~1000 (~16 seconds)
                results["detected_signatures"].append("REVIT_NEAR_ZERO_TDINDWG")
                if results["likely_application"] is None:
                    results["likely_application"] = CADApplication.REVIT_EXPORT
                    results["confidence"] = max(results["confidence"], 0.75)
                results["forensic_notes"].append(
                    f"TDINDWG={edit_time} (~{edit_time/60000:.3f} minutes) is extremely low. "
                    "This suggests the file was exported/generated, not interactively edited. "
                    "Revit exports typically have TDINDWG ~1000."
                )

        # =================================================================
        # Check HANDSEED for Revit pattern (second element = 3)
        # =================================================================
        handseed = drawing_vars.get("HANDSEED")
        if handseed is not None:
            results["raw_values"]["HANDSEED"] = handseed
            if isinstance(handseed, list) and len(handseed) >= 2:
                if handseed[1] == 3:
                    results["detected_signatures"].append("REVIT_HANDSEED_PATTERN")
                    if results["likely_application"] is None:
                        results["likely_application"] = CADApplication.REVIT_EXPORT
                    results["confidence"] = max(results["confidence"], 0.85)
                    results["forensic_notes"].append(
                        f"HANDSEED[1]={handseed[1]} - Revit exports use 3, while AutoCAD "
                        "and other applications typically use 2. This is a reliable Revit indicator."
                    )
                elif handseed[1] == 2:
                    results["forensic_notes"].append(
                        f"HANDSEED[1]={handseed[1]} - Standard value (AutoCAD, Civil 3D, LibreDWG)"
                    )

        # =================================================================
        # Check class count for application fingerprinting
        # =================================================================
        class_count = drawing_vars.get("class_count")
        if class_count is not None:
            results["raw_values"]["class_count"] = class_count

            if class_count <= 15:
                results["detected_signatures"].append("REVIT_LOW_CLASS_COUNT")
                if results["likely_application"] is None:
                    results["likely_application"] = CADApplication.REVIT_EXPORT
                results["confidence"] = max(results["confidence"], 0.70)
                results["forensic_notes"].append(
                    f"Class count={class_count} is very low. Revit exports typically have ~10 "
                    "classes. Native AutoCAD has 90-100+, Civil 3D has 600+."
                )
            elif class_count >= 400:
                results["detected_signatures"].append("CIVIL3D_HIGH_CLASS_COUNT")
                if results["likely_application"] is None or results["likely_application"] == CADApplication.REVIT_EXPORT:
                    results["likely_application"] = CADApplication.AUTOCAD_CIVIL3D
                results["confidence"] = max(results["confidence"], 0.80)
                results["forensic_notes"].append(
                    f"Class count={class_count} indicates Civil 3D or AEC application "
                    "with specialized civil engineering object types."
                )
            elif 50 <= class_count <= 200:
                results["forensic_notes"].append(
                    f"Class count={class_count} is typical for standard AutoCAD files."
                )

        # =================================================================
        # Check object count to class count ratio
        # =================================================================
        object_count = drawing_vars.get("object_count")
        if object_count is not None and class_count is not None and class_count > 0:
            ratio = object_count / class_count
            results["raw_values"]["object_count"] = object_count
            results["raw_values"]["object_to_class_ratio"] = ratio

            if ratio > 1000:
                results["forensic_notes"].append(
                    f"Object/class ratio={ratio:.0f} is very high. "
                    "Revit exports have high ratios due to many objects using few classes."
                )

        # Set default if nothing detected
        if results["likely_application"] is None:
            results["likely_application"] = CADApplication.UNKNOWN
            results["confidence"] = 0.3

        return results

    def detect_oda_based(self, file_path: Path) -> Dict[str, Any]:
        """
        Detect if file was created by an ODA SDK-based application.

        ODA-based applications share common characteristics that distinguish
        them from genuine AutoCAD files.

        Args:
            file_path: Path to the DWG file

        Returns:
            Dictionary with ODA detection results
        """
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            return {"error": str(e), "is_oda_based": False}

        oda_indicators = []

        # Check for ODA class name prefixes
        if b"OdDb" in data:
            oda_indicators.append("OdDb class prefix detected")

        # Check for Teigha markers (legacy ODA name)
        if b"Teigha" in data or b"TEIGHA" in data:
            oda_indicators.append("Teigha/legacy ODA marker detected")

        # Check for DWGdirect markers
        if b"DWGdirect" in data:
            oda_indicators.append("DWGdirect library marker detected")

        # Check for Open Design Alliance text
        if b"Open Design" in data:
            oda_indicators.append("Open Design Alliance marker detected")

        # Check for specific ODA-based application markers
        app_markers = {
            b"BRICSYS": "BricsCAD",
            b"BricsCAD": "BricsCAD",
            b"NANOCAD": "NanoCAD",
            b"nanoCAD": "NanoCAD",
            b"Nanosoft": "NanoCAD",
            b"DRAFTSIGHT": "DraftSight",
            b"DraftSight": "DraftSight",
            b"ZWCAD": "ZWCAD",
            b"GstarCAD": "GstarCAD",
            b"progeCAD": "progeCAD",
            b"IntelliCAD": "IntelliCAD",
            b"CorelCAD": "CorelCAD",
        }

        detected_apps = []
        for marker, app_name in app_markers.items():
            if marker in data:
                detected_apps.append(app_name)
                oda_indicators.append(f"{app_name} application marker detected")

        is_oda = len(oda_indicators) > 0

        return {
            "is_oda_based": is_oda,
            "indicators": oda_indicators,
            "detected_applications": list(set(detected_apps)),
            "forensic_significance": (
                "ODA-based applications may not maintain Autodesk timestamp integrity. "
                "Files created by these tools should be examined for timestamp manipulation."
            ) if is_oda else None,
        }

    def _determine_application(
        self,
        signatures: List[CADSignature],
        evidence: Dict[str, Any],
    ) -> FingerprintResult:
        """Determine most likely application from matching signatures."""

        if not signatures:
            # No signature matches - unable to determine application
            return FingerprintResult(
                detected_application=CADApplication.UNKNOWN,
                confidence=0.3,
                forensic_summary="Unable to identify specific CAD application",
            )

        # Count votes by application with confidence weighting
        votes: Dict[CADApplication, float] = {}
        for sig in signatures:
            app = sig.application
            current_vote = votes.get(app, 0.0)
            votes[app] = current_vote + sig.confidence

        # Find highest confidence application
        best_app = max(votes, key=lambda x: votes[x])
        total_confidence = votes[best_app]

        # Normalize confidence to 0-1
        confidence = min(total_confidence / len(signatures), 1.0)

        # Check if ODA-based
        is_oda = best_app in self.ODA_BASED_APPS or any(
            sig.application == CADApplication.ODA_SDK for sig in signatures
        )

        # Generate forensic summary
        summary_parts = []
        for sig in signatures:
            summary_parts.append(f"- {sig.description}: {sig.forensic_note}")

        forensic_summary = f"Detected: {best_app.value}\n" + "\n".join(summary_parts)

        return FingerprintResult(
            detected_application=best_app,
            confidence=confidence,
            matching_signatures=signatures,
            is_autodesk=(best_app == CADApplication.AUTOCAD),
            is_oda_based=is_oda,
            forensic_summary=forensic_summary,
        )

    def get_forensic_report(self, result: FingerprintResult) -> str:
        """Generate a forensic report from fingerprinting results."""
        lines = [
            "=" * 60,
            "CAD APPLICATION FINGERPRINTING REPORT",
            "=" * 60,
            "",
            f"Detected Application: {result.detected_application.value.upper()}",
            f"Confidence: {result.confidence:.0%}",
            f"Is Autodesk Product: {'Yes' if result.is_autodesk else 'No'}",
            f"Uses ODA SDK: {'Yes' if result.is_oda_based else 'No/Unknown'}",
            "",
            "MATCHING SIGNATURES:",
            "-" * 40,
        ]

        if result.matching_signatures:
            for sig in result.matching_signatures:
                lines.append(f"  [{sig.pattern_type.upper()}] {sig.description}")
                lines.append(f"    Confidence: {sig.confidence:.0%}")
                if sig.forensic_note:
                    lines.append(f"    Note: {sig.forensic_note}")
                lines.append("")
        else:
            lines.append("  No specific signatures detected")
            lines.append("")

        lines.extend([
            "FORENSIC SIGNIFICANCE:",
            "-" * 40,
        ])

        if not result.is_autodesk:
            lines.extend([
                "  [!] File was NOT created by genuine Autodesk software",
                "  [!] Third-party CAD applications may not maintain timestamp integrity",
                "  [!] CRC and metadata may have been handled differently than AutoCAD",
                "",
            ])

        if result.is_oda_based:
            lines.extend([
                "  [i] Application uses ODA (Open Design Alliance) SDK",
                "  [i] ODA-based apps produce DWG files with known differences from AutoCAD",
                "",
            ])

        lines.append("=" * 60)

        return "\n".join(lines)


# Convenience function for quick fingerprinting
def fingerprint_dwg(
    file_path: Path,
    header_crc: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> FingerprintResult:
    """
    Convenience function to fingerprint a DWG file.

    Args:
        file_path: Path to the DWG file
        header_crc: Pre-extracted header CRC value
        metadata: Pre-extracted metadata dictionary

    Returns:
        FingerprintResult with detected application and forensic details
    """
    fingerprinter = CADFingerprinter()
    return fingerprinter.fingerprint(
        file_path=file_path,
        header_crc=header_crc,
        metadata=metadata,
    )
