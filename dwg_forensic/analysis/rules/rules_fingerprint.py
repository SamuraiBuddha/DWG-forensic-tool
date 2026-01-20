"""
DWG Forensic Tool - CAD Fingerprinting Rules (TAMPER-029 to TAMPER-035)

Detection of third-party CAD application signatures and artifacts.
"""

from typing import Any, Dict

from dwg_forensic.analysis.rules.models import (
    RuleResult,
    RuleStatus,
    TamperingRule,
)


class FingerprintRulesMixin:
    """Mixin providing TAMPER-029 through TAMPER-036 check implementations."""

    # Revit/ODA export GUID signature: "30314341-" = ASCII "01CA"
    REVIT_GUID_PREFIX = "30314341-"

    def _get_forensic_meta(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get forensic_meta from context safely."""
        return context.get("forensic_meta", {})

    def _check_trusted_dwg_authenticity(self, context: Dict[str, Any]) -> bool:
        """Check if TrustedDWG confirms Autodesk application."""
        meta = self._get_forensic_meta(context)
        trusted = meta.get("trusted_dwg", {})
        return trusted.get("autodesk_app", False)

    def _check_revit_export(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Detect Revit export based on multiple signatures.

        Returns dict with:
            is_revit: bool - True if Revit export detected
            confidence: float - Detection confidence (0.0-1.0)
            indicators: list - List of indicators found
            forensic_note: str - Explanation of findings
        """
        indicators = []
        confidence = 0.0

        # Check revit_detection from analyzer
        revit_detection = context.get("revit_detection", {})
        if revit_detection.get("is_revit_export"):
            indicators.append("revit_detector_positive")
            confidence = max(confidence, revit_detection.get("confidence_score", 0.7))

        # Check FINGERPRINTGUID for "30314341-" pattern (ASCII "01CA")
        metadata = context.get("metadata", {})
        fingerprint_guid = metadata.get("fingerprintguid") or metadata.get("fingerprint_guid", "")
        if fingerprint_guid and str(fingerprint_guid).upper().startswith(self.REVIT_GUID_PREFIX):
            indicators.append("guid_01ca_pattern")
            confidence = max(confidence, 0.92)

        # Check forensic_meta for Revit product name
        meta = self._get_forensic_meta(context)
        app_info = meta.get("app_info", {})
        product_name = (app_info.get("product_name") or "").lower()
        if "revit" in product_name:
            indicators.append("product_name_revit")
            confidence = max(confidence, 0.95)

        # Check cad_fingerprint for Revit detection
        fingerprint = context.get("cad_fingerprint", {})
        detected_app = fingerprint.get("detected_application", "")
        if detected_app.lower() in ["revit_export", "revit"]:
            indicators.append("fingerprint_revit")
            confidence = max(confidence, 0.85)

        # Check for Revit signatures in drawing vars analysis
        detected_sigs = fingerprint.get("detected_signatures", [])
        revit_sigs = [s for s in detected_sigs if "REVIT" in s.upper()]
        if revit_sigs:
            indicators.extend(revit_sigs)
            confidence = max(confidence, 0.80)

        # Check CRC validation for Revit flag
        crc = context.get("crc_validation", {})
        if crc.get("is_revit_export"):
            indicators.append("crc_revit_flag")
            confidence = max(confidence, 0.75)

        is_revit = len(indicators) > 0 and confidence >= 0.5

        forensic_note = ""
        if is_revit:
            forensic_note = (
                f"Revit export detected (confidence: {confidence:.0%}). "
                f"Indicators: {', '.join(indicators)}. "
                "Revit exports have EXPECTED characteristics: zero CRC, "
                "missing TDCREATE/TDUPDATE, and malformed GUIDs. "
                "These are NOT tampering indicators."
            )

        return {
            "is_revit": is_revit,
            "confidence": confidence,
            "indicators": indicators,
            "forensic_note": forensic_note,
        }

    def _check_oda_sdk_artifacts(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-029: ODA SDK Artifact Detection.

        Detects artifacts from the Open Design Alliance SDK, which is the
        foundation for many non-Autodesk CAD applications.
        """
        fingerprint = context.get("cad_fingerprint", {})
        oda_detection = context.get("oda_detection", {})

        is_oda = fingerprint.get("is_oda_based", False) or oda_detection.get("is_oda_based", False)

        # Check forensic_meta for ODA product names
        meta = self._get_forensic_meta(context)
        app_info = meta.get("app_info", {})
        product_name = (app_info.get("product_name") or "").lower()
        oda_products = ["bricscad", "draftsight", "nanocad", "librecad", "zwcad", "ares"]
        from_product = any(p in product_name for p in oda_products)
        is_oda = is_oda or from_product
        indicators = oda_detection.get("indicators", [])
        detected_apps = oda_detection.get("detected_applications", [])

        if not is_oda:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] No ODA SDK artifacts detected",
                confidence=1.0,
            )

        app_list = ", ".join(detected_apps) if detected_apps else "Unknown ODA-based app"
        # ODA SDK-based applications are LEGITIMATE CAD software
        # Detection is informational, not evidence of tampering
        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.PASSED,  # Changed from FAILED - legitimate software
            severity=rule.severity,
            description=f"[OK] File created by ODA SDK-based software: {app_list}",
            confidence=1.0,
            details={
                "is_oda_based": True,
                "indicators": indicators,
                "detected_applications": detected_apps,
                "forensic_note": (
                    "ODA SDK-based applications (BricsCAD, DraftSight, NanoCAD, etc.) are "
                    "legitimate CAD software. They create valid DWG files but may not include "
                    "AutoCAD-specific metadata. This is expected behavior, not tampering."
                ),
            },
        )

    def _check_bricscad_signature(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-030: BricsCAD Signature Detection.

        Detects BRICSYS APPID and ACAD_BRICSCAD_INFO dictionary entries.
        """
        fingerprint = context.get("cad_fingerprint", {})
        detected_app = fingerprint.get("detected_application", "")

        # Check for BricsCAD detection
        is_bricscad = detected_app.lower() == "bricscad"

        # Also check binary markers in raw_evidence
        raw_evidence = fingerprint.get("raw_evidence", {})
        bricscad_markers = raw_evidence.get("bricscad_markers", [])

        # Check forensic_meta for BricsCAD
        meta = self._get_forensic_meta(context)
        app_info = meta.get("app_info", {})
        product_name = (app_info.get("product_name") or "").lower()
        from_product = "bricscad" in product_name or "bricsys" in product_name

        if not is_bricscad and not bricscad_markers and not from_product:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] No BricsCAD signatures detected",
                confidence=1.0,
            )

        # BricsCAD is a LEGITIMATE CAD application - detection is informational
        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.PASSED,  # Changed from FAILED - legitimate software
            severity=rule.severity,
            description="[OK] File created by BricsCAD (legitimate CAD software)",
            confidence=1.0,
            details={
                "application": "BricsCAD",
                "vendor": "Bricsys",
                "markers": bricscad_markers,
                "forensic_note": (
                    "BricsCAD is a legitimate ODA-based CAD application by Bricsys. "
                    "It creates valid DWG files but may not include AutoCAD-specific metadata "
                    "like TDINDWG or TrustedDWG watermarks. This is expected behavior."
                ),
            },
        )

    def _check_nanocad_signature(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-031: NanoCAD Signature Detection.

        Detects NANOCAD APPID and CP1251 codepage indicators.
        """
        fingerprint = context.get("cad_fingerprint", {})
        metadata = context.get("metadata", {})

        detected_app = fingerprint.get("detected_application", "")
        is_nanocad = detected_app.lower() == "nanocad"

        # Check for Cyrillic codepage
        codepage = metadata.get("codepage", "")
        has_cyrillic = "1251" in str(codepage)

        # Check forensic_meta for NanoCAD
        meta = self._get_forensic_meta(context)
        app_info = meta.get("app_info", {})
        product_name = (app_info.get("product_name") or "").lower()
        from_product = "nanocad" in product_name or "nanosoft" in product_name

        if not is_nanocad and not has_cyrillic and not from_product:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] No NanoCAD signatures detected",
                confidence=1.0,
            )

        details = {
            "application": "NanoCAD",
            "vendor": "Nanosoft",
            "origin": "Russia",
            "forensic_note": (
                "NanoCAD is a legitimate ODA-based CAD application by Nanosoft. "
                "It creates valid DWG files but may not include AutoCAD-specific metadata. "
                "Files may contain Cyrillic text in CP1251 encoding."
            ),
        }

        if has_cyrillic:
            details["codepage"] = codepage
            details["cyrillic_indicator"] = True

        # NanoCAD is a LEGITIMATE CAD application - detection is informational
        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.PASSED,  # Changed from FAILED - legitimate software
            severity=rule.severity,
            description="[OK] File created by NanoCAD (legitimate CAD software)",
            confidence=1.0,
            details=details,
        )

    def _check_draftsight_signature(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-032: DraftSight Signature Detection.

        Detects DRAFTSIGHT APPID and DS_LICENSE_TYPE custom property.
        """
        fingerprint = context.get("cad_fingerprint", {})
        metadata = context.get("metadata", {})

        detected_app = fingerprint.get("detected_application", "")
        is_draftsight = detected_app.lower() == "draftsight"

        # Check for DraftSight license type property
        license_type = metadata.get("DS_LICENSE_TYPE", metadata.get("ds_license_type"))

        # Check forensic_meta for DraftSight
        meta = self._get_forensic_meta(context)
        app_info = meta.get("app_info", {})
        product_name = (app_info.get("product_name") or "").lower()
        from_product = "draftsight" in product_name or "dassault" in product_name

        if not is_draftsight and not license_type and not from_product:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] No DraftSight signatures detected",
                confidence=1.0,
            )

        details = {
            "application": "DraftSight",
            "vendor": "Dassault Systemes",
            "forensic_note": (
                "DraftSight is a legitimate ODA-based CAD application by Dassault Systemes. "
                "It creates valid DWG files but may not include AutoCAD-specific metadata. "
                "Free version was discontinued in 2019."
            ),
        }

        if license_type:
            details["license_type"] = license_type

        # DraftSight is a LEGITIMATE CAD application - detection is informational
        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.PASSED,  # Changed from FAILED - legitimate software
            severity=rule.severity,
            description="[OK] File created by DraftSight (legitimate CAD software)",
            confidence=1.0,
            details=details,
        )

    def _check_opensource_cad_conversion(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-033: Open Source CAD Conversion Detection.

        Detects LibreCAD, QCAD, and FreeCAD conversion artifacts.
        These tools primarily work with DXF and convert to DWG.
        """
        fingerprint = context.get("cad_fingerprint", {})
        timestamp_anomalies = context.get("timestamp_anomalies", {})

        detected_app = fingerprint.get("detected_application", "")
        is_opensource = detected_app.lower() in ["librecad", "qcad", "freecad", "libredwg"]

        # Check for open source indicators
        patterns = timestamp_anomalies.get("patterns", [])
        opensource_patterns = [
            p for p in patterns
            if p in ["ZERO_TIMESTAMPS", "ZERO_TDINDWG", "TDCREATE_EQUALS_TDUPDATE"]
        ]

        if not is_opensource and not opensource_patterns:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] No open source CAD conversion artifacts detected",
                confidence=1.0,
            )

        forensic_notes = timestamp_anomalies.get("forensic_notes", [])

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=(
                f"[WARN] Open source CAD artifacts detected: "
                f"{detected_app.upper() if is_opensource else 'conversion patterns'}"
            ),
            confidence=0.85,
            details={
                "detected_application": detected_app if is_opensource else "Unknown",
                "conversion_patterns": opensource_patterns,
                "forensic_notes": forensic_notes,
                "forensic_significance": (
                    "Open source CAD tools (LibreCAD, QCAD, FreeCAD) do not create "
                    "native DWG files directly. Files with these artifacts were "
                    "converted from DXF or processed by external conversion tools, "
                    "which may not preserve timestamp integrity."
                ),
            },
        )

    def _check_zero_timestamp_pattern(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-034: Zero Timestamp Pattern Detection.

        Detects when TDCREATE and TDUPDATE are both zero or identical
        with zero TDINDWG - a strong indicator of programmatic generation.

        NOTE: ODA SDK-based files and Revit exports may have zero timestamps.
        This is EXPECTED for these legitimate CAD applications, not evidence of tampering.
        """
        # Check for Revit export - zero timestamps are EXPECTED
        revit_check = self._check_revit_export(context)
        if revit_check["is_revit"]:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] Zero/missing timestamps expected for Revit exports",
                confidence=1.0,
                details={
                    "is_revit_export": True,
                    "revit_indicators": revit_check["indicators"],
                    "forensic_note": revit_check["forensic_note"],
                },
            )

        # Check for ODA SDK files - zero timestamps may be EXPECTED
        structure = context.get("structure_analysis", {})
        structure_type = structure.get("structure_type", "")
        detected_tool = structure.get("detected_tool", "unknown")
        is_oda_based = structure.get("is_oda_based", False)

        fingerprint = context.get("application_fingerprint", {})
        if not is_oda_based:
            is_oda_based = fingerprint.get("is_oda_based", False)

        if is_oda_based or structure_type == "non_autocad":
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description=f"[OK] Zero timestamp patterns expected for ODA SDK files ({detected_tool})",
                confidence=1.0,
                details={
                    "detected_tool": detected_tool,
                    "is_oda_based": True,
                    "structure_type": structure_type,
                    "forensic_note": (
                        "ODA SDK-based applications may not fully populate timestamp fields. "
                        "Zero or identical timestamps are expected behavior for these legitimate "
                        "CAD applications, not evidence of manipulation."
                    ),
                },
            )

        timestamp_data = context.get("timestamp_data", {})
        metadata = context.get("metadata", {})
        timestamp_anomalies = context.get("timestamp_anomalies", {})

        # Get timestamp values (must use 'is None' check since 0 is valid)
        tdcreate = timestamp_data.get("tdcreate")
        if tdcreate is None:
            tdcreate = metadata.get("tdcreate")
        tdupdate = timestamp_data.get("tdupdate")
        if tdupdate is None:
            tdupdate = metadata.get("tdupdate")
        tdindwg = timestamp_data.get("tdindwg")
        if tdindwg is None:
            tdindwg = metadata.get("tdindwg")

        # Check for patterns already detected
        patterns = timestamp_anomalies.get("patterns", [])

        zero_pattern = False
        pattern_details = []

        # Check for zero timestamps
        if tdcreate == 0 and tdupdate == 0:
            zero_pattern = True
            pattern_details.append("Both TDCREATE and TDUPDATE are zero")

        # Check for identical timestamps with zero edit time
        if tdcreate is not None and tdupdate is not None:
            if tdcreate == tdupdate and tdcreate != 0 and tdindwg == 0:
                zero_pattern = True
                pattern_details.append("TDCREATE equals TDUPDATE with zero TDINDWG")

        # Also check timestamp_anomalies
        if "ZERO_TIMESTAMPS" in patterns or "ZERO_TDINDWG" in patterns:
            zero_pattern = True

        if not zero_pattern:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] No zero timestamp patterns detected",
                confidence=1.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description="[WARN] Zero timestamp pattern detected - programmatic generation likely",
            confidence=0.9,
            details={
                "pattern_details": pattern_details,
                "tdcreate": tdcreate,
                "tdupdate": tdupdate,
                "tdindwg": tdindwg,
                "forensic_significance": (
                    "Zero or identical timestamps with no editing time is impossible "
                    "for legitimately created CAD drawings. This pattern indicates "
                    "programmatic file generation (LibreCAD, QCAD, conversion tools) "
                    "or deliberate timestamp manipulation."
                ),
            },
        )

    def _check_missing_autocad_identifiers(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-035: Missing AutoCAD Identifiers Detection.

        AutoCAD always generates FINGERPRINTGUID and VERSIONGUID.
        Their absence indicates third-party CAD tool origin.

        NOTE: ODA SDK-based files (BricsCAD, DraftSight, etc.) do NOT generate
        these identifiers. This is EXPECTED for these legitimate CAD applications.
        """
        # Check for ODA SDK files - missing identifiers is EXPECTED
        structure = context.get("structure_analysis", {})
        structure_type = structure.get("structure_type", "")
        detected_tool = structure.get("detected_tool", "unknown")
        is_oda_based = structure.get("is_oda_based", False)

        fingerprint = context.get("application_fingerprint", {})
        if not is_oda_based:
            is_oda_based = fingerprint.get("is_oda_based", False)

        if is_oda_based or structure_type == "non_autocad":
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description=f"[OK] Missing AutoCAD identifiers is normal for ODA SDK files ({detected_tool})",
                confidence=1.0,
                details={
                    "detected_tool": detected_tool,
                    "is_oda_based": True,
                    "structure_type": structure_type,
                    "forensic_note": (
                        "ODA SDK-based applications do not generate FINGERPRINTGUID and "
                        "VERSIONGUID identifiers. This is expected behavior for legitimate "
                        "third-party CAD applications, not evidence of tampering."
                    ),
                },
            )

        metadata = context.get("metadata", {})
        timestamp_anomalies = context.get("timestamp_anomalies", {})

        # If no metadata was extracted, we can't make a determination - pass
        if not metadata:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] Metadata not available - cannot check AutoCAD identifiers",
                confidence=0.5,
            )

        # Get GUID values
        fingerprintguid = metadata.get("fingerprintguid", metadata.get("FINGERPRINTGUID"))
        versionguid = metadata.get("versionguid", metadata.get("VERSIONGUID"))

        # Check patterns from timestamp_anomalies
        patterns = timestamp_anomalies.get("patterns", [])

        missing_identifiers = []

        null_guid = "{00000000-0000-0000-0000-000000000000}"
        if fingerprintguid is None or fingerprintguid == "" or fingerprintguid == null_guid:
            missing_identifiers.append("FINGERPRINTGUID")

        if versionguid is None or versionguid == "" or versionguid == null_guid:
            missing_identifiers.append("VERSIONGUID")

        # Also check from patterns
        if "MISSING_FINGERPRINTGUID" in patterns:
            if "FINGERPRINTGUID" not in missing_identifiers:
                missing_identifiers.append("FINGERPRINTGUID")
        if "MISSING_VERSIONGUID" in patterns:
            if "VERSIONGUID" not in missing_identifiers:
                missing_identifiers.append("VERSIONGUID")

        if not missing_identifiers:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] AutoCAD identifiers (FINGERPRINTGUID, VERSIONGUID) present",
                confidence=1.0,
            )

        # Cross-validate with TrustedDWG
        is_autodesk = self._check_trusted_dwg_authenticity(context)
        confidence = 0.85
        description = f"[WARN] Missing AutoCAD identifiers: {', '.join(missing_identifiers)}"

        if is_autodesk and missing_identifiers:
            # SUSPICIOUS: TrustedDWG says Autodesk but identifiers missing
            description = f"[CRITICAL] TrustedDWG confirms Autodesk but identifiers missing: {', '.join(missing_identifiers)}"
            confidence = 0.95

        # Check for Revit export - missing identifiers are EXPECTED
        revit_check = self._check_revit_export(context)
        if revit_check["is_revit"]:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] Missing AutoCAD identifiers expected for Revit export",
                confidence=1.0,
                details={
                    "is_revit_export": True,
                    "revit_indicators": revit_check["indicators"],
                    "revit_confidence": revit_check["confidence"],
                    "forensic_note": revit_check["forensic_note"],
                },
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=description,
            confidence=confidence,
            details={
                "missing_identifiers": missing_identifiers,
                "fingerprintguid": fingerprintguid,
                "versionguid": versionguid,
                "forensic_significance": (
                    "AutoCAD always generates unique FINGERPRINTGUID and VERSIONGUID "
                    "identifiers for every file. Their absence is definitive proof "
                    "the file was not created by genuine AutoCAD software."
                ),
            },
        )

    def _check_revit_export_signature(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-036: Revit Export Signature Detection.

        Detects Autodesk Revit DWG exports by multiple signatures:
        - FINGERPRINTGUID starting with "30314341-" (ASCII "01CA")
        - Zero CRC (Revit doesn't compute CRC during export)
        - Missing TDCREATE/TDUPDATE timestamps
        - Revit-specific object classes

        FORENSIC IMPORTANCE: Revit exports are LEGITIMATE files that have
        characteristics that may appear suspicious (zero CRC, missing timestamps,
        malformed GUIDs). This detection PREVENTS FALSE POSITIVES.
        """
        revit_check = self._check_revit_export(context)

        if not revit_check["is_revit"]:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] No Revit export signatures detected",
                confidence=1.0,
            )

        # Revit export detected - this is INFORMATIONAL, not a failure
        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.PASSED,  # PASSED because Revit is legitimate
            severity=rule.severity,
            description=(
                f"[INFO] Revit export detected (confidence: {revit_check['confidence']:.0%})"
            ),
            confidence=revit_check["confidence"],
            details={
                "is_revit_export": True,
                "indicators": revit_check["indicators"],
                "forensic_note": revit_check["forensic_note"],
                "expected_characteristics": [
                    "Zero CRC (0x00000000) - Revit does not compute CRC",
                    "Missing TDCREATE/TDUPDATE - Revit does not set creation timestamps",
                    "FINGERPRINTGUID with '30314341-' prefix (ASCII '01CA')",
                    "Malformed VERSIONGUID format",
                ],
                "forensic_conclusion": (
                    "This file is a legitimate Revit DWG export. "
                    "The characteristics that appear suspicious (zero CRC, missing timestamps) "
                    "are EXPECTED and NORMAL for Revit exports. "
                    "These are NOT indicators of tampering."
                ),
            },
        )
