"""
DWG Forensic Tool - Basic Tampering Rules (TAMPER-001 to TAMPER-012)

Core integrity checks covering CRC validation and basic timestamp anomalies.

These rules now use provenance-aware tolerance profiles to reduce false positives
while maintaining detection accuracy for genuine tampering.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from dwg_forensic.analysis.rules.models import (
    RuleResult,
    RuleSeverity,
    RuleStatus,
    TamperingRule,
)


class BasicRulesMixin:
    """Mixin providing TAMPER-001 through TAMPER-012 check implementations."""

    def _check_header_crc(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-001: Check header CRC.

        CRC=0x00000000 is NORMAL for:
        - Revit exports (Revit doesn't compute CRC during export)
        - ODA SDK-based software (BricsCAD, DraftSight, NanoCAD, etc.)

        These are NOT indications of tampering.
        """
        # Support both context formats
        crc = context.get("crc") or context.get("crc_validation", {})

        if not crc:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="No CRC data available",
                confidence=0.0,
            )

        is_valid = crc.get("is_valid", True)
        stored = crc.get("header_crc_stored", "")
        calculated = crc.get("header_crc_calculated", "")
        forensic_notes = crc.get("forensic_notes", "")
        is_revit = crc.get("is_revit_export", False)
        is_oda = crc.get("is_oda_export", False)

        # Check structure analysis for ODA detection (more reliable than CRC-based detection)
        structure = context.get("structure_analysis", {})
        structure_type = structure.get("structure_type", "")
        detected_tool = structure.get("detected_tool", "unknown")

        # CRC=0 is NORMAL for ODA SDK files - NOT tampering
        if stored == "0x00000000" and (structure_type == "non_autocad" or is_oda):
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description=f"[OK] CRC=0 is normal for ODA SDK-based software ({detected_tool})",
                expected=stored,
                found=calculated,
                confidence=1.0,
                details={
                    "detected_tool": detected_tool,
                    "is_oda_based": True,
                    "structure_type": structure_type,
                    "forensic_note": "ODA SDK-based applications (BricsCAD, DraftSight, etc.) "
                                     "do not compute CRC checksums. CRC=0 is expected and "
                                     "is NOT an indication of tampering.",
                },
            )

        # CRC=0 is NORMAL for Revit exports - NOT tampering
        if stored == "0x00000000" and is_revit:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] CRC=0 is normal for Revit DWG exports",
                expected=stored,
                found=calculated,
                confidence=1.0,
                details={
                    "is_revit_export": True,
                    "forensic_note": "Revit does not compute CRC checksums during DWG export. "
                                     "CRC=0 is expected and is NOT an indication of tampering.",
                },
            )

        if is_valid:
            # Include forensic context if CRC didn't match but was marked valid (e.g., Revit)
            if stored != calculated and forensic_notes:
                return RuleResult(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    status=RuleStatus.PASSED,
                    severity=rule.severity,
                    description=f"[OK] CRC validation passed - {forensic_notes}",
                    expected=stored,
                    found=calculated,
                    confidence=1.0,
                    details={"is_revit_export": is_revit, "forensic_notes": forensic_notes},
                )
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] Header CRC32 checksum is valid",
                expected=stored,
                found=calculated,
                confidence=1.0,
            )

        # CRC mismatch - include forensic context if available
        description = "[FAIL] Header CRC32 mismatch - file modified after last save"
        if forensic_notes:
            description = f"[FAIL] {forensic_notes}"

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=description,
            expected=stored,
            found=calculated,
            confidence=1.0,
            details={"tampering_indicator": "crc_mismatch", "forensic_notes": forensic_notes},
        )

    def _check_section_crc(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-002: Check section CRCs."""
        crc = context.get("crc") or context.get("crc_validation", {})
        sections = crc.get("section_results", [])

        failed = [s for s in sections if not s.get("is_valid", True)]

        if not failed:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] All section CRCs valid",
                confidence=1.0,
            )

        names = ", ".join(s.get("section_name", "?") for s in failed)
        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=f"[FAIL] Section CRC mismatch: {names}",
            confidence=1.0,
            details={"failed_sections": failed},
        )

    def _check_timestamp_reversal(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-005: Check for timestamp reversal."""
        metadata = context.get("metadata", {})

        created = metadata.get("created_date") if metadata else None
        modified = metadata.get("modified_date") if metadata else None

        if not created or not modified:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="Timestamp data not available",
                confidence=0.0,
            )

        # Parse if strings
        if isinstance(created, str):
            created = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if isinstance(modified, str):
            modified = datetime.fromisoformat(modified.replace("Z", "+00:00"))

        if created <= modified:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] Timestamps in correct order",
                confidence=1.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description="[FAIL] Created date after modified date",
            expected="Created <= Modified",
            found=f"Created: {created}, Modified: {modified}",
            confidence=1.0,
        )

    def _check_future_timestamp(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-006: Check for future timestamp.

        Uses provenance-aware tolerance for clock skew grace period.
        """
        metadata = context.get("metadata", {})
        modified = metadata.get("modified_date") if metadata else None

        if not modified:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="Modified timestamp not available",
                confidence=0.0,
            )

        if isinstance(modified, str):
            modified = datetime.fromisoformat(modified.replace("Z", "+00:00"))

        now = datetime.now(timezone.utc)
        if modified.tzinfo is None:
            modified = modified.replace(tzinfo=timezone.utc)

        if modified <= now:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] Modified timestamp not in future",
                confidence=1.0,
            )

        delta = (modified - now).total_seconds()

        # Grace period for clock skew - use tolerance profile
        profile = self.get_tolerance()
        grace_period_seconds = profile.time_window_minutes * 60

        if delta <= grace_period_seconds:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description=f"[OK] {delta:.0f}s future (within {grace_period_seconds:.0f}s grace period)",
                confidence=0.5,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=f"[FAIL] Modified date {delta:.0f}s in future",
            expected=f"Modified <= {now.isoformat()}",
            found=f"Modified: {modified.isoformat()}",
            confidence=1.0,
        )

    def _check_edit_time(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-007: Check edit time consistency.

        Uses provenance-aware tolerance for edit time padding.
        Revit exports may show higher variance due to background processing.
        """
        metadata = context.get("metadata", {})

        created = metadata.get("created_date") if metadata else None
        modified = metadata.get("modified_date") if metadata else None
        edit_hours = metadata.get("total_editing_time_hours") if metadata else None

        if not all([created, modified, edit_hours is not None]):
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="Insufficient data for edit time check",
                confidence=0.0,
            )

        if isinstance(created, str):
            created = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if isinstance(modified, str):
            modified = datetime.fromisoformat(modified.replace("Z", "+00:00"))

        span_hours = (modified - created).total_seconds() / 3600

        # Use tolerance profile for padding
        profile = self.get_tolerance()
        tolerance_padding = profile.percentage_padding
        max_allowed_hours = span_hours * (1.0 + tolerance_padding)

        if edit_hours <= max_allowed_hours:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description=f"[OK] Edit time ({edit_hours:.1f}h) consistent with {tolerance_padding*100:.0f}% tolerance",
                confidence=1.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=f"[WARN] Edit time ({edit_hours:.1f}h) exceeds span ({span_hours:.1f}h) with {tolerance_padding*100:.0f}% tolerance",
            expected=f"Edit time <= {max_allowed_hours:.1f}h",
            found=f"Edit time: {edit_hours:.1f}h",
            confidence=0.7,
        )

    def _check_version_downgrade(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-008: Check for version downgrade."""
        # This check requires object-level version analysis
        # For now, check anomalies for version-related issues
        anomalies = context.get("anomalies", [])

        version_issues = [
            a for a in anomalies
            if "version" in str(a.get("description", "")).lower()
            and "downgrade" in str(a.get("description", "")).lower()
        ]

        if not version_issues:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] No version downgrade detected",
                confidence=0.8,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description="[WARN] Version downgrade indicators found",
            confidence=0.9,
            details={"issues": version_issues},
        )

    def _check_version_mismatch(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-009: Check for version mismatch."""
        anomalies = context.get("anomalies", [])

        version_mismatches = [
            a for a in anomalies
            if a.get("anomaly_type") == "VERSION_MISMATCH"
        ]

        if not version_mismatches:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] No version mismatch detected",
                confidence=1.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description="[WARN] Version mismatch detected",
            confidence=0.8,
            details={"mismatches": version_mismatches},
        )

    def _check_non_autodesk(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-010: Check for non-Autodesk origin using fingerprint data."""
        fingerprint = context.get("application_fingerprint", {})

        # Check is_autodesk flag from fingerprint
        is_autodesk = fingerprint.get("is_autodesk", False)
        detected_app = fingerprint.get("detected_application", "unknown")

        if is_autodesk:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] Autodesk application origin",
                confidence=1.0,
            )

        # Check for Autodesk markers in detected application name
        autodesk_markers = ["autocad", "autodesk", "civil3d", "revit"]
        is_autodesk_name = any(m in str(detected_app).lower() for m in autodesk_markers)

        if is_autodesk_name:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] Autodesk application origin",
                confidence=0.9,
            )

        # Unknown or no fingerprint data - inconclusive
        if detected_app == "unknown" or not fingerprint:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="[INFO] Application origin could not be determined",
                confidence=0.3,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=f"[INFO] Non-Autodesk origin: {detected_app}",
            expected="Autodesk application",
            found=str(detected_app),
            confidence=0.9,
        )

    def _check_orphaned_objects(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-011: Check for orphaned objects."""
        # This requires deep object graph analysis
        # Placeholder that passes unless anomalies indicate issues
        anomalies = context.get("anomalies", [])

        orphan_issues = [
            a for a in anomalies
            if "orphan" in str(a.get("description", "")).lower()
        ]

        if not orphan_issues:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] No orphaned objects detected",
                confidence=0.7,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description="[WARN] Orphaned objects found",
            confidence=0.95,
            details={"orphan_count": len(orphan_issues)},
        )

    def _check_slack_space(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-012: Check for unusual slack space."""
        anomalies = context.get("anomalies", [])

        slack_issues = [
            a for a in anomalies
            if "slack" in str(a.get("description", "")).lower()
            or "padding" in str(a.get("description", "")).lower()
        ]

        if not slack_issues:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] No unusual slack space",
                confidence=1.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description="[INFO] Unusual data in slack space",
            confidence=0.6,
            details={"slack_issues": slack_issues},
        )
