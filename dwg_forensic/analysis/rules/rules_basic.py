"""
DWG Forensic Tool - Basic Tampering Rules (TAMPER-001 to TAMPER-012)

Core integrity checks covering CRC validation, TrustedDWG watermarks, and basic timestamp anomalies.
"""

from datetime import datetime, timezone
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
        """TAMPER-001: Check header CRC."""
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

        if is_valid:
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

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description="[FAIL] Header CRC32 mismatch - possible tampering",
            expected=stored,
            found=calculated,
            confidence=1.0,
            details={"tampering_indicator": "crc_mismatch"},
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

    def _check_missing_watermark(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-003: Check for missing TrustedDWG watermark."""
        watermark = context.get("watermark") or context.get("trusted_dwg", {})
        header = context.get("header") or context.get("header_analysis", {})

        version = header.get("version_string", "AC1032")
        # TrustedDWG only expected for AC1021 (R2007) and later
        requires_watermark = version >= "AC1021"

        if not requires_watermark:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description=f"TrustedDWG not expected for {version}",
                confidence=0.0,
            )

        # Support both key formats
        is_present = watermark.get("present", watermark.get("watermark_present", False))

        if is_present:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] TrustedDWG watermark present",
                confidence=1.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=f"[WARN] TrustedDWG watermark missing for {version}",
            expected="TrustedDWG watermark present",
            found="No watermark found",
            confidence=0.8,
        )

    def _check_invalid_watermark(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-004: Check for invalid TrustedDWG watermark."""
        watermark = context.get("watermark") or context.get("trusted_dwg", {})

        is_present = watermark.get("present", watermark.get("watermark_present", False))
        if not is_present:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="No watermark to validate",
                confidence=0.0,
            )

        is_valid = watermark.get("valid", watermark.get("watermark_valid", True))
        if is_valid:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] TrustedDWG watermark is valid",
                confidence=1.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description="[FAIL] TrustedDWG watermark is malformed",
            expected="Valid watermark signature",
            found="Malformed or tampered watermark",
            confidence=1.0,
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
        """TAMPER-006: Check for future timestamp."""
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
        # Grace period for clock skew
        if delta <= 300:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description=f"[OK] {delta:.0f}s future (within grace period)",
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
        """TAMPER-007: Check edit time consistency."""
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

        # Allow 10% tolerance
        if edit_hours <= span_hours * 1.1:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description=f"[OK] Edit time ({edit_hours:.1f}h) consistent",
                confidence=1.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=f"[WARN] Edit time ({edit_hours:.1f}h) exceeds span ({span_hours:.1f}h)",
            expected=f"Edit time <= {span_hours:.1f}h",
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
        """TAMPER-010: Check for non-Autodesk origin."""
        watermark = context.get("watermark") or context.get("trusted_dwg", {})
        origin = watermark.get("application_origin", "")

        # Check is_autodesk flag if available
        is_autodesk_flag = watermark.get("is_autodesk")
        if is_autodesk_flag is not None:
            if is_autodesk_flag:
                return RuleResult(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    status=RuleStatus.PASSED,
                    severity=rule.severity,
                    description="[OK] Autodesk application origin",
                    confidence=1.0,
                )

        autodesk_markers = ["AutoCAD", "Autodesk", "ACAD"]
        is_autodesk = any(m.lower() in origin.lower() for m in autodesk_markers)

        if is_autodesk or not origin:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] Autodesk application origin",
                confidence=1.0 if is_autodesk else 0.5,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=f"[INFO] Non-Autodesk origin: {origin}",
            expected="Autodesk application",
            found=origin,
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
