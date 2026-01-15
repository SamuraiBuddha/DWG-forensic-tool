"""
DWG Forensic Tool - Deep Structure Rules (TAMPER-036 to TAMPER-040)

Deep DWG binary structure analysis including handle gaps, section maps,
and internal timestamp validation.
"""

from datetime import datetime
from typing import Any, Dict

from dwg_forensic.analysis.rules.models import (
    RuleResult,
    RuleStatus,
    TamperingRule,
)


class StructureRulesMixin:
    """Mixin providing TAMPER-036 through TAMPER-040 check implementations."""

    def _check_critical_handle_gaps(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-036: Critical Handle Gap Detection.

        Large gaps in the handle sequence indicate mass deletion of objects,
        which may be evidence of tampering to hide information.
        """
        handle_analysis = context.get("handle_analysis", {})

        if not handle_analysis:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="Handle analysis data not available",
                confidence=0.0,
            )

        gaps = handle_analysis.get("gaps", [])
        critical_gaps = [g for g in gaps if g.get("severity") == "critical"]

        if not critical_gaps:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] No critical handle gaps detected",
                confidence=1.0,
            )

        largest_gap = max(g.get("gap_size", 0) for g in critical_gaps)
        total_missing = sum(g.get("gap_size", 0) for g in critical_gaps)

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=(
                f"[FAIL] {len(critical_gaps)} critical handle gap(s) detected - "
                f"largest gap: {largest_gap} handles, total missing: {total_missing}"
            ),
            confidence=0.95,
            details={
                "critical_gap_count": len(critical_gaps),
                "largest_gap": largest_gap,
                "total_missing_handles": total_missing,
                "forensic_significance": (
                    "Large handle gaps indicate mass deletion of objects. "
                    "This could be intentional removal of evidence or data."
                ),
            },
        )

    def _check_missing_header_section(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-037: Missing Header Section Detection.

        The AcDb:Header section is essential for valid DWG files.
        Its absence or corruption indicates structural tampering.
        """
        section_map = context.get("section_map", {})

        if not section_map:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="Section map data not available",
                confidence=0.0,
            )

        sections = section_map.get("sections", {})
        # Section type 1 is HEADER (AcDb:Header)
        has_header = 1 in sections or "1" in sections or "HEADER" in str(sections).upper()

        if has_header:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] AcDb:Header section present",
                confidence=1.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description="[FAIL] AcDb:Header section missing - structural tampering detected",
            confidence=0.95,
            details={
                "missing_section": "AcDb:Header",
                "forensic_significance": (
                    "The Header section contains critical drawing variables including "
                    "timestamps. Its absence indicates severe file corruption or "
                    "deliberate structural manipulation."
                ),
            },
        )

    def _check_dwg_internal_timestamp_contradiction(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-038: DWG Internal Timestamp Contradiction.

        Compares TDCREATE/TDUPDATE from DWG header with filesystem timestamps.
        Large discrepancies prove timestamp manipulation.
        """
        drawing_vars = context.get("drawing_variables", {})
        metadata = context.get("metadata", {})

        if not drawing_vars:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="Drawing variables not available",
                confidence=0.0,
            )

        tdcreate = drawing_vars.get("tdcreate", {})
        tdupdate = drawing_vars.get("tdupdate", {})

        dwg_create_str = tdcreate.get("datetime_utc") if tdcreate else None
        dwg_update_str = tdupdate.get("datetime_utc") if tdupdate else None

        file_created = metadata.get("created_date")
        file_modified = metadata.get("modified_date")

        if not dwg_create_str and not dwg_update_str:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="DWG internal timestamps not available",
                confidence=0.0,
            )

        anomalies = []

        # Check creation time discrepancy
        if dwg_create_str and file_created:
            try:
                dwg_dt = datetime.fromisoformat(dwg_create_str.replace("Z", "+00:00"))
                file_dt = datetime.fromisoformat(str(file_created).replace("Z", "+00:00"))
                diff_seconds = abs((dwg_dt - file_dt).total_seconds())

                # More than 1 day difference is suspicious
                if diff_seconds > 86400:
                    anomalies.append({
                        "type": "creation_mismatch",
                        "dwg_time": dwg_create_str,
                        "file_time": str(file_created),
                        "diff_days": diff_seconds / 86400,
                    })
            except (ValueError, TypeError):
                pass

        # Check modification time discrepancy
        if dwg_update_str and file_modified:
            try:
                dwg_dt = datetime.fromisoformat(dwg_update_str.replace("Z", "+00:00"))
                file_dt = datetime.fromisoformat(str(file_modified).replace("Z", "+00:00"))
                diff_seconds = abs((dwg_dt - file_dt).total_seconds())

                if diff_seconds > 86400:
                    anomalies.append({
                        "type": "modification_mismatch",
                        "dwg_time": dwg_update_str,
                        "file_time": str(file_modified),
                        "diff_days": diff_seconds / 86400,
                    })
            except (ValueError, TypeError):
                pass

        if not anomalies:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] DWG internal timestamps consistent with filesystem",
                confidence=1.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=(
                f"[FAIL] DWG internal timestamps contradict filesystem - "
                f"{len(anomalies)} discrepancy/discrepancies found"
            ),
            confidence=0.9,
            details={
                "anomalies": anomalies,
                "forensic_significance": (
                    "TDCREATE and TDUPDATE are stored inside the DWG file and "
                    "are difficult to modify without specialized tools. "
                    "Discrepancies with filesystem timestamps indicate "
                    "either file copying with timestamp preservation or "
                    "deliberate timestamp manipulation."
                ),
            },
        )

    def _check_handle_gap_ratio(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-039: Handle Gap Ratio Anomaly.

        High ratio of missing handles to total handles indicates
        unusual deletion patterns.
        """
        handle_analysis = context.get("handle_analysis", {})

        if not handle_analysis:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="Handle analysis data not available",
                confidence=0.0,
            )

        statistics = handle_analysis.get("statistics", {})
        total_handles = statistics.get("total_handles", 0)
        total_missing = statistics.get("total_missing_handles", 0)

        if total_handles == 0:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="No handles found for analysis",
                confidence=0.0,
            )

        total = total_handles + total_missing
        gap_ratio = total_missing / total if total > 0 else 0

        # Threshold: more than 20% missing handles is suspicious
        if gap_ratio < 0.20:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description=f"[OK] Handle gap ratio {gap_ratio * 100:.1f}% within normal range",
                confidence=1.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=(
                f"[WARN] Handle gap ratio {gap_ratio * 100:.1f}% exceeds threshold - "
                f"{total_missing} handles missing from sequence"
            ),
            confidence=0.8,
            details={
                "gap_ratio_percent": f"{gap_ratio * 100:.2f}",
                "total_handles": total_handles,
                "missing_handles": total_missing,
                "forensic_significance": (
                    "A high handle gap ratio indicates many objects have been deleted. "
                    "While some deletion is normal during editing, unusually high ratios "
                    "may indicate targeted removal of content."
                ),
            },
        )

    def _check_section_map_integrity(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-040: Section Map Integrity Failure.

        Checks for section map parsing failures or structural anomalies.
        """
        section_map = context.get("section_map", {})

        if not section_map:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="Section map data not available",
                confidence=0.0,
            )

        parsing_errors = section_map.get("parsing_errors", [])
        section_count = section_map.get("section_count", 0)

        # Check for parsing errors
        if parsing_errors:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.FAILED,
                severity=rule.severity,
                description=f"[FAIL] Section map parsing errors: {len(parsing_errors)} error(s)",
                confidence=0.85,
                details={
                    "parsing_errors": parsing_errors,
                    "forensic_significance": (
                        "Section map parsing errors indicate file corruption or "
                        "deliberate structural manipulation of the DWG file format."
                    ),
                },
            )

        # Check for suspiciously low section count
        if section_count == 0:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.FAILED,
                severity=rule.severity,
                description="[FAIL] No sections found in section map - structural anomaly",
                confidence=0.9,
                details={
                    "section_count": 0,
                    "forensic_significance": (
                        "A valid DWG file should contain multiple sections. "
                        "Zero sections indicates severe corruption or tampering."
                    ),
                },
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.PASSED,
            severity=rule.severity,
            description=f"[OK] Section map intact with {section_count} section(s)",
            confidence=1.0,
        )
