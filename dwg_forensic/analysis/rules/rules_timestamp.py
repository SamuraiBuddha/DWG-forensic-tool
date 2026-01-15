"""
DWG Forensic Tool - Advanced Timestamp Rules (TAMPER-013 to TAMPER-018)

Sophisticated timestamp analysis including cumulative editing time validation,
version anachronism detection, and timezone/timer manipulation indicators.
"""

from typing import Any, Dict

from dwg_forensic.analysis.rules.models import (
    RuleResult,
    RuleStatus,
    TamperingRule,
)


class TimestampRulesMixin:
    """Mixin providing TAMPER-013 through TAMPER-018 check implementations."""

    def _check_tdindwg_manipulation(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-013: Check for TDINDWG manipulation.

        TDINDWG is a read-only field tracking cumulative editing time.
        It cannot exceed the calendar span between creation and last save.
        If it does, this proves timestamp manipulation.
        """
        timestamp_data = context.get("timestamp_data", {})
        anomalies = context.get("anomalies", [])

        # Check if TDINDWG data is available
        tdindwg = timestamp_data.get("tdindwg") if timestamp_data else None
        calendar_span = timestamp_data.get("calendar_span_days") if timestamp_data else None

        if tdindwg is None:
            # Also check for anomalies already detected
            tdindwg_anomalies = [
                a for a in anomalies
                if a.get("anomaly_type") == "TDINDWG_EXCEEDS_SPAN"
            ]
            if tdindwg_anomalies:
                details = tdindwg_anomalies[0].get("details", {})
                return RuleResult(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    status=RuleStatus.FAILED,
                    severity=rule.severity,
                    description="[FAIL] TDINDWG exceeds calendar span - timestamp manipulation proven",
                    expected=f"Editing time <= {details.get('calendar_span_days', '?')} days",
                    found=f"Editing time: {details.get('tdindwg_days', '?')} days",
                    confidence=1.0,
                    details=details,
                )
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="TDINDWG data not available",
                confidence=0.0,
            )

        # If we have the raw data, check directly
        if calendar_span is not None and tdindwg > calendar_span:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.FAILED,
                severity=rule.severity,
                description="[FAIL] TDINDWG exceeds calendar span - timestamp manipulation proven",
                expected=f"Editing time <= {calendar_span:.2f} days",
                found=f"Editing time: {tdindwg:.2f} days",
                confidence=1.0,
                details={
                    "tdindwg_days": round(tdindwg, 4),
                    "calendar_span_days": round(calendar_span, 4),
                    "excess_days": round(tdindwg - calendar_span, 4),
                },
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.PASSED,
            severity=rule.severity,
            description="[OK] TDINDWG consistent with calendar span",
            confidence=1.0,
        )

    def _check_version_anachronism(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-014: Check for version anachronism.

        A file saved in a specific DWG version cannot claim a creation date
        before that version was released. This is an infallible backdating check.
        """
        anomalies = context.get("anomalies", [])

        # Check for already detected anomalies
        anachronism_anomalies = [
            a for a in anomalies
            if a.get("anomaly_type") == "VERSION_ANACHRONISM"
        ]

        if anachronism_anomalies:
            details = anachronism_anomalies[0].get("details", {})
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.FAILED,
                severity=rule.severity,
                description=(
                    f"[FAIL] Version anachronism: {details.get('version_name', 'Unknown')} "
                    f"did not exist on {details.get('claimed_creation_date', '?')}"
                ),
                expected=f"Creation date >= {details.get('version_release_date', '?')}",
                found=f"Creation date: {details.get('claimed_creation_date', '?')}",
                confidence=1.0,
                details=details,
            )

        # Also check timestamp_data if available
        timestamp_data = context.get("timestamp_data", {})
        header = context.get("header") or context.get("header_analysis", {})
        version_string = header.get("version_string", "")

        if timestamp_data and version_string:
            tdcreate = timestamp_data.get("tdcreate")
            version_release = context.get("version_release_date")

            if tdcreate and version_release:
                # Convert MJD to check
                try:
                    from dwg_forensic.parsers.timestamp import mjd_to_datetime
                    from dwg_forensic.analysis.version_dates import is_date_before_version_release

                    claimed_date = mjd_to_datetime(tdcreate)
                    if is_date_before_version_release(version_string, claimed_date):
                        return RuleResult(
                            rule_id=rule.rule_id,
                            rule_name=rule.name,
                            status=RuleStatus.FAILED,
                            severity=rule.severity,
                            description=f"[FAIL] File claims creation before {version_string} existed",
                            confidence=1.0,
                        )
                except (ValueError, ImportError):
                    pass

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.PASSED,
            severity=rule.severity,
            description="[OK] No version anachronism detected",
            confidence=1.0,
        )

    def _check_timezone_discrepancy(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-015: Check for timezone discrepancy.

        Compares local (TDCREATE) and UTC (TDUCREATE) timestamps.
        Valid timezone offsets are -12 to +14 hours.
        """
        anomalies = context.get("anomalies", [])

        # Check for already detected anomalies
        tz_anomalies = [
            a for a in anomalies
            if a.get("anomaly_type") == "TIMEZONE_DISCREPANCY"
        ]

        if tz_anomalies:
            details = tz_anomalies[0].get("details", {})
            offset = details.get("offset_hours", "?")
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.FAILED,
                severity=rule.severity,
                description=f"[WARN] Invalid timezone offset: {offset} hours",
                expected="Timezone offset in range [-12, +14] hours",
                found=f"Offset: {offset} hours",
                confidence=0.9,
                details=details,
            )

        # Check timestamp_data directly
        timestamp_data = context.get("timestamp_data", {})
        offset_hours = timestamp_data.get("timezone_offset_hours")

        if offset_hours is not None:
            if offset_hours < -12 or offset_hours > 14:
                return RuleResult(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    status=RuleStatus.FAILED,
                    severity=rule.severity,
                    description=f"[WARN] Invalid timezone offset: {offset_hours:.2f} hours",
                    expected="Timezone offset in range [-12, +14] hours",
                    found=f"Offset: {offset_hours:.2f} hours",
                    confidence=0.9,
                )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.PASSED,
            severity=rule.severity,
            description="[OK] No timezone discrepancy detected",
            confidence=1.0,
        )

    def _check_educational_watermark(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-016: Check for educational version watermark.

        Educational licenses embed a watermark that appears on all plots.
        This may be relevant for IP or licensing compliance investigations.
        """
        timestamp_data = context.get("timestamp_data", {})
        metadata = context.get("metadata", {})

        # Check in timestamp_data
        edu_watermark = timestamp_data.get("educational_watermark", False)

        # Also check in metadata
        if not edu_watermark and metadata:
            edu_watermark = metadata.get("educational_watermark", False)

        if edu_watermark:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.FAILED,
                severity=rule.severity,
                description="[INFO] Educational Version watermark detected",
                found="Student/Educational license watermark present",
                confidence=1.0,
                details={
                    "educational_watermark": True,
                    "forensic_note": (
                        "This file was created with an educational license. "
                        "Educational licenses restrict commercial use."
                    ),
                },
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.PASSED,
            severity=rule.severity,
            description="[OK] No educational watermark detected",
            confidence=1.0,
        )

    def _check_tdusrtimer_reset(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-017: Check if TDUSRTIMER was reset.

        TDUSRTIMER is user-resettable, but TDINDWG is not.
        If TDUSRTIMER << TDINDWG, the user deliberately reset
        the timer to hide editing history.
        """
        timestamp_data = context.get("timestamp_data", {})
        metadata = context.get("metadata", {})

        # Get TDINDWG and TDUSRTIMER values
        tdindwg = timestamp_data.get("tdindwg") if timestamp_data else None
        tdusrtimer = timestamp_data.get("tdusrtimer") if timestamp_data else None

        # Also check metadata if timestamp_data not available
        if tdindwg is None and metadata:
            tdindwg = metadata.get("tdindwg")
        if tdusrtimer is None and metadata:
            tdusrtimer = metadata.get("tdusrtimer")

        if tdindwg is None or tdusrtimer is None:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="Timer data not available (TDINDWG or TDUSRTIMER missing)",
                confidence=0.0,
            )

        # Both values are in MJD fraction (days), convert to hours for clarity
        tdindwg_hours = tdindwg * 24 if tdindwg else 0
        tdusrtimer_hours = tdusrtimer * 24 if tdusrtimer else 0

        # If TDINDWG is very small, there's nothing significant to hide
        if tdindwg_hours < 0.1:  # Less than 6 minutes
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] Minimal editing time - timer reset check not applicable",
                confidence=0.5,
            )

        # If user timer is within 10% of TDINDWG, it wasn't reset
        if tdindwg_hours > 0 and tdusrtimer_hours >= tdindwg_hours * 0.9:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description=(
                    f"[OK] User timer ({tdusrtimer_hours:.2f}h) consistent "
                    f"with TDINDWG ({tdindwg_hours:.2f}h)"
                ),
                confidence=1.0,
            )

        # Timer was reset - calculate ratio
        ratio = tdusrtimer_hours / tdindwg_hours if tdindwg_hours > 0 else 0
        hidden_hours = tdindwg_hours - tdusrtimer_hours

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=(
                f"[WARN] User timer reset detected - showing {ratio:.0%} "
                f"of actual editing time"
            ),
            expected=f"TDUSRTIMER ~ {tdindwg_hours:.2f}h",
            found=f"TDUSRTIMER = {tdusrtimer_hours:.2f}h ({ratio:.0%})",
            confidence=0.7,
            details={
                "tdindwg_hours": round(tdindwg_hours, 4),
                "tdusrtimer_hours": round(tdusrtimer_hours, 4),
                "ratio": round(ratio, 4),
                "hidden_hours": round(hidden_hours, 4),
                "forensic_note": (
                    "Timer was reset to hide editing history. "
                    "TDINDWG cannot be reset and reveals true editing time."
                ),
            },
        )

    def _check_network_path_leakage(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-018: Check for network paths that reveal file origin.

        External references (xrefs), image paths, and font paths may contain
        UNC paths (\\\\SERVER\\share\\) or URLs that reveal the original network
        environment where the file was created or modified.
        """
        metadata = context.get("metadata", {})

        # Get network paths from metadata
        network_paths = metadata.get("network_paths_detected", []) if metadata else []
        xref_paths = metadata.get("xref_paths", []) if metadata else []

        # If network_paths not pre-computed, extract from xref_paths
        if not network_paths and xref_paths:
            network_paths = [
                p for p in xref_paths
                if p.startswith('\\\\') or '://' in p
            ]

        if not network_paths:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] No network paths detected in file references",
                confidence=1.0,
            )

        # Extract server names from UNC paths
        servers = set()
        for path in network_paths:
            if path.startswith('\\\\'):
                # UNC path: \\SERVER\share\path
                parts = path.split('\\')
                if len(parts) > 2 and parts[2]:
                    servers.add(parts[2])
            elif '://' in path:
                # URL: protocol://host/path
                try:
                    # Extract host from URL
                    from urllib.parse import urlparse
                    parsed = urlparse(path)
                    if parsed.netloc:
                        servers.add(parsed.netloc)
                except Exception:
                    pass

        server_list = sorted(servers) if servers else []
        server_display = ", ".join(server_list) if server_list else "paths found"

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=f"[INFO] Network paths reveal origin: {server_display}",
            confidence=1.0,
            details={
                "network_paths": network_paths,
                "servers_detected": server_list,
                "path_count": len(network_paths),
                "forensic_value": (
                    "Network paths may contradict claimed file origin. "
                    "Server names and paths reveal organizational network topology."
                ),
            },
        )
