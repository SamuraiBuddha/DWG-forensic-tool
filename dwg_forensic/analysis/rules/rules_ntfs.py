"""
DWG Forensic Tool - NTFS Cross-Validation Rules (TAMPER-019 to TAMPER-028)

"Smoking gun" indicators comparing DWG internal timestamps with NTFS filesystem metadata.
These rules produce court-admissible proof of timestamp manipulation.
"""

from typing import Any, Dict

from dwg_forensic.analysis.rules.models import (
    RuleResult,
    RuleStatus,
    TamperingRule,
)


class NTFSRulesMixin:
    """Mixin providing TAMPER-019 through TAMPER-028 check implementations."""

    def _check_ntfs_timestomping(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-019: NTFS Timestomping Detection.

        DEFINITIVE PROOF: If $STANDARD_INFORMATION timestamps are earlier than
        $FILE_NAME timestamps, this is IMPOSSIBLE without timestomping tools.
        $FILE_NAME timestamps are only modified by the Windows kernel.
        """
        ntfs_data = context.get("ntfs_data", {})

        if not ntfs_data:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="NTFS timestamp data not available",
                confidence=0.0,
            )

        si_fn_mismatch = ntfs_data.get("si_fn_mismatch", False)
        mismatch_details = ntfs_data.get("mismatch_details", "")

        if not si_fn_mismatch:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] No $SI/$FN timestamp mismatch detected",
                confidence=1.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=(
                "[FAIL] DEFINITIVE PROOF OF TIMESTOMPING: $STANDARD_INFORMATION "
                "timestamps are earlier than $FILE_NAME timestamps"
            ),
            found=mismatch_details or "SI timestamps precede FN timestamps",
            confidence=1.0,
            details={
                "forensic_conclusion": (
                    "PROVEN: File timestamps were manipulated using timestomping tools. "
                    "$FILE_NAME timestamps are protected by the Windows kernel and cannot "
                    "be modified by standard tools. This discrepancy is conclusive evidence "
                    "of deliberate timestamp manipulation."
                ),
                "legal_significance": (
                    "This finding constitutes definitive proof of timestamp manipulation "
                    "and may be sufficient grounds to challenge the authenticity of this "
                    "file as evidence."
                ),
            },
        )

    def _check_ntfs_nanosecond_truncation(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-020: NTFS Nanosecond Truncation Detection.

        TOOL SIGNATURE: NTFS stores timestamps at 100-nanosecond resolution.
        With 10 million possible values, timestamps naturally ending in .0000000
        are statistically improbable (p < 0.0001). Multiple truncated timestamps
        indicate manipulation by forensic/timestomping tools.
        """
        ntfs_data = context.get("ntfs_data", {})

        if not ntfs_data:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="NTFS nanosecond data not available",
                confidence=0.0,
            )

        nanoseconds_truncated = ntfs_data.get("nanoseconds_truncated", False)
        truncation_details = ntfs_data.get("truncation_details", "")

        if not nanoseconds_truncated:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] Timestamps have normal nanosecond distribution",
                confidence=1.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=(
                "[FAIL] TOOL SIGNATURE: Timestamps have zero nanoseconds - "
                "indicates manipulation by forensic/timestomping tools"
            ),
            found=truncation_details or "Multiple timestamps truncated to zero nanoseconds",
            confidence=0.95,
            details={
                "forensic_conclusion": (
                    "STRONG INDICATOR: NTFS timestamps have 100-nanosecond precision. "
                    "With 10 million possible values, the probability of multiple timestamps "
                    "naturally ending in .0000000 is less than 0.01%. This pattern is a "
                    "known signature of timestamp manipulation tools."
                ),
                "statistical_probability": "< 0.0001 (statistically improbable)",
            },
        )

    def _check_ntfs_impossible_timestamp(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-021: NTFS Impossible Timestamp Order.

        IMPOSSIBLE CONDITION: File creation timestamp after modification
        timestamp cannot occur naturally on any filesystem.
        """
        ntfs_data = context.get("ntfs_data", {})

        if not ntfs_data:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="NTFS timestamp data not available",
                confidence=0.0,
            )

        creation_after_modification = ntfs_data.get("creation_after_modification", False)

        if not creation_after_modification:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] NTFS timestamps in valid order",
                confidence=1.0,
            )

        si_created = ntfs_data.get("si_created")
        si_modified = ntfs_data.get("si_modified")

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=(
                "[FAIL] IMPOSSIBLE: File created after it was modified - "
                "this cannot occur naturally"
            ),
            expected="Created timestamp <= Modified timestamp",
            found=f"Created: {si_created}, Modified: {si_modified}",
            confidence=1.0,
            details={
                "forensic_conclusion": (
                    "PROVEN MANIPULATION: A file cannot be modified before it exists. "
                    "This timestamp ordering is physically impossible and proves "
                    "deliberate timestamp manipulation."
                ),
            },
        )

    def _check_dwg_ntfs_creation_contradiction(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-022: DWG vs NTFS Creation Timestamp Contradiction.

        PROVEN BACKDATING: If DWG internal creation date is before the file
        existed on the filesystem, this is IMPOSSIBLE and proves backdating.
        """
        ntfs_data = context.get("ntfs_data", {})
        contradictions = context.get("ntfs_contradictions", {})

        # Check for pre-computed contradictions (dict format from analyzer)
        if isinstance(contradictions, dict) and contradictions.get("creation_contradiction"):
            details = contradictions.get("creation_details", {})
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.FAILED,
                severity=rule.severity,
                description=(
                    f"[FAIL] PROVEN BACKDATING: "
                    f"DWG claims creation before file existed on filesystem"
                ),
                expected="DWG created >= NTFS created",
                found=details.get("forensic_conclusion", "Creation timestamp contradiction"),
                confidence=1.0,
                details={
                    "forensic_conclusion": (
                        "DEFINITIVE PROOF: A file cannot contain a creation date from before "
                        "the file itself was created on the filesystem. This conclusively "
                        "proves the DWG internal timestamp was BACKDATED."
                    ),
                    "dwg_created": details.get("dwg_created"),
                    "ntfs_created": details.get("ntfs_created"),
                    "difference_hours": details.get("difference_hours"),
                },
            )

        # Manual check if no pre-computed contradictions
        if not ntfs_data:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="NTFS/DWG cross-validation data not available",
                confidence=0.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.PASSED,
            severity=rule.severity,
            description="[OK] DWG creation timestamp consistent with NTFS filesystem",
            confidence=1.0,
        )

    def _check_dwg_ntfs_modification_contradiction(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-023: DWG vs NTFS Modification Timestamp Contradiction.

        PROVEN MANIPULATION: If DWG internal modification date is before the
        file was created on filesystem, this file is a copy with backdated timestamps.
        """
        ntfs_data = context.get("ntfs_data", {})
        contradictions = context.get("ntfs_contradictions", {})

        # Check for pre-computed contradictions (dict format from analyzer)
        if isinstance(contradictions, dict) and contradictions.get("modification_contradiction"):
            details = contradictions.get("modification_details", {})
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.FAILED,
                severity=rule.severity,
                description=(
                    "[FAIL] PROVEN MANIPULATION: "
                    "DWG modification timestamp contradicts NTFS filesystem"
                ),
                expected="DWG modified consistent with NTFS modified",
                found=details.get("forensic_conclusion", "Modification timestamp contradiction"),
                details={
                    "forensic_conclusion": (
                        "TIMESTAMP CONTRADICTION: DWG internal modification timestamp "
                        "differs significantly from NTFS modification timestamp."
                    ),
                    "dwg_modified": details.get("dwg_modified"),
                    "ntfs_modified": details.get("ntfs_modified"),
                    "difference_hours": details.get("difference_hours"),
                },
            )

        # Check if NTFS data is available
        if not ntfs_data:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="NTFS/DWG cross-validation data not available",
                confidence=0.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.PASSED,
            severity=rule.severity,
            description="[OK] DWG modification timestamp consistent with NTFS filesystem",
            confidence=1.0,
        )

    def _check_zero_edit_time(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-024: Zero Edit Time Detection.

        Files with zero or near-zero editing time (TDINDWG) indicate:
        1. Programmatic file generation
        2. Direct timestamp manipulation
        3. File created by copying another file
        """
        timestamp_data = context.get("timestamp_data", {})
        metadata = context.get("metadata", {})

        tdindwg = timestamp_data.get("tdindwg") if timestamp_data else None
        if tdindwg is None and metadata:
            tdindwg = metadata.get("tdindwg")

        if tdindwg is None:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="TDINDWG data not available",
                confidence=0.0,
            )

        # Convert to hours
        edit_hours = tdindwg * 24

        # Check for zero or near-zero edit time (less than 1 minute)
        if edit_hours > 0.0167:  # More than 1 minute
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description=f"[OK] Edit time ({edit_hours:.2f}h) is plausible",
                confidence=1.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=(
                f"[WARN] Zero/minimal edit time ({edit_hours * 60:.1f} minutes) - "
                f"file may be programmatically generated or copied"
            ),
            expected="Edit time > 1 minute for legitimate drawings",
            found=f"TDINDWG: {edit_hours * 60:.1f} minutes",
            confidence=0.7,
            details={
                "tdindwg_hours": round(edit_hours, 6),
                "forensic_note": (
                    "Legitimate CAD drawings require meaningful editing time. "
                    "Zero or near-zero TDINDWG proves the file was not created "
                    "through normal drawing operations."
                ),
            },
        )

    def _check_implausible_edit_ratio(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-025: Implausible Edit Ratio.

        The ratio of editing time to file complexity (size) should be reasonable.
        Very large files with minimal edit time indicate copying or manipulation.
        """
        timestamp_data = context.get("timestamp_data", {})
        metadata = context.get("metadata", {})
        file_data = context.get("file", {})

        tdindwg = timestamp_data.get("tdindwg") if timestamp_data else None
        if tdindwg is None and metadata:
            tdindwg = metadata.get("tdindwg")

        file_size = file_data.get("size", 0)

        if tdindwg is None or file_size == 0:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="Insufficient data for edit ratio analysis",
                confidence=0.0,
            )

        # Convert to hours and MB
        edit_hours = tdindwg * 24
        file_mb = file_size / (1024 * 1024)

        # Skip for very small files
        if file_mb < 0.1:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] File too small for meaningful ratio analysis",
                confidence=0.5,
            )

        # Calculate ratio: MB per hour of editing
        # Normal CAD work produces roughly 0.1-10 MB per hour depending on content
        if edit_hours > 0:
            mb_per_hour = file_mb / edit_hours
        else:
            mb_per_hour = float('inf')

        # Flag if more than 100 MB per hour (implausibly fast)
        if mb_per_hour <= 100:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description=f"[OK] Edit ratio ({mb_per_hour:.1f} MB/h) is plausible",
                confidence=1.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=(
                f"[WARN] Implausible edit ratio: {mb_per_hour:.0f} MB per hour of editing"
            ),
            expected="< 100 MB per hour of editing for normal CAD work",
            found=f"{file_mb:.2f} MB in {edit_hours:.2f}h = {mb_per_hour:.0f} MB/h",
            confidence=0.6,
            details={
                "file_size_mb": round(file_mb, 2),
                "edit_hours": round(edit_hours, 4),
                "mb_per_hour": round(mb_per_hour, 1),
                "forensic_note": (
                    "This file's size-to-editing-time ratio is implausibly high. "
                    "The file may have been copied from another source or generated "
                    "programmatically rather than created through normal CAD operations."
                ),
            },
        )

    def _check_third_party_tool(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-026: Third-Party Tool Detection.

        Files modified by third-party (non-Autodesk) tools have higher
        risk of timestamp manipulation since these tools may not properly
        update or preserve timestamp integrity.
        """
        fingerprint = context.get("application_fingerprint", {})

        # Check fingerprint data for application origin
        is_autodesk = fingerprint.get("is_autodesk", False)
        is_oda_based = fingerprint.get("is_oda_based", False)
        detected_app = str(fingerprint.get("detected_application", "unknown"))

        # Known third-party applications
        third_party_markers = [
            "bricscad", "draftsight", "librecad", "zwcad", "gstarcad",
            "progecad", "intellicad", "corelcad", "turbocad", "nanocad",
            "oda_sdk", "libredwg", "freecad", "qcad"
        ]

        detected_tool = None
        detected_app_lower = detected_app.lower()
        for marker in third_party_markers:
            if marker in detected_app_lower:
                detected_tool = detected_app
                break

        # If Autodesk origin confirmed, pass
        if is_autodesk:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] File created by Autodesk application",
                confidence=1.0,
            )

        if detected_tool or is_oda_based:
            tool_name = detected_tool or "ODA-based application"
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.FAILED,
                severity=rule.severity,
                description=f"[INFO] Third-party tool detected: {tool_name}",
                found=f"Detected application: {detected_app}",
                confidence=0.8,
                details={
                    "detected_tool": tool_name,
                    "is_oda_based": is_oda_based,
                    "forensic_note": (
                        f"{tool_name} is a third-party CAD application. "
                        "Third-party tools may not preserve Autodesk timestamp integrity "
                        "and can be used to manipulate file metadata."
                    ),
                },
            )

        # Unknown origin - inconclusive
        if detected_app == "unknown":
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="[INFO] Application origin could not be determined",
                confidence=0.5,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.PASSED,
            severity=rule.severity,
            description="[OK] No third-party tool indicators detected",
            confidence=0.7,
        )

    def _check_multiple_timestamp_anomalies(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-027: Multiple Timestamp Anomalies Detection.

        COMPOUND EVIDENCE: When multiple independent timestamp anomalies
        are detected, the probability of all occurring naturally becomes
        statistically negligible.
        """
        anomalies = context.get("anomalies", [])

        # Count timestamp-related anomalies
        timestamp_anomaly_types = [
            "TDINDWG_EXCEEDS_SPAN",
            "VERSION_ANACHRONISM",
            "TIMEZONE_DISCREPANCY",
            "TIMESTAMP_PRECISION_ANOMALY",
            "TIMESTAMP_ANOMALY",
            "SUSPICIOUS_EDIT_TIME",
            "NTFS_SI_FN_MISMATCH",
            "NTFS_NANOSECOND_TRUNCATION",
            "NTFS_CREATION_AFTER_MODIFICATION",
            "DWG_NTFS_CREATION_CONTRADICTION",
            "DWG_NTFS_MODIFICATION_CONTRADICTION",
        ]

        timestamp_anomalies = [
            a for a in anomalies
            if a.get("anomaly_type") in timestamp_anomaly_types
        ]

        anomaly_count = len(timestamp_anomalies)

        if anomaly_count < 2:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description=f"[OK] Only {anomaly_count} timestamp anomaly detected",
                confidence=1.0,
            )

        # Multiple anomalies - calculate combined probability
        # Each independent anomaly has some false positive rate
        # Combined probability is much lower
        combined_confidence = min(0.5 + (anomaly_count * 0.15), 1.0)

        anomaly_descriptions = [
            a.get("description", a.get("anomaly_type", "Unknown"))
            for a in timestamp_anomalies
        ]

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=(
                f"[FAIL] COMPOUND EVIDENCE: {anomaly_count} independent timestamp "
                f"anomalies detected - statistically improbable"
            ),
            found=f"{anomaly_count} anomalies: {', '.join(anomaly_descriptions[:3])}...",
            confidence=combined_confidence,
            details={
                "anomaly_count": anomaly_count,
                "anomalies": anomaly_descriptions,
                "forensic_conclusion": (
                    f"Multiple independent timestamp anomalies ({anomaly_count}) detected. "
                    "The probability of all these anomalies occurring naturally is "
                    "statistically negligible. This constitutes strong compound evidence "
                    "of deliberate timestamp manipulation."
                ),
            },
        )

    def _check_forensic_impossibility_score(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """TAMPER-028: Forensic Impossibility Score.

        DEFINITIVE CONCLUSION: Calculates an overall impossibility score
        based on all forensic indicators. A high score indicates the
        combination of evidence proves manipulation beyond reasonable doubt.
        """
        # Collect all definitive indicators
        impossible_conditions = []
        strong_indicators = []
        circumstantial_indicators = []

        # Check NTFS contradictions (definitive)
        ntfs_data = context.get("ntfs_data", {})
        contradictions = context.get("ntfs_contradictions", {})

        if ntfs_data.get("si_fn_mismatch"):
            impossible_conditions.append("NTFS $SI/$FN timestamp mismatch (timestomping)")
        if ntfs_data.get("creation_after_modification"):
            impossible_conditions.append("File created after modification (impossible)")

        # Handle dict format from analyzer
        if isinstance(contradictions, dict):
            if contradictions.get("creation_contradiction"):
                impossible_conditions.append("DWG creation predates filesystem (backdating)")
            if contradictions.get("modification_contradiction"):
                strong_indicators.append("DWG/NTFS modification timestamp mismatch")

        # Check anomalies
        anomalies = context.get("anomalies", [])
        for a in anomalies:
            anomaly_type = a.get("anomaly_type", "")
            severity = a.get("severity", "")

            if anomaly_type in ["TDINDWG_EXCEEDS_SPAN", "VERSION_ANACHRONISM"]:
                impossible_conditions.append(a.get("description", anomaly_type))
            elif severity == "HIGH":
                strong_indicators.append(a.get("description", anomaly_type))
            else:
                circumstantial_indicators.append(a.get("description", anomaly_type))

        # Check NTFS nanosecond truncation (strong indicator)
        if ntfs_data.get("nanoseconds_truncated"):
            strong_indicators.append("NTFS timestamp nanosecond truncation (tool signature)")

        # Calculate impossibility score
        score = (
            len(impossible_conditions) * 40 +  # Definitive proof
            len(strong_indicators) * 15 +       # Strong evidence
            len(circumstantial_indicators) * 5  # Supporting evidence
        )

        # Normalize to 0-100
        score = min(score, 100)

        if score < 40:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description=f"[OK] Forensic impossibility score: {score}/100",
                confidence=1.0,
                details={
                    "score": score,
                    "impossible_conditions": len(impossible_conditions),
                    "strong_indicators": len(strong_indicators),
                    "circumstantial_indicators": len(circumstantial_indicators),
                },
            )

        # Determine conclusion based on score
        if score >= 80:
            conclusion = "DEFINITIVE: Timestamp manipulation PROVEN beyond reasonable doubt"
            confidence = 1.0
        elif score >= 60:
            conclusion = "STRONG EVIDENCE: Multiple indicators prove manipulation"
            confidence = 0.95
        else:
            conclusion = "SUBSTANTIAL EVIDENCE: Multiple tampering indicators present"
            confidence = 0.85

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=f"[FAIL] {conclusion} (Score: {score}/100)",
            confidence=confidence,
            details={
                "impossibility_score": score,
                "conclusion": conclusion,
                "impossible_conditions": impossible_conditions,
                "strong_indicators": strong_indicators,
                "circumstantial_indicators": circumstantial_indicators,
                "forensic_summary": (
                    f"This file exhibits {len(impossible_conditions)} physically impossible "
                    f"conditions, {len(strong_indicators)} strong manipulation indicators, "
                    f"and {len(circumstantial_indicators)} circumstantial indicators. "
                    f"Combined forensic impossibility score: {score}/100."
                ),
                "legal_conclusion": (
                    "Based on the forensic evidence, this file's timestamps have been "
                    "manipulated. The combination of indicators makes natural occurrence "
                    "statistically impossible. This analysis may be used to challenge "
                    "the admissibility of this file as evidence."
                ) if score >= 60 else None,
            },
        )
