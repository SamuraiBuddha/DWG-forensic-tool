"""
DWG Forensic Tool - Tampering Rule Engine

Core engine implementing all 40 built-in tampering detection rules
and support for custom YAML/JSON rules.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from dwg_forensic.analysis.rules.models import (
    EvidenceStrength,
    RuleCondition,
    RuleResult,
    RuleSeverity,
    RuleStatus,
    TamperingRule,
)
from dwg_forensic.analysis.rules.rules_basic import BasicRulesMixin
from dwg_forensic.analysis.rules.rules_fingerprint import FingerprintRulesMixin
from dwg_forensic.analysis.rules.rules_ntfs import NTFSRulesMixin
from dwg_forensic.analysis.rules.rules_structure import StructureRulesMixin
from dwg_forensic.analysis.rules.rules_timestamp import TimestampRulesMixin
from dwg_forensic.analysis.tolerance_profiles import (
    ProvenanceToleranceProfile,
    UNKNOWN,
)
from dwg_forensic.analysis.tolerance_mapper import ProvenanceToleranceMapper


class TamperingRuleEngine(
    BasicRulesMixin,
    TimestampRulesMixin,
    NTFSRulesMixin,
    FingerprintRulesMixin,
    StructureRulesMixin,
):
    """
    Rule engine for DWG tampering detection.

    Implements all 40 built-in rules and supports custom YAML/JSON rules.
    Uses mixin classes for rule implementations organized by category:
    - BasicRulesMixin: TAMPER-001 to TAMPER-012 (CRC, basic timestamps)
    - TimestampRulesMixin: TAMPER-013 to TAMPER-018 (Advanced timestamp manipulation)
    - NTFSRulesMixin: TAMPER-019 to TAMPER-028 (NTFS cross-validation)
    - FingerprintRulesMixin: TAMPER-029 to TAMPER-035 (CAD application fingerprinting)
    - StructureRulesMixin: TAMPER-036 to TAMPER-040 (Deep DWG structure analysis)
    """

    def __init__(
        self,
        tolerance_profile: Optional[ProvenanceToleranceProfile] = None
    ):
        """
        Initialize with built-in rules and optional tolerance profile.

        Args:
            tolerance_profile: Optional ProvenanceToleranceProfile for
                provenance-aware rule evaluation. If None, uses UNKNOWN profile
                (conservative fallback). Can be auto-selected using
                ProvenanceToleranceMapper.
        """
        self.rules: List[TamperingRule] = []
        self.results: List[RuleResult] = []
        self._tolerance_profile = tolerance_profile or UNKNOWN
        self._load_builtin_rules()

    def _load_builtin_rules(self) -> None:
        """Load all 40 built-in tampering detection rules."""
        builtin = [
            # Basic Rules (TAMPER-001 to TAMPER-012)
            TamperingRule(
                rule_id="TAMPER-001",
                name="CRC Header Mismatch",
                severity=RuleSeverity.CRITICAL,
                description="Header CRC32 checksum does not match calculated value",
                evidence_strength=EvidenceStrength.DEFINITIVE,
                is_smoking_gun=True,
            ),
            TamperingRule(
                rule_id="TAMPER-002",
                name="CRC Section Mismatch",
                severity=RuleSeverity.CRITICAL,
                description="Section CRC checksum does not match calculated value",
                evidence_strength=EvidenceStrength.DEFINITIVE,
                is_smoking_gun=True,
            ),
            TamperingRule(
                rule_id="TAMPER-005",
                name="Timestamp Reversal",
                severity=RuleSeverity.CRITICAL,
                description="Created timestamp is after modified timestamp - IMPOSSIBLE",
                evidence_strength=EvidenceStrength.DEFINITIVE,
                is_smoking_gun=True,
            ),
            TamperingRule(
                rule_id="TAMPER-006",
                name="Future Timestamp",
                severity=RuleSeverity.CRITICAL,
                description="Modified timestamp is in the future - IMPOSSIBLE without tampering",
                evidence_strength=EvidenceStrength.DEFINITIVE,
                is_smoking_gun=True,
            ),
            TamperingRule(
                rule_id="TAMPER-007",
                name="Edit Time Mismatch",
                severity=RuleSeverity.WARNING,
                description="Editing time inconsistent with creation/modification dates",
                evidence_strength=EvidenceStrength.CIRCUMSTANTIAL,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-008",
                name="Version Downgrade",
                severity=RuleSeverity.WARNING,
                description="File contains objects from newer version than header",
                evidence_strength=EvidenceStrength.CIRCUMSTANTIAL,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-009",
                name="Version Mismatch",
                severity=RuleSeverity.WARNING,
                description="Header version does not match internal object versions",
                evidence_strength=EvidenceStrength.CIRCUMSTANTIAL,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-010",
                name="Non-Autodesk Origin",
                severity=RuleSeverity.INFO,
                description="File created or modified by non-Autodesk application",
                evidence_strength=EvidenceStrength.INFORMATIONAL,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-011",
                name="Orphaned Objects",
                severity=RuleSeverity.WARNING,
                description="Objects with invalid or dangling handle references found",
                evidence_strength=EvidenceStrength.STRONG,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-012",
                name="Unusual Slack Space",
                severity=RuleSeverity.INFO,
                description="Unexpected data found in padding/slack space areas",
                evidence_strength=EvidenceStrength.INFORMATIONAL,
                is_smoking_gun=False,
            ),
            # Advanced Timestamp Rules (TAMPER-013 to TAMPER-018)
            TamperingRule(
                rule_id="TAMPER-013",
                name="TDINDWG Manipulation",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "Cumulative editing time (TDINDWG) exceeds calendar span - "
                    "MATHEMATICALLY IMPOSSIBLE - proves timestamp manipulation"
                ),
                evidence_strength=EvidenceStrength.DEFINITIVE,
                is_smoking_gun=True,
            ),
            TamperingRule(
                rule_id="TAMPER-014",
                name="Version Anachronism",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "File claims creation date before DWG version existed - "
                    "IMPOSSIBLE - proves timestamp backdating"
                ),
                evidence_strength=EvidenceStrength.DEFINITIVE,
                is_smoking_gun=True,
            ),
            TamperingRule(
                rule_id="TAMPER-015",
                name="Timezone Discrepancy",
                severity=RuleSeverity.WARNING,
                description=(
                    "UTC/local timestamp offset is invalid or inconsistent - "
                    "indicates timestamp manipulation"
                ),
                evidence_strength=EvidenceStrength.CIRCUMSTANTIAL,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-016",
                name="Educational Watermark",
                severity=RuleSeverity.INFO,
                description=(
                    "Educational Version watermark present - "
                    "file created with student license"
                ),
                evidence_strength=EvidenceStrength.INFORMATIONAL,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-017",
                name="TDUSRTIMER Reset Indicator",
                severity=RuleSeverity.WARNING,
                description=(
                    "User timer significantly less than TDINDWG - "
                    "timer was deliberately reset to hide editing history"
                ),
                evidence_strength=EvidenceStrength.CIRCUMSTANTIAL,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-018",
                name="Network Path Leakage",
                severity=RuleSeverity.INFO,
                description=(
                    "File contains network paths (UNC or URLs) that may reveal "
                    "original file origin and network topology"
                ),
                evidence_strength=EvidenceStrength.INFORMATIONAL,
                is_smoking_gun=False,
            ),
            # NTFS Cross-Validation Rules (TAMPER-019 to TAMPER-028) - THE SMOKING GUNS
            TamperingRule(
                rule_id="TAMPER-019",
                name="NTFS Timestomping Detected",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "DEFINITIVE PROOF: $STANDARD_INFORMATION timestamps are earlier than "
                    "$FILE_NAME timestamps - this is IMPOSSIBLE without timestomping tools"
                ),
                evidence_strength=EvidenceStrength.DEFINITIVE,
                is_smoking_gun=True,
            ),
            TamperingRule(
                rule_id="TAMPER-020",
                name="NTFS Nanosecond Truncation",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "TOOL SIGNATURE: Timestamps have zero nanoseconds - with 10 million "
                    "possible values, this indicates manipulation by forensic/timestomping tools"
                ),
                evidence_strength=EvidenceStrength.DEFINITIVE,
                is_smoking_gun=True,
            ),
            TamperingRule(
                rule_id="TAMPER-021",
                name="NTFS Impossible Timestamp Order",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "IMPOSSIBLE CONDITION: File creation timestamp is after modification "
                    "timestamp - this cannot occur naturally on any filesystem"
                ),
                evidence_strength=EvidenceStrength.DEFINITIVE,
                is_smoking_gun=True,
            ),
            TamperingRule(
                rule_id="TAMPER-022",
                name="DWG-NTFS Creation Contradiction",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "PROVEN BACKDATING: DWG internal creation date is before the file "
                    "existed on the filesystem - conclusive evidence of timestamp manipulation"
                ),
                evidence_strength=EvidenceStrength.DEFINITIVE,
                is_smoking_gun=True,
            ),
            TamperingRule(
                rule_id="TAMPER-023",
                name="DWG-NTFS Modification Contradiction",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "PROVEN MANIPULATION: DWG internal modification date is before the file "
                    "was created - this file is a copy with backdated timestamps"
                ),
                evidence_strength=EvidenceStrength.DEFINITIVE,
                is_smoking_gun=True,
            ),
            TamperingRule(
                rule_id="TAMPER-024",
                name="Zero Edit Time",
                severity=RuleSeverity.WARNING,
                description=(
                    "File shows zero or near-zero editing time - file was "
                    "programmatically generated or timestamps were manipulated"
                ),
                evidence_strength=EvidenceStrength.STRONG,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-025",
                name="Implausible Edit Ratio",
                severity=RuleSeverity.WARNING,
                description=(
                    "Edit time to file complexity ratio is implausible - "
                    "file was copied from another source or timestamps were manipulated"
                ),
                evidence_strength=EvidenceStrength.CIRCUMSTANTIAL,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-026",
                name="Third-Party Tool Detected",
                severity=RuleSeverity.INFO,
                description=(
                    "File was modified by third-party (non-Autodesk) software - "
                    "increases risk of timestamp manipulation"
                ),
                evidence_strength=EvidenceStrength.INFORMATIONAL,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-027",
                name="Multiple Timestamp Anomalies",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "COMPOUND EVIDENCE: Multiple independent timestamp anomalies detected - "
                    "the probability of all occurring naturally is statistically negligible"
                ),
                evidence_strength=EvidenceStrength.DEFINITIVE,
                is_smoking_gun=True,
            ),
            TamperingRule(
                rule_id="TAMPER-028",
                name="Forensic Impossibility Score",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "DEFINITIVE CONCLUSION: Combination of forensic indicators proves "
                    "timestamp manipulation beyond reasonable doubt"
                ),
                evidence_strength=EvidenceStrength.DEFINITIVE,
                is_smoking_gun=True,
            ),
            # CAD Application Fingerprinting Rules (TAMPER-029 to TAMPER-035)
            # These are informational - NOT smoking guns per user feedback
            TamperingRule(
                rule_id="TAMPER-029",
                name="ODA SDK Artifact Detection",
                severity=RuleSeverity.INFO,
                description=(
                    "Open Design Alliance SDK artifacts detected - file created by "
                    "non-Autodesk application (BricsCAD, NanoCAD, DraftSight, etc.)"
                ),
                evidence_strength=EvidenceStrength.INFORMATIONAL,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-030",
                name="BricsCAD Signature",
                severity=RuleSeverity.INFO,
                description=(
                    "BricsCAD-specific signatures detected (BRICSYS APPID, "
                    "ACAD_BRICSCAD_INFO dictionary) - file created by BricsCAD"
                ),
                evidence_strength=EvidenceStrength.INFORMATIONAL,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-031",
                name="NanoCAD Signature",
                severity=RuleSeverity.INFO,
                description=(
                    "NanoCAD-specific signatures detected (NANOCAD APPID, "
                    "CP1251 codepage) - file created by Russian NanoCAD"
                ),
                evidence_strength=EvidenceStrength.INFORMATIONAL,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-032",
                name="DraftSight Signature",
                severity=RuleSeverity.INFO,
                description=(
                    "DraftSight-specific signatures detected (DRAFTSIGHT APPID, "
                    "DS_LICENSE_TYPE) - file created by Dassault Systemes DraftSight"
                ),
                evidence_strength=EvidenceStrength.INFORMATIONAL,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-033",
                name="Open Source CAD Conversion",
                severity=RuleSeverity.INFO,  # Demoted from WARNING
                description=(
                    "LibreCAD/QCAD/FreeCAD conversion artifacts detected - file was "
                    "converted from DXF or created by open-source CAD software"
                ),
                evidence_strength=EvidenceStrength.INFORMATIONAL,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-034",
                name="Zero Timestamp Pattern",
                severity=RuleSeverity.WARNING,
                description=(
                    "TDCREATE and TDUPDATE are both zero or identical with zero TDINDWG - "
                    "strong indicator of LibreCAD, QCAD, or programmatic file generation"
                ),
                evidence_strength=EvidenceStrength.STRONG,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-035",
                name="Missing AutoCAD Identifiers",
                severity=RuleSeverity.INFO,  # Demoted from WARNING
                description=(
                    "Missing FINGERPRINTGUID and/or VERSIONGUID - AutoCAD always generates "
                    "these identifiers. Absence indicates third-party CAD tool origin."
                ),
                evidence_strength=EvidenceStrength.INFORMATIONAL,
                is_smoking_gun=False,
            ),
            # Deep DWG Parsing Rules (TAMPER-036 to TAMPER-040) - STRUCTURAL SMOKING GUNS
            TamperingRule(
                rule_id="TAMPER-036",
                name="Critical Handle Gap Detection",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "EVIDENCE OF DELETION: Large gaps detected in object handle sequence - "
                    "indicates mass deletion of objects, potentially to hide evidence"
                ),
                evidence_strength=EvidenceStrength.DEFINITIVE,
                is_smoking_gun=True,
            ),
            TamperingRule(
                rule_id="TAMPER-037",
                name="Missing Header Section",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "STRUCTURAL ANOMALY: AcDb:Header section missing or corrupted - "
                    "file has been structurally tampered with"
                ),
                evidence_strength=EvidenceStrength.DEFINITIVE,
                is_smoking_gun=True,
            ),
            TamperingRule(
                rule_id="TAMPER-038",
                name="DWG Internal Timestamp Contradiction",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "PROVEN MANIPULATION: TDCREATE/TDUPDATE from DWG header contradicts "
                    "filesystem timestamps beyond normal variance"
                ),
                evidence_strength=EvidenceStrength.DEFINITIVE,
                is_smoking_gun=True,
            ),
            TamperingRule(
                rule_id="TAMPER-039",
                name="Handle Gap Ratio Anomaly",
                severity=RuleSeverity.WARNING,
                description=(
                    "STATISTICAL ANOMALY: Handle gap ratio exceeds threshold - "
                    "unusual amount of deleted objects suggests targeted removal"
                ),
                evidence_strength=EvidenceStrength.STRONG,
                is_smoking_gun=False,
            ),
            TamperingRule(
                rule_id="TAMPER-040",
                name="Section Map Integrity Failure",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "STRUCTURAL CORRUPTION: Section map parsing failed or returned "
                    "invalid data - file structure has been corrupted or manipulated"
                ),
                evidence_strength=EvidenceStrength.DEFINITIVE,
                is_smoking_gun=True,
            ),
            # Revit Export Detection (TAMPER-041) - FALSE POSITIVE PREVENTION
            TamperingRule(
                rule_id="TAMPER-041",
                name="Revit Export Signature Detection",
                severity=RuleSeverity.INFO,
                description=(
                    "Detects Autodesk Revit DWG exports by GUID pattern, zero CRC, "
                    "and missing timestamps. Revit exports are LEGITIMATE files - "
                    "this detection PREVENTS FALSE POSITIVES."
                ),
                evidence_strength=EvidenceStrength.INFORMATIONAL,
                is_smoking_gun=False,
            ),
        ]
        self.rules.extend(builtin)

    def get_builtin_rules(self) -> List[TamperingRule]:
        """Get all built-in tampering rules."""
        return [r for r in self.rules if r.rule_id.startswith("TAMPER-")]

    def load_rules(self, rules_path: Optional[Path] = None) -> None:
        """
        Load custom rules from YAML or JSON file.

        Args:
            rules_path: Path to rules configuration file
        """
        if rules_path is None:
            return

        if not rules_path.exists():
            raise FileNotFoundError(f"Rules file not found: {rules_path}")

        suffix = rules_path.suffix.lower()

        with open(rules_path, "r", encoding="utf-8") as f:
            if suffix in [".yaml", ".yml"]:
                config = yaml.safe_load(f)
            elif suffix == ".json":
                config = json.load(f)
            else:
                raise ValueError(f"Unsupported format: {suffix}")

        if not isinstance(config, dict) or "rules" not in config:
            raise ValueError("Rules file must contain 'rules' key")

        for rule_data in config["rules"]:
            rule = TamperingRule(**rule_data)
            self.rules.append(rule)

    def evaluate_rule(
        self, rule: TamperingRule, context: Dict[str, Any]
    ) -> RuleResult:
        """
        Evaluate a single rule against analysis context.

        Args:
            rule: Rule to evaluate
            context: Analysis context dictionary

        Returns:
            RuleResult with evaluation outcome
        """
        if not rule.enabled:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.INCONCLUSIVE,
                severity=rule.severity,
                description="Rule is disabled",
                confidence=0.0,
            )

        # Custom rules with conditions
        if rule.condition:
            passed = self._evaluate_condition(rule.condition, context)
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED if passed else RuleStatus.FAILED,
                severity=rule.severity,
                description=rule.message or rule.description,
                confidence=1.0,
            )

        # Built-in rules - dispatcher dictionary
        evaluators = {
            # Basic Rules (TAMPER-001 to TAMPER-012)
            "TAMPER-001": self._check_header_crc,
            "TAMPER-002": self._check_section_crc,
            "TAMPER-005": self._check_timestamp_reversal,
            "TAMPER-006": self._check_future_timestamp,
            "TAMPER-007": self._check_edit_time,
            "TAMPER-008": self._check_version_downgrade,
            "TAMPER-009": self._check_version_mismatch,
            "TAMPER-010": self._check_non_autodesk,
            "TAMPER-011": self._check_orphaned_objects,
            "TAMPER-012": self._check_slack_space,
            # Advanced Timestamp Rules (TAMPER-013 to TAMPER-018)
            "TAMPER-013": self._check_tdindwg_manipulation,
            "TAMPER-014": self._check_version_anachronism,
            "TAMPER-015": self._check_timezone_discrepancy,
            "TAMPER-016": self._check_educational_watermark,
            "TAMPER-017": self._check_tdusrtimer_reset,
            "TAMPER-018": self._check_network_path_leakage,
            # NTFS Cross-Validation Rules (TAMPER-019 to TAMPER-028)
            "TAMPER-019": self._check_ntfs_timestomping,
            "TAMPER-020": self._check_ntfs_nanosecond_truncation,
            "TAMPER-021": self._check_ntfs_impossible_timestamp,
            "TAMPER-022": self._check_dwg_ntfs_creation_contradiction,
            "TAMPER-023": self._check_dwg_ntfs_modification_contradiction,
            "TAMPER-024": self._check_zero_edit_time,
            "TAMPER-025": self._check_implausible_edit_ratio,
            "TAMPER-026": self._check_third_party_tool,
            "TAMPER-027": self._check_multiple_timestamp_anomalies,
            "TAMPER-028": self._check_forensic_impossibility_score,
            # CAD Application Fingerprinting Rules (TAMPER-029 to TAMPER-035)
            "TAMPER-029": self._check_oda_sdk_artifacts,
            "TAMPER-030": self._check_bricscad_signature,
            "TAMPER-031": self._check_nanocad_signature,
            "TAMPER-032": self._check_draftsight_signature,
            "TAMPER-033": self._check_opensource_cad_conversion,
            "TAMPER-034": self._check_zero_timestamp_pattern,
            "TAMPER-035": self._check_missing_autocad_identifiers,
            # Deep DWG Parsing Rules (TAMPER-036 to TAMPER-040)
            "TAMPER-036": self._check_critical_handle_gaps,
            "TAMPER-037": self._check_missing_header_section,
            "TAMPER-038": self._check_dwg_internal_timestamp_contradiction,
            "TAMPER-039": self._check_handle_gap_ratio,
            "TAMPER-040": self._check_section_map_integrity,
            # Revit Export Detection (TAMPER-041)
            "TAMPER-041": self._check_revit_export_signature,
        }

        evaluator = evaluators.get(rule.rule_id)
        if evaluator:
            return evaluator(rule, context)

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.INCONCLUSIVE,
            severity=rule.severity,
            description="Rule implementation not found",
            confidence=0.0,
        )

    def _evaluate_condition(
        self, condition: RuleCondition, context: Dict[str, Any]
    ) -> bool:
        """Evaluate custom rule condition."""
        # Navigate to field via dot notation
        parts = condition.field.split(".")
        value = context

        try:
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    return False

            if condition.operator == "equals":
                return value == condition.value
            elif condition.operator == "not_equals":
                return value != condition.value
            elif condition.operator == "greater_than":
                return value > condition.value
            elif condition.operator == "less_than":
                return value < condition.value
            elif condition.operator == "contains":
                return condition.value in value
            elif condition.operator == "not_contains":
                return condition.value not in value
            elif condition.operator == "exists":
                return value is not None
            elif condition.operator == "not_exists":
                return value is None

        except (KeyError, TypeError, AttributeError):
            pass

        return False

    def evaluate_all(
        self,
        context: Dict[str, Any],
        skip_rules: Optional[List[str]] = None
    ) -> List[RuleResult]:
        """Evaluate all enabled rules.

        Args:
            context: Analysis context dictionary
            skip_rules: Optional list of rule IDs to skip (e.g., ["TAMPER-001", "TAMPER-002"])
                        Used for provenance-based filtering (Revit exports, ODA tools, etc.)

        Returns:
            List of RuleResults
        """
        self.results = []
        skip_set = set(skip_rules or [])

        for rule in self.rules:
            if rule.enabled and rule.rule_id not in skip_set:
                result = self.evaluate_rule(rule, context)
                self.results.append(result)
            elif rule.rule_id in skip_set:
                # Add a skipped result for audit trail
                self.results.append(RuleResult(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    status=RuleStatus.INCONCLUSIVE,
                    severity=rule.severity,
                    description=f"Rule skipped based on file provenance (legitimate file characteristic)",
                    confidence=0.0,
                ))

        return self.results

    def get_failed_rules(
        self, results: Optional[List[RuleResult]] = None
    ) -> List[RuleResult]:
        """Get rules that failed evaluation.

        Args:
            results: Optional list of results to filter. If None, uses self.results.

        Returns:
            List of failed RuleResults
        """
        target = results if results is not None else self.results
        return [r for r in target if r.status == RuleStatus.FAILED]

    def get_smoking_guns(
        self, results: Optional[List[RuleResult]] = None
    ) -> List[RuleResult]:
        """Get only smoking gun (definitive proof) findings.

        Smoking guns are findings that prove tampering with MATHEMATICAL CERTAINTY.
        These are the only findings that should be presented in court as
        conclusive evidence.

        Args:
            results: Optional list of results to filter. If None, uses self.results.

        Returns:
            List of RuleResults that are smoking guns AND failed
        """
        target = results if results is not None else self.results
        return [
            r for r in target
            if r.status == RuleStatus.FAILED and r.is_smoking_gun
        ]

    def get_smoking_gun_rules(self) -> List[TamperingRule]:
        """Get all rules that can produce smoking gun evidence.

        Returns:
            List of TamperingRule instances marked as smoking guns
        """
        return [r for r in self.rules if r.is_smoking_gun]

    def has_definitive_proof(self, results: Optional[List[RuleResult]] = None) -> bool:
        """Check if any definitive proof of tampering exists.

        Args:
            results: Optional list of results to check. If None, uses self.results.

        Returns:
            True if at least one smoking gun finding exists
        """
        return len(self.get_smoking_guns(results)) > 0

    def get_tampering_score(self) -> float:
        """Calculate tampering likelihood score (0.0-1.0)."""
        if not self.results:
            return 0.0

        weights = {
            RuleSeverity.CRITICAL: 1.0,
            RuleSeverity.WARNING: 0.5,
            RuleSeverity.INFO: 0.2,
        }

        total_weight = sum(weights.get(r.severity, 0) for r in self.results)
        weighted_failures = sum(
            weights.get(r.severity, 0) * r.confidence
            for r in self.results
            if r.status == RuleStatus.FAILED
        )

        if total_weight == 0:
            return 0.0

        return min(weighted_failures / total_weight, 1.0)

    def get_tolerance(self) -> ProvenanceToleranceProfile:
        """
        Get the current tolerance profile.

        Returns:
            ProvenanceToleranceProfile instance currently in use
        """
        return self._tolerance_profile

    def set_tolerance(self, profile: ProvenanceToleranceProfile) -> None:
        """
        Set the tolerance profile for rule evaluation.

        Args:
            profile: ProvenanceToleranceProfile to use
        """
        self._tolerance_profile = profile
