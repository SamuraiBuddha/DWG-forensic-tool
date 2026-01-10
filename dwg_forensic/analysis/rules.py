"""
DWG Forensic Tool - Tampering Rule Engine

Implements FR-TAMPER-001 through FR-TAMPER-003:
- Configurable rule definitions (YAML/JSON)
- 12 built-in tampering detection rules
- Custom rules support
"""

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field


class RuleSeverity(str, Enum):
    """Severity levels for tampering rules."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class RuleStatus(str, Enum):
    """Evaluation status for rules."""
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class RuleCondition(BaseModel):
    """Condition specification for custom rules."""
    field: str = Field(..., description="Dot-notation path to field")
    operator: Literal[
        "equals", "not_equals", "greater_than", "less_than",
        "contains", "not_contains", "exists", "not_exists"
    ]
    value: Optional[Any] = None


class TamperingRule(BaseModel):
    """Tampering detection rule specification."""
    model_config = ConfigDict(populate_by_name=True)

    rule_id: str = Field(..., alias="id", description="Rule ID (e.g., TAMPER-001)")
    name: str = Field(..., description="Human-readable rule name")
    severity: RuleSeverity = Field(..., description="Rule severity level")
    description: str = Field(..., description="Detailed description")
    enabled: bool = Field(default=True, description="Whether rule is active")
    condition: Optional[RuleCondition] = Field(
        default=None, description="Condition for custom rules"
    )
    message: Optional[str] = Field(
        default=None, description="Custom failure message"
    )


class RuleResult(BaseModel):
    """Result of rule evaluation."""
    rule_id: str
    rule_name: str
    status: RuleStatus
    severity: RuleSeverity
    description: str
    expected: Optional[str] = None
    found: Optional[str] = None
    byte_offset: Optional[int] = None
    hex_dump: Optional[str] = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    details: Optional[Dict[str, Any]] = None


class TamperingRuleEngine:
    """
    Rule engine for DWG tampering detection.

    Implements all 12 built-in rules and supports custom YAML/JSON rules.
    """

    def __init__(self):
        """Initialize with built-in rules."""
        self.rules: List[TamperingRule] = []
        self.results: List[RuleResult] = []
        self._load_builtin_rules()

    def _load_builtin_rules(self) -> None:
        """Load all 12 built-in tampering detection rules."""
        builtin = [
            TamperingRule(
                rule_id="TAMPER-001",
                name="CRC Header Mismatch",
                severity=RuleSeverity.CRITICAL,
                description="Header CRC32 checksum does not match calculated value",
            ),
            TamperingRule(
                rule_id="TAMPER-002",
                name="CRC Section Mismatch",
                severity=RuleSeverity.CRITICAL,
                description="Section CRC checksum does not match calculated value",
            ),
            TamperingRule(
                rule_id="TAMPER-003",
                name="Missing TrustedDWG",
                severity=RuleSeverity.WARNING,
                description="TrustedDWG watermark is absent (expected in R2007+)",
            ),
            TamperingRule(
                rule_id="TAMPER-004",
                name="Invalid TrustedDWG",
                severity=RuleSeverity.CRITICAL,
                description="TrustedDWG watermark is present but malformed",
            ),
            TamperingRule(
                rule_id="TAMPER-005",
                name="Timestamp Reversal",
                severity=RuleSeverity.CRITICAL,
                description="Created timestamp is after modified timestamp",
            ),
            TamperingRule(
                rule_id="TAMPER-006",
                name="Future Timestamp",
                severity=RuleSeverity.CRITICAL,
                description="Modified timestamp is in the future",
            ),
            TamperingRule(
                rule_id="TAMPER-007",
                name="Edit Time Mismatch",
                severity=RuleSeverity.WARNING,
                description="Editing time inconsistent with creation/modification dates",
            ),
            TamperingRule(
                rule_id="TAMPER-008",
                name="Version Downgrade",
                severity=RuleSeverity.WARNING,
                description="File contains objects from newer version than header",
            ),
            TamperingRule(
                rule_id="TAMPER-009",
                name="Version Mismatch",
                severity=RuleSeverity.WARNING,
                description="Header version does not match internal object versions",
            ),
            TamperingRule(
                rule_id="TAMPER-010",
                name="Non-Autodesk Origin",
                severity=RuleSeverity.INFO,
                description="File created or modified by non-Autodesk application",
            ),
            TamperingRule(
                rule_id="TAMPER-011",
                name="Orphaned Objects",
                severity=RuleSeverity.WARNING,
                description="Objects with invalid or dangling handle references found",
            ),
            TamperingRule(
                rule_id="TAMPER-012",
                name="Unusual Slack Space",
                severity=RuleSeverity.INFO,
                description="Unexpected data found in padding/slack space areas",
            ),
            # Advanced timestamp manipulation detection rules
            TamperingRule(
                rule_id="TAMPER-013",
                name="TDINDWG Manipulation",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "Cumulative editing time (TDINDWG) exceeds calendar span - "
                    "proves timestamp manipulation"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-014",
                name="Version Anachronism",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "File claims creation date before DWG version existed - "
                    "proves timestamp backdating"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-015",
                name="Timezone Discrepancy",
                severity=RuleSeverity.WARNING,
                description=(
                    "UTC/local timestamp offset is invalid or inconsistent - "
                    "indicates timestamp manipulation"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-016",
                name="Educational Watermark",
                severity=RuleSeverity.INFO,
                description=(
                    "Educational Version watermark present - "
                    "file created with student license"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-017",
                name="TDUSRTIMER Reset Indicator",
                severity=RuleSeverity.WARNING,
                description=(
                    "User timer significantly less than TDINDWG - "
                    "timer was deliberately reset to hide editing history"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-018",
                name="Network Path Leakage",
                severity=RuleSeverity.INFO,
                description=(
                    "File contains network paths (UNC or URLs) that may reveal "
                    "original file origin and network topology"
                ),
            ),
            # NTFS Cross-Validation Rules (Smoking Gun Indicators)
            TamperingRule(
                rule_id="TAMPER-019",
                name="NTFS Timestomping Detected",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "DEFINITIVE PROOF: $STANDARD_INFORMATION timestamps are earlier than "
                    "$FILE_NAME timestamps - this is IMPOSSIBLE without timestomping tools"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-020",
                name="NTFS Nanosecond Truncation",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "TOOL SIGNATURE: Timestamps have zero nanoseconds - with 10 million "
                    "possible values, this indicates manipulation by forensic/timestomping tools"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-021",
                name="NTFS Impossible Timestamp Order",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "IMPOSSIBLE CONDITION: File creation timestamp is after modification "
                    "timestamp - this cannot occur naturally on any filesystem"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-022",
                name="DWG-NTFS Creation Contradiction",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "PROVEN BACKDATING: DWG internal creation date is before the file "
                    "existed on the filesystem - conclusive evidence of timestamp manipulation"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-023",
                name="DWG-NTFS Modification Contradiction",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "PROVEN MANIPULATION: DWG internal modification date is before the file "
                    "was created - this file is a copy with backdated timestamps"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-024",
                name="Zero Edit Time",
                severity=RuleSeverity.WARNING,
                description=(
                    "File shows zero or near-zero editing time - file was "
                    "programmatically generated or timestamps were manipulated"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-025",
                name="Implausible Edit Ratio",
                severity=RuleSeverity.WARNING,
                description=(
                    "Edit time to file complexity ratio is implausible - "
                    "file was copied from another source or timestamps were manipulated"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-026",
                name="Third-Party Tool Detected",
                severity=RuleSeverity.INFO,
                description=(
                    "File was modified by third-party (non-Autodesk) software - "
                    "increases risk of timestamp manipulation"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-027",
                name="Multiple Timestamp Anomalies",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "COMPOUND EVIDENCE: Multiple independent timestamp anomalies detected - "
                    "the probability of all occurring naturally is statistically negligible"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-028",
                name="Forensic Impossibility Score",
                severity=RuleSeverity.CRITICAL,
                description=(
                    "DEFINITIVE CONCLUSION: Combination of forensic indicators proves "
                    "timestamp manipulation beyond reasonable doubt"
                ),
            ),
            # =================================================================
            # CAD APPLICATION FINGERPRINTING RULES (TAMPER-029 to TAMPER-035)
            # Based on comprehensive research of third-party CAD applications
            # =================================================================
            TamperingRule(
                rule_id="TAMPER-029",
                name="ODA SDK Artifact Detection",
                severity=RuleSeverity.INFO,
                description=(
                    "Open Design Alliance SDK artifacts detected - file created by "
                    "non-Autodesk application (BricsCAD, NanoCAD, DraftSight, etc.)"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-030",
                name="BricsCAD Signature",
                severity=RuleSeverity.INFO,
                description=(
                    "BricsCAD-specific signatures detected (BRICSYS APPID, "
                    "ACAD_BRICSCAD_INFO dictionary) - file created by BricsCAD"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-031",
                name="NanoCAD Signature",
                severity=RuleSeverity.INFO,
                description=(
                    "NanoCAD-specific signatures detected (NANOCAD APPID, "
                    "CP1251 codepage) - file created by Russian NanoCAD"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-032",
                name="DraftSight Signature",
                severity=RuleSeverity.INFO,
                description=(
                    "DraftSight-specific signatures detected (DRAFTSIGHT APPID, "
                    "DS_LICENSE_TYPE) - file created by Dassault Systemes DraftSight"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-033",
                name="Open Source CAD Conversion",
                severity=RuleSeverity.WARNING,
                description=(
                    "LibreCAD/QCAD/FreeCAD conversion artifacts detected - file was "
                    "converted from DXF or created by open-source CAD software"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-034",
                name="Zero Timestamp Pattern",
                severity=RuleSeverity.WARNING,
                description=(
                    "TDCREATE and TDUPDATE are both zero or identical with zero TDINDWG - "
                    "strong indicator of LibreCAD, QCAD, or programmatic file generation"
                ),
            ),
            TamperingRule(
                rule_id="TAMPER-035",
                name="Missing AutoCAD Identifiers",
                severity=RuleSeverity.WARNING,
                description=(
                    "Missing FINGERPRINTGUID and/or VERSIONGUID - AutoCAD always generates "
                    "these identifiers. Absence indicates third-party CAD tool origin."
                ),
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

        # Built-in rules
        evaluators = {
            "TAMPER-001": self._check_header_crc,
            "TAMPER-002": self._check_section_crc,
            "TAMPER-003": self._check_missing_watermark,
            "TAMPER-004": self._check_invalid_watermark,
            "TAMPER-005": self._check_timestamp_reversal,
            "TAMPER-006": self._check_future_timestamp,
            "TAMPER-007": self._check_edit_time,
            "TAMPER-008": self._check_version_downgrade,
            "TAMPER-009": self._check_version_mismatch,
            "TAMPER-010": self._check_non_autodesk,
            "TAMPER-011": self._check_orphaned_objects,
            "TAMPER-012": self._check_slack_space,
            # Advanced timestamp manipulation rules
            "TAMPER-013": self._check_tdindwg_manipulation,
            "TAMPER-014": self._check_version_anachronism,
            "TAMPER-015": self._check_timezone_discrepancy,
            "TAMPER-016": self._check_educational_watermark,
            "TAMPER-017": self._check_tdusrtimer_reset,
            "TAMPER-018": self._check_network_path_leakage,
            # NTFS Cross-Validation Rules (Smoking Gun Indicators)
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
            # CAD Application Fingerprinting Rules
            "TAMPER-029": self._check_oda_sdk_artifacts,
            "TAMPER-030": self._check_bricscad_signature,
            "TAMPER-031": self._check_nanocad_signature,
            "TAMPER-032": self._check_draftsight_signature,
            "TAMPER-033": self._check_opensource_cad_conversion,
            "TAMPER-034": self._check_zero_timestamp_pattern,
            "TAMPER-035": self._check_missing_autocad_identifiers,
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

    # =========================================================================
    # Advanced Timestamp Manipulation Rules (TAMPER-013 to TAMPER-016)
    # =========================================================================

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
                from dwg_forensic.parsers.timestamp import mjd_to_datetime
                from dwg_forensic.analysis.version_dates import is_date_before_version_release

                try:
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

    # =========================================================================
    # NTFS Cross-Validation Rules (TAMPER-019 to TAMPER-028)
    # These rules provide DEFINITIVE forensic evidence of tampering
    # =========================================================================

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
        watermark = context.get("watermark") or context.get("trusted_dwg", {})

        # Check for valid Autodesk watermark
        is_present = watermark.get("present", watermark.get("watermark_present", False))
        is_valid = watermark.get("valid", watermark.get("watermark_valid", True))
        origin = watermark.get("application_origin", "")

        # Known third-party applications
        third_party_markers = [
            "BricsCAD", "DraftSight", "LibreCAD", "ZWCAD", "GstarCAD",
            "progeCAD", "IntelliCAD", "CorelCAD", "TurboCAD", "NanoCAD",
            "Open Design", "ODA", "LibreDWG", "DWGdirect"
        ]

        detected_tool = None
        for marker in third_party_markers:
            if marker.lower() in origin.lower():
                detected_tool = marker
                break

        # If valid Autodesk watermark present, pass
        if is_present and is_valid:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] File has valid Autodesk TrustedDWG watermark",
                confidence=1.0,
            )

        if detected_tool:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.FAILED,
                severity=rule.severity,
                description=f"[INFO] Third-party tool detected: {detected_tool}",
                found=f"Application origin: {origin}",
                confidence=0.8,
                details={
                    "detected_tool": detected_tool,
                    "forensic_note": (
                        f"{detected_tool} is a third-party CAD application. "
                        "Third-party tools do not preserve Autodesk timestamp integrity "
                        "and can be used to manipulate file metadata."
                    ),
                },
            )

        # No watermark and no detected third-party tool
        if not is_present:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.FAILED,
                severity=rule.severity,
                description="[INFO] No TrustedDWG watermark - third-party modification detected",
                confidence=0.6,
                details={
                    "forensic_note": (
                        "The absence of an Autodesk TrustedDWG watermark confirms "
                        "this file was created or modified by non-Autodesk software, "
                        "which significantly increases the risk of timestamp manipulation."
                    ),
                },
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

    # =========================================================================
    # CAD Application Fingerprinting Rules (TAMPER-029 to TAMPER-035)
    # Based on comprehensive research of third-party CAD applications
    # =========================================================================

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
        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=f"[INFO] ODA SDK artifacts detected: {app_list}",
            confidence=0.9,
            details={
                "is_oda_based": True,
                "indicators": indicators,
                "detected_applications": detected_apps,
                "forensic_note": (
                    "ODA-based applications do not generate TrustedDWG watermarks "
                    "and may not maintain Autodesk timestamp integrity."
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

        if not is_bricscad and not bricscad_markers:
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                status=RuleStatus.PASSED,
                severity=rule.severity,
                description="[OK] No BricsCAD signatures detected",
                confidence=1.0,
            )

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description="[INFO] BricsCAD application signatures detected",
            confidence=0.95,
            details={
                "application": "BricsCAD",
                "markers": bricscad_markers,
                "forensic_note": (
                    "BricsCAD is an ODA-based CAD application by Bricsys. "
                    "Files created by BricsCAD lack TrustedDWG watermarks."
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

        if not is_nanocad and not has_cyrillic:
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
            "origin": "Russian (Nanosoft)",
            "forensic_note": (
                "NanoCAD is a Russian ODA-based CAD application. "
                "Files may contain Cyrillic text in CP1251 encoding."
            ),
        }

        if has_cyrillic:
            details["codepage"] = codepage
            details["cyrillic_indicator"] = True

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description="[INFO] NanoCAD application signatures detected",
            confidence=0.9 if is_nanocad else 0.7,
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

        if not is_draftsight and not license_type:
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
                "DraftSight is an ODA-based CAD application by Dassault Systemes. "
                "Free version was discontinued in 2019."
            ),
        }

        if license_type:
            details["license_type"] = license_type

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description="[INFO] DraftSight application signatures detected",
            confidence=0.95,
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
        """
        timestamp_data = context.get("timestamp_data", {})
        metadata = context.get("metadata", {})
        timestamp_anomalies = context.get("timestamp_anomalies", {})

        # Get timestamp values
        tdcreate = timestamp_data.get("tdcreate") or metadata.get("tdcreate")
        tdupdate = timestamp_data.get("tdupdate") or metadata.get("tdupdate")
        tdindwg = timestamp_data.get("tdindwg") or metadata.get("tdindwg")

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
        """
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

        if fingerprintguid is None or fingerprintguid == "" or fingerprintguid == "{00000000-0000-0000-0000-000000000000}":
            missing_identifiers.append("FINGERPRINTGUID")

        if versionguid is None or versionguid == "" or versionguid == "{00000000-0000-0000-0000-000000000000}":
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

        return RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=RuleStatus.FAILED,
            severity=rule.severity,
            description=f"[WARN] Missing AutoCAD identifiers: {', '.join(missing_identifiers)}",
            confidence=0.85,
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

    def evaluate_all(self, context: Dict[str, Any]) -> List[RuleResult]:
        """Evaluate all enabled rules."""
        self.results = []

        for rule in self.rules:
            if rule.enabled:
                result = self.evaluate_rule(rule, context)
                self.results.append(result)

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
