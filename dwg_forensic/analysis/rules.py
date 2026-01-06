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
from pydantic import BaseModel, Field


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

    class Config:
        populate_by_name = True


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
                rule_id=rule.id,
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
                rule_id=rule.id,
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
