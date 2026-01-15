"""
DWG Forensic Tool - Tampering Rule Models

Pydantic models for tampering detection rules and results.
"""

from enum import Enum
from typing import Any, Dict, Literal, Optional

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


class EvidenceStrength(str, Enum):
    """Evidence strength classification for legal admissibility."""
    DEFINITIVE = "definitive"  # Mathematical impossibility - smoking gun
    STRONG = "strong"  # Very high confidence, multiple corroborating factors
    CIRCUMSTANTIAL = "circumstantial"  # Suggestive but not conclusive
    INFORMATIONAL = "informational"  # Contextual only, not evidence


class TamperingRule(BaseModel):
    """Tampering detection rule specification."""
    model_config = ConfigDict(populate_by_name=True)

    rule_id: str = Field(..., alias="id", description="Rule ID (e.g., TAMPER-001)")
    name: str = Field(..., description="Human-readable rule name")
    severity: RuleSeverity = Field(..., description="Rule severity level")
    description: str = Field(..., description="Detailed description")
    enabled: bool = Field(default=True, description="Whether rule is active")
    evidence_strength: EvidenceStrength = Field(
        default=EvidenceStrength.CIRCUMSTANTIAL,
        description="Legal evidence strength classification"
    )
    is_smoking_gun: bool = Field(
        default=False,
        description="True if this rule proves tampering with mathematical certainty"
    )
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
    evidence_strength: EvidenceStrength = Field(
        default=EvidenceStrength.CIRCUMSTANTIAL,
        description="Legal evidence strength classification"
    )
    is_smoking_gun: bool = Field(
        default=False,
        description="True if this finding proves tampering with mathematical certainty"
    )
    forensic_reasoning: Optional[str] = Field(
        default=None,
        description="Expert-level explanation of why this proves tampering"
    )
