"""
DWG Forensic Tool - Tampering Rules Package

This package provides modular tampering detection rules for DWG files.
All public APIs are re-exported here for convenience.

Rule Organization:
- models.py: Pydantic models (RuleSeverity, RuleStatus, TamperingRule, RuleResult)
- engine.py: TamperingRuleEngine class
- rules_basic.py: TAMPER-001 to TAMPER-012 (CRC, watermarks, basic timestamps)
- rules_timestamp.py: TAMPER-013 to TAMPER-018 (Advanced timestamp manipulation)
- rules_ntfs.py: TAMPER-019 to TAMPER-028 (NTFS cross-validation, SMOKING GUNS)
- rules_fingerprint.py: TAMPER-029 to TAMPER-035 (CAD application fingerprinting)
- rules_structure.py: TAMPER-036 to TAMPER-040 (Deep DWG structure analysis)

Evidence Strength Classification:
- DEFINITIVE: Mathematical impossibility - smoking gun, court-admissible
- STRONG: Very high confidence, multiple corroborating factors
- CIRCUMSTANTIAL: Suggestive but not conclusive
- INFORMATIONAL: Contextual only, not evidence of tampering
"""

from dwg_forensic.analysis.rules.engine import TamperingRuleEngine
from dwg_forensic.analysis.rules.models import (
    EvidenceStrength,
    RuleCondition,
    RuleResult,
    RuleSeverity,
    RuleStatus,
    TamperingRule,
)

__all__ = [
    # Models
    "EvidenceStrength",
    "RuleSeverity",
    "RuleStatus",
    "RuleCondition",
    "TamperingRule",
    "RuleResult",
    # Engine
    "TamperingRuleEngine",
]
