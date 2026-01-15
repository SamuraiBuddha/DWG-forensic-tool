"""
DWG Forensic Tool - Tampering Rule Engine (Backward Compatibility Shim)

This module re-exports all public APIs from the rules subpackage.
For new code, import directly from dwg_forensic.analysis.rules.

Note: This file maintains backward compatibility with existing imports:
    from dwg_forensic.analysis.rules import TamperingRuleEngine
    from dwg_forensic.analysis import TamperingRuleEngine  # Also works
"""

# Re-export all public APIs from the rules subpackage
from dwg_forensic.analysis.rules import (
    RuleCondition,
    RuleResult,
    RuleSeverity,
    RuleStatus,
    TamperingRule,
    TamperingRuleEngine,
)

__all__ = [
    "RuleSeverity",
    "RuleStatus",
    "RuleCondition",
    "TamperingRule",
    "RuleResult",
    "TamperingRuleEngine",
]
