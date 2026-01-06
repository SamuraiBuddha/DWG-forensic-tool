"""
DWG Forensic Tool - Analysis Module

Phase 3 analysis capabilities for tampering detection:
- Anomaly detection (timestamp, version, structural)
- Tampering rule engine with built-in and custom rules
- Risk scoring and assessment
"""

from dwg_forensic.analysis.anomaly import AnomalyDetector
from dwg_forensic.analysis.rules import (
    TamperingRule,
    RuleResult,
    TamperingRuleEngine,
    RuleSeverity,
    RuleStatus,
)
from dwg_forensic.analysis.risk import RiskScorer, TamperingReport

__all__ = [
    "AnomalyDetector",
    "TamperingRule",
    "RuleResult",
    "TamperingRuleEngine",
    "RuleSeverity",
    "RuleStatus",
    "RiskScorer",
    "TamperingReport",
]
