"""
DWG Forensic Tool - Analysis Module

Phase 3 analysis capabilities for tampering detection:
- Anomaly detection (timestamp, version, structural)
- Tampering rule engine with built-in and custom rules
- Risk scoring and assessment
- Smoking gun synthesis (DEFINITIVE proof filtering with LLM narratives)

Evidence Strength Classification:
- DEFINITIVE: Mathematical impossibility - smoking gun, court-admissible
- STRONG: Very high confidence, multiple corroborating factors
- CIRCUMSTANTIAL: Suggestive but not conclusive
- INFORMATIONAL: Contextual only, not evidence of tampering
"""

from dwg_forensic.analysis.anomaly import AnomalyDetector
from dwg_forensic.analysis.rules import (
    EvidenceStrength,
    TamperingRule,
    RuleResult,
    TamperingRuleEngine,
    RuleSeverity,
    RuleStatus,
)
from dwg_forensic.analysis.risk import RiskScorer, TamperingReport
from dwg_forensic.analysis.smoking_gun import (
    SmokingGunFinding,
    SmokingGunReport,
    SmokingGunSynthesizer,
)

__all__ = [
    "AnomalyDetector",
    "EvidenceStrength",
    "TamperingRule",
    "RuleResult",
    "TamperingRuleEngine",
    "RuleSeverity",
    "RuleStatus",
    "RiskScorer",
    "TamperingReport",
    "SmokingGunFinding",
    "SmokingGunReport",
    "SmokingGunSynthesizer",
]
