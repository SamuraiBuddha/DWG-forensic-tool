"""
Data models for LLM-powered anomaly filtering.

These models support Phase 4.2 integration where the ForensicReasoner evaluates
anomalies detected by the rule engine and filters out expected red herrings
based on file provenance context (Revit exports, ODA tools, file transfers).
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from dwg_forensic.models import AnomalyType, RiskLevel


@dataclass
class Anomaly:
    """
    Detected anomaly from the rule engine.

    This is a simplified representation of rule violations that
    the LLM reasoner evaluates for forensic significance.
    """
    rule_id: str
    description: str
    severity: RiskLevel
    timestamp_related: bool = False
    evidence_strength: str = "CIRCUMSTANTIAL"  # DEFINITIVE, STRONG, CIRCUMSTANTIAL, INFORMATIONAL
    details: dict = field(default_factory=dict)

    @classmethod
    def from_rule_result(cls, rule_result: dict) -> "Anomaly":
        """Create Anomaly from rule engine result."""
        return cls(
            rule_id=rule_result.get("rule_id", "UNKNOWN"),
            description=rule_result.get("description", ""),
            severity=RiskLevel(rule_result.get("severity", "LOW")),
            timestamp_related="timestamp" in rule_result.get("description", "").lower(),
            evidence_strength=rule_result.get("evidence_strength", "CIRCUMSTANTIAL"),
            details=rule_result.get("details", {}),
        )


@dataclass
class ProvenanceInfo:
    """
    File provenance context for anomaly filtering.

    This captures the origin and creation context of the DWG file,
    which determines which anomalies are expected vs suspicious.
    """
    cad_app: str  # "AutoCAD", "Revit", "BricsCAD", "ODA Tool", etc.
    version: Optional[str] = None
    provenance_path: str = "Unknown"  # "Revit Export", "ODA Transfer", "Native AutoCAD"
    confidence: float = 0.0  # 0.0-1.0 detection confidence

    # Flags for common provenance patterns
    is_revit_export: bool = False
    is_oda_tool: bool = False
    is_file_transfer: bool = False
    is_native_autocad: bool = False

    # Additional context
    expected_anomalies: List[str] = field(default_factory=list)  # Rule IDs expected for this provenance
    detection_notes: List[str] = field(default_factory=list)

    @classmethod
    def from_provenance_result(cls, provenance: dict) -> "ProvenanceInfo":
        """Create ProvenanceInfo from provenance detector result."""
        return cls(
            cad_app=provenance.get("source_application", "Unknown"),
            version=provenance.get("version"),
            provenance_path=cls._determine_path(provenance),
            confidence=provenance.get("confidence", 0.0),
            is_revit_export=provenance.get("is_revit_export", False),
            is_oda_tool=provenance.get("is_oda_tool", False),
            is_file_transfer=provenance.get("is_transferred", False),
            is_native_autocad=provenance.get("is_native_autocad", False),
            expected_anomalies=provenance.get("rules_to_skip", []),
            detection_notes=provenance.get("detection_notes", []),
        )

    @staticmethod
    def _determine_path(provenance: dict) -> str:
        """Determine provenance path description."""
        if provenance.get("is_revit_export"):
            return "Revit Export"
        elif provenance.get("is_oda_tool"):
            return "ODA SDK Tool"
        elif provenance.get("is_transferred"):
            return "File Transfer"
        elif provenance.get("is_native_autocad"):
            return "Native AutoCAD"
        else:
            return "Unknown Origin"


@dataclass
class FilteredAnomalies:
    """
    Result of LLM-powered anomaly filtering.

    The reasoner separates true smoking guns from expected red herrings
    based on file provenance context and forensic logic.
    """
    kept_anomalies: List[Anomaly]
    filtered_anomalies: List[Anomaly]
    reasoning: str
    llm_confidence: float  # 0.0-1.0 confidence in filtering decision
    method: str  # "llm" or "heuristic"

    # Statistics
    total_count: int = field(init=False)
    kept_count: int = field(init=False)
    filtered_count: int = field(init=False)
    filter_rate: float = field(init=False)  # Percentage filtered

    # Warnings
    low_confidence_warning: bool = field(init=False)
    smoking_guns_preserved: int = field(init=False)  # Count of DEFINITIVE evidence kept

    def __post_init__(self):
        """Calculate statistics after initialization."""
        self.kept_count = len(self.kept_anomalies)
        self.filtered_count = len(self.filtered_anomalies)
        self.total_count = self.kept_count + self.filtered_count
        self.filter_rate = (self.filtered_count / self.total_count * 100) if self.total_count > 0 else 0.0
        self.low_confidence_warning = self.llm_confidence < 0.6
        self.smoking_guns_preserved = sum(
            1 for a in self.kept_anomalies if a.evidence_strength == "DEFINITIVE"
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "kept_anomalies": [
                {
                    "rule_id": a.rule_id,
                    "description": a.description,
                    "severity": a.severity.value,
                    "evidence_strength": a.evidence_strength,
                }
                for a in self.kept_anomalies
            ],
            "filtered_anomalies": [
                {
                    "rule_id": a.rule_id,
                    "description": a.description,
                    "severity": a.severity.value,
                    "evidence_strength": a.evidence_strength,
                }
                for a in self.filtered_anomalies
            ],
            "reasoning": self.reasoning,
            "llm_confidence": self.llm_confidence,
            "method": self.method,
            "statistics": {
                "total_count": self.total_count,
                "kept_count": self.kept_count,
                "filtered_count": self.filtered_count,
                "filter_rate": f"{self.filter_rate:.1f}%",
                "smoking_guns_preserved": self.smoking_guns_preserved,
            },
            "warnings": {
                "low_confidence": self.low_confidence_warning,
            },
        }


@dataclass
class SmokingGunRule:
    """
    Rules that should NEVER be filtered - definitive proof of tampering.

    These represent mathematical or physical impossibilities that cannot
    occur naturally, regardless of file provenance.

    Note: TAMPER-001 (CRC) is handled specially - only a smoking gun if
    CRC is non-zero and mismatched. CRC=0 for Revit/ODA is expected.
    """
    rule_ids: List[str] = field(default_factory=lambda: [
        # TAMPER-001 excluded - special handling needed for CRC=0 vs mismatch
        "TAMPER-019",  # NTFS SI/FN mismatch - kernel-level proof
        "TAMPER-020",  # NTFS creation after modification - impossible
        "TAMPER-021",  # NTFS nanosecond truncation - tool signature
        "TAMPER-022",  # DWG-NTFS creation contradiction - strong proof
        "TAMPER-023",  # DWG-NTFS modification contradiction
        "TAMPER-024",  # Multiple NTFS zero nanoseconds - statistical impossibility
        "TAMPER-025",  # NTFS impossible timestamp sequence
        "TAMPER-026",  # NTFS future timestamp
        "TAMPER-027",  # NTFS kernel-protected timestamp violation
        "TAMPER-028",  # NTFS forensic chain broken
        "TAMPER-014",  # TDINDWG exceeds span - mathematical impossibility
        "TAMPER-015",  # Version anachronism - temporal impossibility
    ])

    def is_smoking_gun(self, rule_id: str) -> bool:
        """Check if rule ID represents a smoking gun."""
        return rule_id in self.rule_ids

    def validate_filtering(self, filtered_anomalies: List[Anomaly]) -> Optional[str]:
        """
        Validate that no smoking guns were filtered.

        Returns error message if smoking guns were filtered, None otherwise.
        """
        filtered_guns = [
            a for a in filtered_anomalies if self.is_smoking_gun(a.rule_id)
        ]

        if filtered_guns:
            gun_ids = [a.rule_id for a in filtered_guns]
            return f"CRITICAL ERROR: Smoking gun rules filtered: {gun_ids}"

        return None
