"""
DWG Forensic Tool - Knowledge Graph Models

Pydantic models for forensic knowledge graph data structures.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ReliabilityLevel(str, Enum):
    """Reliability classification for forensic techniques."""

    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    EXPERIMENTAL = "Experimental"


class ForensicStandardInfo(BaseModel):
    """Information about a forensic standard or guideline."""

    name: str = Field(..., description="Standard name (e.g., ISO/IEC 27037:2012)")
    organization: str = Field(..., description="Issuing organization")
    description: str = Field(default="", description="Standard description")
    version: Optional[str] = Field(None, description="Version or year")
    url: Optional[str] = Field(None, description="Reference URL")
    relevance: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Relevance score to current analysis"
    )


class LegalCaseInfo(BaseModel):
    """Information about a legal precedent case."""

    name: str = Field(..., description="Case name (e.g., Daubert v. Merrell Dow)")
    citation: str = Field(..., description="Legal citation (e.g., 509 U.S. 579)")
    year: int = Field(..., description="Year of decision")
    jurisdiction: str = Field(default="US", description="Legal jurisdiction")
    holding: str = Field(default="", description="Key holding or principle")
    relevance: str = Field(
        default="", description="Why this case is relevant to the analysis"
    )


class ForensicTechniqueInfo(BaseModel):
    """Information about a forensic analysis technique."""

    name: str = Field(..., description="Technique name")
    description: str = Field(default="", description="Technique description")
    reliability: ReliabilityLevel = Field(
        default=ReliabilityLevel.HIGH, description="Reliability classification"
    )
    error_rate: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Known error rate if available"
    )
    peer_reviewed: bool = Field(
        default=True, description="Whether technique is peer-reviewed"
    )
    standards_compliance: List[str] = Field(
        default_factory=list, description="Applicable standards"
    )


class TamperingIndicatorInfo(BaseModel):
    """Information about a tampering indicator from the knowledge graph."""

    indicator_id: str = Field(..., description="Indicator ID (e.g., TIMESTAMP-001)")
    name: str = Field(..., description="Indicator name")
    description: str = Field(default="", description="What this indicator detects")
    severity: str = Field(default="MEDIUM", description="Severity level")
    forensic_significance: str = Field(
        default="", description="Why this is forensically significant"
    )
    rule_ids: List[str] = Field(
        default_factory=list, description="Mapped TAMPER-XXX rule IDs"
    )
    techniques: List[str] = Field(
        default_factory=list, description="Detection techniques used"
    )
    legal_cases: List[str] = Field(
        default_factory=list, description="Relevant legal precedents"
    )


class ForensicKnowledge(BaseModel):
    """Aggregated forensic knowledge for an analysis."""

    standards: List[ForensicStandardInfo] = Field(
        default_factory=list, description="Applicable forensic standards"
    )
    legal_cases: List[LegalCaseInfo] = Field(
        default_factory=list, description="Relevant legal precedents"
    )
    techniques: List[ForensicTechniqueInfo] = Field(
        default_factory=list, description="Forensic techniques applied"
    )
    tampering_indicators: List[TamperingIndicatorInfo] = Field(
        default_factory=list, description="Matched tampering indicators"
    )
    expert_context: Dict[str, Any] = Field(
        default_factory=dict, description="Additional context for expert testimony"
    )
    retrieval_timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="When knowledge was retrieved"
    )

    def get_citation_summary(self) -> str:
        """Generate a summary of legal citations for reports."""
        if not self.legal_cases:
            return ""

        citations = []
        for case in self.legal_cases:
            citations.append(f"{case.name}, {case.citation} ({case.year})")

        return "; ".join(citations)

    def get_standards_summary(self) -> str:
        """Generate a summary of applicable standards for reports."""
        if not self.standards:
            return ""

        return ", ".join(s.name for s in self.standards)

    def get_admissibility_statement(self) -> str:
        """Generate an admissibility statement based on knowledge graph data."""
        statements = []

        # Check for Daubert standard
        daubert_cases = [c for c in self.legal_cases if "daubert" in c.name.lower()]
        if daubert_cases:
            statements.append(
                "Analysis methodology meets Daubert standard requirements for "
                "scientific evidence admissibility."
            )

        # Check for peer-reviewed techniques
        peer_reviewed = [t for t in self.techniques if t.peer_reviewed]
        if peer_reviewed:
            technique_names = ", ".join(t.name for t in peer_reviewed[:3])
            statements.append(
                f"Techniques employed ({technique_names}) are peer-reviewed "
                "and generally accepted in the digital forensics community."
            )

        # Check standards compliance
        if self.standards:
            std_names = ", ".join(s.name for s in self.standards[:3])
            statements.append(
                f"Analysis conducted in accordance with {std_names}."
            )

        return " ".join(statements) if statements else ""

    class Config:
        """Pydantic configuration."""

        json_encoders = {datetime: lambda v: v.isoformat()}
