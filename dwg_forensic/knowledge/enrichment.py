"""
DWG Forensic Tool - Knowledge Enrichment Module

Enriches forensic analysis results with knowledge graph data including
legal citations, forensic standards compliance, and expert witness context.
Provides fallback data when Neo4j is unavailable.
"""

import logging
from typing import Any, Dict, List, Optional, Set

from dwg_forensic.knowledge.client import Neo4jKnowledgeClient
from dwg_forensic.knowledge.models import (
    ForensicKnowledge,
    ForensicStandardInfo,
    ForensicTechniqueInfo,
    LegalCaseInfo,
    ReliabilityLevel,
    TamperingIndicatorInfo,
)

logger = logging.getLogger(__name__)


# Fallback data when Neo4j is unavailable
# This ensures the tool works offline with essential forensic knowledge
FALLBACK_STANDARDS: List[ForensicStandardInfo] = [
    ForensicStandardInfo(
        name="ISO/IEC 27037:2012",
        organization="ISO/IEC",
        description=(
            "Guidelines for identification, collection, acquisition and "
            "preservation of digital evidence"
        ),
        version="2012",
    ),
    ForensicStandardInfo(
        name="NIST SP 800-86",
        organization="NIST",
        description="Guide to Integrating Forensic Techniques into Incident Response",
        version="2006",
    ),
    ForensicStandardInfo(
        name="SWGDE Best Practices",
        organization="SWGDE",
        description=(
            "Scientific Working Group on Digital Evidence best practices "
            "for computer forensics"
        ),
    ),
    ForensicStandardInfo(
        name="ACPO Guidelines v5",
        organization="ACPO",
        description="Good Practice Guide for Digital Evidence",
        version="v5",
    ),
]

FALLBACK_LEGAL_CASES: List[LegalCaseInfo] = [
    LegalCaseInfo(
        name="Daubert v. Merrell Dow Pharmaceuticals",
        citation="509 U.S. 579",
        year=1993,
        jurisdiction="US Supreme Court",
        holding=(
            "Scientific evidence must be based on sufficient facts, reliable principles "
            "and methods, and reliably applied to the facts of the case"
        ),
        relevance=(
            "Establishes standard for admissibility of scientific/technical expert testimony"
        ),
    ),
    LegalCaseInfo(
        name="Lorraine v. Markel American Insurance Co.",
        citation="241 F.R.D. 534",
        year=2007,
        jurisdiction="D. Maryland",
        holding=(
            "ESI must satisfy authentication requirements under FRE 901(b)(4) and "
            "the best evidence rule under FRE 1001-1008"
        ),
        relevance=(
            "Comprehensive framework for authentication of electronic evidence"
        ),
    ),
    LegalCaseInfo(
        name="Frye v. United States",
        citation="293 F. 1013",
        year=1923,
        jurisdiction="D.C. Circuit",
        holding=(
            "Scientific evidence must be sufficiently established to have gained "
            "general acceptance in the particular field"
        ),
        relevance="Pre-Daubert standard still used in some jurisdictions",
    ),
]

FALLBACK_TECHNIQUES: List[ForensicTechniqueInfo] = [
    ForensicTechniqueInfo(
        name="CRC32 Validation",
        description=(
            "Validates file integrity by comparing stored CRC32 checksum against "
            "calculated value from file content"
        ),
        reliability=ReliabilityLevel.HIGH,
        error_rate=0.0,
        peer_reviewed=True,
        standards_compliance=["ISO/IEC 27037:2012", "NIST SP 800-86"],
    ),
    ForensicTechniqueInfo(
        name="Timestamp Cross-Validation",
        description=(
            "Compares timestamps from multiple sources (DWG internal, NTFS $MFT, "
            "$STANDARD_INFORMATION, $FILE_NAME) to detect manipulation"
        ),
        reliability=ReliabilityLevel.HIGH,
        error_rate=0.01,
        peer_reviewed=True,
        standards_compliance=["SWGDE Best Practices"],
    ),
    ForensicTechniqueInfo(
        name="GUID Analysis",
        description=(
            "Analyzes FINGERPRINTGUID and VERSIONGUID to determine file origin "
            "and detect unauthorized modifications"
        ),
        reliability=ReliabilityLevel.HIGH,
        error_rate=0.0,
        peer_reviewed=True,
        standards_compliance=["ISO/IEC 27037:2012"],
    ),
    ForensicTechniqueInfo(
        name="NTFS $MFT Analysis",
        description=(
            "Examines NTFS Master File Table timestamps including "
            "$STANDARD_INFORMATION and $FILE_NAME attributes"
        ),
        reliability=ReliabilityLevel.HIGH,
        error_rate=0.0,
        peer_reviewed=True,
        standards_compliance=["NIST SP 800-86", "SWGDE Best Practices"],
    ),
]

FALLBACK_INDICATORS: List[TamperingIndicatorInfo] = [
    TamperingIndicatorInfo(
        indicator_id="TIMESTAMP-001",
        name="TDUPDATE Before TDCREATE",
        description="DWG modification timestamp precedes creation timestamp",
        severity="CRITICAL",
        forensic_significance=(
            "Impossible in normal file creation - indicates timestamp manipulation"
        ),
        rule_ids=["TAMPER-005", "TAMPER-006"],
        techniques=["Timestamp Cross-Validation"],
        legal_cases=["Lorraine v. Markel"],
    ),
    TamperingIndicatorInfo(
        indicator_id="INTEGRITY-001",
        name="CRC Mismatch",
        description="Stored CRC32 does not match calculated file checksum",
        severity="CRITICAL",
        forensic_significance=(
            "File content was modified after original save without proper update"
        ),
        rule_ids=["TAMPER-001", "TAMPER-002"],
        techniques=["CRC32 Validation"],
        legal_cases=["Daubert v. Merrell Dow"],
    ),
    TamperingIndicatorInfo(
        indicator_id="NTFS-TIMESTOMP-001",
        name="SI vs FN Timestamp Discrepancy",
        description=(
            "NTFS $STANDARD_INFORMATION timestamp differs from $FILE_NAME timestamp"
        ),
        severity="CRITICAL",
        forensic_significance=(
            "Classic timestomping indicator - $SI can be modified, $FN requires "
            "kernel-level access and is rarely manipulated"
        ),
        rule_ids=["TAMPER-019", "TAMPER-020", "TAMPER-021"],
        techniques=["NTFS $MFT Analysis", "Timestamp Cross-Validation"],
        legal_cases=["Lorraine v. Markel"],
    ),
    TamperingIndicatorInfo(
        indicator_id="NTFS-TIMESTOMP-002",
        name="Nanosecond Truncation",
        description="NTFS timestamps show truncated nanosecond precision",
        severity="HIGH",
        forensic_significance=(
            "File copying or timestamp manipulation tools often truncate "
            "nanosecond precision that NTFS natively supports"
        ),
        rule_ids=["TAMPER-022", "TAMPER-023"],
        techniques=["NTFS $MFT Analysis"],
        legal_cases=[],
    ),
    TamperingIndicatorInfo(
        indicator_id="FINGERPRINT-001",
        name="Missing AutoCAD Identifiers",
        description="FINGERPRINTGUID or VERSIONGUID missing or null",
        severity="MEDIUM",
        forensic_significance=(
            "AutoCAD always generates these GUIDs - absence indicates "
            "third-party CAD tool or file manipulation"
        ),
        rule_ids=["TAMPER-035"],
        techniques=["GUID Analysis"],
        legal_cases=[],
    ),
]


# Mapping from TAMPER-XXX rule IDs to indicator categories
RULE_TO_INDICATOR_MAP: Dict[str, str] = {
    # CRC rules
    "TAMPER-001": "INTEGRITY",
    "TAMPER-002": "INTEGRITY",
    # Basic timestamp rules
    "TAMPER-005": "TIMESTAMP",
    "TAMPER-006": "TIMESTAMP",
    "TAMPER-007": "TIMESTAMP",
    "TAMPER-008": "TIMESTAMP",
    "TAMPER-009": "TIMESTAMP",
    "TAMPER-010": "TIMESTAMP",
    "TAMPER-011": "TIMESTAMP",
    "TAMPER-012": "TIMESTAMP",
    # Advanced timestamp rules
    "TAMPER-013": "TIMESTAMP",
    "TAMPER-014": "TIMESTAMP",
    "TAMPER-015": "TIMESTAMP",
    "TAMPER-016": "TIMESTAMP",
    "TAMPER-017": "TIMESTAMP",
    "TAMPER-018": "TIMESTAMP",
    # NTFS rules
    "TAMPER-019": "NTFS-TIMESTOMP",
    "TAMPER-020": "NTFS-TIMESTOMP",
    "TAMPER-021": "NTFS-TIMESTOMP",
    "TAMPER-022": "NTFS-TIMESTOMP",
    "TAMPER-023": "NTFS-TIMESTOMP",
    "TAMPER-024": "NTFS-TIMESTOMP",
    "TAMPER-025": "NTFS-TIMESTOMP",
    "TAMPER-026": "NTFS-TIMESTOMP",
    "TAMPER-027": "NTFS-TIMESTOMP",
    "TAMPER-028": "NTFS-TIMESTOMP",
    # Fingerprint rules
    "TAMPER-029": "FINGERPRINT",
    "TAMPER-030": "FINGERPRINT",
    "TAMPER-031": "FINGERPRINT",
    "TAMPER-032": "FINGERPRINT",
    "TAMPER-033": "FINGERPRINT",
    "TAMPER-034": "FINGERPRINT",
    "TAMPER-035": "FINGERPRINT",
    # Structure rules
    "TAMPER-036": "STRUCTURE",
    "TAMPER-037": "STRUCTURE",
    "TAMPER-038": "STRUCTURE",
    "TAMPER-039": "STRUCTURE",
    "TAMPER-040": "STRUCTURE",
}


class KnowledgeEnricher:
    """Enriches forensic analysis with knowledge graph data."""

    def __init__(
        self,
        neo4j_client: Optional[Neo4jKnowledgeClient] = None,
        use_fallback: bool = True,
    ):
        """Initialize knowledge enricher.

        Args:
            neo4j_client: Optional Neo4j client for live queries
            use_fallback: Whether to use fallback data when Neo4j unavailable
        """
        self.client = neo4j_client
        self.use_fallback = use_fallback
        self._cached_knowledge: Optional[ForensicKnowledge] = None

    def enrich_analysis(
        self,
        failed_rule_ids: List[str],
        detected_anomalies: Optional[List[str]] = None,
        include_admissibility: bool = True,
    ) -> ForensicKnowledge:
        """Enrich analysis results with forensic knowledge.

        Args:
            failed_rule_ids: List of TAMPER-XXX rule IDs that failed
            detected_anomalies: Optional list of anomaly types detected
            include_admissibility: Whether to include admissibility context

        Returns:
            ForensicKnowledge with relevant standards, cases, techniques
        """
        # Try to get knowledge from Neo4j
        if self.client and self.client.is_connected:
            try:
                knowledge = self._enrich_from_neo4j(
                    failed_rule_ids, include_admissibility
                )
                if knowledge.standards or knowledge.legal_cases:
                    return knowledge
            except Exception as e:
                logger.warning("Neo4j enrichment failed, using fallback: %s", str(e))

        # Use fallback data
        if self.use_fallback:
            return self._enrich_from_fallback(failed_rule_ids, include_admissibility)

        # Return empty knowledge if no fallback
        return ForensicKnowledge()

    def _enrich_from_neo4j(
        self, failed_rule_ids: List[str], include_admissibility: bool
    ) -> ForensicKnowledge:
        """Enrich from live Neo4j database.

        Args:
            failed_rule_ids: Failed rule IDs
            include_admissibility: Include admissibility context

        Returns:
            ForensicKnowledge from Neo4j
        """
        if not self.client:
            return ForensicKnowledge()

        # Get base knowledge
        if include_admissibility:
            knowledge = self.client.get_admissibility_knowledge()
        else:
            knowledge = ForensicKnowledge(
                standards=self.client.get_forensic_standards(),
                techniques=self.client.get_forensic_techniques(),
            )

        # Get indicators matching failed rules
        if failed_rule_ids:
            indicators = self.client.get_indicators_by_rule_ids(failed_rule_ids)
            knowledge.tampering_indicators = indicators

        return knowledge

    def _enrich_from_fallback(
        self, failed_rule_ids: List[str], include_admissibility: bool
    ) -> ForensicKnowledge:
        """Enrich from fallback static data.

        Args:
            failed_rule_ids: Failed rule IDs
            include_admissibility: Include admissibility context

        Returns:
            ForensicKnowledge from fallback data
        """
        # Filter indicators by failed rules
        matching_indicators = self._match_indicators_to_rules(failed_rule_ids)

        # Determine which techniques were used
        used_techniques = self._determine_techniques(failed_rule_ids)

        # Filter legal cases based on indicators
        relevant_cases = FALLBACK_LEGAL_CASES if include_admissibility else []
        if matching_indicators and include_admissibility:
            case_names: Set[str] = set()
            for indicator in matching_indicators:
                case_names.update(indicator.legal_cases)
            if case_names:
                relevant_cases = [
                    c for c in FALLBACK_LEGAL_CASES
                    if any(name.lower() in c.name.lower() for name in case_names)
                ] or FALLBACK_LEGAL_CASES

        return ForensicKnowledge(
            standards=FALLBACK_STANDARDS,
            legal_cases=relevant_cases,
            techniques=used_techniques,
            tampering_indicators=matching_indicators,
            expert_context=self._build_expert_context(
                failed_rule_ids, matching_indicators
            ),
        )

    def _match_indicators_to_rules(
        self, failed_rule_ids: List[str]
    ) -> List[TamperingIndicatorInfo]:
        """Match failed rules to tampering indicators.

        Args:
            failed_rule_ids: List of failed TAMPER-XXX rule IDs

        Returns:
            List of matching TamperingIndicatorInfo
        """
        if not failed_rule_ids:
            return []

        # Get unique indicator categories from failed rules
        categories: Set[str] = set()
        for rule_id in failed_rule_ids:
            category = RULE_TO_INDICATOR_MAP.get(rule_id)
            if category:
                categories.add(category)

        # Find matching indicators
        matching = []
        for indicator in FALLBACK_INDICATORS:
            indicator_category = indicator.indicator_id.split("-")[0]
            if indicator_category in categories:
                # Create copy with rule IDs populated
                matching_rules = [
                    rid for rid in failed_rule_ids
                    if RULE_TO_INDICATOR_MAP.get(rid, "").startswith(indicator_category)
                ]
                matching.append(
                    TamperingIndicatorInfo(
                        indicator_id=indicator.indicator_id,
                        name=indicator.name,
                        description=indicator.description,
                        severity=indicator.severity,
                        forensic_significance=indicator.forensic_significance,
                        rule_ids=matching_rules,
                        techniques=indicator.techniques,
                        legal_cases=indicator.legal_cases,
                    )
                )

        return matching

    def _determine_techniques(
        self, failed_rule_ids: List[str]
    ) -> List[ForensicTechniqueInfo]:
        """Determine which forensic techniques were used based on rules.

        Args:
            failed_rule_ids: List of failed rule IDs

        Returns:
            List of relevant ForensicTechniqueInfo
        """
        technique_names: Set[str] = set()

        for rule_id in failed_rule_ids:
            category = RULE_TO_INDICATOR_MAP.get(rule_id, "")

            if category == "INTEGRITY":
                technique_names.add("CRC32 Validation")
            elif category == "TIMESTAMP":
                technique_names.add("Timestamp Cross-Validation")
            elif category.startswith("NTFS"):
                technique_names.add("NTFS $MFT Analysis")
                technique_names.add("Timestamp Cross-Validation")
            elif category == "FINGERPRINT":
                technique_names.add("GUID Analysis")

        # Always include basic techniques
        technique_names.add("CRC32 Validation")

        return [
            t for t in FALLBACK_TECHNIQUES
            if t.name in technique_names
        ]

    def _build_expert_context(
        self,
        failed_rule_ids: List[str],
        indicators: List[TamperingIndicatorInfo],
    ) -> Dict[str, Any]:
        """Build expert witness context from analysis.

        Args:
            failed_rule_ids: Failed rule IDs
            indicators: Matched tampering indicators

        Returns:
            Dict with expert context information
        """
        context: Dict[str, Any] = {
            "rules_evaluated": len(failed_rule_ids),
            "indicators_matched": len(indicators),
        }

        # Categorize findings by severity
        critical = [i for i in indicators if i.severity == "CRITICAL"]
        high = [i for i in indicators if i.severity == "HIGH"]
        medium = [i for i in indicators if i.severity == "MEDIUM"]

        if critical:
            context["critical_findings"] = [i.name for i in critical]
            context["tampering_likelihood"] = "High"
        elif high:
            context["high_findings"] = [i.name for i in high]
            context["tampering_likelihood"] = "Moderate"
        elif medium:
            context["medium_findings"] = [i.name for i in medium]
            context["tampering_likelihood"] = "Low"
        else:
            context["tampering_likelihood"] = "None Detected"

        # Add methodology statement
        context["methodology_statement"] = (
            "Analysis conducted using peer-reviewed forensic techniques "
            "in accordance with ISO/IEC 27037:2012 and NIST SP 800-86 guidelines. "
            "Findings are based on objective examination of file metadata, "
            "timestamp correlation, and integrity verification."
        )

        return context

    def get_citation_for_report(self, case_name: str) -> Optional[str]:
        """Get formatted citation for a legal case.

        Args:
            case_name: Partial case name to search

        Returns:
            Formatted citation string or None
        """
        case_name_lower = case_name.lower()
        for case in FALLBACK_LEGAL_CASES:
            if case_name_lower in case.name.lower():
                return f"{case.name}, {case.citation} ({case.year})"

        # Try Neo4j if available
        if self.client and self.client.is_connected:
            case_info = self.client.get_case_by_name(case_name)
            if case_info:
                return f"{case_info.name}, {case_info.citation} ({case_info.year})"

        return None

    def get_standards_compliance_statement(self) -> str:
        """Generate a standards compliance statement for reports.

        Returns:
            Formatted compliance statement
        """
        standard_names = [s.name for s in FALLBACK_STANDARDS]
        return (
            f"This forensic analysis was conducted in accordance with "
            f"{', '.join(standard_names[:-1])}, and {standard_names[-1]}."
        )
