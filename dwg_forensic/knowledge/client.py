"""
DWG Forensic Tool - Neo4j Knowledge Graph Client

Client for querying the forensic knowledge graph stored in Neo4j.
Provides methods to retrieve forensic standards, legal cases, techniques,
and tampering indicators relevant to DWG file analysis.
"""

import logging
import os
from typing import Any, Dict, List, Optional

from dwg_forensic.knowledge.models import (
    ForensicKnowledge,
    ForensicStandardInfo,
    ForensicTechniqueInfo,
    LegalCaseInfo,
    ReliabilityLevel,
    TamperingIndicatorInfo,
)

logger = logging.getLogger(__name__)


class Neo4jKnowledgeClient:
    """Client for querying forensic knowledge from Neo4j graph database."""

    def __init__(
        self,
        uri: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: str = "neo4j",
    ):
        """Initialize Neo4j client.

        Args:
            uri: Neo4j connection URI (defaults to NEO4J_URI env var)
            user: Neo4j username (defaults to NEO4J_USER env var)
            password: Neo4j password (defaults to NEO4J_PASSWORD env var)
            database: Database name (defaults to neo4j)
        """
        self.uri = uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.environ.get("NEO4J_USER", "neo4j")
        self.password = password or os.environ.get("NEO4J_PASSWORD", "")
        self.database = database
        self._driver = None
        self._connected = False

    def connect(self) -> bool:
        """Establish connection to Neo4j database.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            from neo4j import GraphDatabase

            self._driver = GraphDatabase.driver(
                self.uri, auth=(self.user, self.password)
            )
            # Verify connection
            self._driver.verify_connectivity()
            self._connected = True
            logger.info("Connected to Neo4j knowledge graph at %s", self.uri)
            return True
        except ImportError:
            logger.warning("neo4j driver not installed. Run: pip install neo4j")
            return False
        except Exception as e:
            logger.warning("Failed to connect to Neo4j: %s", str(e))
            self._connected = False
            return False

    def close(self) -> None:
        """Close the Neo4j connection."""
        if self._driver:
            self._driver.close()
            self._connected = False
            logger.debug("Neo4j connection closed")

    @property
    def is_connected(self) -> bool:
        """Check if client is connected to Neo4j."""
        return self._connected and self._driver is not None

    def _execute_query(
        self, query: str, parameters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Execute a Cypher query and return results.

        Args:
            query: Cypher query string
            parameters: Query parameters

        Returns:
            List of result records as dictionaries
        """
        if not self.is_connected:
            if not self.connect():
                return []

        try:
            with self._driver.session(database=self.database) as session:
                result = session.run(query, parameters or {})
                return [record.data() for record in result]
        except Exception as e:
            logger.error("Neo4j query failed: %s", str(e))
            return []

    def get_forensic_standards(
        self, limit: int = 10
    ) -> List[ForensicStandardInfo]:
        """Retrieve all forensic standards from the knowledge graph.

        Args:
            limit: Maximum number of standards to retrieve

        Returns:
            List of ForensicStandardInfo objects
        """
        query = """
        MATCH (s:ForensicStandard)
        RETURN s.name AS name,
               s.organization AS organization,
               s.description AS description,
               s.version AS version,
               s.url AS url
        LIMIT $limit
        """
        results = self._execute_query(query, {"limit": limit})

        standards = []
        for record in results:
            standards.append(
                ForensicStandardInfo(
                    name=record.get("name", "Unknown"),
                    organization=record.get("organization", "Unknown"),
                    description=record.get("description", ""),
                    version=record.get("version"),
                    url=record.get("url"),
                )
            )

        return standards

    def get_legal_cases(self, limit: int = 10) -> List[LegalCaseInfo]:
        """Retrieve legal precedent cases from the knowledge graph.

        Args:
            limit: Maximum number of cases to retrieve

        Returns:
            List of LegalCaseInfo objects
        """
        query = """
        MATCH (c:LegalCase)
        RETURN c.name AS name,
               c.citation AS citation,
               c.year AS year,
               c.jurisdiction AS jurisdiction,
               c.holding AS holding,
               c.significance AS significance
        LIMIT $limit
        """
        results = self._execute_query(query, {"limit": limit})

        cases = []
        for record in results:
            year = record.get("year", 0)
            # Handle year as string or int
            if isinstance(year, str):
                try:
                    year = int(year)
                except ValueError:
                    year = 0

            cases.append(
                LegalCaseInfo(
                    name=record.get("name", "Unknown"),
                    citation=record.get("citation", ""),
                    year=year,
                    jurisdiction=record.get("jurisdiction", "US"),
                    holding=record.get("holding", ""),
                    relevance=record.get("significance", ""),
                )
            )

        return cases

    def get_forensic_techniques(
        self, limit: int = 10
    ) -> List[ForensicTechniqueInfo]:
        """Retrieve forensic techniques from the knowledge graph.

        Args:
            limit: Maximum number of techniques to retrieve

        Returns:
            List of ForensicTechniqueInfo objects
        """
        query = """
        MATCH (t:ForensicTechnique)
        OPTIONAL MATCH (t)-[:COMPLIES_WITH]->(s:ForensicStandard)
        RETURN t.name AS name,
               t.description AS description,
               t.reliability AS reliability,
               t.errorRate AS error_rate,
               t.peerReviewed AS peer_reviewed,
               collect(s.name) AS standards
        LIMIT $limit
        """
        results = self._execute_query(query, {"limit": limit})

        techniques = []
        for record in results:
            # Map reliability string to enum
            reliability_str = record.get("reliability", "High")
            try:
                reliability = ReliabilityLevel(reliability_str)
            except ValueError:
                reliability = ReliabilityLevel.HIGH

            techniques.append(
                ForensicTechniqueInfo(
                    name=record.get("name", "Unknown"),
                    description=record.get("description", ""),
                    reliability=reliability,
                    error_rate=record.get("error_rate"),
                    peer_reviewed=record.get("peer_reviewed", True),
                    standards_compliance=[s for s in record.get("standards", []) if s],
                )
            )

        return techniques

    def get_tampering_indicators(
        self, limit: int = 20
    ) -> List[TamperingIndicatorInfo]:
        """Retrieve tampering indicators from the knowledge graph.

        Args:
            limit: Maximum number of indicators to retrieve

        Returns:
            List of TamperingIndicatorInfo objects
        """
        query = """
        MATCH (i:TamperingIndicator)
        OPTIONAL MATCH (i)-[:DETECTED_BY]->(t:ForensicTechnique)
        OPTIONAL MATCH (i)-[:CITED_IN]->(c:LegalCase)
        RETURN i.indicatorId AS indicator_id,
               i.name AS name,
               i.description AS description,
               i.severity AS severity,
               i.forensicSignificance AS forensic_significance,
               collect(DISTINCT t.name) AS techniques,
               collect(DISTINCT c.name) AS legal_cases
        LIMIT $limit
        """
        results = self._execute_query(query, {"limit": limit})

        indicators = []
        for record in results:
            indicators.append(
                TamperingIndicatorInfo(
                    indicator_id=record.get("indicator_id", "UNKNOWN"),
                    name=record.get("name", "Unknown"),
                    description=record.get("description", ""),
                    severity=record.get("severity", "MEDIUM"),
                    forensic_significance=record.get("forensic_significance", ""),
                    rule_ids=[],  # Mapped separately
                    techniques=[t for t in record.get("techniques", []) if t],
                    legal_cases=[c for c in record.get("legal_cases", []) if c],
                )
            )

        return indicators

    def get_indicators_by_rule_ids(
        self, rule_ids: List[str]
    ) -> List[TamperingIndicatorInfo]:
        """Retrieve tampering indicators that match specific rule IDs.

        Args:
            rule_ids: List of TAMPER-XXX rule IDs to match

        Returns:
            List of matching TamperingIndicatorInfo objects
        """
        if not rule_ids:
            return []

        # Build indicator ID patterns from rule IDs
        # Map TAMPER-XXX rules to indicator types
        indicator_patterns = []
        for rule_id in rule_ids:
            # Extract rule number
            rule_num = rule_id.replace("TAMPER-", "")
            try:
                num = int(rule_num)
                # Map rule numbers to indicator categories
                if num <= 2:  # CRC rules
                    indicator_patterns.append("INTEGRITY")
                elif num <= 12:  # Basic timestamp rules
                    indicator_patterns.append("TIMESTAMP")
                elif num <= 18:  # Advanced timestamp rules
                    indicator_patterns.append("TIMESTAMP")
                elif num <= 28:  # NTFS rules
                    indicator_patterns.append("NTFS")
                elif num <= 35:  # Fingerprint rules
                    indicator_patterns.append("FINGERPRINT")
                elif num <= 40:  # Structure rules
                    indicator_patterns.append("STRUCTURE")
            except ValueError:
                continue

        # Remove duplicates while preserving order
        indicator_patterns = list(dict.fromkeys(indicator_patterns))

        if not indicator_patterns:
            return []

        query = """
        MATCH (i:TamperingIndicator)
        WHERE any(pattern IN $patterns WHERE i.indicatorId CONTAINS pattern)
        OPTIONAL MATCH (i)-[:DETECTED_BY]->(t:ForensicTechnique)
        OPTIONAL MATCH (i)-[:CITED_IN]->(c:LegalCase)
        RETURN i.indicatorId AS indicator_id,
               i.name AS name,
               i.description AS description,
               i.severity AS severity,
               i.forensicSignificance AS forensic_significance,
               collect(DISTINCT t.name) AS techniques,
               collect(DISTINCT c.name) AS legal_cases
        """
        results = self._execute_query(query, {"patterns": indicator_patterns})

        indicators = []
        for record in results:
            indicators.append(
                TamperingIndicatorInfo(
                    indicator_id=record.get("indicator_id", "UNKNOWN"),
                    name=record.get("name", "Unknown"),
                    description=record.get("description", ""),
                    severity=record.get("severity", "MEDIUM"),
                    forensic_significance=record.get("forensic_significance", ""),
                    rule_ids=rule_ids,
                    techniques=[t for t in record.get("techniques", []) if t],
                    legal_cases=[c for c in record.get("legal_cases", []) if c],
                )
            )

        return indicators

    def get_case_by_name(self, case_name: str) -> Optional[LegalCaseInfo]:
        """Retrieve a specific legal case by name.

        Args:
            case_name: Case name to search for (partial match)

        Returns:
            LegalCaseInfo if found, None otherwise
        """
        query = """
        MATCH (c:LegalCase)
        WHERE toLower(c.name) CONTAINS toLower($name)
        RETURN c.name AS name,
               c.citation AS citation,
               c.year AS year,
               c.jurisdiction AS jurisdiction,
               c.holding AS holding,
               c.significance AS significance
        LIMIT 1
        """
        results = self._execute_query(query, {"name": case_name})

        if not results:
            return None

        record = results[0]
        year = record.get("year", 0)
        if isinstance(year, str):
            try:
                year = int(year)
            except ValueError:
                year = 0

        return LegalCaseInfo(
            name=record.get("name", "Unknown"),
            citation=record.get("citation", ""),
            year=year,
            jurisdiction=record.get("jurisdiction", "US"),
            holding=record.get("holding", ""),
            relevance=record.get("significance", ""),
        )

    def get_all_knowledge(self) -> ForensicKnowledge:
        """Retrieve all forensic knowledge from the graph.

        Returns:
            ForensicKnowledge containing all standards, cases, techniques, indicators
        """
        return ForensicKnowledge(
            standards=self.get_forensic_standards(),
            legal_cases=self.get_legal_cases(),
            techniques=self.get_forensic_techniques(),
            tampering_indicators=self.get_tampering_indicators(),
        )

    def get_admissibility_knowledge(self) -> ForensicKnowledge:
        """Retrieve knowledge specifically relevant to evidence admissibility.

        This includes Daubert, Frye, and Lorraine standards.

        Returns:
            ForensicKnowledge focused on admissibility requirements
        """
        # Get key admissibility cases
        query = """
        MATCH (c:LegalCase)
        WHERE c.name CONTAINS 'Daubert' OR c.name CONTAINS 'Frye' OR c.name CONTAINS 'Lorraine'
        RETURN c.name AS name,
               c.citation AS citation,
               c.year AS year,
               c.jurisdiction AS jurisdiction,
               c.holding AS holding,
               c.significance AS significance
        """
        case_results = self._execute_query(query)

        cases = []
        for record in case_results:
            year = record.get("year", 0)
            if isinstance(year, str):
                try:
                    year = int(year)
                except ValueError:
                    year = 0

            cases.append(
                LegalCaseInfo(
                    name=record.get("name", "Unknown"),
                    citation=record.get("citation", ""),
                    year=year,
                    jurisdiction=record.get("jurisdiction", "US"),
                    holding=record.get("holding", ""),
                    relevance=record.get("significance", ""),
                )
            )

        # Get peer-reviewed techniques
        query_tech = """
        MATCH (t:ForensicTechnique)
        WHERE t.peerReviewed = true OR t.reliability = 'High'
        OPTIONAL MATCH (t)-[:COMPLIES_WITH]->(s:ForensicStandard)
        RETURN t.name AS name,
               t.description AS description,
               t.reliability AS reliability,
               t.errorRate AS error_rate,
               t.peerReviewed AS peer_reviewed,
               collect(s.name) AS standards
        """
        tech_results = self._execute_query(query_tech)

        techniques = []
        for record in tech_results:
            reliability_str = record.get("reliability", "High")
            try:
                reliability = ReliabilityLevel(reliability_str)
            except ValueError:
                reliability = ReliabilityLevel.HIGH

            techniques.append(
                ForensicTechniqueInfo(
                    name=record.get("name", "Unknown"),
                    description=record.get("description", ""),
                    reliability=reliability,
                    error_rate=record.get("error_rate"),
                    peer_reviewed=record.get("peer_reviewed", True),
                    standards_compliance=[s for s in record.get("standards", []) if s],
                )
            )

        return ForensicKnowledge(
            standards=self.get_forensic_standards(),
            legal_cases=cases,
            techniques=techniques,
            tampering_indicators=[],
            expert_context={
                "purpose": "Evidence admissibility assessment",
                "applicable_standards": ["Daubert", "Frye", "Lorraine"],
            },
        )
