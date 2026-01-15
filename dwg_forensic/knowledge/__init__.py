"""
DWG Forensic Tool - Knowledge Graph Package

This package provides integration with Neo4j knowledge graph for forensic
knowledge enrichment including legal citations, forensic standards, and
expert witness context.
"""

from dwg_forensic.knowledge.client import Neo4jKnowledgeClient
from dwg_forensic.knowledge.enrichment import KnowledgeEnricher
from dwg_forensic.knowledge.models import (
    ForensicKnowledge,
    ForensicStandardInfo,
    ForensicTechniqueInfo,
    LegalCaseInfo,
    TamperingIndicatorInfo,
)

__all__ = [
    "Neo4jKnowledgeClient",
    "KnowledgeEnricher",
    "ForensicKnowledge",
    "ForensicStandardInfo",
    "ForensicTechniqueInfo",
    "LegalCaseInfo",
    "TamperingIndicatorInfo",
]
