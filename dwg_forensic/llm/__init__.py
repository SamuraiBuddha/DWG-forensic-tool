"""
DWG Forensic Tool - LLM Integration Module

Provides LLM-powered forensic analysis:
- ForensicReasoner: LLM-based evidence evaluation and smoking gun detection
- ForensicNarrator: Narrative generation for reports
- OllamaClient: Low-level Ollama API client
- OllamaHealthChecker: Health checking for Ollama availability
- LLMModeManager: Mode management (AUTO/FORCE/OFF) with graceful fallback

Phase 4.2: Anomaly Filtering Integration
- Anomaly filtering models (Anomaly, ProvenanceInfo, FilteredAnomalies)
- Heuristic filter fallback for when LLM is unavailable
- LLM prompts for forensic reasoning

The ForensicReasoner is the key innovation - it uses the LLM to REASON about
evidence rather than just running algorithms. This allows it to:
1. Filter red herrings like TrustedDWG watermark absence
2. Identify true smoking guns through logical reasoning
3. Provide expert-level analysis that understands context
4. (Phase 4.2) Filter anomalies based on provenance context
"""

from dwg_forensic.llm.ollama_client import OllamaClient
from dwg_forensic.llm.forensic_narrator import ForensicNarrator
from dwg_forensic.llm.forensic_reasoner import ForensicReasoner, ForensicReasoning
from dwg_forensic.llm.ollama_health import OllamaHealthChecker
from dwg_forensic.llm.mode_manager import LLMModeManager, LLMMode
# Phase 4.2 exports
from dwg_forensic.llm.anomaly_models import (
    Anomaly,
    ProvenanceInfo,
    FilteredAnomalies,
    SmokingGunRule,
)
from dwg_forensic.llm.heuristic_filter import HeuristicAnomalyFilter

__all__ = [
    "OllamaClient",
    "ForensicNarrator",
    "ForensicReasoner",
    "ForensicReasoning",
    "OllamaHealthChecker",
    "LLMModeManager",
    "LLMMode",
    # Phase 4.2
    "Anomaly",
    "ProvenanceInfo",
    "FilteredAnomalies",
    "SmokingGunRule",
    "HeuristicAnomalyFilter",
]
