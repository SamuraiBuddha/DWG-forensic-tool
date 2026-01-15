"""
DWG Forensic Tool - LLM Integration Module

Provides LLM-powered forensic analysis:
- ForensicReasoner: LLM-based evidence evaluation and smoking gun detection
- ForensicNarrator: Narrative generation for reports
- OllamaClient: Low-level Ollama API client

The ForensicReasoner is the key innovation - it uses the LLM to REASON about
evidence rather than just running algorithms. This allows it to:
1. Filter red herrings like TrustedDWG watermark absence
2. Identify true smoking guns through logical reasoning
3. Provide expert-level analysis that understands context
"""

from dwg_forensic.llm.ollama_client import OllamaClient
from dwg_forensic.llm.forensic_narrator import ForensicNarrator
from dwg_forensic.llm.forensic_reasoner import ForensicReasoner, ForensicReasoning

__all__ = [
    "OllamaClient",
    "ForensicNarrator",
    "ForensicReasoner",
    "ForensicReasoning",
]
