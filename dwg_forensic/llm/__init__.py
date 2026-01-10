"""
DWG Forensic Tool - LLM Integration Module

Provides LLM-powered narrative generation for forensic reports
using local Ollama models with strict forensic accuracy guardrails.
"""

from dwg_forensic.llm.ollama_client import OllamaClient
from dwg_forensic.llm.forensic_narrator import ForensicNarrator

__all__ = ["OllamaClient", "ForensicNarrator"]
