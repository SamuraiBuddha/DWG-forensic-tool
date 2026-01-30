"""
DWG Forensic Tool - LLM-Powered Forensic Reasoner

Uses LLM to perform actual forensic REASONING about evidence, not just
run algorithms and generate narratives. The LLM acts as a forensic expert
that evaluates evidence significance and identifies true smoking guns.

Key Principles:
1. LLM reasons about evidence, not just explains algorithm results
2. Red herrings (like TrustedDWG watermark) are filtered through reasoning
3. Only mathematically impossible conditions are flagged as smoking guns
4. Context matters - the same finding may or may not be significant
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

# LLM client import with graceful degradation
try:
    from dwg_forensic.llm.ollama_client import OllamaClient
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    OllamaClient = None  # type: ignore

# Phase 4.2: Import anomaly models and prompts
from dwg_forensic.llm.anomaly_models import (
    Anomaly,
    ProvenanceInfo,
    FilteredAnomalies,
    SmokingGunRule,
)
from dwg_forensic.llm.reasoner_prompts import format_filter_prompt

logger = logging.getLogger(__name__)


@dataclass
class ForensicReasoning:
    """Result of LLM forensic reasoning."""

    has_definitive_proof: bool
    smoking_guns: List[Dict[str, Any]]
    filtered_red_herrings: List[Dict[str, Any]]
    reasoning_chain: str
    expert_conclusion: str
    confidence: float
    model_used: str


# Evidence that should be IGNORED or heavily discounted
RED_HERRINGS = {
    "third_party_origin": (
        "Files created by non-Autodesk CAD software (BricsCAD, NanoCAD, etc.) "
        "are legitimate. Third-party origin does NOT indicate tampering."
    ),
    "missing_guids": (
        "Missing FINGERPRINTGUID/VERSIONGUID simply indicates the file was "
        "created by non-AutoCAD software. This is common and NOT suspicious."
    ),
}

# True smoking guns - mathematically impossible conditions
SMOKING_GUN_CRITERIA = """
A finding is a SMOKING GUN only if it represents a MATHEMATICAL or PHYSICAL IMPOSSIBILITY:

1. TIMESTAMP IMPOSSIBILITIES:
   - Created timestamp AFTER modified timestamp (effect before cause)
   - Modified timestamp in the FUTURE (time travel required)
   - TDINDWG (cumulative edit time) EXCEEDS calendar span between creation and modification
   - File claims creation date BEFORE its DWG version existed (anachronism)

2. NTFS KERNEL-LEVEL CONTRADICTIONS:
   - $STANDARD_INFORMATION timestamps EARLIER than $FILE_NAME timestamps
     (This is IMPOSSIBLE without kernel-level timestomping tools because
      $FILE_NAME is only updated by the Windows kernel)
   - Multiple timestamps with ZERO nanoseconds (statistically impossible, p < 0.0001)

3. CRYPTOGRAPHIC PROOF:
   - CRC32 checksum mismatch (mathematical proof of modification)
   - Hash comparison failure against known-good original

4. STRUCTURAL IMPOSSIBILITIES:
   - Large gaps in sequential object handle assignment (mass deletion evidence)
   - Missing mandatory DWG sections (structural corruption)
   - Section map pointing to invalid locations

NOT SMOKING GUNS (these are red herrings):
- TrustedDWG watermark missing or invalid
- Third-party CAD software origin
- Missing GUIDs
- Minor timestamp discrepancies that could be timezone/DST issues
"""


class ForensicReasoner:
    """
    LLM-powered forensic reasoner that analyzes evidence significance.

    Unlike algorithmic analysis that flags every anomaly, the LLM reasoner:
    1. Evaluates whether findings actually prove tampering
    2. Filters out red herrings like TrustedDWG absence
    3. Identifies true smoking guns through logical reasoning
    4. Provides expert-level analysis of evidence chains
    """

    def __init__(
        self,
        llm_model: str = "mistral",
        ollama_host: str = "http://localhost:11434",
    ):
        """
        Initialize the forensic reasoner.

        Args:
            llm_model: Ollama model to use (e.g., 'mistral', 'gpt-oss:20b')
            ollama_host: Ollama API host URL
        """
        self._model = llm_model
        self._host = ollama_host
        self._client: Optional[Any] = None

        if LLM_AVAILABLE:
            self._client = OllamaClient(base_url=ollama_host, model=llm_model)

    def _format_evidence(self, analysis_data: Dict[str, Any]) -> str:
        """Format analysis data for LLM consumption."""
        evidence_parts = []

        # File info
        if "file" in analysis_data:
            f = analysis_data["file"]
            evidence_parts.append(f"FILE: {f.get('filename', 'unknown')}, {f.get('size', 0)} bytes")

        # Header info
        if "header" in analysis_data:
            h = analysis_data["header"]
            evidence_parts.append(f"DWG VERSION: {h.get('version_string', 'unknown')}")

        # Timestamps
        if "metadata" in analysis_data:
            m = analysis_data["metadata"]
            evidence_parts.append(f"TDCREATE: {m.get('tdcreate', 'N/A')}")
            evidence_parts.append(f"TDUPDATE: {m.get('tdupdate', 'N/A')}")
            evidence_parts.append(f"TDINDWG: {m.get('tdindwg', 'N/A')} days")

        # CRC
        if "crc_validation" in analysis_data:
            crc = analysis_data["crc_validation"]
            evidence_parts.append(f"CRC VALID: {crc.get('is_valid', 'unknown')}")

        # Parse diagnostics (if available)
        if "parse_diagnostics" in analysis_data:
            evidence_parts.append("")
            evidence_parts.append("PARSE DIAGNOSTICS:")
            diag = analysis_data["parse_diagnostics"]

            method = diag.get("timestamp_extraction_method", "unknown")
            evidence_parts.append(f"- Timestamp extraction method: {method}")

            sections_found = diag.get("sections_found", [])
            if sections_found:
                evidence_parts.append(f"- Sections found: {', '.join(sections_found)}")

            sections_missing = diag.get("sections_missing", [])
            if sections_missing:
                evidence_parts.append(f"- Sections missing: {', '.join(sections_missing)}")

            compression_errors = diag.get("compression_errors", [])
            if compression_errors:
                evidence_parts.append(f"- Compression errors: {', '.join(compression_errors[:3])}")

            revit_detected = diag.get("revit_detected", False)
            evidence_parts.append(f"- Revit detected: {'yes' if revit_detected else 'no'}")

        # Revit detection context (if available)
        if "revit_detection" in analysis_data:
            revit = analysis_data["revit_detection"]
            if revit.get("is_revit_export", False):
                evidence_parts.append("")
                evidence_parts.append("REVIT EXPORT CONTEXT:")
                evidence_parts.append("This file was exported from Autodesk Revit. Key implications:")
                evidence_parts.append("- CRC value of 0x00000000 is expected (Revit doesn't compute CRC)")
                evidence_parts.append("- Internal timestamps may reflect export time, not original design creation")
                evidence_parts.append("- Section structure may differ from native AutoCAD files")
                evidence_parts.append("Do NOT flag these Revit-specific behaviors as tampering evidence.")

                version = revit.get("revit_version")
                if version:
                    evidence_parts.append(f"- Detected Revit version: {version}")

                confidence = revit.get("confidence_score", 0.0)
                evidence_parts.append(f"- Detection confidence: {confidence*100:.1f}%")

        # NTFS data
        if "ntfs_data" in analysis_data:
            ntfs = analysis_data["ntfs_data"]
            evidence_parts.append(f"NTFS SI/FN MISMATCH: {ntfs.get('si_fn_mismatch', False)}")
            evidence_parts.append(f"NTFS NANOSECOND TRUNCATION: {ntfs.get('nanoseconds_truncated', False)}")

        # Anomalies
        if "anomalies" in analysis_data:
            for a in analysis_data["anomalies"][:10]:  # Limit to first 10
                evidence_parts.append(f"ANOMALY: {a.get('anomaly_type', 'unknown')} - {a.get('description', '')}")

        # Rule results
        if "rule_results" in analysis_data:
            failed = [r for r in analysis_data["rule_results"] if r.get("status") == "failed"]
            for r in failed[:10]:
                evidence_parts.append(f"FAILED RULE: {r.get('rule_id', '')} - {r.get('description', '')}")

        return "\n".join(evidence_parts)

    async def reason_about_evidence(
        self, analysis_data: Dict[str, Any]
    ) -> ForensicReasoning:
        """
        Use LLM to reason about forensic evidence and identify true smoking guns.

        Args:
            analysis_data: Dictionary containing all forensic analysis results

        Returns:
            ForensicReasoning with LLM's expert analysis
        """
        if not self._client:
            return self._fallback_reasoning(analysis_data)

        evidence_text = self._format_evidence(analysis_data)

        prompt = f"""You are a digital forensics expert analyzing a DWG (AutoCAD) file for evidence of tampering.

CRITICAL INSTRUCTIONS:
1. Only flag findings as SMOKING GUNS if they represent MATHEMATICAL or PHYSICAL IMPOSSIBILITIES
2. The TrustedDWG watermark is a RED HERRING - its absence does NOT prove tampering
3. Third-party CAD software origin is NOT evidence of tampering
4. Focus ONLY on conditions that CANNOT occur naturally

{SMOKING_GUN_CRITERIA}

EVIDENCE TO ANALYZE:
{evidence_text}

Analyze this evidence and respond in the following JSON format:
{{
    "has_definitive_proof": true/false,
    "smoking_guns": [
        {{
            "finding": "description of the impossible condition",
            "why_impossible": "explanation of why this cannot occur naturally",
            "confidence": 0.0-1.0
        }}
    ],
    "red_herrings_filtered": [
        {{
            "finding": "what was flagged but is NOT evidence",
            "why_not_significant": "explanation"
        }}
    ],
    "reasoning_chain": "Step-by-step logical reasoning about the evidence",
    "expert_conclusion": "Your professional conclusion as a forensic expert"
}}

Be rigorous. If there are no TRUE smoking guns, say so clearly. Do not inflate findings."""

        try:
            response = await self._client.generate(prompt, model=self._model)

            # Parse JSON response
            try:
                # Find JSON in response
                json_start = response.find("{")
                json_end = response.rfind("}") + 1
                if json_start >= 0 and json_end > json_start:
                    result = json.loads(response[json_start:json_end])
                else:
                    return self._fallback_reasoning(analysis_data)

                return ForensicReasoning(
                    has_definitive_proof=result.get("has_definitive_proof", False),
                    smoking_guns=result.get("smoking_guns", []),
                    filtered_red_herrings=result.get("red_herrings_filtered", []),
                    reasoning_chain=result.get("reasoning_chain", ""),
                    expert_conclusion=result.get("expert_conclusion", ""),
                    confidence=self._calculate_confidence(result.get("smoking_guns", [])),
                    model_used=self._model,
                )
            except json.JSONDecodeError:
                # LLM didn't return valid JSON, extract what we can
                return ForensicReasoning(
                    has_definitive_proof="smoking gun" in response.lower() or "impossible" in response.lower(),
                    smoking_guns=[],
                    filtered_red_herrings=[],
                    reasoning_chain=response,
                    expert_conclusion=response[-500:] if len(response) > 500 else response,
                    confidence=0.5,
                    model_used=self._model,
                )

        except Exception as e:
            # Fall back to algorithmic analysis
            return self._fallback_reasoning(analysis_data)

    def _calculate_confidence(self, smoking_guns: List[Dict]) -> float:
        """Calculate overall confidence from smoking gun findings."""
        if not smoking_guns:
            return 0.0

        confidences = [sg.get("confidence", 0.5) for sg in smoking_guns]
        return sum(confidences) / len(confidences)

    def _fallback_reasoning(self, analysis_data: Dict[str, Any]) -> ForensicReasoning:
        """Algorithmic fallback when LLM is unavailable."""
        smoking_guns = []
        red_herrings = []

        # Check for TRUE smoking guns (algorithmic)

        # 1. CRC mismatch
        crc = analysis_data.get("crc_validation", {})
        if crc.get("is_valid") is False:
            smoking_guns.append({
                "finding": "CRC32 checksum mismatch",
                "why_impossible": "CRC is a mathematical function - mismatch proves modification",
                "confidence": 1.0,
            })

        # 2. Timestamp impossibilities
        anomalies = analysis_data.get("anomalies", [])
        for a in anomalies:
            atype = a.get("anomaly_type", "")

            if atype == "TDINDWG_EXCEEDS_SPAN":
                smoking_guns.append({
                    "finding": "Edit time exceeds calendar span",
                    "why_impossible": "Cannot spend more time editing than has elapsed",
                    "confidence": 1.0,
                })
            elif atype == "VERSION_ANACHRONISM":
                smoking_guns.append({
                    "finding": "File claims creation before version existed",
                    "why_impossible": "File cannot use format that didn't exist yet",
                    "confidence": 1.0,
                })
            elif atype in ["CREATED_AFTER_MODIFIED", "TIMESTAMP_REVERSAL"]:
                smoking_guns.append({
                    "finding": "Created timestamp after modified timestamp",
                    "why_impossible": "Effect cannot precede cause",
                    "confidence": 1.0,
                })

        # 3. NTFS contradictions
        ntfs = analysis_data.get("ntfs_data", {})
        if ntfs.get("si_fn_mismatch"):
            smoking_guns.append({
                "finding": "NTFS $SI timestamps earlier than $FN timestamps",
                "why_impossible": "$FN is kernel-protected - cannot be backdated without kernel tools",
                "confidence": 1.0,
            })

        # Build conclusion
        if smoking_guns:
            conclusion = (
                f"DEFINITIVE PROOF OF TAMPERING: {len(smoking_guns)} mathematically "
                f"impossible condition(s) detected. These findings prove file manipulation "
                f"beyond reasonable doubt."
            )
        else:
            conclusion = (
                "No definitive proof of tampering found. While some anomalies may be present, "
                "none represent mathematical or physical impossibilities."
            )

        return ForensicReasoning(
            has_definitive_proof=len(smoking_guns) > 0,
            smoking_guns=smoking_guns,
            filtered_red_herrings=red_herrings,
            reasoning_chain="Algorithmic analysis (LLM unavailable)",
            expert_conclusion=conclusion,
            confidence=1.0 if smoking_guns else 0.0,
            model_used="algorithmic_fallback",
        )

    async def filter_anomalies(
        self,
        anomalies: List[Anomaly],
        provenance: ProvenanceInfo,
        dwg_version: str = "Unknown",
        batch_mode: bool = False,
    ) -> FilteredAnomalies:
        """
        Filter anomalies using LLM reasoning based on provenance context.

        This is the core Phase 4.2 integration point. The LLM evaluates whether
        detected anomalies are expected red herrings for the file's provenance
        (Revit export, ODA tool, file transfer) or represent true smoking guns.

        Args:
            anomalies: List of Anomaly objects from rule engine
            provenance: ProvenanceInfo describing file origin and context
            dwg_version: DWG version string (e.g., "AC1032")
            batch_mode: Use simplified prompt for faster batch processing

        Returns:
            FilteredAnomalies with kept/filtered lists, reasoning, and confidence
        """
        if not anomalies:
            return FilteredAnomalies(
                kept_anomalies=[],
                filtered_anomalies=[],
                reasoning="No anomalies detected",
                llm_confidence=1.0,
                method="none",
            )

        # Instantiate smoking gun validator
        smoking_gun_rules = SmokingGunRule()

        # If LLM unavailable, fall back to heuristic filtering
        if not self._client:
            logger.warning("LLM client unavailable, using heuristic fallback")
            return self._heuristic_filter_anomalies(anomalies, provenance, smoking_gun_rules)

        try:
            # Build prompt with file context
            prompt = format_filter_prompt(
                anomalies=anomalies,
                provenance=provenance.__dict__,
                dwg_version=dwg_version,
                batch_mode=batch_mode,
            )

            # Query LLM
            response = await self._client.generate(prompt, model=self._model)

            # Parse JSON response
            json_start = response.find("{")
            json_end = response.rfind("}") + 1
            if json_start < 0 or json_end <= json_start:
                logger.warning("LLM response missing JSON, falling back to heuristic")
                return self._heuristic_filter_anomalies(anomalies, provenance, smoking_gun_rules)

            result = json.loads(response[json_start:json_end])

            # Extract filtering decisions
            keep_ids = set(result.get("keep", []))
            filter_ids = set(result.get("filter", []))
            reasoning_text = result.get("reasoning", "LLM reasoning not provided")
            llm_confidence = float(result.get("confidence", 0.7))

            # Separate anomalies into kept and filtered
            kept = []
            filtered = []

            for anomaly in anomalies:
                # CRITICAL: Never filter smoking guns
                if smoking_gun_rules.is_smoking_gun(anomaly.rule_id):
                    kept.append(anomaly)
                    if anomaly.rule_id in filter_ids:
                        logger.error(
                            f"LLM attempted to filter smoking gun {anomaly.rule_id}, overriding"
                        )
                elif anomaly.rule_id in filter_ids:
                    filtered.append(anomaly)
                else:
                    # If not explicitly filtered, keep it (conservative approach)
                    kept.append(anomaly)

            filtered_result = FilteredAnomalies(
                kept_anomalies=kept,
                filtered_anomalies=filtered,
                reasoning=reasoning_text,
                llm_confidence=llm_confidence,
                method="llm",
            )

            # Validate no smoking guns were filtered
            validation_error = smoking_gun_rules.validate_filtering(filtered)
            if validation_error:
                logger.critical(validation_error)
                # Move filtered smoking guns back to kept
                smoking_guns_filtered = [
                    a for a in filtered if smoking_gun_rules.is_smoking_gun(a.rule_id)
                ]
                for sg in smoking_guns_filtered:
                    filtered_result.filtered_anomalies.remove(sg)
                    filtered_result.kept_anomalies.append(sg)

            logger.info(
                f"LLM filtered {len(filtered)} of {len(anomalies)} anomalies "
                f"(confidence: {llm_confidence:.1%})"
            )

            return filtered_result

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM JSON response: {e}, using heuristic fallback")
            return self._heuristic_filter_anomalies(anomalies, provenance, smoking_gun_rules)
        except Exception as e:
            logger.error(f"LLM filtering failed: {e}, using heuristic fallback")
            return self._heuristic_filter_anomalies(anomalies, provenance, smoking_gun_rules)

    def _heuristic_filter_anomalies(
        self,
        anomalies: List[Anomaly],
        provenance: ProvenanceInfo,
        smoking_gun_rules: SmokingGunRule,
    ) -> FilteredAnomalies:
        """
        Fallback heuristic filtering when LLM is unavailable.

        Uses static rule-based logic to filter expected anomalies based on
        provenance patterns. This provides conservative filtering without LLM.
        """
        kept = []
        filtered = []
        reasoning_parts = []

        # Revit export filtering
        if provenance.is_revit_export:
            revit_filter_rules = {
                "TAMPER-013",  # TDINDWG zero (Revit normal)
                "TAMPER-006",  # Zero firmware version
                "TAMPER-003",  # TrustedDWG missing
                "TAMPER-004",  # Watermark missing
                "TAMPER-029",  # Third-party origin
            }
            reasoning_parts.append("Revit export detected: Filtering expected anomalies")
        else:
            revit_filter_rules = set()

        # ODA tool filtering
        if provenance.is_oda_tool:
            oda_filter_rules = {
                "TAMPER-003",  # TrustedDWG missing
                "TAMPER-029",  # Third-party origin
                "TAMPER-030",  # Missing GUIDs
            }
            reasoning_parts.append("ODA SDK tool detected: Filtering application-specific patterns")
        else:
            oda_filter_rules = set()

        # File transfer filtering
        if provenance.is_file_transfer:
            transfer_filter_rules = {
                "TAMPER-020",  # NTFS creation after modification (normal for copy)
            }
            reasoning_parts.append("File transfer detected: Filtering copy-related patterns")
        else:
            transfer_filter_rules = set()

        # Combine all filter rules
        all_filter_rules = revit_filter_rules | oda_filter_rules | transfer_filter_rules

        # Apply filtering
        for anomaly in anomalies:
            # CRITICAL: Never filter smoking guns
            if smoking_gun_rules.is_smoking_gun(anomaly.rule_id):
                kept.append(anomaly)
            elif anomaly.rule_id in all_filter_rules:
                filtered.append(anomaly)
                reasoning_parts.append(f"Filtered {anomaly.rule_id}: Expected for {provenance.provenance_path}")
            else:
                kept.append(anomaly)

        reasoning_text = ". ".join(reasoning_parts) if reasoning_parts else "Heuristic filtering applied"

        # Conservative confidence (heuristics are less nuanced than LLM)
        confidence = 0.7 if provenance.confidence > 0.7 else 0.5

        logger.info(
            f"Heuristic filtered {len(filtered)} of {len(anomalies)} anomalies "
            f"(provenance: {provenance.provenance_path})"
        )

        return FilteredAnomalies(
            kept_anomalies=kept,
            filtered_anomalies=filtered,
            reasoning=reasoning_text,
            llm_confidence=confidence,
            method="heuristic",
        )

    def get_llm_confidence(self) -> float:
        """
        Get LLM confidence level (0-1).

        Returns:
            1.0 if LLM available and healthy
            0.0 if LLM unavailable (falls back to heuristic)
        """
        if not self._client:
            return 0.0

        try:
            # Simple health check - could be enhanced with actual ping
            return 1.0 if LLM_AVAILABLE else 0.0
        except Exception:
            return 0.0

    def generate_expert_report(self, reasoning: ForensicReasoning) -> str:
        """Generate a plain-text expert report from reasoning results."""
        lines = [
            "=" * 70,
            "FORENSIC EVIDENCE ANALYSIS - LLM-POWERED REASONING",
            "=" * 70,
            "",
        ]

        if reasoning.has_definitive_proof:
            lines.append("[!!] DEFINITIVE PROOF OF TAMPERING DETECTED")
            lines.append("")
            lines.append("SMOKING GUN FINDINGS:")
            for i, sg in enumerate(reasoning.smoking_guns, 1):
                lines.append(f"  {i}. {sg.get('finding', 'Unknown')}")
                lines.append(f"     Why impossible: {sg.get('why_impossible', 'N/A')}")
                lines.append(f"     Confidence: {sg.get('confidence', 0):.0%}")
                lines.append("")
        else:
            lines.append("[OK] NO DEFINITIVE PROOF OF TAMPERING")
            lines.append("")

        if reasoning.filtered_red_herrings:
            lines.append("RED HERRINGS FILTERED (NOT evidence of tampering):")
            for rh in reasoning.filtered_red_herrings:
                lines.append(f"  - {rh.get('finding', 'Unknown')}")
                lines.append(f"    Reason: {rh.get('why_not_significant', 'N/A')[:100]}...")
            lines.append("")

        lines.append("EXPERT CONCLUSION:")
        lines.append(reasoning.expert_conclusion)
        lines.append("")
        lines.append(f"Analysis model: {reasoning.model_used}")
        lines.append("=" * 70)

        return "\n".join(lines)
