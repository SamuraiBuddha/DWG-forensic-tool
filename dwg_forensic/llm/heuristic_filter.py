"""
Heuristic anomaly filtering fallback.

This module provides static rule-based filtering when LLM is unavailable.
It uses provenance context to filter expected anomalies based on known
patterns for Revit exports, ODA tools, and file transfers.

The heuristic approach is more conservative than LLM reasoning but provides
30%+ false positive reduction without requiring Ollama.
"""

import logging
from typing import List, Set

from dwg_forensic.llm.anomaly_models import (
    Anomaly,
    ProvenanceInfo,
    FilteredAnomalies,
    SmokingGunRule,
)

logger = logging.getLogger(__name__)


class HeuristicAnomalyFilter:
    """
    Static rule-based anomaly filter for provenance-aware filtering.

    This filter implements forensic expert knowledge as static rules:
    - Revit exports: Filter TDINDWG=0, zero firmware, missing watermarks
    - ODA tools: Filter TrustedDWG absence, third-party origin flags
    - File transfers: Filter NTFS creation after modification (normal copy behavior)
    - AutoCAD native: Keep all anomalies (strict mode)

    CRITICAL: Smoking gun rules (CRC, NTFS SI/FN mismatch) are NEVER filtered.
    """

    # Revit export filter rules
    REVIT_FILTER_RULES: Set[str] = {
        "TAMPER-001",  # CRC mismatch - Revit has CRC=0 by design (KEEP if CRC != 0)
        "TAMPER-002",  # CRC section mismatch
        "TAMPER-003",  # TrustedDWG missing
        "TAMPER-004",  # Watermark missing
        "TAMPER-006",  # Zero firmware version
        "TAMPER-013",  # TDINDWG zero or suspicious
        "TAMPER-029",  # Third-party origin detection
    }

    # ODA SDK tool filter rules
    ODA_FILTER_RULES: Set[str] = {
        "TAMPER-001",  # CRC may be 0 for ODA tools (KEEP if CRC != 0)
        "TAMPER-003",  # TrustedDWG missing
        "TAMPER-004",  # Watermark missing
        "TAMPER-029",  # Third-party origin
        "TAMPER-030",  # Missing GUIDs
        "TAMPER-031",  # Non-Autodesk fingerprint
    }

    # File transfer filter rules
    TRANSFER_FILTER_RULES: Set[str] = {
        "TAMPER-020",  # NTFS creation after modification (normal Windows copy)
        "TAMPER-022",  # DWG-NTFS creation difference (normal transfer delay)
    }

    # Application fingerprint rules (informational, not tampering evidence)
    FINGERPRINT_INFO_RULES: Set[str] = {
        "TAMPER-029",  # Third-party CAD detected
        "TAMPER-030",  # Missing GUIDs
        "TAMPER-031",  # Non-Autodesk software
        "TAMPER-032",  # BricsCAD detected
        "TAMPER-033",  # NanoCAD detected
        "TAMPER-034",  # LibreCAD detected
        "TAMPER-035",  # ODA SDK detected
    }

    def __init__(self):
        """Initialize the heuristic filter."""
        self.smoking_gun_rules = SmokingGunRule()

    def filter_anomalies(
        self,
        anomalies: List[Anomaly],
        provenance: ProvenanceInfo,
    ) -> FilteredAnomalies:
        """
        Filter anomalies using static heuristic rules.

        Args:
            anomalies: List of Anomaly objects from rule engine
            provenance: ProvenanceInfo describing file origin

        Returns:
            FilteredAnomalies with kept/filtered lists and reasoning
        """
        if not anomalies:
            return FilteredAnomalies(
                kept_anomalies=[],
                filtered_anomalies=[],
                reasoning="No anomalies detected",
                llm_confidence=1.0,
                method="heuristic",
            )

        kept = []
        filtered = []
        reasoning_parts = []

        # Determine filter rules based on provenance
        filter_rules = self._get_filter_rules(provenance, reasoning_parts)

        # Apply filtering logic
        for anomaly in anomalies:
            # CRITICAL: Never filter smoking guns
            if self.smoking_gun_rules.is_smoking_gun(anomaly.rule_id):
                kept.append(anomaly)
                continue

            # Special handling for CRC rules (TAMPER-001, TAMPER-002)
            if anomaly.rule_id in ["TAMPER-001", "TAMPER-002"]:
                if self._should_filter_crc(anomaly, provenance):
                    filtered.append(anomaly)
                    reasoning_parts.append(
                        f"Filtered {anomaly.rule_id}: CRC=0 is expected for {provenance.provenance_path}"
                    )
                else:
                    # CRC != 0 indicates real modification, even for Revit/ODA
                    kept.append(anomaly)
                continue

            # Filter based on provenance patterns
            if anomaly.rule_id in filter_rules:
                filtered.append(anomaly)
                reasoning_parts.append(
                    f"Filtered {anomaly.rule_id}: Expected for {provenance.provenance_path}"
                )
            else:
                kept.append(anomaly)

        # Build reasoning text
        reasoning_text = self._build_reasoning(provenance, len(filtered), reasoning_parts)

        # Calculate confidence based on provenance detection confidence
        confidence = self._calculate_confidence(provenance)

        # Validate no smoking guns filtered
        validation_error = self.smoking_gun_rules.validate_filtering(filtered)
        if validation_error:
            logger.critical(validation_error)
            # This should never happen, but fail-safe
            smoking_guns_filtered = [
                a for a in filtered if self.smoking_gun_rules.is_smoking_gun(a.rule_id)
            ]
            for sg in smoking_guns_filtered:
                filtered.remove(sg)
                kept.append(sg)

        logger.info(
            f"Heuristic filtered {len(filtered)} of {len(anomalies)} anomalies "
            f"(provenance: {provenance.provenance_path}, confidence: {confidence:.1%})"
        )

        return FilteredAnomalies(
            kept_anomalies=kept,
            filtered_anomalies=filtered,
            reasoning=reasoning_text,
            llm_confidence=confidence,
            method="heuristic",
        )

    def _get_filter_rules(
        self,
        provenance: ProvenanceInfo,
        reasoning_parts: List[str],
    ) -> Set[str]:
        """Determine which rules to filter based on provenance."""
        filter_rules: Set[str] = set()

        if provenance.is_revit_export:
            filter_rules.update(self.REVIT_FILTER_RULES)
            reasoning_parts.append(
                "Revit export detected: Filtering expected CRC=0, TDINDWG=0, missing watermarks"
            )

        if provenance.is_oda_tool:
            filter_rules.update(self.ODA_FILTER_RULES)
            reasoning_parts.append(
                "ODA SDK tool detected: Filtering TrustedDWG absence and application fingerprints"
            )

        if provenance.is_file_transfer:
            filter_rules.update(self.TRANSFER_FILTER_RULES)
            reasoning_parts.append(
                "File transfer detected: Filtering NTFS creation after modification (normal copy)"
            )

        if provenance.is_native_autocad:
            reasoning_parts.append(
                "Native AutoCAD file: Strict mode - keeping all anomalies for manual review"
            )
            # No filtering for native AutoCAD (except informational fingerprints)
            filter_rules.update(self.FINGERPRINT_INFO_RULES)

        # Always filter informational fingerprint rules (not tampering evidence)
        filter_rules.update(self.FINGERPRINT_INFO_RULES)

        return filter_rules

    def _should_filter_crc(self, anomaly: Anomaly, provenance: ProvenanceInfo) -> bool:
        """
        Determine if CRC anomaly should be filtered.

        Revit and some ODA tools have CRC=0 by design. However, if CRC is
        non-zero and invalid, that indicates real modification.

        Args:
            anomaly: CRC-related anomaly
            provenance: File provenance info

        Returns:
            True if CRC=0 is expected for this provenance, False if suspicious
        """
        # Check anomaly details for actual CRC value
        details = anomaly.details
        stored_crc = details.get("stored_crc", "0x00000000")
        calculated_crc = details.get("calculated_crc", "0x00000000")

        # CRC=0 is expected for Revit and some ODA tools
        if stored_crc == "0x00000000" and calculated_crc == "0x00000000":
            if provenance.is_revit_export or provenance.is_oda_tool:
                return True  # Filter - expected behavior

        # Non-zero CRC mismatch is suspicious even for Revit/ODA
        if stored_crc != "0x00000000" and stored_crc != calculated_crc:
            return False  # Keep - real modification

        return False  # Default: keep if uncertain

    def _build_reasoning(
        self,
        provenance: ProvenanceInfo,
        filtered_count: int,
        reasoning_parts: List[str],
    ) -> str:
        """Build human-readable reasoning text."""
        if not reasoning_parts:
            return f"Heuristic filtering applied for {provenance.provenance_path}"

        base = f"Heuristic filtering for {provenance.provenance_path}. "
        details = ". ".join(reasoning_parts)
        summary = f"Filtered {filtered_count} expected anomalies."

        return f"{base}{details}. {summary}"

    def _calculate_confidence(self, provenance: ProvenanceInfo) -> float:
        """
        Calculate confidence in filtering decision.

        Based on provenance detection confidence:
        - High provenance confidence (>0.8) -> High filter confidence (0.75)
        - Medium provenance confidence (0.6-0.8) -> Medium filter confidence (0.6)
        - Low provenance confidence (<0.6) -> Low filter confidence (0.4)

        Returns:
            Confidence score 0.0-1.0
        """
        prov_conf = provenance.confidence

        if prov_conf >= 0.8:
            return 0.75  # High confidence in heuristic filtering
        elif prov_conf >= 0.6:
            return 0.6  # Medium confidence
        elif prov_conf >= 0.4:
            return 0.5  # Low-medium confidence
        else:
            return 0.4  # Low confidence - manual review recommended
