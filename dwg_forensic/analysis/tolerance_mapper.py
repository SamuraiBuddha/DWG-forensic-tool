"""
DWG Forensic Tool - Provenance Tolerance Mapper

Maps file provenance detection results to appropriate tolerance profiles.

This module bridges the gap between provenance detection and rule evaluation:
1. Takes FileProvenance from ProvenanceDetector
2. Selects the most appropriate ToleranceProfile
3. Provides confidence scoring for the mapping
4. Integrates with SmokingGunDetector for enhanced accuracy

The mapper uses a decision tree approach based on provenance attributes:
- Revit exports -> REVIT_EXPORT profile (high tolerance)
- ODA tools or file transfers -> ODA_TRANSFER profile (medium tolerance)
- Native AutoCAD -> DIRECT_AUTOCAD profile (strict tolerance)
- Unknown/ambiguous -> UNKNOWN profile (conservative fallback)
"""

from typing import Optional

from dwg_forensic.analysis.provenance_detector import FileProvenance
from dwg_forensic.analysis.tolerance_profiles import (
    ProvenanceToleranceProfile,
    REVIT_EXPORT,
    DIRECT_AUTOCAD,
    ODA_TRANSFER,
    UNKNOWN,
)


class ProvenanceToleranceMapper:
    """
    Maps file provenance to appropriate tolerance profile.

    This class implements a decision tree for selecting tolerance profiles
    based on detected file characteristics. The selection prioritizes
    specificity: Revit > ODA > AutoCAD > Unknown.

    Confidence scoring considers:
    - Provenance detection confidence (from detector)
    - Clarity of provenance signals (unambiguous vs mixed signals)
    - Strength of evidence for selected profile
    """

    # Confidence thresholds for profile selection
    HIGH_CONFIDENCE_THRESHOLD = 0.8
    MEDIUM_CONFIDENCE_THRESHOLD = 0.5
    LOW_CONFIDENCE_THRESHOLD = 0.3

    def __init__(self):
        """Initialize the tolerance mapper."""
        self._last_provenance: Optional[FileProvenance] = None
        self._last_profile: Optional[ProvenanceToleranceProfile] = None
        self._last_confidence: float = 0.0

    def select_profile(
        self,
        provenance: FileProvenance
    ) -> ProvenanceToleranceProfile:
        """
        Select the most appropriate tolerance profile for a file provenance.

        Args:
            provenance: FileProvenance result from ProvenanceDetector

        Returns:
            ProvenanceToleranceProfile instance

        Decision tree:
        1. If Revit export detected (confidence > 0.5) -> REVIT_EXPORT
        2. If ODA tool or file transfer detected -> ODA_TRANSFER
        3. If native AutoCAD detected -> DIRECT_AUTOCAD
        4. Otherwise -> UNKNOWN (conservative fallback)
        """
        # Store for confidence calculation
        self._last_provenance = provenance

        # Decision tree - order matters (most specific first)

        # 1. Revit export (highest priority)
        if provenance.is_revit_export:
            # Revit detection requires high confidence
            if provenance.revit_confidence > self.MEDIUM_CONFIDENCE_THRESHOLD:
                self._last_profile = REVIT_EXPORT
                self._last_confidence = self._calculate_confidence(provenance, REVIT_EXPORT)
                return REVIT_EXPORT

        # 2. ODA SDK tools or file transfers
        if provenance.is_oda_tool or provenance.is_transferred:
            self._last_profile = ODA_TRANSFER
            self._last_confidence = self._calculate_confidence(provenance, ODA_TRANSFER)
            return ODA_TRANSFER

        # 3. Native AutoCAD
        if provenance.is_native_autocad:
            # Only use strict AutoCAD profile if we have reasonable confidence
            if provenance.confidence > self.LOW_CONFIDENCE_THRESHOLD:
                self._last_profile = DIRECT_AUTOCAD
                self._last_confidence = self._calculate_confidence(
                    provenance,
                    DIRECT_AUTOCAD
                )
                return DIRECT_AUTOCAD

        # 4. Unknown (conservative fallback)
        self._last_profile = UNKNOWN
        self._last_confidence = self._calculate_confidence(provenance, UNKNOWN)
        return UNKNOWN

    def get_confidence(self) -> float:
        """
        Get confidence score for the last profile selection.

        Returns:
            Confidence score from 0.0 to 1.0
        """
        return self._last_confidence

    def get_profile_name(self) -> str:
        """
        Get the name of the last selected profile.

        Returns:
            Profile name or "NONE" if no profile selected
        """
        if self._last_profile:
            return self._last_profile.name
        return "NONE"

    def get_selection_summary(self) -> str:
        """
        Get human-readable summary of the last profile selection.

        Returns:
            Summary string describing the selection and confidence
        """
        if not self._last_profile or not self._last_provenance:
            return "No profile selected yet"

        profile_name = self._last_profile.name
        confidence = self._last_confidence
        provenance = self._last_provenance

        summary_parts = [
            f"Selected tolerance profile: {profile_name}",
            f"Confidence: {confidence:.2f}",
            f"Source application: {provenance.source_application}",
        ]

        if provenance.is_revit_export:
            summary_parts.append(
                f"Revit export (confidence: {provenance.revit_confidence:.2f})"
            )
        elif provenance.is_oda_tool:
            summary_parts.append(
                f"ODA SDK tool (confidence: {provenance.fingerprint_confidence:.2f})"
            )
        elif provenance.is_transferred:
            summary_parts.append("File transfer detected")
        elif provenance.is_native_autocad:
            summary_parts.append("Native AutoCAD")

        return " | ".join(summary_parts)

    def _calculate_confidence(
        self,
        provenance: FileProvenance,
        profile: ProvenanceToleranceProfile
    ) -> float:
        """
        Calculate confidence score for profile selection.

        Args:
            provenance: FileProvenance result
            profile: Selected ProvenanceToleranceProfile

        Returns:
            Confidence score from 0.0 to 1.0
        """
        # Start with base provenance confidence
        base_confidence = provenance.confidence

        # Adjust based on profile type and provenance clarity
        if profile.name == "REVIT_EXPORT":
            # Revit detection is very specific - high confidence if detected
            if provenance.is_revit_export:
                return min(base_confidence * 1.1, 1.0)  # Boost by 10%

        elif profile.name == "ODA_TRANSFER":
            # ODA or transfer detection is moderately specific
            if provenance.is_oda_tool:
                return min(base_confidence * 1.05, 1.0)  # Boost by 5%
            elif provenance.is_transferred:
                return min(base_confidence * 1.0, 1.0)  # No boost for transfers

        elif profile.name == "DIRECT_AUTOCAD":
            # AutoCAD detection is a positive assertion
            if provenance.is_native_autocad:
                return min(base_confidence * 1.0, 1.0)  # No boost

        elif profile.name == "UNKNOWN":
            # Unknown is a fallback - reduce confidence
            return min(base_confidence * 0.8, 1.0)  # Reduce by 20%

        # Fallback - use base confidence
        return base_confidence

    def should_use_strict_mode(self) -> bool:
        """
        Determine if strict mode should be used based on profile.

        Strict mode means using the DIRECT_AUTOCAD profile's strict tolerances.

        Returns:
            True if strict mode should be used (native AutoCAD detected)
        """
        if self._last_profile:
            return self._last_profile.name == "DIRECT_AUTOCAD"
        return False

    def should_use_relaxed_mode(self) -> bool:
        """
        Determine if relaxed mode should be used based on profile.

        Relaxed mode means using the REVIT_EXPORT profile's lenient tolerances.

        Returns:
            True if relaxed mode should be used (Revit export detected)
        """
        if self._last_profile:
            return self._last_profile.name == "REVIT_EXPORT"
        return False


def map_provenance_to_profile(
    provenance: FileProvenance
) -> ProvenanceToleranceProfile:
    """
    Convenience function to map provenance to tolerance profile.

    Args:
        provenance: FileProvenance result from detector

    Returns:
        ProvenanceToleranceProfile instance
    """
    mapper = ProvenanceToleranceMapper()
    return mapper.select_profile(provenance)
