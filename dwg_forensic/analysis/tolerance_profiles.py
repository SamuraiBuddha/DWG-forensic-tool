"""
DWG Forensic Tool - Tolerance Profiles

Provenance-aware tolerance profiles for tampering detection rules.

This module defines tolerance configurations for different file origins:
- Revit exports: High tolerance for timestamps, zero CRC is expected
- Direct AutoCAD: Strict tolerance, expect proper timestamps and CRC
- ODA transfers: Medium tolerance for CRC/watermarks, normal timestamps
- Unknown: Conservative fallback with moderate tolerance

Each profile specifies rule-specific tolerances to prevent false positives
while maintaining detection accuracy for genuine tampering.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class ProvenanceToleranceProfile:
    """
    Tolerance profile for a specific file provenance type.

    Attributes:
        name: Profile identifier (e.g., "REVIT_EXPORT", "DIRECT_AUTOCAD")
        description: Human-readable description of the profile
        time_window_minutes: Tolerance window for timestamp comparisons (minutes)
        percentage_padding: Percentage padding for threshold-based rules (0.0-1.0)
        threshold_strictness: Multiplier for threshold values (1.0 = normal)
        rule_tolerances: Per-rule tolerance overrides
    """
    name: str
    description: str
    time_window_minutes: float = 5.0
    percentage_padding: float = 0.1
    threshold_strictness: float = 1.0
    rule_tolerances: Dict[str, Dict[str, float]] = field(default_factory=dict)

    def get_rule_tolerance(
        self,
        rule_id: str,
        parameter: str,
        default: Optional[float] = None
    ) -> Optional[float]:
        """
        Get tolerance value for a specific rule parameter.

        Args:
            rule_id: Rule identifier (e.g., "TAMPER-013")
            parameter: Parameter name (e.g., "time_window_minutes")
            default: Default value if not specified

        Returns:
            Tolerance value or default if not found
        """
        if rule_id in self.rule_tolerances:
            return self.rule_tolerances[rule_id].get(parameter, default)
        return default

    def apply_strictness(self, threshold: float) -> float:
        """
        Apply strictness multiplier to a threshold value.

        Args:
            threshold: Base threshold value

        Returns:
            Adjusted threshold based on strictness setting
        """
        return threshold * self.threshold_strictness

    def apply_padding(self, value: float) -> float:
        """
        Apply percentage padding to a value.

        Args:
            value: Base value

        Returns:
            Value with percentage padding applied
        """
        return value * (1.0 + self.percentage_padding)


# Built-in tolerance profiles

REVIT_EXPORT = ProvenanceToleranceProfile(
    name="REVIT_EXPORT",
    description=(
        "Autodesk Revit DWG exports - High tolerance for timestamp variance, "
        "zero CRC is expected, missing timestamps are normal"
    ),
    time_window_minutes=120.0,  # 2 hours tolerance for Revit export timestamps
    percentage_padding=0.25,  # 25% padding for thresholds
    threshold_strictness=0.7,  # Relaxed thresholds (70% of normal)
    rule_tolerances={
        "TAMPER-013": {
            "time_window_minutes": 180.0,  # 3 hours for TDINDWG checks
            "percentage_padding": 0.3,  # 30% padding for edit time checks
        },
        "TAMPER-014": {
            "time_window_minutes": 240.0,  # 4 hours for version anachronism
        },
        "TAMPER-022": {
            "time_window_minutes": 300.0,  # 5 hours for DWG-NTFS creation check
            "percentage_padding": 0.5,  # 50% padding - Revit exports vary widely
        },
        "TAMPER-023": {
            "time_window_minutes": 300.0,  # 5 hours for DWG-NTFS modification check
            "percentage_padding": 0.5,
        },
        "TAMPER-038": {
            "time_window_minutes": 300.0,  # 5 hours for internal timestamp check
            "percentage_padding": 0.4,
        },
    },
)

DIRECT_AUTOCAD = ProvenanceToleranceProfile(
    name="DIRECT_AUTOCAD",
    description=(
        "Native AutoCAD files - Strict tolerance, expect proper CRC and "
        "accurate timestamps with minimal variance"
    ),
    time_window_minutes=2.0,  # 2 minutes tolerance (strict)
    percentage_padding=0.05,  # 5% padding (strict)
    threshold_strictness=1.0,  # Normal thresholds (100%)
    rule_tolerances={
        "TAMPER-013": {
            "time_window_minutes": 5.0,  # 5 minutes for TDINDWG checks
            "percentage_padding": 0.1,  # 10% padding
        },
        "TAMPER-014": {
            "time_window_minutes": 10.0,  # 10 minutes for version anachronism
        },
        "TAMPER-022": {
            "time_window_minutes": 15.0,  # 15 minutes for DWG-NTFS creation
            "percentage_padding": 0.1,
        },
        "TAMPER-023": {
            "time_window_minutes": 15.0,  # 15 minutes for DWG-NTFS modification
            "percentage_padding": 0.1,
        },
        "TAMPER-038": {
            "time_window_minutes": 15.0,  # 15 minutes for internal timestamps
            "percentage_padding": 0.1,
        },
    },
)

ODA_TRANSFER = ProvenanceToleranceProfile(
    name="ODA_TRANSFER",
    description=(
        "ODA SDK tools (BricsCAD, NanoCAD, DraftSight) and file transfers - "
        "Medium tolerance, CRC may be zero, timestamps may show transfer gaps"
    ),
    time_window_minutes=30.0,  # 30 minutes tolerance for ODA/transfers
    percentage_padding=0.15,  # 15% padding
    threshold_strictness=0.85,  # Slightly relaxed thresholds (85%)
    rule_tolerances={
        "TAMPER-013": {
            "time_window_minutes": 60.0,  # 1 hour for TDINDWG checks
            "percentage_padding": 0.2,  # 20% padding
        },
        "TAMPER-014": {
            "time_window_minutes": 90.0,  # 1.5 hours for version anachronism
        },
        "TAMPER-022": {
            "time_window_minutes": 120.0,  # 2 hours for DWG-NTFS creation
            "percentage_padding": 0.3,  # 30% padding - transfers have gaps
        },
        "TAMPER-023": {
            "time_window_minutes": 120.0,  # 2 hours for DWG-NTFS modification
            "percentage_padding": 0.3,
        },
        "TAMPER-038": {
            "time_window_minutes": 120.0,  # 2 hours for internal timestamps
            "percentage_padding": 0.25,
        },
    },
)

UNKNOWN = ProvenanceToleranceProfile(
    name="UNKNOWN",
    description=(
        "Unknown file origin - Conservative fallback profile with moderate "
        "tolerance to avoid false positives while maintaining detection capability"
    ),
    time_window_minutes=15.0,  # 15 minutes tolerance (moderate)
    percentage_padding=0.1,  # 10% padding (moderate)
    threshold_strictness=0.9,  # Slightly relaxed thresholds (90%)
    rule_tolerances={
        "TAMPER-013": {
            "time_window_minutes": 30.0,  # 30 minutes for TDINDWG checks
            "percentage_padding": 0.15,  # 15% padding
        },
        "TAMPER-014": {
            "time_window_minutes": 45.0,  # 45 minutes for version anachronism
        },
        "TAMPER-022": {
            "time_window_minutes": 60.0,  # 1 hour for DWG-NTFS creation
            "percentage_padding": 0.2,  # 20% padding
        },
        "TAMPER-023": {
            "time_window_minutes": 60.0,  # 1 hour for DWG-NTFS modification
            "percentage_padding": 0.2,
        },
        "TAMPER-038": {
            "time_window_minutes": 60.0,  # 1 hour for internal timestamps
            "percentage_padding": 0.15,
        },
    },
)


# Profile registry
TOLERANCE_PROFILES = {
    "REVIT_EXPORT": REVIT_EXPORT,
    "DIRECT_AUTOCAD": DIRECT_AUTOCAD,
    "ODA_TRANSFER": ODA_TRANSFER,
    "UNKNOWN": UNKNOWN,
}


def get_profile(name: str) -> Optional[ProvenanceToleranceProfile]:
    """
    Get tolerance profile by name.

    Args:
        name: Profile name (e.g., "REVIT_EXPORT")

    Returns:
        ProvenanceToleranceProfile instance or None if not found
    """
    return TOLERANCE_PROFILES.get(name)


def list_profiles() -> Dict[str, ProvenanceToleranceProfile]:
    """
    Get all available tolerance profiles.

    Returns:
        Dictionary of profile name to ProvenanceToleranceProfile
    """
    return TOLERANCE_PROFILES.copy()
