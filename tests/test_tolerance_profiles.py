"""
Tests for DWG Forensic Tool - Tolerance Profiles

This test suite validates Phase 2.1: Core Tolerance Infrastructure for
provenance-aware tampering detection.

Test Coverage:
1. ProvenanceToleranceProfile dataclass functionality
2. Built-in profile definitions (REVIT_EXPORT, DIRECT_AUTOCAD, ODA_TRANSFER, UNKNOWN)
3. ProvenanceToleranceMapper selection logic
4. TamperingRuleEngine integration with tolerance profiles
5. Backward compatibility (no tolerance profile = UNKNOWN profile)

All tests must pass to ensure no regression in existing behavior.
"""

import pytest
from dataclasses import dataclass, field
from typing import Dict, List

from dwg_forensic.analysis.tolerance_profiles import (
    ProvenanceToleranceProfile,
    REVIT_EXPORT,
    DIRECT_AUTOCAD,
    ODA_TRANSFER,
    UNKNOWN,
    get_profile,
    list_profiles,
)
from dwg_forensic.analysis.tolerance_mapper import (
    ProvenanceToleranceMapper,
    map_provenance_to_profile,
)
from dwg_forensic.analysis.provenance_detector import FileProvenance
from dwg_forensic.analysis.rules.engine import TamperingRuleEngine


class TestProvenanceToleranceProfile:
    """Test ProvenanceToleranceProfile dataclass."""

    def test_default_initialization(self):
        """Test profile with default values."""
        profile = ProvenanceToleranceProfile(
            name="TEST_PROFILE",
            description="Test profile"
        )

        assert profile.name == "TEST_PROFILE"
        assert profile.description == "Test profile"
        assert profile.time_window_minutes == 5.0
        assert profile.percentage_padding == 0.1
        assert profile.threshold_strictness == 1.0
        assert profile.rule_tolerances == {}

    def test_custom_initialization(self):
        """Test profile with custom values."""
        profile = ProvenanceToleranceProfile(
            name="CUSTOM",
            description="Custom profile",
            time_window_minutes=10.0,
            percentage_padding=0.2,
            threshold_strictness=0.8,
            rule_tolerances={
                "TAMPER-013": {
                    "time_window_minutes": 30.0,
                    "percentage_padding": 0.3,
                }
            },
        )

        assert profile.name == "CUSTOM"
        assert profile.time_window_minutes == 10.0
        assert profile.percentage_padding == 0.2
        assert profile.threshold_strictness == 0.8
        assert "TAMPER-013" in profile.rule_tolerances

    def test_get_rule_tolerance_found(self):
        """Test getting rule tolerance when it exists."""
        profile = ProvenanceToleranceProfile(
            name="TEST",
            description="Test",
            rule_tolerances={
                "TAMPER-013": {
                    "time_window_minutes": 30.0,
                    "percentage_padding": 0.25,
                }
            },
        )

        assert profile.get_rule_tolerance(
            "TAMPER-013", "time_window_minutes"
        ) == 30.0
        assert profile.get_rule_tolerance(
            "TAMPER-013", "percentage_padding"
        ) == 0.25

    def test_get_rule_tolerance_not_found(self):
        """Test getting rule tolerance when it doesn't exist."""
        profile = ProvenanceToleranceProfile(
            name="TEST",
            description="Test",
        )

        assert profile.get_rule_tolerance(
            "TAMPER-999", "time_window_minutes"
        ) is None
        assert profile.get_rule_tolerance(
            "TAMPER-999", "time_window_minutes", default=15.0
        ) == 15.0

    def test_apply_strictness(self):
        """Test applying strictness multiplier."""
        profile = ProvenanceToleranceProfile(
            name="TEST",
            description="Test",
            threshold_strictness=0.8,
        )

        assert profile.apply_strictness(100.0) == 80.0
        assert profile.apply_strictness(50.0) == 40.0

    def test_apply_padding(self):
        """Test applying percentage padding."""
        profile = ProvenanceToleranceProfile(
            name="TEST",
            description="Test",
            percentage_padding=0.1,
        )

        # Use pytest.approx for floating point comparison
        assert profile.apply_padding(100.0) == pytest.approx(110.0)
        assert profile.apply_padding(50.0) == pytest.approx(55.0)


class TestBuiltinProfiles:
    """Test built-in tolerance profiles."""

    def test_revit_export_profile(self):
        """Test REVIT_EXPORT profile characteristics."""
        assert REVIT_EXPORT.name == "REVIT_EXPORT"
        assert REVIT_EXPORT.time_window_minutes == 120.0
        assert REVIT_EXPORT.percentage_padding == 0.25
        assert REVIT_EXPORT.threshold_strictness == 0.7

        # Check specific rule tolerances
        assert REVIT_EXPORT.get_rule_tolerance(
            "TAMPER-013", "time_window_minutes"
        ) == 180.0
        assert REVIT_EXPORT.get_rule_tolerance(
            "TAMPER-022", "percentage_padding"
        ) == 0.5

    def test_direct_autocad_profile(self):
        """Test DIRECT_AUTOCAD profile characteristics."""
        assert DIRECT_AUTOCAD.name == "DIRECT_AUTOCAD"
        assert DIRECT_AUTOCAD.time_window_minutes == 2.0
        assert DIRECT_AUTOCAD.percentage_padding == 0.05
        assert DIRECT_AUTOCAD.threshold_strictness == 1.0

        # Check specific rule tolerances
        assert DIRECT_AUTOCAD.get_rule_tolerance(
            "TAMPER-013", "time_window_minutes"
        ) == 5.0
        assert DIRECT_AUTOCAD.get_rule_tolerance(
            "TAMPER-022", "percentage_padding"
        ) == 0.1

    def test_oda_transfer_profile(self):
        """Test ODA_TRANSFER profile characteristics."""
        assert ODA_TRANSFER.name == "ODA_TRANSFER"
        assert ODA_TRANSFER.time_window_minutes == 30.0
        assert ODA_TRANSFER.percentage_padding == 0.15
        assert ODA_TRANSFER.threshold_strictness == 0.85

        # Check specific rule tolerances
        assert ODA_TRANSFER.get_rule_tolerance(
            "TAMPER-013", "time_window_minutes"
        ) == 60.0
        assert ODA_TRANSFER.get_rule_tolerance(
            "TAMPER-022", "percentage_padding"
        ) == 0.3

    def test_unknown_profile(self):
        """Test UNKNOWN profile characteristics."""
        assert UNKNOWN.name == "UNKNOWN"
        assert UNKNOWN.time_window_minutes == 15.0
        assert UNKNOWN.percentage_padding == 0.1
        assert UNKNOWN.threshold_strictness == 0.9

        # Check specific rule tolerances
        assert UNKNOWN.get_rule_tolerance(
            "TAMPER-013", "time_window_minutes"
        ) == 30.0
        assert UNKNOWN.get_rule_tolerance(
            "TAMPER-022", "percentage_padding"
        ) == 0.2

    def test_profile_ordering_strictness(self):
        """Test that profiles are ordered correctly by strictness."""
        # DIRECT_AUTOCAD should be strictest
        assert DIRECT_AUTOCAD.time_window_minutes < ODA_TRANSFER.time_window_minutes
        assert DIRECT_AUTOCAD.time_window_minutes < REVIT_EXPORT.time_window_minutes

        # REVIT_EXPORT should be most lenient
        assert REVIT_EXPORT.time_window_minutes > DIRECT_AUTOCAD.time_window_minutes
        assert REVIT_EXPORT.percentage_padding > DIRECT_AUTOCAD.percentage_padding

    def test_get_profile(self):
        """Test get_profile function."""
        assert get_profile("REVIT_EXPORT") == REVIT_EXPORT
        assert get_profile("DIRECT_AUTOCAD") == DIRECT_AUTOCAD
        assert get_profile("ODA_TRANSFER") == ODA_TRANSFER
        assert get_profile("UNKNOWN") == UNKNOWN
        assert get_profile("NONEXISTENT") is None

    def test_list_profiles(self):
        """Test list_profiles function."""
        profiles = list_profiles()
        assert len(profiles) == 4
        assert "REVIT_EXPORT" in profiles
        assert "DIRECT_AUTOCAD" in profiles
        assert "ODA_TRANSFER" in profiles
        assert "UNKNOWN" in profiles


class TestProvenanceToleranceMapper:
    """Test ProvenanceToleranceMapper class."""

    def test_revit_export_mapping(self):
        """Test mapping Revit export to REVIT_EXPORT profile."""
        provenance = FileProvenance(
            source_application="Revit",
            is_export=True,
            is_revit_export=True,
            revit_confidence=0.95,
            confidence=0.95,
        )

        mapper = ProvenanceToleranceMapper()
        profile = mapper.select_profile(provenance)

        assert profile.name == "REVIT_EXPORT"
        assert mapper.get_confidence() > 0.9

    def test_oda_tool_mapping(self):
        """Test mapping ODA tool to ODA_TRANSFER profile."""
        provenance = FileProvenance(
            source_application="BricsCAD",
            is_oda_tool=True,
            fingerprint_confidence=0.85,
            confidence=0.85,
        )

        mapper = ProvenanceToleranceMapper()
        profile = mapper.select_profile(provenance)

        assert profile.name == "ODA_TRANSFER"
        assert mapper.get_confidence() > 0.8

    def test_file_transfer_mapping(self):
        """Test mapping file transfer to ODA_TRANSFER profile."""
        provenance = FileProvenance(
            source_application="Unknown",
            is_transferred=True,
            confidence=0.85,
            transfer_indicators=["NTFS Created > Modified"],
        )

        mapper = ProvenanceToleranceMapper()
        profile = mapper.select_profile(provenance)

        assert profile.name == "ODA_TRANSFER"
        assert mapper.get_confidence() > 0.7

    def test_native_autocad_mapping(self):
        """Test mapping native AutoCAD to DIRECT_AUTOCAD profile."""
        provenance = FileProvenance(
            source_application="AutoCAD",
            is_native_autocad=True,
            confidence=0.7,
        )

        mapper = ProvenanceToleranceMapper()
        profile = mapper.select_profile(provenance)

        assert profile.name == "DIRECT_AUTOCAD"
        assert mapper.get_confidence() > 0.6

    def test_unknown_mapping(self):
        """Test mapping unknown provenance to UNKNOWN profile."""
        provenance = FileProvenance(
            source_application="Unknown",
            confidence=0.3,
        )

        mapper = ProvenanceToleranceMapper()
        profile = mapper.select_profile(provenance)

        assert profile.name == "UNKNOWN"
        assert mapper.get_confidence() > 0.0

    def test_low_confidence_revit_fallback(self):
        """Test that low confidence Revit detection falls back to UNKNOWN."""
        provenance = FileProvenance(
            source_application="Revit",
            is_revit_export=True,
            revit_confidence=0.3,  # Below threshold
            confidence=0.3,
        )

        mapper = ProvenanceToleranceMapper()
        profile = mapper.select_profile(provenance)

        # Should fall back to UNKNOWN due to low confidence
        assert profile.name == "UNKNOWN"

    def test_get_selection_summary(self):
        """Test get_selection_summary method."""
        provenance = FileProvenance(
            source_application="Revit",
            is_revit_export=True,
            revit_confidence=0.95,
            confidence=0.95,
        )

        mapper = ProvenanceToleranceMapper()
        mapper.select_profile(provenance)
        summary = mapper.get_selection_summary()

        assert "REVIT_EXPORT" in summary
        assert "Revit" in summary
        assert "0.95" in summary or "95" in summary

    def test_should_use_strict_mode(self):
        """Test strict mode detection."""
        # Native AutoCAD should use strict mode
        provenance_autocad = FileProvenance(
            source_application="AutoCAD",
            is_native_autocad=True,
            confidence=0.7,
        )

        mapper = ProvenanceToleranceMapper()
        mapper.select_profile(provenance_autocad)
        assert mapper.should_use_strict_mode() is True
        assert mapper.should_use_relaxed_mode() is False

    def test_should_use_relaxed_mode(self):
        """Test relaxed mode detection."""
        # Revit export should use relaxed mode
        provenance_revit = FileProvenance(
            source_application="Revit",
            is_revit_export=True,
            revit_confidence=0.95,
            confidence=0.95,
        )

        mapper = ProvenanceToleranceMapper()
        mapper.select_profile(provenance_revit)
        assert mapper.should_use_relaxed_mode() is True
        assert mapper.should_use_strict_mode() is False

    def test_map_provenance_to_profile_convenience(self):
        """Test convenience function."""
        provenance = FileProvenance(
            source_application="Revit",
            is_revit_export=True,
            revit_confidence=0.95,
            confidence=0.95,
        )

        profile = map_provenance_to_profile(provenance)
        assert profile.name == "REVIT_EXPORT"


class TestTamperingRuleEngineIntegration:
    """Test TamperingRuleEngine integration with tolerance profiles."""

    def test_engine_default_tolerance(self):
        """Test engine uses UNKNOWN profile by default."""
        engine = TamperingRuleEngine()
        profile = engine.get_tolerance()

        assert profile.name == "UNKNOWN"

    def test_engine_custom_tolerance(self):
        """Test engine with custom tolerance profile."""
        engine = TamperingRuleEngine(tolerance_profile=REVIT_EXPORT)
        profile = engine.get_tolerance()

        assert profile.name == "REVIT_EXPORT"

    def test_engine_set_tolerance(self):
        """Test changing tolerance profile after initialization."""
        engine = TamperingRuleEngine()
        assert engine.get_tolerance().name == "UNKNOWN"

        engine.set_tolerance(DIRECT_AUTOCAD)
        assert engine.get_tolerance().name == "DIRECT_AUTOCAD"

    def test_backward_compatibility_no_profile(self):
        """Test backward compatibility - no profile argument."""
        # Old code that doesn't pass tolerance_profile should still work
        engine = TamperingRuleEngine()
        assert engine.get_tolerance().name == "UNKNOWN"

        # Should still have all rules loaded
        # Note: Currently 39 rules (TAMPER-003 and TAMPER-004 not implemented)
        rules = engine.get_builtin_rules()
        assert len(rules) >= 39  # All built-in rules

    def test_all_profiles_with_engine(self):
        """Test engine initialization with all built-in profiles."""
        for profile_name in ["REVIT_EXPORT", "DIRECT_AUTOCAD", "ODA_TRANSFER", "UNKNOWN"]:
            profile = get_profile(profile_name)
            engine = TamperingRuleEngine(tolerance_profile=profile)
            assert engine.get_tolerance().name == profile_name


class TestEndToEndIntegration:
    """Test end-to-end tolerance profile workflow."""

    def test_full_workflow_revit(self):
        """Test complete workflow for Revit export."""
        # 1. Create provenance (normally from ProvenanceDetector)
        provenance = FileProvenance(
            source_application="Revit",
            is_revit_export=True,
            revit_confidence=0.95,
            confidence=0.95,
        )

        # 2. Map provenance to tolerance profile
        mapper = ProvenanceToleranceMapper()
        profile = mapper.select_profile(provenance)
        assert profile.name == "REVIT_EXPORT"

        # 3. Initialize rule engine with profile
        engine = TamperingRuleEngine(tolerance_profile=profile)
        assert engine.get_tolerance().name == "REVIT_EXPORT"

        # 4. Verify profile characteristics are accessible
        assert engine.get_tolerance().time_window_minutes == 120.0
        assert engine.get_tolerance().percentage_padding == 0.25

    def test_full_workflow_autocad(self):
        """Test complete workflow for native AutoCAD."""
        # 1. Create provenance
        provenance = FileProvenance(
            source_application="AutoCAD",
            is_native_autocad=True,
            confidence=0.7,
        )

        # 2. Map to profile
        mapper = ProvenanceToleranceMapper()
        profile = mapper.select_profile(provenance)
        assert profile.name == "DIRECT_AUTOCAD"

        # 3. Initialize engine
        engine = TamperingRuleEngine(tolerance_profile=profile)
        assert engine.get_tolerance().name == "DIRECT_AUTOCAD"

        # 4. Verify strict tolerances
        assert engine.get_tolerance().time_window_minutes == 2.0
        assert engine.get_tolerance().percentage_padding == 0.05

    def test_tolerance_profile_affects_no_rules_yet(self):
        """
        Test that tolerance profile is stored but doesn't affect rule logic yet.

        This is Phase 2.1 - we're only building the infrastructure.
        Phase 2.2 will actually use the tolerances in rule implementations.
        """
        # Create engine with lenient Revit profile
        engine_revit = TamperingRuleEngine(tolerance_profile=REVIT_EXPORT)

        # Create engine with strict AutoCAD profile
        engine_autocad = TamperingRuleEngine(tolerance_profile=DIRECT_AUTOCAD)

        # Both engines should have the same rules (no logic changes yet)
        assert len(engine_revit.get_builtin_rules()) == len(
            engine_autocad.get_builtin_rules()
        )

        # Profile is stored and retrievable
        assert engine_revit.get_tolerance().name == "REVIT_EXPORT"
        assert engine_autocad.get_tolerance().name == "DIRECT_AUTOCAD"
