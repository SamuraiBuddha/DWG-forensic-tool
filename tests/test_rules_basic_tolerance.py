"""
Tests for DWG Forensic Tool - Phase 2.2: Basic Rules Tolerance Integration

This test suite validates that TAMPER-001 to TAMPER-012 correctly use
provenance-aware tolerance profiles to reduce false positives while
maintaining 100% true positive detection rate.

Test Coverage:
1. CRC checks remain STRICT across all profiles (smoking guns)
2. TrustedDWG checks remain STRICT across all profiles (smoking guns)
3. Timestamp checks adapt to profile tolerances
4. Revit profile allows higher tolerance for timestamp comparisons
5. UNKNOWN profile uses conservative thresholds
6. Edit time checks use profile percentage padding
7. Future timestamp checks use profile time windows
8. All rules maintain backward compatibility

Phase 2.2 Success Criteria:
- 8 new tests passing
- CRC/TrustedDWG checks never relaxed
- Revit timestamp tolerance reduces false positives
- No new false negatives introduced
"""

import pytest
from datetime import datetime, timedelta, timezone
from typing import Dict, Any

from dwg_forensic.analysis.tolerance_profiles import (
    REVIT_EXPORT,
    DIRECT_AUTOCAD,
    ODA_TRANSFER,
    UNKNOWN,
)
from dwg_forensic.analysis.rules.engine import TamperingRuleEngine
from dwg_forensic.analysis.rules.models import RuleStatus


class TestBasicRulesTolerance:
    """Test basic rules (TAMPER-001 to TAMPER-012) with tolerance profiles."""

    def test_crc_check_remains_strict_all_profiles(self):
        """
        TAMPER-001: CRC checks must remain STRICT regardless of profile.
        CRC mismatches are definitive smoking guns - NO tolerance allowed.
        """
        # Test with all profiles
        for profile in [REVIT_EXPORT, DIRECT_AUTOCAD, ODA_TRANSFER, UNKNOWN]:
            engine = TamperingRuleEngine(tolerance_profile=profile)

            # CRC mismatch context (non-Revit, non-ODA)
            context = {
                "crc_validation": {
                    "is_valid": False,
                    "header_crc_stored": "0xABCDEF12",
                    "header_crc_calculated": "0x12345678",
                    "is_revit_export": False,
                    "is_oda_export": False,
                },
                "structure_analysis": {
                    "structure_type": "autocad",
                    "detected_tool": "AutoCAD",
                },
            }

            results = engine.evaluate_all(context)
            tamper_001 = next(r for r in results if r.rule_id == "TAMPER-001")

            # Must FAIL for all profiles - CRC checks are never relaxed
            assert tamper_001.status == RuleStatus.FAILED
            assert tamper_001.confidence == 1.0
            assert "CRC" in tamper_001.description

    def test_revit_crc_zero_normal_all_profiles(self):
        """
        TAMPER-001: CRC=0 must be treated as NORMAL for Revit exports
        across all profiles (this is provenance-specific, not tolerance).
        """
        for profile in [REVIT_EXPORT, DIRECT_AUTOCAD, ODA_TRANSFER, UNKNOWN]:
            engine = TamperingRuleEngine(tolerance_profile=profile)

            context = {
                "crc_validation": {
                    "is_valid": True,
                    "header_crc_stored": "0x00000000",
                    "header_crc_calculated": "0x00000000",
                    "is_revit_export": True,
                },
            }

            results = engine.evaluate_all(context)
            tamper_001 = next(r for r in results if r.rule_id == "TAMPER-001")

            # Must PASS for all profiles - Revit CRC=0 is normal
            assert tamper_001.status == RuleStatus.PASSED
            assert "Revit" in tamper_001.description or "OK" in tamper_001.description

    def test_future_timestamp_revit_tolerance(self):
        """
        TAMPER-006: Future timestamp check uses profile tolerance.
        Revit should allow 120 minutes grace period (2 hours).
        """
        engine = TamperingRuleEngine(tolerance_profile=REVIT_EXPORT)

        # Timestamp 90 minutes in future (within Revit's 120 min tolerance)
        now = datetime.now(timezone.utc)
        future_time = now + timedelta(minutes=90)

        context = {
            "metadata": {
                "modified_date": future_time.isoformat(),
            }
        }

        results = engine.evaluate_all(context)
        tamper_006 = next(r for r in results if r.rule_id == "TAMPER-006")

        # Should PASS with Revit profile (90 < 120 minutes)
        assert tamper_006.status == RuleStatus.PASSED
        assert "grace period" in tamper_006.description.lower()

    def test_future_timestamp_strict_autocad(self):
        """
        TAMPER-006: Future timestamp check strict for AutoCAD.
        Direct AutoCAD should only allow 2 minutes grace period.
        """
        engine = TamperingRuleEngine(tolerance_profile=DIRECT_AUTOCAD)

        # Timestamp 90 minutes in future (exceeds AutoCAD's 2 min tolerance)
        now = datetime.now(timezone.utc)
        future_time = now + timedelta(minutes=90)

        context = {
            "metadata": {
                "modified_date": future_time.isoformat(),
            }
        }

        results = engine.evaluate_all(context)
        tamper_006 = next(r for r in results if r.rule_id == "TAMPER-006")

        # Should FAIL with AutoCAD profile (90 > 2 minutes)
        assert tamper_006.status == RuleStatus.FAILED
        assert "future" in tamper_006.description.lower()

    def test_edit_time_revit_tolerance(self):
        """
        TAMPER-007: Edit time check uses profile percentage padding.
        Revit should allow 25% padding due to background processing.
        """
        engine = TamperingRuleEngine(tolerance_profile=REVIT_EXPORT)

        # Created 10 hours ago, edit time 12 hours (20% over span)
        created = datetime.now(timezone.utc) - timedelta(hours=10)
        modified = datetime.now(timezone.utc)

        context = {
            "metadata": {
                "created_date": created.isoformat(),
                "modified_date": modified.isoformat(),
                "total_editing_time_hours": 12.0,  # 20% over 10h span
            }
        }

        results = engine.evaluate_all(context)
        tamper_007 = next(r for r in results if r.rule_id == "TAMPER-007")

        # Should PASS with Revit (20% < 25% tolerance)
        assert tamper_007.status == RuleStatus.PASSED
        assert "consistent" in tamper_007.description.lower()

    def test_edit_time_strict_autocad(self):
        """
        TAMPER-007: Edit time check strict for AutoCAD.
        Direct AutoCAD should only allow 5% padding.
        """
        engine = TamperingRuleEngine(tolerance_profile=DIRECT_AUTOCAD)

        # Created 10 hours ago, edit time 12 hours (20% over span)
        created = datetime.now(timezone.utc) - timedelta(hours=10)
        modified = datetime.now(timezone.utc)

        context = {
            "metadata": {
                "created_date": created.isoformat(),
                "modified_date": modified.isoformat(),
                "total_editing_time_hours": 12.0,  # 20% over 10h span
            }
        }

        results = engine.evaluate_all(context)
        tamper_007 = next(r for r in results if r.rule_id == "TAMPER-007")

        # Should FAIL with AutoCAD (20% > 5% tolerance)
        assert tamper_007.status == RuleStatus.FAILED
        assert "exceeds" in tamper_007.description.lower()

    def test_unknown_profile_conservative_tolerance(self):
        """
        TAMPER-006/007: UNKNOWN profile uses moderate/conservative thresholds.
        Should be between strict AutoCAD and lenient Revit.
        """
        engine = TamperingRuleEngine(tolerance_profile=UNKNOWN)

        # Future timestamp 10 minutes (UNKNOWN: 15 min tolerance)
        now = datetime.now(timezone.utc)
        future_time = now + timedelta(minutes=10)

        context = {
            "metadata": {
                "modified_date": future_time.isoformat(),
            }
        }

        results = engine.evaluate_all(context)
        tamper_006 = next(r for r in results if r.rule_id == "TAMPER-006")

        # Should PASS with UNKNOWN (10 < 15 minutes)
        assert tamper_006.status == RuleStatus.PASSED

    def test_timestamp_reversal_remains_strict(self):
        """
        TAMPER-005: Timestamp reversal is a definitive smoking gun.
        Must remain STRICT across all profiles - no tolerance.
        """
        for profile in [REVIT_EXPORT, DIRECT_AUTOCAD, ODA_TRANSFER, UNKNOWN]:
            engine = TamperingRuleEngine(tolerance_profile=profile)

            # Created AFTER modified (impossible)
            now = datetime.now(timezone.utc)
            created = now
            modified = now - timedelta(hours=1)

            context = {
                "metadata": {
                    "created_date": created.isoformat(),
                    "modified_date": modified.isoformat(),
                }
            }

            results = engine.evaluate_all(context)
            tamper_005 = next(r for r in results if r.rule_id == "TAMPER-005")

            # Must FAIL for all profiles - timestamp reversal is DEFINITIVE
            assert tamper_005.status == RuleStatus.FAILED
            assert tamper_005.confidence == 1.0
            assert "after" in tamper_005.description.lower()
