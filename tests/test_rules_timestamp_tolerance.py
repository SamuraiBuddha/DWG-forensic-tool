"""
Tests for DWG Forensic Tool - Phase 2.3: Timestamp Rules Tolerance Integration

This test suite validates that TAMPER-013 to TAMPER-018 correctly use
provenance-aware tolerance profiles for advanced timestamp analysis.

Test Coverage:
1. TDINDWG (TAMPER-013) allows tolerance for Revit exports (zero is normal)
2. TDINDWG strict for native AutoCAD (smoking gun when exceeded)
3. Version anachronism remains strict (TAMPER-014)
4. Timezone checks remain strict (TAMPER-015)
5. Timer reset (TAMPER-017) adapts consistency threshold by profile
6. Revit allows higher timer variance (65% vs 85% for AutoCAD)
7. Network path leakage remains informational (TAMPER-018)
8. Educational watermark remains informational (TAMPER-016)
9. All timestamp smoking guns maintain 100% detection rate
10. False positive reduction for Revit timestamp variants

Phase 2.3 Success Criteria:
- 10 new tests passing
- TDINDWG tolerant for Revit (60%+ false positive reduction)
- Timer reset threshold adapts by profile
- Smoking gun timestamp rules remain strict
- No new false negatives
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


class TestTimestampRulesTolerance:
    """Test timestamp rules (TAMPER-013 to 018) with tolerance profiles."""

    def test_tdindwg_revit_tolerance(self):
        """
        TAMPER-013: TDINDWG check allows tolerance for Revit exports.
        Revit exports may have TDINDWG slightly exceeding calendar span
        due to background processing - this is normal, not tampering.
        """
        engine = TamperingRuleEngine(tolerance_profile=REVIT_EXPORT)

        # TDINDWG exceeds calendar span by 1 day (within Revit's 3-hour tolerance)
        context = {
            "timestamp_data": {
                "tdindwg": 10.05,  # days
                "calendar_span_days": 10.0,  # days (excess: 0.05 days = 1.2 hours)
            }
        }

        results = engine.evaluate_all(context)
        tamper_013 = next(r for r in results if r.rule_id == "TAMPER-013")

        # Should PASS with Revit (0.05 days < 0.125 days [3 hours tolerance])
        assert tamper_013.status == RuleStatus.PASSED
        assert "consistent" in tamper_013.description.lower()

    def test_tdindwg_strict_autocad(self):
        """
        TAMPER-013: TDINDWG check strict for native AutoCAD.
        Even small excesses should trigger failure for AutoCAD files.
        """
        engine = TamperingRuleEngine(tolerance_profile=DIRECT_AUTOCAD)

        # TDINDWG exceeds calendar span by 1 hour (exceeds AutoCAD's 5-min tolerance)
        context = {
            "timestamp_data": {
                "tdindwg": 10.05,  # days (excess: 0.05 days = 1.2 hours)
                "calendar_span_days": 10.0,  # days
            }
        }

        results = engine.evaluate_all(context)
        tamper_013 = next(r for r in results if r.rule_id == "TAMPER-013")

        # Should FAIL with AutoCAD (1.2 hours > 5 minutes tolerance)
        assert tamper_013.status == RuleStatus.FAILED
        assert "exceeds" in tamper_013.description.lower()

    def test_tdindwg_zero_revit_normal(self):
        """
        TAMPER-013: TDINDWG=0 is normal for Revit exports.
        Revit does not track editing time - TDINDWG=0 is expected.
        """
        engine = TamperingRuleEngine(tolerance_profile=REVIT_EXPORT)

        context = {
            "timestamp_data": {
                "tdindwg": 0.0,  # Zero editing time (normal for Revit)
                "calendar_span_days": 10.0,
            }
        }

        results = engine.evaluate_all(context)
        tamper_013 = next(r for r in results if r.rule_id == "TAMPER-013")

        # Should PASS - TDINDWG=0 does not exceed span
        assert tamper_013.status == RuleStatus.PASSED

    def test_version_anachronism_remains_strict(self):
        """
        TAMPER-014: Version anachronism is a definitive smoking gun.
        Must remain STRICT across all profiles - no tolerance.
        A file cannot claim creation before its version existed.
        """
        for profile in [REVIT_EXPORT, DIRECT_AUTOCAD, ODA_TRANSFER, UNKNOWN]:
            engine = TamperingRuleEngine(tolerance_profile=profile)

            # Simulate version anachronism via anomalies
            context = {
                "anomalies": [
                    {
                        "anomaly_type": "VERSION_ANACHRONISM",
                        "details": {
                            "version_name": "AutoCAD 2018",
                            "version_release_date": "2017-03-21",
                            "claimed_creation_date": "2015-01-01",
                        }
                    }
                ]
            }

            results = engine.evaluate_all(context)
            tamper_014 = next(r for r in results if r.rule_id == "TAMPER-014")

            # Must FAIL for all profiles - version anachronism is DEFINITIVE
            assert tamper_014.status == RuleStatus.FAILED
            assert tamper_014.confidence == 1.0
            assert "anachronism" in tamper_014.description.lower()

    def test_timezone_discrepancy_remains_strict(self):
        """
        TAMPER-015: Timezone discrepancy is a strong tampering indicator.
        Must remain STRICT across all profiles - timezone offsets have physical limits.
        """
        for profile in [REVIT_EXPORT, DIRECT_AUTOCAD, ODA_TRANSFER, UNKNOWN]:
            engine = TamperingRuleEngine(tolerance_profile=profile)

            # Invalid timezone offset (outside -12 to +14 hours)
            context = {
                "timestamp_data": {
                    "timezone_offset_hours": 20.0,  # Impossible offset
                }
            }

            results = engine.evaluate_all(context)
            tamper_015 = next(r for r in results if r.rule_id == "TAMPER-015")

            # Must FAIL for all profiles
            assert tamper_015.status == RuleStatus.FAILED
            assert "timezone" in tamper_015.description.lower()

    def test_timer_reset_revit_tolerance(self):
        """
        TAMPER-017: Timer reset check uses profile tolerance.
        Revit should allow larger discrepancies (65% threshold vs 85% for AutoCAD).
        """
        engine = TamperingRuleEngine(tolerance_profile=REVIT_EXPORT)

        # TDUSRTIMER is 70% of TDINDWG (within Revit's 65% threshold)
        context = {
            "timestamp_data": {
                "tdindwg": 10.0,  # days (240 hours)
                "tdusrtimer": 7.0,  # days (168 hours, 70% of TDINDWG)
            }
        }

        results = engine.evaluate_all(context)
        tamper_017 = next(r for r in results if r.rule_id == "TAMPER-017")

        # Should PASS with Revit (70% >= 65% threshold)
        assert tamper_017.status == RuleStatus.PASSED
        assert "consistent" in tamper_017.description.lower()

    def test_timer_reset_strict_autocad(self):
        """
        TAMPER-017: Timer reset check strict for AutoCAD.
        AutoCAD should enforce 85% consistency threshold.
        """
        engine = TamperingRuleEngine(tolerance_profile=DIRECT_AUTOCAD)

        # TDUSRTIMER is 70% of TDINDWG (below AutoCAD's 85% threshold)
        context = {
            "timestamp_data": {
                "tdindwg": 10.0,  # days
                "tdusrtimer": 7.0,  # days (70% of TDINDWG)
            }
        }

        results = engine.evaluate_all(context)
        tamper_017 = next(r for r in results if r.rule_id == "TAMPER-017")

        # Should FAIL with AutoCAD (70% < 85% threshold)
        assert tamper_017.status == RuleStatus.FAILED
        assert "reset" in tamper_017.description.lower()

    def test_timer_reset_minimal_editing_time(self):
        """
        TAMPER-017: Minimal editing time check adapts to profile.
        Files with very short editing times should pass regardless of timer mismatch.
        """
        for profile in [REVIT_EXPORT, DIRECT_AUTOCAD, UNKNOWN]:
            engine = TamperingRuleEngine(tolerance_profile=profile)

            # Very small TDINDWG (< threshold)
            context = {
                "timestamp_data": {
                    "tdindwg": 0.001,  # 0.024 hours (< 0.1 hour base threshold)
                    "tdusrtimer": 0.0,  # Even if zero, should pass
                }
            }

            results = engine.evaluate_all(context)
            tamper_017 = next(r for r in results if r.rule_id == "TAMPER-017")

            # Should PASS - editing time too small to be significant
            assert tamper_017.status == RuleStatus.PASSED
            assert "minimal" in tamper_017.description.lower()

    def test_educational_watermark_informational(self):
        """
        TAMPER-016: Educational watermark is informational, not tampering.
        Should be consistent across all profiles.
        """
        for profile in [REVIT_EXPORT, DIRECT_AUTOCAD, ODA_TRANSFER, UNKNOWN]:
            engine = TamperingRuleEngine(tolerance_profile=profile)

            context = {
                "timestamp_data": {
                    "educational_watermark": True,
                }
            }

            results = engine.evaluate_all(context)
            tamper_016 = next(r for r in results if r.rule_id == "TAMPER-016")

            # Should FAIL (informational flag) but confidence=1.0
            assert tamper_016.status == RuleStatus.FAILED
            assert tamper_016.confidence == 1.0
            assert "educational" in tamper_016.description.lower()

    def test_network_path_leakage_informational(self):
        """
        TAMPER-018: Network path leakage is informational forensic value.
        Should be consistent across all profiles.
        """
        for profile in [REVIT_EXPORT, DIRECT_AUTOCAD, ODA_TRANSFER, UNKNOWN]:
            engine = TamperingRuleEngine(tolerance_profile=profile)

            context = {
                "metadata": {
                    "network_paths_detected": [
                        "\\\\SERVER01\\shared\\project\\drawing.dwg",
                        "\\\\FILESERVER\\CAD\\library\\",
                    ]
                }
            }

            results = engine.evaluate_all(context)
            tamper_018 = next(r for r in results if r.rule_id == "TAMPER-018")

            # Should FAIL (informational flag) with confidence=1.0
            assert tamper_018.status == RuleStatus.FAILED
            assert tamper_018.confidence == 1.0
            assert "network" in tamper_018.description.lower() or "origin" in tamper_018.description.lower()
