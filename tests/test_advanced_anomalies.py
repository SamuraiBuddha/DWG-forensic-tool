"""
Tests for advanced timestamp anomaly detection.

Tests TDINDWG exceeds span detection, version anachronism detection,
timezone discrepancy detection, and educational watermark detection.
"""

import pytest
from datetime import datetime, timezone
from pathlib import Path

from dwg_forensic.analysis.anomaly import AnomalyDetector
from dwg_forensic.parsers.timestamp import TimestampData
from dwg_forensic.models import AnomalyType, RiskLevel, DWGMetadata


# ============================================================================
# TDINDWG Detection Tests
# ============================================================================

class TestTDINDWGAnomalies:
    """Test TDINDWG (cumulative editing time) anomaly detection."""

    @pytest.fixture
    def detector(self):
        """Create anomaly detector instance."""
        return AnomalyDetector()

    def test_tdindwg_exceeds_span_detected(self, detector):
        """Test detection when TDINDWG exceeds calendar span."""
        # 5 days of editing but only 2 days elapsed
        data = TimestampData(
            tdcreate=60000.0,
            tdupdate=60002.0,  # 2 days later
            tdindwg=5.0,       # 5 days of editing time
        )

        anomalies = detector.detect_tdindwg_anomalies(data)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == AnomalyType.TDINDWG_EXCEEDS_SPAN
        assert anomalies[0].severity == RiskLevel.CRITICAL

    def test_tdindwg_valid_no_anomaly(self, detector):
        """Test no anomaly when TDINDWG is valid."""
        # 1 day of editing within 10 day span
        data = TimestampData(
            tdcreate=60000.0,
            tdupdate=60010.0,  # 10 days later
            tdindwg=1.0,       # 1 day of editing (reasonable)
        )

        anomalies = detector.detect_tdindwg_anomalies(data)

        assert len(anomalies) == 0

    def test_tdindwg_none_no_anomaly(self, detector):
        """Test no anomaly when TDINDWG is None."""
        data = TimestampData(
            tdcreate=60000.0,
            tdupdate=60010.0,
        )

        anomalies = detector.detect_tdindwg_anomalies(data)

        assert len(anomalies) == 0

    def test_tdindwg_equal_to_span_no_anomaly(self, detector):
        """Test no anomaly when TDINDWG equals calendar span."""
        # Exactly 5 days of editing in 5 day span (maximum possible)
        data = TimestampData(
            tdcreate=60000.0,
            tdupdate=60005.0,
            tdindwg=5.0,
        )

        anomalies = detector.detect_tdindwg_anomalies(data)

        assert len(anomalies) == 0


# ============================================================================
# Version Anachronism Tests
# ============================================================================

class TestVersionAnachronism:
    """Test version anachronism detection."""

    @pytest.fixture
    def detector(self):
        """Create anomaly detector instance."""
        return AnomalyDetector()

    def test_anachronism_detected(self, detector):
        """Test detection when file claims creation before version existed."""
        # AC1024 (AutoCAD 2010) was released March 2009
        # MJD for Jan 1, 2008 = ~54466
        from dwg_forensic.parsers.timestamp import datetime_to_mjd

        date_2008 = datetime(2008, 1, 1, tzinfo=timezone.utc)
        mjd_2008 = datetime_to_mjd(date_2008)

        data = TimestampData(tdcreate=mjd_2008)

        anomalies = detector.detect_version_anachronism("AC1024", data)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == AnomalyType.VERSION_ANACHRONISM
        assert anomalies[0].severity == RiskLevel.CRITICAL

    def test_no_anachronism_valid_date(self, detector):
        """Test no anomaly when creation date is after version release."""
        # AC1024 was released March 2009, use date from 2015
        from dwg_forensic.parsers.timestamp import datetime_to_mjd

        date_2015 = datetime(2015, 6, 15, tzinfo=timezone.utc)
        mjd_2015 = datetime_to_mjd(date_2015)

        data = TimestampData(tdcreate=mjd_2015)

        anomalies = detector.detect_version_anachronism("AC1024", data)

        assert len(anomalies) == 0

    def test_no_tdcreate_no_anomaly(self, detector):
        """Test no anomaly when TDCREATE is None."""
        data = TimestampData()

        anomalies = detector.detect_version_anachronism("AC1024", data)

        assert len(anomalies) == 0

    def test_unknown_version_no_anomaly(self, detector):
        """Test no anomaly for unknown version."""
        from dwg_forensic.parsers.timestamp import datetime_to_mjd

        date_2008 = datetime(2008, 1, 1, tzinfo=timezone.utc)
        mjd_2008 = datetime_to_mjd(date_2008)

        data = TimestampData(tdcreate=mjd_2008)

        # Unknown version should not raise or detect anomaly
        anomalies = detector.detect_version_anachronism("AC9999", data)

        assert len(anomalies) == 0


# ============================================================================
# Timezone Discrepancy Tests
# ============================================================================

class TestTimezoneDiscrepancy:
    """Test timezone discrepancy detection."""

    @pytest.fixture
    def detector(self):
        """Create anomaly detector instance."""
        return AnomalyDetector()

    def test_invalid_timezone_offset_detected(self, detector):
        """Test detection of invalid timezone offset."""
        # Create data with impossible timezone offset (+20 hours)
        data = TimestampData(
            tdcreate=60000.0 + 0.5,       # Local: noon
            tducreate=60000.0 - (8/24),   # UTC: 8 hours earlier (impossible)
        )

        anomalies = detector.detect_timezone_discrepancy(data)

        # Should detect HIGH severity anomaly
        assert len(anomalies) >= 1
        high_severity = [a for a in anomalies if a.severity == RiskLevel.HIGH]
        assert len(high_severity) >= 1

    def test_valid_timezone_no_anomaly(self, detector):
        """Test no anomaly with valid timezone offset."""
        # +5 hour offset (valid timezone)
        data = TimestampData(
            tdcreate=60000.5,             # Local: noon
            tducreate=60000.5 - (5/24),   # UTC: 5 hours earlier
        )

        anomalies = detector.detect_timezone_discrepancy(data)

        # Should not detect invalid timezone offset
        high_severity = [a for a in anomalies
                        if a.anomaly_type == AnomalyType.TIMEZONE_DISCREPANCY
                        and a.severity == RiskLevel.HIGH]
        assert len(high_severity) == 0

    def test_no_data_no_anomaly(self, detector):
        """Test no anomaly when timezone data is missing."""
        data = TimestampData()

        anomalies = detector.detect_timezone_discrepancy(data)

        assert len(anomalies) == 0


# ============================================================================
# Timestamp Precision Tests
# ============================================================================

class TestTimestampPrecision:
    """Test timestamp precision anomaly detection."""

    @pytest.fixture
    def detector(self):
        """Create anomaly detector instance."""
        return AnomalyDetector()

    def test_midnight_timestamp_detected(self, detector):
        """Test detection of exactly midnight creation time."""
        data = TimestampData(
            tdcreate=60000.0,  # Exactly midnight (no fractional day)
        )

        anomalies = detector.detect_timestamp_precision_anomaly(data)

        assert len(anomalies) >= 1
        assert anomalies[0].anomaly_type == AnomalyType.TIMESTAMP_PRECISION_ANOMALY
        assert anomalies[0].severity == RiskLevel.LOW

    def test_zero_editing_time_detected(self, detector):
        """Test detection of zero editing time with different dates."""
        data = TimestampData(
            tdcreate=60000.5,
            tdupdate=60010.5,  # Different from create
            tdindwg=0.0,       # Zero editing time (suspicious)
        )

        anomalies = detector.detect_timestamp_precision_anomaly(data)

        # Should detect the zero editing time anomaly
        zero_edit_anomalies = [a for a in anomalies
                               if "Zero editing time" in a.description]
        assert len(zero_edit_anomalies) >= 1

    def test_normal_timestamp_no_anomaly(self, detector):
        """Test no anomaly for normal timestamps."""
        data = TimestampData(
            tdcreate=60000.4321,  # Not exactly midnight
            tdupdate=60010.5678,
            tdindwg=2.5,          # Reasonable editing time
        )

        anomalies = detector.detect_timestamp_precision_anomaly(data)

        # Should not detect midnight or zero editing anomalies
        assert len(anomalies) == 0


# ============================================================================
# Educational Watermark Tests
# ============================================================================

class TestEducationalWatermark:
    """Test educational watermark detection."""

    @pytest.fixture
    def detector(self):
        """Create anomaly detector instance."""
        return AnomalyDetector()

    def test_educational_watermark_detected(self, detector):
        """Test detection of educational version watermark."""
        data = TimestampData(educational_watermark=True)

        anomalies = detector.detect_educational_watermark(data)

        assert len(anomalies) == 1
        assert anomalies[0].severity == RiskLevel.MEDIUM
        assert "Educational" in anomalies[0].description

    def test_no_educational_watermark(self, detector):
        """Test no anomaly when no educational watermark."""
        data = TimestampData(educational_watermark=False)

        anomalies = detector.detect_educational_watermark(data)

        assert len(anomalies) == 0


# ============================================================================
# Orchestrator Tests
# ============================================================================

class TestAdvancedTimestampAnomalies:
    """Test the orchestrator method that runs all detectors."""

    @pytest.fixture
    def detector(self):
        """Create anomaly detector instance."""
        return AnomalyDetector()

    def test_runs_all_detectors(self, detector):
        """Test orchestrator runs all detection methods."""
        from dwg_forensic.parsers.timestamp import datetime_to_mjd

        # Create data that triggers multiple anomalies
        date_2008 = datetime(2008, 1, 1, tzinfo=timezone.utc)
        data = TimestampData(
            tdcreate=datetime_to_mjd(date_2008),  # Anachronism for AC1024
            tdupdate=datetime_to_mjd(date_2008) + 2,
            tdindwg=5.0,  # Exceeds span (5 days > 2 days)
            educational_watermark=True,
        )

        anomalies = detector.detect_advanced_timestamp_anomalies(
            "AC1024", data
        )

        # Should detect multiple anomalies
        assert len(anomalies) >= 2

        # Check specific anomaly types are present
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.TDINDWG_EXCEEDS_SPAN in types
        assert AnomalyType.VERSION_ANACHRONISM in types

    def test_clean_file_no_anomalies(self, detector):
        """Test clean file produces no advanced anomalies."""
        from dwg_forensic.parsers.timestamp import datetime_to_mjd

        # Create data that is completely valid
        date_2015 = datetime(2015, 6, 15, 10, 30, tzinfo=timezone.utc)
        data = TimestampData(
            tdcreate=datetime_to_mjd(date_2015),
            tdupdate=datetime_to_mjd(date_2015) + 30,  # 30 days later
            tducreate=datetime_to_mjd(date_2015) - (5/24),  # Valid UTC
            tdindwg=10.0,  # 10 days editing in 30 day span
            educational_watermark=False,
        )

        anomalies = detector.detect_advanced_timestamp_anomalies(
            "AC1024", data
        )

        # Should have minimal anomalies (possibly none)
        critical = [a for a in anomalies if a.severity == RiskLevel.CRITICAL]
        assert len(critical) == 0


# ============================================================================
# Version Dates Module Tests
# ============================================================================

class TestVersionDates:
    """Test version release date mapping functions."""

    def test_get_version_release_date(self):
        """Test getting version release dates."""
        from dwg_forensic.analysis.version_dates import get_version_release_date

        date = get_version_release_date("AC1024")
        assert date is not None
        assert date.year == 2009
        assert date.month == 3

    def test_get_version_name(self):
        """Test getting version names."""
        from dwg_forensic.analysis.version_dates import get_version_name

        name = get_version_name("AC1024")
        assert "2010" in name or "AutoCAD" in name

    def test_is_date_before_version_release(self):
        """Test checking if date is before version release."""
        from dwg_forensic.analysis.version_dates import is_date_before_version_release

        # 2008 is before AC1024 release (March 2009)
        date_2008 = datetime(2008, 1, 1, tzinfo=timezone.utc)
        assert is_date_before_version_release("AC1024", date_2008) is True

        # 2015 is after AC1024 release
        date_2015 = datetime(2015, 1, 1, tzinfo=timezone.utc)
        assert is_date_before_version_release("AC1024", date_2015) is False

    def test_could_file_exist_at_date(self):
        """Test checking if file could exist at date."""
        from dwg_forensic.analysis.version_dates import could_file_exist_at_date

        # AC1024 file could not exist in 2008
        date_2008 = datetime(2008, 1, 1, tzinfo=timezone.utc)
        possible, explanation = could_file_exist_at_date("AC1024", date_2008)
        assert possible is False
        assert "[FAIL]" in explanation

        # AC1024 file could exist in 2015
        date_2015 = datetime(2015, 1, 1, tzinfo=timezone.utc)
        possible, explanation = could_file_exist_at_date("AC1024", date_2015)
        assert possible is True
        assert "[OK]" in explanation

    def test_get_version_release_date_unknown(self):
        """Test get_version_release_date returns None for unknown version."""
        from dwg_forensic.analysis.version_dates import get_version_release_date

        result = get_version_release_date("AC9999")
        assert result is None

    def test_get_version_name_unknown(self):
        """Test get_version_name returns formatted unknown for unknown version."""
        from dwg_forensic.analysis.version_dates import get_version_name

        name = get_version_name("AC9999")
        assert "Unknown" in name
        assert "AC9999" in name

    def test_get_version_span(self):
        """Test get_version_span returns correct span."""
        from dwg_forensic.analysis.version_dates import get_version_span

        span = get_version_span("AC1024")
        assert span is not None
        start, end = span
        assert start.year == 2009
        assert end.year == 2012

    def test_get_version_span_unknown(self):
        """Test get_version_span returns None for unknown version."""
        from dwg_forensic.analysis.version_dates import get_version_span

        span = get_version_span("AC9999")
        assert span is None

    def test_is_date_before_version_release_naive_datetime(self):
        """Test is_date_before_version_release with naive datetime."""
        from dwg_forensic.analysis.version_dates import is_date_before_version_release

        # Naive datetime (no timezone)
        date_2008 = datetime(2008, 1, 1)
        assert is_date_before_version_release("AC1024", date_2008) is True

    def test_is_date_before_version_release_unknown_version(self):
        """Test is_date_before_version_release with unknown version returns False."""
        from dwg_forensic.analysis.version_dates import is_date_before_version_release

        date_2008 = datetime(2008, 1, 1, tzinfo=timezone.utc)
        # Unknown version should return False (cannot determine)
        assert is_date_before_version_release("AC9999", date_2008) is False

    def test_get_anachronism_details(self):
        """Test get_anachronism_details returns details for anachronism."""
        from dwg_forensic.analysis.version_dates import get_anachronism_details

        date_2008 = datetime(2008, 1, 1, tzinfo=timezone.utc)
        details = get_anachronism_details("AC1024", date_2008)

        assert details is not None
        assert details["version_string"] == "AC1024"
        assert "2010" in details["version_name"]
        assert details["days_before_release"] > 0

    def test_get_anachronism_details_no_anachronism(self):
        """Test get_anachronism_details returns None when no anachronism."""
        from dwg_forensic.analysis.version_dates import get_anachronism_details

        date_2015 = datetime(2015, 1, 1, tzinfo=timezone.utc)
        details = get_anachronism_details("AC1024", date_2015)

        assert details is None

    def test_get_anachronism_details_naive_datetime(self):
        """Test get_anachronism_details with naive datetime."""
        from dwg_forensic.analysis.version_dates import get_anachronism_details

        # Naive datetime
        date_2008 = datetime(2008, 1, 1)
        details = get_anachronism_details("AC1024", date_2008)

        assert details is not None
        assert details["days_before_release"] > 0

    def test_could_file_exist_at_date_unknown_version(self):
        """Test could_file_exist_at_date with unknown version."""
        from dwg_forensic.analysis.version_dates import could_file_exist_at_date

        date = datetime(2015, 1, 1, tzinfo=timezone.utc)
        possible, explanation = could_file_exist_at_date("AC9999", date)

        assert possible is True
        assert "Unknown" in explanation or "cannot verify" in explanation

    def test_could_file_exist_at_date_naive_datetime(self):
        """Test could_file_exist_at_date with naive datetime."""
        from dwg_forensic.analysis.version_dates import could_file_exist_at_date

        # Naive datetime
        date_2008 = datetime(2008, 1, 1)
        possible, explanation = could_file_exist_at_date("AC1024", date_2008)

        assert possible is False
        assert "[FAIL]" in explanation

    def test_get_expected_version_for_date(self):
        """Test get_expected_version_for_date returns correct version."""
        from dwg_forensic.analysis.version_dates import get_expected_version_for_date

        # Date in 2010 should return AC1024
        date_2010 = datetime(2010, 6, 1, tzinfo=timezone.utc)
        version = get_expected_version_for_date(date_2010)
        assert version == "AC1024"

        # Date in 2015 should return AC1027
        date_2015 = datetime(2015, 6, 1, tzinfo=timezone.utc)
        version = get_expected_version_for_date(date_2015)
        assert version == "AC1027"

        # Date in 2020 should return AC1032
        date_2020 = datetime(2020, 6, 1, tzinfo=timezone.utc)
        version = get_expected_version_for_date(date_2020)
        assert version == "AC1032"

    def test_get_expected_version_for_date_naive_datetime(self):
        """Test get_expected_version_for_date with naive datetime."""
        from dwg_forensic.analysis.version_dates import get_expected_version_for_date

        # Naive datetime
        date_2010 = datetime(2010, 6, 1)
        version = get_expected_version_for_date(date_2010)
        assert version == "AC1024"

    def test_get_expected_version_for_date_before_dwg(self):
        """Test get_expected_version_for_date for date before DWG format."""
        from dwg_forensic.analysis.version_dates import get_expected_version_for_date

        # Date before any DWG version existed
        date_1980 = datetime(1980, 1, 1, tzinfo=timezone.utc)
        version = get_expected_version_for_date(date_1980)
        assert version is None
