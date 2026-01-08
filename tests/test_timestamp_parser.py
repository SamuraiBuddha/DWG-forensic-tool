"""
Tests for the timestamp parser module.

Tests MJD conversions, TimestampData helper methods, and GUID extraction.
"""

import pytest
from datetime import datetime, timezone
from pathlib import Path

from dwg_forensic.parsers.timestamp import (
    TimestampParser,
    TimestampData,
    mjd_to_datetime,
    datetime_to_mjd,
    MJD_EPOCH,
)


# ============================================================================
# MJD Conversion Tests
# ============================================================================

class TestMJDConversion:
    """Test Modified Julian Date conversion functions."""

    def test_mjd_epoch_constant(self):
        """Test MJD epoch is November 17, 1858."""
        assert MJD_EPOCH == datetime(1858, 11, 17, tzinfo=timezone.utc)

    def test_mjd_to_datetime_zero(self):
        """Test MJD 0 converts to epoch date."""
        result = mjd_to_datetime(0.0)
        expected = datetime(1858, 11, 17, tzinfo=timezone.utc)
        assert result == expected

    def test_mjd_to_datetime_known_date(self):
        """Test MJD conversion for a known date (2024-01-01)."""
        # 2024-01-01 00:00 UTC is MJD 60310
        result = mjd_to_datetime(60310.0)
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 1
        assert result.tzinfo == timezone.utc

    def test_mjd_to_datetime_with_fraction(self):
        """Test MJD conversion with fractional day (time component)."""
        # MJD 60310.5 = 2024-01-01 12:00 UTC
        result = mjd_to_datetime(60310.5)
        assert result.hour == 12
        assert result.minute == 0

    def test_datetime_to_mjd_epoch(self):
        """Test epoch date converts to MJD 0."""
        epoch = datetime(1858, 11, 17, tzinfo=timezone.utc)
        result = datetime_to_mjd(epoch)
        assert result == 0.0

    def test_datetime_to_mjd_known_date(self):
        """Test datetime conversion for a known date."""
        dt = datetime(2024, 1, 1, tzinfo=timezone.utc)
        result = datetime_to_mjd(dt)
        assert 60309 < result < 60311  # Within 1 day of expected

    def test_mjd_round_trip(self):
        """Test MJD conversion round-trip preserves date."""
        original = datetime(2020, 6, 15, 14, 30, 45, tzinfo=timezone.utc)
        mjd = datetime_to_mjd(original)
        recovered = mjd_to_datetime(mjd)

        # Should match within 1 second (floating point precision)
        diff = abs((original - recovered).total_seconds())
        assert diff < 1

    def test_mjd_to_datetime_negative_returns_epoch(self):
        """Test negative MJD values return epoch date."""
        result = mjd_to_datetime(-1.0)
        assert result == MJD_EPOCH

    def test_datetime_to_mjd_before_epoch_returns_negative(self):
        """Test dates before MJD epoch return negative value."""
        ancient = datetime(1800, 1, 1, tzinfo=timezone.utc)
        result = datetime_to_mjd(ancient)
        assert result < 0


# ============================================================================
# TimestampData Tests
# ============================================================================

class TestTimestampData:
    """Test TimestampData dataclass and helper methods."""

    def test_default_values(self):
        """Test TimestampData default values."""
        data = TimestampData()
        assert data.tdcreate is None
        assert data.tdupdate is None
        assert data.tducreate is None
        assert data.tduupdate is None
        assert data.tdindwg is None
        assert data.tdusrtimer is None
        assert data.fingerprint_guid is None
        assert data.version_guid is None
        assert data.login_name is None
        assert data.educational_watermark is False

    def test_calendar_span_days_basic(self):
        """Test get_calendar_span_days with valid data."""
        data = TimestampData(
            tdcreate=60000.0,  # Some base date
            tdupdate=60010.0,  # 10 days later
        )
        span = data.get_calendar_span_days()
        assert span == 10.0

    def test_calendar_span_days_none_without_dates(self):
        """Test get_calendar_span_days returns None without dates."""
        data = TimestampData()
        assert data.get_calendar_span_days() is None

        data2 = TimestampData(tdcreate=60000.0)
        assert data2.get_calendar_span_days() is None

    def test_timezone_offset_hours_basic(self):
        """Test get_timezone_offset_hours with valid data."""
        # TDCREATE is local time, TDUCREATE is UTC
        # If local is +5 hours from UTC, offset should be 5
        data = TimestampData(
            tdcreate=60000.5,  # Local: noon (0.5 day)
            tducreate=60000.2917,  # UTC: 7am (0.2917 day = 7/24)
        )
        offset = data.get_timezone_offset_hours()
        # 0.5 - 0.2917 = 0.2083 days = 5 hours
        assert offset is not None
        assert 4.9 < offset < 5.1

    def test_timezone_offset_hours_none_without_data(self):
        """Test get_timezone_offset_hours returns None without data."""
        data = TimestampData()
        assert data.get_timezone_offset_hours() is None

        data2 = TimestampData(tdcreate=60000.0)
        assert data2.get_timezone_offset_hours() is None

    def test_extraction_success_true(self):
        """Test extraction_success is True with valid data."""
        data = TimestampData(
            tdcreate=60000.0,
            tdupdate=60010.0,
            extraction_success=True,
        )
        assert data.extraction_success is True

    def test_extraction_success_false(self):
        """Test extraction_success defaults to False."""
        data = TimestampData()
        assert data.extraction_success is False


# ============================================================================
# TimestampParser Tests
# ============================================================================

class TestTimestampParser:
    """Test TimestampParser class."""

    def test_init_creates_instance(self):
        """Test TimestampParser can be initialized."""
        parser = TimestampParser()
        assert parser is not None

    def test_parse_returns_timestamp_data(self, tmp_path):
        """Test parse returns TimestampData object."""
        # Create a minimal DWG-like file
        test_file = tmp_path / "test.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)

        parser = TimestampParser()
        result = parser.parse(test_file, "AC1032")

        assert isinstance(result, TimestampData)

    def test_parse_empty_file_returns_empty_data(self, tmp_path):
        """Test parsing empty file returns empty TimestampData."""
        test_file = tmp_path / "empty.dwg"
        test_file.write_bytes(b"")

        parser = TimestampParser()
        result = parser.parse(test_file, "AC1032")

        assert isinstance(result, TimestampData)
        assert result.tdcreate is None

    def test_has_timestamp_support(self):
        """Test parser supports expected versions."""
        parser = TimestampParser()

        # Should support R18+ versions
        assert parser.has_timestamp_support("AC1024")
        assert parser.has_timestamp_support("AC1027")
        assert parser.has_timestamp_support("AC1032")

        # Also supports older 2000-series versions
        assert parser.has_timestamp_support("AC1015")
        assert parser.has_timestamp_support("AC1018")
        assert parser.has_timestamp_support("AC1021")


# ============================================================================
# GUID Extraction Tests
# ============================================================================

class TestGUIDExtraction:
    """Test GUID extraction from TimestampData."""

    def test_fingerprint_guid_format(self):
        """Test FINGERPRINTGUID is in correct format."""
        data = TimestampData(
            fingerprint_guid="12345678-1234-1234-1234-123456789ABC"
        )
        assert len(data.fingerprint_guid) == 36
        assert data.fingerprint_guid.count("-") == 4

    def test_version_guid_format(self):
        """Test VERSIONGUID is in correct format."""
        data = TimestampData(
            version_guid="ABCDEF01-2345-6789-ABCD-EF0123456789"
        )
        assert len(data.version_guid) == 36
        assert data.version_guid.count("-") == 4

    def test_guids_can_be_none(self):
        """Test GUIDs default to None."""
        data = TimestampData()
        assert data.fingerprint_guid is None
        assert data.version_guid is None


# ============================================================================
# Integration Tests
# ============================================================================

class TestTimestampParserIntegration:
    """Integration tests for timestamp parsing."""

    @pytest.fixture
    def sample_dwg_file(self, tmp_path):
        """Create a sample DWG file for testing."""
        # Create minimal valid DWG header structure
        header = b"AC1032"
        padding = b"\x00" * 500
        file_path = tmp_path / "sample.dwg"
        file_path.write_bytes(header + padding)
        return file_path

    def test_full_parse_workflow(self, sample_dwg_file):
        """Test complete timestamp parsing workflow."""
        parser = TimestampParser()
        result = parser.parse(sample_dwg_file, "AC1032")

        # Should return valid TimestampData
        assert isinstance(result, TimestampData)

        # Should be able to get calendar span (may be None for synthetic files)
        span = result.get_calendar_span_days()
        # Span is None or a number
        assert span is None or isinstance(span, float)

        # Should be able to get timezone offset
        offset = result.get_timezone_offset_hours()
        assert offset is None or isinstance(offset, float)
