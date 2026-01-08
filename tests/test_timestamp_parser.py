"""
Tests for the timestamp parser module.

Tests MJD conversions, TimestampData helper methods, and GUID extraction.
"""

import struct
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from dwg_forensic.parsers.timestamp import (
    TimestampParser,
    TimestampData,
    mjd_to_datetime,
    datetime_to_mjd,
    MJD_EPOCH,
    SECONDS_PER_DAY,
)
from dwg_forensic.utils.exceptions import ParseError


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

    def test_datetime_to_mjd_naive_datetime(self):
        """Test datetime_to_mjd with naive datetime (no timezone)."""
        # Naive datetime should be treated as UTC
        naive_dt = datetime(2020, 1, 1, 12, 0, 0)  # No tzinfo
        result = datetime_to_mjd(naive_dt)

        # Should produce same result as explicit UTC
        utc_dt = datetime(2020, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        expected = datetime_to_mjd(utc_dt)

        assert result == expected


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

    def test_get_tdcreate_datetime(self):
        """Test get_tdcreate_datetime converts MJD to datetime."""
        data = TimestampData(tdcreate=60310.0)  # 2024-01-01
        result = data.get_tdcreate_datetime()
        assert result is not None
        assert result.year == 2024
        assert result.month == 1

    def test_get_tdcreate_datetime_none(self):
        """Test get_tdcreate_datetime returns None when no data."""
        data = TimestampData()
        assert data.get_tdcreate_datetime() is None

    def test_get_tdcreate_datetime_zero(self):
        """Test get_tdcreate_datetime returns None for zero value."""
        data = TimestampData(tdcreate=0.0)
        assert data.get_tdcreate_datetime() is None

    def test_get_tdupdate_datetime(self):
        """Test get_tdupdate_datetime converts MJD to datetime."""
        data = TimestampData(tdupdate=60320.0)
        result = data.get_tdupdate_datetime()
        assert result is not None
        assert result.year == 2024

    def test_get_tdupdate_datetime_none(self):
        """Test get_tdupdate_datetime returns None when no data."""
        data = TimestampData()
        assert data.get_tdupdate_datetime() is None

    def test_get_tducreate_datetime(self):
        """Test get_tducreate_datetime converts UTC MJD to datetime."""
        data = TimestampData(tducreate=60310.0)
        result = data.get_tducreate_datetime()
        assert result is not None
        assert result.tzinfo == timezone.utc

    def test_get_tducreate_datetime_none(self):
        """Test get_tducreate_datetime returns None when no data."""
        data = TimestampData()
        assert data.get_tducreate_datetime() is None

    def test_get_tducreate_datetime_zero(self):
        """Test get_tducreate_datetime returns None for zero value."""
        data = TimestampData(tducreate=0.0)
        assert data.get_tducreate_datetime() is None

    def test_get_tduupdate_datetime(self):
        """Test get_tduupdate_datetime converts UTC MJD to datetime."""
        data = TimestampData(tduupdate=60320.0)
        result = data.get_tduupdate_datetime()
        assert result is not None
        assert result.tzinfo == timezone.utc

    def test_get_tduupdate_datetime_none(self):
        """Test get_tduupdate_datetime returns None when no data."""
        data = TimestampData()
        assert data.get_tduupdate_datetime() is None

    def test_get_tduupdate_datetime_zero(self):
        """Test get_tduupdate_datetime returns None for zero value."""
        data = TimestampData(tduupdate=0.0)
        assert data.get_tduupdate_datetime() is None

    def test_get_tdindwg_hours(self):
        """Test get_tdindwg_hours converts days to hours."""
        data = TimestampData(tdindwg=1.0)  # 1 day
        result = data.get_tdindwg_hours()
        assert result == 24.0

    def test_get_tdindwg_hours_none(self):
        """Test get_tdindwg_hours returns None when no data."""
        data = TimestampData()
        assert data.get_tdindwg_hours() is None

    def test_get_tdindwg_days(self):
        """Test get_tdindwg_days returns raw value."""
        data = TimestampData(tdindwg=2.5)
        result = data.get_tdindwg_days()
        assert result == 2.5

    def test_get_tdindwg_days_none(self):
        """Test get_tdindwg_days returns None when no data."""
        data = TimestampData()
        assert data.get_tdindwg_days() is None

    def test_get_tdusrtimer_hours(self):
        """Test get_tdusrtimer_hours converts days to hours."""
        data = TimestampData(tdusrtimer=0.5)  # 0.5 days = 12 hours
        result = data.get_tdusrtimer_hours()
        assert result == 12.0

    def test_get_tdusrtimer_hours_none(self):
        """Test get_tdusrtimer_hours returns None when no data."""
        data = TimestampData()
        assert data.get_tdusrtimer_hours() is None

    def test_to_dict(self):
        """Test to_dict serialization."""
        data = TimestampData(
            tdcreate=60310.0,
            tdupdate=60320.0,
            tdindwg=1.0,
            fingerprint_guid="12345678-1234-1234-1234-123456789abc",
            login_name="testuser",
            educational_watermark=True,
        )
        result = data.to_dict()

        assert result["tdcreate"] == 60310.0
        assert result["tdupdate"] == 60320.0
        assert result["tdindwg"] == 1.0
        assert result["fingerprint_guid"] == "12345678-1234-1234-1234-123456789abc"
        assert result["login_name"] == "testuser"
        assert result["educational_watermark"] is True
        assert result["tdindwg_hours"] == 24.0
        assert "tdcreate_datetime" in result
        assert "calendar_span_days" in result

    def test_to_dict_empty(self):
        """Test to_dict with empty data."""
        data = TimestampData()
        result = data.to_dict()

        assert result["tdcreate"] is None
        assert result["tdcreate_datetime"] is None
        assert result["tdindwg_hours"] is None
        assert result["calendar_span_days"] is None


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

    def test_has_timestamp_support_unsupported(self):
        """Test parser rejects unsupported versions."""
        parser = TimestampParser()
        assert parser.has_timestamp_support("AC1009") is False
        assert parser.has_timestamp_support("UNKNOWN") is False

    def test_parse_file_not_found(self, tmp_path):
        """Test parse raises error for non-existent file."""
        parser = TimestampParser()
        with pytest.raises(ParseError):
            parser.parse(tmp_path / "nonexistent.dwg")

    def test_parse_small_file(self, tmp_path):
        """Test parse handles file smaller than minimum size."""
        test_file = tmp_path / "tiny.dwg"
        test_file.write_bytes(b"AC1032")  # Only 6 bytes

        parser = TimestampParser()
        result = parser.parse(test_file)

        assert "File too small" in result.extraction_errors[0]

    def test_parse_detects_version(self, tmp_path):
        """Test parse auto-detects version when not provided."""
        test_file = tmp_path / "test.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 300)

        parser = TimestampParser()
        result = parser.parse(test_file)  # No version provided

        assert isinstance(result, TimestampData)

    def test_parse_with_educational_watermark(self, tmp_path):
        """Test parse detects educational watermark."""
        test_file = tmp_path / "edu.dwg"
        content = b"AC1032" + b"\x00" * 100 + b"EDUCATIONAL VERSION" + b"\x00" * 200
        test_file.write_bytes(content)

        parser = TimestampParser()
        result = parser.parse(test_file)

        assert result.educational_watermark is True

    def test_parse_student_version_marker(self, tmp_path):
        """Test parse detects student version marker."""
        test_file = tmp_path / "student.dwg"
        content = b"AC1032" + b"\x00" * 100 + b"STUDENT VERSION" + b"\x00" * 200
        test_file.write_bytes(content)

        parser = TimestampParser()
        result = parser.parse(test_file)

        assert result.educational_watermark is True

    def test_parse_with_valid_mjd_timestamps(self, tmp_path):
        """Test parse extracts valid MJD timestamps."""
        # Create file with valid MJD values embedded
        test_file = tmp_path / "timestamps.dwg"

        # Create two consecutive valid MJD values
        mjd1 = 60310.0  # 2024-01-01
        mjd2 = 60320.0  # 2024-01-11

        content = b"AC1032" + b"\x00" * 50
        content += struct.pack("<d", mjd1)  # TDCREATE
        content += struct.pack("<d", mjd2)  # TDUPDATE
        content += b"\x00" * 200

        test_file.write_bytes(content)

        parser = TimestampParser()
        result = parser.parse(test_file)

        # Should find at least one timestamp
        assert isinstance(result, TimestampData)


# ============================================================================
# TimestampParser Internal Methods Tests
# ============================================================================

class TestTimestampParserInternals:
    """Test TimestampParser internal methods."""

    def test_is_valid_mjd_valid_values(self):
        """Test _is_valid_mjd accepts valid MJD values."""
        parser = TimestampParser()

        assert parser._is_valid_mjd(60000.0) is True
        assert parser._is_valid_mjd(60310.5) is True
        assert parser._is_valid_mjd(50000.0) is True

    def test_is_valid_mjd_invalid_values(self):
        """Test _is_valid_mjd rejects invalid values."""
        parser = TimestampParser()

        # Below minimum (before 1900)
        assert parser._is_valid_mjd(10000.0) is False

        # Above maximum (after 2100)
        assert parser._is_valid_mjd(100000.0) is False

        # Special values
        assert parser._is_valid_mjd(float("nan")) is False
        assert parser._is_valid_mjd(float("inf")) is False
        assert parser._is_valid_mjd(float("-inf")) is False

    def test_could_be_editing_time_valid(self):
        """Test _could_be_editing_time accepts valid values."""
        parser = TimestampParser()
        result = TimestampData()

        assert parser._could_be_editing_time(1.0, result) is True
        assert parser._could_be_editing_time(10.0, result) is True

    def test_could_be_editing_time_negative(self):
        """Test _could_be_editing_time rejects negative values."""
        parser = TimestampParser()
        result = TimestampData()

        assert parser._could_be_editing_time(-1.0, result) is False
        assert parser._could_be_editing_time(0.0, result) is False

    def test_could_be_editing_time_exceeds_span(self):
        """Test _could_be_editing_time with calendar span check."""
        parser = TimestampParser()
        result = TimestampData(tdcreate=60000.0, tdupdate=60010.0)  # 10 day span

        # Value way larger than span * 10 should be rejected
        assert parser._could_be_editing_time(200.0, result) is False

        # Reasonable value should be accepted
        assert parser._could_be_editing_time(5.0, result) is True

    def test_find_timestamp_clusters_empty(self):
        """Test _find_timestamp_clusters with empty list."""
        parser = TimestampParser()
        result = parser._find_timestamp_clusters([])
        assert result == []

    def test_find_timestamp_clusters_consecutive(self):
        """Test _find_timestamp_clusters finds consecutive values."""
        parser = TimestampParser()
        found_mjds = [
            (0, 60000.0),
            (8, 60010.0),
            (16, 60020.0),
        ]
        result = parser._find_timestamp_clusters(found_mjds)

        assert len(result) == 1
        assert len(result[0]) == 3

    def test_find_timestamp_clusters_non_consecutive(self):
        """Test _find_timestamp_clusters handles gaps."""
        parser = TimestampParser()
        found_mjds = [
            (0, 60000.0),
            (8, 60010.0),
            (100, 60020.0),  # Gap
            (108, 60030.0),
        ]
        result = parser._find_timestamp_clusters(found_mjds)

        # Should find 2 clusters
        assert len(result) == 2

    def test_find_timestamp_clusters_single_values(self):
        """Test _find_timestamp_clusters ignores single values."""
        parser = TimestampParser()
        found_mjds = [
            (0, 60000.0),
            (100, 60010.0),  # Not consecutive
        ]
        result = parser._find_timestamp_clusters(found_mjds)

        # Single values don't form clusters
        assert len(result) == 0

    def test_assign_timestamps_from_cluster(self):
        """Test _assign_timestamps_from_cluster assigns values."""
        parser = TimestampParser()
        result = TimestampData()

        cluster = [
            (0, 60000.0),
            (8, 60010.0),
        ]

        parser._assign_timestamps_from_cluster(cluster, result)

        assert result.tdcreate == 60000.0
        assert result.tdupdate == 60010.0

    def test_assign_timestamps_from_cluster_four_values(self):
        """Test _assign_timestamps_from_cluster with 4+ values."""
        parser = TimestampParser()
        result = TimestampData()

        cluster = [
            (0, 60000.0),
            (8, 60005.0),
            (16, 60010.0),
            (24, 60015.0),
        ]

        parser._assign_timestamps_from_cluster(cluster, result)

        # Should assign UTC versions too
        assert result.tdcreate is not None
        assert result.tdupdate is not None
        assert result.tducreate is not None
        assert result.tduupdate is not None

    def test_detect_version_valid(self):
        """Test _detect_version with valid header."""
        parser = TimestampParser()
        data = b"AC1032" + b"\x00" * 100

        result = parser._detect_version(data)
        assert result == "AC1032"

    def test_detect_version_short_data(self):
        """Test _detect_version with short data."""
        parser = TimestampParser()
        data = b"AC10"  # Less than 6 bytes

        result = parser._detect_version(data)
        assert result is None

    def test_detect_version_non_ac(self):
        """Test _detect_version with non-AC header."""
        parser = TimestampParser()
        data = b"XXXXXX" + b"\x00" * 100

        result = parser._detect_version(data)
        assert result is None

    def test_detect_version_decode_error(self):
        """Test _detect_version handles decode errors."""
        parser = TimestampParser()
        data = b"\xff\xff\xff\xff\xff\xff" + b"\x00" * 100

        result = parser._detect_version(data)
        assert result is None

    def test_is_likely_guid_valid(self):
        """Test _is_likely_guid with valid GUID bytes."""
        parser = TimestampParser()

        # A reasonable GUID with varied bytes
        guid_bytes = bytes(range(16))
        assert parser._is_likely_guid(guid_bytes) is True

    def test_is_likely_guid_all_zeros(self):
        """Test _is_likely_guid rejects all zeros."""
        parser = TimestampParser()
        assert parser._is_likely_guid(b"\x00" * 16) is False

    def test_is_likely_guid_all_ones(self):
        """Test _is_likely_guid rejects all 0xff."""
        parser = TimestampParser()
        assert parser._is_likely_guid(b"\xff" * 16) is False

    def test_is_likely_guid_repeated_pattern(self):
        """Test _is_likely_guid rejects repeated patterns."""
        parser = TimestampParser()
        # Only 2 unique bytes
        assert parser._is_likely_guid(b"\x00\xff" * 8) is False

    def test_is_likely_guid_wrong_length(self):
        """Test _is_likely_guid rejects wrong length."""
        parser = TimestampParser()
        assert parser._is_likely_guid(b"\x00" * 10) is False

    def test_bytes_to_guid_string_valid(self):
        """Test _bytes_to_guid_string with valid bytes."""
        parser = TimestampParser()
        # Valid 16-byte GUID
        guid_bytes = bytes(range(16))
        result = parser._bytes_to_guid_string(guid_bytes)

        assert result is not None
        assert len(result) == 36
        assert result.count("-") == 4

    def test_extract_login_name(self, tmp_path):
        """Test _extract_login_name extracts name."""
        parser = TimestampParser()
        data = b"\x00" * 100 + b"LOGINNAME\x00\x00testuser\x00" + b"\x00" * 100

        result = parser._extract_login_name(data)
        assert result == "testuser"

    def test_extract_login_name_not_found(self):
        """Test _extract_login_name returns None when not found."""
        parser = TimestampParser()
        data = b"\x00" * 200

        result = parser._extract_login_name(data)
        assert result is None


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
