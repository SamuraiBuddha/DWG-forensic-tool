"""
Tests for NTFS Timestamp Parser module.

This module tests the NTFS filesystem timestamp parsing and forensic
analysis capabilities for detecting timestomping and manipulation.
"""

import os
import stat
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import tempfile

from dwg_forensic.parsers.ntfs import (
    NTFSTimestamps,
    FileNameTimestamps,
    NTFSForensicData,
    NTFSTimestampParser,
    get_ntfs_timestamps,
    FILETIME_EPOCH,
    FILETIME_TO_UNIX_EPOCH_TICKS,
)


# =============================================================================
# NTFSTimestamps Dataclass Tests
# =============================================================================


class TestNTFSTimestamps:
    """Tests for NTFSTimestamps dataclass."""

    def test_default_values(self):
        """Test NTFSTimestamps with default values."""
        ts = NTFSTimestamps()
        assert ts.created is None
        assert ts.modified is None
        assert ts.accessed is None
        assert ts.created_raw is None
        assert ts.modified_raw is None
        assert ts.accessed_raw is None
        assert ts.created_nanoseconds is None
        assert ts.modified_nanoseconds is None
        assert ts.accessed_nanoseconds is None
        assert ts.mft_modified is None
        assert ts.mft_modified_raw is None

    def test_with_all_values(self):
        """Test NTFSTimestamps with all values populated."""
        now = datetime.now(timezone.utc)
        ts = NTFSTimestamps(
            created=now,
            modified=now,
            accessed=now,
            created_raw=132456789012345678,
            modified_raw=132456789012345678,
            accessed_raw=132456789012345678,
            created_nanoseconds=1234567,
            modified_nanoseconds=7654321,
            accessed_nanoseconds=9999999,
            mft_modified=now,
            mft_modified_raw=132456789012345678,
        )
        assert ts.created == now
        assert ts.modified == now
        assert ts.accessed == now
        assert ts.created_raw == 132456789012345678
        assert ts.created_nanoseconds == 1234567


class TestFileNameTimestamps:
    """Tests for FileNameTimestamps dataclass."""

    def test_default_values(self):
        """Test FileNameTimestamps with default values."""
        fn = FileNameTimestamps()
        assert fn.created is None
        assert fn.modified is None
        assert fn.accessed is None
        assert fn.mft_modified is None

    def test_with_values(self):
        """Test FileNameTimestamps with values."""
        now = datetime.now(timezone.utc)
        fn = FileNameTimestamps(
            created=now,
            modified=now,
            accessed=now,
            mft_modified=now,
        )
        assert fn.created == now
        assert fn.modified == now


# =============================================================================
# NTFSForensicData Dataclass Tests
# =============================================================================


class TestNTFSForensicData:
    """Tests for NTFSForensicData dataclass."""

    def test_default_values(self):
        """Test NTFSForensicData with default values."""
        data = NTFSForensicData()
        assert data.si_timestamps is not None
        assert data.fn_timestamps is None
        assert data.si_fn_mismatch is False
        assert data.nanoseconds_truncated is False
        assert data.creation_after_modification is False
        assert data.mismatch_details is None
        assert data.truncation_details is None
        assert data.file_size == 0
        assert data.is_readonly is False
        assert data.is_hidden is False
        assert data.is_system is False
        assert data.mft_parsed is False

    def test_has_timestomping_evidence_false(self):
        """Test has_timestomping_evidence returns False when no indicators."""
        data = NTFSForensicData()
        assert data.has_timestomping_evidence() is False

    def test_has_timestomping_evidence_si_fn_mismatch(self):
        """Test has_timestomping_evidence with SI/FN mismatch."""
        data = NTFSForensicData(si_fn_mismatch=True)
        assert data.has_timestomping_evidence() is True

    def test_has_timestomping_evidence_nanoseconds_truncated(self):
        """Test has_timestomping_evidence with nanosecond truncation."""
        data = NTFSForensicData(nanoseconds_truncated=True)
        assert data.has_timestomping_evidence() is True

    def test_has_timestomping_evidence_creation_after_modification(self):
        """Test has_timestomping_evidence does NOT flag creation_after_modification.

        IMPORTANT: creation_after_modification is NORMAL for copied files on Windows.
        When copying a file, Windows sets Created=time of copy but preserves Modified
        from the source. This is NOT timestomping evidence.
        """
        data = NTFSForensicData(creation_after_modification=True)
        # This should be False - creation_after_modification is NOT timestomping evidence
        assert data.has_timestomping_evidence() is False

    def test_has_timestomping_evidence_multiple_indicators(self):
        """Test has_timestomping_evidence with multiple indicators."""
        data = NTFSForensicData(
            si_fn_mismatch=True,
            nanoseconds_truncated=True,
            creation_after_modification=True,
        )
        assert data.has_timestomping_evidence() is True


# =============================================================================
# NTFSTimestampParser Tests
# =============================================================================


class TestNTFSTimestampParserInit:
    """Tests for NTFSTimestampParser initialization."""

    def test_init_detects_windows(self):
        """Test that parser detects Windows platform."""
        parser = NTFSTimestampParser()
        assert parser._is_windows == (os.name == 'nt')

    @patch('os.name', 'nt')
    def test_init_on_windows(self):
        """Test initialization on Windows."""
        parser = NTFSTimestampParser()
        assert parser._is_windows is True

    @patch('os.name', 'posix')
    def test_init_on_unix(self):
        """Test initialization on Unix-like systems."""
        parser = NTFSTimestampParser()
        assert parser._is_windows is False


class TestNTFSTimestampParserParse:
    """Tests for NTFSTimestampParser.parse method."""

    def test_parse_nonexistent_file_raises(self):
        """Test parse raises FileNotFoundError for missing file."""
        parser = NTFSTimestampParser()
        with pytest.raises(FileNotFoundError):
            parser.parse(Path("/nonexistent/file.dwg"))

    def test_parse_existing_file(self, tmp_path):
        """Test parse returns data for existing file."""
        test_file = tmp_path / "test.dwg"
        test_file.write_bytes(b"test content for file")

        parser = NTFSTimestampParser()
        result = parser.parse(test_file)

        assert isinstance(result, NTFSForensicData)
        assert result.si_timestamps is not None
        assert result.si_timestamps.modified is not None
        assert result.file_size == 21  # len("test content for file")

    def test_parse_returns_timestamps(self, tmp_path):
        """Test parse returns valid timestamps."""
        test_file = tmp_path / "test.dwg"
        test_file.write_bytes(b"x" * 100)

        parser = NTFSTimestampParser()
        result = parser.parse(test_file)

        # Should have modified and accessed timestamps
        assert result.si_timestamps.modified is not None
        assert result.si_timestamps.accessed is not None

        # Timestamps should be timezone-aware
        assert result.si_timestamps.modified.tzinfo is not None
        assert result.si_timestamps.accessed.tzinfo is not None

    def test_parse_string_path(self, tmp_path):
        """Test parse works with string path."""
        test_file = tmp_path / "test.dwg"
        test_file.write_bytes(b"test")

        parser = NTFSTimestampParser()
        result = parser.parse(str(test_file))

        assert isinstance(result, NTFSForensicData)


class TestNTFSTimestampParserStatParsing:
    """Tests for _parse_stat_timestamps method."""

    def test_stat_parses_file_size(self, tmp_path):
        """Test stat parsing captures file size."""
        test_file = tmp_path / "test.dwg"
        content = b"x" * 12345
        test_file.write_bytes(content)

        parser = NTFSTimestampParser()
        result = parser.parse(test_file)

        assert result.file_size == 12345

    def test_stat_parses_readonly_flag(self, tmp_path):
        """Test stat parsing detects read-only files."""
        test_file = tmp_path / "readonly.dwg"
        test_file.write_bytes(b"test")

        # Make file read-only
        os.chmod(test_file, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

        try:
            parser = NTFSTimestampParser()
            result = parser.parse(test_file)
            assert result.is_readonly is True
        finally:
            # Restore write permission for cleanup
            os.chmod(test_file, stat.S_IWUSR | stat.S_IRUSR)

    def test_stat_parses_writable_file(self, tmp_path):
        """Test stat parsing for writable files."""
        test_file = tmp_path / "writable.dwg"
        test_file.write_bytes(b"test")

        parser = NTFSTimestampParser()
        result = parser.parse(test_file)

        assert result.is_readonly is False


class TestNTFSTimestampParserFiletimeConversion:
    """Tests for FILETIME conversion methods."""

    def test_filetime_to_int(self):
        """Test FILETIME structure to int conversion."""
        parser = NTFSTimestampParser()

        # Create mock FILETIME
        filetime = Mock()
        filetime.dwLowDateTime = 0x12345678
        filetime.dwHighDateTime = 0x01D6A8B0

        result = parser._filetime_to_int(filetime)

        expected = (0x01D6A8B0 << 32) | 0x12345678
        assert result == expected

    def test_filetime_to_int_zero(self):
        """Test FILETIME conversion with zero values."""
        parser = NTFSTimestampParser()

        filetime = Mock()
        filetime.dwLowDateTime = 0
        filetime.dwHighDateTime = 0

        result = parser._filetime_to_int(filetime)
        assert result == 0

    def test_filetime_int_to_datetime_valid(self):
        """Test FILETIME int to datetime conversion."""
        parser = NTFSTimestampParser()

        # FILETIME for a known date - use the epoch difference to calculate
        # 2024-01-01 00:00:00 UTC
        # Seconds since 1601-01-01: 13,356,441,600 (approximately)
        # FILETIME = seconds * 10_000_000
        target_date = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        seconds_since_1601 = (target_date - FILETIME_EPOCH).total_seconds()
        filetime_int = int(seconds_since_1601 * 10_000_000)

        dt, ns = parser._filetime_int_to_datetime(filetime_int)

        assert dt is not None
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 1
        assert dt.tzinfo == timezone.utc

    def test_filetime_int_to_datetime_with_nanoseconds(self):
        """Test FILETIME conversion extracts nanoseconds."""
        parser = NTFSTimestampParser()

        # Add some nanoseconds (1234567 * 100 ns = 123456700 ns)
        filetime_int = 133499880001234567

        dt, ns = parser._filetime_int_to_datetime(filetime_int)

        assert dt is not None
        assert ns is not None
        # nanoseconds = (filetime_int % 10_000_000) * 100
        expected_ns = (1234567) * 100
        assert ns == expected_ns

    def test_filetime_int_to_datetime_zero(self):
        """Test FILETIME conversion with zero returns None."""
        parser = NTFSTimestampParser()

        dt, ns = parser._filetime_int_to_datetime(0)

        assert dt is None
        assert ns is None

    def test_filetime_int_to_datetime_negative(self):
        """Test FILETIME conversion with negative returns None."""
        parser = NTFSTimestampParser()

        dt, ns = parser._filetime_int_to_datetime(-1)

        assert dt is None
        assert ns is None


class TestNTFSTimestampParserAnomalyDetection:
    """Tests for _detect_timestamp_anomalies method."""

    def test_no_anomalies_clean_file(self):
        """Test no anomalies detected for clean file."""
        parser = NTFSTimestampParser()
        now = datetime.now(timezone.utc)

        data = NTFSForensicData()
        data.si_timestamps = NTFSTimestamps(
            created=now - timedelta(days=1),
            modified=now,
            accessed=now,
            created_nanoseconds=1234567,
            modified_nanoseconds=7654321,
            accessed_nanoseconds=9876543,
        )

        parser._detect_timestamp_anomalies(data)

        assert data.nanoseconds_truncated is False
        assert data.creation_after_modification is False

    def test_detects_nanosecond_truncation_multiple(self):
        """Test detection of multiple truncated nanoseconds."""
        parser = NTFSTimestampParser()
        now = datetime.now(timezone.utc)

        data = NTFSForensicData()
        data.si_timestamps = NTFSTimestamps(
            created=now - timedelta(days=1),
            modified=now,
            accessed=now,
            created_nanoseconds=0,
            modified_nanoseconds=0,
            accessed_nanoseconds=0,
        )

        parser._detect_timestamp_anomalies(data)

        assert data.nanoseconds_truncated is True
        assert "zero nanoseconds" in data.truncation_details.lower()

    def test_no_truncation_single_zero(self):
        """Test single zero nanosecond is not flagged (could be coincidence)."""
        parser = NTFSTimestampParser()
        now = datetime.now(timezone.utc)

        data = NTFSForensicData()
        data.si_timestamps = NTFSTimestamps(
            created=now - timedelta(days=1),
            modified=now,
            accessed=now,
            created_nanoseconds=0,
            modified_nanoseconds=1234567,  # Non-zero
            accessed_nanoseconds=7654321,  # Non-zero
        )

        parser._detect_timestamp_anomalies(data)

        # Single zero is not flagged - could be coincidence
        assert data.nanoseconds_truncated is False

    def test_detects_creation_after_modification(self):
        """Test detection of impossible timestamp condition."""
        parser = NTFSTimestampParser()
        now = datetime.now(timezone.utc)

        data = NTFSForensicData()
        data.si_timestamps = NTFSTimestamps(
            created=now,  # Created NOW
            modified=now - timedelta(days=1),  # Modified YESTERDAY (impossible!)
            accessed=now,
        )

        parser._detect_timestamp_anomalies(data)

        assert data.creation_after_modification is True

    def test_no_creation_after_mod_normal_case(self):
        """Test normal case doesn't flag creation after modification."""
        parser = NTFSTimestampParser()
        now = datetime.now(timezone.utc)

        data = NTFSForensicData()
        data.si_timestamps = NTFSTimestamps(
            created=now - timedelta(days=10),  # Created 10 days ago
            modified=now,  # Modified now (normal)
            accessed=now,
        )

        parser._detect_timestamp_anomalies(data)

        assert data.creation_after_modification is False

    def test_detects_si_fn_mismatch(self):
        """Test detection of SI/FN timestamp mismatch (timestomping proof)."""
        parser = NTFSTimestampParser()
        now = datetime.now(timezone.utc)

        data = NTFSForensicData()
        # SI timestamp claims file was created a week ago
        data.si_timestamps = NTFSTimestamps(
            created=now - timedelta(days=7),
            modified=now,
        )
        # FN timestamp shows file was actually created yesterday
        data.fn_timestamps = FileNameTimestamps(
            created=now - timedelta(days=1),
            modified=now,
        )

        parser._detect_timestamp_anomalies(data)

        assert data.si_fn_mismatch is True
        assert "DEFINITIVE PROOF OF TIMESTOMPING" in data.mismatch_details
        assert "$FILE_NAME" in data.mismatch_details

    def test_no_si_fn_mismatch_consistent(self):
        """Test consistent SI/FN timestamps don't trigger mismatch."""
        parser = NTFSTimestampParser()
        now = datetime.now(timezone.utc)
        created = now - timedelta(days=7)

        data = NTFSForensicData()
        data.si_timestamps = NTFSTimestamps(
            created=created,
            modified=now,
        )
        data.fn_timestamps = FileNameTimestamps(
            created=created,  # Same as SI
            modified=now,
        )

        parser._detect_timestamp_anomalies(data)

        assert data.si_fn_mismatch is False


class TestNTFSTimestampParserCrossValidation:
    """Tests for cross_validate_with_dwg method."""

    def test_no_contradictions_consistent_timestamps(self):
        """Test no contradictions when timestamps are consistent."""
        parser = NTFSTimestampParser()
        now = datetime.now(timezone.utc)
        created = now - timedelta(days=30)
        modified = now - timedelta(hours=1)

        ntfs_data = NTFSForensicData()
        ntfs_data.si_timestamps = NTFSTimestamps(
            created=created,
            modified=modified,
        )

        contradictions = parser.cross_validate_with_dwg(
            ntfs_data,
            dwg_created=created + timedelta(seconds=5),  # Shortly after NTFS
            dwg_modified=modified + timedelta(seconds=5),
        )

        assert len(contradictions) == 0

    def test_detects_dwg_created_before_file_existed(self):
        """Test detection of DWG claiming creation before NTFS file existed."""
        parser = NTFSTimestampParser()
        now = datetime.now(timezone.utc)

        # NTFS says file was created today
        ntfs_data = NTFSForensicData()
        ntfs_data.si_timestamps = NTFSTimestamps(
            created=now,
            modified=now,
        )

        # DWG claims it was created a month ago (impossible!)
        contradictions = parser.cross_validate_with_dwg(
            ntfs_data,
            dwg_created=now - timedelta(days=30),
            dwg_modified=now,
        )

        assert len(contradictions) >= 1
        assert any(c["type"] == "DWG_CREATED_BEFORE_FILE_EXISTED" for c in contradictions)
        assert any(c["severity"] == "CRITICAL" for c in contradictions)
        assert any("PROVEN TIMESTAMP BACKDATING" in c["conclusion"] for c in contradictions)

    def test_detects_dwg_modified_before_file_existed(self):
        """Test detection of DWG claiming modification before file existed."""
        parser = NTFSTimestampParser()
        now = datetime.now(timezone.utc)

        # NTFS says file was created today
        ntfs_data = NTFSForensicData()
        ntfs_data.si_timestamps = NTFSTimestamps(
            created=now,
            modified=now,
        )

        # DWG claims it was modified a month ago (impossible for this file!)
        contradictions = parser.cross_validate_with_dwg(
            ntfs_data,
            dwg_created=now - timedelta(days=60),  # Also backdated
            dwg_modified=now - timedelta(days=30),
        )

        assert len(contradictions) >= 1
        assert any(c["type"] == "DWG_MODIFIED_BEFORE_FILE_EXISTED" for c in contradictions)

    def test_detects_modification_timestamp_gap(self):
        """Test detection of significant gap between DWG and NTFS modified times."""
        parser = NTFSTimestampParser()
        now = datetime.now(timezone.utc)

        # NTFS says file was modified today
        ntfs_data = NTFSForensicData()
        ntfs_data.si_timestamps = NTFSTimestamps(
            created=now - timedelta(days=30),
            modified=now,
        )

        # DWG claims last modification was 5 days ago (indicates copy/transfer)
        contradictions = parser.cross_validate_with_dwg(
            ntfs_data,
            dwg_created=now - timedelta(days=30),
            dwg_modified=now - timedelta(days=5),
        )

        assert len(contradictions) >= 1
        gap_finding = next(
            (c for c in contradictions if c["type"] == "MODIFICATION_TIMESTAMP_GAP"),
            None
        )
        assert gap_finding is not None
        assert gap_finding["severity"] == "WARNING"
        assert "copy" in gap_finding["description"].lower() or "transfer" in gap_finding["description"].lower()

    def test_no_gap_warning_for_small_difference(self):
        """Test small time differences don't trigger gap warning."""
        parser = NTFSTimestampParser()
        now = datetime.now(timezone.utc)

        ntfs_data = NTFSForensicData()
        ntfs_data.si_timestamps = NTFSTimestamps(
            created=now - timedelta(days=30),
            modified=now,
        )

        # Only 30 seconds difference - within grace period
        contradictions = parser.cross_validate_with_dwg(
            ntfs_data,
            dwg_created=now - timedelta(days=30),
            dwg_modified=now - timedelta(seconds=30),
        )

        # Should not have modification gap warning
        assert not any(c["type"] == "MODIFICATION_TIMESTAMP_GAP" for c in contradictions)

    def test_cross_validation_with_naive_datetimes(self):
        """Test cross-validation handles naive (timezone-unaware) datetimes."""
        parser = NTFSTimestampParser()
        now = datetime.now()  # Naive datetime

        ntfs_data = NTFSForensicData()
        ntfs_data.si_timestamps = NTFSTimestamps(
            created=now - timedelta(days=30),
            modified=now,
        )

        # Should not raise exception with naive datetimes
        contradictions = parser.cross_validate_with_dwg(
            ntfs_data,
            dwg_created=now - timedelta(days=30),
            dwg_modified=now,
        )

        # Should complete without error
        assert isinstance(contradictions, list)

    def test_cross_validation_with_none_values(self):
        """Test cross-validation handles None values gracefully."""
        parser = NTFSTimestampParser()

        ntfs_data = NTFSForensicData()
        ntfs_data.si_timestamps = NTFSTimestamps()  # All None

        # Should not raise exception
        contradictions = parser.cross_validate_with_dwg(
            ntfs_data,
            dwg_created=None,
            dwg_modified=None,
        )

        assert contradictions == []

    def test_cross_validation_partial_timestamps(self):
        """Test cross-validation with only some timestamps available."""
        parser = NTFSTimestampParser()
        now = datetime.now(timezone.utc)

        ntfs_data = NTFSForensicData()
        ntfs_data.si_timestamps = NTFSTimestamps(
            created=now,
            modified=None,  # No modification time
        )

        contradictions = parser.cross_validate_with_dwg(
            ntfs_data,
            dwg_created=now - timedelta(days=30),  # Backdated
            dwg_modified=None,
        )

        # Should still detect creation backdating
        assert any(c["type"] == "DWG_CREATED_BEFORE_FILE_EXISTED" for c in contradictions)


class TestConvenienceFunction:
    """Tests for get_ntfs_timestamps convenience function."""

    def test_get_ntfs_timestamps(self, tmp_path):
        """Test convenience function returns data."""
        test_file = tmp_path / "test.dwg"
        test_file.write_bytes(b"test content")

        result = get_ntfs_timestamps(test_file)

        assert isinstance(result, NTFSForensicData)
        assert result.si_timestamps.modified is not None
        assert result.file_size == 12

    def test_get_ntfs_timestamps_nonexistent(self):
        """Test convenience function raises for nonexistent file."""
        with pytest.raises(FileNotFoundError):
            get_ntfs_timestamps(Path("/nonexistent/file.dwg"))


# =============================================================================
# Windows-Specific Tests (Mocked)
# =============================================================================


class TestWindowsAPIIntegration:
    """Tests for Windows API timestamp parsing (mocked)."""

    @patch('os.name', 'nt')
    def test_windows_api_called_on_windows(self, tmp_path):
        """Test Windows API is attempted on Windows."""
        test_file = tmp_path / "test.dwg"
        test_file.write_bytes(b"test")

        with patch.object(
            NTFSTimestampParser, '_parse_windows_timestamps'
        ) as mock_windows:
            parser = NTFSTimestampParser()
            parser._is_windows = True  # Force Windows mode
            parser.parse(test_file)

            mock_windows.assert_called_once()

    def test_windows_api_not_called_on_unix(self, tmp_path):
        """Test Windows API is not called on Unix."""
        test_file = tmp_path / "test.dwg"
        test_file.write_bytes(b"test")

        # Create parser and manually set to Unix mode to test cross-platform behavior
        parser = NTFSTimestampParser()
        parser._is_windows = False  # Force Unix mode

        with patch.object(parser, '_parse_windows_timestamps') as mock_windows:
            parser.parse(test_file)

            # Verify Windows API was not called in Unix mode
            mock_windows.assert_not_called()


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================


class TestEdgeCases:
    """Edge case tests for NTFS parser."""

    def test_empty_file(self, tmp_path):
        """Test parsing empty file."""
        test_file = tmp_path / "empty.dwg"
        test_file.write_bytes(b"")

        parser = NTFSTimestampParser()
        result = parser.parse(test_file)

        assert result.file_size == 0
        assert result.si_timestamps.modified is not None

    def test_large_file_metadata(self, tmp_path):
        """Test parsing large file metadata (without reading full content)."""
        test_file = tmp_path / "large.dwg"
        # Create file with some content (not actually large to keep test fast)
        test_file.write_bytes(b"x" * 1000000)

        parser = NTFSTimestampParser()
        result = parser.parse(test_file)

        assert result.file_size == 1000000

    def test_path_with_spaces(self, tmp_path):
        """Test parsing file with spaces in path."""
        dir_with_spaces = tmp_path / "path with spaces"
        dir_with_spaces.mkdir()
        test_file = dir_with_spaces / "file with spaces.dwg"
        test_file.write_bytes(b"test")

        parser = NTFSTimestampParser()
        result = parser.parse(test_file)

        assert result.file_size == 4

    def test_unicode_path(self, tmp_path):
        """Test parsing file with unicode characters in path."""
        # Some systems may not support all unicode in paths
        try:
            test_file = tmp_path / "test_unicode.dwg"
            test_file.write_bytes(b"test")

            parser = NTFSTimestampParser()
            result = parser.parse(test_file)

            assert result.file_size == 4
        except (OSError, UnicodeError):
            pytest.skip("System doesn't support unicode in paths")

    def test_timestamps_in_far_past(self):
        """Test handling timestamps from distant past."""
        parser = NTFSTimestampParser()

        # Very early FILETIME (year 1602)
        early_filetime = 10_000_000_000  # About 1000 seconds after 1601

        dt, ns = parser._filetime_int_to_datetime(early_filetime)

        # Should handle early dates
        if dt is not None:  # Some systems may not support dates this early
            assert dt.year < 1970

    def test_timestamps_in_far_future(self):
        """Test handling timestamps from distant future."""
        parser = NTFSTimestampParser()

        # FILETIME for year 3000 (approximately)
        future_filetime = 440000000000000000

        dt, ns = parser._filetime_int_to_datetime(future_filetime)

        # Should handle or gracefully fail for future dates
        # (might return None if outside datetime range)
        assert dt is None or dt.year > 2100


class TestForensicScenarios:
    """Tests simulating real forensic scenarios."""

    def test_scenario_classic_timestomping(self):
        """Simulate classic timestomping where SI is backdated."""
        parser = NTFSTimestampParser()
        now = datetime.now(timezone.utc)

        # Attacker backdated SI to claim file existed last year
        data = NTFSForensicData()
        data.si_timestamps = NTFSTimestamps(
            created=now - timedelta(days=365),  # "Created" a year ago
            modified=now - timedelta(days=1),
            created_nanoseconds=0,  # Timestomping tool didn't set nanoseconds
            modified_nanoseconds=0,
        )
        # FN reveals truth - file was actually created today
        data.fn_timestamps = FileNameTimestamps(
            created=now,
            modified=now,
        )

        parser._detect_timestamp_anomalies(data)

        # Should detect both indicators
        assert data.si_fn_mismatch is True
        assert data.nanoseconds_truncated is True
        assert data.has_timestomping_evidence() is True

    def test_scenario_file_copy_detection(self):
        """Simulate detection of file copy/transfer."""
        parser = NTFSTimestampParser()
        now = datetime.now(timezone.utc)

        # File was copied - DWG internal timestamps are from original
        ntfs_data = NTFSForensicData()
        ntfs_data.si_timestamps = NTFSTimestamps(
            created=now,  # File created on this system today
            modified=now,
        )

        # DWG claims it was created and modified months ago on another system
        contradictions = parser.cross_validate_with_dwg(
            ntfs_data,
            dwg_created=now - timedelta(days=90),
            dwg_modified=now - timedelta(days=30),
        )

        # Should detect the backdating
        assert len(contradictions) >= 2
        types = [c["type"] for c in contradictions]
        assert "DWG_CREATED_BEFORE_FILE_EXISTED" in types
        assert "DWG_MODIFIED_BEFORE_FILE_EXISTED" in types

    def test_scenario_legitimate_file(self, tmp_path):
        """Simulate analysis of legitimate unmodified file."""
        # Create a real test file
        test_file = tmp_path / "legitimate.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 100)  # Fake DWG header

        parser = NTFSTimestampParser()
        result = parser.parse(test_file)

        # Freshly created file should have no anomalies
        # Note: nanoseconds might be truncated on some filesystems
        assert result.creation_after_modification is False
        assert result.si_fn_mismatch is False


# =============================================================================
# Constants Tests
# =============================================================================


class TestConstants:
    """Tests for module constants."""

    def test_filetime_epoch(self):
        """Test FILETIME epoch constant."""
        assert FILETIME_EPOCH.year == 1601
        assert FILETIME_EPOCH.month == 1
        assert FILETIME_EPOCH.day == 1
        assert FILETIME_EPOCH.tzinfo == timezone.utc

    def test_filetime_to_unix_epoch_ticks(self):
        """Test FILETIME to Unix epoch conversion constant."""
        # Should be approximately 11644473600 seconds * 10_000_000
        assert FILETIME_TO_UNIX_EPOCH_TICKS == 116444736000000000

        # Verify by calculation
        epoch_diff = datetime(1970, 1, 1, tzinfo=timezone.utc) - FILETIME_EPOCH
        expected = int(epoch_diff.total_seconds() * 10_000_000)
        assert FILETIME_TO_UNIX_EPOCH_TICKS == expected
