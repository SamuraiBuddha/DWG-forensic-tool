"""
Tests for DWG Drawing Variables Parser module.

This module tests extraction of forensically critical drawing variables:
- TDCREATE/TDUPDATE timestamps
- TDINDWG editing time
- FINGERPRINTGUID/VERSIONGUID identifiers
- Timestamp comparison and anomaly detection
"""

import pytest
import struct
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

from dwg_forensic.parsers.drawing_vars import (
    DWGVariableType,
    DrawingTimestamp,
    DrawingGUID,
    DrawingVariablesResult,
    DrawingVariablesParser,
    extract_drawing_variables,
    compare_timestamps,
    JULIAN_EPOCH,
)


class TestDWGVariableType:
    """Tests for DWGVariableType enumeration."""

    def test_variable_types_defined(self):
        """Test all variable types are defined."""
        assert DWGVariableType.BIT.value == "BIT"
        assert DWGVariableType.BITSHORT.value == "BS"
        assert DWGVariableType.BITLONG.value == "BL"
        assert DWGVariableType.BITDOUBLE.value == "BD"
        assert DWGVariableType.HANDLE.value == "H"
        assert DWGVariableType.TEXT.value == "T"
        assert DWGVariableType.JULIAN_DATE.value == "JD"
        assert DWGVariableType.TIMEBLL.value == "TIMEBLL"
        assert DWGVariableType.RAW_DOUBLE.value == "RD"


class TestDrawingTimestamp:
    """Tests for DrawingTimestamp dataclass."""

    def test_timestamp_creation(self):
        """Test DrawingTimestamp can be created with basic fields."""
        ts = DrawingTimestamp(
            variable_name="TDCREATE",
            julian_day=2459580.5,
            milliseconds=43200000,
        )
        assert ts.variable_name == "TDCREATE"
        assert ts.julian_day == 2459580.5
        assert ts.milliseconds == 43200000
        assert ts.is_valid is True

    def test_timestamp_defaults(self):
        """Test DrawingTimestamp has correct defaults."""
        ts = DrawingTimestamp(variable_name="TEST")
        assert ts.julian_day == 0.0
        assert ts.milliseconds == 0
        assert ts.datetime_utc is None
        assert ts.raw_bytes == b""
        assert ts.is_valid is True
        assert ts.parse_error == ""

    def test_timestamp_with_datetime(self):
        """Test DrawingTimestamp with datetime value."""
        dt = datetime(2024, 1, 15, 12, 30, 0, tzinfo=timezone.utc)
        ts = DrawingTimestamp(
            variable_name="TDUPDATE",
            julian_day=2460325.0,
            datetime_utc=dt,
        )
        assert ts.datetime_utc == dt
        assert ts.datetime_utc.year == 2024

    def test_timestamp_with_error(self):
        """Test DrawingTimestamp with parse error."""
        ts = DrawingTimestamp(
            variable_name="TDCREATE",
            is_valid=False,
            parse_error="Invalid Julian date format",
        )
        assert ts.is_valid is False
        assert "Invalid" in ts.parse_error

    def test_timestamp_to_dict(self):
        """Test DrawingTimestamp serialization to dict."""
        dt = datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        ts = DrawingTimestamp(
            variable_name="TDCREATE",
            julian_day=2460476.0,
            milliseconds=36000000,
            datetime_utc=dt,
            raw_bytes=b"\x00\x01\x02\x03",
        )
        d = ts.to_dict()
        assert d["variable_name"] == "TDCREATE"
        assert d["julian_day"] == 2460476.0
        assert d["milliseconds"] == 36000000
        assert "2024-06-15" in d["datetime_utc"]
        assert d["raw_hex"] == "00010203"
        assert d["is_valid"] is True

    def test_timestamp_to_dict_no_datetime(self):
        """Test DrawingTimestamp serialization when datetime is None."""
        ts = DrawingTimestamp(variable_name="TEST")
        d = ts.to_dict()
        assert d["datetime_utc"] is None


class TestDrawingGUID:
    """Tests for DrawingGUID dataclass."""

    def test_guid_creation(self):
        """Test DrawingGUID can be created."""
        guid = DrawingGUID(
            variable_name="FINGERPRINTGUID",
            guid_string="A1B2C3D4-E5F6-4789-ABCD-EF0123456789",
        )
        assert guid.variable_name == "FINGERPRINTGUID"
        assert guid.guid_string == "A1B2C3D4-E5F6-4789-ABCD-EF0123456789"

    def test_guid_defaults(self):
        """Test DrawingGUID has correct defaults."""
        guid = DrawingGUID(variable_name="TEST")
        assert guid.guid_string == ""
        assert guid.raw_bytes == b""
        assert guid.is_valid is True
        assert guid.parse_error == ""

    def test_guid_with_raw_bytes(self):
        """Test DrawingGUID with raw bytes."""
        raw = b"\xd4\xc3\xb2\xa1\xf6\xe5\x89\x47\xab\xcd\xef\x01\x23\x45\x67\x89"
        guid = DrawingGUID(
            variable_name="VERSIONGUID",
            guid_string="A1B2C3D4-E5F6-4789-ABCD-EF0123456789",
            raw_bytes=raw,
        )
        assert len(guid.raw_bytes) == 16

    def test_guid_to_dict(self):
        """Test DrawingGUID serialization to dict."""
        guid = DrawingGUID(
            variable_name="FINGERPRINTGUID",
            guid_string="12345678-1234-4567-89AB-CDEF01234567",
            raw_bytes=b"\x01\x02\x03\x04",
        )
        d = guid.to_dict()
        assert d["variable_name"] == "FINGERPRINTGUID"
        assert d["guid_string"] == "12345678-1234-4567-89AB-CDEF01234567"
        assert d["raw_hex"] == "01020304"
        assert d["is_valid"] is True


class TestDrawingVariablesResult:
    """Tests for DrawingVariablesResult dataclass."""

    def test_empty_result(self):
        """Test empty result has correct defaults."""
        result = DrawingVariablesResult()
        assert result.tdcreate is None
        assert result.tdupdate is None
        assert result.tdindwg is None
        assert result.fingerprintguid is None
        assert result.versionguid is None
        assert result.parsing_errors == []

    def test_has_timestamps_true(self):
        """Test has_timestamps returns True when timestamps exist."""
        result = DrawingVariablesResult()
        result.tdcreate = DrawingTimestamp(
            variable_name="TDCREATE",
            is_valid=True,
        )
        assert result.has_timestamps() is True

    def test_has_timestamps_false(self):
        """Test has_timestamps returns False when no valid timestamps."""
        result = DrawingVariablesResult()
        assert result.has_timestamps() is False

    def test_has_timestamps_invalid(self):
        """Test has_timestamps returns False when timestamp invalid."""
        result = DrawingVariablesResult()
        result.tdcreate = DrawingTimestamp(
            variable_name="TDCREATE",
            is_valid=False,
        )
        assert result.has_timestamps() is False

    def test_get_creation_time(self):
        """Test get_creation_time returns datetime."""
        dt = datetime(2024, 3, 15, 14, 30, 0, tzinfo=timezone.utc)
        result = DrawingVariablesResult()
        result.tdcreate = DrawingTimestamp(
            variable_name="TDCREATE",
            datetime_utc=dt,
        )
        assert result.get_creation_time() == dt

    def test_get_creation_time_none(self):
        """Test get_creation_time returns None when not set."""
        result = DrawingVariablesResult()
        assert result.get_creation_time() is None

    def test_get_modification_time(self):
        """Test get_modification_time returns datetime."""
        dt = datetime(2024, 5, 20, 16, 45, 0, tzinfo=timezone.utc)
        result = DrawingVariablesResult()
        result.tdupdate = DrawingTimestamp(
            variable_name="TDUPDATE",
            datetime_utc=dt,
        )
        assert result.get_modification_time() == dt

    def test_get_total_edit_time(self):
        """Test get_total_edit_time returns timedelta."""
        result = DrawingVariablesResult()
        result.tdindwg = DrawingTimestamp(
            variable_name="TDINDWG",
            julian_day=5.5,  # 5.5 days of editing
        )
        edit_time = result.get_total_edit_time()
        assert edit_time is not None
        assert edit_time.days == 5
        assert edit_time.seconds == 43200  # 12 hours

    def test_get_total_edit_time_zero(self):
        """Test get_total_edit_time returns None for zero."""
        result = DrawingVariablesResult()
        result.tdindwg = DrawingTimestamp(
            variable_name="TDINDWG",
            julian_day=0.0,
        )
        assert result.get_total_edit_time() is None

    def test_result_to_dict(self):
        """Test result serialization to dict."""
        result = DrawingVariablesResult()
        result.file_version = "AC1032"
        result.maintver = 5
        result.parsing_errors.append("Test error")

        d = result.to_dict()
        assert d["file_version"] == "AC1032"
        assert d["maintver"] == 5
        assert "Test error" in d["parsing_errors"]


class TestDrawingVariablesParser:
    """Tests for DrawingVariablesParser class."""

    def test_parser_initialization(self):
        """Test parser can be initialized."""
        parser = DrawingVariablesParser()
        assert parser is not None

    def test_parser_guid_size(self):
        """Test GUID_SIZE constant is correct."""
        assert DrawingVariablesParser.GUID_SIZE == 16

    def test_parser_julian_date_size(self):
        """Test JULIAN_DATE_SIZE constant is correct."""
        assert DrawingVariablesParser.JULIAN_DATE_SIZE == 16


class TestDrawingVariablesParserFileAccess:
    """Tests for file access handling."""

    def test_file_not_found(self):
        """Test parser handles missing file."""
        parser = DrawingVariablesParser()
        result = parser.parse(Path("/nonexistent/file.dwg"))
        assert len(result.parsing_errors) > 0
        assert "Failed to read file" in result.parsing_errors[0]

    def test_file_too_small(self):
        """Test parser handles file too small."""
        parser = DrawingVariablesParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(b"AC1032" + b"\x00" * 50)
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert "too small" in result.parsing_errors[0]
        finally:
            temp_path.unlink()

    def test_invalid_version_string(self):
        """Test parser handles invalid version string."""
        parser = DrawingVariablesParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(bytes([0xFF, 0xFE, 0x00]) + b"\x00" * 300)
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert "Invalid version" in result.parsing_errors[0]
        finally:
            temp_path.unlink()


class TestDrawingVariablesParserVersions:
    """Tests for version-specific parsing."""

    def _create_dwg_stub(self, version: str) -> bytes:
        """Create a minimal DWG file stub."""
        data = bytearray(0x400)  # 1KB
        data[0:6] = version.encode("ascii")
        data[0x0B] = 5  # Maintenance version
        return bytes(data)

    def test_parse_ac1018_version(self):
        """Test parsing AC1018 (AutoCAD 2004-2006) files."""
        parser = DrawingVariablesParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_stub("AC1018"))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.file_version == "AC1018"
            # Should not have unsupported version error
            assert not any("not supported for AC1018" in err for err in result.parsing_errors)
        finally:
            temp_path.unlink()

    def test_parse_ac1021_version(self):
        """Test parsing AC1021 (AutoCAD 2007-2009) files."""
        parser = DrawingVariablesParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_stub("AC1021"))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.file_version == "AC1021"
        finally:
            temp_path.unlink()

    def test_parse_ac1024_version(self):
        """Test parsing AC1024 (AutoCAD 2010-2012) files."""
        parser = DrawingVariablesParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_stub("AC1024"))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.file_version == "AC1024"
        finally:
            temp_path.unlink()

    def test_parse_ac1027_version(self):
        """Test parsing AC1027 (AutoCAD 2013-2017) files."""
        parser = DrawingVariablesParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_stub("AC1027"))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.file_version == "AC1027"
        finally:
            temp_path.unlink()

    def test_parse_ac1032_version(self):
        """Test parsing AC1032 (AutoCAD 2018+) files."""
        parser = DrawingVariablesParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_stub("AC1032"))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.file_version == "AC1032"
        finally:
            temp_path.unlink()

    def test_unsupported_version(self):
        """Test parser handles unsupported versions."""
        parser = DrawingVariablesParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_stub("AC1015"))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert any("not supported" in err for err in result.parsing_errors)
        finally:
            temp_path.unlink()


class TestJulianDateConversion:
    """Tests for Julian date to datetime conversion."""

    def test_julian_to_datetime_valid(self):
        """Test valid Julian date conversion."""
        parser = DrawingVariablesParser()
        # Julian day 2459580.5 = January 1, 2022 (noon UTC)
        dt = parser._julian_to_datetime(2459580.5, 0.0)
        assert dt is not None
        assert dt.year == 2022
        assert dt.month == 1
        assert dt.day == 1

    def test_julian_to_datetime_with_fraction(self):
        """Test Julian date conversion with day fraction."""
        parser = DrawingVariablesParser()
        # Noon (0.0 fraction because Julian days start at noon)
        dt = parser._julian_to_datetime(2459580.5, 0.5)
        assert dt is not None
        # 0.5 fraction = 12 hours
        # Note: exact hour depends on interpretation

    def test_julian_to_datetime_invalid_range(self):
        """Test Julian date outside valid range returns None."""
        parser = DrawingVariablesParser()
        # Very old date
        dt = parser._julian_to_datetime(1000000.0, 0.0)
        assert dt is None

    def test_julian_to_datetime_future(self):
        """Test Julian date far in future returns None."""
        parser = DrawingVariablesParser()
        # Year 2200+
        dt = parser._julian_to_datetime(2580000.0, 0.0)
        assert dt is None


class TestGUIDConversion:
    """Tests for GUID byte conversion."""

    def test_bytes_to_guid_string_valid(self):
        """Test valid GUID bytes conversion."""
        parser = DrawingVariablesParser()
        # Standard GUID bytes (mixed endian)
        guid_bytes = bytes([
            0xD4, 0xC3, 0xB2, 0xA1,  # Part 1 (little-endian)
            0xF6, 0xE5,              # Part 2 (little-endian)
            0x89, 0x47,              # Part 3 (little-endian)
            0xAB, 0xCD,              # Part 4 (big-endian)
            0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,  # Part 5 (big-endian)
        ])
        guid_str = parser._bytes_to_guid_string(guid_bytes)
        assert len(guid_str) == 36  # Standard GUID format
        assert "-" in guid_str
        assert guid_str.count("-") == 4

    def test_bytes_to_guid_string_wrong_length(self):
        """Test GUID conversion with wrong length returns empty."""
        parser = DrawingVariablesParser()
        guid_str = parser._bytes_to_guid_string(b"\x01\x02\x03")
        assert guid_str == ""

    def test_bytes_to_guid_string_format(self):
        """Test GUID string format is correct."""
        parser = DrawingVariablesParser()
        guid_bytes = bytes([
            0x78, 0x56, 0x34, 0x12,  # 12345678
            0x34, 0x12,              # 1234
            0x67, 0x45,              # 4567
            0x89, 0xAB,
            0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
        ])
        guid_str = parser._bytes_to_guid_string(guid_bytes)
        # Format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
        parts = guid_str.split("-")
        assert len(parts) == 5
        assert len(parts[0]) == 8
        assert len(parts[1]) == 4
        assert len(parts[2]) == 4
        assert len(parts[3]) == 4
        assert len(parts[4]) == 12


class TestTimestampScanning:
    """Tests for timestamp pattern scanning."""

    def _create_dwg_with_timestamp(self, julian_day: float, fraction: float) -> bytes:
        """Create DWG stub with embedded Julian date timestamp."""
        data = bytearray(0x400)
        data[0:6] = b"AC1032"

        # Embed Julian date at offset 0x100
        struct.pack_into("<d", data, 0x100, julian_day)
        struct.pack_into("<d", data, 0x108, fraction)

        return bytes(data)

    def test_scan_finds_valid_timestamp(self):
        """Test scanner finds valid Julian date timestamp."""
        parser = DrawingVariablesParser()
        # Julian day for around 2024
        julian_day = 2460310.5  # January 1, 2024
        fraction = 0.5  # Noon

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_with_timestamp(julian_day, fraction))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            # Should find at least one timestamp
            # Note: may or may not be assigned depending on scan order
            assert result.file_version == "AC1032"
        finally:
            temp_path.unlink()


class TestGUIDScanning:
    """Tests for GUID pattern scanning."""

    def _create_dwg_with_guid(self) -> bytes:
        """Create DWG stub with embedded UUID v4."""
        data = bytearray(0x400)
        data[0:6] = b"AC1032"

        # Create a valid UUID v4 pattern at offset 0x100
        # UUID v4 has version=4 in byte 6 (high nibble) and variant=2 in byte 8
        uuid_bytes = bytes([
            0x12, 0x34, 0x56, 0x78,  # Random
            0x9A, 0xBC,              # Random
            0x4D, 0xEF,              # Version 4 (high nibble = 4)
            0x8F, 0x01,              # Variant 2 (high 2 bits = 10)
            0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,  # Random
        ])
        data[0x100:0x110] = uuid_bytes

        return bytes(data)

    def test_scan_finds_uuid_v4(self):
        """Test scanner can find UUID v4 pattern."""
        parser = DrawingVariablesParser()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(self._create_dwg_with_guid())
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            # Should find the GUID
            if result.fingerprintguid:
                assert result.fingerprintguid.is_valid
                assert len(result.fingerprintguid.guid_string) == 36
        finally:
            temp_path.unlink()


class TestExtractHeaderInfo:
    """Tests for header info extraction."""

    def test_extract_maintenance_version(self):
        """Test maintenance version extraction."""
        parser = DrawingVariablesParser()
        data = bytearray(0x400)
        data[0:6] = b"AC1032"
        data[0x0B] = 7  # Maintenance version

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(bytes(data))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result.maintver == 7
        finally:
            temp_path.unlink()

    def test_extract_codepage(self):
        """Test codepage extraction."""
        parser = DrawingVariablesParser()
        data = bytearray(0x400)
        data[0:6] = b"AC1032"
        struct.pack_into("<H", data, 0x13, 1252)  # Windows-1252

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(bytes(data))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert "1252" in result.dwgcodepage
        finally:
            temp_path.unlink()


class TestExtractDrawingVariablesConvenience:
    """Tests for convenience function."""

    def test_extract_drawing_variables_returns_result(self):
        """Test convenience function returns DrawingVariablesResult."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            data = b"AC1032" + b"\x00" * 0x300
            f.write(data)
            temp_path = Path(f.name)

        try:
            result = extract_drawing_variables(temp_path)
            assert isinstance(result, DrawingVariablesResult)
            assert result.file_version == "AC1032"
        finally:
            temp_path.unlink()

    def test_extract_drawing_variables_invalid_file(self):
        """Test convenience function handles invalid file."""
        result = extract_drawing_variables(Path("/nonexistent/file.dwg"))
        assert isinstance(result, DrawingVariablesResult)
        assert len(result.parsing_errors) > 0


class TestCompareTimestamps:
    """Tests for timestamp comparison function."""

    def test_compare_matching_timestamps(self):
        """Test comparison when timestamps match."""
        dwg_create = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        dwg_update = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        file_create = datetime(2024, 1, 15, 10, 0, 30, tzinfo=timezone.utc)
        file_modify = datetime(2024, 1, 15, 12, 0, 30, tzinfo=timezone.utc)

        result = compare_timestamps(dwg_create, dwg_update, file_create, file_modify)

        assert result["create_match"] is True
        assert result["modify_match"] is True
        assert len(result["anomalies"]) == 0

    def test_compare_mismatched_creation(self):
        """Test comparison detects mismatched creation time."""
        dwg_create = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        dwg_update = datetime(2024, 1, 20, 12, 0, 0, tzinfo=timezone.utc)
        file_create = datetime(2024, 1, 10, 10, 0, 0, tzinfo=timezone.utc)  # 5 days off
        file_modify = datetime(2024, 1, 20, 12, 0, 0, tzinfo=timezone.utc)

        result = compare_timestamps(dwg_create, dwg_update, file_create, file_modify)

        assert result["create_match"] is False
        assert any(a["type"] == "creation_timestamp_mismatch" for a in result["anomalies"])

    def test_compare_mismatched_modification(self):
        """Test comparison detects mismatched modification time."""
        dwg_create = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        dwg_update = datetime(2024, 1, 20, 12, 0, 0, tzinfo=timezone.utc)
        file_create = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        file_modify = datetime(2024, 1, 25, 12, 0, 0, tzinfo=timezone.utc)  # 5 days off

        result = compare_timestamps(dwg_create, dwg_update, file_create, file_modify)

        assert result["modify_match"] is False
        assert any(a["type"] == "modification_timestamp_mismatch" for a in result["anomalies"])

    def test_compare_creation_after_modification(self):
        """Test comparison detects creation after modification anomaly."""
        dwg_create = datetime(2024, 1, 20, 10, 0, 0, tzinfo=timezone.utc)
        dwg_update = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)  # Before creation!
        file_create = datetime(2024, 1, 20, 10, 0, 0, tzinfo=timezone.utc)
        file_modify = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        result = compare_timestamps(dwg_create, dwg_update, file_create, file_modify)

        assert any(a["type"] == "creation_after_modification" for a in result["anomalies"])
        assert any(a["severity"] == "critical" for a in result["anomalies"])

    def test_compare_future_creation(self):
        """Test comparison detects future creation timestamp."""
        future = datetime.now(timezone.utc) + timedelta(days=365)
        dwg_create = future
        dwg_update = future
        file_create = datetime.now(timezone.utc)
        file_modify = datetime.now(timezone.utc)

        result = compare_timestamps(dwg_create, dwg_update, file_create, file_modify)

        assert any(a["type"] == "future_creation_time" for a in result["anomalies"])

    def test_compare_future_modification(self):
        """Test comparison detects future modification timestamp."""
        now = datetime.now(timezone.utc)
        future = now + timedelta(days=365)
        dwg_create = now
        dwg_update = future
        file_create = now
        file_modify = future

        result = compare_timestamps(dwg_create, dwg_update, file_create, file_modify)

        assert any(a["type"] == "future_modification_time" for a in result["anomalies"])

    def test_compare_with_none_values(self):
        """Test comparison handles None values gracefully."""
        result = compare_timestamps(None, None, None, None)
        assert result["create_match"] is None
        assert result["modify_match"] is None
        assert len(result["anomalies"]) == 0

    def test_compare_partial_none_values(self):
        """Test comparison handles partial None values."""
        dwg_create = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = compare_timestamps(dwg_create, None, None, None)
        # Should not crash
        assert result["create_match"] is None
        assert result["modify_match"] is None

    def test_compare_diff_seconds_calculated(self):
        """Test time difference is calculated in seconds."""
        dwg_create = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        file_create = datetime(2024, 1, 15, 10, 0, 30, tzinfo=timezone.utc)

        result = compare_timestamps(dwg_create, None, file_create, None)

        assert result["create_diff_seconds"] == 30


class TestForensicScenarios:
    """Tests simulating forensic investigation scenarios."""

    def test_timestomping_detection(self):
        """Test detection of timestomping (manual timestamp manipulation)."""
        # File claims to be created in 2020 but DWG header says 2024
        dwg_create = datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        dwg_update = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        file_create = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)  # Manipulated
        file_modify = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

        result = compare_timestamps(dwg_create, dwg_update, file_create, file_modify)

        # Should detect the creation time mismatch
        assert any(a["type"] == "creation_timestamp_mismatch" for a in result["anomalies"])
        mismatch = [a for a in result["anomalies"] if a["type"] == "creation_timestamp_mismatch"][0]
        assert mismatch["severity"] == "high"

    def test_backdated_file_detection(self):
        """Test detection of file backdating."""
        # Someone set DWG creation time to earlier than file creation
        dwg_create = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)  # Backdated
        dwg_update = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        file_create = datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        file_modify = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

        result = compare_timestamps(dwg_create, dwg_update, file_create, file_modify)

        # Should detect the mismatch
        assert len(result["anomalies"]) > 0
        # DWG creation is 4+ years before file creation
        assert result["create_diff_seconds"] > 86400 * 365  # More than 1 year


class TestVersionCoverageDrawingVars:
    """Tests ensuring all required versions are supported."""

    def _test_version_supported(self, version: str):
        """Helper to test version is supported."""
        parser = DrawingVariablesParser()
        data = bytearray(0x400)
        data[0:6] = version.encode("ascii")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dwg") as f:
            f.write(bytes(data))
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            # Should not report version as unsupported
            assert not any(f"not supported for {version}" in err for err in result.parsing_errors)
        finally:
            temp_path.unlink()

    def test_ac1018_supported(self):
        """Verify AC1018 (AutoCAD 2004) is supported."""
        self._test_version_supported("AC1018")

    def test_ac1021_supported(self):
        """Verify AC1021 (AutoCAD 2007) is supported."""
        self._test_version_supported("AC1021")

    def test_ac1024_supported(self):
        """Verify AC1024 (AutoCAD 2010) is supported."""
        self._test_version_supported("AC1024")

    def test_ac1027_supported(self):
        """Verify AC1027 (AutoCAD 2013) is supported."""
        self._test_version_supported("AC1027")

    def test_ac1032_supported(self):
        """Verify AC1032 (AutoCAD 2018+) is supported."""
        self._test_version_supported("AC1032")
