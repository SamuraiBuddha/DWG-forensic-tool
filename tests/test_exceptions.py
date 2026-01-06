"""Tests for custom exception classes."""

import pytest

from dwg_forensic.utils.exceptions import (
    CRCMismatchError,
    DWGForensicError,
    IntakeError,
    InvalidDWGError,
    ParseError,
    UnsupportedVersionError,
)


class TestDWGForensicError:
    """Tests for base DWGForensicError."""

    def test_basic_error(self):
        """Test basic error creation."""
        error = DWGForensicError("Test error")
        assert str(error) == "Test error"
        assert error.message == "Test error"
        assert error.details == {}

    def test_error_with_details(self):
        """Test error with details."""
        error = DWGForensicError("Test error", {"key": "value"})
        assert "key=value" in str(error)
        assert error.details == {"key": "value"}


class TestUnsupportedVersionError:
    """Tests for UnsupportedVersionError."""

    def test_basic_unsupported_version(self):
        """Test basic unsupported version error."""
        error = UnsupportedVersionError(version="AC1015")
        assert "AC1015" in str(error)
        assert error.version == "AC1015"
        assert error.min_supported == "AC1024"

    def test_with_version_name(self):
        """Test with version name."""
        error = UnsupportedVersionError(
            version="AC1015",
            version_name="AutoCAD 2000",
        )
        assert "AutoCAD 2000" in str(error)
        assert error.version_name == "AutoCAD 2000"

    def test_with_file_path(self):
        """Test with file path."""
        error = UnsupportedVersionError(
            version="AC1015",
            file_path="/path/to/file.dwg",
        )
        assert error.file_path == "/path/to/file.dwg"
        assert "file_path" in error.details


class TestInvalidDWGError:
    """Tests for InvalidDWGError."""

    def test_basic_invalid_error(self):
        """Test basic invalid DWG error."""
        error = InvalidDWGError(file_path="/path/to/file.dwg")
        assert "Invalid DWG file" in str(error)
        assert error.file_path == "/path/to/file.dwg"

    def test_with_reason(self):
        """Test with specific reason."""
        error = InvalidDWGError(
            file_path="/path/to/file.dwg",
            reason="File is too small",
        )
        assert "File is too small" in str(error)
        assert error.reason == "File is too small"

    def test_with_magic_bytes(self):
        """Test with magic bytes."""
        error = InvalidDWGError(
            file_path="/path/to/file.dwg",
            magic_bytes=b"\x00\x01\x02",
        )
        assert error.magic_bytes == b"\x00\x01\x02"
        assert "magic_bytes" in error.details


class TestCRCMismatchError:
    """Tests for CRCMismatchError."""

    def test_basic_crc_error(self):
        """Test basic CRC mismatch error."""
        error = CRCMismatchError(
            section="header",
            expected_crc=0x12345678,
            actual_crc=0xDEADBEEF,
        )
        assert "0x12345678" in str(error)
        assert "0xDEADBEEF" in str(error)
        assert error.section == "header"

    def test_with_file_path_and_offset(self):
        """Test with file path and offset."""
        error = CRCMismatchError(
            section="header",
            expected_crc=0x12345678,
            actual_crc=0xDEADBEEF,
            file_path="/path/to/file.dwg",
            offset=0x68,
        )
        assert error.file_path == "/path/to/file.dwg"
        assert error.offset == 0x68


class TestParseError:
    """Tests for ParseError."""

    def test_basic_parse_error(self):
        """Test basic parse error."""
        error = ParseError("Unexpected data format")
        assert "Parse error" in str(error)
        assert "Unexpected data format" in str(error)

    def test_with_section(self):
        """Test with section."""
        error = ParseError("Unexpected data", section="AcDb:Header")
        assert "AcDb:Header" in str(error)
        assert error.section == "AcDb:Header"

    def test_with_cause(self):
        """Test with underlying cause."""
        cause = ValueError("Original error")
        error = ParseError("Parse failed", cause=cause)
        assert error.cause == cause


class TestIntakeError:
    """Tests for IntakeError."""

    def test_basic_intake_error(self):
        """Test basic intake error."""
        error = IntakeError(file_path="/path/to/file.dwg")
        assert "Failed to intake" in str(error)
        assert error.file_path == "/path/to/file.dwg"

    def test_with_reason_and_cause(self):
        """Test with reason and cause."""
        cause = PermissionError("Access denied")
        error = IntakeError(
            file_path="/path/to/file.dwg",
            reason="Permission denied",
            cause=cause,
        )
        assert "Permission denied" in str(error)
        assert error.cause == cause
        assert error.details["cause_type"] == "PermissionError"


class TestExceptionHierarchy:
    """Tests for exception hierarchy."""

    def test_all_inherit_from_base(self):
        """Test that all exceptions inherit from DWGForensicError."""
        exceptions = [
            UnsupportedVersionError("AC1015"),
            InvalidDWGError(),
            CRCMismatchError("header", 0, 1),
            ParseError("test"),
            IntakeError("/path"),
        ]
        for exc in exceptions:
            assert isinstance(exc, DWGForensicError)

    def test_can_catch_with_base_class(self):
        """Test that exceptions can be caught with base class."""
        with pytest.raises(DWGForensicError):
            raise UnsupportedVersionError("AC1015")
