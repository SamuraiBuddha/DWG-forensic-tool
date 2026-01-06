"""
Custom exception classes for DWG forensic analysis.

This module defines the exception hierarchy for all error conditions
that can occur during DWG file analysis and forensic processing.
"""


class DWGForensicError(Exception):
    """
    Base exception class for all DWG forensic tool errors.

    All custom exceptions in this module inherit from this base class,
    allowing for broad exception handling when needed.

    Attributes:
        message: Human-readable error description
        details: Optional dictionary containing additional error context
    """

    def __init__(self, message: str, details: dict = None):
        """
        Initialize the base exception.

        Args:
            message: Error message describing what went wrong
            details: Optional dictionary with additional context
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        """Return a string representation of the exception."""
        if self.details:
            detail_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            return f"{self.message} ({detail_str})"
        return self.message


class UnsupportedVersionError(DWGForensicError):
    """
    Raised when a DWG file version is not supported by the forensic tool.

    The tool requires DWG files to be version R18 (AC1024) or later.
    This exception is raised when an earlier version is encountered.

    Attributes:
        version: The DWG version string that was detected (e.g., 'AC1015')
        version_name: Human-readable version name (e.g., 'R2000')
        min_supported: The minimum supported version string
        file_path: Optional path to the file that caused the error
    """

    def __init__(
        self,
        version: str,
        version_name: str = None,
        file_path: str = None,
        min_supported: str = "AC1024"
    ):
        """
        Initialize the unsupported version exception.

        Args:
            version: The detected DWG version string (e.g., 'AC1015')
            version_name: Human-readable version name (e.g., 'R2000')
            file_path: Optional path to the file
            min_supported: Minimum supported version (default: 'AC1024' / R18)
        """
        self.version = version
        self.version_name = version_name or version
        self.min_supported = min_supported
        self.file_path = file_path

        message = (
            f"Unsupported DWG version: {self.version_name} ({version}). "
            f"Minimum supported version is R18 ({min_supported})."
        )

        details = {
            "detected_version": version,
            "version_name": self.version_name,
            "min_supported": min_supported,
        }

        if file_path:
            details["file_path"] = file_path

        super().__init__(message, details)


class InvalidDWGError(DWGForensicError):
    """
    Raised when a file is not a valid DWG file.

    This exception is raised when:
    - The file does not start with a valid DWG magic number
    - The file structure is fundamentally corrupted
    - The file appears to be a different format entirely

    Attributes:
        file_path: Path to the invalid file
        reason: Specific reason why the file is invalid
        magic_bytes: The actual bytes found at the start of the file
    """

    def __init__(
        self,
        file_path: str = None,
        reason: str = None,
        magic_bytes: bytes = None
    ):
        """
        Initialize the invalid DWG exception.

        Args:
            file_path: Path to the file that failed validation
            reason: Specific reason for the failure
            magic_bytes: The actual bytes found (for diagnostic purposes)
        """
        self.file_path = file_path
        self.reason = reason or "File is not a valid DWG file"
        self.magic_bytes = magic_bytes

        if file_path:
            message = f"Invalid DWG file: {file_path}. {self.reason}"
        else:
            message = f"Invalid DWG file. {self.reason}"

        details = {"reason": self.reason}

        if file_path:
            details["file_path"] = file_path
        if magic_bytes:
            details["magic_bytes"] = magic_bytes.hex()

        super().__init__(message, details)


class CRCMismatchError(DWGForensicError):
    """
    Raised when CRC validation fails during DWG file parsing.

    DWG files include CRC checksums for data integrity verification.
    This exception indicates that computed CRC values do not match
    the stored values, suggesting file corruption or tampering.

    Attributes:
        section: The section or component where CRC mismatch occurred
        expected_crc: The CRC value stored in the file
        actual_crc: The CRC value computed from the data
        file_path: Optional path to the file
        offset: Optional byte offset where the mismatch occurred
    """

    def __init__(
        self,
        section: str,
        expected_crc: int,
        actual_crc: int,
        file_path: str = None,
        offset: int = None
    ):
        """
        Initialize the CRC mismatch exception.

        Args:
            section: Name of the section with CRC mismatch
            expected_crc: CRC value from the file
            actual_crc: Computed CRC value
            file_path: Optional path to the file
            offset: Optional byte offset of the mismatch
        """
        self.section = section
        self.expected_crc = expected_crc
        self.actual_crc = actual_crc
        self.file_path = file_path
        self.offset = offset

        message = (
            f"CRC mismatch in {section}: "
            f"expected 0x{expected_crc:08X}, got 0x{actual_crc:08X}"
        )

        details = {
            "section": section,
            "expected_crc": f"0x{expected_crc:08X}",
            "actual_crc": f"0x{actual_crc:08X}",
        }

        if file_path:
            details["file_path"] = file_path
        if offset is not None:
            details["offset"] = offset

        super().__init__(message, details)


class ParseError(DWGForensicError):
    """
    Raised when parsing of DWG file structure fails.

    This exception covers general parsing failures including:
    - Unexpected data structures
    - Truncated files
    - Invalid section headers
    - Malformed object definitions

    Attributes:
        section: The section being parsed when the error occurred
        file_path: Optional path to the file
        offset: Optional byte offset where parsing failed
        cause: Optional underlying exception that caused the parse error
    """

    def __init__(
        self,
        message: str,
        section: str = None,
        file_path: str = None,
        offset: int = None,
        cause: Exception = None
    ):
        """
        Initialize the parse error exception.

        Args:
            message: Description of the parse error
            section: Section being parsed when error occurred
            file_path: Optional path to the file
            offset: Optional byte offset of the error
            cause: Optional underlying exception
        """
        self.section = section
        self.file_path = file_path
        self.offset = offset
        self.cause = cause

        full_message = f"Parse error: {message}"
        if section:
            full_message += f" (in section: {section})"

        details = {}
        if section:
            details["section"] = section
        if file_path:
            details["file_path"] = file_path
        if offset is not None:
            details["offset"] = offset
        if cause:
            details["cause"] = str(cause)

        super().__init__(full_message, details)


class IntakeError(DWGForensicError):
    """
    Raised when file intake and validation fails.

    This exception is raised during the initial file intake process when:
    - The file cannot be accessed or read
    - The file path is invalid
    - Permissions are insufficient
    - The file is locked by another process

    Attributes:
        file_path: Path to the file that failed intake
        reason: Specific reason for the intake failure
        cause: Optional underlying exception (e.g., IOError, PermissionError)
    """

    def __init__(
        self,
        file_path: str,
        reason: str = None,
        cause: Exception = None
    ):
        """
        Initialize the intake error exception.

        Args:
            file_path: Path to the file that failed intake
            reason: Specific reason for the failure
            cause: Optional underlying exception
        """
        self.file_path = file_path
        self.reason = reason or "File intake failed"
        self.cause = cause

        message = f"Failed to intake file: {file_path}. {self.reason}"

        details = {
            "file_path": file_path,
            "reason": self.reason,
        }

        if cause:
            details["cause"] = str(cause)
            details["cause_type"] = type(cause).__name__

        super().__init__(message, details)
