"""
Utility modules for DWG forensic analysis.

This package contains shared utilities including custom exceptions,
helper functions, audit logging, and common data structures used across the forensic tool.
"""

from dwg_forensic.utils.audit import AuditLevel, AuditLogger, get_audit_logger
from dwg_forensic.utils.exceptions import (
    CRCMismatchError,
    DWGForensicError,
    IntakeError,
    InvalidDWGError,
    ParseError,
    UnsupportedVersionError,
)

__all__ = [
    # Exceptions
    "DWGForensicError",
    "UnsupportedVersionError",
    "InvalidDWGError",
    "CRCMismatchError",
    "ParseError",
    "IntakeError",
    # Audit Logging
    "AuditLevel",
    "AuditLogger",
    "get_audit_logger",
]
