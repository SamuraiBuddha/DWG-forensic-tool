"""
Pydantic data models for DWG forensic analysis.

This module defines all data structures used for analyzing AutoCAD DWG files
for forensic purposes. Supports R18+ versions only (AC1024, AC1027, AC1032).
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class RiskLevel(str, Enum):
    """Risk level classification for forensic analysis."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AnomalyType(str, Enum):
    """Types of anomalies detected during forensic analysis."""
    VERSION_MISMATCH = "VERSION_MISMATCH"
    TIMESTAMP_ANOMALY = "TIMESTAMP_ANOMALY"
    CRC_MISMATCH = "CRC_MISMATCH"
    WATERMARK_INVALID = "WATERMARK_INVALID"
    SUSPICIOUS_EDIT_TIME = "SUSPICIOUS_EDIT_TIME"
    OTHER = "OTHER"
    # Advanced timestamp manipulation detection
    TDINDWG_EXCEEDS_SPAN = "TDINDWG_EXCEEDS_SPAN"
    VERSION_ANACHRONISM = "VERSION_ANACHRONISM"
    TIMEZONE_DISCREPANCY = "TIMEZONE_DISCREPANCY"
    TIMESTAMP_PRECISION_ANOMALY = "TIMESTAMP_PRECISION_ANOMALY"


class TamperingIndicatorType(str, Enum):
    """Types of tampering indicators detected in DWG files."""
    CRC_MODIFIED = "CRC_MODIFIED"
    WATERMARK_REMOVED = "WATERMARK_REMOVED"
    TIMESTAMP_BACKDATED = "TIMESTAMP_BACKDATED"
    VERSION_INCONSISTENCY = "VERSION_INCONSISTENCY"
    SUSPICIOUS_PATTERN = "SUSPICIOUS_PATTERN"
    OTHER = "OTHER"
    # Advanced timestamp manipulation indicators
    TDINDWG_MANIPULATION = "TDINDWG_MANIPULATION"
    VERSION_ANACHRONISM = "VERSION_ANACHRONISM"
    TIMEZONE_MANIPULATION = "TIMEZONE_MANIPULATION"
    EDUCATIONAL_VERSION = "EDUCATIONAL_VERSION"


class FileInfo(BaseModel):
    """Basic file information captured at intake."""
    filename: str = Field(..., description="Name of the DWG file")
    sha256: str = Field(..., description="SHA-256 hash of the file", min_length=64, max_length=64)
    file_size_bytes: int = Field(..., description="File size in bytes", ge=0)
    intake_timestamp: datetime = Field(..., description="Timestamp when file was received for analysis")

    @field_validator('sha256')
    @classmethod
    def validate_sha256(cls, v: str) -> str:
        """Validate SHA-256 hash format."""
        if not all(c in '0123456789abcdefABCDEF' for c in v):
            raise ValueError("SHA-256 hash must be hexadecimal")
        return v.lower()


class HeaderAnalysis(BaseModel):
    """DWG file header analysis results."""
    version_string: str = Field(..., description="Raw version string from header (e.g., 'AC1032')")
    version_name: str = Field(..., description="Human-readable version name (e.g., 'AutoCAD 2018+')")
    maintenance_version: int = Field(..., description="Maintenance release version number", ge=0)
    preview_address: int = Field(..., description="Offset to preview image data", ge=0)
    codepage: int = Field(..., description="Code page identifier", ge=0)
    is_supported: bool = Field(..., description="Whether this version is supported for analysis (R18+ only)")


class SectionCRCResult(BaseModel):
    """CRC validation result for a specific section."""
    section_name: str = Field(..., description="Name of the section")
    offset: int = Field(..., description="Byte offset of the section in file", ge=0)
    stored_crc: str = Field(..., description="CRC value stored in file (hex string with 0x prefix)")
    calculated_crc: str = Field(..., description="CRC value calculated from data (hex string with 0x prefix)")
    is_valid: bool = Field(..., description="Whether stored and calculated CRC match")


class CRCValidation(BaseModel):
    """Overall CRC validation results for the DWG file."""
    header_crc_stored: str = Field(..., description="CRC stored in file header (hex string with 0x prefix)")
    header_crc_calculated: str = Field(..., description="CRC calculated from header data (hex string with 0x prefix)")
    is_valid: bool = Field(..., description="Whether overall file CRC is valid")
    section_results: list[SectionCRCResult] = Field(
        default_factory=list,
        description="CRC validation results for individual sections"
    )


class TrustedDWGAnalysis(BaseModel):
    """Analysis of TrustedDWG watermark and authentication."""
    watermark_present: bool = Field(..., description="Whether a TrustedDWG watermark was found")
    watermark_text: Optional[str] = Field(None, description="Text content of the watermark")
    watermark_valid: bool = Field(..., description="Whether the watermark signature is valid")
    application_origin: Optional[str] = Field(None, description="Originating application from watermark")
    watermark_offset: Optional[int] = Field(None, description="Byte offset of watermark in file", ge=0)


class ApplicationFingerprint(BaseModel):
    """Fingerprint of the application that created/modified the file."""
    created_by: Optional[str] = Field(None, description="Application that created the file")
    application_id: Optional[str] = Field(None, description="Application identifier code")
    build_number: Optional[str] = Field(None, description="Build number of the application")


class DWGMetadata(BaseModel):
    """Metadata extracted from DWG file properties.

    Includes Modified Julian Date (MJD) timestamp fields for forensic analysis.
    MJD format: integer part = days since Nov 17, 1858; decimal = fraction of day.
    """
    title: Optional[str] = Field(None, description="Document title")
    author: Optional[str] = Field(None, description="Document author")
    last_saved_by: Optional[str] = Field(None, description="User who last saved the file")
    created_date: Optional[datetime] = Field(None, description="Document creation timestamp")
    modified_date: Optional[datetime] = Field(None, description="Last modification timestamp")
    revision_number: Optional[int] = Field(None, description="Revision number", ge=0)
    total_editing_time_hours: Optional[float] = Field(
        None,
        description="Total editing time in hours",
        ge=0.0
    )
    comments: Optional[str] = Field(None, description="Document comments")
    keywords: Optional[str] = Field(None, description="Document keywords")

    # MJD Timestamp Fields - Critical for forensic timestamp manipulation detection
    tdcreate: Optional[float] = Field(
        None,
        description="TDCREATE - Local creation date/time as Modified Julian Date"
    )
    tdupdate: Optional[float] = Field(
        None,
        description="TDUPDATE - Local last-save date/time as Modified Julian Date"
    )
    tducreate: Optional[float] = Field(
        None,
        description="TDUCREATE - UTC creation time as Modified Julian Date"
    )
    tduupdate: Optional[float] = Field(
        None,
        description="TDUUPDATE - UTC last-save time as Modified Julian Date"
    )
    tdindwg: Optional[float] = Field(
        None,
        description="TDINDWG - Cumulative editing time as MJD fraction (read-only, cannot exceed calendar span)"
    )
    tdusrtimer: Optional[float] = Field(
        None,
        description="TDUSRTIMER - User-resettable timer as MJD fraction"
    )

    # GUID Fields - File lineage tracking
    fingerprint_guid: Optional[str] = Field(
        None,
        description="FINGERPRINTGUID - Unique file ID that persists across copies and saves"
    )
    version_guid: Optional[str] = Field(
        None,
        description="VERSIONGUID - Changes with each save operation"
    )

    # User Identity Artifacts
    login_name: Optional[str] = Field(
        None,
        description="LOGINNAME - Windows username who last saved the file"
    )
    educational_watermark: Optional[bool] = Field(
        None,
        description="Whether Educational Version watermark is present (student license)"
    )


class Anomaly(BaseModel):
    """Detected anomaly in DWG file analysis."""
    anomaly_type: AnomalyType = Field(..., description="Type of anomaly detected")
    description: str = Field(..., description="Human-readable description of the anomaly")
    severity: RiskLevel = Field(..., description="Severity level of the anomaly")
    details: dict = Field(
        default_factory=dict,
        description="Additional details about the anomaly"
    )


class TamperingIndicator(BaseModel):
    """Indicator of potential file tampering."""
    indicator_type: TamperingIndicatorType = Field(..., description="Type of tampering indicator")
    description: str = Field(..., description="Description of the tampering indicator")
    confidence: float = Field(
        ...,
        description="Confidence level (0.0 to 1.0)",
        ge=0.0,
        le=1.0
    )
    evidence: str = Field(..., description="Evidence supporting this indicator")


class RiskAssessment(BaseModel):
    """Overall risk assessment for the analyzed DWG file."""
    overall_risk: RiskLevel = Field(..., description="Overall risk level classification")
    factors: list[str] = Field(
        default_factory=list,
        description="List of factors contributing to risk assessment"
    )
    recommendation: str = Field(..., description="Recommended action based on risk assessment")


class ForensicAnalysis(BaseModel):
    """Complete forensic analysis results for a DWG file."""
    file_info: FileInfo = Field(..., description="Basic file information")
    header_analysis: HeaderAnalysis = Field(..., description="DWG header analysis results")
    trusted_dwg: TrustedDWGAnalysis = Field(..., description="TrustedDWG watermark analysis")
    crc_validation: CRCValidation = Field(..., description="CRC validation results")
    metadata: Optional[DWGMetadata] = Field(None, description="File metadata")
    application_fingerprint: Optional[ApplicationFingerprint] = Field(
        None,
        description="Application fingerprint"
    )
    anomalies: list[Anomaly] = Field(
        default_factory=list,
        description="List of detected anomalies"
    )
    tampering_indicators: list[TamperingIndicator] = Field(
        default_factory=list,
        description="List of tampering indicators"
    )
    risk_assessment: RiskAssessment = Field(..., description="Overall risk assessment")
    analysis_timestamp: datetime = Field(
        default_factory=datetime.now,
        description="Timestamp when analysis was completed"
    )
    analyzer_version: str = Field(..., description="Version of the forensic analyzer")
