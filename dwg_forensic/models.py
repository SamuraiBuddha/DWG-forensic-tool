"""
Pydantic data models for DWG forensic analysis.

This module defines all data structures used for analyzing AutoCAD DWG files
for forensic purposes. Supports R18+ versions only (AC1024, AC1027, AC1032).
"""

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

if TYPE_CHECKING:
    from dwg_forensic.knowledge.models import ForensicKnowledge


class RiskLevel(str, Enum):
    """Risk level classification for forensic analysis."""
    INFO = "INFO"  # Informational only - not a risk
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AnomalyType(str, Enum):
    """Types of anomalies detected during forensic analysis."""
    VERSION_MISMATCH = "VERSION_MISMATCH"
    TIMESTAMP_ANOMALY = "TIMESTAMP_ANOMALY"
    CRC_MISMATCH = "CRC_MISMATCH"
    SUSPICIOUS_EDIT_TIME = "SUSPICIOUS_EDIT_TIME"
    OTHER = "OTHER"
    # Advanced timestamp manipulation detection
    TDINDWG_EXCEEDS_SPAN = "TDINDWG_EXCEEDS_SPAN"
    VERSION_ANACHRONISM = "VERSION_ANACHRONISM"
    TIMEZONE_DISCREPANCY = "TIMEZONE_DISCREPANCY"
    TIMESTAMP_PRECISION_ANOMALY = "TIMESTAMP_PRECISION_ANOMALY"
    # NTFS Cross-Validation Anomalies (Smoking Gun Indicators)
    NTFS_SI_FN_MISMATCH = "NTFS_SI_FN_MISMATCH"  # Definitive timestomping proof
    NTFS_NANOSECOND_TRUNCATION = "NTFS_NANOSECOND_TRUNCATION"  # Tool signature
    NTFS_CREATION_AFTER_MODIFICATION = "NTFS_CREATION_AFTER_MODIFICATION"  # Impossible
    DWG_NTFS_CREATION_CONTRADICTION = "DWG_NTFS_CREATION_CONTRADICTION"  # Backdating proof (DEPRECATED - use FILE_TRANSFER_DETECTED)
    DWG_NTFS_CREATION_DIFFERENCE = "DWG_NTFS_CREATION_DIFFERENCE"  # Normal file transfer time difference
    DWG_NTFS_MODIFICATION_CONTRADICTION = "DWG_NTFS_MODIFICATION_CONTRADICTION"


class TamperingIndicatorType(str, Enum):
    """Types of tampering indicators detected in DWG files."""
    CRC_MODIFIED = "CRC_MODIFIED"
    TIMESTAMP_BACKDATED = "TIMESTAMP_BACKDATED"
    VERSION_INCONSISTENCY = "VERSION_INCONSISTENCY"
    SUSPICIOUS_PATTERN = "SUSPICIOUS_PATTERN"
    OTHER = "OTHER"
    # Advanced timestamp manipulation indicators
    TDINDWG_MANIPULATION = "TDINDWG_MANIPULATION"
    VERSION_ANACHRONISM = "VERSION_ANACHRONISM"
    TIMEZONE_MANIPULATION = "TIMEZONE_MANIPULATION"
    EDUCATIONAL_VERSION = "EDUCATIONAL_VERSION"
    # NTFS Cross-Validation Tampering Indicators (Definitive Proof)
    NTFS_TIMESTOMPING_DETECTED = "NTFS_TIMESTOMPING_DETECTED"  # SI/FN mismatch
    NTFS_TOOL_SIGNATURE = "NTFS_TOOL_SIGNATURE"  # Nanosecond truncation
    NTFS_IMPOSSIBLE_TIMESTAMP = "NTFS_IMPOSSIBLE_TIMESTAMP"  # Created > Modified
    DWG_NTFS_CONTRADICTION = "DWG_NTFS_CONTRADICTION"  # Internal vs filesystem mismatch
    PROVEN_BACKDATING = "PROVEN_BACKDATING"  # Definitive backdating evidence (DEPRECATED - use FILE_TRANSFER_DETECTED)
    FILE_TRANSFER_DETECTED = "FILE_TRANSFER_DETECTED"  # Normal file transfer/copy context


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
    maintenance_version: Optional[int] = Field(None, description="Maintenance release version number (None for unknown versions)", ge=0)
    preview_address: Optional[int] = Field(None, description="Offset to preview image data (None for unknown versions)", ge=0)
    codepage: Optional[int] = Field(None, description="Code page identifier (None for unknown versions)", ge=0)
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
    # Forensic context fields
    is_revit_export: bool = Field(
        default=False,
        description="Whether file is a Revit export (CRC=0 is expected for Revit)"
    )
    is_oda_export: bool = Field(
        default=False,
        description="Whether file was created by ODA SDK-based software (may have CRC=0)"
    )
    forensic_notes: Optional[str] = Field(
        None,
        description="Forensic context explaining CRC validation result"
    )
    validation_skipped: bool = Field(
        default=False,
        description="Whether CRC validation was skipped (e.g., unsupported version)"
    )


class ApplicationFingerprint(BaseModel):
    """Fingerprint of the CAD application that created/modified the DWG file.

    Forensic significance: Identifying the authoring application is informational only.
    Third-party CAD tools (BricsCAD, DraftSight, LibreCAD, etc.) are legitimate and
    commonly used. Application origin does NOT indicate tampering.
    """
    detected_application: str = Field(
        ...,
        description="Identified CAD application (e.g., 'autocad', 'bricscad', 'librecad')"
    )
    confidence: float = Field(
        ...,
        description="Detection confidence level (0.0-1.0)",
        ge=0.0,
        le=1.0
    )
    is_autodesk: bool = Field(
        False,
        description="Whether file was created by genuine Autodesk software"
    )
    is_oda_based: bool = Field(
        False,
        description="Whether application uses ODA (Open Design Alliance) SDK"
    )
    forensic_summary: str = Field(
        "",
        description="Summary of forensic significance of the fingerprint"
    )
    # Legacy fields for backward compatibility
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

    # External Reference Paths - May reveal file origin
    xref_paths: Optional[List[str]] = Field(
        default=None,
        description="External reference (xref) paths found in the file"
    )
    network_paths_detected: Optional[List[str]] = Field(
        default=None,
        description="Network paths (UNC or URLs) that may reveal original file location"
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


class NTFSTimestampAnalysis(BaseModel):
    """NTFS filesystem timestamp analysis for cross-validation.

    This is critical for detecting timestomping attacks where internal
    DWG timestamps may have been manipulated. NTFS provides multiple
    timestamp sources that are harder to forge.
    """
    # Standard Information timestamps (visible to users, can be timestomped)
    si_created: Optional[datetime] = Field(
        None,
        description="$STANDARD_INFORMATION created timestamp (can be timestomped)"
    )
    si_modified: Optional[datetime] = Field(
        None,
        description="$STANDARD_INFORMATION modified timestamp (can be timestomped)"
    )
    si_accessed: Optional[datetime] = Field(
        None,
        description="$STANDARD_INFORMATION accessed timestamp"
    )

    # Nanosecond precision data (critical for forensic analysis)
    si_created_nanoseconds: Optional[int] = Field(
        None,
        description="Nanosecond component of created timestamp (0 = indicates truncation)"
    )
    si_modified_nanoseconds: Optional[int] = Field(
        None,
        description="Nanosecond component of modified timestamp (0 = indicates truncation)"
    )

    # File Name timestamps (kernel-only, resistant to timestomping)
    fn_created: Optional[datetime] = Field(
        None,
        description="$FILE_NAME created timestamp (kernel-protected, cannot be timestomped)"
    )
    fn_modified: Optional[datetime] = Field(
        None,
        description="$FILE_NAME modified timestamp (kernel-protected)"
    )

    # Forensic findings
    timestomping_detected: bool = Field(
        default=False,
        description="DEFINITIVE: SI timestamps earlier than FN timestamps proves timestomping"
    )
    nanosecond_truncation: bool = Field(
        default=False,
        description="Timestamps ending in .0000000 indicate manipulation tool usage"
    )
    impossible_timestamps: bool = Field(
        default=False,
        description="Created > Modified (INFORMATIONAL: indicates file was copied - NORMAL Windows behavior)"
    )

    # Cross-validation with DWG internal timestamps
    dwg_ntfs_contradiction: bool = Field(
        default=False,
        description="DWG internal timestamps contradict NTFS timestamps"
    )
    contradiction_details: Optional[str] = Field(
        None,
        description="Detailed explanation of timestamp contradictions"
    )

    # Forensic conclusion
    forensic_conclusion: Optional[str] = Field(
        None,
        description="Expert forensic conclusion based on NTFS analysis"
    )


class ForensicAnalysis(BaseModel):
    """Complete forensic analysis results for a DWG file."""
    file_info: FileInfo = Field(..., description="Basic file information")
    header_analysis: HeaderAnalysis = Field(..., description="DWG header analysis results")
    crc_validation: CRCValidation = Field(..., description="CRC validation results")
    metadata: Optional[DWGMetadata] = Field(None, description="File metadata")
    ntfs_analysis: Optional[NTFSTimestampAnalysis] = Field(
        None,
        description="NTFS filesystem timestamp analysis for cross-validation"
    )
    file_provenance: Optional[Dict[str, Any]] = Field(
        None,
        description="File origin and creation context (Revit export, ODA tool, file transfer, etc.)"
    )
    application_fingerprint: Optional[ApplicationFingerprint] = Field(
        None,
        description="Application fingerprint"
    )
    revit_detection: Optional[Dict[str, Any]] = Field(
        None,
        description="Revit export detection results (for interpreting CRC and timestamp behavior)"
    )
    structure_analysis: Optional[Dict[str, Any]] = Field(
        None,
        description="DWG structure analysis - detects non-standard or stripped files"
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
    forensic_knowledge: Optional[Dict[str, Any]] = Field(
        None,
        description="Forensic knowledge from graph database (standards, cases, techniques)"
    )
    llm_narrative: Optional[str] = Field(
        None,
        description="LLM-generated expert narrative analysis of the forensic findings"
    )
    llm_model_used: Optional[str] = Field(
        None,
        description="LLM model used for narrative generation (e.g., 'mistral', 'llama3')"
    )
    # Smoking Gun Analysis - DEFINITIVE proof filtering
    smoking_gun_report: Optional[Dict[str, Any]] = Field(
        None,
        description="Smoking gun report with ONLY definitive proof of tampering"
    )
    has_definitive_proof: bool = Field(
        default=False,
        description="True if mathematically impossible conditions prove tampering"
    )
    # LLM Forensic Reasoning - LLM evaluates evidence, not just generates narratives
    llm_reasoning: Optional[Dict[str, Any]] = Field(
        None,
        description="LLM forensic reasoning about evidence significance (smoking guns vs red herrings)"
    )
    # Forensic error tracking - ALL errors are potential evidence in forensic analysis
    analysis_errors: Optional[List[Dict[str, Any]]] = Field(
        None,
        description="List of all errors encountered during analysis (forensic audit trail)"
    )
    analysis_timestamp: datetime = Field(
        default_factory=datetime.now,
        description="Timestamp when analysis was completed"
    )
    analyzer_version: str = Field(..., description="Version of the forensic analyzer")
