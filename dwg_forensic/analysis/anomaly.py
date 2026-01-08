"""
DWG Forensic Tool - Anomaly Detection Module

Implements anomaly detection per PRD requirements:
- FR-ANOMALY-001: Timestamp anomaly detection
- FR-ANOMALY-002: Version anomaly detection
- FR-ANOMALY-003: Structural anomaly detection

Advanced Timestamp Manipulation Detection:
- TDINDWG vs calendar span detection
- Version anachronism detection
- UTC/local timezone discrepancy detection
- Timestamp precision anomaly detection
- Educational version watermark detection
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any, TYPE_CHECKING

from dwg_forensic.models import (
    Anomaly,
    AnomalyType,
    RiskLevel,
    DWGMetadata,
    HeaderAnalysis,
)
from dwg_forensic.analysis.version_dates import (
    get_version_release_date,
    get_version_name,
    is_date_before_version_release,
    get_anachronism_details,
)

if TYPE_CHECKING:
    from dwg_forensic.parsers.timestamp import TimestampData


class AnomalyDetector:
    """
    Detects anomalies in DWG files including timestamp inconsistencies,
    version mismatches, and structural issues.
    """

    def __init__(self):
        """Initialize the anomaly detector."""
        pass

    def detect_timestamp_anomalies(
        self, metadata: DWGMetadata, file_path: Path
    ) -> List[Anomaly]:
        """
        Detect timestamp-related anomalies in DWG files.

        Implements FR-ANOMALY-001:
        - Created date > Modified date
        - Modified date in the future
        - Editing time inconsistent with date range
        - Filesystem timestamps don't match internal timestamps

        Args:
            metadata: DWG metadata containing timestamp information
            file_path: Path to the DWG file for filesystem comparison

        Returns:
            List of detected timestamp anomalies
        """
        anomalies: List[Anomaly] = []
        now = datetime.now(timezone.utc)

        # Get filesystem timestamps
        try:
            fs_stats = os.stat(file_path)
            fs_modified = datetime.fromtimestamp(fs_stats.st_mtime, tz=timezone.utc)
        except OSError:
            fs_modified = None

        # Check 1: Created date > Modified date (TAMPER-005)
        if metadata.created_date and metadata.modified_date:
            # Ensure both are timezone-aware for comparison
            created = metadata.created_date
            modified = metadata.modified_date

            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            if modified.tzinfo is None:
                modified = modified.replace(tzinfo=timezone.utc)

            if created > modified:
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.TIMESTAMP_ANOMALY,
                        description="Created date is later than modified date - possible timestamp manipulation",
                        severity=RiskLevel.CRITICAL,
                        details={
                            "created_date": created.isoformat(),
                            "modified_date": modified.isoformat(),
                            "difference_seconds": (created - modified).total_seconds(),
                        },
                    )
                )

        # Check 2: Modified date in the future (TAMPER-006)
        if metadata.modified_date:
            modified = metadata.modified_date
            if modified.tzinfo is None:
                modified = modified.replace(tzinfo=timezone.utc)

            if modified > now:
                diff_seconds = (modified - now).total_seconds()
                # Allow 5 minutes grace for clock skew
                if diff_seconds > 300:
                    anomalies.append(
                        Anomaly(
                            anomaly_type=AnomalyType.TIMESTAMP_ANOMALY,
                            description="Modified date is in the future - possible timestamp manipulation",
                            severity=RiskLevel.CRITICAL,
                            details={
                                "modified_date": modified.isoformat(),
                                "current_time": now.isoformat(),
                                "seconds_in_future": diff_seconds,
                            },
                        )
                    )

        # Check 3: Editing time inconsistent with date range (TAMPER-007)
        if (
            metadata.total_editing_time_hours is not None
            and metadata.created_date
            and metadata.modified_date
        ):
            created = metadata.created_date
            modified = metadata.modified_date

            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            if modified.tzinfo is None:
                modified = modified.replace(tzinfo=timezone.utc)

            time_span_hours = (modified - created).total_seconds() / 3600
            edit_hours = metadata.total_editing_time_hours

            # Edit time cannot exceed total elapsed time
            if edit_hours > time_span_hours * 1.1:  # 10% tolerance
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.SUSPICIOUS_EDIT_TIME,
                        description="Total editing time exceeds time span between creation and modification",
                        severity=RiskLevel.HIGH,
                        details={
                            "total_editing_hours": edit_hours,
                            "time_span_hours": time_span_hours,
                            "excess_hours": edit_hours - time_span_hours,
                        },
                    )
                )

        # Check 4: Filesystem vs internal timestamp mismatch
        if metadata.modified_date and fs_modified:
            internal_modified = metadata.modified_date
            if internal_modified.tzinfo is None:
                internal_modified = internal_modified.replace(tzinfo=timezone.utc)

            diff_seconds = abs((internal_modified - fs_modified).total_seconds())
            # Allow 5 minute tolerance
            if diff_seconds > 300:
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.TIMESTAMP_ANOMALY,
                        description="Internal modified date doesn't match filesystem timestamp",
                        severity=RiskLevel.MEDIUM,
                        details={
                            "internal_modified": internal_modified.isoformat(),
                            "filesystem_modified": fs_modified.isoformat(),
                            "difference_seconds": diff_seconds,
                        },
                    )
                )

        return anomalies

    def detect_version_anomalies(
        self, header: HeaderAnalysis, file_path: Path
    ) -> List[Anomaly]:
        """
        Detect version-related anomalies in DWG files.

        Implements FR-ANOMALY-002:
        - Compare header version vs. internal object versions
        - Flag downgraded files (newer objects in older format)
        - Flag version mismatches

        Args:
            header: Header analysis containing version information
            file_path: Path to the DWG file

        Returns:
            List of detected version anomalies
        """
        anomalies: List[Anomaly] = []

        # Check if version is supported
        if not header.is_supported:
            anomalies.append(
                Anomaly(
                    anomaly_type=AnomalyType.VERSION_MISMATCH,
                    description=f"Unsupported DWG version: {header.version_string}",
                    severity=RiskLevel.MEDIUM,
                    details={
                        "version_string": header.version_string,
                        "version_name": header.version_name,
                    },
                )
            )

        # Check for version marker inconsistencies
        try:
            with open(file_path, "rb") as f:
                file_data = f.read(min(65536, file_path.stat().st_size))  # First 64KB

            version_markers = self._find_version_markers(file_data)

            if len(version_markers) > 1:
                # Multiple different version markers found
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.VERSION_MISMATCH,
                        description="Multiple version markers found - possible version downgrade",
                        severity=RiskLevel.HIGH,
                        details={
                            "header_version": header.version_string,
                            "found_markers": list(version_markers),
                        },
                    )
                )
        except Exception as e:
            anomalies.append(
                Anomaly(
                    anomaly_type=AnomalyType.OTHER,
                    description=f"Error during version analysis: {str(e)}",
                    severity=RiskLevel.LOW,
                    details={"error": str(e)},
                )
            )

        return anomalies

    def detect_structural_anomalies(self, file_path: Path) -> List[Anomaly]:
        """
        Detect structural anomalies in DWG files.

        Implements FR-ANOMALY-003:
        - Detect unusual padding or slack space
        - Detect incomplete sections
        - Basic structural integrity checks

        Args:
            file_path: Path to the DWG file

        Returns:
            List of detected structural anomalies
        """
        anomalies: List[Anomaly] = []

        try:
            file_size = file_path.stat().st_size

            # Check minimum valid size
            if file_size < 108:  # Minimum DWG header size
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.OTHER,
                        description="File too small to be a valid DWG file",
                        severity=RiskLevel.CRITICAL,
                        details={
                            "file_size_bytes": file_size,
                            "minimum_required": 108,
                        },
                    )
                )
                return anomalies

            with open(file_path, "rb") as f:
                file_data = f.read()

            # Check for excessive null padding (TAMPER-012)
            null_ratio = self._calculate_null_ratio(file_data)
            if null_ratio > 0.3:  # More than 30% null bytes
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.OTHER,
                        description="Excessive null byte padding detected - possible hidden data or corruption",
                        severity=RiskLevel.MEDIUM,
                        details={
                            "null_ratio": round(null_ratio * 100, 2),
                            "file_size_bytes": file_size,
                        },
                    )
                )

            # Check for unusual patterns in slack space
            slack_issues = self._check_slack_space(file_data)
            anomalies.extend(slack_issues)

        except Exception as e:
            anomalies.append(
                Anomaly(
                    anomaly_type=AnomalyType.OTHER,
                    description=f"Error during structural analysis: {str(e)}",
                    severity=RiskLevel.LOW,
                    details={"error": str(e)},
                )
            )

        return anomalies

    def detect_all(
        self,
        header: HeaderAnalysis,
        metadata: Optional[DWGMetadata],
        file_path: Path,
    ) -> List[Anomaly]:
        """
        Detect all types of anomalies in a DWG file.

        Args:
            header: Header analysis results
            metadata: DWG metadata (optional)
            file_path: Path to the DWG file

        Returns:
            List of all detected anomalies
        """
        all_anomalies: List[Anomaly] = []

        # Version anomalies
        version_anomalies = self.detect_version_anomalies(header, file_path)
        all_anomalies.extend(version_anomalies)

        # Timestamp anomalies (only if metadata available)
        if metadata:
            timestamp_anomalies = self.detect_timestamp_anomalies(metadata, file_path)
            all_anomalies.extend(timestamp_anomalies)

        # Structural anomalies
        structural_anomalies = self.detect_structural_anomalies(file_path)
        all_anomalies.extend(structural_anomalies)

        return all_anomalies

    # =========================================================================
    # Advanced Timestamp Manipulation Detection Methods
    # =========================================================================

    def detect_tdindwg_anomalies(
        self, timestamp_data: "TimestampData"
    ) -> List[Anomaly]:
        """
        Detect TDINDWG (cumulative editing time) anomalies.

        TDINDWG is read-only and tracks total editing time. It cannot exceed
        the calendar span between creation and last save. If it does, this
        proves timestamp manipulation.

        Args:
            timestamp_data: Parsed timestamp data from the DWG file

        Returns:
            List of detected TDINDWG anomalies
        """
        anomalies: List[Anomaly] = []

        if timestamp_data.tdindwg is None:
            return anomalies

        calendar_span = timestamp_data.get_calendar_span_days()

        if calendar_span is not None and calendar_span >= 0:
            # TDINDWG is stored as MJD fraction (days)
            editing_days = timestamp_data.tdindwg

            # This is mathematically impossible without manipulation
            if editing_days > calendar_span:
                excess_days = editing_days - calendar_span
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.TDINDWG_EXCEEDS_SPAN,
                        description=(
                            "TDINDWG (cumulative editing time) exceeds calendar span - "
                            "proves timestamp manipulation"
                        ),
                        severity=RiskLevel.CRITICAL,
                        details={
                            "tdindwg_days": round(editing_days, 4),
                            "calendar_span_days": round(calendar_span, 4),
                            "excess_days": round(excess_days, 4),
                            "tdcreate": timestamp_data.tdcreate,
                            "tdupdate": timestamp_data.tdupdate,
                            "explanation": (
                                f"File claims {round(editing_days * 24, 1)} hours of editing "
                                f"but only {round(calendar_span * 24, 1)} hours elapsed "
                                "between creation and last save"
                            ),
                        },
                    )
                )

        return anomalies

    def detect_version_anachronism(
        self, version_string: str, timestamp_data: "TimestampData"
    ) -> List[Anomaly]:
        """
        Detect version anachronism - file claiming creation before version existed.

        A file saved in AC1024 format (AutoCAD 2010) cannot claim a creation
        date before March 2009 when AutoCAD 2010 was released.

        Args:
            version_string: DWG version code (e.g., 'AC1024')
            timestamp_data: Parsed timestamp data

        Returns:
            List of detected version anachronism anomalies
        """
        from dwg_forensic.parsers.timestamp import mjd_to_datetime

        anomalies: List[Anomaly] = []

        if timestamp_data.tdcreate is None:
            return anomalies

        try:
            claimed_date = mjd_to_datetime(timestamp_data.tdcreate)
        except (ValueError, OverflowError):
            return anomalies

        if is_date_before_version_release(version_string, claimed_date):
            details = get_anachronism_details(version_string, claimed_date)
            if details:
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.VERSION_ANACHRONISM,
                        description=details["description"],
                        severity=RiskLevel.CRITICAL,
                        details=details,
                    )
                )

        return anomalies

    def detect_timezone_discrepancy(
        self, timestamp_data: "TimestampData"
    ) -> List[Anomaly]:
        """
        Detect timezone discrepancies between local and UTC timestamps.

        Compares TDCREATE (local) with TDUCREATE (UTC) to detect manipulation.
        Valid timezone offsets range from -12 to +14 hours.

        Args:
            timestamp_data: Parsed timestamp data

        Returns:
            List of detected timezone discrepancy anomalies
        """
        anomalies: List[Anomaly] = []

        offset_hours = timestamp_data.get_timezone_offset_hours()

        if offset_hours is not None:
            # Valid timezone offsets are -12 to +14 hours
            if offset_hours < -12 or offset_hours > 14:
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.TIMEZONE_DISCREPANCY,
                        description=(
                            f"Invalid timezone offset of {round(offset_hours, 2)} hours - "
                            "indicates timestamp manipulation"
                        ),
                        severity=RiskLevel.HIGH,
                        details={
                            "offset_hours": round(offset_hours, 2),
                            "tdcreate": timestamp_data.tdcreate,
                            "tducreate": timestamp_data.tducreate,
                            "valid_range": "[-12, +14] hours",
                        },
                    )
                )

            # Also check for non-standard timezone offsets (not on hour/half-hour)
            fractional_minutes = (offset_hours * 60) % 30
            if fractional_minutes > 1 and fractional_minutes < 29:
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.TIMEZONE_DISCREPANCY,
                        description=(
                            "Non-standard timezone offset - "
                            "valid timezones are on 30-minute boundaries"
                        ),
                        severity=RiskLevel.MEDIUM,
                        details={
                            "offset_hours": round(offset_hours, 4),
                            "fractional_minutes": round(fractional_minutes, 2),
                        },
                    )
                )

        return anomalies

    def detect_timestamp_precision_anomaly(
        self, timestamp_data: "TimestampData"
    ) -> List[Anomaly]:
        """
        Detect suspiciously precise or round timestamp values.

        Legitimate files rarely have perfectly round timestamps like
        exactly midnight (0.0 fractional day) or zero editing time.

        Args:
            timestamp_data: Parsed timestamp data

        Returns:
            List of detected timestamp precision anomalies
        """
        anomalies: List[Anomaly] = []

        # Check for suspiciously round creation time (exactly midnight)
        if timestamp_data.tdcreate is not None:
            fractional = timestamp_data.tdcreate % 1.0
            if fractional == 0.0:
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.TIMESTAMP_PRECISION_ANOMALY,
                        description=(
                            "Creation timestamp is exactly midnight - "
                            "unusual precision may indicate manipulation"
                        ),
                        severity=RiskLevel.LOW,
                        details={
                            "tdcreate": timestamp_data.tdcreate,
                            "fractional_day": fractional,
                        },
                    )
                )

        # Check for zero editing time on non-new file
        if timestamp_data.tdindwg is not None and timestamp_data.tdindwg == 0.0:
            if timestamp_data.tdcreate and timestamp_data.tdupdate:
                if timestamp_data.tdcreate != timestamp_data.tdupdate:
                    anomalies.append(
                        Anomaly(
                            anomaly_type=AnomalyType.TIMESTAMP_PRECISION_ANOMALY,
                            description=(
                                "Zero editing time despite different creation and save dates - "
                                "indicates TDINDWG was reset or manipulated"
                            ),
                            severity=RiskLevel.MEDIUM,
                            details={
                                "tdindwg": timestamp_data.tdindwg,
                                "tdcreate": timestamp_data.tdcreate,
                                "tdupdate": timestamp_data.tdupdate,
                            },
                        )
                    )

        return anomalies

    def detect_educational_watermark(
        self, timestamp_data: "TimestampData"
    ) -> List[Anomaly]:
        """
        Detect educational version watermark in DWG file.

        Files created with educational licenses contain a watermark that
        appears on plots. This may be relevant for intellectual property
        or licensing compliance investigations.

        Args:
            timestamp_data: Parsed timestamp data

        Returns:
            List of educational watermark anomalies
        """
        anomalies: List[Anomaly] = []

        if timestamp_data.educational_watermark:
            anomalies.append(
                Anomaly(
                    anomaly_type=AnomalyType.OTHER,
                    description=(
                        "Educational Version watermark detected - "
                        "file created with student license"
                    ),
                    severity=RiskLevel.MEDIUM,
                    details={
                        "educational_watermark": True,
                        "forensic_note": (
                            "Educational licenses have restrictions on commercial use. "
                            "This watermark appears on all plots from this file."
                        ),
                    },
                )
            )

        return anomalies

    def detect_advanced_timestamp_anomalies(
        self,
        version_string: str,
        timestamp_data: "TimestampData",
        metadata: Optional[DWGMetadata] = None,
    ) -> List[Anomaly]:
        """
        Run all advanced timestamp manipulation detection checks.

        This orchestrator runs all 5 specialized detection methods:
        1. TDINDWG exceeds calendar span
        2. Version anachronism detection
        3. Timezone discrepancy detection
        4. Timestamp precision anomaly detection
        5. Educational watermark detection

        Args:
            version_string: DWG version code
            timestamp_data: Parsed timestamp data
            metadata: Optional DWG metadata for additional context

        Returns:
            List of all detected advanced timestamp anomalies
        """
        all_anomalies: List[Anomaly] = []

        # 1. TDINDWG exceeds calendar span (CRITICAL)
        all_anomalies.extend(self.detect_tdindwg_anomalies(timestamp_data))

        # 2. Version anachronism (CRITICAL)
        all_anomalies.extend(
            self.detect_version_anachronism(version_string, timestamp_data)
        )

        # 3. Timezone discrepancy (HIGH/MEDIUM)
        all_anomalies.extend(self.detect_timezone_discrepancy(timestamp_data))

        # 4. Timestamp precision anomaly (LOW/MEDIUM)
        all_anomalies.extend(self.detect_timestamp_precision_anomaly(timestamp_data))

        # 5. Educational watermark (MEDIUM)
        all_anomalies.extend(self.detect_educational_watermark(timestamp_data))

        return all_anomalies

    def _find_version_markers(self, data: bytes) -> set:
        """Find all DWG version markers in file data."""
        markers = set()
        version_patterns = [
            b"AC1032", b"AC1027", b"AC1024",
            b"AC1021", b"AC1018", b"AC1015",
        ]

        for pattern in version_patterns:
            if pattern in data:
                markers.add(pattern.decode("ascii"))

        return markers

    def _calculate_null_ratio(self, data: bytes) -> float:
        """Calculate ratio of null bytes in file data."""
        if not data:
            return 0.0
        null_count = data.count(b'\x00')
        return null_count / len(data)

    def _check_slack_space(self, data: bytes) -> List[Anomaly]:
        """Check for unusual patterns in slack space areas."""
        anomalies = []

        # Look for long sequences of repeated non-null bytes
        # which might indicate hidden data
        min_sequence_len = 100

        i = 0
        while i < len(data) - min_sequence_len:
            byte = data[i]
            if byte != 0 and byte != 0xFF:
                # Count consecutive same bytes
                count = 1
                while i + count < len(data) and data[i + count] == byte:
                    count += 1

                if count >= min_sequence_len:
                    anomalies.append(
                        Anomaly(
                            anomaly_type=AnomalyType.OTHER,
                            description=f"Unusual repeated pattern found at offset 0x{i:X}",
                            severity=RiskLevel.LOW,
                            details={
                                "offset": i,
                                "byte_value": hex(byte),
                                "sequence_length": count,
                            },
                        )
                    )
                i += count
            else:
                i += 1

        return anomalies
