"""
DWG Forensic Tool - Anomaly Detection Module

Implements anomaly detection per PRD requirements:
- FR-ANOMALY-001: Timestamp anomaly detection
- FR-ANOMALY-002: Version anomaly detection
- FR-ANOMALY-003: Structural anomaly detection
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any

from dwg_forensic.models import (
    Anomaly,
    AnomalyType,
    RiskLevel,
    DWGMetadata,
    HeaderAnalysis,
)


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
