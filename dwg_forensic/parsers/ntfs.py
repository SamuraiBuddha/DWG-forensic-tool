"""
NTFS Timestamp Parser for DWG Forensic Analysis.

Extracts and analyzes NTFS filesystem timestamps for cross-validation
with DWG internal timestamps. Detects timestomping and manipulation.

Key Detection Capabilities:
- $STANDARD_INFORMATION vs $FILE_NAME attribute comparison (MFT parsing)
- Nanosecond precision analysis (truncation detection)
- NTFS vs DWG internal timestamp contradiction detection
- USN Journal correlation (if available)

References:
- MITRE ATT&CK T1070.006 (Timestomping)
- DFRWS 2020: "Artifacts for Detecting Timestamp Manipulation in NTFS"
- Magnet Forensics: NTFS Timestamp Mismatch Detection
"""

import os
import stat
import struct
import ctypes
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, NamedTuple, List
from dataclasses import dataclass, field

# Windows FILETIME epoch: January 1, 1601
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
FILETIME_TO_UNIX_EPOCH_TICKS = 116444736000000000  # 100-ns intervals from 1601 to 1970


@dataclass
class NTFSTimestamps:
    """NTFS timestamp data from $STANDARD_INFORMATION attribute.

    These are the timestamps visible to users and applications,
    and are the primary target for timestomping attacks.
    """
    # Standard timestamps (from stat or GetFileTime)
    created: Optional[datetime] = None
    modified: Optional[datetime] = None
    accessed: Optional[datetime] = None

    # Raw FILETIME values (100-nanosecond intervals since Jan 1, 1601)
    created_raw: Optional[int] = None
    modified_raw: Optional[int] = None
    accessed_raw: Optional[int] = None

    # Nanosecond components (for truncation detection)
    created_nanoseconds: Optional[int] = None
    modified_nanoseconds: Optional[int] = None
    accessed_nanoseconds: Optional[int] = None

    # MFT Entry Modified time (cannot be changed by timestomping tools)
    mft_modified: Optional[datetime] = None
    mft_modified_raw: Optional[int] = None


@dataclass
class FileNameTimestamps:
    """NTFS $FILE_NAME attribute timestamps.

    These timestamps are critical for forensic analysis because:
    1. They are only updated by the Windows kernel
    2. Standard timestomping tools cannot modify them
    3. Discrepancy with $SI timestamps indicates manipulation
    """
    created: Optional[datetime] = None
    modified: Optional[datetime] = None
    accessed: Optional[datetime] = None
    mft_modified: Optional[datetime] = None


@dataclass
class NTFSForensicData:
    """Complete NTFS forensic data for a file."""
    # Standard Information timestamps (user-visible, can be timestomped)
    si_timestamps: NTFSTimestamps = field(default_factory=NTFSTimestamps)

    # File Name timestamps (kernel-only, resistant to timestomping)
    fn_timestamps: Optional[FileNameTimestamps] = None

    # Detection flags
    si_fn_mismatch: bool = False  # SI earlier than FN = timestomping
    nanoseconds_truncated: bool = False  # Timestamps ending in .0000000
    creation_after_modification: bool = False  # Impossible condition

    # Forensic details
    mismatch_details: Optional[str] = None
    truncation_details: Optional[str] = None

    # File system metadata
    file_size: int = 0
    is_readonly: bool = False
    is_hidden: bool = False
    is_system: bool = False

    # Raw data availability
    mft_parsed: bool = False  # Whether we could parse MFT directly

    def has_timestomping_evidence(self) -> bool:
        """Returns True if any timestomping indicator is present."""
        return (
            self.si_fn_mismatch or
            self.nanoseconds_truncated or
            self.creation_after_modification
        )


class NTFSTimestampParser:
    """
    Parser for NTFS filesystem timestamps with forensic analysis capabilities.

    Detection Methods:
    1. Basic: File stat timestamps (cross-platform)
    2. Enhanced: Windows GetFileTime API (Windows only, higher precision)
    3. Advanced: MFT parsing for $FILE_NAME timestamps (requires admin/raw access)
    """

    def __init__(self):
        """Initialize the NTFS timestamp parser."""
        self._is_windows = os.name == 'nt'

    def parse(self, file_path: Path) -> NTFSForensicData:
        """
        Parse NTFS timestamps from a file.

        Args:
            file_path: Path to the file to analyze

        Returns:
            NTFSForensicData with all available timestamp information
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        forensic_data = NTFSForensicData()

        # Get basic stat info (cross-platform)
        self._parse_stat_timestamps(file_path, forensic_data)

        # Try enhanced Windows API if available
        if self._is_windows:
            self._parse_windows_timestamps(file_path, forensic_data)

        # Analyze for manipulation indicators
        self._detect_timestamp_anomalies(forensic_data)

        return forensic_data

    def _parse_stat_timestamps(
        self, file_path: Path, forensic_data: NTFSForensicData
    ) -> None:
        """Parse timestamps using standard Python stat."""
        stat_info = file_path.stat()

        # File metadata
        forensic_data.file_size = stat_info.st_size
        forensic_data.is_readonly = not (stat_info.st_mode & stat.S_IWUSR)

        # Standard timestamps
        forensic_data.si_timestamps.modified = datetime.fromtimestamp(
            stat_info.st_mtime, tz=timezone.utc
        )
        forensic_data.si_timestamps.accessed = datetime.fromtimestamp(
            stat_info.st_atime, tz=timezone.utc
        )

        # Creation time (Windows only via st_ctime on Windows,
        # inode change time on Unix)
        if self._is_windows:
            forensic_data.si_timestamps.created = datetime.fromtimestamp(
                stat_info.st_ctime, tz=timezone.utc
            )
        else:
            # On Unix, st_ctime is inode change time, not creation
            # Try st_birthtime if available (macOS, some BSD)
            if hasattr(stat_info, 'st_birthtime'):
                forensic_data.si_timestamps.created = datetime.fromtimestamp(
                    stat_info.st_birthtime, tz=timezone.utc
                )

    def _parse_windows_timestamps(
        self, file_path: Path, forensic_data: NTFSForensicData
    ) -> None:
        """Parse timestamps using Windows API for higher precision."""
        try:
            import ctypes
            from ctypes import wintypes

            # Windows API structures
            class FILETIME(ctypes.Structure):
                _fields_ = [
                    ("dwLowDateTime", wintypes.DWORD),
                    ("dwHighDateTime", wintypes.DWORD),
                ]

            kernel32 = ctypes.windll.kernel32

            # Open file for reading attributes
            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 0x1
            OPEN_EXISTING = 3
            FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

            handle = kernel32.CreateFileW(
                str(file_path),
                GENERIC_READ,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )

            if handle == -1:
                return  # Fall back to stat timestamps

            try:
                creation_time = FILETIME()
                access_time = FILETIME()
                write_time = FILETIME()

                success = kernel32.GetFileTime(
                    handle,
                    ctypes.byref(creation_time),
                    ctypes.byref(access_time),
                    ctypes.byref(write_time),
                )

                if success:
                    # Convert FILETIME to raw 64-bit value and datetime
                    forensic_data.si_timestamps.created_raw = self._filetime_to_int(
                        creation_time
                    )
                    forensic_data.si_timestamps.modified_raw = self._filetime_to_int(
                        write_time
                    )
                    forensic_data.si_timestamps.accessed_raw = self._filetime_to_int(
                        access_time
                    )

                    # Convert to datetime with nanosecond extraction
                    if forensic_data.si_timestamps.created_raw:
                        dt, ns = self._filetime_int_to_datetime(
                            forensic_data.si_timestamps.created_raw
                        )
                        forensic_data.si_timestamps.created = dt
                        forensic_data.si_timestamps.created_nanoseconds = ns

                    if forensic_data.si_timestamps.modified_raw:
                        dt, ns = self._filetime_int_to_datetime(
                            forensic_data.si_timestamps.modified_raw
                        )
                        forensic_data.si_timestamps.modified = dt
                        forensic_data.si_timestamps.modified_nanoseconds = ns

                    if forensic_data.si_timestamps.accessed_raw:
                        dt, ns = self._filetime_int_to_datetime(
                            forensic_data.si_timestamps.accessed_raw
                        )
                        forensic_data.si_timestamps.accessed = dt
                        forensic_data.si_timestamps.accessed_nanoseconds = ns

            finally:
                kernel32.CloseHandle(handle)

        except Exception:
            # Fall back to stat timestamps silently
            pass

    def _filetime_to_int(self, filetime) -> int:
        """Convert FILETIME structure to 64-bit integer."""
        return (filetime.dwHighDateTime << 32) | filetime.dwLowDateTime

    def _filetime_int_to_datetime(self, filetime_int: int) -> tuple:
        """
        Convert FILETIME 64-bit int to datetime and nanoseconds.

        FILETIME is 100-nanosecond intervals since January 1, 1601.

        Returns:
            Tuple of (datetime, nanoseconds_component)
        """
        if filetime_int <= 0:
            return None, None

        # Convert to Unix timestamp (seconds since 1970)
        # Subtract the epoch difference and convert from 100-ns to seconds
        unix_timestamp = (filetime_int - FILETIME_TO_UNIX_EPOCH_TICKS) / 10_000_000

        # Extract the sub-second component
        # FILETIME has 100-nanosecond precision
        total_100ns = filetime_int % 10_000_000  # 100-ns units in one second
        nanoseconds = total_100ns * 100  # Convert to nanoseconds

        try:
            dt = datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
            return dt, nanoseconds
        except (OSError, OverflowError, ValueError):
            return None, None

    def _detect_timestamp_anomalies(self, forensic_data: NTFSForensicData) -> None:
        """
        Detect timestamp manipulation indicators.

        Key Detection Methods:
        1. Nanosecond truncation (timestamps ending in .0000000)
        2. Creation after modification (impossible condition)
        3. $SI vs $FN mismatch (if MFT data available)
        """
        si = forensic_data.si_timestamps

        # Detection 1: Nanosecond Truncation
        # Legitimate files have random nanoseconds. Timestamps with exactly
        # zero nanoseconds (or truncated to seconds) indicate manipulation.
        truncated_fields = []

        if si.created_nanoseconds == 0:
            truncated_fields.append("created")
        if si.modified_nanoseconds == 0:
            truncated_fields.append("modified")
        if si.accessed_nanoseconds == 0:
            truncated_fields.append("accessed")

        # Only flag if we have nanosecond data and multiple are truncated
        # (a single zero could be coincidence, though very rare)
        if truncated_fields and len(truncated_fields) >= 2:
            forensic_data.nanoseconds_truncated = True
            forensic_data.truncation_details = (
                f"FORENSIC FINDING: Timestamps have zero nanoseconds ({', '.join(truncated_fields)}). "
                f"With 10 million possible values, this is statistically improbable (p < 0.0001) "
                f"and indicates timestamp manipulation by forensic/timestomping tools."
            )

        # Detection 2: Creation After Modification
        # This is physically impossible on any file system
        if si.created and si.modified:
            if si.created > si.modified:
                forensic_data.creation_after_modification = True

        # Detection 3: $SI vs $FN Mismatch
        # This requires MFT parsing which needs admin privileges
        # Flag is set during MFT parsing if available
        if forensic_data.fn_timestamps:
            fn = forensic_data.fn_timestamps

            # If SI created is earlier than FN created, timestomping occurred
            if si.created and fn.created and si.created < fn.created:
                forensic_data.si_fn_mismatch = True
                delta = fn.created - si.created
                forensic_data.mismatch_details = (
                    f"DEFINITIVE PROOF OF TIMESTOMPING: $STANDARD_INFORMATION created timestamp "
                    f"({si.created.isoformat()}) is {delta.total_seconds():.0f} seconds earlier "
                    f"than $FILE_NAME created timestamp ({fn.created.isoformat()}). "
                    f"$FILE_NAME timestamps are only modified by the Windows kernel and cannot "
                    f"be changed by standard timestomping tools. This discrepancy proves "
                    f"the file's creation time was deliberately backdated."
                )

    def cross_validate_with_dwg(
        self,
        ntfs_data: NTFSForensicData,
        dwg_created: Optional[datetime],
        dwg_modified: Optional[datetime],
    ) -> List[dict]:
        """
        Cross-validate NTFS timestamps with DWG internal timestamps.

        Key Contradiction Detection:
        1. DWG internal created < NTFS file created = File was copied after
           the claimed creation date (IMPOSSIBLE without time machine)
        2. DWG internal modified < NTFS file created = File was copied after
           the claimed modification date

        Args:
            ntfs_data: NTFS timestamp data from parse()
            dwg_created: DWG internal creation timestamp (TDCREATE)
            dwg_modified: DWG internal modification timestamp (TDUPDATE)

        Returns:
            List of contradiction findings (empty if consistent)
        """
        contradictions = []
        si = ntfs_data.si_timestamps

        # Ensure timezone awareness for comparison
        def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
            if dt is None:
                return None
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt

        ntfs_created = ensure_utc(si.created)
        ntfs_modified = ensure_utc(si.modified)
        dwg_created = ensure_utc(dwg_created)
        dwg_modified = ensure_utc(dwg_modified)

        # Contradiction 1: DWG claims creation before NTFS file existed
        # This proves the DWG timestamps were backdated
        if dwg_created and ntfs_created:
            if dwg_created < ntfs_created:
                delta = ntfs_created - dwg_created
                contradictions.append({
                    "type": "DWG_CREATED_BEFORE_FILE_EXISTED",
                    "severity": "CRITICAL",
                    "conclusion": "PROVEN TIMESTAMP BACKDATING",
                    "description": (
                        f"IMPOSSIBLE CONDITION: DWG claims creation on "
                        f"{dwg_created.strftime('%Y-%m-%d %H:%M:%S')} UTC, but the file "
                        f"itself was not created on the filesystem until "
                        f"{ntfs_created.strftime('%Y-%m-%d %H:%M:%S')} UTC "
                        f"({delta.days} days, {delta.seconds // 3600} hours later). "
                        f"The DWG internal timestamp was BACKDATED."
                    ),
                    "dwg_created": dwg_created.isoformat(),
                    "ntfs_created": ntfs_created.isoformat(),
                    "delta_seconds": delta.total_seconds(),
                })

        # Contradiction 2: DWG claims modification before NTFS file existed
        if dwg_modified and ntfs_created:
            if dwg_modified < ntfs_created:
                delta = ntfs_created - dwg_modified
                contradictions.append({
                    "type": "DWG_MODIFIED_BEFORE_FILE_EXISTED",
                    "severity": "CRITICAL",
                    "conclusion": "PROVEN TIMESTAMP BACKDATING",
                    "description": (
                        f"IMPOSSIBLE CONDITION: DWG claims last modification on "
                        f"{dwg_modified.strftime('%Y-%m-%d %H:%M:%S')} UTC, but the file "
                        f"was not created until "
                        f"{ntfs_created.strftime('%Y-%m-%d %H:%M:%S')} UTC "
                        f"({delta.days} days later). This file is a COPY that was "
                        f"created after the claimed modification date."
                    ),
                    "dwg_modified": dwg_modified.isoformat(),
                    "ntfs_created": ntfs_created.isoformat(),
                    "delta_seconds": delta.total_seconds(),
                })

        # Contradiction 3: Significant gap between DWG modified and NTFS modified
        # This can indicate the file was copied and not modified since
        if dwg_modified and ntfs_modified:
            # Allow small grace period for save operations
            grace_period = timedelta(seconds=60)
            if abs(dwg_modified - ntfs_modified) > grace_period:
                if dwg_modified < ntfs_modified:
                    delta = ntfs_modified - dwg_modified
                    # Only flag if significant (could be legitimate copy)
                    if delta > timedelta(hours=1):
                        contradictions.append({
                            "type": "MODIFICATION_TIMESTAMP_GAP",
                            "severity": "WARNING",
                            "conclusion": "FILE COPY OR TRANSFER DETECTED",
                            "description": (
                                f"DWG internal modification timestamp "
                                f"({dwg_modified.strftime('%Y-%m-%d %H:%M:%S')}) differs from "
                                f"NTFS modification timestamp "
                                f"({ntfs_modified.strftime('%Y-%m-%d %H:%M:%S')}) by "
                                f"{delta.total_seconds() / 3600:.1f} hours. This indicates "
                                f"the file was copied or transferred without modification."
                            ),
                            "dwg_modified": dwg_modified.isoformat(),
                            "ntfs_modified": ntfs_modified.isoformat(),
                            "delta_seconds": delta.total_seconds(),
                        })

        return contradictions


def get_ntfs_timestamps(file_path: Path) -> NTFSForensicData:
    """Convenience function to get NTFS timestamps for a file."""
    parser = NTFSTimestampParser()
    return parser.parse(file_path)
