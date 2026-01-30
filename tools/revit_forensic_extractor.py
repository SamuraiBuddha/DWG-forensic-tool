"""
Revit RVT Forensic Metadata Extractor

Extracts forensic metadata from Autodesk Revit (.rvt) files using OLE2
compound document parsing to establish ground truth before analyzing DWG exports.

Usage:
    python revit_forensic_extractor.py <directory_path> [--output report.csv]

Requirements:
    pip install olefile
"""

import hashlib
import json
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    import olefile
except ImportError:
    print("[ERROR] olefile library not found. Install with: pip install olefile")
    sys.exit(1)


@dataclass
class RevitMetadata:
    """Extracted Revit metadata from OLE2 BasicFileInfo stream."""

    filename: str
    file_path: str
    file_size_bytes: int
    ntfs_modified: Optional[datetime]
    ntfs_created: Optional[datetime]
    sha256_hash: str

    # OLE2 validation
    is_valid_ole2: bool
    ole2_error: Optional[str] = None

    # Extracted metadata
    revit_version: Optional[str] = None
    revit_build: Optional[str] = None
    revit_full_version: Optional[str] = None
    last_saved_timestamp: Optional[str] = None
    is_workshared: Optional[bool] = None
    username: Optional[str] = None

    # Raw metadata
    raw_metadata_hex: Optional[str] = None
    basic_file_info_size: Optional[int] = None

    # Forensic flags
    timestamp_mismatch: bool = False
    version_anachronism: bool = False
    suspicious_indicators: List[str] = field(default_factory=list)


class RevitForensicExtractor:
    """Forensic extractor for Revit RVT files using OLE2 parsing."""

    BASIC_FILE_INFO_STREAM = "BasicFileInfo"

    # Revit version regex patterns
    REVIT_VERSION_PATTERN = re.compile(r"Revit\s+(\d{4})", re.IGNORECASE)
    BUILD_PATTERN = re.compile(r"Build:\s*(\d+_\d+_\w+|\d+)")

    # Known Revit version release dates (for anachronism detection)
    REVIT_VERSION_DATES = {
        "2018": datetime(2017, 4, 5),
        "2019": datetime(2018, 4, 12),
        "2020": datetime(2019, 4, 10),
        "2021": datetime(2020, 4, 15),
        "2022": datetime(2021, 3, 31),
        "2023": datetime(2022, 4, 13),
        "2024": datetime(2023, 4, 12),
        "2025": datetime(2024, 4, 17),
    }

    def __init__(self):
        """Initialize the forensic extractor."""
        self.results: List[RevitMetadata] = []

    def extract_file(self, file_path: str) -> RevitMetadata:
        """
        Extract forensic metadata from a single RVT file.

        Args:
            file_path: Absolute path to the RVT file

        Returns:
            RevitMetadata object with extracted information
        """
        file_path = Path(file_path).resolve()

        # Initialize metadata with file system information
        metadata = RevitMetadata(
            filename=file_path.name,
            file_path=str(file_path),
            file_size_bytes=0,
            ntfs_modified=None,
            ntfs_created=None,
            sha256_hash="",
            is_valid_ole2=False,
        )

        # Validate file exists
        if not file_path.exists():
            metadata.ole2_error = f"File not found: {file_path}"
            return metadata

        # Extract NTFS timestamps and file size
        try:
            stat_info = file_path.stat()
            metadata.file_size_bytes = stat_info.st_size
            metadata.ntfs_modified = datetime.fromtimestamp(stat_info.st_mtime)
            metadata.ntfs_created = datetime.fromtimestamp(stat_info.st_ctime)
        except Exception as e:
            metadata.suspicious_indicators.append(f"NTFS stat error: {e}")

        # Calculate SHA-256 hash
        try:
            metadata.sha256_hash = self._calculate_sha256(file_path)
        except Exception as e:
            metadata.suspicious_indicators.append(f"SHA-256 calculation error: {e}")

        # Validate OLE2 structure
        try:
            if not olefile.isOleFile(str(file_path)):
                metadata.ole2_error = "Not a valid OLE2 compound document"
                return metadata

            metadata.is_valid_ole2 = True

            # Open OLE2 file and extract metadata
            with olefile.OleFileIO(str(file_path)) as ole:
                self._extract_basic_file_info(ole, metadata)

        except Exception as e:
            metadata.ole2_error = f"OLE2 parsing error: {type(e).__name__}: {e}"
            return metadata

        # Perform forensic analysis
        self._analyze_metadata(metadata)

        return metadata

    def _extract_basic_file_info(
        self,
        ole: olefile.OleFileIO,
        metadata: RevitMetadata
    ) -> None:
        """
        Extract metadata from the BasicFileInfo stream.

        Args:
            ole: Opened OLE2 file object
            metadata: Metadata object to populate
        """
        try:
            if not ole.exists(self.BASIC_FILE_INFO_STREAM):
                metadata.suspicious_indicators.append(
                    "BasicFileInfo stream not found (unusual for RVT files)"
                )
                return

            # Read the BasicFileInfo stream
            stream_data = ole.openstream(self.BASIC_FILE_INFO_STREAM).read()
            metadata.basic_file_info_size = len(stream_data)

            # Store raw hex for forensic review (first 512 bytes)
            metadata.raw_metadata_hex = stream_data[:512].hex()

            # Parse BasicFileInfo header (binary format)
            # Structure: int32 + version_year + build_string + path
            try:
                # Skip first 16 bytes (header)
                offset = 16

                # Read format field (int32)
                format_id = struct.unpack('<I', stream_data[offset:offset+4])[0]
                offset += 4

                # Version year is stored as UTF-16LE string
                # Find the version year (4 digits like "2022")
                text = stream_data.decode('utf-16le', errors='ignore')

                # Extract 4-digit year (appears early in the stream)
                year_match = re.search(r'\b(20[12]\d)\b', text)
                if year_match:
                    metadata.revit_version = year_match.group(1)

                # Extract build string (format: YYYYMMDD_HHMM(x64))
                build_match = re.search(r'(\d{8}_\d{4}\([^\)]+\))', text)
                if build_match:
                    metadata.revit_build = build_match.group(1)
                elif re.search(r'(\d{8}_\d{4})', text):
                    # Fallback: just the date_time part
                    build_match = re.search(r'(\d{8}_\d{4})', text)
                    metadata.revit_build = build_match.group(1)

            except Exception as e:
                # Fallback to text parsing
                metadata.suspicious_indicators.append(
                    f"Binary parse failed, using text fallback: {e}"
                )

                # Convert to UTF-16LE string (Revit uses Unicode)
                try:
                    # Try UTF-16LE first (common in Windows apps)
                    text = stream_data.decode('utf-16le', errors='ignore')
                except Exception:
                    # Fallback to Latin-1 if UTF-16 fails
                    text = stream_data.decode('latin-1', errors='ignore')

                # Extract Revit version
                version_match = self.REVIT_VERSION_PATTERN.search(text)
                if version_match:
                    metadata.revit_version = version_match.group(1)

                # Extract build number
                build_match = self.BUILD_PATTERN.search(text)
                if build_match:
                    metadata.revit_build = build_match.group(1)

            # Construct full version string
            if metadata.revit_version or metadata.revit_build:
                parts = []
                if metadata.revit_version:
                    parts.append(f"Revit {metadata.revit_version}")
                if metadata.revit_build:
                    parts.append(f"build {metadata.revit_build}")
                metadata.revit_full_version = " ".join(parts)

            # Search for worksharing indicators
            if "IsWorkshared" in text:
                # Look for boolean value after the key
                ws_match = re.search(r"IsWorkshared[^\x00]*?([01])", text)
                if ws_match:
                    metadata.is_workshared = ws_match.group(1) == "1"
            elif "workshared" in text.lower():
                metadata.is_workshared = True  # Heuristic

            # Search for username
            username_match = re.search(r"Username[^\x00]*?:\s*([^\x00]+)", text)
            if username_match:
                metadata.username = username_match.group(1).strip()

            # Search for last saved timestamp (multiple patterns)
            timestamp_patterns = [
                r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})",  # ISO format
                r"(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2})",  # US format
            ]

            for pattern in timestamp_patterns:
                ts_match = re.search(pattern, text)
                if ts_match:
                    metadata.last_saved_timestamp = ts_match.group(1)
                    break

        except Exception as e:
            metadata.suspicious_indicators.append(
                f"BasicFileInfo extraction error: {type(e).__name__}: {e}"
            )

    def _calculate_sha256(self, file_path: Path) -> str:
        """
        Calculate SHA-256 hash of the file.

        Args:
            file_path: Path to the file

        Returns:
            Hex string of SHA-256 hash
        """
        sha256 = hashlib.sha256()

        with open(file_path, 'rb') as f:
            # Read in 64KB chunks for large files
            while chunk := f.read(65536):
                sha256.update(chunk)

        return sha256.hexdigest()

    def _analyze_metadata(self, metadata: RevitMetadata) -> None:
        """
        Perform forensic analysis on extracted metadata.

        Args:
            metadata: Metadata object to analyze
        """
        # Check for version anachronism
        if metadata.revit_version and metadata.ntfs_modified:
            release_date = self.REVIT_VERSION_DATES.get(metadata.revit_version)

            if release_date:
                # File modified before Revit version was released
                if metadata.ntfs_modified < release_date:
                    metadata.version_anachronism = True
                    metadata.suspicious_indicators.append(
                        f"Version anachronism: File modified {metadata.ntfs_modified.date()} "
                        f"but contains Revit {metadata.revit_version} "
                        f"(released {release_date.date()})"
                    )

        # Check for timestamp mismatch between NTFS and internal
        if metadata.last_saved_timestamp and metadata.ntfs_modified:
            try:
                # Parse internal timestamp
                for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                           "%m/%d/%Y %H:%M:%S"]:
                    try:
                        internal_dt = datetime.strptime(
                            metadata.last_saved_timestamp.split('.')[0],  # Strip microseconds
                            fmt
                        )
                        break
                    except ValueError:
                        continue
                else:
                    # Could not parse timestamp
                    internal_dt = None

                if internal_dt:
                    # Check if timestamps differ by more than 1 hour
                    time_diff = abs((metadata.ntfs_modified - internal_dt).total_seconds())

                    if time_diff > 3600:  # 1 hour threshold
                        metadata.timestamp_mismatch = True
                        metadata.suspicious_indicators.append(
                            f"Timestamp mismatch: NTFS modified {metadata.ntfs_modified} "
                            f"vs internal last-saved {internal_dt} "
                            f"(diff: {time_diff/3600:.1f} hours)"
                        )
            except Exception as e:
                metadata.suspicious_indicators.append(
                    f"Timestamp comparison error: {e}"
                )

        # Check filename vs NTFS timestamp discrepancy
        filename_lower = metadata.filename.lower()

        # Extract dates from filename (common patterns)
        filename_date_patterns = [
            r"(\d{2})_(\d{2})_(\d{2,4})",  # 07_07_21 or 07_07_2021
            r"(\d{1,2})[/\-\.](\d{1,2})[/\-\.](\d{2,4})",  # 7/7/21 or 7-7-21
            r"(\d{4})[/\-\.](\d{1,2})[/\-\.](\d{1,2})",  # 2021/7/7 or 2021-7-7
        ]

        filename_date = None
        for pattern in filename_date_patterns:
            match = re.search(pattern, filename_lower)
            if match:
                try:
                    # Try multiple date formats
                    groups = match.groups()

                    # Handle MM_DD_YY format
                    if len(groups[2]) == 2:
                        year = 2000 + int(groups[2])
                        filename_date = datetime(year, int(groups[0]), int(groups[1]))
                    # Handle YYYY_MM_DD format
                    elif len(groups[0]) == 4:
                        filename_date = datetime(
                            int(groups[0]), int(groups[1]), int(groups[2])
                        )
                    else:
                        # Ambiguous format, skip
                        continue

                    break
                except (ValueError, IndexError):
                    continue

        if filename_date and metadata.ntfs_modified:
            # Check if filename date and NTFS modified differ significantly
            date_diff_days = abs((metadata.ntfs_modified - filename_date).days)

            if date_diff_days > 365:  # More than 1 year difference
                metadata.suspicious_indicators.append(
                    f"Filename date mismatch: Filename suggests {filename_date.date()} "
                    f"but NTFS modified is {metadata.ntfs_modified.date()} "
                    f"(diff: {date_diff_days} days)"
                )

    def extract_directory(
        self,
        directory_path: str,
        recursive: bool = True
    ) -> List[RevitMetadata]:
        """
        Extract metadata from all RVT files in a directory.

        Args:
            directory_path: Path to directory containing RVT files
            recursive: Whether to search subdirectories

        Returns:
            List of RevitMetadata objects
        """
        directory = Path(directory_path).resolve()

        if not directory.exists():
            print(f"[ERROR] Directory not found: {directory}")
            return []

        # Find all RVT files
        pattern = "**/*.rvt" if recursive else "*.rvt"
        rvt_files = list(directory.glob(pattern))

        print(f"[INFO] Found {len(rvt_files)} RVT files in {directory}")

        results = []
        for i, rvt_file in enumerate(rvt_files, 1):
            print(f"[{i}/{len(rvt_files)}] Processing: {rvt_file.name}")

            metadata = self.extract_file(str(rvt_file))
            results.append(metadata)

            # Show summary
            if metadata.is_valid_ole2:
                print(f"  - Version: {metadata.revit_full_version or 'Unknown'}")
                print(f"  - NTFS Modified: {metadata.ntfs_modified}")
                print(f"  - Suspicious Indicators: {len(metadata.suspicious_indicators)}")
            else:
                print(f"  - [ERROR] {metadata.ole2_error}")

        self.results = results
        return results

    def export_csv(self, output_path: str) -> None:
        """
        Export results to CSV format.

        Args:
            output_path: Path to output CSV file
        """
        import csv

        if not self.results:
            print("[WARN] No results to export")
            return

        fieldnames = [
            "filename",
            "file_path",
            "file_size_mb",
            "ntfs_created",
            "ntfs_modified",
            "sha256_hash",
            "is_valid_ole2",
            "revit_full_version",
            "revit_version",
            "revit_build",
            "last_saved_timestamp",
            "is_workshared",
            "username",
            "basic_file_info_size",
            "timestamp_mismatch",
            "version_anachronism",
            "suspicious_indicators_count",
            "suspicious_indicators",
            "ole2_error",
        ]

        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for metadata in self.results:
                row = {
                    "filename": metadata.filename,
                    "file_path": metadata.file_path,
                    "file_size_mb": f"{metadata.file_size_bytes / (1024*1024):.2f}",
                    "ntfs_created": metadata.ntfs_created.isoformat()
                                   if metadata.ntfs_created else "",
                    "ntfs_modified": metadata.ntfs_modified.isoformat()
                                    if metadata.ntfs_modified else "",
                    "sha256_hash": metadata.sha256_hash,
                    "is_valid_ole2": "YES" if metadata.is_valid_ole2 else "NO",
                    "revit_full_version": metadata.revit_full_version or "",
                    "revit_version": metadata.revit_version or "",
                    "revit_build": metadata.revit_build or "",
                    "last_saved_timestamp": metadata.last_saved_timestamp or "",
                    "is_workshared": "YES" if metadata.is_workshared
                                   else ("NO" if metadata.is_workshared is False else "UNKNOWN"),
                    "username": metadata.username or "",
                    "basic_file_info_size": metadata.basic_file_info_size or "",
                    "timestamp_mismatch": "YES" if metadata.timestamp_mismatch else "NO",
                    "version_anachronism": "YES" if metadata.version_anachronism else "NO",
                    "suspicious_indicators_count": len(metadata.suspicious_indicators),
                    "suspicious_indicators": " | ".join(metadata.suspicious_indicators),
                    "ole2_error": metadata.ole2_error or "",
                }
                writer.writerow(row)

        print(f"[OK] CSV report exported to: {output_path}")

    def export_json(self, output_path: str) -> None:
        """
        Export results to JSON format.

        Args:
            output_path: Path to output JSON file
        """
        if not self.results:
            print("[WARN] No results to export")
            return

        # Convert dataclasses to dictionaries
        results_dict = []

        for metadata in self.results:
            result = {
                "filename": metadata.filename,
                "file_path": metadata.file_path,
                "file_size_bytes": metadata.file_size_bytes,
                "ntfs_created": metadata.ntfs_created.isoformat()
                               if metadata.ntfs_created else None,
                "ntfs_modified": metadata.ntfs_modified.isoformat()
                                if metadata.ntfs_modified else None,
                "sha256_hash": metadata.sha256_hash,
                "is_valid_ole2": metadata.is_valid_ole2,
                "ole2_error": metadata.ole2_error,
                "revit_version": metadata.revit_version,
                "revit_build": metadata.revit_build,
                "revit_full_version": metadata.revit_full_version,
                "last_saved_timestamp": metadata.last_saved_timestamp,
                "is_workshared": metadata.is_workshared,
                "username": metadata.username,
                "basic_file_info_size": metadata.basic_file_info_size,
                "timestamp_mismatch": metadata.timestamp_mismatch,
                "version_anachronism": metadata.version_anachronism,
                "suspicious_indicators": metadata.suspicious_indicators,
            }
            results_dict.append(result)

        with open(output_path, 'w', encoding='utf-8') as jsonfile:
            json.dump(results_dict, jsonfile, indent=2, ensure_ascii=False)

        print(f"[OK] JSON report exported to: {output_path}")

    def print_summary(self) -> None:
        """Print a forensic summary of all extracted files."""
        if not self.results:
            print("[WARN] No results to summarize")
            return

        print("\n" + "=" * 80)
        print("REVIT FORENSIC METADATA EXTRACTION SUMMARY")
        print("=" * 80)

        total_files = len(self.results)
        valid_ole2 = sum(1 for r in self.results if r.is_valid_ole2)
        total_suspicious = sum(len(r.suspicious_indicators) for r in self.results)

        print(f"\nTotal RVT files analyzed: {total_files}")
        print(f"Valid OLE2 files: {valid_ole2}")
        print(f"Invalid/corrupted files: {total_files - valid_ole2}")
        print(f"Total suspicious indicators: {total_suspicious}")

        # Version distribution
        versions = {}
        for r in self.results:
            if r.revit_version:
                versions[r.revit_version] = versions.get(r.revit_version, 0) + 1

        if versions:
            print("\nRevit version distribution:")
            for version, count in sorted(versions.items()):
                print(f"  - Revit {version}: {count} file(s)")

        # Timestamp analysis
        if any(r.timestamp_mismatch for r in self.results):
            print("\n[WARN] Timestamp mismatches detected:")
            for r in self.results:
                if r.timestamp_mismatch:
                    print(f"  - {r.filename}")

        # Version anachronisms
        if any(r.version_anachronism for r in self.results):
            print("\n[WARN] Version anachronisms detected:")
            for r in self.results:
                if r.version_anachronism:
                    print(f"  - {r.filename}")

        # Files with most suspicious indicators
        suspicious_files = [r for r in self.results if r.suspicious_indicators]
        if suspicious_files:
            print("\n[WARN] Files with suspicious indicators:")
            for r in sorted(suspicious_files,
                          key=lambda x: len(x.suspicious_indicators),
                          reverse=True)[:5]:
                print(f"  - {r.filename}: {len(r.suspicious_indicators)} indicator(s)")
                for indicator in r.suspicious_indicators[:3]:
                    print(f"      {indicator}")

        print("\n" + "=" * 80)


def main():
    """Main entry point for CLI usage."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Revit RVT Forensic Metadata Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python revit_forensic_extractor.py /path/to/directory
  python revit_forensic_extractor.py /path/to/directory --output report.csv
  python revit_forensic_extractor.py /path/to/directory --format json
        """
    )

    parser.add_argument(
        "directory",
        help="Directory containing RVT files to analyze"
    )

    parser.add_argument(
        "--output", "-o",
        default="revit_forensic_report.csv",
        help="Output file path (default: revit_forensic_report.csv)"
    )

    parser.add_argument(
        "--format", "-f",
        choices=["csv", "json"],
        default="csv",
        help="Output format (default: csv)"
    )

    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Do not search subdirectories"
    )

    args = parser.parse_args()

    # Initialize extractor
    extractor = RevitForensicExtractor()

    # Extract metadata
    print(f"[INFO] Starting forensic extraction from: {args.directory}")
    results = extractor.extract_directory(
        args.directory,
        recursive=not args.no_recursive
    )

    if not results:
        print("[ERROR] No RVT files found or processed")
        sys.exit(1)

    # Export results
    if args.format == "csv":
        extractor.export_csv(args.output)
    elif args.format == "json":
        extractor.export_json(args.output)

    # Print summary
    extractor.print_summary()


if __name__ == "__main__":
    main()
