"""
Revit Partition Forensic Comparator

Performs deep OLE2 partition-level comparison between two RVT files to identify:
- Deleted partitions (e.g., Partition 2158 in Lane.0024.rvt)
- Expanded partitions (e.g., Partition 2152: 39KB -> 3.2MB)
- Bit-for-bit identical partitions
- Keyword searches in partition data (pool, cabana, kitchen)
- Hex analysis of suspicious partitions

Usage:
    python revit_partition_comparator.py <original.rvt> <variant.rvt> --output report_dir
"""

import hashlib
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import olefile
except ImportError:
    print("[ERROR] olefile library not found. Install with: pip install olefile")
    sys.exit(1)


@dataclass
class PartitionInfo:
    """Information about a single OLE2 partition (stream)."""

    path: str  # Stream path (e.g., "PartitionMap/Partition_2158")
    size_bytes: int
    sha256_hash: str
    timestamp: Optional[datetime] = None
    partition_id: Optional[str] = None  # Extracted partition number


@dataclass
class PartitionComparison:
    """Comparison result between two RVT files."""

    file_a_name: str
    file_b_name: str
    file_a_size: int
    file_b_size: int

    # Partition sets
    partitions_only_in_a: List[PartitionInfo] = field(default_factory=list)
    partitions_only_in_b: List[PartitionInfo] = field(default_factory=list)
    partitions_identical: List[Tuple[PartitionInfo, PartitionInfo]] = field(default_factory=list)
    partitions_modified: List[Tuple[PartitionInfo, PartitionInfo]] = field(default_factory=list)

    # Statistics
    total_partitions_a: int = 0
    total_partitions_b: int = 0
    percent_file_changed: float = 0.0

    # Keyword analysis results
    keyword_findings: Dict[str, List[str]] = field(default_factory=dict)


class RevitPartitionComparator:
    """Forensic partition-level comparison tool for Revit RVT files."""

    # Keywords to search for in partition data
    AMENITY_KEYWORDS = [
        "pool", "Pool", "POOL",
        "cabana", "Cabana", "CABANA",
        "kitchen", "Kitchen", "KITCHEN",
        "spa", "Spa", "SPA",
        "amenity", "Amenity", "AMENITY",
    ]

    def __init__(self):
        """Initialize the comparator."""
        self.file_a_path: Optional[Path] = None
        self.file_b_path: Optional[Path] = None
        self.comparison: Optional[PartitionComparison] = None

    def compare_files(self, file_a: str, file_b: str) -> PartitionComparison:
        """
        Compare two RVT files at partition level.

        Args:
            file_a: Path to original RVT file (e.g., Lane.rvt)
            file_b: Path to variant RVT file (e.g., Lane.0024.rvt)

        Returns:
            PartitionComparison object with detailed results
        """
        self.file_a_path = Path(file_a).resolve()
        self.file_b_path = Path(file_b).resolve()

        # Validate files exist
        if not self.file_a_path.exists():
            raise FileNotFoundError(f"File A not found: {self.file_a_path}")
        if not self.file_b_path.exists():
            raise FileNotFoundError(f"File B not found: {self.file_b_path}")

        # Extract partition information from both files
        print(f"[INFO] Extracting partitions from: {self.file_a_path.name}")
        partitions_a = self._extract_partitions(self.file_a_path)

        print(f"[INFO] Extracting partitions from: {self.file_b_path.name}")
        partitions_b = self._extract_partitions(self.file_b_path)

        # Initialize comparison result
        comparison = PartitionComparison(
            file_a_name=self.file_a_path.name,
            file_b_name=self.file_b_path.name,
            file_a_size=self.file_a_path.stat().st_size,
            file_b_size=self.file_b_path.stat().st_size,
            total_partitions_a=len(partitions_a),
            total_partitions_b=len(partitions_b),
        )

        # Build lookup dictionaries by partition path
        partitions_a_dict = {p.path: p for p in partitions_a}
        partitions_b_dict = {p.path: p for p in partitions_b}

        paths_a = set(partitions_a_dict.keys())
        paths_b = set(partitions_b_dict.keys())

        # Identify partitions only in A (DELETED in B)
        only_in_a_paths = paths_a - paths_b
        comparison.partitions_only_in_a = [
            partitions_a_dict[path] for path in sorted(only_in_a_paths)
        ]

        # Identify partitions only in B (ADDED in B)
        only_in_b_paths = paths_b - paths_a
        comparison.partitions_only_in_b = [
            partitions_b_dict[path] for path in sorted(only_in_b_paths)
        ]

        # Compare common partitions
        common_paths = paths_a & paths_b

        for path in sorted(common_paths):
            part_a = partitions_a_dict[path]
            part_b = partitions_b_dict[path]

            if part_a.sha256_hash == part_b.sha256_hash:
                # Identical partition
                comparison.partitions_identical.append((part_a, part_b))
            else:
                # Modified partition
                comparison.partitions_modified.append((part_a, part_b))

        # Calculate percentage of file changed
        total_bytes_changed = 0

        # Count deleted bytes
        for part in comparison.partitions_only_in_a:
            total_bytes_changed += part.size_bytes

        # Count added bytes
        for part in comparison.partitions_only_in_b:
            total_bytes_changed += part.size_bytes

        # Count modified bytes (use size difference as approximation)
        for part_a, part_b in comparison.partitions_modified:
            total_bytes_changed += abs(part_b.size_bytes - part_a.size_bytes)

        # Percentage relative to file A
        if comparison.file_a_size > 0:
            comparison.percent_file_changed = (
                total_bytes_changed / comparison.file_a_size
            ) * 100

        self.comparison = comparison
        return comparison

    def _extract_partitions(self, file_path: Path) -> List[PartitionInfo]:
        """
        Extract all partitions from an RVT file.

        Args:
            file_path: Path to RVT file

        Returns:
            List of PartitionInfo objects
        """
        partitions = []

        if not olefile.isOleFile(str(file_path)):
            raise ValueError(f"Not a valid OLE2 file: {file_path.name}")

        with olefile.OleFileIO(str(file_path)) as ole:
            # List all streams
            stream_list = ole.listdir()

            for stream_path_list in stream_list:
                # Convert list to path string
                stream_path = "/".join(stream_path_list)

                try:
                    # Get stream size
                    stream_size = ole.get_size(stream_path_list)

                    # Read stream data for hash calculation
                    stream_data = ole.openstream(stream_path_list).read()

                    # Calculate SHA-256 hash
                    sha256_hash = hashlib.sha256(stream_data).hexdigest()

                    # Extract partition ID from path (e.g., "Partitions/2158" or "PartitionMap/Partition_2158")
                    partition_id = None
                    match = re.search(r'Partition[s]?[/_\s]?(\d+)', stream_path, re.IGNORECASE)
                    if match:
                        partition_id = match.group(1)

                    # Create PartitionInfo
                    partition = PartitionInfo(
                        path=stream_path,
                        size_bytes=stream_size,
                        sha256_hash=sha256_hash,
                        partition_id=partition_id,
                    )

                    partitions.append(partition)

                except Exception as e:
                    print(f"[WARN] Error reading stream {stream_path}: {e}")
                    continue

        return partitions

    def analyze_deleted_partition(
        self,
        partition_id: str,
        output_dir: Path
    ) -> Optional[Dict[str, any]]:
        """
        Perform deep analysis on a deleted partition from file A.

        Args:
            partition_id: Partition ID to analyze (e.g., "2158")
            output_dir: Directory to save hex dumps

        Returns:
            Dictionary with analysis results
        """
        if not self.file_a_path:
            raise RuntimeError("Must call compare_files() first")

        print(f"\n[INFO] Analyzing deleted Partition {partition_id} from {self.file_a_path.name}")

        # Find the partition in file A
        target_partition = None

        with olefile.OleFileIO(str(self.file_a_path)) as ole:
            stream_list = ole.listdir()

            for stream_path_list in stream_list:
                stream_path = "/".join(stream_path_list)

                # Check if this is the target partition (supports "Partitions/2158" or "Partition_2158")
                match = re.search(r'Partition[s]?[/_\s]?(\d+)', stream_path, re.IGNORECASE)
                if match and match.group(1) == partition_id:
                    target_partition = stream_path_list
                    break

            if not target_partition:
                print(f"[ERROR] Partition {partition_id} not found in {self.file_a_path.name}")
                return None

            # Read partition data
            stream_data = ole.openstream(target_partition).read()
            stream_size = len(stream_data)

            print(f"[OK] Found partition: {'/'.join(target_partition)}")
            print(f"[OK] Size: {stream_size:,} bytes ({stream_size / 1024:.2f} KB)")

            # Generate hex dump
            hex_dump_path = output_dir / f"partition_{partition_id}_hexdump.txt"
            self._generate_hex_dump(stream_data, hex_dump_path)

            # Search for keywords
            keyword_findings = self._search_keywords(stream_data)

            # Attempt to decode as UTF-16LE (common in Revit)
            decoded_text_utf16 = ""
            try:
                decoded_text_utf16 = stream_data.decode('utf-16le', errors='ignore')
            except Exception:
                pass

            # Attempt to decode as Latin-1
            decoded_text_latin1 = ""
            try:
                decoded_text_latin1 = stream_data.decode('latin-1', errors='ignore')
            except Exception:
                pass

            # Save decoded text
            decoded_path = output_dir / f"partition_{partition_id}_decoded.txt"
            with open(decoded_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write(f"Partition {partition_id} Decoded Text Analysis\n")
                f.write("=" * 80 + "\n\n")
                f.write("[UTF-16LE Decoding]\n")
                f.write("-" * 80 + "\n")
                f.write(decoded_text_utf16[:10000])  # First 10KB
                f.write("\n\n")
                f.write("[Latin-1 Decoding]\n")
                f.write("-" * 80 + "\n")
                f.write(decoded_text_latin1[:10000])  # First 10KB

            print(f"[OK] Hex dump saved to: {hex_dump_path}")
            print(f"[OK] Decoded text saved to: {decoded_path}")

            # Estimate element count (heuristic based on partition structure)
            element_estimate = self._estimate_element_count(stream_data)

            analysis_result = {
                "partition_id": partition_id,
                "size_bytes": stream_size,
                "hex_dump_path": str(hex_dump_path),
                "decoded_path": str(decoded_path),
                "keyword_findings": keyword_findings,
                "element_count_estimate": element_estimate,
            }

            return analysis_result

    def _generate_hex_dump(self, data: bytes, output_path: Path) -> None:
        """Generate formatted hex dump of binary data."""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f"Hex Dump - Total Size: {len(data):,} bytes\n")
            f.write("=" * 80 + "\n\n")

            # Generate hex dump in 16-byte rows
            for offset in range(0, min(len(data), 65536), 16):  # Limit to first 64KB
                hex_chunk = data[offset:offset+16].hex()

                # Format as: OFFSET: HEX ASCII
                hex_formatted = " ".join(
                    hex_chunk[i:i+2] for i in range(0, len(hex_chunk), 2)
                )

                # ASCII representation
                ascii_repr = "".join(
                    chr(b) if 32 <= b < 127 else "."
                    for b in data[offset:offset+16]
                )

                f.write(f"{offset:08x}: {hex_formatted:<48}  {ascii_repr}\n")

    def _search_keywords(self, data: bytes) -> Dict[str, List[int]]:
        """
        Search for amenity-related keywords in binary data.

        Returns:
            Dictionary mapping keyword -> list of byte offsets where found
        """
        findings = {}

        # Try both UTF-16LE and Latin-1 encodings
        for keyword in self.AMENITY_KEYWORDS:
            offsets = []

            # Search as UTF-16LE
            keyword_utf16 = keyword.encode('utf-16le')
            offset = 0
            while True:
                index = data.find(keyword_utf16, offset)
                if index == -1:
                    break
                offsets.append(index)
                offset = index + 1

            # Search as Latin-1
            keyword_latin1 = keyword.encode('latin-1')
            offset = 0
            while True:
                index = data.find(keyword_latin1, offset)
                if index == -1:
                    break
                offsets.append(index)
                offset = index + 1

            if offsets:
                findings[keyword] = sorted(set(offsets))  # Remove duplicates

        return findings

    def _estimate_element_count(self, data: bytes) -> int:
        """
        Estimate Revit element count based on partition structure patterns.

        This is a heuristic based on common Revit element ID patterns.
        """
        # Look for element ID patterns (e.g., repeated sequences of 4-byte integers)
        # Revit element IDs are typically int32 values

        element_id_pattern = re.compile(b'[\x00-\xff]{4}', re.DOTALL)
        matches = element_id_pattern.findall(data)

        # Very rough estimate: assume ~100-500 bytes per element
        estimate = len(data) // 250

        return estimate

    def export_comparison_csv(self, output_path: Path) -> None:
        """Export detailed partition comparison to CSV."""
        if not self.comparison:
            raise RuntimeError("Must call compare_files() first")

        import csv

        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                "partition_path",
                "partition_id",
                "status",
                "size_file_a_bytes",
                "size_file_b_bytes",
                "size_diff_bytes",
                "sha256_file_a",
                "sha256_file_b",
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            # Write partitions only in A (DELETED)
            for part in self.comparison.partitions_only_in_a:
                writer.writerow({
                    "partition_path": part.path,
                    "partition_id": part.partition_id or "",
                    "status": "DELETED_IN_B",
                    "size_file_a_bytes": part.size_bytes,
                    "size_file_b_bytes": "",
                    "size_diff_bytes": f"-{part.size_bytes}",
                    "sha256_file_a": part.sha256_hash,
                    "sha256_file_b": "",
                })

            # Write partitions only in B (ADDED)
            for part in self.comparison.partitions_only_in_b:
                writer.writerow({
                    "partition_path": part.path,
                    "partition_id": part.partition_id or "",
                    "status": "ADDED_IN_B",
                    "size_file_a_bytes": "",
                    "size_file_b_bytes": part.size_bytes,
                    "size_diff_bytes": f"+{part.size_bytes}",
                    "sha256_file_a": "",
                    "sha256_file_b": part.sha256_hash,
                })

            # Write identical partitions
            for part_a, part_b in self.comparison.partitions_identical:
                writer.writerow({
                    "partition_path": part_a.path,
                    "partition_id": part_a.partition_id or "",
                    "status": "IDENTICAL",
                    "size_file_a_bytes": part_a.size_bytes,
                    "size_file_b_bytes": part_b.size_bytes,
                    "size_diff_bytes": "0",
                    "sha256_file_a": part_a.sha256_hash,
                    "sha256_file_b": part_b.sha256_hash,
                })

            # Write modified partitions
            for part_a, part_b in self.comparison.partitions_modified:
                size_diff = part_b.size_bytes - part_a.size_bytes
                writer.writerow({
                    "partition_path": part_a.path,
                    "partition_id": part_a.partition_id or "",
                    "status": "MODIFIED",
                    "size_file_a_bytes": part_a.size_bytes,
                    "size_file_b_bytes": part_b.size_bytes,
                    "size_diff_bytes": f"{size_diff:+d}",
                    "sha256_file_a": part_a.sha256_hash,
                    "sha256_file_b": part_b.sha256_hash,
                })

        print(f"[OK] CSV comparison exported to: {output_path}")

    def generate_forensic_report(self, output_path: Path) -> None:
        """Generate expert forensic analysis report."""
        if not self.comparison:
            raise RuntimeError("Must call compare_files() first")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("REVIT PARTITION FORENSIC ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"Analysis Date: {datetime.now().isoformat()}\n")
            f.write(f"File A (Original): {self.comparison.file_a_name}\n")
            f.write(f"File B (Variant): {self.comparison.file_b_name}\n\n")

            # File-level statistics
            f.write("-" * 80 + "\n")
            f.write("FILE-LEVEL STATISTICS\n")
            f.write("-" * 80 + "\n")
            f.write(f"File A Size: {self.comparison.file_a_size:,} bytes "
                   f"({self.comparison.file_a_size / (1024*1024):.2f} MB)\n")
            f.write(f"File B Size: {self.comparison.file_b_size:,} bytes "
                   f"({self.comparison.file_b_size / (1024*1024):.2f} MB)\n")

            size_diff = self.comparison.file_b_size - self.comparison.file_a_size
            f.write(f"Size Difference: {size_diff:+,} bytes "
                   f"({size_diff / (1024*1024):+.2f} MB)\n\n")

            # Partition-level statistics
            f.write("-" * 80 + "\n")
            f.write("PARTITION-LEVEL STATISTICS\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Partitions in File A: {self.comparison.total_partitions_a}\n")
            f.write(f"Total Partitions in File B: {self.comparison.total_partitions_b}\n")
            f.write(f"Deleted Partitions (in B): {len(self.comparison.partitions_only_in_a)}\n")
            f.write(f"Added Partitions (in B): {len(self.comparison.partitions_only_in_b)}\n")
            f.write(f"Identical Partitions: {len(self.comparison.partitions_identical)}\n")
            f.write(f"Modified Partitions: {len(self.comparison.partitions_modified)}\n")
            f.write(f"Estimated % of File Changed: {self.comparison.percent_file_changed:.2f}%\n\n")

            # Deleted partitions detail
            if self.comparison.partitions_only_in_a:
                f.write("-" * 80 + "\n")
                f.write("DELETED PARTITIONS (Present in File A, Absent in File B)\n")
                f.write("-" * 80 + "\n")

                total_deleted_bytes = sum(p.size_bytes for p in self.comparison.partitions_only_in_a)
                f.write(f"Total Data Deleted: {total_deleted_bytes:,} bytes "
                       f"({total_deleted_bytes / 1024:.2f} KB)\n\n")

                for part in self.comparison.partitions_only_in_a:
                    f.write(f"  - {part.path}\n")
                    f.write(f"    Partition ID: {part.partition_id or 'N/A'}\n")
                    f.write(f"    Size: {part.size_bytes:,} bytes ({part.size_bytes / 1024:.2f} KB)\n")
                    f.write(f"    SHA-256: {part.sha256_hash}\n\n")

            # Modified partitions detail (expansions)
            if self.comparison.partitions_modified:
                f.write("-" * 80 + "\n")
                f.write("MODIFIED PARTITIONS (Size Changes)\n")
                f.write("-" * 80 + "\n\n")

                # Sort by size difference (largest expansions first)
                sorted_modified = sorted(
                    self.comparison.partitions_modified,
                    key=lambda x: x[1].size_bytes - x[0].size_bytes,
                    reverse=True
                )

                for part_a, part_b in sorted_modified[:10]:  # Top 10
                    size_diff = part_b.size_bytes - part_a.size_bytes

                    if abs(size_diff) < 1024:  # Skip tiny changes
                        continue

                    f.write(f"  - {part_a.path}\n")
                    f.write(f"    Partition ID: {part_a.partition_id or 'N/A'}\n")
                    f.write(f"    Size File A: {part_a.size_bytes:,} bytes ({part_a.size_bytes / 1024:.2f} KB)\n")
                    f.write(f"    Size File B: {part_b.size_bytes:,} bytes ({part_b.size_bytes / 1024:.2f} KB)\n")
                    f.write(f"    Difference: {size_diff:+,} bytes ({size_diff / 1024:+.2f} KB)\n")

                    if size_diff > 0:
                        expansion_factor = part_b.size_bytes / part_a.size_bytes if part_a.size_bytes > 0 else 0
                        f.write(f"    Expansion Factor: {expansion_factor:.2f}x\n")

                    f.write("\n")

            # Expert interpretation
            f.write("-" * 80 + "\n")
            f.write("EXPERT INTERPRETATION\n")
            f.write("-" * 80 + "\n\n")

            if len(self.comparison.partitions_only_in_a) > 0:
                f.write("[CRITICAL FINDING] Deleted Partitions Detected\n\n")
                f.write(f"The variant file (File B: {self.comparison.file_b_name}) is MISSING ")
                f.write(f"{len(self.comparison.partitions_only_in_a)} partition(s) that exist in the ")
                f.write(f"original file (File A: {self.comparison.file_a_name}). This indicates ")
                f.write("potential data deletion between versions.\n\n")

                f.write("FORENSIC SIGNIFICANCE:\n")
                f.write("- Partition deletion suggests intentional removal of Revit elements/data\n")
                f.write("- Deleted partitions may contain design elements, families, or parameters\n")
                f.write("- Recommended: Perform keyword analysis on deleted partition data\n\n")

            if len(self.comparison.partitions_modified) > 0:
                large_expansions = [
                    (pa, pb) for pa, pb in self.comparison.partitions_modified
                    if (pb.size_bytes - pa.size_bytes) > 1024 * 1024  # > 1 MB
                ]

                if large_expansions:
                    f.write("[FINDING] Large Partition Expansions Detected\n\n")
                    f.write(f"Detected {len(large_expansions)} partition(s) with significant ")
                    f.write("size increases (>1 MB). This may indicate:\n")
                    f.write("- Addition of new design elements\n")
                    f.write("- Data reorganization/consolidation\n")
                    f.write("- Migration of data from deleted partitions\n\n")

            # Confidence assessment
            identical_count = len(self.comparison.partitions_identical)
            total_partitions = self.comparison.total_partitions_a

            if total_partitions > 0:
                identical_percentage = (identical_count / total_partitions) * 100

                f.write("-" * 80 + "\n")
                f.write("CONFIDENCE ASSESSMENT\n")
                f.write("-" * 80 + "\n\n")
                f.write(f"Partition-level Similarity: {identical_percentage:.2f}%\n")
                f.write(f"({identical_count} of {total_partitions} partitions bit-for-bit identical)\n\n")

                if identical_percentage > 80:
                    confidence = "HIGH"
                elif identical_percentage > 50:
                    confidence = "MODERATE"
                else:
                    confidence = "LOW"

                f.write(f"Confidence Level: {confidence}\n\n")
                f.write("INTERPRETATION:\n")

                if confidence == "HIGH":
                    f.write("- File B is highly derived from File A (>80% identical partitions)\n")
                    f.write("- Changes are localized to specific partitions\n")
                    f.write("- Deleted/modified partitions are primary areas of interest\n")
                elif confidence == "MODERATE":
                    f.write("- File B shows moderate derivation from File A (50-80% identical)\n")
                    f.write("- Significant structural changes detected\n")
                    f.write("- Recommend full element-level comparison\n")
                else:
                    f.write("- File B shows low similarity to File A (<50% identical)\n")
                    f.write("- Extensive modifications or different design lineage\n")
                    f.write("- Caution: May not be direct variant of File A\n")

        print(f"[OK] Forensic report saved to: {output_path}")


def main():
    """Main entry point for CLI usage."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Revit Partition Forensic Comparator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic comparison
  python revit_partition_comparator.py Lane.rvt Lane.0024.rvt --output ./analysis

  # With deleted partition analysis
  python revit_partition_comparator.py Lane.rvt Lane.0024.rvt --output ./analysis --analyze-partition 2158
        """
    )

    parser.add_argument(
        "file_a",
        help="Original RVT file (e.g., Lane.rvt)"
    )

    parser.add_argument(
        "file_b",
        help="Variant RVT file (e.g., Lane.0024.rvt)"
    )

    parser.add_argument(
        "--output", "-o",
        default="./partition_analysis",
        help="Output directory for analysis results (default: ./partition_analysis)"
    )

    parser.add_argument(
        "--analyze-partition", "-p",
        help="Partition ID to perform deep analysis on (e.g., 2158)"
    )

    args = parser.parse_args()

    # Create output directory
    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    print("[INFO] Revit Partition Forensic Comparator")
    print("=" * 80)

    # Initialize comparator
    comparator = RevitPartitionComparator()

    # Perform comparison
    try:
        comparison = comparator.compare_files(args.file_a, args.file_b)

        # Export CSV
        csv_path = output_dir / "RVT_PARTITION_COMPARISON.csv"
        comparator.export_comparison_csv(csv_path)

        # Generate forensic report
        report_path = output_dir / "RVT_PARTITION_FORENSIC_ANALYSIS.txt"
        comparator.generate_forensic_report(report_path)

        # Analyze specific partition if requested
        if args.analyze_partition:
            analysis_result = comparator.analyze_deleted_partition(
                args.analyze_partition,
                output_dir
            )

            if analysis_result:
                print("\n" + "=" * 80)
                print(f"PARTITION {args.analyze_partition} ANALYSIS RESULTS")
                print("=" * 80)
                print(f"Size: {analysis_result['size_bytes']:,} bytes")
                print(f"Element Count Estimate: {analysis_result['element_count_estimate']}")
                print(f"Keyword Findings:")

                for keyword, offsets in analysis_result['keyword_findings'].items():
                    print(f"  - '{keyword}' found at {len(offsets)} location(s)")

                if analysis_result['keyword_findings']:
                    print("\n[CRITICAL] Amenity-related keywords detected in deleted partition!")
                    print("This suggests the variant file removed amenity-related design elements.")
                else:
                    print("\n[INFO] No amenity keywords found in deleted partition.")

        print("\n" + "=" * 80)
        print("[OK] Analysis complete!")
        print(f"[OK] Results saved to: {output_dir}")

    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
