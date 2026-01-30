"""DWG file comparison module for forensic analysis.

This module provides comparison capabilities for analyzing differences between
two DWG files. Useful for detecting modifications, version changes, and
structural alterations.

Phase 3.1 Implementation:
- Basic comparison wrapper around two independent analyses
- Timestamp delta calculation
- Metadata change tracking

Phase 3.2 Implementation:
- Deep structure comparison (section map differences)
- Handle gap detection (object additions/deletions)
- Object count analysis
- Property change tracking
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, TYPE_CHECKING

from dwg_forensic.models import ForensicAnalysis
from dwg_forensic.analysis.structure_models import StructureDiff

if TYPE_CHECKING:
    from dwg_forensic.core.analyzer import ForensicAnalyzer


logger = logging.getLogger(__name__)


class StructureComparator:
    """Compares deep structural elements between two DWG files.

    Phase 3.2: Analyzes handle gaps, section maps, object counts, and properties.
    """

    def compare_structure(
        self, file1_analysis: ForensicAnalysis, file2_analysis: ForensicAnalysis
    ) -> StructureDiff:
        """Compare deep structure between two DWG file analyses.

        Args:
            file1_analysis: Forensic analysis of first file
            file2_analysis: Forensic analysis of second file

        Returns:
            StructureDiff with detailed structural comparison
        """
        diff = StructureDiff()

        # Compare handle gaps
        self._compare_handle_gaps(file1_analysis, file2_analysis, diff)

        # Compare section maps
        self._compare_sections(file1_analysis, file2_analysis, diff)

        # Compare object counts (from metadata/structure analysis)
        self._compare_object_counts(file1_analysis, file2_analysis, diff)

        # Compare properties
        self._compare_properties(file1_analysis, file2_analysis, diff)

        # Generate summary
        diff.summary = diff.summarize()

        return diff

    def _compare_handle_gaps(
        self,
        analysis1: ForensicAnalysis,
        analysis2: ForensicAnalysis,
        diff: StructureDiff,
    ) -> None:
        """Compare handle gaps between two files.

        Args:
            analysis1: First file analysis
            analysis2: Second file analysis
            diff: StructureDiff to populate
        """
        # Extract handle gap data from structure_analysis
        struct1 = analysis1.structure_analysis or {}
        struct2 = analysis2.structure_analysis or {}

        # Get handle gap information if available
        gaps1 = struct1.get("handle_gaps", [])
        gaps2 = struct2.get("handle_gaps", [])

        # Convert to sets of gap start positions for comparison
        gap_starts1 = {gap.get("start_handle", gap) for gap in gaps1 if gap}
        gap_starts2 = {gap.get("start_handle", gap) for gap in gaps2 if gap}

        # Find added and removed gaps
        diff.handle_gaps_added = sorted(gap_starts2 - gap_starts1)
        diff.handle_gaps_removed = sorted(gap_starts1 - gap_starts2)

        # Add detailed gap statistics
        diff.handle_gap_changes = {
            "file1_gap_count": len(gaps1),
            "file2_gap_count": len(gaps2),
            "file1_missing_handles": sum(
                gap.get("gap_size", 0) for gap in gaps1 if isinstance(gap, dict)
            ),
            "file2_missing_handles": sum(
                gap.get("gap_size", 0) for gap in gaps2 if isinstance(gap, dict)
            ),
            "gaps_added": len(diff.handle_gaps_added),
            "gaps_removed": len(diff.handle_gaps_removed),
        }

    def _compare_sections(
        self,
        analysis1: ForensicAnalysis,
        analysis2: ForensicAnalysis,
        diff: StructureDiff,
    ) -> None:
        """Compare section maps between two files.

        Args:
            analysis1: First file analysis
            analysis2: Second file analysis
            diff: StructureDiff to populate
        """
        struct1 = analysis1.structure_analysis or {}
        struct2 = analysis2.structure_analysis or {}

        # Get section information
        sections1 = struct1.get("sections", {})
        sections2 = struct2.get("sections", {})

        # Find all section names across both files
        all_sections = set(sections1.keys()) | set(sections2.keys())

        for section_name in all_sections:
            sect1 = sections1.get(section_name, {})
            sect2 = sections2.get(section_name, {})

            size1 = sect1.get("size", 0) if isinstance(sect1, dict) else 0
            size2 = sect2.get("size", 0) if isinstance(sect2, dict) else 0

            # Only record if there's a change
            if size1 != size2:
                diff.section_changes[section_name] = {
                    "size_before": size1,
                    "size_after": size2,
                    "delta": size2 - size1,
                }

    def _compare_object_counts(
        self,
        analysis1: ForensicAnalysis,
        analysis2: ForensicAnalysis,
        diff: StructureDiff,
    ) -> None:
        """Compare object counts between two files.

        Args:
            analysis1: First file analysis
            analysis2: Second file analysis
            diff: StructureDiff to populate
        """
        struct1 = analysis1.structure_analysis or {}
        struct2 = analysis2.structure_analysis or {}

        # Get object counts if available
        objects1 = struct1.get("object_counts", {})
        objects2 = struct2.get("object_counts", {})

        # Find all object types
        all_types = set(objects1.keys()) | set(objects2.keys())

        for obj_type in all_types:
            count1 = objects1.get(obj_type, 0)
            count2 = objects2.get(obj_type, 0)

            delta = count2 - count1
            if delta != 0:
                diff.object_deltas[obj_type] = delta

    def _compare_properties(
        self,
        analysis1: ForensicAnalysis,
        analysis2: ForensicAnalysis,
        diff: StructureDiff,
    ) -> None:
        """Compare drawing properties between two files.

        Args:
            analysis1: First file analysis
            analysis2: Second file analysis
            diff: StructureDiff to populate
        """
        if not analysis1.metadata or not analysis2.metadata:
            return

        m1 = analysis1.metadata
        m2 = analysis2.metadata

        # Compare key properties
        properties_to_compare = [
            ("title", m1.title, m2.title),
            ("author", m1.author, m2.author),
            ("last_saved_by", m1.last_saved_by, m2.last_saved_by),
            ("revision_number", m1.revision_number, m2.revision_number),
            ("fingerprint_guid", m1.fingerprint_guid, m2.fingerprint_guid),
            ("version_guid", m1.version_guid, m2.version_guid),
        ]

        for prop_name, val1, val2 in properties_to_compare:
            if val1 != val2 and (val1 is not None or val2 is not None):
                diff.property_changes[prop_name] = (val1, val2)


@dataclass
class ComparisonResult:
    """Result of comparing two DWG files.

    Phase 3.1: Basic comparison with timestamp deltas
    Phase 3.2: Deep structure comparison

    Attributes:
        file1_analysis: Forensic analysis of first file
        file2_analysis: Forensic analysis of second file
        timestamp_delta_seconds: Time difference between file creation (file2 - file1)
        modification_delta_seconds: Time difference between last modification (file2 - file1)
        structure_diff: Deep structural differences between files (Phase 3.2)
        metadata_changes: Detected metadata changes between files
        risk_level_change: Change in risk level (file2 - file1)
        comparison_summary: Human-readable summary of key differences
    """
    file1_analysis: ForensicAnalysis
    file2_analysis: ForensicAnalysis
    timestamp_delta_seconds: Optional[int] = None
    modification_delta_seconds: Optional[int] = None
    structure_diff: Optional[StructureDiff] = None
    metadata_changes: List[str] = field(default_factory=list)
    risk_level_change: Optional[str] = None
    comparison_summary: str = ""


class DWGComparator:
    """Compares two DWG files for forensic analysis.

    Phase 3.1: Basic comparison using independent analyses
    Phase 3.2: Deep structure and content comparison
    """

    def __init__(self):
        """Initialize DWG comparator."""
        # Import at runtime to avoid circular import
        from dwg_forensic.core.analyzer import ForensicAnalyzer
        self.analyzer = ForensicAnalyzer()
        self.structure_comparator = StructureComparator()

    def compare_files(self, file1: Path, file2: Path) -> ComparisonResult:
        """Compare two DWG files and identify differences.

        Phase 3.1 Implementation:
        - Analyzes both files independently
        - Calculates timestamp deltas
        - Identifies basic metadata changes
        - Compares risk levels

        Phase 3.2 Implementation:
        - Deep structure comparison (section maps, handle gaps)
        - Object-level change tracking
        - Property change detection

        Args:
            file1: Path to first DWG file
            file2: Path to second DWG file

        Returns:
            ComparisonResult with analysis and comparison data

        Raises:
            ValueError: If files don't exist
            DWGForensicError: If analysis fails
        """
        # Validate inputs
        if not file1.exists():
            raise ValueError(f"File does not exist: {file1}")
        if not file2.exists():
            raise ValueError(f"File does not exist: {file2}")

        logger.info(f"Comparing DWG files: {file1.name} vs {file2.name}")

        # Analyze both files
        analysis1 = self.analyzer.analyze(file1)
        analysis2 = self.analyzer.analyze(file2)

        # Calculate timestamp deltas
        timestamp_delta = self._calculate_timestamp_delta(analysis1, analysis2)
        modification_delta = self._calculate_modification_delta(analysis1, analysis2)

        # Detect metadata changes
        metadata_changes = self._detect_metadata_changes(analysis1, analysis2)

        # Compare risk levels
        risk_change = self._compare_risk_levels(analysis1, analysis2)

        # Phase 3.2: Deep structure comparison
        structure_diff = self.structure_comparator.compare_structure(analysis1, analysis2)

        # Generate summary
        summary = self._generate_comparison_summary(
            analysis1,
            analysis2,
            timestamp_delta,
            modification_delta,
            metadata_changes,
            risk_change,
            structure_diff,
        )

        return ComparisonResult(
            file1_analysis=analysis1,
            file2_analysis=analysis2,
            timestamp_delta_seconds=timestamp_delta,
            modification_delta_seconds=modification_delta,
            structure_diff=structure_diff,
            metadata_changes=metadata_changes,
            risk_level_change=risk_change,
            comparison_summary=summary,
        )

    def _calculate_timestamp_delta(
        self,
        analysis1: ForensicAnalysis,
        analysis2: ForensicAnalysis,
    ) -> Optional[int]:
        """Calculate time difference between file creation timestamps.

        Args:
            analysis1: Analysis of first file
            analysis2: Analysis of second file

        Returns:
            Delta in seconds (file2 - file1), or None if timestamps unavailable
        """
        # Try to use DWG internal timestamps first
        if analysis1.metadata and analysis1.metadata.created_date:
            ts1 = analysis1.metadata.created_date
        else:
            ts1 = analysis1.file_info.intake_timestamp

        if analysis2.metadata and analysis2.metadata.created_date:
            ts2 = analysis2.metadata.created_date
        else:
            ts2 = analysis2.file_info.intake_timestamp

        if ts1 and ts2:
            delta = (ts2 - ts1).total_seconds()
            return int(delta)

        return None

    def _calculate_modification_delta(
        self,
        analysis1: ForensicAnalysis,
        analysis2: ForensicAnalysis,
    ) -> Optional[int]:
        """Calculate time difference between last modification timestamps.

        Args:
            analysis1: Analysis of first file
            analysis2: Analysis of second file

        Returns:
            Delta in seconds (file2 - file1), or None if timestamps unavailable
        """
        # Use DWG internal modification timestamps
        ts1 = analysis1.metadata.modified_date if analysis1.metadata else None
        ts2 = analysis2.metadata.modified_date if analysis2.metadata else None

        if ts1 and ts2:
            delta = (ts2 - ts1).total_seconds()
            return int(delta)

        return None

    def _detect_metadata_changes(
        self,
        analysis1: ForensicAnalysis,
        analysis2: ForensicAnalysis,
    ) -> List[str]:
        """Detect changes in metadata between two files.

        Args:
            analysis1: Analysis of first file
            analysis2: Analysis of second file

        Returns:
            List of human-readable change descriptions
        """
        changes: List[str] = []

        if not analysis1.metadata or not analysis2.metadata:
            return changes

        m1 = analysis1.metadata
        m2 = analysis2.metadata

        # Check for author changes
        if m1.author != m2.author:
            changes.append(f"Author changed: '{m1.author}' -> '{m2.author}'")

        # Check for last saved by changes
        if m1.last_saved_by != m2.last_saved_by:
            changes.append(
                f"Last saved by changed: '{m1.last_saved_by}' -> '{m2.last_saved_by}'"
            )

        # Check for revision number changes
        if m1.revision_number is not None and m2.revision_number is not None:
            if m2.revision_number < m1.revision_number:
                changes.append(
                    f"Revision number decreased: {m1.revision_number} -> {m2.revision_number} "
                    f"(suspicious)"
                )
            elif m2.revision_number > m1.revision_number:
                changes.append(
                    f"Revision number increased: {m1.revision_number} -> {m2.revision_number}"
                )

        return changes

    def _compare_risk_levels(
        self,
        analysis1: ForensicAnalysis,
        analysis2: ForensicAnalysis,
    ) -> Optional[str]:
        """Compare risk levels between two files.

        Args:
            analysis1: Analysis of first file
            analysis2: Analysis of second file

        Returns:
            Human-readable risk level change description, or None if unchanged
        """
        risk1 = analysis1.risk_assessment.overall_risk.value
        risk2 = analysis2.risk_assessment.overall_risk.value

        if risk1 == risk2:
            return None

        return f"{risk1} -> {risk2}"

    def _generate_comparison_summary(
        self,
        analysis1: ForensicAnalysis,
        analysis2: ForensicAnalysis,
        timestamp_delta: Optional[int],
        modification_delta: Optional[int],
        metadata_changes: List[str],
        risk_change: Optional[str],
        structure_diff: Optional[StructureDiff] = None,
    ) -> str:
        """Generate human-readable comparison summary.

        Args:
            analysis1: Analysis of first file
            analysis2: Analysis of second file
            timestamp_delta: Creation timestamp delta in seconds
            modification_delta: Modification timestamp delta in seconds
            metadata_changes: List of metadata changes
            risk_change: Risk level change description
            structure_diff: Deep structure comparison results (Phase 3.2)

        Returns:
            Multi-line summary string
        """
        lines = []

        lines.append("DWG File Comparison Summary")
        lines.append("=" * 50)
        lines.append(f"File 1: {analysis1.file_info.filename}")
        lines.append(f"File 2: {analysis2.file_info.filename}")
        lines.append("")

        # Version comparison
        v1 = analysis1.header_analysis.version_string
        v2 = analysis2.header_analysis.version_string
        if v1 == v2:
            lines.append(f"DWG Version: {v1} (identical)")
        else:
            lines.append(f"DWG Version: {v1} -> {v2}")

        # Timestamp comparison
        if timestamp_delta is not None:
            days = abs(timestamp_delta) // 86400
            hours = (abs(timestamp_delta) % 86400) // 3600
            direction = "newer" if timestamp_delta > 0 else "older"
            lines.append(f"Creation Time Delta: {days}d {hours}h (File 2 is {direction})")

        if modification_delta is not None:
            days = abs(modification_delta) // 86400
            hours = (abs(modification_delta) % 86400) // 3600
            direction = "newer" if modification_delta > 0 else "older"
            lines.append(
                f"Modification Time Delta: {days}d {hours}h (File 2 is {direction})"
            )

        # Risk level comparison
        if risk_change:
            lines.append(f"Risk Level Change: {risk_change}")
        else:
            lines.append(
                f"Risk Level: {analysis1.risk_assessment.overall_risk.value} (unchanged)"
            )

        # Metadata changes
        if metadata_changes:
            lines.append("")
            lines.append("Metadata Changes:")
            for change in metadata_changes:
                lines.append(f"  - {change}")

        # Phase 3.2: Deep structure comparison
        if structure_diff:
            lines.append("")
            lines.append("=" * 50)
            lines.append("Deep Structure Comparison (Phase 3.2)")
            lines.append("=" * 50)
            lines.append(structure_diff.summary)

        return "\n".join(lines)


def compare_dwg_files(file1: Path, file2: Path) -> ComparisonResult:
    """Convenience function to compare two DWG files.

    Args:
        file1: Path to first DWG file
        file2: Path to second DWG file

    Returns:
        ComparisonResult with analysis and comparison data
    """
    comparator = DWGComparator()
    return comparator.compare_files(file1, file2)
