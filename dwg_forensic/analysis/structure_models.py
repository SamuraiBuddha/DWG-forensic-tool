"""
Structure comparison data models for DWG forensic analysis.

This module defines data structures for deep structural comparison between
two DWG files, including handle gap analysis, section map differences, and
object count deltas.

Phase 3.2 Implementation.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Tuple, Optional


@dataclass
class StructureDiff:
    """Deep structural differences between two DWG files.

    This represents the result of comparing internal DWG structure between
    two files to detect additions, deletions, and modifications at the
    object and section level.

    Attributes:
        handle_gaps_added: List of handle gap start positions that appear in file2 but not file1
        handle_gaps_removed: List of handle gap start positions that appear in file1 but not file2
        handle_gap_changes: Detailed handle gap comparison data
        section_changes: Section-level size and presence changes
        object_deltas: Object count changes by type (positive = added, negative = removed)
        property_changes: Metadata property changes (property_name -> (before, after))
        summary: Human-readable summary of structural changes
    """

    handle_gaps_added: List[int] = field(default_factory=list)
    handle_gaps_removed: List[int] = field(default_factory=list)
    handle_gap_changes: Dict[str, Any] = field(default_factory=dict)
    section_changes: Dict[str, Dict[str, int]] = field(default_factory=dict)
    object_deltas: Dict[str, int] = field(default_factory=dict)
    property_changes: Dict[str, Tuple[Any, Any]] = field(default_factory=dict)
    summary: str = ""

    def has_structural_changes(self) -> bool:
        """Check if any structural changes were detected.

        Returns:
            True if any handle gaps, sections, objects, or properties changed
        """
        return (
            len(self.handle_gaps_added) > 0
            or len(self.handle_gaps_removed) > 0
            or len(self.section_changes) > 0
            or len(self.object_deltas) > 0
            or len(self.property_changes) > 0
        )

    def get_change_severity(self) -> str:
        """Calculate severity level of structural changes.

        Returns:
            Severity level: NONE, MINOR, MAJOR, or CRITICAL
        """
        if not self.has_structural_changes():
            return "NONE"

        # Calculate severity based on change magnitude
        severity_score = 0

        # Handle gaps are significant structural changes
        total_gap_changes = len(self.handle_gaps_added) + len(self.handle_gaps_removed)
        if total_gap_changes > 100:
            severity_score += 3  # CRITICAL
        elif total_gap_changes > 10:
            severity_score += 2  # MAJOR
        elif total_gap_changes > 0:
            severity_score += 1  # MINOR

        # Section changes are moderately significant
        if len(self.section_changes) > 5:
            severity_score += 2
        elif len(self.section_changes) > 0:
            severity_score += 1

        # Object count changes
        total_object_changes = sum(abs(delta) for delta in self.object_deltas.values())
        if total_object_changes > 1000:
            severity_score += 3
        elif total_object_changes > 100:
            severity_score += 2
        elif total_object_changes > 0:
            severity_score += 1

        # Property changes are generally minor unless numerous
        if len(self.property_changes) > 10:
            severity_score += 2
        elif len(self.property_changes) > 0:
            severity_score += 1

        # Map score to severity level
        if severity_score >= 6:
            return "CRITICAL"
        elif severity_score >= 4:
            return "MAJOR"
        elif severity_score >= 1:
            return "MINOR"
        else:
            return "NONE"

    def summarize(self) -> str:
        """Generate human-readable summary of structural changes.

        Returns:
            Multi-line summary string describing all changes
        """
        if not self.has_structural_changes():
            return "No structural changes detected between files"

        lines = []
        severity = self.get_change_severity()
        lines.append(f"Structural Change Severity: {severity}")
        lines.append("")

        # Handle gap changes
        if self.handle_gaps_added or self.handle_gaps_removed:
            lines.append("Handle Gap Changes:")
            if self.handle_gaps_added:
                lines.append(f"  - Added gaps: {len(self.handle_gaps_added)}")
            if self.handle_gaps_removed:
                lines.append(f"  - Removed gaps: {len(self.handle_gaps_removed)}")

            # Add handle statistics if available
            if self.handle_gap_changes:
                total_missing_1 = self.handle_gap_changes.get("file1_missing_handles", 0)
                total_missing_2 = self.handle_gap_changes.get("file2_missing_handles", 0)
                if total_missing_1 or total_missing_2:
                    delta = total_missing_2 - total_missing_1
                    direction = "more" if delta > 0 else "fewer"
                    lines.append(
                        f"  - File 2 has {abs(delta)} {direction} missing handles "
                        f"({total_missing_1} -> {total_missing_2})"
                    )
            lines.append("")

        # Section changes
        if self.section_changes:
            lines.append("Section Changes:")
            for section_name, changes in sorted(self.section_changes.items()):
                size_before = changes.get("size_before", 0)
                size_after = changes.get("size_after", 0)
                if size_before == 0 and size_after > 0:
                    lines.append(f"  - {section_name}: Added ({size_after} bytes)")
                elif size_before > 0 and size_after == 0:
                    lines.append(f"  - {section_name}: Removed")
                else:
                    delta = size_after - size_before
                    direction = "increased" if delta > 0 else "decreased"
                    pct_change = (
                        abs(delta) / size_before * 100 if size_before > 0 else 0
                    )
                    lines.append(
                        f"  - {section_name}: Size {direction} by "
                        f"{abs(delta)} bytes ({pct_change:.1f}%)"
                    )
            lines.append("")

        # Object count changes
        if self.object_deltas:
            lines.append("Object Count Changes:")
            for obj_type, delta in sorted(
                self.object_deltas.items(), key=lambda x: abs(x[1]), reverse=True
            ):
                direction = "added" if delta > 0 else "removed"
                lines.append(f"  - {obj_type}: {abs(delta)} {direction}")
            lines.append("")

        # Property changes
        if self.property_changes:
            lines.append("Property Changes:")
            for prop_name, (before, after) in sorted(self.property_changes.items()):
                lines.append(f"  - {prop_name}: {before} -> {after}")
            lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization.

        Returns:
            Dictionary representation of structure diff
        """
        return {
            "has_changes": self.has_structural_changes(),
            "severity": self.get_change_severity(),
            "handle_gaps": {
                "added_count": len(self.handle_gaps_added),
                "removed_count": len(self.handle_gaps_removed),
                "added_gaps": [f"0x{gap:X}" for gap in self.handle_gaps_added],
                "removed_gaps": [f"0x{gap:X}" for gap in self.handle_gaps_removed],
                "details": self.handle_gap_changes,
            },
            "sections": {
                "changed_count": len(self.section_changes),
                "changes": self.section_changes,
            },
            "objects": {
                "changed_types": len(self.object_deltas),
                "total_delta": sum(self.object_deltas.values()),
                "deltas": self.object_deltas,
            },
            "properties": {
                "changed_count": len(self.property_changes),
                "changes": {
                    k: {"before": v[0], "after": v[1]}
                    for k, v in self.property_changes.items()
                },
            },
            "summary": self.summary,
        }
