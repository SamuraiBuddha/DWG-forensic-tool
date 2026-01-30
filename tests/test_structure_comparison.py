"""
Tests for deep structure comparison module (Phase 3.2).

Tests handle gap comparison, section map comparison, object count comparison,
and property change detection between two DWG files.
"""

import pytest
from datetime import datetime
from copy import deepcopy

from dwg_forensic.analysis.comparator import StructureComparator
from dwg_forensic.analysis.structure_models import StructureDiff
from dwg_forensic.models import (
    ForensicAnalysis,
    FileInfo,
    HeaderAnalysis,
    CRCValidation,
    RiskAssessment,
    RiskLevel,
    DWGMetadata,
)


def create_minimal_analysis():
    """Create a minimal ForensicAnalysis for testing."""
    return ForensicAnalysis(
        file_info=FileInfo(
            filename="test.dwg",
            sha256="a" * 64,
            file_size_bytes=1024,
            intake_timestamp=datetime(2024, 1, 1, 10, 0, 0),
        ),
        header_analysis=HeaderAnalysis(
            version_string="AC1032",
            version_name="AutoCAD 2018+",
            maintenance_version=0,
            codepage=30,
            is_supported=True,
        ),
        crc_validation=CRCValidation(
            header_crc_stored="0x12345678",
            header_crc_calculated="0x12345678",
            is_valid=True,
        ),
        risk_assessment=RiskAssessment(
            overall_risk=RiskLevel.LOW,
            factors=["No anomalies detected"],
            recommendation="File appears genuine",
        ),
        analyzer_version="0.1.0",
    )


class TestStructureComparator:
    """Tests for StructureComparator class."""

    def test_initialization(self):
        """Test StructureComparator initialization."""
        comparator = StructureComparator()
        assert comparator is not None

    def test_compare_structure_no_structure_data(self):
        """Test comparison with no structure analysis data."""
        comparator = StructureComparator()
        analysis1 = create_minimal_analysis()
        analysis2 = create_minimal_analysis()

        diff = comparator.compare_structure(analysis1, analysis2)

        assert isinstance(diff, StructureDiff)
        assert not diff.has_structural_changes()
        assert diff.get_change_severity() == "NONE"

    def test_compare_handle_gaps_added(self):
        """Test detection of added handle gaps."""
        comparator = StructureComparator()

        # File 1 has no gaps
        analysis1 = create_minimal_analysis()
        analysis1.structure_analysis = {
            "handle_gaps": [],
        }

        # File 2 has new gaps
        analysis2 = create_minimal_analysis()
        analysis2.structure_analysis = {
            "handle_gaps": [
                {"start_handle": 0x100, "gap_size": 10},
                {"start_handle": 0x200, "gap_size": 5},
            ],
        }

        diff = comparator.compare_structure(analysis1, analysis2)

        assert len(diff.handle_gaps_added) == 2
        assert 0x100 in diff.handle_gaps_added
        assert 0x200 in diff.handle_gaps_added
        assert len(diff.handle_gaps_removed) == 0
        assert diff.has_structural_changes()

    def test_compare_handle_gaps_removed(self):
        """Test detection of removed handle gaps."""
        comparator = StructureComparator()

        # File 1 has gaps
        analysis1 = create_minimal_analysis()
        analysis1.structure_analysis = {
            "handle_gaps": [
                {"start_handle": 0x100, "gap_size": 10},
                {"start_handle": 0x200, "gap_size": 5},
            ],
        }

        # File 2 has no gaps (objects were added)
        analysis2 = create_minimal_analysis()
        analysis2.structure_analysis = {
            "handle_gaps": [],
        }

        diff = comparator.compare_structure(analysis1, analysis2)

        assert len(diff.handle_gaps_removed) == 2
        assert 0x100 in diff.handle_gaps_removed
        assert 0x200 in diff.handle_gaps_removed
        assert len(diff.handle_gaps_added) == 0
        assert diff.has_structural_changes()

    def test_compare_handle_gap_statistics(self):
        """Test handle gap statistics calculation."""
        comparator = StructureComparator()

        analysis1 = create_minimal_analysis()
        analysis1.structure_analysis = {
            "handle_gaps": [
                {"start_handle": 0x100, "gap_size": 10},
            ],
        }

        analysis2 = create_minimal_analysis()
        analysis2.structure_analysis = {
            "handle_gaps": [
                {"start_handle": 0x100, "gap_size": 10},
                {"start_handle": 0x200, "gap_size": 20},
            ],
        }

        diff = comparator.compare_structure(analysis1, analysis2)

        assert diff.handle_gap_changes["file1_gap_count"] == 1
        assert diff.handle_gap_changes["file2_gap_count"] == 2
        assert diff.handle_gap_changes["file1_missing_handles"] == 10
        assert diff.handle_gap_changes["file2_missing_handles"] == 30

    def test_compare_sections_added(self):
        """Test detection of added sections."""
        comparator = StructureComparator()

        # File 1 has one section
        analysis1 = create_minimal_analysis()
        analysis1.structure_analysis = {
            "sections": {
                "AcDb:Header": {"size": 1000},
            },
        }

        # File 2 has additional section
        analysis2 = create_minimal_analysis()
        analysis2.structure_analysis = {
            "sections": {
                "AcDb:Header": {"size": 1000},
                "AcDb:Classes": {"size": 500},
            },
        }

        diff = comparator.compare_structure(analysis1, analysis2)

        assert "AcDb:Classes" in diff.section_changes
        assert diff.section_changes["AcDb:Classes"]["size_before"] == 0
        assert diff.section_changes["AcDb:Classes"]["size_after"] == 500
        assert diff.has_structural_changes()

    def test_compare_sections_removed(self):
        """Test detection of removed sections."""
        comparator = StructureComparator()

        # File 1 has both sections
        analysis1 = create_minimal_analysis()
        analysis1.structure_analysis = {
            "sections": {
                "AcDb:Header": {"size": 1000},
                "AcDb:Classes": {"size": 500},
            },
        }

        # File 2 has one section removed
        analysis2 = create_minimal_analysis()
        analysis2.structure_analysis = {
            "sections": {
                "AcDb:Header": {"size": 1000},
            },
        }

        diff = comparator.compare_structure(analysis1, analysis2)

        assert "AcDb:Classes" in diff.section_changes
        assert diff.section_changes["AcDb:Classes"]["size_before"] == 500
        assert diff.section_changes["AcDb:Classes"]["size_after"] == 0

    def test_compare_sections_size_changed(self):
        """Test detection of section size changes."""
        comparator = StructureComparator()

        # File 1
        analysis1 = create_minimal_analysis()
        analysis1.structure_analysis = {
            "sections": {
                "AcDb:Header": {"size": 1000},
            },
        }

        # File 2 has larger header
        analysis2 = create_minimal_analysis()
        analysis2.structure_analysis = {
            "sections": {
                "AcDb:Header": {"size": 1500},
            },
        }

        diff = comparator.compare_structure(analysis1, analysis2)

        assert "AcDb:Header" in diff.section_changes
        assert diff.section_changes["AcDb:Header"]["delta"] == 500

    def test_compare_object_counts(self):
        """Test object count comparison."""
        comparator = StructureComparator()

        # File 1
        analysis1 = create_minimal_analysis()
        analysis1.structure_analysis = {
            "object_counts": {
                "LINE": 100,
                "CIRCLE": 50,
            },
        }

        # File 2 has more objects
        analysis2 = create_minimal_analysis()
        analysis2.structure_analysis = {
            "object_counts": {
                "LINE": 120,
                "CIRCLE": 45,
                "ARC": 10,
            },
        }

        diff = comparator.compare_structure(analysis1, analysis2)

        assert diff.object_deltas["LINE"] == 20
        assert diff.object_deltas["CIRCLE"] == -5
        assert diff.object_deltas["ARC"] == 10
        assert diff.has_structural_changes()

    def test_compare_properties(self):
        """Test property change detection."""
        comparator = StructureComparator()

        # File 1
        analysis1 = create_minimal_analysis()
        analysis1.metadata = DWGMetadata(
            title="Original Title",
            author="Alice",
            revision_number=5,
        )

        # File 2 has changed properties
        analysis2 = create_minimal_analysis()
        analysis2.metadata = DWGMetadata(
            title="Modified Title",
            author="Bob",
            revision_number=6,
        )

        diff = comparator.compare_structure(analysis1, analysis2)

        assert "title" in diff.property_changes
        assert diff.property_changes["title"] == ("Original Title", "Modified Title")
        assert "author" in diff.property_changes
        assert diff.property_changes["author"] == ("Alice", "Bob")
        assert "revision_number" in diff.property_changes
        assert diff.property_changes["revision_number"] == (5, 6)

    def test_compare_properties_no_metadata(self):
        """Test property comparison with missing metadata."""
        comparator = StructureComparator()

        analysis1 = create_minimal_analysis()
        analysis1.metadata = None

        analysis2 = create_minimal_analysis()
        analysis2.metadata = None

        diff = comparator.compare_structure(analysis1, analysis2)

        assert len(diff.property_changes) == 0


class TestStructureDiff:
    """Tests for StructureDiff model."""

    def test_has_structural_changes_empty(self):
        """Test has_structural_changes with no changes."""
        diff = StructureDiff()
        assert not diff.has_structural_changes()

    def test_has_structural_changes_with_handle_gaps(self):
        """Test has_structural_changes with handle gaps."""
        diff = StructureDiff(handle_gaps_added=[0x100])
        assert diff.has_structural_changes()

    def test_has_structural_changes_with_sections(self):
        """Test has_structural_changes with section changes."""
        diff = StructureDiff(
            section_changes={"AcDb:Header": {"size_before": 100, "size_after": 200}}
        )
        assert diff.has_structural_changes()

    def test_get_change_severity_none(self):
        """Test severity calculation with no changes."""
        diff = StructureDiff()
        assert diff.get_change_severity() == "NONE"

    def test_get_change_severity_minor(self):
        """Test severity calculation for minor changes."""
        diff = StructureDiff(
            handle_gaps_added=[0x100],
            object_deltas={"LINE": 5},
        )
        assert diff.get_change_severity() == "MINOR"

    def test_get_change_severity_major(self):
        """Test severity calculation for major changes."""
        diff = StructureDiff(
            handle_gaps_added=list(range(0x100, 0x120)),  # 32 gaps
            section_changes={
                "AcDb:Header": {"size_before": 100, "size_after": 200, "delta": 100},
                "AcDb:Classes": {"size_before": 100, "size_after": 200, "delta": 100},
                "AcDb:Objects": {"size_before": 100, "size_after": 200, "delta": 100},
                "AcDb:Preview": {"size_before": 100, "size_after": 200, "delta": 100},
                "AcDb:Handles": {"size_before": 100, "size_after": 200, "delta": 100},
                "AcDb:AppInfo": {"size_before": 100, "size_after": 200, "delta": 100},
            },
        )
        assert diff.get_change_severity() in ["MAJOR", "CRITICAL"]

    def test_get_change_severity_critical(self):
        """Test severity calculation for critical changes."""
        diff = StructureDiff(
            handle_gaps_added=list(range(0x100, 0x200)),  # 256 gaps
            object_deltas={"LINE": 2000},
        )
        assert diff.get_change_severity() == "CRITICAL"

    def test_summarize_no_changes(self):
        """Test summary generation with no changes."""
        diff = StructureDiff()
        summary = diff.summarize()
        assert "No structural changes" in summary

    def test_summarize_with_changes(self):
        """Test summary generation with changes."""
        diff = StructureDiff(
            handle_gaps_added=[0x100],
            handle_gap_changes={
                "file1_missing_handles": 10,
                "file2_missing_handles": 20,
            },
            section_changes={
                "AcDb:Header": {"size_before": 100, "size_after": 200, "delta": 100}
            },
            object_deltas={"LINE": 10},
            property_changes={"author": ("Alice", "Bob")},
        )

        summary = diff.summarize()
        assert "Handle Gap Changes" in summary
        assert "Section Changes" in summary
        assert "Object Count Changes" in summary
        assert "Property Changes" in summary

    def test_to_dict(self):
        """Test dictionary serialization."""
        diff = StructureDiff(
            handle_gaps_added=[0x100, 0x200],
            section_changes={
                "AcDb:Header": {"size_before": 100, "size_after": 200, "delta": 100}
            },
            object_deltas={"LINE": 10},
            property_changes={"author": ("Alice", "Bob")},
        )

        result = diff.to_dict()

        assert result["has_changes"] is True
        assert result["severity"] in ["MINOR", "MAJOR", "CRITICAL"]
        assert result["handle_gaps"]["added_count"] == 2
        assert "0x100" in result["handle_gaps"]["added_gaps"]
        assert "AcDb:Header" in result["sections"]["changes"]
        assert result["objects"]["deltas"]["LINE"] == 10
        assert "author" in result["properties"]["changes"]
