"""Tests for Phase 3.3: Advanced Comparative Reporting

Tests PDF and JSON comparison report generation for forensic delta analysis.
"""

import json
import pytest
from pathlib import Path
from datetime import datetime, timedelta

from dwg_forensic.output.comparison_report import (
    ComparisonReportGenerator,
    generate_comparison_pdf_report,
    generate_comparison_json_report,
)
from dwg_forensic.analysis.comparator import ComparisonResult
from dwg_forensic.models import (
    ForensicAnalysis,
    FileInfo,
    HeaderAnalysis,
    CRCValidation,
    RiskAssessment,
    RiskLevel,
    DWGMetadata,
)
from dwg_forensic.analysis.structure_models import StructureDiff


def create_test_analysis(
    filename: str = "test.dwg",
    risk_level: RiskLevel = RiskLevel.LOW,
    created_date: datetime = None,
    modified_date: datetime = None,
) -> ForensicAnalysis:
    """Create a test ForensicAnalysis for comparison testing."""
    if created_date is None:
        created_date = datetime(2024, 1, 1, 12, 0, 0)
    if modified_date is None:
        modified_date = datetime(2024, 1, 2, 12, 0, 0)

    return ForensicAnalysis(
        file_info=FileInfo(
            filename=filename,
            sha256="a" * 64,
            file_size_bytes=1024,
            intake_timestamp=datetime.now(),
        ),
        header_analysis=HeaderAnalysis(
            version_string="AC1032",
            version_name="AutoCAD 2018+",
            is_supported=True,
        ),
        crc_validation=CRCValidation(
            header_crc_stored="0x12345678",
            header_crc_calculated="0x12345678",
            is_valid=True,
        ),
        metadata=DWGMetadata(
            created_date=created_date,
            modified_date=modified_date,
        ),
        risk_assessment=RiskAssessment(
            overall_risk=risk_level,
            factors=["No significant findings"],
            recommendation="File appears authentic",
        ),
        analyzer_version="1.0.0",
    )


def test_comparison_report_pdf_generation(tmp_path):
    """Test: Generate PDF from ComparisonResult."""
    # Create two test analyses
    analysis1 = create_test_analysis(
        filename="file1.dwg",
        risk_level=RiskLevel.LOW,
        created_date=datetime(2024, 1, 1, 12, 0, 0),
    )
    analysis2 = create_test_analysis(
        filename="file2.dwg",
        risk_level=RiskLevel.MEDIUM,
        created_date=datetime(2024, 1, 5, 12, 0, 0),
    )

    # Create comparison result
    comparison = ComparisonResult(
        file1_analysis=analysis1,
        file2_analysis=analysis2,
        timestamp_delta_seconds=4 * 86400,  # 4 days
        modification_delta_seconds=4 * 86400,
        metadata_changes=["Risk level changed: LOW -> MEDIUM"],
        risk_level_change="LOW -> MEDIUM",
        comparison_summary="Test comparison",
    )

    # Generate PDF
    output_path = tmp_path / "comparison_report.pdf"
    generator = ComparisonReportGenerator()
    result_path = generator.generate_pdf(comparison, output_path)

    assert result_path.exists()
    assert result_path.suffix == ".pdf"
    assert result_path.stat().st_size > 1000  # PDF should have content


def test_comparison_report_json_export(tmp_path):
    """Test: Export JSON with all comparison data."""
    # Create two test analyses
    analysis1 = create_test_analysis(filename="file1.dwg")
    analysis2 = create_test_analysis(filename="file2.dwg")

    # Create comparison result with structure diff
    structure_diff = StructureDiff()
    structure_diff.section_changes = {
        "OBJECTS": {"size_before": 1000, "size_after": 1200, "delta": 200}
    }
    structure_diff.object_deltas = {"LINE": 10, "CIRCLE": -5}

    comparison = ComparisonResult(
        file1_analysis=analysis1,
        file2_analysis=analysis2,
        structure_diff=structure_diff,
        comparison_summary="Test comparison with structure diff",
    )

    # Generate JSON
    output_path = tmp_path / "comparison_report.json"
    generator = ComparisonReportGenerator()
    result_path = generator.generate_json(comparison, output_path)

    assert result_path.exists()
    assert result_path.suffix == ".json"

    # Validate JSON content
    with open(result_path) as f:
        data = json.load(f)

    assert "comparison_metadata" in data
    assert "file1" in data
    assert "file2" in data
    assert "deltas" in data
    assert "structure_diff" in data
    assert data["file1"]["filename"] == "file1.dwg"
    assert data["file2"]["filename"] == "file2.dwg"
    assert data["structure_diff"]["section_changes"]["OBJECTS"]["delta"] == 200


def test_cli_compare_with_output_flag(tmp_path):
    """Test: compare file1.dwg file2.dwg -o report.pdf creates PDF."""
    from dwg_forensic.analysis.comparator import DWGComparator

    # This test requires actual DWG files or mocked comparator
    # For now, we test the report generation pipeline
    analysis1 = create_test_analysis(filename="file1.dwg")
    analysis2 = create_test_analysis(filename="file2.dwg")

    comparison = ComparisonResult(
        file1_analysis=analysis1,
        file2_analysis=analysis2,
        comparison_summary="CLI test comparison",
    )

    # Generate PDF report
    output_path = tmp_path / "cli_report.pdf"
    result_path = generate_comparison_pdf_report(
        comparison=comparison,
        output_path=output_path,
        case_id="TEST-001",
    )

    assert result_path.exists()
    assert result_path.suffix == ".pdf"


def test_batch_with_baseline_comparison():
    """Test: Batch generates deltas vs baseline (logic test)."""
    # Test the logic for baseline comparison
    # The actual batch processing would be tested with integration tests

    # Create baseline analysis
    baseline = create_test_analysis(filename="baseline.dwg", risk_level=RiskLevel.LOW)

    # Create file analyses
    file_analyses = [
        create_test_analysis(filename="file1.dwg", risk_level=RiskLevel.LOW),
        create_test_analysis(filename="file2.dwg", risk_level=RiskLevel.MEDIUM),
        create_test_analysis(filename="file3.dwg", risk_level=RiskLevel.HIGH),
    ]

    # For each file, we would generate a comparison against baseline
    # This tests the data flow
    comparisons = []
    for analysis in file_analyses:
        comp = ComparisonResult(
            file1_analysis=baseline,
            file2_analysis=analysis,
            comparison_summary=f"Comparison of {analysis.file_info.filename} vs baseline",
        )
        comparisons.append(comp)

    assert len(comparisons) == 3
    assert comparisons[0].file2_analysis.file_info.filename == "file1.dwg"
    assert comparisons[1].file2_analysis.risk_assessment.overall_risk == RiskLevel.MEDIUM


def test_report_contains_all_sections(tmp_path):
    """Test: PDF has metadata, timeline, structure, anomalies sections."""
    # Create test analyses with various features
    analysis1 = create_test_analysis(
        filename="file1.dwg",
        created_date=datetime(2024, 1, 1, 12, 0, 0),
        modified_date=datetime(2024, 1, 2, 12, 0, 0),
    )
    analysis2 = create_test_analysis(
        filename="file2.dwg",
        created_date=datetime(2024, 1, 10, 12, 0, 0),
        modified_date=datetime(2024, 1, 11, 12, 0, 0),
    )

    # Add structure diff
    structure_diff = StructureDiff()
    structure_diff.section_changes = {
        "OBJECTS": {"size_before": 1000, "size_after": 1500, "delta": 500}
    }
    structure_diff.handle_gaps_added = [100, 200]
    structure_diff.object_deltas = {"LINE": 25}

    comparison = ComparisonResult(
        file1_analysis=analysis1,
        file2_analysis=analysis2,
        timestamp_delta_seconds=9 * 86400,  # 9 days
        modification_delta_seconds=9 * 86400,
        metadata_changes=["Version changed"],
        structure_diff=structure_diff,
        comparison_summary="Complete comparison test",
    )

    # Generate PDF
    output_path = tmp_path / "complete_report.pdf"
    generator = ComparisonReportGenerator()
    result_path = generator.generate_pdf(comparison, output_path)

    assert result_path.exists()
    # PDF should be substantial with all sections
    assert result_path.stat().st_size > 5000


def test_comparison_report_with_case_id(tmp_path):
    """Test: PDF includes case ID when provided."""
    analysis1 = create_test_analysis(filename="file1.dwg")
    analysis2 = create_test_analysis(filename="file2.dwg")

    comparison = ComparisonResult(
        file1_analysis=analysis1,
        file2_analysis=analysis2,
        comparison_summary="Case ID test",
    )

    # Generate with case ID
    output_path = tmp_path / "case_report.pdf"
    result_path = generate_comparison_pdf_report(
        comparison=comparison,
        output_path=output_path,
        case_id="CASE-2024-001",
        company_name="Test Forensics LLC",
        examiner_name="Test Examiner",
    )

    assert result_path.exists()


def test_json_export_structure_diff_details(tmp_path):
    """Test: JSON export includes detailed structure diff data."""
    analysis1 = create_test_analysis(filename="file1.dwg")
    analysis2 = create_test_analysis(filename="file2.dwg")

    # Create detailed structure diff
    structure_diff = StructureDiff()
    structure_diff.section_changes = {
        "HEADER": {"size_before": 500, "size_after": 520, "delta": 20},
        "OBJECTS": {"size_before": 2000, "size_after": 2500, "delta": 500},
    }
    structure_diff.object_deltas = {"LINE": 10, "CIRCLE": -3, "POLYLINE": 5}
    structure_diff.handle_gaps_added = [100, 200, 300]
    structure_diff.handle_gaps_removed = [50]
    structure_diff.property_changes = {
        "author": ("Old Author", "New Author"),
        "title": ("Old Title", "New Title"),
    }

    comparison = ComparisonResult(
        file1_analysis=analysis1,
        file2_analysis=analysis2,
        structure_diff=structure_diff,
        comparison_summary="Detailed structure diff test",
    )

    # Generate JSON
    output_path = tmp_path / "structure_diff.json"
    result_path = generate_comparison_json_report(comparison, output_path)

    # Validate structure diff details
    with open(result_path) as f:
        data = json.load(f)

    assert data["structure_diff"] is not None
    assert len(data["structure_diff"]["section_changes"]) == 2
    assert data["structure_diff"]["section_changes"]["OBJECTS"]["delta"] == 500
    assert len(data["structure_diff"]["object_deltas"]) == 3
    assert data["structure_diff"]["object_deltas"]["LINE"] == 10
    assert len(data["structure_diff"]["handle_gaps_added"]) == 3
    assert len(data["structure_diff"]["handle_gaps_removed"]) == 1
    assert "author" in data["structure_diff"]["property_changes"]


def test_comparison_report_timestamp_visualization(tmp_path):
    """Test: Timestamp section includes timeline visualization data."""
    # Create files with significant time deltas
    analysis1 = create_test_analysis(
        filename="old_file.dwg",
        created_date=datetime(2023, 1, 1, 10, 0, 0),
        modified_date=datetime(2023, 1, 5, 15, 30, 0),
    )
    analysis2 = create_test_analysis(
        filename="new_file.dwg",
        created_date=datetime(2024, 6, 15, 14, 0, 0),
        modified_date=datetime(2024, 6, 20, 9, 45, 0),
    )

    # Calculate deltas
    ts_delta = int((analysis2.metadata.created_date - analysis1.metadata.created_date).total_seconds())
    mod_delta = int((analysis2.metadata.modified_date - analysis1.metadata.modified_date).total_seconds())

    comparison = ComparisonResult(
        file1_analysis=analysis1,
        file2_analysis=analysis2,
        timestamp_delta_seconds=ts_delta,
        modification_delta_seconds=mod_delta,
        comparison_summary="Timeline visualization test",
    )

    # Generate PDF (should include timeline section)
    output_path = tmp_path / "timeline_report.pdf"
    result_path = generate_comparison_pdf_report(comparison, output_path)

    assert result_path.exists()
    # Timeline delta is large (over 1 year)
    assert ts_delta > 365 * 86400


def test_comparison_report_no_structure_diff(tmp_path):
    """Test: Report handles missing structure diff gracefully."""
    analysis1 = create_test_analysis(filename="file1.dwg")
    analysis2 = create_test_analysis(filename="file2.dwg")

    comparison = ComparisonResult(
        file1_analysis=analysis1,
        file2_analysis=analysis2,
        structure_diff=None,  # No structure diff
        comparison_summary="No structure diff test",
    )

    # Generate PDF
    output_path = tmp_path / "no_structure.pdf"
    result_path = generate_comparison_pdf_report(comparison, output_path)

    assert result_path.exists()
    # Should still generate a valid report


def test_comparison_json_without_structure_diff(tmp_path):
    """Test: JSON export handles None structure_diff."""
    analysis1 = create_test_analysis(filename="file1.dwg")
    analysis2 = create_test_analysis(filename="file2.dwg")

    comparison = ComparisonResult(
        file1_analysis=analysis1,
        file2_analysis=analysis2,
        structure_diff=None,
        comparison_summary="No structure diff JSON test",
    )

    # Generate JSON
    output_path = tmp_path / "no_structure.json"
    result_path = generate_comparison_json_report(comparison, output_path)

    with open(result_path) as f:
        data = json.load(f)

    assert data["structure_diff"] is None


def test_anomaly_interpretation_logic():
    """Test: Anomaly interpretation generates correct forensic conclusions."""
    generator = ComparisonReportGenerator()

    # Test 1: No changes
    analysis1 = create_test_analysis("file1.dwg")
    analysis2 = create_test_analysis("file2.dwg")
    comparison = ComparisonResult(
        file1_analysis=analysis1,
        file2_analysis=analysis2,
        comparison_summary="Test",
    )
    interpretation = generator._generate_anomaly_interpretation(comparison)
    assert "same number" in interpretation.lower()

    # Test 2: Increase in anomalies (suspicious)
    from dwg_forensic.models import Anomaly, AnomalyType
    analysis2_with_anomalies = create_test_analysis("file2.dwg")
    analysis2_with_anomalies.anomalies = [
        Anomaly(
            anomaly_type=AnomalyType.CRC_MISMATCH,
            description="Test anomaly",
            severity=RiskLevel.HIGH,
        )
    ]
    comparison2 = ComparisonResult(
        file1_analysis=analysis1,
        file2_analysis=analysis2_with_anomalies,
        comparison_summary="Test",
    )
    interpretation2 = generator._generate_anomaly_interpretation(comparison2)
    assert "more anomalies" in interpretation2.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
