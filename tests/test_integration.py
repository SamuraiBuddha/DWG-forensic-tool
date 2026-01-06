"""
Comprehensive integration tests for DWG Forensic Tool.

Tests full workflows from end to end, ensuring all components
work together correctly for production use.
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest
from click.testing import CliRunner

from dwg_forensic import __version__
from dwg_forensic.cli import main
from dwg_forensic.core.analyzer import ForensicAnalyzer, analyze_file, analyze_tampering
from dwg_forensic.core.custody import CustodyChain, EventType
from dwg_forensic.core.file_guard import FileGuard
from dwg_forensic.core.intake import FileIntake
from dwg_forensic.models import ForensicAnalysis, RiskLevel
from dwg_forensic.output import (
    JSONExporter,
    export_to_json,
    generate_pdf_report,
    generate_expert_witness_document,
    generate_timeline,
    format_hex_dump,
)
from dwg_forensic.utils.audit import AuditLogger, get_audit_logger


class TestFullForensicWorkflow:
    """
    Tests the complete forensic analysis workflow from file intake
    through final report generation.
    """

    def test_complete_analysis_to_report_workflow(self, valid_dwg_ac1032, temp_dir):
        """
        Test complete workflow: analyze file -> generate all outputs.

        This simulates a real forensic examination workflow.
        """
        # Step 1: Perform forensic analysis
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(valid_dwg_ac1032)

        # Verify analysis completed
        assert isinstance(analysis, ForensicAnalysis)
        assert analysis.file_info.filename == "valid_ac1032.dwg"
        assert analysis.analyzer_version == __version__

        # Step 2: Export to JSON
        json_path = temp_dir / "analysis.json"
        exporter = JSONExporter(indent=2)
        exporter.to_file(analysis, json_path)
        assert json_path.exists()

        # Verify JSON is valid and contains expected data
        with open(json_path) as f:
            json_data = json.load(f)
        assert json_data["file_info"]["filename"] == "valid_ac1032.dwg"
        assert "header_analysis" in json_data
        assert "crc_validation" in json_data
        assert "risk_assessment" in json_data

        # Step 3: Generate PDF report
        pdf_path = temp_dir / "forensic_report.pdf"
        generate_pdf_report(
            analysis=analysis,
            output_path=pdf_path,
            case_id="INTEGRATION-TEST-001",
            examiner_name="Test Examiner",
        )
        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 1000  # Should be substantial

        # Step 4: Generate expert witness document
        witness_path = temp_dir / "expert_witness.pdf"
        generate_expert_witness_document(
            analysis=analysis,
            output_path=witness_path,
            case_id="INTEGRATION-TEST-001",
            expert_name="Dr. Test Expert",
        )
        assert witness_path.exists()

        # Step 5: Generate timeline
        timeline_ascii = generate_timeline(analysis, format="ascii")
        assert "Timeline:" in timeline_ascii

        timeline_svg_path = temp_dir / "timeline.svg"
        generate_timeline(analysis, output_path=timeline_svg_path, format="svg")
        assert timeline_svg_path.exists()

    def test_analysis_with_corrupted_file_workflow(self, corrupted_crc_dwg, temp_dir):
        """
        Test workflow with a corrupted file - should detect tampering
        and generate appropriate reports.
        """
        # Analyze corrupted file
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(corrupted_crc_dwg)

        # Should detect CRC mismatch
        assert analysis.crc_validation.is_valid is False

        # Should have HIGH or CRITICAL risk
        assert analysis.risk_assessment.overall_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]

        # Should still be able to generate report
        pdf_path = temp_dir / "corrupted_report.pdf"
        generate_pdf_report(analysis, pdf_path, case_id="CORRUPTED-001")
        assert pdf_path.exists()

        # JSON export should work
        json_output = export_to_json(analysis)
        json_data = json.loads(json_output)
        assert json_data["crc_validation"]["is_valid"] is False


class TestChainOfCustodyWorkflow:
    """
    Tests the complete chain of custody workflow including
    intake, event logging, and verification.
    """

    def test_complete_custody_workflow(self, valid_dwg_ac1032, temp_dir):
        """
        Test full chain of custody: intake -> events -> verification -> report.
        """
        evidence_dir = temp_dir / "evidence"
        db_path = temp_dir / "custody.db"

        # Use context managers to ensure proper cleanup on Windows
        with FileIntake(evidence_dir=evidence_dir, db_path=db_path) as intake:
            # Step 1: Intake evidence
            evidence = intake.intake(
                source_path=valid_dwg_ac1032,
                case_id="CUSTODY-TEST-001",
                examiner="Test Examiner",
                evidence_number="EV-001",
                notes="Integration test intake",
            )

            assert evidence.id is not None
            assert evidence.sha256 is not None
            assert evidence.evidence_number == "EV-001"

            # Step 2: Verify file was protected
            guard = FileGuard()
            evidence_path = Path(evidence.file_path)
            assert evidence_path.exists()

        # Use separate context for CustodyChain
        with CustodyChain(db_path) as custody:
            # Step 3: Log custody events
            # Log access event
            access_event = custody.log_event(
                evidence_id=evidence.id,
                event_type=EventType.ACCESS,
                examiner="Test Examiner",
                description="Accessed for analysis",
                verify_hash=True,
            )
            assert access_event.hash_verified is True

            # Log analysis event
            analysis_event = custody.log_event(
                evidence_id=evidence.id,
                event_type=EventType.ANALYSIS,
                examiner="Test Examiner",
                description="Performed forensic analysis",
                verify_hash=True,
            )
            assert analysis_event is not None

            # Step 4: Verify integrity
            is_valid, message = custody.verify_integrity(evidence.id)
            assert is_valid is True

            # Step 5: Generate custody report
            report = custody.generate_custody_report(evidence.id)
            assert report["evidence"]["id"] == evidence.id
            assert report["integrity_status"]["is_valid"] is True
            assert report["total_events"] >= 3  # Intake + Access + Analysis

    def test_custody_detects_tampering(self, valid_dwg_ac1032, temp_dir):
        """
        Test that chain of custody detects file modification.
        """
        evidence_dir = temp_dir / "evidence"
        db_path = temp_dir / "custody.db"

        # Intake using context manager
        with FileIntake(evidence_dir=evidence_dir, db_path=db_path) as intake:
            evidence = intake.intake(
                source_path=valid_dwg_ac1032,
                case_id="TAMPER-TEST-001",
                examiner="Test Examiner",
            )

        # Tamper with file (remove protection first)
        evidence_path = Path(evidence.file_path)
        guard = FileGuard()
        guard.unprotect(evidence_path)

        with open(evidence_path, "ab") as f:
            f.write(b"TAMPERED")

        # Verification should fail - use context manager
        with CustodyChain(db_path) as custody:
            is_valid, message = custody.verify_integrity(evidence.id)
            assert is_valid is False
            assert "mismatch" in message.lower() or "invalid" in message.lower()


class TestTamperingDetectionWorkflow:
    """
    Tests the tampering detection and analysis workflow.
    """

    def test_tampering_analysis_workflow(self, valid_dwg_ac1032, temp_dir):
        """
        Test complete tampering analysis workflow.
        """
        # Run tampering analysis
        report = analyze_tampering(valid_dwg_ac1032)

        # Valid file should have low risk
        assert report.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM]
        assert report.crc_valid is True

        # Should have factors and recommendation
        assert len(report.factors) > 0
        assert report.recommendation is not None

    def test_tampering_with_corrupted_file(self, corrupted_crc_dwg, temp_dir):
        """
        Test tampering analysis detects corruption.
        """
        report = analyze_tampering(corrupted_crc_dwg)

        # Should detect issues
        assert report.crc_valid is False
        assert report.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert report.rule_failures > 0

    def test_tampering_analysis_json_export(self, valid_dwg_ac1032):
        """
        Test that tampering report can be exported to JSON.
        """
        report = analyze_tampering(valid_dwg_ac1032)

        # Should be serializable
        json_output = json.dumps(report.model_dump(mode="json"), default=str)
        assert json_output is not None

        # Parse back
        parsed = json.loads(json_output)
        assert parsed["crc_valid"] == report.crc_valid


class TestAuditLoggingWorkflow:
    """
    Tests the audit logging throughout the forensic workflow.
    """

    def test_audit_trail_throughout_workflow(self, valid_dwg_ac1032, temp_dir):
        """
        Test that audit logging captures all operations.
        """
        log_dir = temp_dir / "audit_logs"
        audit = AuditLogger(log_dir)

        try:
            # Log intake
            audit.log_intake(
                evidence_id="test-123",
                case_id="AUDIT-TEST-001",
                examiner="Test Examiner",
                filename="test.dwg",
                sha256="a" * 64,
            )

            # Log analysis (no case_id parameter)
            audit.log_analysis(
                evidence_id="test-123",
                examiner="Test Examiner",
                analysis_type="forensic",
                findings={"risk": "LOW"},
            )

            # Log export (uses export_path and export_format)
            audit.log_export(
                evidence_id="test-123",
                examiner="Test Examiner",
                export_path="report.pdf",
                export_format="PDF",
            )

            # Retrieve audit trail
            trail = audit.get_audit_trail()
            assert len(trail) >= 3

            # Verify entries have required fields
            actions = [entry["action"] for entry in trail]
            assert "EVIDENCE_INTAKE" in actions
            assert "EVIDENCE_ANALYSIS" in actions
            assert "DATA_EXPORT" in actions
        finally:
            # Ensure logger is closed to release file handles on Windows
            audit.close()


class TestCLIIntegration:
    """
    Tests CLI command integration with all features.
    """

    def test_cli_analyze_to_json_workflow(self, valid_dwg_ac1032, temp_dir):
        """
        Test CLI analyze command with JSON output.
        """
        runner = CliRunner()
        output_path = temp_dir / "cli_output.json"

        result = runner.invoke(main, [
            "analyze",
            str(valid_dwg_ac1032),
            "-o", str(output_path),
        ])

        assert result.exit_code == 0
        assert output_path.exists()

        # Verify JSON content
        with open(output_path) as f:
            data = json.load(f)
        assert "file_info" in data
        assert "risk_assessment" in data

    def test_cli_tampering_command(self, valid_dwg_ac1032):
        """
        Test CLI tampering command.
        """
        runner = CliRunner()

        result = runner.invoke(main, [
            "tampering",
            str(valid_dwg_ac1032),
            "-f", "table",
        ])

        assert result.exit_code == 0
        assert "Risk Level" in result.output

    def test_cli_report_generation(self, valid_dwg_ac1032, temp_dir):
        """
        Test CLI report command.
        """
        runner = CliRunner()
        output_path = temp_dir / "cli_report.pdf"

        result = runner.invoke(main, [
            "report",
            str(valid_dwg_ac1032),
            "-o", str(output_path),
            "--case-id", "CLI-TEST-001",
        ])

        assert result.exit_code == 0
        assert output_path.exists()
        assert "[OK]" in result.output

    def test_cli_expert_witness_command(self, valid_dwg_ac1032, temp_dir):
        """
        Test CLI expert-witness command.
        """
        runner = CliRunner()
        output_path = temp_dir / "cli_expert.pdf"

        result = runner.invoke(main, [
            "expert-witness",
            str(valid_dwg_ac1032),
            "-o", str(output_path),
            "--expert-name", "Dr. CLI Test",
        ])

        assert result.exit_code == 0
        assert output_path.exists()

    def test_cli_timeline_command(self, valid_dwg_ac1032):
        """
        Test CLI timeline command.
        """
        runner = CliRunner()

        result = runner.invoke(main, [
            "timeline",
            str(valid_dwg_ac1032),
            "-f", "ascii",
        ])

        assert result.exit_code == 0
        assert "Timeline" in result.output

    def test_cli_list_rules_command(self):
        """
        Test CLI list-rules command.
        """
        runner = CliRunner()

        result = runner.invoke(main, ["list-rules"])

        assert result.exit_code == 0
        assert "TAMPER-001" in result.output
        assert "Total:" in result.output

    def test_cli_full_workflow(self, valid_dwg_ac1032, temp_dir):
        """
        Test complete CLI workflow: analyze -> verify -> report.
        """
        runner = CliRunner()

        # Analyze
        json_path = temp_dir / "full_analysis.json"
        result = runner.invoke(main, [
            "analyze",
            str(valid_dwg_ac1032),
            "-o", str(json_path),
        ])
        assert result.exit_code == 0

        # Validate CRC
        result = runner.invoke(main, [
            "validate-crc",
            str(valid_dwg_ac1032),
        ])
        assert result.exit_code == 0
        assert "[OK]" in result.output

        # Check watermark
        result = runner.invoke(main, [
            "check-watermark",
            str(valid_dwg_ac1032),
        ])
        assert result.exit_code == 0

        # Generate report
        pdf_path = temp_dir / "full_report.pdf"
        result = runner.invoke(main, [
            "report",
            str(valid_dwg_ac1032),
            "-o", str(pdf_path),
        ])
        assert result.exit_code == 0
        assert pdf_path.exists()


class TestEdgeCasesAndErrorHandling:
    """
    Tests edge cases and error handling across the system.
    """

    def test_handles_very_small_file(self, temp_dir):
        """
        Test handling of files too small to be valid DWG.
        """
        small_file = temp_dir / "tiny.dwg"
        small_file.write_bytes(b"AC1032")  # Only 6 bytes

        runner = CliRunner()
        result = runner.invoke(main, ["analyze", str(small_file)])

        assert result.exit_code != 0
        assert "error" in result.output.lower()

    def test_handles_invalid_file(self, temp_dir):
        """
        Test handling of non-DWG files.
        """
        invalid_file = temp_dir / "invalid.dwg"
        invalid_file.write_text("This is not a DWG file")

        runner = CliRunner()
        result = runner.invoke(main, ["analyze", str(invalid_file)])

        assert result.exit_code != 0

    def test_handles_nonexistent_file(self):
        """
        Test handling of nonexistent files.
        """
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", "/nonexistent/path/file.dwg"])

        assert result.exit_code != 0

    def test_handles_unsupported_version(self, unsupported_dwg_ac1015):
        """
        Test handling of unsupported DWG versions.
        """
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", str(unsupported_dwg_ac1015)])

        assert result.exit_code != 0
        assert "unsupported" in result.output.lower()


class TestCrossModuleIntegration:
    """
    Tests integration between different modules.
    """

    def test_analysis_to_hex_dump_integration(self, valid_dwg_ac1032):
        """
        Test that hex dump works with analyzed file data.
        """
        # Read file bytes
        with open(valid_dwg_ac1032, "rb") as f:
            header_bytes = f.read(128)

        # Format as hex dump
        hex_output = format_hex_dump(header_bytes, start_offset=0)

        # Should contain version string
        assert "41 43" in hex_output  # "AC" in hex
        assert "|AC1032" in hex_output

    def test_analysis_model_serialization_roundtrip(self, valid_dwg_ac1032):
        """
        Test that analysis can be serialized and deserialized.
        """
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(valid_dwg_ac1032)

        # Serialize
        exporter = JSONExporter()
        json_str = exporter.to_json(analysis)

        # Parse back
        data = json.loads(json_str)

        # Verify key fields
        assert data["file_info"]["sha256"] == analysis.file_info.sha256
        assert data["header_analysis"]["version_string"] == analysis.header_analysis.version_string
        assert data["crc_validation"]["is_valid"] == analysis.crc_validation.is_valid

    def test_all_risk_levels_handled(self, valid_dwg_ac1032, corrupted_crc_dwg, temp_dir):
        """
        Test that reports handle all risk levels properly.
        """
        analyzer = ForensicAnalyzer()

        # Low/Medium risk file
        analysis_low = analyzer.analyze(valid_dwg_ac1032)
        pdf_low = temp_dir / "low_risk.pdf"
        generate_pdf_report(analysis_low, pdf_low)
        assert pdf_low.exists()

        # High/Critical risk file
        analysis_high = analyzer.analyze(corrupted_crc_dwg)
        pdf_high = temp_dir / "high_risk.pdf"
        generate_pdf_report(analysis_high, pdf_high)
        assert pdf_high.exists()


class TestConcurrencyAndPerformance:
    """
    Tests for concurrent operations and performance.
    """

    def test_multiple_analyses_sequential(self, valid_dwg_ac1032, valid_dwg_ac1027, valid_dwg_ac1024):
        """
        Test multiple sequential analyses.
        """
        analyzer = ForensicAnalyzer()

        results = []
        for dwg_file in [valid_dwg_ac1032, valid_dwg_ac1027, valid_dwg_ac1024]:
            result = analyzer.analyze(dwg_file)
            results.append(result)

        # All should complete successfully
        assert len(results) == 3
        assert all(r.file_info.sha256 for r in results)

        # Each should have different version
        versions = {r.header_analysis.version_string for r in results}
        assert len(versions) == 3

    def test_reusing_analyzer_instance(self, valid_dwg_ac1032):
        """
        Test that analyzer can be reused for multiple files.
        """
        analyzer = ForensicAnalyzer()

        # Analyze same file multiple times
        result1 = analyzer.analyze(valid_dwg_ac1032)
        result2 = analyzer.analyze(valid_dwg_ac1032)

        # Results should be consistent
        assert result1.file_info.sha256 == result2.file_info.sha256
        assert result1.header_analysis.version_string == result2.header_analysis.version_string
