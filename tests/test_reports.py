"""Tests for Phase 4 reporting modules."""

from datetime import datetime
from pathlib import Path

import pytest

from dwg_forensic.core.analyzer import ForensicAnalyzer
from dwg_forensic.models import ForensicAnalysis, RiskLevel
from dwg_forensic.output.hex_dump import HexDumpFormatter, format_hex_dump, extract_and_format
from dwg_forensic.output.timeline import (
    TimelineEvent,
    TimelineGenerator,
    generate_timeline,
)
from dwg_forensic.output.pdf_report import (
    PDFReportGenerator,
    generate_pdf_report,
)
from dwg_forensic.output.expert_witness import (
    ExpertWitnessGenerator,
    generate_expert_witness_document,
)


class TestHexDumpFormatter:
    """Tests for HexDumpFormatter class."""

    def test_format_empty_data(self):
        """Test formatting empty data."""
        formatter = HexDumpFormatter()
        result = formatter.format_bytes(b"")
        assert result == "(empty)"

    def test_format_simple_data(self):
        """Test formatting simple data."""
        formatter = HexDumpFormatter(bytes_per_line=8)
        result = formatter.format_bytes(b"ABCDEFGH")
        assert "41 42 43 44 45 46 47 48" in result
        assert "|ABCDEFGH|" in result

    def test_format_with_offset(self):
        """Test formatting with offset display."""
        formatter = HexDumpFormatter(bytes_per_line=4, show_offset=True)
        result = formatter.format_bytes(b"TEST", start_offset=0x100)
        assert "00000100:" in result

    def test_format_without_ascii(self):
        """Test formatting without ASCII representation."""
        formatter = HexDumpFormatter(bytes_per_line=4, show_ascii=False)
        result = formatter.format_bytes(b"TEST")
        assert "|" not in result

    def test_format_lowercase(self):
        """Test lowercase hex output."""
        formatter = HexDumpFormatter(uppercase=False)
        result = formatter.format_bytes(b"\xFF")
        assert "ff" in result

    def test_format_non_printable(self):
        """Test non-printable characters shown as dots."""
        formatter = HexDumpFormatter(bytes_per_line=4)
        result = formatter.format_bytes(b"\x00\x01\x02\x03")
        assert "|....|" in result

    def test_format_with_highlight(self):
        """Test formatting with highlighted bytes."""
        formatter = HexDumpFormatter(bytes_per_line=4)
        result = formatter.format_with_highlight(b"TEST", highlight_offsets=[1, 2])
        assert "[45]" in result  # E
        assert "[53]" in result  # S


class TestFormatHexDumpFunction:
    """Tests for format_hex_dump convenience function."""

    def test_format_hex_dump_basic(self):
        """Test basic hex dump formatting."""
        result = format_hex_dump(b"Hello World")
        assert "48 65 6C 6C 6F 20 57 6F 72 6C 64" in result
        assert "|Hello World|" in result

    def test_format_hex_dump_with_params(self):
        """Test hex dump with custom parameters."""
        result = format_hex_dump(b"Test", bytes_per_line=2, show_ascii=False)
        assert "54 65" in result
        assert "73 74" in result


class TestTimelineEvent:
    """Tests for TimelineEvent class."""

    def test_event_creation(self):
        """Test creating a timeline event."""
        timestamp = datetime(2024, 1, 15, 10, 30)
        event = TimelineEvent(
            timestamp=timestamp,
            event_type="created",
            description="File created",
            source="metadata",
        )
        assert event.timestamp == timestamp
        assert event.event_type == "created"
        assert event.description == "File created"
        assert event.source == "metadata"

    def test_event_comparison(self):
        """Test timeline event sorting by timestamp."""
        event1 = TimelineEvent(
            timestamp=datetime(2024, 1, 10),
            event_type="created",
            description="Earlier",
        )
        event2 = TimelineEvent(
            timestamp=datetime(2024, 1, 15),
            event_type="modified",
            description="Later",
        )
        assert event1 < event2


class TestTimelineGenerator:
    """Tests for TimelineGenerator class."""

    def test_generate_ascii_empty(self):
        """Test generating ASCII timeline with no events."""
        generator = TimelineGenerator()
        result = generator.generate_ascii([], title="Empty Timeline")
        assert "Empty Timeline" in result
        assert "No events to display" in result

    def test_generate_ascii_with_events(self):
        """Test generating ASCII timeline with events."""
        generator = TimelineGenerator()
        events = [
            TimelineEvent(
                timestamp=datetime(2024, 1, 15, 10, 0),
                event_type="created",
                description="File created",
            ),
            TimelineEvent(
                timestamp=datetime(2024, 1, 16, 14, 30),
                event_type="modified",
                description="File modified",
            ),
        ]
        result = generator.generate_ascii(events, title="Test Timeline")
        assert "Test Timeline" in result
        assert "[+]" in result  # created marker
        assert "[M]" in result  # modified marker
        assert "File created" in result
        assert "File modified" in result

    def test_generate_svg_empty(self):
        """Test generating SVG timeline with no events."""
        generator = TimelineGenerator()
        result = generator.generate_svg([], title="Empty Timeline")
        assert '<svg' in result
        assert 'No timeline events' in result

    def test_generate_svg_with_events(self):
        """Test generating SVG timeline with events."""
        generator = TimelineGenerator(width=800, height=400)
        events = [
            TimelineEvent(
                timestamp=datetime(2024, 1, 15),
                event_type="created",
                description="Created",
            ),
            TimelineEvent(
                timestamp=datetime(2024, 1, 20),
                event_type="analyzed",
                description="Analyzed",
            ),
        ]
        result = generator.generate_svg(events, title="Test Timeline")
        assert '<svg' in result
        assert 'width="800"' in result
        assert 'height="400"' in result
        assert 'Test Timeline' in result

    def test_extract_events_from_analysis(self, valid_dwg_ac1032):
        """Test extracting events from forensic analysis."""
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(valid_dwg_ac1032)

        generator = TimelineGenerator()
        events = generator.extract_events(analysis)

        # Should at least have analysis timestamp
        assert len(events) > 0
        assert any(e.event_type == "analyzed" for e in events)


class TestGenerateTimelineFunction:
    """Tests for generate_timeline convenience function."""

    def test_generate_timeline_ascii(self, valid_dwg_ac1032):
        """Test generating ASCII timeline from analysis."""
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(valid_dwg_ac1032)

        result = generate_timeline(analysis, format="ascii")
        assert "Timeline:" in result

    def test_generate_timeline_svg(self, valid_dwg_ac1032):
        """Test generating SVG timeline from analysis."""
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(valid_dwg_ac1032)

        result = generate_timeline(analysis, format="svg")
        assert '<svg' in result


class TestPDFReportGenerator:
    """Tests for PDFReportGenerator class."""

    def test_generator_init(self):
        """Test initializing the PDF report generator."""
        generator = PDFReportGenerator()
        assert generator.styles is not None

    def test_generate_report(self, valid_dwg_ac1032, temp_dir):
        """Test generating a PDF report."""
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(valid_dwg_ac1032)

        generator = PDFReportGenerator()
        output_path = temp_dir / "report.pdf"
        result = generator.generate(analysis, output_path)

        assert result.exists()
        assert result.stat().st_size > 0

    def test_generate_report_with_case_id(self, valid_dwg_ac1032, temp_dir):
        """Test generating a PDF report with case ID."""
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(valid_dwg_ac1032)

        generator = PDFReportGenerator()
        output_path = temp_dir / "report_with_case.pdf"
        result = generator.generate(analysis, output_path, case_id="CASE-2024-001")

        assert result.exists()

    def test_generate_report_with_hex_dump(self, valid_dwg_ac1032, temp_dir):
        """Test generating a PDF report with hex dump appendix."""
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(valid_dwg_ac1032)

        generator = PDFReportGenerator(include_hex_dumps=True)
        output_path = temp_dir / "report_with_hex.pdf"
        result = generator.generate(analysis, output_path)

        assert result.exists()
        # Hex dump version should be larger
        assert result.stat().st_size > 1000


class TestGeneratePDFReportFunction:
    """Tests for generate_pdf_report convenience function."""

    def test_generate_pdf_report_basic(self, valid_dwg_ac1032, temp_dir):
        """Test basic PDF report generation."""
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(valid_dwg_ac1032)

        output_path = temp_dir / "basic_report.pdf"
        result = generate_pdf_report(analysis, output_path)

        assert result.exists()
        assert result.name == "basic_report.pdf"

    def test_generate_pdf_report_with_all_options(self, valid_dwg_ac1032, temp_dir):
        """Test PDF report with all customization options."""
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(valid_dwg_ac1032)

        output_path = temp_dir / "full_report.pdf"
        result = generate_pdf_report(
            analysis=analysis,
            output_path=output_path,
            case_id="TEST-001",
            examiner_name="Test Examiner",
            company_name="Test Lab",
            include_hex_dumps=True,
        )

        assert result.exists()


class TestExpertWitnessGenerator:
    """Tests for ExpertWitnessGenerator class."""

    def test_generator_init(self):
        """Test initializing the expert witness generator."""
        generator = ExpertWitnessGenerator(
            expert_name="Dr. Smith",
            expert_credentials="PhD, CFE",
            company_name="Forensics Inc.",
        )
        assert generator.expert_name == "Dr. Smith"
        assert generator.expert_credentials == "PhD, CFE"
        assert generator.company_name == "Forensics Inc."

    def test_generator_defaults(self):
        """Test default values."""
        generator = ExpertWitnessGenerator()
        assert generator.expert_name == "Digital Forensics Expert"
        assert "Certified" in generator.expert_credentials

    def test_generate_methodology_document(self, valid_dwg_ac1032, temp_dir):
        """Test generating methodology document."""
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(valid_dwg_ac1032)

        generator = ExpertWitnessGenerator(expert_name="Test Expert")
        output_path = temp_dir / "methodology.pdf"
        result = generator.generate_methodology_document(analysis, output_path)

        assert result.exists()
        assert result.stat().st_size > 0

    def test_generate_with_case_id(self, valid_dwg_ac1032, temp_dir):
        """Test generating document with case ID."""
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(valid_dwg_ac1032)

        generator = ExpertWitnessGenerator()
        output_path = temp_dir / "methodology_case.pdf"
        result = generator.generate_methodology_document(
            analysis, output_path, case_id="EXPERT-001"
        )

        assert result.exists()


class TestGenerateExpertWitnessDocumentFunction:
    """Tests for generate_expert_witness_document convenience function."""

    def test_generate_basic(self, valid_dwg_ac1032, temp_dir):
        """Test basic document generation."""
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(valid_dwg_ac1032)

        output_path = temp_dir / "witness.pdf"
        result = generate_expert_witness_document(analysis, output_path)

        assert result.exists()

    def test_generate_with_all_options(self, valid_dwg_ac1032, temp_dir):
        """Test document generation with all options."""
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(valid_dwg_ac1032)

        output_path = temp_dir / "witness_full.pdf"
        result = generate_expert_witness_document(
            analysis=analysis,
            output_path=output_path,
            case_id="CASE-2024-TEST",
            expert_name="Dr. Jane Expert",
            expert_credentials="PhD, CCE, EnCE",
            company_name="Digital Evidence Lab",
        )

        assert result.exists()


class TestReportIntegration:
    """Integration tests for reporting modules."""

    def test_full_report_workflow(self, valid_dwg_ac1032, temp_dir):
        """Test complete reporting workflow."""
        # Run analysis
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(valid_dwg_ac1032)

        # Generate PDF report
        pdf_path = temp_dir / "full_report.pdf"
        pdf_result = generate_pdf_report(
            analysis=analysis,
            output_path=pdf_path,
            case_id="INTEGRATION-001",
        )

        # Generate expert witness document
        witness_path = temp_dir / "expert_witness.pdf"
        witness_result = generate_expert_witness_document(
            analysis=analysis,
            output_path=witness_path,
            case_id="INTEGRATION-001",
        )

        # Generate timeline
        timeline_result = generate_timeline(analysis, format="ascii")

        # Verify all outputs
        assert pdf_result.exists()
        assert witness_result.exists()
        assert len(timeline_result) > 0

    def test_reports_for_corrupted_file(self, corrupted_crc_dwg, temp_dir):
        """Test generating reports for a file with CRC mismatch."""
        analyzer = ForensicAnalyzer()
        analysis = analyzer.analyze(corrupted_crc_dwg)

        # Should still be able to generate reports
        pdf_path = temp_dir / "corrupted_report.pdf"
        result = generate_pdf_report(analysis, pdf_path)

        assert result.exists()
        # Should show HIGH or CRITICAL risk
        assert analysis.risk_assessment.overall_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]

    def test_hex_dump_file_region(self, valid_dwg_ac1032):
        """Test extracting and formatting a file region."""
        result = extract_and_format(
            file_path=valid_dwg_ac1032,
            offset=0,
            length=16,
            context_bytes=0,
        )

        # Should contain version string
        assert "41 43" in result  # AC in hex
        assert "1032" or "|AC1032" in result
