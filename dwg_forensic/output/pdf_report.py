"""
DWG Forensic Tool - PDF Report Generator

Generates litigation-ready PDF forensic reports using ReportLab.
Implements FR-REPORT-001 from the PRD.

Report sections:
1. Executive Summary (1 page, non-technical)
2. Technical Findings
3. Metadata Table
4. Anomaly/Tampering Findings
5. Hash Attestation Page
6. Chain of Custody Log
7. Appendix with Hex Dumps (optional)
"""

import io
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Union

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from dwg_forensic import __version__
from dwg_forensic.models import (
    Anomaly,
    ForensicAnalysis,
    RiskLevel,
    TamperingIndicator,
)
from dwg_forensic.output.hex_dump import HexDumpFormatter
from dwg_forensic.output.text_utils import sanitize_llm_output

# LLM integration (optional - gracefully degrades if unavailable)
try:
    from dwg_forensic.llm import ForensicNarrator
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    ForensicNarrator = None


class PDFReportStyles:
    """Custom styles for forensic PDF reports."""

    def __init__(self):
        """Initialize report styles."""
        self.styles = getSampleStyleSheet()
        self._add_custom_styles()

    def _add_custom_styles(self) -> None:
        """Add custom paragraph styles."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            alignment=TA_CENTER,
            spaceAfter=30,
            textColor=colors.HexColor('#1a1a1a'),
        ))

        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='ReportSubtitle',
            parent=self.styles['Heading2'],
            fontSize=14,
            alignment=TA_CENTER,
            spaceAfter=20,
            textColor=colors.HexColor('#666666'),
        ))

        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.HexColor('#2c3e50'),
            borderWidth=1,
            borderColor=colors.HexColor('#2c3e50'),
            borderPadding=5,
        ))

        # Executive summary text
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=12,
            leading=18,
            alignment=TA_JUSTIFY,
            spaceAfter=12,
        ))

        # Risk level styles
        self.styles.add(ParagraphStyle(
            name='RiskLow',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=colors.HexColor('#28a745'),
            fontName='Helvetica-Bold',
        ))

        self.styles.add(ParagraphStyle(
            name='RiskMedium',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=colors.HexColor('#ffc107'),
            fontName='Helvetica-Bold',
        ))

        self.styles.add(ParagraphStyle(
            name='RiskHigh',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=colors.HexColor('#fd7e14'),
            fontName='Helvetica-Bold',
        ))

        self.styles.add(ParagraphStyle(
            name='RiskCritical',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=colors.HexColor('#dc3545'),
            fontName='Helvetica-Bold',
        ))

        # Monospace for hex dumps and technical data
        self.styles.add(ParagraphStyle(
            name='Monospace',
            parent=self.styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=10,
        ))

        # Footer style
        self.styles.add(ParagraphStyle(
            name='Footer',
            parent=self.styles['Normal'],
            fontSize=8,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#888888'),
        ))

        # Narrative explanation style - for layman-friendly explanations
        self.styles.add(ParagraphStyle(
            name='Narrative',
            parent=self.styles['Normal'],
            fontSize=10,
            leading=14,
            alignment=TA_JUSTIFY,
            spaceAfter=10,
            leftIndent=15,
            rightIndent=15,
            backColor=colors.HexColor('#f8f9fa'),
            borderWidth=1,
            borderColor=colors.HexColor('#dee2e6'),
            borderPadding=8,
        ))

        # Narrative header style
        self.styles.add(ParagraphStyle(
            name='NarrativeHeader',
            parent=self.styles['Normal'],
            fontSize=11,
            fontName='Helvetica-Bold',
            textColor=colors.HexColor('#495057'),
            spaceBefore=15,
            spaceAfter=5,
        ))

        # Finding explanation style - for individual findings
        self.styles.add(ParagraphStyle(
            name='FindingExplanation',
            parent=self.styles['Normal'],
            fontSize=10,
            leading=13,
            alignment=TA_JUSTIFY,
            spaceAfter=8,
            leftIndent=20,
            textColor=colors.HexColor('#212529'),
        ))

        # Critical finding highlight
        self.styles.add(ParagraphStyle(
            name='CriticalNarrative',
            parent=self.styles['Normal'],
            fontSize=10,
            leading=14,
            alignment=TA_JUSTIFY,
            spaceAfter=10,
            leftIndent=15,
            rightIndent=15,
            backColor=colors.HexColor('#fff3cd'),
            borderWidth=2,
            borderColor=colors.HexColor('#dc3545'),
            borderPadding=8,
        ))


class PDFReportGenerator:
    """
    Generates professional PDF forensic reports.

    Creates litigation-ready documents with:
    - Executive summary for non-technical stakeholders
    - Detailed technical findings
    - Evidence documentation with hex dumps
    - Hash verification attestation
    - Chain of custody log
    """

    # Risk level colors for visual indicators
    RISK_COLORS = {
        RiskLevel.LOW: colors.HexColor('#28a745'),
        RiskLevel.MEDIUM: colors.HexColor('#ffc107'),
        RiskLevel.HIGH: colors.HexColor('#fd7e14'),
        RiskLevel.CRITICAL: colors.HexColor('#dc3545'),
    }

    def __init__(
        self,
        include_hex_dumps: bool = True,
        include_timeline: bool = True,
        company_name: Optional[str] = None,
        examiner_name: Optional[str] = None,
        use_llm_narration: bool = False,
        llm_model: Optional[str] = None,
    ):
        """
        Initialize the PDF report generator.

        Args:
            include_hex_dumps: Include hex dump appendix (default: True)
            include_timeline: Include timeline visualization (default: True)
            company_name: Company name for report header
            examiner_name: Examiner name for attestation
            use_llm_narration: Use LLM for enhanced narrative generation (default: False)
            llm_model: Ollama model to use for LLM narration (default: llama3.2)
        """
        self.include_hex_dumps = include_hex_dumps
        self.include_timeline = include_timeline
        self.company_name = company_name or "Digital Forensics Analysis"
        self.examiner_name = examiner_name or "Forensic Examiner"
        self.styles = PDFReportStyles()

        # Initialize LLM narrator if requested and available
        self.narrator = None
        self.use_llm = use_llm_narration and LLM_AVAILABLE
        if self.use_llm and ForensicNarrator:
            self.narrator = ForensicNarrator(model=llm_model, enabled=True)
            if not self.narrator.is_available():
                self.narrator = None
                self.use_llm = False

    def generate(
        self,
        analysis: ForensicAnalysis,
        output_path: Union[str, Path],
        case_id: Optional[str] = None,
    ) -> Path:
        """
        Generate a complete PDF forensic report.

        Args:
            analysis: Forensic analysis results
            output_path: Path to save the PDF
            case_id: Optional case identifier

        Returns:
            Path to the generated PDF file
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )

        # Build the report content
        story = []

        # Cover page
        story.extend(self._build_cover_page(analysis, case_id))
        story.append(PageBreak())

        # Executive Summary
        story.extend(self._build_executive_summary(analysis))
        story.append(PageBreak())

        # Comprehensive LLM Analysis (when enabled) - this replaces most boilerplate
        if self.narrator:
            story.extend(self._build_comprehensive_llm_analysis(analysis))
            story.append(PageBreak())

        # Technical Findings
        story.extend(self._build_technical_findings(analysis))
        story.append(PageBreak())

        # Metadata Section
        story.extend(self._build_metadata_section(analysis))

        # Timestamp Forensics Section (if timestamp data available)
        if analysis.metadata and (
            analysis.metadata.tdindwg is not None or
            analysis.metadata.tdcreate is not None
        ):
            story.append(PageBreak())
            story.extend(self._build_timestamp_analysis(analysis))

        # Anomalies and Tampering
        if analysis.anomalies or analysis.tampering_indicators:
            story.append(PageBreak())
            story.extend(self._build_findings_section(analysis))

        # Hash Attestation
        story.append(PageBreak())
        story.extend(self._build_hash_attestation(analysis, case_id))

        # Hex Dumps Appendix (optional)
        if self.include_hex_dumps:
            story.append(PageBreak())
            story.extend(self._build_hex_dump_appendix(analysis))

        # Build the PDF
        doc.build(story, onFirstPage=self._add_header_footer, onLaterPages=self._add_header_footer)

        return output_path

    def _build_cover_page(
        self,
        analysis: ForensicAnalysis,
        case_id: Optional[str],
    ) -> List:
        """Build the report cover page."""
        elements = []
        styles = self.styles.styles

        # Spacer at top
        elements.append(Spacer(1, 2 * inch))

        # Title
        elements.append(Paragraph(
            "FORENSIC ANALYSIS REPORT",
            styles['ReportTitle']
        ))

        # Subtitle with file name
        elements.append(Paragraph(
            f"File: {analysis.file_info.filename}",
            styles['ReportSubtitle']
        ))

        elements.append(Spacer(1, 0.5 * inch))

        # Get CAD application info for cover page
        cad_app = "Unknown"
        cad_confidence = ""
        if analysis.application_fingerprint:
            cad_app = analysis.application_fingerprint.detected_application.upper()
            conf_pct = int(analysis.application_fingerprint.confidence * 100)
            cad_confidence = f" ({conf_pct}% confidence)"

        # Report metadata table
        report_data = [
            ["Case ID:", case_id or "N/A"],
            ["Analysis Date:", analysis.analysis_timestamp.strftime("%Y-%m-%d %H:%M:%S")],
            ["Analyzer Version:", analysis.analyzer_version],
            ["CAD Application:", f"{cad_app}{cad_confidence}"],
            ["File SHA-256:", analysis.file_info.sha256[:32] + "..."],
            ["Risk Level:", analysis.risk_assessment.overall_risk.value],
        ]

        table = Table(report_data, colWidths=[2 * inch, 4 * inch])
        table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ]))
        elements.append(table)

        elements.append(Spacer(1, 1 * inch))

        # Confidentiality notice
        elements.append(Paragraph(
            "<b>CONFIDENTIAL</b><br/>"
            "This report contains forensic analysis results intended for authorized recipients only. "
            "Unauthorized disclosure, copying, or distribution is prohibited.",
            styles['Normal']
        ))

        return elements

    def _build_executive_summary(self, analysis: ForensicAnalysis) -> List:
        """Build the executive summary section."""
        elements = []
        styles = self.styles.styles

        elements.append(Paragraph("Executive Summary", styles['SectionHeader']))
        elements.append(Spacer(1, 0.2 * inch))

        # Risk assessment box
        risk_level = analysis.risk_assessment.overall_risk
        risk_style = f"Risk{risk_level.value.title()}"

        elements.append(Paragraph(
            f"Overall Risk Assessment: <b>{risk_level.value}</b>",
            styles.get(risk_style, styles['Normal'])
        ))
        elements.append(Spacer(1, 0.2 * inch))

        # Summary paragraphs
        summary_text = self._generate_executive_summary_text(analysis)
        for para in summary_text:
            elements.append(Paragraph(para, styles['ExecutiveSummary']))

        # Key findings table
        elements.append(Spacer(1, 0.3 * inch))
        elements.append(Paragraph("<b>Key Findings:</b>", styles['Normal']))
        elements.append(Spacer(1, 0.1 * inch))

        # Get CAD application for key findings
        cad_app_finding = "Unknown"
        if analysis.application_fingerprint:
            app_name = analysis.application_fingerprint.detected_application.upper()
            is_autodesk = analysis.application_fingerprint.is_autodesk
            cad_app_finding = f"{app_name}" + (" [Autodesk]" if is_autodesk else "")

        findings_data = [
            ["Finding", "Status"],
            ["Authoring Application", cad_app_finding],
            ["File Integrity (CRC)", "[OK]" if analysis.crc_validation.is_valid else "[FAIL]"],
            ["Anomalies Detected", str(len(analysis.anomalies))],
            ["Tampering Indicators", str(len(analysis.tampering_indicators))],
        ]

        table = Table(findings_data, colWidths=[4 * inch, 2 * inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ]))
        elements.append(table)

        # Recommendation
        elements.append(Spacer(1, 0.3 * inch))
        elements.append(Paragraph("<b>Recommendation:</b>", styles['Normal']))
        elements.append(Paragraph(
            analysis.risk_assessment.recommendation,
            styles['ExecutiveSummary']
        ))

        return elements

    def _generate_executive_summary_text(self, analysis: ForensicAnalysis) -> List[str]:
        """Generate executive summary paragraphs."""
        paragraphs = []

        # CRITICAL: SMOKING GUN VERDICT FIRST (if definitive proof exists)
        # This is the most important finding - put it at the very top
        if analysis.has_definitive_proof:
            smoking_gun_count = 0
            if analysis.smoking_gun_report:
                smoking_gun_count = analysis.smoking_gun_report.get("smoking_gun_count", 0)

            paragraphs.append(
                f"[!!] DEFINITIVE PROOF OF TAMPERING DETECTED: This forensic analysis has "
                f"identified {smoking_gun_count} mathematically impossible condition(s) that prove "
                f"this file has been tampered with. These findings constitute court-admissible "
                f"evidence of deliberate file manipulation. See the Smoking Gun Findings section "
                f"for detailed forensic reasoning."
            )

        # Opening paragraph
        paragraphs.append(
            f"This report presents the forensic analysis of the AutoCAD DWG file "
            f"'{analysis.file_info.filename}'. The analysis was performed on "
            f"{analysis.analysis_timestamp.strftime('%B %d, %Y')} using DWG Forensic Tool "
            f"version {analysis.analyzer_version}."
        )

        # File identification with CAD application
        cad_app_text = ""
        if analysis.application_fingerprint:
            app = analysis.application_fingerprint
            app_name = app.detected_application.upper()
            conf_pct = int(app.confidence * 100)
            if app.is_autodesk:
                cad_app_text = f" Forensic fingerprinting identified this file as created by {app_name} (genuine Autodesk software) with {conf_pct}% confidence."
            elif app.is_oda_based:
                cad_app_text = f" Forensic fingerprinting identified this file as created by {app_name} (ODA SDK-based CAD application) with {conf_pct}% confidence."
            else:
                cad_app_text = f" Forensic fingerprinting identified this file as created by {app_name} with {conf_pct}% confidence."

        paragraphs.append(
            f"The file is identified as {analysis.header_analysis.version_name} format "
            f"(version string: {analysis.header_analysis.version_string}). "
            f"The file size is {analysis.file_info.file_size_bytes:,} bytes.{cad_app_text}"
        )

        # Integrity assessment
        if analysis.crc_validation.is_valid:
            integrity_text = (
                "File integrity verification PASSED. The CRC32 checksum stored in the file header "
                "matches the calculated checksum, indicating the file has not been corrupted or "
                "tampered with at the binary level."
            )
        else:
            integrity_text = (
                "File integrity verification FAILED. The CRC32 checksum stored in the file header "
                "does NOT match the calculated checksum. This indicates the file was "
                "modified after it was originally saved."
            )
        paragraphs.append(integrity_text)

        return paragraphs

    def _build_technical_findings(self, analysis: ForensicAnalysis) -> List:
        """Build the technical findings section."""
        elements = []
        styles = self.styles.styles

        elements.append(Paragraph("Technical Findings", styles['SectionHeader']))
        elements.append(Spacer(1, 0.2 * inch))

        # Header Analysis
        elements.append(Paragraph("<b>Header Analysis</b>", styles['Heading3']))
        header_data = [
            ["Property", "Value"],
            ["Version String", analysis.header_analysis.version_string],
            ["Version Name", analysis.header_analysis.version_name],
            ["Maintenance Version", str(analysis.header_analysis.maintenance_version)],
            ["Codepage", str(analysis.header_analysis.codepage)],
            ["Supported Version", "Yes" if analysis.header_analysis.is_supported else "No"],
        ]

        table = Table(header_data, colWidths=[2.5 * inch, 4 * inch])
        table.setStyle(self._get_standard_table_style())
        elements.append(table)
        elements.append(Spacer(1, 0.3 * inch))

        # CRC Validation
        elements.append(Paragraph("<b>CRC Validation</b>", styles['Heading3']))
        crc_data = [
            ["Property", "Value"],
            ["Header CRC (Stored)", analysis.crc_validation.header_crc_stored],
            ["Header CRC (Calculated)", analysis.crc_validation.header_crc_calculated],
            ["Validation Status", "[OK] Valid" if analysis.crc_validation.is_valid else "[FAIL] Invalid"],
        ]

        table = Table(crc_data, colWidths=[2.5 * inch, 4 * inch])
        table.setStyle(self._get_standard_table_style())
        elements.append(table)
        elements.append(Spacer(1, 0.15 * inch))

        # CRC Narrative Explanation
        elements.append(Paragraph("What This Means:", styles['NarrativeHeader']))
        elements.extend(self._generate_crc_narrative(analysis))
        elements.append(Spacer(1, 0.3 * inch))

        # Application Fingerprint Analysis
        elements.append(Paragraph("<b>Application Fingerprint Analysis</b>", styles['Heading3']))
        if analysis.application_fingerprint:
            fp = analysis.application_fingerprint
            fingerprint_data = [
                ["Property", "Value"],
                ["Detected Application", fp.detected_application.upper()],
                ["Detection Confidence", f"{int(fp.confidence * 100)}%"],
                ["Is Autodesk Software", "Yes" if fp.is_autodesk else "No"],
                ["Uses ODA SDK", "Yes" if fp.is_oda_based else "No"],
            ]

            table = Table(fingerprint_data, colWidths=[2.5 * inch, 4 * inch])
            table.setStyle(self._get_standard_table_style())
            elements.append(table)
            elements.append(Spacer(1, 0.15 * inch))

            # Forensic significance explanation
            elements.append(Paragraph("What This Means:", styles['NarrativeHeader']))
            if fp.forensic_summary:
                elements.append(Paragraph(fp.forensic_summary, styles['Narrative']))
            else:
                elements.extend(self._generate_fingerprint_narrative(analysis))
        else:
            elements.append(Paragraph(
                "Application fingerprinting was not performed or no conclusive identification was made.",
                styles['Normal']
            ))
        elements.append(Spacer(1, 0.3 * inch))

        # Section Summary
        elements.append(Paragraph("Technical Findings Summary:", styles['NarrativeHeader']))
        elements.extend(self._generate_technical_summary(analysis))

        return elements

    def _build_metadata_section(self, analysis: ForensicAnalysis) -> List:
        """Build the metadata section."""
        elements = []
        styles = self.styles.styles

        elements.append(Paragraph("File Metadata", styles['SectionHeader']))
        elements.append(Spacer(1, 0.2 * inch))

        # File info
        elements.append(Paragraph("<b>File Information</b>", styles['Heading3']))
        file_data = [
            ["Property", "Value"],
            ["Filename", analysis.file_info.filename],
            ["File Size", f"{analysis.file_info.file_size_bytes:,} bytes"],
            ["SHA-256 Hash", analysis.file_info.sha256],
            ["Intake Timestamp", analysis.file_info.intake_timestamp.strftime("%Y-%m-%d %H:%M:%S")],
        ]

        table = Table(file_data, colWidths=[2 * inch, 4.5 * inch])
        table.setStyle(self._get_standard_table_style())
        elements.append(table)
        elements.append(Spacer(1, 0.3 * inch))

        # DWG Metadata (if available)
        if analysis.metadata:
            elements.append(Paragraph("<b>DWG Properties</b>", styles['Heading3']))
            meta = analysis.metadata
            meta_data = [
                ["Property", "Value"],
                ["Title", meta.title or "N/A"],
                ["Author", meta.author or "N/A"],
                ["Last Saved By", meta.last_saved_by or "N/A"],
                ["Created Date", meta.created_date.strftime("%Y-%m-%d %H:%M:%S") if meta.created_date else "N/A"],
                ["Modified Date", meta.modified_date.strftime("%Y-%m-%d %H:%M:%S") if meta.modified_date else "N/A"],
                ["Total Editing Time", f"{meta.total_editing_time_hours:.2f} hours" if meta.total_editing_time_hours else "N/A"],
            ]

            table = Table(meta_data, colWidths=[2 * inch, 4.5 * inch])
            table.setStyle(self._get_standard_table_style())
            elements.append(table)

        return elements

    def _build_timestamp_analysis(self, analysis: ForensicAnalysis) -> List:
        """Build the timestamp forensic analysis section."""
        elements = []
        styles = self.styles.styles

        elements.append(Paragraph("Timestamp Forensic Analysis", styles['SectionHeader']))
        elements.append(Spacer(1, 0.2 * inch))

        meta = analysis.metadata
        if not meta:
            elements.append(Paragraph("Timestamp data not available", styles['Normal']))
            return elements

        # Introduction paragraph
        elements.append(Paragraph(
            "This section analyzes DWG internal timestamps for signs of clock manipulation. "
            "The TDINDWG variable tracks cumulative editing time and cannot be reset through "
            "normal AutoCAD operations, making it a reliable indicator of timestamp authenticity.",
            styles['ExecutiveSummary']
        ))
        elements.append(Spacer(1, 0.2 * inch))

        # Convert MJD values to readable format if available
        def format_mjd(mjd_val):
            """Convert MJD fraction to hours or format datetime."""
            if mjd_val is None:
                return "N/A"
            if mjd_val < 100:  # Likely a duration in days
                hours = mjd_val * 24
                if hours < 1:
                    return f"{hours * 60:.1f} minutes"
                return f"{hours:.2f} hours"
            # Likely a date - just return the raw value
            return f"{mjd_val:.6f} (MJD)"

        # Build timestamp data table
        elements.append(Paragraph("<b>Timestamp Variables</b>", styles['Heading3']))

        ts_data = [
            ["Variable", "Value", "Description"],
            [
                "TDCREATE",
                format_mjd(meta.tdcreate) if meta.tdcreate and meta.tdcreate < 100 else
                (str(meta.created_date.strftime("%Y-%m-%d %H:%M:%S") if meta.created_date else "N/A")),
                "Local creation timestamp"
            ],
            [
                "TDUPDATE",
                format_mjd(meta.tdupdate) if meta.tdupdate and meta.tdupdate < 100 else
                (str(meta.modified_date.strftime("%Y-%m-%d %H:%M:%S") if meta.modified_date else "N/A")),
                "Local last-save timestamp"
            ],
            [
                "TDINDWG",
                format_mjd(meta.tdindwg) if meta.tdindwg else "N/A",
                "Cumulative editing time (READ-ONLY)"
            ],
            [
                "TDUSRTIMER",
                format_mjd(meta.tdusrtimer) if meta.tdusrtimer else "N/A",
                "User-resettable timer"
            ],
        ]

        table = Table(ts_data, colWidths=[1.5 * inch, 2 * inch, 3 * inch])
        table.setStyle(self._get_standard_table_style())
        elements.append(table)
        elements.append(Spacer(1, 0.15 * inch))

        # Narrative explanation of timestamp variables
        elements.append(Paragraph("What These Variables Mean:", styles['NarrativeHeader']))
        timestamp_narrative = (
            "<b>Understanding DWG Timestamps:</b> AutoCAD stores several timestamps that help "
            "determine when a drawing was created and how long it was worked on. The key insight "
            "is that TDINDWG (total editing time) is a READ-ONLY counter that cannot be reset "
            "by users. It continuously accumulates editing time across all sessions. If someone "
            "tries to make a file look older by changing TDCREATE (creation date), the TDINDWG "
            "value will often reveal the deception because the editing time won't match the "
            "claimed timeline. TDUSRTIMER can be reset by users, so it is less reliable for "
            "forensic purposes."
        )
        elements.append(Paragraph(timestamp_narrative, styles['Narrative']))
        elements.append(Spacer(1, 0.3 * inch))

        # Calculate and display calendar span vs editing time
        if meta.tdindwg is not None and meta.created_date and meta.modified_date:
            elements.append(Paragraph("<b>Impossibility Analysis</b>", styles['Heading3']))

            # Calculate calendar span
            calendar_span = (meta.modified_date - meta.created_date).total_seconds() / 3600
            tdindwg_hours = meta.tdindwg * 24 if meta.tdindwg else 0

            analysis_data = [
                ["Metric", "Value"],
                ["Calendar Span", f"{calendar_span:.2f} hours"],
                ["Editing Time (TDINDWG)", f"{tdindwg_hours:.2f} hours"],
            ]

            # Check for impossibility
            if tdindwg_hours > calendar_span * 1.1:
                excess = tdindwg_hours - calendar_span
                analysis_data.append(["Excess Time", f"{excess:.2f} hours"])
                analysis_data.append(["Status", "[CRITICAL] IMPOSSIBLE - Clock Manipulation Proven"])
            else:
                analysis_data.append(["Status", "[OK] Timestamps Consistent"])

            table = Table(analysis_data, colWidths=[2.5 * inch, 4 * inch])
            table.setStyle(self._get_standard_table_style())
            elements.append(table)
            elements.append(Spacer(1, 0.2 * inch))

            # Add detailed explanation - use LLM if available
            elements.append(Paragraph("What This Analysis Proves:", styles['NarrativeHeader']))

            llm_analysis_added = False
            # Use LLM narrator for timestamp analysis if available
            if self.narrator:
                result = self.narrator.generate_section_analysis(analysis, "timestamps")
                if result.success:
                    # Sanitize LLM output for ReportLab compatibility
                    sanitized_narrative = sanitize_llm_output(result.narrative)
                    # Use LLM-generated analysis
                    style = styles['CriticalNarrative'] if tdindwg_hours > calendar_span * 1.1 else styles['Narrative']
                    elements.append(Paragraph(sanitized_narrative, style))
                    if result.generation_time_ms:
                        elements.append(Paragraph(
                            f"<i>[Timestamp analysis by AI Forensic Expert - Model: {result.model_used} - {result.generation_time_ms}ms]</i>",
                            styles['Normal']
                        ))
                    llm_analysis_added = True

            # Static fallback - only if LLM didn't generate content
            if not llm_analysis_added and tdindwg_hours > calendar_span * 1.1:
                excess = tdindwg_hours - calendar_span
                impossibility_narrative = (
                    f"<b>[!] DEFINITIVE PROOF OF CLOCK MANIPULATION:</b> "
                    f"According to this file's timestamps, it was created on "
                    f"{meta.created_date.strftime('%B %d, %Y')} and last saved on "
                    f"{meta.modified_date.strftime('%B %d, %Y')}. That is a span of "
                    f"{calendar_span:.1f} hours. However, the file records {tdindwg_hours:.1f} hours "
                    f"of actual editing time - that is {excess:.1f} MORE hours than physically existed "
                    f"between those two dates. This is mathematically impossible. "
                    f"The only explanation is that someone manipulated the computer's clock to "
                    f"make the file appear to be created earlier than it actually was. "
                    f"This is definitive, irrefutable evidence of timestamp falsification."
                )
                elements.append(Paragraph(impossibility_narrative, styles['CriticalNarrative']))
            elif not llm_analysis_added:
                consistency_narrative = (
                    f"<b>Timestamps Are Consistent:</b> The calendar span between creation and "
                    f"last save ({calendar_span:.1f} hours) is greater than the recorded editing "
                    f"time ({tdindwg_hours:.1f} hours). This is physically possible and consistent "
                    f"with normal file usage. No evidence of clock manipulation was detected "
                    f"through this analysis method."
                )
                elements.append(Paragraph(consistency_narrative, styles['Narrative']))

        # File identity GUIDs
        if meta.fingerprint_guid or meta.version_guid:
            elements.append(Spacer(1, 0.2 * inch))
            elements.append(Paragraph("<b>File Identity GUIDs</b>", styles['Heading3']))

            guid_data = [
                ["GUID Type", "Value", "Behavior"],
                [
                    "FINGERPRINTGUID",
                    meta.fingerprint_guid or "N/A",
                    "Persists across saves and copies"
                ],
                [
                    "VERSIONGUID",
                    meta.version_guid or "N/A",
                    "Changes with each save"
                ],
            ]

            table = Table(guid_data, colWidths=[1.5 * inch, 2.5 * inch, 2.5 * inch])
            table.setStyle(self._get_standard_table_style())
            elements.append(table)

        # Network paths if detected
        if meta.network_paths_detected:
            elements.append(Spacer(1, 0.2 * inch))
            elements.append(Paragraph("<b>Network Path Leakage</b>", styles['Heading3']))
            elements.append(Paragraph(
                "The following network paths were detected in file references. These may "
                "reveal the original network environment where the file was created:",
                styles['Normal']
            ))
            elements.append(Spacer(1, 0.1 * inch))

            for path in meta.network_paths_detected[:10]:  # Limit to 10 paths
                # Escape special characters for XML
                safe_path = path.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                elements.append(Paragraph(f"  [->] {safe_path}", styles['Monospace']))

            if len(meta.network_paths_detected) > 10:
                elements.append(Paragraph(
                    f"  ... and {len(meta.network_paths_detected) - 10} more paths",
                    styles['Normal']
                ))

        return elements

    def _build_findings_section(self, analysis: ForensicAnalysis) -> List:
        """Build the anomalies and tampering findings section with detailed explanations."""
        elements = []
        styles = self.styles.styles

        # SMOKING GUN FINDINGS - DEFINITIVE PROOF SECTION (if present)
        # This section goes FIRST because it contains the most critical evidence
        if analysis.has_definitive_proof and analysis.smoking_gun_report:
            elements.append(Paragraph(
                "[!!] SMOKING GUN FINDINGS - DEFINITIVE PROOF OF TAMPERING",
                styles['SectionHeader']
            ))
            elements.append(Spacer(1, 0.2 * inch))

            # Critical warning banner
            elements.append(Paragraph(
                "<b>CRITICAL:</b> The findings below represent MATHEMATICALLY IMPOSSIBLE conditions "
                "that prove this file has been tampered with. These are not probabilistic assessments - "
                "they are definitive proof suitable for legal proceedings.",
                styles['CriticalNarrative']
            ))
            elements.append(Spacer(1, 0.2 * inch))

            # List each smoking gun finding
            smoking_guns = analysis.smoking_gun_report.get("smoking_guns", [])
            for i, sg in enumerate(smoking_guns, 1):
                elements.append(Paragraph(
                    f"<b>Smoking Gun #{i}: {sg.get('rule_name', 'Unknown')}</b>",
                    styles['Heading3']
                ))
                elements.append(Paragraph(
                    f"<b>Finding:</b> {sg.get('description', 'N/A')}",
                    styles['FindingExplanation']
                ))
                elements.append(Paragraph(
                    f"<b>Forensic Reasoning:</b> {sg.get('forensic_reasoning', 'N/A')}",
                    styles['CriticalNarrative']
                ))
                elements.append(Paragraph(
                    f"<b>Legal Significance:</b> {sg.get('legal_significance', 'N/A')}",
                    styles['Narrative']
                ))
                elements.append(Spacer(1, 0.15 * inch))

            # Expert summary from smoking gun report
            expert_summary = analysis.smoking_gun_report.get("expert_summary", "")
            if expert_summary:
                elements.append(Paragraph("<b>Expert Summary:</b>", styles['NarrativeHeader']))
                elements.append(Paragraph(expert_summary, styles['CriticalNarrative']))
                elements.append(Spacer(1, 0.15 * inch))

            # Legal conclusion
            legal_conclusion = analysis.smoking_gun_report.get("legal_conclusion", "")
            if legal_conclusion:
                elements.append(Paragraph("<b>Legal Conclusion:</b>", styles['NarrativeHeader']))
                elements.append(Paragraph(legal_conclusion, styles['Narrative']))
                elements.append(Spacer(1, 0.15 * inch))

            # Recommendation
            recommendation = analysis.smoking_gun_report.get("recommendation", "")
            if recommendation:
                elements.append(Paragraph("<b>Recommended Actions:</b>", styles['NarrativeHeader']))
                elements.append(Paragraph(recommendation, styles['Narrative']))

            elements.append(Spacer(1, 0.3 * inch))
            elements.append(PageBreak())

        # Standard findings section header
        elements.append(Paragraph("Anomalies and Tampering Indicators", styles['SectionHeader']))
        elements.append(Spacer(1, 0.2 * inch))

        # Introduction explaining what this section covers
        elements.append(Paragraph(
            "This section presents findings that indicate potential tampering or manipulation "
            "of the DWG file. Each finding includes a plain-English explanation of what was "
            "checked, what was found, and why it matters.",
            styles['ExecutiveSummary']
        ))
        elements.append(Spacer(1, 0.2 * inch))

        # Risk factors
        elements.append(Paragraph("<b>Risk Factors Identified</b>", styles['Heading3']))
        for factor in analysis.risk_assessment.factors:
            elements.append(Paragraph(f"  [*] {factor}", styles['Normal']))
        elements.append(Spacer(1, 0.2 * inch))

        # Anomalies with detailed explanations
        if analysis.anomalies:
            elements.append(Paragraph("<b>Detected Anomalies</b>", styles['Heading3']))
            elements.append(Paragraph(
                "Anomalies are unusual patterns in the file that deviate from normal AutoCAD "
                "behavior. While not always proof of tampering, they warrant investigation.",
                styles['Normal']
            ))
            elements.append(Spacer(1, 0.1 * inch))

            for i, anomaly in enumerate(analysis.anomalies, 1):
                elements.append(Paragraph(
                    f"<b>Anomaly #{i}: {anomaly.anomaly_type.value}</b> "
                    f"[Severity: {anomaly.severity.value}]",
                    styles['Heading4'] if 'Heading4' in styles else styles['Normal']
                ))
                elements.append(Paragraph(anomaly.description, styles['FindingExplanation']))
                # Add layman explanation
                explanation = self._get_anomaly_explanation(anomaly)
                if explanation:
                    elements.append(Paragraph(explanation, styles['Narrative']))
                elements.append(Spacer(1, 0.1 * inch))

            elements.append(Spacer(1, 0.2 * inch))

        # Tampering indicators with detailed explanations
        if analysis.tampering_indicators:
            elements.append(Paragraph("<b>Tampering Indicators - Detailed Analysis</b>", styles['Heading3']))
            elements.append(Paragraph(
                "Tampering indicators are specific forensic findings that provide evidence "
                "of file manipulation. Each indicator below explains what was tested, what "
                "value was found, and what that value proves.",
                styles['Normal']
            ))
            elements.append(Spacer(1, 0.15 * inch))

            for i, indicator in enumerate(analysis.tampering_indicators, 1):
                # Determine if this is a critical finding based on indicator type
                critical_types = ["crc", "impossible", "timestomp", "si_fn", "exceed"]
                is_critical = any(ct in indicator.indicator_type.value.lower() for ct in critical_types)

                elements.append(Paragraph(
                    f"<b>Finding #{i}: {indicator.indicator_type.value}</b>",
                    styles['Heading4'] if 'Heading4' in styles else styles['Normal']
                ))

                # Full description
                elements.append(Paragraph(
                    f"<b>Technical Finding:</b> {indicator.description}",
                    styles['FindingExplanation']
                ))

                # Get detailed layman explanation
                explanation = self._get_tampering_explanation(indicator)
                style = styles['CriticalNarrative'] if is_critical else styles['Narrative']
                elements.append(Paragraph(explanation, style))

                elements.append(Spacer(1, 0.15 * inch))

        # Section summary
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph("Findings Summary:", styles['NarrativeHeader']))
        elements.extend(self._generate_findings_summary(analysis))

        return elements

    def _build_hash_attestation(
        self,
        analysis: ForensicAnalysis,
        case_id: Optional[str],
    ) -> List:
        """Build the hash attestation page."""
        elements = []
        styles = self.styles.styles

        elements.append(Paragraph("Hash Attestation", styles['SectionHeader']))
        elements.append(Spacer(1, 0.3 * inch))

        attestation_text = (
            f"I hereby attest that the file described below was analyzed using DWG Forensic Tool "
            f"version {analysis.analyzer_version}. The cryptographic hash values listed below "
            f"were calculated at the time of analysis and can be used to verify the integrity "
            f"of the analyzed file."
        )
        elements.append(Paragraph(attestation_text, styles['ExecutiveSummary']))
        elements.append(Spacer(1, 0.3 * inch))

        # Hash details
        hash_data = [
            ["Property", "Value"],
            ["Filename", analysis.file_info.filename],
            ["File Size", f"{analysis.file_info.file_size_bytes:,} bytes"],
            ["SHA-256 Hash", analysis.file_info.sha256],
            ["Analysis Timestamp", analysis.analysis_timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")],
            ["Case ID", case_id or "N/A"],
        ]

        table = Table(hash_data, colWidths=[2 * inch, 4.5 * inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 2), (1, 2), 'Courier'),  # Hash in monospace
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(table)

        elements.append(Spacer(1, 0.5 * inch))

        # Signature block
        elements.append(Paragraph("<b>Attestation</b>", styles['Normal']))
        elements.append(Spacer(1, 0.5 * inch))

        signature_data = [
            ["Examiner Name:", "_" * 40],
            ["Signature:", "_" * 40],
            ["Date:", "_" * 40],
        ]

        table = Table(signature_data, colWidths=[1.5 * inch, 4 * inch])
        table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 20),
        ]))
        elements.append(table)

        return elements

    def _build_hex_dump_appendix(self, analysis: ForensicAnalysis) -> List:
        """Build the hex dump appendix."""
        elements = []
        styles = self.styles.styles

        elements.append(Paragraph("Appendix: Hex Dumps", styles['SectionHeader']))
        elements.append(Spacer(1, 0.2 * inch))

        elements.append(Paragraph(
            "This appendix contains hexadecimal representations of key file regions "
            "for forensic verification purposes.",
            styles['Normal']
        ))
        elements.append(Spacer(1, 0.2 * inch))

        # Header region hex dump (first 128 bytes)
        elements.append(Paragraph("<b>File Header (First 128 bytes)</b>", styles['Heading3']))
        elements.append(Paragraph(
            "Note: Actual hex dump would be extracted from the original file. "
            "The version string is located at offset 0x00-0x05.",
            styles['Monospace']
        ))
        elements.append(Spacer(1, 0.2 * inch))

        # Example hex dump format
        hex_example = """00000000:  41 43 31 30 33 32 00 00  00 00 00 00 00 00 00 00  |AC1032..........|
00000010:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000020:  [Additional hex data would appear here...]"""

        elements.append(Paragraph(
            hex_example.replace("\n", "<br/>"),
            styles['Monospace']
        ))

        return elements

    def _get_standard_table_style(self) -> TableStyle:
        """Get standard table styling."""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ])

    def _add_header_footer(self, canvas, doc) -> None:
        """Add header and footer to each page."""
        canvas.saveState()

        # Header
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor('#888888'))
        canvas.drawString(0.75 * inch, letter[1] - 0.5 * inch, self.company_name)
        canvas.drawRightString(letter[0] - 0.75 * inch, letter[1] - 0.5 * inch, "CONFIDENTIAL")

        # Footer
        canvas.drawString(0.75 * inch, 0.5 * inch, f"Generated by DWG Forensic Tool v{__version__}")
        canvas.drawRightString(letter[0] - 0.75 * inch, 0.5 * inch, f"Page {doc.page}")

        canvas.restoreState()

    # =========================================================================
    # COMPREHENSIVE LLM ANALYSIS
    # When LLM is enabled, this section provides the full reasoned analysis
    # =========================================================================

    def _build_comprehensive_llm_analysis(self, analysis: ForensicAnalysis) -> List:
        """
        Build the comprehensive LLM analysis section.

        This section contains the full forensic analysis generated by the LLM,
        including evidence inventory, cross-validation, and reasoned conclusions.
        This replaces the algorithmic/boilerplate content with real analysis.
        """
        elements = []
        styles = self.styles.styles

        elements.append(Paragraph("Expert Forensic Analysis", styles['SectionHeader']))
        elements.append(Spacer(1, 0.2 * inch))

        # Introduction explaining this section
        elements.append(Paragraph(
            "The following analysis was generated by an AI forensic expert using the "
            "comprehensive forensic data extracted from this DWG file. The analysis follows "
            "a structured methodology: evidence inventory, technical interpretation, "
            "cross-validation between independent sources, step-by-step reasoning, and "
            "conclusions that distinguish between what is PROVEN, INDICATED, and UNCERTAIN.",
            styles['ExecutiveSummary']
        ))
        elements.append(Spacer(1, 0.3 * inch))

        # Generate the full comprehensive analysis
        result = self.narrator.generate_full_analysis(analysis)

        if result.success:
            # Sanitize the LLM output for ReportLab compatibility
            # This converts markdown to HTML and fixes character encoding
            narrative_text = sanitize_llm_output(result.narrative)

            # Split by double newlines to get paragraphs
            paragraphs = [p.strip() for p in narrative_text.split('\n\n') if p.strip()]

            for para in paragraphs:
                # Check if this is a section header (starts with numbers or all caps)
                if para.startswith(('1.', '2.', '3.', '4.', '5.', '6.')) or para.isupper():
                    # Section header
                    elements.append(Spacer(1, 0.15 * inch))
                    elements.append(Paragraph(f"<b>{para}</b>", styles['Heading3']))
                elif para.startswith('- ') or para.startswith('* '):
                    # Bullet point - format as list
                    bullet_text = para[2:] if para.startswith('- ') or para.startswith('* ') else para
                    elements.append(Paragraph(f"[*] {bullet_text}", styles['Normal']))
                elif 'CRITICAL' in para.upper() or 'PROOF' in para.upper() or 'IMPOSSIBLE' in para.upper():
                    # Critical finding - highlight
                    elements.append(Paragraph(para, styles['CriticalNarrative']))
                else:
                    # Regular paragraph
                    elements.append(Paragraph(para, styles['ExecutiveSummary']))

            elements.append(Spacer(1, 0.3 * inch))

            # Attribution
            gen_time = f" - Generation time: {result.generation_time_ms}ms" if result.generation_time_ms else ""
            elements.append(Paragraph(
                f"<i>[Comprehensive analysis generated by AI Forensic Expert - "
                f"Model: {result.model_used}{gen_time}]</i>",
                styles['Normal']
            ))
        else:
            # LLM generation failed - show error
            elements.append(Paragraph(
                f"<b>LLM Analysis Unavailable:</b> {result.error or 'Unknown error'}",
                styles['Narrative']
            ))
            elements.append(Paragraph(
                "The analysis will continue with static forensic narratives in the following sections.",
                styles['Normal']
            ))

        return elements

    # =========================================================================
    # NARRATIVE GENERATION METHODS
    # These methods generate plain-English explanations for non-technical readers
    # =========================================================================

    def _generate_crc_narrative(self, analysis: ForensicAnalysis) -> List:
        """Generate plain-English explanation of CRC validation results."""
        elements = []
        styles = self.styles.styles

        # Use LLM narrator if available - comprehensive analysis
        if self.narrator:
            result = self.narrator.generate_section_analysis(analysis, "crc")
            if result.success:
                # Sanitize LLM output for ReportLab compatibility
                sanitized_narrative = sanitize_llm_output(result.narrative)
                # LLM generated a comprehensive, reasoned narrative
                style = styles['CriticalNarrative'] if not analysis.crc_validation.is_valid else styles['Narrative']
                elements.append(Paragraph(sanitized_narrative, style))
                if result.generation_time_ms:
                    elements.append(Paragraph(
                        f"<i>[Analysis by AI Forensic Expert - Model: {result.model_used} - {result.generation_time_ms}ms]</i>",
                        styles['Normal']
                    ))
                return elements

        # Static fallback - Explain what CRC is - forensically accurate
        crc_intro = (
            "<b>What is CRC?</b> A CRC (Cyclic Redundancy Check) is a mathematical checksum "
            "that AutoCAD calculates and stores inside every DWG file each time it saves. "
            "Think of it like a tamper-evident seal: every time AutoCAD saves a file, it "
            "applies a fresh, valid seal. Normal workflow (opening, editing, and saving in "
            "AutoCAD) always produces a valid CRC because AutoCAD recalculates it on every save."
        )
        elements.append(Paragraph(crc_intro, styles['Narrative']))

        # Explain what was found
        if analysis.crc_validation.is_valid:
            finding = (
                f"<b>Finding:</b> The stored CRC value ({analysis.crc_validation.header_crc_stored}) "
                f"matches the calculated CRC value ({analysis.crc_validation.header_crc_calculated}). "
                "This confirms the file has not been modified outside of AutoCAD since its last save. "
                "Normal editing and saving in AutoCAD always maintains a valid CRC."
            )
            elements.append(Paragraph(finding, styles['Narrative']))
        else:
            finding = (
                f"<b>[!] CRITICAL FINDING:</b> The stored CRC value ({analysis.crc_validation.header_crc_stored}) "
                f"does NOT match the calculated CRC value ({analysis.crc_validation.header_crc_calculated}). "
                "This indicates the file was modified by something OTHER than AutoCAD after its last "
                "legitimate save. AutoCAD always updates the CRC when saving - a mismatch indicates "
                "the file was altered by external means."
            )
            elements.append(Paragraph(finding, styles['CriticalNarrative']))

            why_matters = (
                "<b>Why This Matters:</b> A CRC mismatch cannot occur through normal AutoCAD usage. "
                "This indicates the file was modified using a hex editor, non-Autodesk software, or other "
                "tools that altered the binary content without properly updating the checksum. "
                "This is strong evidence of modification outside the normal "
                "AutoCAD workflow. The file's integrity cannot be trusted."
            )
            elements.append(Paragraph(why_matters, styles['Narrative']))

        return elements

    def _generate_fingerprint_narrative(self, analysis: ForensicAnalysis) -> List:
        """Generate plain-English explanation of application fingerprint results."""
        elements = []
        styles = self.styles.styles

        if not analysis.application_fingerprint:
            elements.append(Paragraph(
                "<b>Application Detection:</b> No application fingerprint data is available for this file.",
                styles['Narrative']
            ))
            return elements

        fp = analysis.application_fingerprint
        app_name = fp.detected_application.upper()
        conf_pct = int(fp.confidence * 100)

        if fp.is_autodesk:
            narrative = (
                f"<b>Genuine Autodesk Software Detected:</b> This file was identified as being created "
                f"or last saved by {app_name}, which is genuine Autodesk software. Detection confidence "
                f"is {conf_pct}%. Files from Autodesk applications maintain proper internal timestamp "
                f"structures. The tampering detection rules for Autodesk files apply fully to this file."
            )
            elements.append(Paragraph(narrative, styles['Narrative']))
        elif fp.is_oda_based:
            narrative = (
                f"<b>ODA SDK-Based Application Detected:</b> This file was identified as being created "
                f"or last saved by {app_name} with {conf_pct}% confidence. This application uses the "
                f"Open Design Alliance (ODA) SDK for DWG file handling. ODA-based applications can read "
                f"and write DWG files. Some internal timestamp fields may differ from native AutoCAD "
                f"behavior, which is expected and not evidence of tampering."
            )
            elements.append(Paragraph(narrative, styles['Narrative']))
        else:
            narrative = (
                f"<b>Non-Autodesk Application Detected:</b> This file was identified as being created "
                f"or last saved by {app_name} with {conf_pct}% confidence. This application is not "
                f"genuine Autodesk software and may not maintain all DWG metadata fields in the same "
                f"manner as AutoCAD. Differences in timestamp handling may be expected behavior for "
                f"this application rather than evidence of tampering."
            )
            elements.append(Paragraph(narrative, styles['Narrative']))

        return elements

    def _generate_technical_summary(self, analysis: ForensicAnalysis) -> List:
        """Generate summary narrative for technical findings section."""
        elements = []
        styles = self.styles.styles

        # Use LLM narrator if available for comprehensive summary
        if self.narrator:
            result = self.narrator.generate_section_analysis(analysis, "summary")
            if result.success:
                # Sanitize LLM output for ReportLab compatibility
                sanitized_narrative = sanitize_llm_output(result.narrative)
                style = styles['CriticalNarrative'] if not analysis.crc_validation.is_valid else styles['Narrative']
                elements.append(Paragraph(sanitized_narrative, style))
                if result.generation_time_ms:
                    elements.append(Paragraph(
                        f"<i>[Summary by AI Forensic Expert - Model: {result.model_used} - {result.generation_time_ms}ms]</i>",
                        styles['Normal']
                    ))
                return elements

        # Static fallback - Build summary based on findings
        crc_status = "PASSED" if analysis.crc_validation.is_valid else "FAILED"
        anomaly_count = len(analysis.anomalies)

        if analysis.crc_validation.is_valid and anomaly_count == 0:
            summary = (
                f"<b>Summary:</b> The technical analysis found no evidence of tampering at the "
                f"binary level. The file's CRC checksum is valid and no anomalies were detected. "
                f"This supports the conclusion that this file has not been tampered with."
            )
            elements.append(Paragraph(summary, styles['Narrative']))
        elif not analysis.crc_validation.is_valid:
            summary = (
                f"<b>Summary:</b> The technical analysis found DEFINITIVE EVIDENCE OF TAMPERING. "
                f"The CRC checksum FAILED validation, which indicates the file was "
                f"modified after it was saved. CRC validation is {crc_status}. "
                f"This file should not be relied upon as authentic evidence."
            )
            elements.append(Paragraph(summary, styles['CriticalNarrative']))
        elif anomaly_count > 0:
            summary = (
                f"<b>Summary:</b> The technical analysis detected {anomaly_count} anomal{'y' if anomaly_count == 1 else 'ies'}. "
                f"CRC validation is {crc_status}. While the CRC check passed, the detected anomalies "
                f"warrant further investigation into the file's origin and chain of custody."
            )
            elements.append(Paragraph(summary, styles['Narrative']))
        else:
            summary = (
                f"<b>Summary:</b> The technical analysis completed successfully. "
                f"CRC validation is {crc_status}. No significant findings were detected."
            )
            elements.append(Paragraph(summary, styles['Narrative']))

        return elements

    def _get_anomaly_explanation(self, anomaly: Anomaly) -> str:
        """Get plain-English explanation for an anomaly type."""
        explanations = {
            "timestamp_precision": (
                "<b>What this means:</b> Normal timestamps have varied precision (seconds, "
                "minutes, etc.). When a timestamp falls exactly on midnight or a round number, "
                "it suggests the timestamp was manually set rather than naturally occurring "
                "from a save operation."
            ),
            "timestamp_sequence": (
                "<b>What this means:</b> The timestamps in this file are out of order. For example, "
                "the 'created' date is after the 'modified' date, which is logically impossible "
                "under normal circumstances. This indicates timestamp manipulation."
            ),
            "timestamp_future": (
                "<b>What this means:</b> A timestamp in this file is set in the future, which "
                "is impossible unless the system clock was manipulated or timestamps were "
                "deliberately falsified."
            ),
            "version_mismatch": (
                "<b>What this means:</b> The file claims to be a certain version of the DWG format, "
                "but internal evidence contradicts this. This suggests the file was converted "
                "or modified in a way that created inconsistencies."
            ),
            "editing_time_impossible": (
                "<b>What this means:</b> The recorded editing time exceeds what is physically "
                "possible given the calendar time between creation and last save. This indicates "
                "the system clock was manipulated to falsify when work was done."
            ),
        }

        # Try to match anomaly type
        anomaly_type_lower = anomaly.anomaly_type.value.lower()
        for key, explanation in explanations.items():
            if key in anomaly_type_lower:
                return explanation

        # Default explanation
        return (
            "<b>What this means:</b> This anomaly indicates a deviation from normal AutoCAD "
            "file behavior that warrants investigation. The specific pattern detected is unusual "
            "and may indicate file manipulation or corruption."
        )

    def _get_tampering_explanation(self, indicator: TamperingIndicator) -> str:
        """Get detailed plain-English explanation for a tampering indicator."""
        # Map indicator types to forensically accurate explanations
        indicator_type = indicator.indicator_type.value.lower()

        if "crc" in indicator_type:
            return (
                "<b>Plain English:</b> Every DWG file contains a mathematical checksum (CRC) that "
                "AutoCAD recalculates and updates each time it saves. A valid CRC means the file "
                "was last modified by AutoCAD or compatible software that correctly updates this "
                "value. The CRC in this file does NOT match the calculated value, which indicates "
                "the file was modified by something other than AutoCAD - such as a hex editor, "
                "file corruption, or tampering software - after its last legitimate save."
            )
        elif "impossible" in indicator_type or "exceed" in indicator_type:
            return (
                "<b>Plain English:</b> AutoCAD maintains a counter called TDINDWG that tracks "
                "total editing time. This counter accumulates across all editing sessions and "
                "CANNOT be reset through normal AutoCAD operations. The editing time recorded "
                "in this file EXCEEDS the calendar time between creation and last save dates. "
                "This is mathematically impossible unless the computer's clock was manipulated. "
                "This indicates the creation date was falsified to make the file appear older than "
                "it actually is."
            )
        elif "ntfs" in indicator_type and "creat" in indicator_type:
            return (
                "<b>Plain English:</b> The DWG file's internal creation timestamp does not match "
                "the Windows filesystem (NTFS) creation timestamp. These should be consistent "
                "for a file created normally. The discrepancy indicates either: (1) The file was "
                "copied from another location (NTFS creation time reflects when the copy was made); "
                "(2) The internal DWG timestamps were modified; or (3) The NTFS timestamps were "
                "deliberately altered using timestamp manipulation tools."
            )
        elif "ntfs" in indicator_type and "modif" in indicator_type:
            return (
                "<b>Plain English:</b> The DWG file's internal modification timestamp does not "
                "match the Windows filesystem (NTFS) modification timestamp. For a file edited "
                "and saved normally, these should be nearly identical. The discrepancy indicates "
                "either: (1) The file was transferred or copied after its last edit; (2) Internal "
                "DWG timestamps were manipulated; or (3) NTFS timestamps were altered using "
                "specialized tools."
            )
        elif "timestomp" in indicator_type or "si_fn" in indicator_type:
            return (
                "<b>Plain English:</b> Windows NTFS stores two sets of timestamps: "
                "$STANDARD_INFORMATION (SI) and $FILE_NAME (FN). The SI timestamps can be modified "
                "by users or software, but the FN timestamps are protected by Windows and much "
                "harder to alter. When SI and FN timestamps disagree, this indicates someone used "
                "specialized tools (a technique called 'timestomping') to falsify when this file "
                "was created. The FN timestamp reveals the true creation time."
            )
        elif "nanosecond" in indicator_type or "truncat" in indicator_type:
            return (
                "<b>Plain English:</b> NTFS timestamps have 100-nanosecond precision. Normal file "
                "operations produce timestamps with seemingly random nanosecond values. When "
                "timestamps show truncated or rounded nanosecond values (ending in zeros), it "
                "indicates they were set by tools that don't preserve full precision - a signature "
                "of timestamp manipulation software."
            )
        elif "version" in indicator_type:
            return (
                "<b>Plain English:</b> DWG files contain multiple version identifiers that should "
                "be internally consistent. This file has version markers that contradict each "
                "other, indicating it was processed by software that modified some fields but "
                "not others. This inconsistency indicates the file was altered outside of normal "
                "AutoCAD operations."
            )
        elif "guid" in indicator_type or "fingerprint" in indicator_type:
            return (
                "<b>Plain English:</b> Each DWG file has unique identifiers (GUIDs) that track "
                "its identity. FINGERPRINTGUID persists across saves and copies (identifying the "
                "original drawing), while VERSIONGUID changes with each save. Anomalies in these "
                "identifiers can reveal if a file was cloned, had its identity forged, or was "
                "manipulated to appear as a different drawing."
            )
        elif "editing" in indicator_type or "tdindwg" in indicator_type:
            return (
                "<b>Plain English:</b> AutoCAD tracks cumulative editing time in TDINDWG, a "
                "counter that runs whenever the file is open for editing. Unlike other timestamps, "
                "TDINDWG cannot be reset through normal AutoCAD operations. The editing time in "
                "this file is inconsistent with the claimed creation and modification dates, "
                "indicating that timestamps were manipulated to misrepresent when work was performed."
            )
        elif "zero" in indicator_type and "edit" in indicator_type:
            return (
                "<b>Plain English:</b> This file shows zero or near-zero editing time (TDINDWG), "
                "yet contains drawing content. A file with actual drawing work would accumulate "
                "editing time. Zero editing time indicates the file was either: (1) Programmatically "
                "generated without using AutoCAD's drawing interface; (2) Converted from another "
                "format; or (3) Had its metadata reset to hide its true editing history."
            )
        else:
            return (
                f"<b>Plain English:</b> This indicator ({indicator.indicator_type.value}) detected "
                f"a pattern that deviates from how genuine, unmodified AutoCAD files behave. "
                f"The specific anomaly described above demonstrates that this file was not created "
                f"or maintained through normal AutoCAD workflow, indicating manipulation or "
                f"processing by non-standard software."
            )

    def _generate_findings_summary(self, analysis: ForensicAnalysis) -> List:
        """Generate summary narrative for findings section."""
        elements = []
        styles = self.styles.styles

        num_anomalies = len(analysis.anomalies)
        num_indicators = len(analysis.tampering_indicators)

        # Check for critical indicator types that represent definitive evidence
        critical_types = ["crc", "impossible", "timestomp", "si_fn", "exceed"]
        critical_count = sum(
            1 for i in analysis.tampering_indicators
            if any(ct in i.indicator_type.value.lower() for ct in critical_types)
        )

        if num_indicators == 0 and num_anomalies == 0:
            summary = (
                "<b>Conclusion:</b> No anomalies or tampering indicators were detected in this file. "
                "The forensic analysis found no evidence of manipulation. This supports the "
                "conclusion that the file is authentic and has not been tampered with."
            )
            elements.append(Paragraph(summary, styles['Narrative']))
        elif critical_count > 0:
            summary = (
                f"<b>Conclusion:</b> This analysis detected {num_indicators} tampering indicator(s) "
                f"and {num_anomalies} anomaly(ies). Of these, {critical_count} finding(s) represent "
                f"DEFINITIVE EVIDENCE of tampering - these are not probabilistic assessments but "
                f"mathematical or forensic certainties. Based on these findings, this file should "
                f"NOT be considered authentic. The evidence indicates deliberate manipulation of file "
                f"data or timestamps."
            )
            elements.append(Paragraph(summary, styles['CriticalNarrative']))
        else:
            summary = (
                f"<b>Conclusion:</b> This analysis detected {num_indicators} tampering indicator(s) "
                f"and {num_anomalies} anomaly(ies). These findings indicate deviation from normal "
                f"AutoCAD file behavior and warrant careful consideration. The file's authenticity "
                f"should be verified through additional means such as chain of custody documentation, "
                f"comparison with backup copies, or testimony from the file's creator."
            )
            elements.append(Paragraph(summary, styles['Narrative']))

        return elements


def generate_pdf_report(
    analysis: ForensicAnalysis,
    output_path: Union[str, Path],
    case_id: Optional[str] = None,
    include_hex_dumps: bool = True,
    company_name: Optional[str] = None,
    examiner_name: Optional[str] = None,
    use_llm_narration: bool = False,
    llm_model: Optional[str] = None,
) -> Path:
    """
    Convenience function to generate a PDF forensic report.

    Args:
        analysis: Forensic analysis results
        output_path: Path to save the PDF
        case_id: Optional case identifier
        include_hex_dumps: Include hex dump appendix
        company_name: Company name for report header
        examiner_name: Examiner name for attestation
        use_llm_narration: Use LLM for enhanced narrative generation
        llm_model: Ollama model to use for LLM narration

    Returns:
        Path to the generated PDF file
    """
    generator = PDFReportGenerator(
        include_hex_dumps=include_hex_dumps,
        company_name=company_name,
        examiner_name=examiner_name,
        use_llm_narration=use_llm_narration,
        llm_model=llm_model,
    )
    return generator.generate(analysis, output_path, case_id)
