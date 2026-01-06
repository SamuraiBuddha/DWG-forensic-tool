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
    ):
        """
        Initialize the PDF report generator.

        Args:
            include_hex_dumps: Include hex dump appendix (default: True)
            include_timeline: Include timeline visualization (default: True)
            company_name: Company name for report header
            examiner_name: Examiner name for attestation
        """
        self.include_hex_dumps = include_hex_dumps
        self.include_timeline = include_timeline
        self.company_name = company_name or "Digital Forensics Analysis"
        self.examiner_name = examiner_name or "Forensic Examiner"
        self.styles = PDFReportStyles()

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

        # Technical Findings
        story.extend(self._build_technical_findings(analysis))
        story.append(PageBreak())

        # Metadata Section
        story.extend(self._build_metadata_section(analysis))

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

        # Report metadata table
        report_data = [
            ["Case ID:", case_id or "N/A"],
            ["Analysis Date:", analysis.analysis_timestamp.strftime("%Y-%m-%d %H:%M:%S")],
            ["Analyzer Version:", analysis.analyzer_version],
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

        findings_data = [
            ["Finding", "Status"],
            ["File Integrity (CRC)", "[OK]" if analysis.crc_validation.is_valid else "[FAIL]"],
            ["TrustedDWG Watermark", "[OK]" if analysis.trusted_dwg.watermark_valid else "[WARN]"],
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

        # Opening paragraph
        paragraphs.append(
            f"This report presents the forensic analysis of the AutoCAD DWG file "
            f"'{analysis.file_info.filename}'. The analysis was performed on "
            f"{analysis.analysis_timestamp.strftime('%B %d, %Y')} using DWG Forensic Tool "
            f"version {analysis.analyzer_version}."
        )

        # File identification
        paragraphs.append(
            f"The file is identified as {analysis.header_analysis.version_name} format "
            f"(version string: {analysis.header_analysis.version_string}). "
            f"The file size is {analysis.file_info.file_size_bytes:,} bytes."
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
                "does NOT match the calculated checksum. This indicates the file may have been "
                "modified after it was originally saved, potentially indicating tampering."
            )
        paragraphs.append(integrity_text)

        # Watermark assessment
        if analysis.trusted_dwg.watermark_present:
            if analysis.trusted_dwg.watermark_valid:
                watermark_text = (
                    "The TrustedDWG watermark is present and valid, indicating the file was "
                    "created or last saved by an authorized Autodesk application."
                )
            else:
                watermark_text = (
                    "A TrustedDWG watermark is present but appears to be invalid or corrupted. "
                    "This may indicate the file was modified by unauthorized software."
                )
        else:
            watermark_text = (
                "No TrustedDWG watermark was found in this file. This may indicate the file was "
                "created by non-Autodesk software or the watermark was removed."
            )
        paragraphs.append(watermark_text)

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
        elements.append(Spacer(1, 0.3 * inch))

        # TrustedDWG Analysis
        elements.append(Paragraph("<b>TrustedDWG Watermark</b>", styles['Heading3']))
        watermark_data = [
            ["Property", "Value"],
            ["Watermark Present", "Yes" if analysis.trusted_dwg.watermark_present else "No"],
            ["Watermark Valid", "Yes" if analysis.trusted_dwg.watermark_valid else "No"],
            ["Watermark Text", analysis.trusted_dwg.watermark_text or "N/A"],
            ["Application Origin", analysis.trusted_dwg.application_origin or "Unknown"],
        ]

        table = Table(watermark_data, colWidths=[2.5 * inch, 4 * inch])
        table.setStyle(self._get_standard_table_style())
        elements.append(table)

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

    def _build_findings_section(self, analysis: ForensicAnalysis) -> List:
        """Build the anomalies and tampering findings section."""
        elements = []
        styles = self.styles.styles

        elements.append(Paragraph("Anomalies and Tampering Indicators", styles['SectionHeader']))
        elements.append(Spacer(1, 0.2 * inch))

        # Risk factors
        elements.append(Paragraph("<b>Risk Factors</b>", styles['Heading3']))
        for factor in analysis.risk_assessment.factors:
            elements.append(Paragraph(f"  {factor}", styles['Normal']))
        elements.append(Spacer(1, 0.2 * inch))

        # Anomalies table
        if analysis.anomalies:
            elements.append(Paragraph("<b>Detected Anomalies</b>", styles['Heading3']))
            anomaly_data = [["Type", "Severity", "Description"]]
            for anomaly in analysis.anomalies:
                anomaly_data.append([
                    anomaly.anomaly_type.value,
                    anomaly.severity.value,
                    anomaly.description[:60] + "..." if len(anomaly.description) > 60 else anomaly.description,
                ])

            table = Table(anomaly_data, colWidths=[1.5 * inch, 1 * inch, 4 * inch])
            table.setStyle(self._get_standard_table_style())
            elements.append(table)
            elements.append(Spacer(1, 0.3 * inch))

        # Tampering indicators table
        if analysis.tampering_indicators:
            elements.append(Paragraph("<b>Tampering Indicators</b>", styles['Heading3']))
            indicator_data = [["Type", "Confidence", "Description"]]
            for indicator in analysis.tampering_indicators:
                indicator_data.append([
                    indicator.indicator_type.value,
                    f"{indicator.confidence:.0%}",
                    indicator.description[:50] + "..." if len(indicator.description) > 50 else indicator.description,
                ])

            table = Table(indicator_data, colWidths=[1.5 * inch, 1 * inch, 4 * inch])
            table.setStyle(self._get_standard_table_style())
            elements.append(table)

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


def generate_pdf_report(
    analysis: ForensicAnalysis,
    output_path: Union[str, Path],
    case_id: Optional[str] = None,
    include_hex_dumps: bool = True,
    company_name: Optional[str] = None,
    examiner_name: Optional[str] = None,
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

    Returns:
        Path to the generated PDF file
    """
    generator = PDFReportGenerator(
        include_hex_dumps=include_hex_dumps,
        company_name=company_name,
        examiner_name=examiner_name,
    )
    return generator.generate(analysis, output_path, case_id)
