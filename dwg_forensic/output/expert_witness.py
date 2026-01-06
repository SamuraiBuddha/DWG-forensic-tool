"""
DWG Forensic Tool - Expert Witness Documentation

Generates expert witness documentation for litigation support.
Implements FR-REPORT-003 from the PRD.

Includes:
- Methodology description
- Tool version and dependencies
- Reproducibility instructions
- Limitations statement
- Opinion support framework
"""

from datetime import datetime
from pathlib import Path
from typing import Optional, Union

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from dwg_forensic import __version__
from dwg_forensic.models import ForensicAnalysis, RiskLevel


class ExpertWitnessGenerator:
    """
    Generates expert witness documentation for forensic analysis.

    Creates professional documentation suitable for:
    - Court submission
    - Deposition support
    - Expert testimony preparation
    - Methodology documentation
    """

    def __init__(
        self,
        expert_name: str = "Digital Forensics Expert",
        expert_credentials: Optional[str] = None,
        company_name: Optional[str] = None,
    ):
        """
        Initialize the expert witness generator.

        Args:
            expert_name: Name of the expert witness
            expert_credentials: Expert's credentials/certifications
            company_name: Company or organization name
        """
        self.expert_name = expert_name
        self.expert_credentials = expert_credentials or "Certified Digital Forensics Examiner"
        self.company_name = company_name or "Digital Forensics Laboratory"
        self.styles = getSampleStyleSheet()
        self._add_custom_styles()

    def _add_custom_styles(self) -> None:
        """Add custom paragraph styles."""
        self.styles.add(ParagraphStyle(
            name='DocumentTitle',
            parent=self.styles['Heading1'],
            fontSize=18,
            alignment=TA_CENTER,
            spaceAfter=20,
        ))

        self.styles.add(ParagraphStyle(
            name='SectionTitle',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceBefore=15,
            spaceAfter=10,
            textColor=colors.HexColor('#2c3e50'),
        ))

        self.styles.add(ParagraphStyle(
            name='ExpertBodyText',
            parent=self.styles['Normal'],
            fontSize=11,
            leading=16,
            alignment=TA_JUSTIFY,
            spaceAfter=10,
        ))

        self.styles.add(ParagraphStyle(
            name='BulletPoint',
            parent=self.styles['Normal'],
            fontSize=11,
            leftIndent=20,
            spaceAfter=5,
        ))

    def generate_methodology_document(
        self,
        analysis: ForensicAnalysis,
        output_path: Union[str, Path],
        case_id: Optional[str] = None,
    ) -> Path:
        """
        Generate a methodology document for expert witness testimony.

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
            rightMargin=inch,
            leftMargin=inch,
            topMargin=inch,
            bottomMargin=inch,
        )

        story = []

        # Title
        story.extend(self._build_title_section(case_id))

        # Methodology section
        story.extend(self._build_methodology_section())

        # Tool information
        story.extend(self._build_tool_section(analysis))

        # Reproducibility
        story.extend(self._build_reproducibility_section(analysis))

        # Limitations
        story.extend(self._build_limitations_section())

        # Opinion support
        story.extend(self._build_opinion_section(analysis))

        # Expert attestation
        story.append(PageBreak())
        story.extend(self._build_attestation_section(analysis, case_id))

        doc.build(story)
        return output_path

    def _build_title_section(self, case_id: Optional[str]) -> list:
        """Build the document title section."""
        elements = []

        elements.append(Paragraph(
            "EXPERT WITNESS METHODOLOGY STATEMENT",
            self.styles['DocumentTitle']
        ))

        elements.append(Paragraph(
            "DWG File Forensic Analysis",
            self.styles['Heading2']
        ))

        if case_id:
            elements.append(Paragraph(
                f"Case Reference: {case_id}",
                self.styles['Normal']
            ))

        elements.append(Paragraph(
            f"Date: {datetime.now().strftime('%B %d, %Y')}",
            self.styles['Normal']
        ))

        elements.append(Spacer(1, 0.3 * inch))

        return elements

    def _build_methodology_section(self) -> list:
        """Build the methodology description section."""
        elements = []

        elements.append(Paragraph("1. METHODOLOGY", self.styles['SectionTitle']))

        methodology_text = """
        The forensic analysis of AutoCAD DWG files follows a systematic methodology designed
        to ensure accuracy, completeness, and reproducibility. This methodology is based on
        established digital forensics principles and the technical specifications published
        by the Open Design Alliance (ODA) for DWG file format.
        """
        elements.append(Paragraph(methodology_text.strip(), self.styles['ExpertBodyText']))

        elements.append(Paragraph("<b>1.1 Analysis Steps</b>", self.styles['Normal']))

        steps = [
            "<b>Step 1: File Intake and Hashing</b> - Calculate SHA-256 cryptographic hash "
            "before any analysis operations to establish file integrity baseline.",

            "<b>Step 2: Header Analysis</b> - Parse the DWG file header to extract version "
            "information, maintenance version, and codepage settings.",

            "<b>Step 3: CRC Validation</b> - Validate CRC32 checksums stored in the file "
            "header against calculated values to detect modifications.",

            "<b>Step 4: TrustedDWG Detection</b> - Analyze the TrustedDWG watermark to "
            "determine if the file originated from authorized Autodesk software.",

            "<b>Step 5: Metadata Extraction</b> - Extract DWGPROPS metadata including "
            "author, dates, editing time, and custom properties.",

            "<b>Step 6: Anomaly Detection</b> - Apply detection rules to identify "
            "timestamp anomalies, version inconsistencies, and structural issues.",

            "<b>Step 7: Risk Assessment</b> - Calculate overall tampering risk score "
            "based on weighted analysis of all findings.",
        ]

        for step in steps:
            elements.append(Paragraph(f"  {step}", self.styles['BulletPoint']))

        elements.append(Spacer(1, 0.2 * inch))

        return elements

    def _build_tool_section(self, analysis: ForensicAnalysis) -> list:
        """Build the tool information section."""
        elements = []

        elements.append(Paragraph("2. TOOL INFORMATION", self.styles['SectionTitle']))

        elements.append(Paragraph(
            "The analysis was performed using the DWG Forensic Tool, an open-source "
            "forensic analysis toolkit specifically designed for AutoCAD DWG files.",
            self.styles['ExpertBodyText']
        ))

        # Tool details table
        tool_data = [
            ["Property", "Value"],
            ["Tool Name", "DWG Forensic Tool"],
            ["Version", analysis.analyzer_version],
            ["License", "Open Source (GPLv3)"],
            ["Source Code", "https://github.com/ehrigconsulting/dwg-forensic-tool"],
            ["Primary Language", "Python 3.10+"],
        ]

        table = Table(tool_data, colWidths=[2 * inch, 4 * inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 0.2 * inch))

        elements.append(Paragraph("<b>2.1 Key Dependencies</b>", self.styles['Normal']))

        dependencies = [
            "Python 3.10+ - Runtime environment",
            "Pydantic 2.0+ - Data validation and modeling",
            "ReportLab 4.0+ - PDF report generation",
            "Click 8.0+ - Command-line interface",
            "SQLite 3.35+ - Audit database storage",
        ]

        for dep in dependencies:
            elements.append(Paragraph(f"  - {dep}", self.styles['BulletPoint']))

        elements.append(Spacer(1, 0.2 * inch))

        return elements

    def _build_reproducibility_section(self, analysis: ForensicAnalysis) -> list:
        """Build the reproducibility instructions section."""
        elements = []

        elements.append(Paragraph("3. REPRODUCIBILITY", self.styles['SectionTitle']))

        elements.append(Paragraph(
            "The analysis results can be independently verified by following "
            "these reproduction steps:",
            self.styles['ExpertBodyText']
        ))

        steps = [
            f"<b>File Verification:</b> Calculate SHA-256 hash of the evidence file. "
            f"The hash should match: {analysis.file_info.sha256}",

            f"<b>Tool Installation:</b> Install DWG Forensic Tool version {analysis.analyzer_version} "
            "from the official repository.",

            "<b>Execute Analysis:</b> Run the command: "
            f"<font face='Courier'>dwg-forensic analyze \"{analysis.file_info.filename}\"</font>",

            "<b>Compare Results:</b> The output should produce identical findings for "
            "header analysis, CRC validation, and watermark detection.",
        ]

        for i, step in enumerate(steps, 1):
            elements.append(Paragraph(f"  {i}. {step}", self.styles['BulletPoint']))

        elements.append(Spacer(1, 0.1 * inch))

        elements.append(Paragraph(
            "<b>Note:</b> Minor variations may occur in timestamps and dynamically "
            "generated fields, but core findings (CRC validation, version detection, "
            "watermark analysis) should be identical.",
            self.styles['ExpertBodyText']
        ))

        elements.append(Spacer(1, 0.2 * inch))

        return elements

    def _build_limitations_section(self) -> list:
        """Build the limitations statement section."""
        elements = []

        elements.append(Paragraph("4. LIMITATIONS", self.styles['SectionTitle']))

        elements.append(Paragraph(
            "The following limitations apply to this forensic analysis:",
            self.styles['ExpertBodyText']
        ))

        limitations = [
            "<b>Version Support:</b> Full analysis is supported for DWG versions R18+ "
            "(AutoCAD 2010 and later). Earlier versions have limited analysis capabilities.",

            "<b>TrustedDWG Detection:</b> TrustedDWG watermarks are only present in files "
            "created by Autodesk applications since 2007. Absence of watermark does not "
            "conclusively indicate non-Autodesk origin.",

            "<b>Timestamp Reliability:</b> Internal timestamps can be modified by "
            "applications. Timestamp analysis should be corroborated with external evidence.",

            "<b>Encrypted Files:</b> Password-protected DWG files cannot be fully analyzed "
            "without decryption.",

            "<b>Third-Party Modifications:</b> The tool cannot detect all forms of "
            "modification, particularly those that correctly update CRC values.",

            "<b>File Corruption:</b> Severely corrupted files may produce incomplete "
            "or inaccurate analysis results.",
        ]

        for limitation in limitations:
            elements.append(Paragraph(f"  - {limitation}", self.styles['BulletPoint']))

        elements.append(Spacer(1, 0.2 * inch))

        return elements

    def _build_opinion_section(self, analysis: ForensicAnalysis) -> list:
        """Build the opinion support framework section."""
        elements = []

        elements.append(Paragraph("5. OPINION SUPPORT FRAMEWORK", self.styles['SectionTitle']))

        elements.append(Paragraph(
            "Based on the forensic analysis conducted, the following opinions can be "
            "supported by the evidence:",
            self.styles['ExpertBodyText']
        ))

        # Generate opinion points based on analysis
        opinions = []

        # CRC-based opinion
        if analysis.crc_validation.is_valid:
            opinions.append(
                "<b>File Integrity:</b> The CRC validation PASSED, supporting the opinion "
                "that the file has not been corrupted or modified at the binary level since "
                "its last save operation."
            )
        else:
            opinions.append(
                "<b>File Integrity:</b> The CRC validation FAILED, supporting the opinion "
                "that the file has been modified after its original save operation, possibly "
                "indicating tampering or corruption."
            )

        # Watermark-based opinion
        if analysis.trusted_dwg.watermark_present and analysis.trusted_dwg.watermark_valid:
            opinions.append(
                "<b>Application Origin:</b> A valid TrustedDWG watermark is present, "
                "supporting the opinion that this file was created or last saved by "
                "authorized Autodesk software."
            )
        elif not analysis.trusted_dwg.watermark_present:
            opinions.append(
                "<b>Application Origin:</b> No TrustedDWG watermark is present. This may "
                "indicate the file was created by non-Autodesk software or the watermark "
                "was removed. Further investigation may be warranted."
            )

        # Risk-based opinion
        risk_opinions = {
            RiskLevel.LOW: (
                "<b>Overall Assessment:</b> The LOW risk score supports the opinion "
                "that this file appears authentic and has not been tampered with."
            ),
            RiskLevel.MEDIUM: (
                "<b>Overall Assessment:</b> The MEDIUM risk score indicates some anomalies "
                "were detected. Additional verification is recommended before drawing "
                "definitive conclusions."
            ),
            RiskLevel.HIGH: (
                "<b>Overall Assessment:</b> The HIGH risk score indicates significant "
                "integrity issues. The file may have been modified, and expert review "
                "of the specific findings is recommended."
            ),
            RiskLevel.CRITICAL: (
                "<b>Overall Assessment:</b> The CRITICAL risk score indicates severe "
                "integrity failures. This file should not be relied upon without "
                "extensive forensic investigation and corroborating evidence."
            ),
        }
        opinions.append(risk_opinions.get(analysis.risk_assessment.overall_risk, ""))

        for opinion in opinions:
            if opinion:
                elements.append(Paragraph(f"  - {opinion}", self.styles['BulletPoint']))

        elements.append(Spacer(1, 0.2 * inch))

        return elements

    def _build_attestation_section(
        self,
        analysis: ForensicAnalysis,
        case_id: Optional[str],
    ) -> list:
        """Build the expert attestation section."""
        elements = []

        elements.append(Paragraph("6. EXPERT ATTESTATION", self.styles['SectionTitle']))

        attestation_text = f"""
        I, {self.expert_name}, hereby attest that:

        1. I conducted the forensic analysis described in this document using the
           methodology and tools specified herein.

        2. The findings presented are accurate and based solely on the technical
           evidence contained within the analyzed file.

        3. I am qualified to perform this analysis by virtue of my training,
           experience, and credentials in digital forensics.

        4. I have no personal interest in the outcome of this case beyond providing
           accurate forensic analysis.

        5. I am prepared to testify to these findings and methodology under oath.
        """
        elements.append(Paragraph(attestation_text.strip(), self.styles['ExpertBodyText']))

        elements.append(Spacer(1, 0.5 * inch))

        # Signature block
        sig_data = [
            ["Expert Name:", self.expert_name],
            ["Credentials:", self.expert_credentials],
            ["Organization:", self.company_name],
            ["Date:", "_" * 30],
            ["Signature:", "_" * 30],
        ]

        table = Table(sig_data, colWidths=[1.5 * inch, 4 * inch])
        table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(table)

        return elements


def generate_expert_witness_document(
    analysis: ForensicAnalysis,
    output_path: Union[str, Path],
    case_id: Optional[str] = None,
    expert_name: str = "Digital Forensics Expert",
    expert_credentials: Optional[str] = None,
    company_name: Optional[str] = None,
) -> Path:
    """
    Convenience function to generate expert witness documentation.

    Args:
        analysis: Forensic analysis results
        output_path: Path to save the PDF
        case_id: Optional case identifier
        expert_name: Name of the expert witness
        expert_credentials: Expert's credentials
        company_name: Company or organization name

    Returns:
        Path to the generated PDF file
    """
    generator = ExpertWitnessGenerator(
        expert_name=expert_name,
        expert_credentials=expert_credentials,
        company_name=company_name,
    )
    return generator.generate_methodology_document(analysis, output_path, case_id)
