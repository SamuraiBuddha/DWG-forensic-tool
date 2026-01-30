"""DWG Forensic Tool - Comparison Report Generator

Generates detailed delta reports for comparing two DWG files.
Implements Phase 3.3 - Advanced Comparative Reporting.

Report sections:
1. Metadata comparison table (file info, versions, risk levels)
2. Timestamp delta timeline (visual showing time differences)
3. Structure diff summary (handle gaps, object deltas, section changes)
4. Detailed anomaly comparison (anomalies in file1 vs file2)
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from dwg_forensic import __version__
from dwg_forensic.analysis.comparator import ComparisonResult
from dwg_forensic.output.pdf_report import PDFReportStyles


class ComparisonReportGenerator:
    """Generates professional PDF comparison reports for DWG file analysis.

    Creates litigation-ready documents comparing two DWG files with:
    - Metadata comparison table
    - Timestamp delta timeline
    - Structure diff summary
    - Detailed anomaly comparison
    """

    def __init__(
        self,
        company_name: Optional[str] = None,
        examiner_name: Optional[str] = None,
    ):
        """Initialize the comparison report generator.

        Args:
            company_name: Company name for report header
            examiner_name: Examiner name for attestation
        """
        self.company_name = company_name or "Digital Forensics Analysis"
        self.examiner_name = examiner_name or "Forensic Examiner"
        self.styles = PDFReportStyles()

    def generate_pdf(
        self,
        comparison: ComparisonResult,
        output_path: Union[str, Path],
        case_id: Optional[str] = None,
    ) -> Path:
        """Generate a complete PDF comparison report.

        Args:
            comparison: ComparisonResult with analysis and comparison data
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
        story.extend(self._build_cover_page(comparison, case_id))
        story.append(PageBreak())

        # Section 1: Metadata comparison
        story.extend(self._build_metadata_comparison(comparison))
        story.append(Spacer(1, 0.3 * inch))

        # Section 2: Timestamp delta timeline
        story.extend(self._build_timestamp_comparison(comparison))
        story.append(PageBreak())

        # Section 3: Structure diff summary
        if comparison.structure_diff and comparison.structure_diff.has_structural_changes():
            story.extend(self._build_structure_comparison(comparison))
            story.append(PageBreak())

        # Section 4: Detailed anomaly comparison
        story.extend(self._build_anomaly_comparison(comparison))

        # Build the PDF
        doc.build(story, onFirstPage=self._add_header_footer, onLaterPages=self._add_header_footer)

        return output_path

    def generate_json(
        self,
        comparison: ComparisonResult,
        output_path: Union[str, Path],
    ) -> Path:
        """Generate a JSON export of the comparison data.

        Args:
            comparison: ComparisonResult with analysis and comparison data
            output_path: Path to save the JSON file

        Returns:
            Path to the generated JSON file
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Build comparison data dictionary
        comparison_data = {
            "comparison_metadata": {
                "generated_timestamp": datetime.now().isoformat(),
                "analyzer_version": __version__,
                "comparison_type": "dwg_file_comparison",
            },
            "file1": {
                "filename": comparison.file1_analysis.file_info.filename,
                "sha256": comparison.file1_analysis.file_info.sha256,
                "file_size_bytes": comparison.file1_analysis.file_info.file_size_bytes,
                "version": comparison.file1_analysis.header_analysis.version_string,
                "risk_level": comparison.file1_analysis.risk_assessment.overall_risk.value,
                "crc_valid": comparison.file1_analysis.crc_validation.is_valid,
                "anomaly_count": len(comparison.file1_analysis.anomalies),
                "tampering_indicator_count": len(comparison.file1_analysis.tampering_indicators),
            },
            "file2": {
                "filename": comparison.file2_analysis.file_info.filename,
                "sha256": comparison.file2_analysis.file_info.sha256,
                "file_size_bytes": comparison.file2_analysis.file_info.file_size_bytes,
                "version": comparison.file2_analysis.header_analysis.version_string,
                "risk_level": comparison.file2_analysis.risk_assessment.overall_risk.value,
                "crc_valid": comparison.file2_analysis.crc_validation.is_valid,
                "anomaly_count": len(comparison.file2_analysis.anomalies),
                "tampering_indicator_count": len(comparison.file2_analysis.tampering_indicators),
            },
            "deltas": {
                "timestamp_delta_seconds": comparison.timestamp_delta_seconds,
                "modification_delta_seconds": comparison.modification_delta_seconds,
                "metadata_changes": comparison.metadata_changes,
                "risk_level_change": comparison.risk_level_change,
            },
            "structure_diff": None,
            "comparison_summary": comparison.comparison_summary,
        }

        # Add structure diff if available
        if comparison.structure_diff:
            comparison_data["structure_diff"] = {
                "handle_gaps_added": comparison.structure_diff.handle_gaps_added,
                "handle_gaps_removed": comparison.structure_diff.handle_gaps_removed,
                "handle_gap_changes": comparison.structure_diff.handle_gap_changes,
                "section_changes": comparison.structure_diff.section_changes,
                "object_deltas": comparison.structure_diff.object_deltas,
                "property_changes": {
                    k: {"before": v[0], "after": v[1]}
                    for k, v in comparison.structure_diff.property_changes.items()
                },
                "summary": comparison.structure_diff.summary,
                "change_severity": comparison.structure_diff.get_change_severity(),
            }

        # Write JSON file
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(comparison_data, f, indent=2, default=str)

        return output_path

    def _build_cover_page(
        self,
        comparison: ComparisonResult,
        case_id: Optional[str],
    ) -> list:
        """Build the report cover page."""
        elements = []
        styles = self.styles.styles

        # Spacer at top
        elements.append(Spacer(1, 2 * inch))

        # Title
        elements.append(Paragraph(
            "DWG FILE COMPARISON REPORT",
            styles['ReportTitle']
        ))

        # Subtitle
        elements.append(Paragraph(
            "Forensic Delta Analysis",
            styles['ReportSubtitle']
        ))

        elements.append(Spacer(1, 0.5 * inch))

        # Report metadata table
        report_data = [
            ["Case ID:", case_id or "N/A"],
            ["Report Date:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Analyzer Version:", __version__],
            ["File 1:", comparison.file1_analysis.file_info.filename],
            ["File 2:", comparison.file2_analysis.file_info.filename],
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

    def _build_metadata_comparison(self, comparison: ComparisonResult) -> list:
        """Build the metadata comparison section."""
        elements = []
        styles = self.styles.styles

        elements.append(Paragraph("1. Metadata Comparison", styles['SectionHeader']))
        elements.append(Spacer(1, 0.2 * inch))

        # File information comparison
        file_data = [
            ["Property", "File 1", "File 2", "Delta"],
            [
                "Filename",
                comparison.file1_analysis.file_info.filename,
                comparison.file2_analysis.file_info.filename,
                "Same" if comparison.file1_analysis.file_info.filename == comparison.file2_analysis.file_info.filename else "Different"
            ],
            [
                "Version",
                comparison.file1_analysis.header_analysis.version_string,
                comparison.file2_analysis.header_analysis.version_string,
                "Same" if comparison.file1_analysis.header_analysis.version_string == comparison.file2_analysis.header_analysis.version_string else "Changed"
            ],
            [
                "Risk Level",
                comparison.file1_analysis.risk_assessment.overall_risk.value,
                comparison.file2_analysis.risk_assessment.overall_risk.value,
                comparison.risk_level_change or "No change"
            ],
            [
                "CRC Valid",
                "[OK]" if comparison.file1_analysis.crc_validation.is_valid else "[FAIL]",
                "[OK]" if comparison.file2_analysis.crc_validation.is_valid else "[FAIL]",
                "Same" if comparison.file1_analysis.crc_validation.is_valid == comparison.file2_analysis.crc_validation.is_valid else "Changed"
            ],
            [
                "File Size",
                f"{comparison.file1_analysis.file_info.file_size_bytes:,} bytes",
                f"{comparison.file2_analysis.file_info.file_size_bytes:,} bytes",
                f"{comparison.file2_analysis.file_info.file_size_bytes - comparison.file1_analysis.file_info.file_size_bytes:+,} bytes"
            ],
        ]

        table = Table(file_data, colWidths=[1.5 * inch, 1.8 * inch, 1.8 * inch, 1.5 * inch])
        table.setStyle(self._get_standard_table_style())
        elements.append(table)

        elements.append(Spacer(1, 0.2 * inch))

        # Metadata changes
        if comparison.metadata_changes:
            elements.append(Paragraph("<b>Detected Changes:</b>", styles['Normal']))
            elements.append(Spacer(1, 0.1 * inch))
            for change in comparison.metadata_changes:
                elements.append(Paragraph(f"[->] {change}", styles['Normal']))
        else:
            elements.append(Paragraph(
                "[OK] No metadata changes detected between files.",
                styles['Normal']
            ))

        return elements

    def _build_timestamp_comparison(self, comparison: ComparisonResult) -> list:
        """Build the timestamp comparison section with visual timeline."""
        elements = []
        styles = self.styles.styles

        elements.append(Paragraph("2. Timestamp Delta Analysis", styles['SectionHeader']))
        elements.append(Spacer(1, 0.2 * inch))

        # Timestamp delta table
        if comparison.timestamp_delta_seconds is not None or comparison.modification_delta_seconds is not None:
            ts_data = [["Timestamp Type", "File 1", "File 2", "Delta"]]

            # Creation timestamps
            if comparison.timestamp_delta_seconds is not None:
                meta1 = comparison.file1_analysis.metadata
                meta2 = comparison.file2_analysis.metadata
                ts1 = meta1.created_date if meta1 and meta1.created_date else comparison.file1_analysis.file_info.intake_timestamp
                ts2 = meta2.created_date if meta2 and meta2.created_date else comparison.file2_analysis.file_info.intake_timestamp

                days = abs(comparison.timestamp_delta_seconds) // 86400
                hours = (abs(comparison.timestamp_delta_seconds) % 86400) // 3600
                direction = "newer" if comparison.timestamp_delta_seconds > 0 else "older"

                ts_data.append([
                    "Creation",
                    ts1.strftime("%Y-%m-%d %H:%M:%S") if ts1 else "N/A",
                    ts2.strftime("%Y-%m-%d %H:%M:%S") if ts2 else "N/A",
                    f"{days}d {hours}h (File 2 is {direction})"
                ])

            # Modification timestamps
            if comparison.modification_delta_seconds is not None:
                meta1 = comparison.file1_analysis.metadata
                meta2 = comparison.file2_analysis.metadata
                mod1 = meta1.modified_date if meta1 else None
                mod2 = meta2.modified_date if meta2 else None

                days = abs(comparison.modification_delta_seconds) // 86400
                hours = (abs(comparison.modification_delta_seconds) % 86400) // 3600
                direction = "newer" if comparison.modification_delta_seconds > 0 else "older"

                ts_data.append([
                    "Last Modified",
                    mod1.strftime("%Y-%m-%d %H:%M:%S") if mod1 else "N/A",
                    mod2.strftime("%Y-%m-%d %H:%M:%S") if mod2 else "N/A",
                    f"{days}d {hours}h (File 2 is {direction})"
                ])

            table = Table(ts_data, colWidths=[1.5 * inch, 1.8 * inch, 1.8 * inch, 1.8 * inch])
            table.setStyle(self._get_standard_table_style())
            elements.append(table)
        else:
            elements.append(Paragraph(
                "[INFO] Timestamp comparison not available - no timestamps found in file metadata.",
                styles['Normal']
            ))

        elements.append(Spacer(1, 0.2 * inch))

        # Timeline visualization explanation
        elements.append(Paragraph("<b>Timeline Interpretation:</b>", styles['NarrativeHeader']))
        timeline_explanation = (
            "The timestamp delta shows the time difference between when the two files "
            "were created and last modified. A large delta may indicate files from different "
            "project phases, while a small delta suggests minor revisions. Forensically, "
            "compare these deltas with editing time metadata to detect clock manipulation."
        )
        elements.append(Paragraph(timeline_explanation, styles['Narrative']))

        return elements

    def _build_structure_comparison(self, comparison: ComparisonResult) -> list:
        """Build the structure diff comparison section."""
        elements = []
        styles = self.styles.styles

        elements.append(Paragraph("3. Deep Structure Comparison", styles['SectionHeader']))
        elements.append(Spacer(1, 0.2 * inch))

        structure_diff = comparison.structure_diff
        if not structure_diff:
            elements.append(Paragraph(
                "[INFO] Deep structure comparison not available.",
                styles['Normal']
            ))
            return elements

        # Change severity
        severity = structure_diff.get_change_severity()
        severity_colors = {
            "NONE": "green",
            "MINOR": "yellow",
            "MAJOR": "red",
            "CRITICAL": "red bold",
        }
        severity_color = severity_colors.get(severity, "white")
        elements.append(Paragraph(
            f"Change Severity: <b>{severity}</b>",
            styles['Normal']
        ))
        elements.append(Spacer(1, 0.2 * inch))

        # Handle gap changes
        if structure_diff.handle_gaps_added or structure_diff.handle_gaps_removed:
            elements.append(Paragraph("<b>Handle Gap Changes</b>", styles['Heading3']))
            gap_data = [["Metric", "Value"]]

            if structure_diff.handle_gap_changes:
                changes = structure_diff.handle_gap_changes
                if "file1_gap_count" in changes:
                    gap_data.append(["File 1 Gap Count", str(changes["file1_gap_count"])])
                if "file2_gap_count" in changes:
                    gap_data.append(["File 2 Gap Count", str(changes["file2_gap_count"])])
                if structure_diff.handle_gaps_added:
                    gap_data.append(["Gaps Added", str(len(structure_diff.handle_gaps_added))])
                if structure_diff.handle_gaps_removed:
                    gap_data.append(["Gaps Removed", str(len(structure_diff.handle_gaps_removed))])

            table = Table(gap_data, colWidths=[3 * inch, 3.5 * inch])
            table.setStyle(self._get_standard_table_style())
            elements.append(table)
            elements.append(Spacer(1, 0.2 * inch))

        # Section changes
        if structure_diff.section_changes:
            elements.append(Paragraph("<b>Section Map Changes</b>", styles['Heading3']))
            section_data = [["Section", "Size Before", "Size After", "Delta"]]

            for section_name, changes in sorted(structure_diff.section_changes.items()):
                size_before = changes["size_before"]
                size_after = changes["size_after"]
                delta = changes["delta"]

                section_data.append([
                    section_name,
                    f"{size_before:,}" if size_before > 0 else "-",
                    f"{size_after:,}" if size_after > 0 else "-",
                    f"{delta:+,}"
                ])

            table = Table(section_data, colWidths=[1.5 * inch, 1.5 * inch, 1.5 * inch, 1.5 * inch])
            table.setStyle(self._get_standard_table_style())
            elements.append(table)
            elements.append(Spacer(1, 0.2 * inch))

        # Object count changes
        if structure_diff.object_deltas:
            elements.append(Paragraph("<b>Object Count Changes</b>", styles['Heading3']))
            object_data = [["Object Type", "Delta", "Direction"]]

            for obj_type, delta in sorted(
                structure_diff.object_deltas.items(),
                key=lambda x: abs(x[1]),
                reverse=True
            ):
                direction = "Added" if delta > 0 else "Removed"
                object_data.append([obj_type, f"{delta:+d}", direction])

            table = Table(object_data, colWidths=[3 * inch, 1.5 * inch, 2 * inch])
            table.setStyle(self._get_standard_table_style())
            elements.append(table)
            elements.append(Spacer(1, 0.2 * inch))

        # Summary
        elements.append(Paragraph("<b>Structure Analysis Summary:</b>", styles['NarrativeHeader']))
        elements.append(Paragraph(structure_diff.summary or "No significant structural changes detected.", styles['Narrative']))

        return elements

    def _build_anomaly_comparison(self, comparison: ComparisonResult) -> list:
        """Build the anomaly comparison section."""
        elements = []
        styles = self.styles.styles

        elements.append(Paragraph("4. Anomaly and Tampering Comparison", styles['SectionHeader']))
        elements.append(Spacer(1, 0.2 * inch))

        # Anomaly counts comparison
        anomaly_data = [
            ["Metric", "File 1", "File 2", "Delta"],
            [
                "Anomalies Detected",
                str(len(comparison.file1_analysis.anomalies)),
                str(len(comparison.file2_analysis.anomalies)),
                f"{len(comparison.file2_analysis.anomalies) - len(comparison.file1_analysis.anomalies):+d}"
            ],
            [
                "Tampering Indicators",
                str(len(comparison.file1_analysis.tampering_indicators)),
                str(len(comparison.file2_analysis.tampering_indicators)),
                f"{len(comparison.file2_analysis.tampering_indicators) - len(comparison.file1_analysis.tampering_indicators):+d}"
            ],
        ]

        table = Table(anomaly_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch, 1.5 * inch])
        table.setStyle(self._get_standard_table_style())
        elements.append(table)

        elements.append(Spacer(1, 0.3 * inch))

        # Detailed anomaly breakdown
        elements.append(Paragraph("<b>File 1 Findings:</b>", styles['Heading3']))
        if comparison.file1_analysis.anomalies or comparison.file1_analysis.tampering_indicators:
            elements.append(Paragraph(
                f"[*] {len(comparison.file1_analysis.anomalies)} anomalies detected",
                styles['Normal']
            ))
            elements.append(Paragraph(
                f"[*] {len(comparison.file1_analysis.tampering_indicators)} tampering indicators detected",
                styles['Normal']
            ))
        else:
            elements.append(Paragraph(
                "[OK] No anomalies or tampering indicators detected.",
                styles['Normal']
            ))

        elements.append(Spacer(1, 0.2 * inch))

        elements.append(Paragraph("<b>File 2 Findings:</b>", styles['Heading3']))
        if comparison.file2_analysis.anomalies or comparison.file2_analysis.tampering_indicators:
            elements.append(Paragraph(
                f"[*] {len(comparison.file2_analysis.anomalies)} anomalies detected",
                styles['Normal']
            ))
            elements.append(Paragraph(
                f"[*] {len(comparison.file2_analysis.tampering_indicators)} tampering indicators detected",
                styles['Normal']
            ))
        else:
            elements.append(Paragraph(
                "[OK] No anomalies or tampering indicators detected.",
                styles['Normal']
            ))

        elements.append(Spacer(1, 0.3 * inch))

        # Forensic interpretation
        elements.append(Paragraph("<b>Forensic Interpretation:</b>", styles['NarrativeHeader']))
        interpretation = self._generate_anomaly_interpretation(comparison)
        elements.append(Paragraph(interpretation, styles['Narrative']))

        return elements

    def _generate_anomaly_interpretation(self, comparison: ComparisonResult) -> str:
        """Generate forensic interpretation of anomaly changes."""
        anomaly_delta = len(comparison.file2_analysis.anomalies) - len(comparison.file1_analysis.anomalies)
        indicator_delta = len(comparison.file2_analysis.tampering_indicators) - len(comparison.file1_analysis.tampering_indicators)

        if anomaly_delta == 0 and indicator_delta == 0:
            return (
                "Both files show the same number of anomalies and tampering indicators. "
                "This suggests the files are from the same lineage with minimal forensic changes. "
                "Any differences are likely legitimate edits rather than tampering."
            )
        elif anomaly_delta > 0 or indicator_delta > 0:
            return (
                f"File 2 shows <b>{abs(anomaly_delta)} more anomalies</b> and "
                f"<b>{abs(indicator_delta)} more tampering indicators</b> than File 1. "
                "This increase in forensic findings suggests File 2 may have undergone "
                "additional modification or manipulation. Recommend detailed investigation "
                "of the specific new findings to determine if they represent legitimate edits "
                "or evidence of tampering."
            )
        else:
            return (
                f"File 2 shows <b>{abs(anomaly_delta)} fewer anomalies</b> and "
                f"<b>{abs(indicator_delta)} fewer tampering indicators</b> than File 1. "
                "This reduction suggests File 2 may be a cleaned or corrected version, "
                "or the findings in File 1 were false positives that resolved in subsequent saves. "
                "Review the specific findings that disappeared to understand the changes."
            )

    def _get_standard_table_style(self) -> TableStyle:
        """Get standard table styling for comparison reports."""
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


def generate_comparison_pdf_report(
    comparison: ComparisonResult,
    output_path: Union[str, Path],
    case_id: Optional[str] = None,
    company_name: Optional[str] = None,
    examiner_name: Optional[str] = None,
) -> Path:
    """Convenience function to generate a comparison PDF report.

    Args:
        comparison: ComparisonResult with analysis and comparison data
        output_path: Path to save the PDF
        case_id: Optional case identifier
        company_name: Company name for report header
        examiner_name: Examiner name for attestation

    Returns:
        Path to the generated PDF file
    """
    generator = ComparisonReportGenerator(
        company_name=company_name,
        examiner_name=examiner_name,
    )
    return generator.generate_pdf(comparison, output_path, case_id)


def generate_comparison_json_report(
    comparison: ComparisonResult,
    output_path: Union[str, Path],
) -> Path:
    """Convenience function to generate a comparison JSON report.

    Args:
        comparison: ComparisonResult with analysis and comparison data
        output_path: Path to save the JSON file

    Returns:
        Path to the generated JSON file
    """
    generator = ComparisonReportGenerator()
    return generator.generate_json(comparison, output_path)
