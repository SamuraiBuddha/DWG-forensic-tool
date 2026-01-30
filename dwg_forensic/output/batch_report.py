"""
Batch Report Generator - PDF reports for batch analysis results.

Generates comprehensive PDF reports for batches of DWG files including:
- Risk distribution visualization
- Per-file summaries with LLM narratives
- LLM filtering statistics
- Aggregate tampering statistics

Phase 4.4 Implementation
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)

from dwg_forensic.models import ForensicAnalysis, RiskLevel

logger = logging.getLogger(__name__)


def _truncate_text(text: str, max_length: int = 500) -> str:
    """Truncate text to max length with ellipsis.

    Args:
        text: Text to truncate
        max_length: Maximum length

    Returns:
        Truncated text
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def _format_risk_level(risk: RiskLevel) -> str:
    """Format risk level with color indicator.

    Args:
        risk: RiskLevel enum

    Returns:
        Formatted string with ASCII indicator
    """
    indicators = {
        RiskLevel.INFO: "[INFO]",
        RiskLevel.LOW: "[LOW]",
        RiskLevel.MEDIUM: "[MEDIUM]",
        RiskLevel.HIGH: "[HIGH]",
        RiskLevel.CRITICAL: "[CRITICAL]",
    }
    return indicators.get(risk, "[UNKNOWN]")


def generate_batch_report(
    batch_result: Any,  # BatchAnalysisResult
    output_path: Path,
    case_id: Optional[str] = None,
    examiner: Optional[str] = None,
) -> Path:
    """Generate PDF report for batch analysis results.

    Args:
        batch_result: BatchAnalysisResult with analysis data
        output_path: Output PDF file path
        case_id: Optional case identifier
        examiner: Optional examiner name

    Returns:
        Path to generated PDF report
    """
    logger.info(f"Generating batch report: {output_path}")

    # Create PDF document
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    # Build document content
    story = []
    styles = getSampleStyleSheet()

    # Title
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=colors.HexColor("#1a1a1a"),
        spaceAfter=12,
    )
    story.append(Paragraph("DWG Forensic Batch Analysis Report", title_style))
    story.append(Spacer(1, 0.2 * inch))

    # Metadata table
    metadata_data = [
        ["Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Total Files Processed", str(batch_result.total_files)],
        ["Successful Analyses", str(batch_result.successful)],
        ["Failed Analyses", str(batch_result.failed)],
        ["Processing Time", f"{batch_result.processing_time_seconds:.2f}s"],
    ]

    if case_id:
        metadata_data.insert(0, ["Case ID", case_id])
    if examiner:
        metadata_data.insert(1 if case_id else 0, ["Examiner", examiner])

    if batch_result.llm_enabled and batch_result.llm_result:
        llm_result = batch_result.llm_result
        metadata_data.extend([
            ["LLM Model", llm_result.model_used],
            ["LLM Narratives Generated", str(llm_result.processed_files)],
            ["LLM Processing Time", f"{llm_result.processing_time_seconds:.2f}s"],
        ])

    metadata_table = Table(metadata_data, colWidths=[2.5 * inch, 4 * inch])
    metadata_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8e8e8")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))

    story.append(metadata_table)
    story.append(Spacer(1, 0.3 * inch))

    # Risk Distribution
    story.append(Paragraph("Risk Distribution", styles["Heading2"]))
    story.append(Spacer(1, 0.1 * inch))

    risk_dist_data = [["Risk Level", "Count", "Percentage"]]
    total = sum(batch_result.risk_distribution.values())

    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = batch_result.risk_distribution.get(level, 0)
        percentage = (count / total * 100) if total > 0 else 0.0
        risk_dist_data.append([level, str(count), f"{percentage:.1f}%"])

    risk_table = Table(risk_dist_data, colWidths=[2 * inch, 1.5 * inch, 2 * inch])
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 11),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        # Color-code risk levels
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#ff4444")),  # CRITICAL
        ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#ff9944")),  # HIGH
        ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#ffff44")),  # MEDIUM
        ("BACKGROUND", (0, 4), (-1, 4), colors.HexColor("#88ff88")),  # LOW
        ("BACKGROUND", (0, 5), (-1, 5), colors.HexColor("#cccccc")),  # INFO
    ]))

    story.append(risk_table)
    story.append(Spacer(1, 0.3 * inch))

    # LLM Filtering Summary (if enabled)
    if batch_result.llm_enabled and batch_result.llm_result:
        story.append(Paragraph("LLM Processing Summary", styles["Heading2"]))
        story.append(Spacer(1, 0.1 * inch))

        llm_result = batch_result.llm_result

        llm_summary = Paragraph(
            f"Processed {llm_result.processed_files} out of {llm_result.total_files} "
            f"files using {llm_result.model_used} model. "
            f"Skipped {llm_result.skipped_files} low-risk files. "
            f"Processing completed in {llm_result.processing_time_seconds:.2f}s "
            f"({llm_result.processed_files / llm_result.processing_time_seconds:.1f} files/sec).",
            styles["BodyText"]
        )
        story.append(llm_summary)
        story.append(Spacer(1, 0.3 * inch))

    # Per-File Summaries
    story.append(PageBreak())
    story.append(Paragraph("Individual File Summaries", styles["Heading2"]))
    story.append(Spacer(1, 0.2 * inch))

    for analysis in batch_result.results[:50]:  # Limit to 50 files for PDF size
        file_summary = _generate_file_summary(
            analysis,
            batch_result.llm_result,
            styles,
        )
        story.append(file_summary)
        story.append(Spacer(1, 0.2 * inch))

    if len(batch_result.results) > 50:
        remaining = len(batch_result.results) - 50
        story.append(Paragraph(
            f"[Note: {remaining} additional files omitted for brevity. "
            f"See JSON export for complete results.]",
            styles["Italic"]
        ))

    # Build PDF
    doc.build(story)

    logger.info(f"Batch report generated: {output_path}")
    return output_path


def _generate_file_summary(
    analysis: ForensicAnalysis,
    llm_result: Optional[Any],  # Optional[BatchLLMResult]
    styles: Any,
) -> KeepTogether:
    """Generate summary section for a single file.

    Args:
        analysis: ForensicAnalysis result
        llm_result: Optional BatchLLMResult
        styles: ReportLab styles

    Returns:
        KeepTogether element with file summary
    """
    elements = []

    # File header
    file_header = Paragraph(
        f"<b>{analysis.file_info.filename}</b> - "
        f"{_format_risk_level(analysis.risk_assessment.overall_risk)}",
        styles["Heading3"]
    )
    elements.append(file_header)

    # Basic info
    info_text = (
        f"SHA-256: {analysis.file_info.sha256[:16]}... | "
        f"Version: {analysis.header_analysis.version_name} | "
        f"Size: {analysis.file_info.file_size_bytes:,} bytes"
    )
    elements.append(Paragraph(info_text, styles["BodyText"]))
    elements.append(Spacer(1, 0.05 * inch))

    # Tampering indicators
    if analysis.tampering_indicators:
        indicators_text = "<b>Tampering Indicators:</b> " + ", ".join(
            [ind.indicator_type.value for ind in analysis.tampering_indicators[:3]]
        )
        elements.append(Paragraph(indicators_text, styles["BodyText"]))
        elements.append(Spacer(1, 0.05 * inch))

    # LLM narrative (if available)
    if llm_result and llm_result.narratives:
        # Find narrative by filename
        narrative = llm_result.narratives.get(analysis.file_info.filename)
        if narrative:
            # Truncate for PDF
            truncated_narrative = _truncate_text(narrative, max_length=400)
            narrative_para = Paragraph(
                f"<b>Expert Analysis:</b> {truncated_narrative}",
                styles["BodyText"]
            )
            elements.append(narrative_para)

    return KeepTogether(elements)


def export_batch_json(
    batch_result: Any,  # BatchAnalysisResult
    output_path: Path,
) -> Path:
    """Export batch results to JSON format.

    Args:
        batch_result: BatchAnalysisResult
        output_path: Output JSON file path

    Returns:
        Path to generated JSON file
    """
    import json

    logger.info(f"Exporting batch results to JSON: {output_path}")

    # Build JSON structure
    data = {
        "metadata": {
            "total_files": batch_result.total_files,
            "successful": batch_result.successful,
            "failed": batch_result.failed,
            "processing_time_seconds": batch_result.processing_time_seconds,
            "aggregated_risk_score": batch_result.aggregated_risk_score,
        },
        "risk_distribution": batch_result.risk_distribution,
        "results": [
            {
                "filename": analysis.file_info.filename,
                "sha256": analysis.file_info.sha256,
                "risk_level": analysis.risk_assessment.overall_risk.value,
                "version": analysis.header_analysis.version_name,
                "tampering_indicators": len(analysis.tampering_indicators),
                "llm_narrative": (
                    batch_result.llm_result.narratives.get(analysis.file_info.filename)
                    if batch_result.llm_enabled and batch_result.llm_result
                    else None
                ),
            }
            for analysis in batch_result.results
        ],
        "failures": [
            {
                "filename": failure.file_path.name,
                "error": failure.error,
                "error_type": failure.error_type,
            }
            for failure in batch_result.failures
        ],
    }

    if batch_result.llm_enabled and batch_result.llm_result:
        data["llm_summary"] = {
            "model_used": batch_result.llm_result.model_used,
            "processed_files": batch_result.llm_result.processed_files,
            "skipped_files": batch_result.llm_result.skipped_files,
            "failed_files": batch_result.llm_result.failed_files,
            "processing_time_seconds": batch_result.llm_result.processing_time_seconds,
        }

    # Write JSON
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    logger.info(f"Batch JSON export complete: {output_path}")
    return output_path
