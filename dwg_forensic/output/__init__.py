"""Output generation modules for DWG forensic analysis.

This package provides output formatters and exporters for forensic analysis results.
"""

from dwg_forensic.output.json_export import JSONExporter, export_to_json
from dwg_forensic.output.hex_dump import HexDumpFormatter, format_hex_dump, extract_and_format
from dwg_forensic.output.timeline import (
    TimelineEvent,
    TimelineGenerator,
    generate_timeline,
)
from dwg_forensic.output.pdf_report import (
    PDFReportGenerator,
    PDFReportStyles,
    generate_pdf_report,
)
from dwg_forensic.output.expert_witness import (
    ExpertWitnessGenerator,
    generate_expert_witness_document,
)

__all__ = [
    # JSON Export
    "JSONExporter",
    "export_to_json",
    # Hex Dump
    "HexDumpFormatter",
    "format_hex_dump",
    "extract_and_format",
    # Timeline
    "TimelineEvent",
    "TimelineGenerator",
    "generate_timeline",
    # PDF Report
    "PDFReportGenerator",
    "PDFReportStyles",
    "generate_pdf_report",
    # Expert Witness
    "ExpertWitnessGenerator",
    "generate_expert_witness_document",
]
