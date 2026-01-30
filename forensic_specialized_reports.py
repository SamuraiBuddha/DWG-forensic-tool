#!/usr/bin/env python3
"""
FORENSIC SPECIALIZED REPORTS
Case: 2026-001 Kara Murphy vs Danny Garcia

Generates specialized forensic reports:
- HANDLE_GAP_ANALYSIS.txt (content deletion evidence)
- APPLICATION_FINGERPRINT_REPORT.txt (tool identification)
- DWG_vs_REVIT_TIMELINE.txt (RVT-DWG correlation)
"""

import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from dwg_forensic.core.batch_processor import BatchAnalysisResult
from dwg_forensic.models import ForensicAnalysis

logger = logging.getLogger(__name__)

# Case configuration
CASE_ROOT = Path(r"\\adam\DataPool\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia")
OUTPUT_DIR = CASE_ROOT / "FORENSIC_ANALYSIS_OUTPUT"
CASE_ID = "2026-001"
EXAMINER = "John Ehrig, P.E."


def generate_handle_gap_analysis(batch_result: BatchAnalysisResult, output_dir: Path) -> Path:
    """Generate comprehensive handle gap analysis report.

    Handle gaps indicate deleted or modified objects in DWG files.
    This is forensic evidence of content manipulation.

    Args:
        batch_result: BatchAnalysisResult from forensic sweep
        output_dir: Output directory for report

    Returns:
        Path to generated report
    """
    report_path = output_dir / "HANDLE_GAP_ANALYSIS.txt"
    logger.info(f"Generating handle gap analysis: {report_path}")

    # Collect files with handle gaps
    files_with_gaps: List[tuple] = []

    for analysis in batch_result.results:
        if hasattr(analysis, 'structure_analysis') and analysis.structure_analysis:
            if hasattr(analysis.structure_analysis, 'handle_gaps'):
                gaps = analysis.structure_analysis.handle_gaps
                if gaps:
                    files_with_gaps.append((analysis.file_info.filename, len(gaps), gaps, analysis))

    # Sort by gap count descending
    files_with_gaps.sort(key=lambda x: x[1], reverse=True)

    # Write report
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("HANDLE GAP ANALYSIS - CONTENT DELETION EVIDENCE\n")
        f.write("=" * 80 + "\n")
        f.write(f"Case: {CASE_ID} - Kara Murphy vs Danny Garcia\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Examiner: {EXAMINER}\n")
        f.write("=" * 80 + "\n\n")

        f.write("EXECUTIVE SUMMARY\n")
        f.write("-" * 80 + "\n")
        f.write(f"Total Files Analyzed: {batch_result.total_files}\n")
        f.write(f"Files with Handle Gaps: {len(files_with_gaps)}\n")
        total_gaps = sum(x[1] for x in files_with_gaps)
        f.write(f"Total Handle Gaps Detected: {total_gaps}\n\n")

        if files_with_gaps:
            percentage = (len(files_with_gaps) / batch_result.total_files * 100)
            f.write(f"[FINDING] {percentage:.1f}% of DWG files show evidence of object deletion.\n")
            f.write("This indicates post-creation modification of drawing content.\n\n")

        # Methodology
        f.write("\nMETHODOLOGY\n")
        f.write("-" * 80 + "\n")
        f.write("Handle gaps are discontinuities in the sequential object handle numbering\n")
        f.write("system used by AutoCAD. Each object in a DWG file receives a unique handle\n")
        f.write("(hexadecimal identifier). When objects are deleted, gaps appear in the\n")
        f.write("sequence. These gaps provide forensic evidence of content modification.\n\n")

        f.write("Forensic Significance:\n")
        f.write("  - Handle gaps prove objects were created then deleted\n")
        f.write("  - Number of gaps indicates extent of modification\n")
        f.write("  - Large gaps suggest bulk deletion operations\n")
        f.write("  - Patterns across files suggest coordinated modification\n\n")

        # Detailed findings
        f.write("\nDETAILED FINDINGS - FILES WITH HANDLE GAPS\n")
        f.write("-" * 80 + "\n\n")

        for rank, (filename, gap_count, gaps, analysis) in enumerate(files_with_gaps, 1):
            f.write(f"\n#{rank}. {filename}\n")
            f.write(f"    Handle Gaps Detected: {gap_count}\n")
            f.write(f"    Risk Level: {analysis.risk_assessment.overall_risk.value}\n")
            f.write(f"    DWG Version: {analysis.header_analysis.version_name}\n")

            # Show first 10 gaps
            f.write(f"    Gap Details (first 10):\n")
            for gap in gaps[:10]:
                f.write(f"      - Gap at handle 0x{gap:X} ({gap})\n")

            if gap_count > 10:
                f.write(f"      ... and {gap_count - 10} more gaps\n")

            # Interpretation
            if gap_count > 100:
                f.write("    [INTERPRETATION] Extensive deletion - significant content removed\n")
            elif gap_count > 50:
                f.write("    [INTERPRETATION] Moderate deletion - multiple objects removed\n")
            elif gap_count > 10:
                f.write("    [INTERPRETATION] Minor deletion - some objects removed\n")

        # Pattern analysis across folders
        f.write("\n\nPATTERN ANALYSIS - HANDLE GAPS BY FOLDER\n")
        f.write("-" * 80 + "\n")

        folder_gaps: Dict[str, List[int]] = defaultdict(list)
        for filename, gap_count, _, _ in files_with_gaps:
            # Extract folder from filename
            if "2022 Drawing Files" in filename:
                folder_gaps["2022 Drawing Files"].append(gap_count)
            elif "2021 Initial Permit" in filename:
                folder_gaps["2021 Initial Permit"].append(gap_count)
            else:
                folder_gaps["Other"].append(gap_count)

        for folder, gap_counts in sorted(folder_gaps.items(), key=lambda x: sum(x[1]), reverse=True):
            total = sum(gap_counts)
            avg = total / len(gap_counts) if gap_counts else 0
            f.write(f"\n{folder}:\n")
            f.write(f"  Files with Gaps: {len(gap_counts)}\n")
            f.write(f"  Total Gaps: {total}\n")
            f.write(f"  Average Gaps per File: {avg:.1f}\n")

        # Litigation recommendations
        f.write("\n\nLITIGATION RECOMMENDATIONS\n")
        f.write("-" * 80 + "\n")
        f.write("1. Depose defendant regarding deleted objects:\n")
        f.write("   - What objects were deleted and why?\n")
        f.write("   - When were deletions made?\n")
        f.write("   - Were deletions made in anticipation of litigation?\n\n")

        f.write("2. Cross-reference handle gaps with deposition testimony:\n")
        f.write("   - Defendant claims drawings are 'original' or 'unmodified'\n")
        f.write("   - Handle gaps prove modification occurred\n\n")

        f.write("3. Expert witness testimony:\n")
        f.write("   - Handle gap analysis demonstrates spoliation of evidence\n")
        f.write("   - Coordinated deletion pattern suggests intentional concealment\n\n")

    logger.info(f"Handle gap analysis complete: {report_path}")
    return report_path


def generate_application_fingerprint_report(batch_result: BatchAnalysisResult, output_dir: Path) -> Path:
    """Generate application fingerprinting report.

    Identifies which CAD application created/modified each DWG file.
    This can reveal use of non-AutoCAD tools (ODA, BricsCAD, NanoCAD) which
    may indicate file manipulation.

    Args:
        batch_result: BatchAnalysisResult from forensic sweep
        output_dir: Output directory for report

    Returns:
        Path to generated report
    """
    report_path = output_dir / "APPLICATION_FINGERPRINT_REPORT.txt"
    logger.info(f"Generating application fingerprint report: {report_path}")

    # Collect application fingerprints
    app_counts: Dict[str, int] = defaultdict(int)
    app_files: Dict[str, List[tuple]] = defaultdict(list)

    for analysis in batch_result.results:
        app_name = "Unknown"
        confidence = 0.0

        if analysis.application_fingerprint:
            app_name = analysis.application_fingerprint.detected_application
            confidence = analysis.application_fingerprint.confidence

        app_counts[app_name] += 1
        app_files[app_name].append((analysis.file_info.filename, confidence, analysis))

    # Write report
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("APPLICATION FINGERPRINT REPORT - CAD TOOL IDENTIFICATION\n")
        f.write("=" * 80 + "\n")
        f.write(f"Case: {CASE_ID} - Kara Murphy vs Danny Garcia\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Examiner: {EXAMINER}\n")
        f.write("=" * 80 + "\n\n")

        f.write("EXECUTIVE SUMMARY\n")
        f.write("-" * 80 + "\n")
        f.write(f"Total Files Analyzed: {batch_result.total_files}\n\n")

        f.write("Application Distribution:\n")
        for app, count in sorted(app_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / batch_result.total_files * 100) if batch_result.total_files > 0 else 0
            f.write(f"  {app:30s} : {count:3d} files ({percentage:5.1f}%)\n")

        # Forensic significance
        f.write("\n\nFORENSIC SIGNIFICANCE\n")
        f.write("-" * 80 + "\n")
        f.write("Application fingerprinting reveals which CAD software created or modified\n")
        f.write("each DWG file. This is forensically significant because:\n\n")

        f.write("1. AutoCAD vs ODA/BricsCAD/NanoCAD:\n")
        f.write("   - Genuine AutoCAD files have specific binary signatures\n")
        f.write("   - ODA FileConverter and clone applications leave different signatures\n")
        f.write("   - Use of converters may indicate file manipulation\n\n")

        f.write("2. Version Consistency:\n")
        f.write("   - Files from same project should use same application\n")
        f.write("   - Mixed applications suggest post-processing or conversion\n\n")

        f.write("3. Spoliation Indicators:\n")
        f.write("   - Defendant claims 'original AutoCAD files'\n")
        f.write("   - Detection of converter tools contradicts testimony\n\n")

        # Detailed findings by application
        f.write("\nDETAILED FINDINGS BY APPLICATION\n")
        f.write("-" * 80 + "\n")

        for app in sorted(app_counts.keys(), key=lambda x: app_counts[x], reverse=True):
            files = app_files[app]
            f.write(f"\n{app.upper()} ({len(files)} files)\n")
            f.write("-" * 80 + "\n")

            # Show first 20 files
            for filename, confidence, analysis in files[:20]:
                f.write(f"  - {filename}\n")
                f.write(f"      Confidence: {confidence:.2f}\n")
                f.write(f"      DWG Version: {analysis.header_analysis.version_name}\n")
                f.write(f"      Risk Level: {analysis.risk_assessment.overall_risk.value}\n")

            if len(files) > 20:
                f.write(f"  ... and {len(files) - 20} more files\n")

        # Litigation recommendations
        f.write("\n\nLITIGATION RECOMMENDATIONS\n")
        f.write("-" * 80 + "\n")
        f.write("1. Deposition questions regarding CAD software:\n")
        f.write("   - What CAD software did you use to create drawings?\n")
        f.write("   - Did you use any file conversion tools?\n")
        f.write("   - Did you use ODA FileConverter, BricsCAD, or NanoCAD?\n\n")

        f.write("2. Compare fingerprints to defendant testimony:\n")
        f.write("   - Defendant claims 'created in AutoCAD'\n")
        f.write("   - Fingerprint reveals use of conversion tools\n\n")

        f.write("3. Expert witness testimony:\n")
        f.write("   - Application fingerprinting is forensically sound\n")
        f.write("   - Detection of converters indicates file manipulation\n\n")

    logger.info(f"Application fingerprint report complete: {report_path}")
    return report_path


def generate_dwg_vs_revit_timeline(batch_result: BatchAnalysisResult, output_dir: Path) -> Path:
    """Generate DWG vs Revit timeline correlation analysis.

    Correlates DWG file timestamps with Revit model timestamps to detect
    temporal inconsistencies and workflow anomalies.

    Args:
        batch_result: BatchAnalysisResult from forensic sweep
        output_dir: Output directory for report

    Returns:
        Path to generated report
    """
    report_path = output_dir / "DWG_vs_REVIT_TIMELINE.txt"
    logger.info(f"Generating DWG vs Revit timeline: {report_path}")

    # Collect DWG timestamps
    dwg_timeline: List[tuple] = []

    for analysis in batch_result.results:
        # Extract TDCREATE and TDUPDATE timestamps from metadata
        tdcreate = None
        tdupdate = None

        if analysis.metadata:
            if hasattr(analysis.metadata, 'tdcreate') and analysis.metadata.tdcreate:
                tdcreate = analysis.metadata.tdcreate
            if hasattr(analysis.metadata, 'tdupdate') and analysis.metadata.tdupdate:
                tdupdate = analysis.metadata.tdupdate

        # Get NTFS timestamps
        ntfs_created = None
        ntfs_modified = None
        if analysis.ntfs_analysis:
            ntfs_created = analysis.ntfs_analysis.si_created
            ntfs_modified = analysis.ntfs_analysis.si_modified

        dwg_timeline.append({
            'filename': analysis.file_info.filename,
            'tdcreate': tdcreate,
            'tdupdate': tdupdate,
            'ntfs_created': ntfs_created,
            'ntfs_modified': ntfs_modified,
            'dwg_version': analysis.header_analysis.version_name,
            'risk_level': analysis.risk_assessment.overall_risk.value
        })

    # Find Revit files (if any in case directory)
    revit_files = list(CASE_ROOT.glob("**/*.rvt"))
    logger.info(f"Found {len(revit_files)} Revit files for correlation")

    # Write report
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("DWG vs REVIT TIMELINE CORRELATION ANALYSIS\n")
        f.write("=" * 80 + "\n")
        f.write(f"Case: {CASE_ID} - Kara Murphy vs Danny Garcia\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Examiner: {EXAMINER}\n")
        f.write("=" * 80 + "\n\n")

        f.write("EXECUTIVE SUMMARY\n")
        f.write("-" * 80 + "\n")
        f.write(f"DWG Files Analyzed: {len(dwg_timeline)}\n")
        f.write(f"Revit Files Found: {len(revit_files)}\n\n")

        # DWG timestamp analysis
        f.write("\nDWG TIMESTAMP ANALYSIS\n")
        f.write("-" * 80 + "\n")

        dwg_with_tdcreate = sum(1 for x in dwg_timeline if x['tdcreate'] is not None)
        dwg_with_tdupdate = sum(1 for x in dwg_timeline if x['tdupdate'] is not None)

        f.write(f"Files with TDCREATE: {dwg_with_tdcreate}/{len(dwg_timeline)} ")
        f.write(f"({dwg_with_tdcreate/len(dwg_timeline)*100:.1f}%)\n")

        f.write(f"Files with TDUPDATE: {dwg_with_tdupdate}/{len(dwg_timeline)} ")
        f.write(f"({dwg_with_tdupdate/len(dwg_timeline)*100:.1f}%)\n\n")

        # Timestamp destruction analysis
        destroyed_count = len(dwg_timeline) - dwg_with_tdcreate
        if destroyed_count > 0:
            f.write(f"[FINDING] {destroyed_count} files show timestamp destruction.\n")
            f.write("This prevents accurate timeline reconstruction and suggests spoliation.\n\n")

        # DWG files with timestamps (for timeline)
        f.write("\nDWG FILES WITH TIMESTAMPS (chronological)\n")
        f.write("-" * 80 + "\n")

        # Sort by TDCREATE (if available)
        timeline_sorted = [x for x in dwg_timeline if x['tdcreate'] is not None]
        timeline_sorted.sort(key=lambda x: x['tdcreate'])

        for entry in timeline_sorted[:30]:  # First 30
            f.write(f"\n{entry['filename']}\n")
            f.write(f"  TDCREATE: {entry['tdcreate']}\n")
            f.write(f"  TDUPDATE: {entry['tdupdate']}\n")
            if entry['ntfs_created']:
                f.write(f"  NTFS Created: {entry['ntfs_created']}\n")
            if entry['ntfs_modified']:
                f.write(f"  NTFS Modified: {entry['ntfs_modified']}\n")

        if len(timeline_sorted) > 30:
            f.write(f"\n... and {len(timeline_sorted) - 30} more files with timestamps\n")

        # DWG files WITHOUT timestamps
        f.write("\n\nDWG FILES WITHOUT TIMESTAMPS (SPOLIATION EVIDENCE)\n")
        f.write("-" * 80 + "\n")

        destroyed = [x for x in dwg_timeline if x['tdcreate'] is None or x['tdupdate'] is None]
        for entry in destroyed[:30]:  # First 30
            f.write(f"  - {entry['filename']}\n")
            f.write(f"      TDCREATE: {'DESTROYED' if entry['tdcreate'] is None else 'Present'}\n")
            f.write(f"      TDUPDATE: {'DESTROYED' if entry['tdupdate'] is None else 'Present'}\n")

        if len(destroyed) > 30:
            f.write(f"\n... and {len(destroyed) - 30} more files with destroyed timestamps\n")

        # Revit correlation (if files found)
        if revit_files:
            f.write("\n\nREVIT FILE CORRELATION\n")
            f.write("-" * 80 + "\n")
            f.write("Revit files found in case directory:\n")
            for rvt_path in revit_files:
                f.write(f"  - {rvt_path.name}\n")
                # Get NTFS timestamps
                if rvt_path.exists():
                    stat = rvt_path.stat()
                    f.write(f"      NTFS Created: {datetime.fromtimestamp(stat.st_ctime)}\n")
                    f.write(f"      NTFS Modified: {datetime.fromtimestamp(stat.st_mtime)}\n")

            f.write("\n[ANALYSIS REQUIRED] Manual correlation of Revit and DWG timelines\n")
            f.write("to detect workflow inconsistencies.\n")

        # Litigation recommendations
        f.write("\n\nLITIGATION RECOMMENDATIONS\n")
        f.write("-" * 80 + "\n")
        f.write("1. Timeline Reconstruction:\n")
        f.write("   - Use remaining timestamps to establish creation timeline\n")
        f.write("   - Identify temporal gaps and anomalies\n\n")

        f.write("2. Spoliation Argument:\n")
        f.write(f"   - {destroyed_count} files show timestamp destruction\n")
        f.write("   - Timestamp destruction prevents timeline verification\n")
        f.write("   - Request adverse inference for destroyed evidence\n\n")

        f.write("3. Deposition Questions:\n")
        f.write("   - When were DWG files created from Revit model?\n")
        f.write("   - Why are timestamps missing from DWG files?\n")
        f.write("   - Did you use any timestamp modification tools?\n\n")

    logger.info(f"DWG vs Revit timeline complete: {report_path}")
    return report_path


def main():
    """Generate all specialized forensic reports.

    Note: This script requires the batch_result from forensic_sweep_153_dwg.py
    In production, this should be integrated into the main sweep script or
    load the JSON export.
    """
    logger.info("=" * 80)
    logger.info("GENERATING SPECIALIZED FORENSIC REPORTS")
    logger.info("=" * 80)

    # For standalone use, this would load the JSON export
    # For now, this is designed to be called from the main sweep script
    logger.info("This module should be imported and called from forensic_sweep_153_dwg.py")
    logger.info("See forensic_sweep_153_dwg.py for integration.")


if __name__ == "__main__":
    main()
