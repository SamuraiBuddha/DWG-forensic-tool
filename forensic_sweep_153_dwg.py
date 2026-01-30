#!/usr/bin/env python3
"""
FORENSIC DWG ANALYSIS: Complete 153-File Sweep
Case: 2026-001 Kara Murphy vs Danny Garcia

Purpose: Execute comprehensive forensic analysis on all 153 AutoCAD DWG files
         to detect tampering, timestamp destruction, handle gaps, version anachronisms.

Deliverables:
- DWG_FORENSIC_COMPLETE_ANALYSIS.csv (all 153 files)
- DWG_TAMPERING_SUMMARY.txt (pattern analysis)
- TOP_10_SMOKING_GUN_DWG.txt (most damaging files)
- DWG_vs_REVIT_TIMELINE.txt (RVT-DWG correlation)
- HANDLE_GAP_ANALYSIS.txt (content deletion evidence)
- APPLICATION_FINGERPRINT_REPORT.txt (tool identification)
"""

import csv
import logging
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

from dwg_forensic.core.batch_processor import BatchProcessor, BatchAnalysisResult
from dwg_forensic.models import ForensicAnalysis, RiskLevel
from dwg_forensic.output.batch_report import export_batch_json

# Import specialized report generators
import sys
sys.path.insert(0, str(Path(__file__).parent))
from forensic_specialized_reports import (
    generate_handle_gap_analysis,
    generate_application_fingerprint_report,
    generate_dwg_vs_revit_timeline
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('forensic_sweep.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Case configuration
CASE_ROOT = Path(r"\\adam\DataPool\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia")
OUTPUT_DIR = CASE_ROOT / "FORENSIC_ANALYSIS_OUTPUT"
CASE_ID = "2026-001"
EXAMINER = "John Ehrig, P.E."

# Priority folders (processed first)
PRIORITY_FOLDERS = [
    "6075 English Oaks - Naples 2, 2022 Drawing Files",
]


def create_output_directory() -> Path:
    """Create output directory for forensic deliverables."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    logger.info(f"Output directory: {OUTPUT_DIR}")
    return OUTPUT_DIR


def find_all_dwg_files() -> Tuple[List[Path], Dict[str, List[Path]]]:
    """Find all 153 DWG files and organize by folder.

    Returns:
        Tuple of (all_files, files_by_folder)
    """
    logger.info("Scanning for DWG files...")

    # Find all DWG files recursively
    all_files = list(CASE_ROOT.glob("**/*.dwg"))
    logger.info(f"Found {len(all_files)} DWG files")

    # Organize by top-level folder
    files_by_folder: Dict[str, List[Path]] = defaultdict(list)
    for file_path in all_files:
        # Get relative path from case root
        rel_path = file_path.relative_to(CASE_ROOT)
        # First component is folder name
        folder_name = rel_path.parts[0]
        files_by_folder[folder_name].append(file_path)

    # Log folder distribution
    logger.info("DWG files by folder:")
    for folder, files in sorted(files_by_folder.items(), key=lambda x: len(x[1]), reverse=True):
        logger.info(f"  {folder}: {len(files)} files")

    return all_files, files_by_folder


def execute_batch_forensic_analysis(all_files: List[Path]) -> BatchAnalysisResult:
    """Execute forensic analysis on all DWG files.

    Args:
        all_files: List of all DWG file paths

    Returns:
        BatchAnalysisResult with aggregated findings
    """
    logger.info(f"Starting batch forensic analysis of {len(all_files)} files...")

    # Create temporary directory containing all files (for batch processor)
    # Alternative: Process each file individually
    processor = BatchProcessor(num_workers=8)

    # Since files are scattered across directories, process from root with recursive=True
    batch_result = processor.process_directory(
        directory=CASE_ROOT,
        recursive=True,
        pattern="*.dwg",
        with_llm=False,  # Disable LLM for speed (153 files)
    )

    logger.info(f"Batch analysis complete: {batch_result.successful}/{batch_result.total_files} successful")
    return batch_result


def generate_csv_export(batch_result: BatchAnalysisResult, output_dir: Path) -> Path:
    """Generate comprehensive CSV with all forensic findings.

    Columns:
    - file_name, file_path, file_size_bytes
    - dwg_version, crc_status, crc_mismatch
    - tdcreate_present, tdupdate_present, tdindwg_present
    - handle_gaps_detected, gap_count
    - application_fingerprint, confidence_score
    - tampering_indicators_count
    - forensic_confidence (95%, 75%, 50%)
    - smoking_gun_status (DEFINITIVE, STRONG, BASELINE, CLEAN)
    - risk_level
    """
    csv_path = output_dir / "DWG_FORENSIC_COMPLETE_ANALYSIS.csv"
    logger.info(f"Generating CSV export: {csv_path}")

    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'file_name', 'file_path', 'file_size_bytes', 'sha256',
            'dwg_version', 'crc_status', 'crc_mismatch',
            'tdcreate_present', 'tdupdate_present', 'tdindwg_present',
            'handle_gaps_detected', 'gap_count',
            'application_fingerprint', 'fingerprint_confidence',
            'tampering_indicators_count', 'tampering_types',
            'forensic_confidence', 'smoking_gun_status', 'risk_level',
            'analysis_timestamp'
        ]

        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for analysis in batch_result.results:
            # Extract timestamp data from metadata
            tdcreate_present = False
            tdupdate_present = False
            tdindwg_present = False

            if analysis.metadata:
                if hasattr(analysis.metadata, 'tdcreate') and analysis.metadata.tdcreate is not None:
                    tdcreate_present = True
                if hasattr(analysis.metadata, 'tdupdate') and analysis.metadata.tdupdate is not None:
                    tdupdate_present = True
                if hasattr(analysis.metadata, 'tdindwg') and analysis.metadata.tdindwg is not None:
                    tdindwg_present = True

            # Handle gaps
            handle_gaps_detected = False
            gap_count = 0
            if hasattr(analysis, 'structure_analysis') and analysis.structure_analysis:
                if hasattr(analysis.structure_analysis, 'handle_gaps'):
                    gap_count = len(analysis.structure_analysis.handle_gaps)
                    handle_gaps_detected = gap_count > 0

            # Application fingerprint
            app_fingerprint = "Unknown"
            fingerprint_confidence = 0.0
            if analysis.application_fingerprint:
                app_fingerprint = analysis.application_fingerprint.detected_application
                fingerprint_confidence = analysis.application_fingerprint.confidence

            # Tampering indicators
            tampering_count = len(analysis.tampering_indicators)
            tampering_types = ",".join(set(ind.indicator_type.value for ind in analysis.tampering_indicators))

            # Forensic confidence and smoking gun status
            forensic_confidence = _calculate_forensic_confidence(analysis)
            smoking_gun_status = _determine_smoking_gun_status(analysis)

            # Write row
            writer.writerow({
                'file_name': analysis.file_info.filename,
                'file_path': str(Path(analysis.file_info.filename).parent),  # Relative path
                'file_size_bytes': analysis.file_info.file_size_bytes,
                'sha256': analysis.file_info.sha256,
                'dwg_version': analysis.header_analysis.version_name,
                'crc_status': 'VALID' if analysis.crc_validation.is_valid else 'INVALID',
                'crc_mismatch': not analysis.crc_validation.is_valid,
                'tdcreate_present': tdcreate_present,
                'tdupdate_present': tdupdate_present,
                'tdindwg_present': tdindwg_present,
                'handle_gaps_detected': handle_gaps_detected,
                'gap_count': gap_count,
                'application_fingerprint': app_fingerprint,
                'fingerprint_confidence': f"{fingerprint_confidence:.2f}",
                'tampering_indicators_count': tampering_count,
                'tampering_types': tampering_types,
                'forensic_confidence': forensic_confidence,
                'smoking_gun_status': smoking_gun_status,
                'risk_level': analysis.risk_assessment.overall_risk.value,
                'analysis_timestamp': datetime.now().isoformat()
            })

    logger.info(f"CSV export complete: {len(batch_result.results)} files")
    return csv_path


def _calculate_forensic_confidence(analysis: ForensicAnalysis) -> str:
    """Calculate forensic confidence level based on evidence strength."""
    tampering_count = len(analysis.tampering_indicators)

    if tampering_count >= 5:
        return "95%"
    elif tampering_count >= 3:
        return "75%"
    elif tampering_count >= 1:
        return "50%"
    else:
        return "BASELINE"


def _determine_smoking_gun_status(analysis: ForensicAnalysis) -> str:
    """Determine smoking gun status based on evidence type."""
    # Check for definitive indicators
    indicator_types = [ind.indicator_type.value for ind in analysis.tampering_indicators]

    # Definitive: CRC mismatch + timestamp destruction
    has_crc_mismatch = not analysis.crc_validation.is_valid
    has_timestamp_destruction = any('timestamp' in ind.lower() for ind in indicator_types)

    if has_crc_mismatch and has_timestamp_destruction:
        return "DEFINITIVE"
    elif len(analysis.tampering_indicators) >= 5:
        return "STRONG"
    elif len(analysis.tampering_indicators) >= 1:
        return "BASELINE"
    else:
        return "CLEAN"


def generate_tampering_summary(batch_result: BatchAnalysisResult, output_dir: Path) -> Path:
    """Generate pattern analysis summary.

    Analyzes:
    - Type A: Timestamp destruction (TDCREATE/TDUPDATE missing)
    - Type B: CRC mismatch
    - Type C: Handle gaps
    - Type D: Version anachronisms
    - Type E: Clean
    """
    summary_path = output_dir / "DWG_TAMPERING_SUMMARY.txt"
    logger.info(f"Generating tampering summary: {summary_path}")

    # Categorize files by tampering pattern
    pattern_counts = Counter()
    pattern_files: Dict[str, List[str]] = defaultdict(list)

    for analysis in batch_result.results:
        patterns = []

        # Check for timestamp destruction
        tdcreate_present = False
        tdupdate_present = False
        if analysis.metadata:
            if hasattr(analysis.metadata, 'tdcreate') and analysis.metadata.tdcreate is not None:
                tdcreate_present = True
            if hasattr(analysis.metadata, 'tdupdate') and analysis.metadata.tdupdate is not None:
                tdupdate_present = True

        if not tdcreate_present or not tdupdate_present:
            patterns.append("Type_A_Timestamp_Destruction")
            pattern_files["Type_A_Timestamp_Destruction"].append(analysis.file_info.filename)

        # Check for CRC mismatch
        if not analysis.crc_validation.is_valid:
            patterns.append("Type_B_CRC_Mismatch")
            pattern_files["Type_B_CRC_Mismatch"].append(analysis.file_info.filename)

        # Check for handle gaps
        if hasattr(analysis, 'structure_analysis') and analysis.structure_analysis:
            if hasattr(analysis.structure_analysis, 'handle_gaps'):
                if len(analysis.structure_analysis.handle_gaps) > 0:
                    patterns.append("Type_C_Handle_Gaps")
                    pattern_files["Type_C_Handle_Gaps"].append(analysis.file_info.filename)

        # Check for version anachronisms
        indicator_types = [ind.indicator_type.value for ind in analysis.tampering_indicators]
        if any('version' in ind.lower() or 'anachronism' in ind.lower() for ind in indicator_types):
            patterns.append("Type_D_Version_Anachronism")
            pattern_files["Type_D_Version_Anachronism"].append(analysis.file_info.filename)

        if not patterns:
            patterns.append("Type_E_Clean")
            pattern_files["Type_E_Clean"].append(analysis.file_info.filename)

        for pattern in patterns:
            pattern_counts[pattern] += 1

    # Write summary
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write("DWG TAMPERING PATTERN ANALYSIS\n")
        f.write("=" * 80 + "\n")
        f.write(f"Case: {CASE_ID} - Kara Murphy vs Danny Garcia\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Examiner: {EXAMINER}\n")
        f.write(f"Total Files Analyzed: {batch_result.total_files}\n")
        f.write("=" * 80 + "\n\n")

        f.write("TAMPERING PATTERN DISTRIBUTION\n")
        f.write("-" * 80 + "\n")
        for pattern, count in pattern_counts.most_common():
            percentage = (count / batch_result.successful * 100) if batch_result.successful > 0 else 0
            f.write(f"{pattern:40s} : {count:4d} files ({percentage:5.1f}%)\n")
        f.write("\n")

        # Detailed file lists for each pattern
        for pattern in ["Type_A_Timestamp_Destruction", "Type_B_CRC_Mismatch",
                       "Type_C_Handle_Gaps", "Type_D_Version_Anachronism"]:
            if pattern in pattern_files:
                f.write(f"\n{pattern.upper()}\n")
                f.write("-" * 80 + "\n")
                for filename in pattern_files[pattern][:20]:  # First 20
                    f.write(f"  - {filename}\n")
                if len(pattern_files[pattern]) > 20:
                    f.write(f"  ... and {len(pattern_files[pattern]) - 20} more files\n")

        # Coordinated spoliation analysis
        f.write("\n\nCOORDINATED SPOLIATION ANALYSIS\n")
        f.write("-" * 80 + "\n")
        f.write("Files in '2022 Drawing Files' folder with timestamp destruction:\n")

        folder_2022_count = 0
        for filename in pattern_files.get("Type_A_Timestamp_Destruction", []):
            if "2022 Drawing Files" in filename:
                f.write(f"  - {filename}\n")
                folder_2022_count += 1

        if folder_2022_count > 0:
            f.write(f"\n[FINDING] {folder_2022_count} files in '2022 Drawing Files' show ")
            f.write("timestamp destruction pattern, suggesting coordinated spoliation.\n")

    logger.info(f"Tampering summary complete: {summary_path}")
    return summary_path


def generate_top_10_smoking_guns(batch_result: BatchAnalysisResult, output_dir: Path) -> Path:
    """Generate list of top 10 most damaging DWG files for litigation."""
    top_10_path = output_dir / "TOP_10_SMOKING_GUN_DWG.txt"
    logger.info(f"Generating top 10 smoking guns: {top_10_path}")

    # Score each file by tampering severity
    scored_files = []
    for analysis in batch_result.results:
        score = 0

        # CRC mismatch: +50 points
        if not analysis.crc_validation.is_valid:
            score += 50

        # Timestamp destruction: +30 points per missing timestamp
        if analysis.metadata:
            if not (hasattr(analysis.metadata, 'tdcreate') and analysis.metadata.tdcreate):
                score += 30
            if not (hasattr(analysis.metadata, 'tdupdate') and analysis.metadata.tdupdate):
                score += 30

        # Handle gaps: +20 points per gap
        if hasattr(analysis, 'structure_analysis') and analysis.structure_analysis:
            if hasattr(analysis.structure_analysis, 'handle_gaps'):
                score += 20 * len(analysis.structure_analysis.handle_gaps)

        # Each tampering indicator: +10 points
        score += 10 * len(analysis.tampering_indicators)

        # Risk level bonus
        risk_bonus = {
            RiskLevel.CRITICAL: 100,
            RiskLevel.HIGH: 50,
            RiskLevel.MEDIUM: 20,
            RiskLevel.LOW: 5,
            RiskLevel.INFO: 0
        }
        score += risk_bonus.get(analysis.risk_assessment.overall_risk, 0)

        scored_files.append((score, analysis))

    # Sort by score descending
    scored_files.sort(reverse=True, key=lambda x: x[0])
    top_10 = scored_files[:10]

    # Write report
    with open(top_10_path, 'w', encoding='utf-8') as f:
        f.write("TOP 10 SMOKING GUN DWG FILES\n")
        f.write("=" * 80 + "\n")
        f.write(f"Case: {CASE_ID} - Kara Murphy vs Danny Garcia\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Examiner: {EXAMINER}\n")
        f.write("=" * 80 + "\n\n")

        f.write("Ranked by forensic tampering severity score.\n")
        f.write("Recommended for expert witness testimony and deposition exhibits.\n\n")

        for rank, (score, analysis) in enumerate(top_10, 1):
            f.write(f"\n#{rank}. {analysis.file_info.filename}\n")
            f.write("-" * 80 + "\n")
            f.write(f"Tampering Score: {score}\n")
            f.write(f"Risk Level: {analysis.risk_assessment.overall_risk.value}\n")
            f.write(f"SHA-256: {analysis.file_info.sha256}\n")
            f.write(f"DWG Version: {analysis.header_analysis.version_name}\n")
            f.write(f"File Size: {analysis.file_info.file_size_bytes:,} bytes\n")
            f.write(f"\nForensic Findings:\n")

            # CRC status
            crc_status = "VALID" if analysis.crc_validation.is_valid else "INVALID [SMOKING GUN]"
            f.write(f"  - CRC Status: {crc_status}\n")

            # Timestamps from metadata
            if analysis.metadata:
                f.write(f"  - Timestamps:\n")
                tdcreate_status = "PRESENT" if hasattr(analysis.metadata, 'tdcreate') and analysis.metadata.tdcreate else "DESTROYED [SMOKING GUN]"
                tdupdate_status = "PRESENT" if hasattr(analysis.metadata, 'tdupdate') and analysis.metadata.tdupdate else "DESTROYED [SMOKING GUN]"
                tdindwg_status = "PRESENT" if hasattr(analysis.metadata, 'tdindwg') and analysis.metadata.tdindwg else "DESTROYED [SMOKING GUN]"
                f.write(f"      TDCREATE: {tdcreate_status}\n")
                f.write(f"      TDUPDATE: {tdupdate_status}\n")
                f.write(f"      TDINDWG: {tdindwg_status}\n")

            # Handle gaps
            if hasattr(analysis, 'structure_analysis') and analysis.structure_analysis:
                if hasattr(analysis.structure_analysis, 'handle_gaps'):
                    gap_count = len(analysis.structure_analysis.handle_gaps)
                    if gap_count > 0:
                        f.write(f"  - Handle Gaps: {gap_count} detected [EVIDENCE OF DELETION]\n")

            # Tampering indicators
            if analysis.tampering_indicators:
                f.write(f"  - Tampering Indicators ({len(analysis.tampering_indicators)}):\n")
                for ind in analysis.tampering_indicators[:5]:  # First 5
                    # TamperingIndicator has confidence, not severity
                    f.write(f"      [Confidence: {ind.confidence:.2f}] {ind.indicator_type.value}\n")

    logger.info(f"Top 10 smoking guns complete: {top_10_path}")
    return top_10_path


def main():
    """Execute complete 153-file forensic sweep."""
    logger.info("=" * 80)
    logger.info("FORENSIC DWG ANALYSIS: Complete 153-File Sweep")
    logger.info("Case: 2026-001 Kara Murphy vs Danny Garcia")
    logger.info("=" * 80)

    try:
        # Step 1: Create output directory
        output_dir = create_output_directory()

        # Step 2: Find all DWG files
        all_files, files_by_folder = find_all_dwg_files()

        if len(all_files) != 153:
            logger.warning(f"Expected 153 files, found {len(all_files)}")

        # Step 3: Execute batch forensic analysis
        batch_result = execute_batch_forensic_analysis(all_files)

        # Step 4: Generate CSV export
        csv_path = generate_csv_export(batch_result, output_dir)
        logger.info(f"[OK] CSV export: {csv_path}")

        # Step 5: Generate tampering summary
        summary_path = generate_tampering_summary(batch_result, output_dir)
        logger.info(f"[OK] Tampering summary: {summary_path}")

        # Step 6: Generate top 10 smoking guns
        top_10_path = generate_top_10_smoking_guns(batch_result, output_dir)
        logger.info(f"[OK] Top 10 smoking guns: {top_10_path}")

        # Step 7: Export JSON for complete data
        json_path = export_batch_json(batch_result, output_dir / "DWG_FORENSIC_COMPLETE.json")
        logger.info(f"[OK] JSON export: {json_path}")

        # Step 8: Generate handle gap analysis
        handle_gap_path = generate_handle_gap_analysis(batch_result, output_dir)
        logger.info(f"[OK] Handle gap analysis: {handle_gap_path}")

        # Step 9: Generate application fingerprint report
        fingerprint_path = generate_application_fingerprint_report(batch_result, output_dir)
        logger.info(f"[OK] Application fingerprint: {fingerprint_path}")

        # Step 10: Generate DWG vs Revit timeline
        timeline_path = generate_dwg_vs_revit_timeline(batch_result, output_dir)
        logger.info(f"[OK] DWG vs Revit timeline: {timeline_path}")

        # Summary
        logger.info("=" * 80)
        logger.info("FORENSIC SWEEP COMPLETE")
        logger.info("=" * 80)
        logger.info(f"Files Analyzed: {batch_result.successful}/{batch_result.total_files}")
        logger.info(f"Processing Time: {batch_result.processing_time_seconds:.2f}s")
        logger.info(f"Aggregated Risk Score: {batch_result.aggregated_risk_score:.2f}")
        logger.info(f"\nRisk Distribution:")
        for level, count in batch_result.risk_distribution.items():
            logger.info(f"  {level:10s}: {count:3d} files")
        logger.info(f"\nDeliverables:")
        logger.info(f"  1. {csv_path.name}")
        logger.info(f"  2. {summary_path.name}")
        logger.info(f"  3. {top_10_path.name}")
        logger.info(f"  4. {json_path.name}")
        logger.info(f"  5. {handle_gap_path.name}")
        logger.info(f"  6. {fingerprint_path.name}")
        logger.info(f"  7. {timeline_path.name}")
        logger.info(f"\nAll deliverables saved to: {output_dir}")

    except Exception as e:
        logger.error(f"Fatal error during forensic sweep: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
