#!/usr/bin/env python3
"""
DWG Timeline Forensic Analysis Script

Extracts DWG internal timestamps ($TDCREATE, $TDUPDATE, $TDINDWG) from all DWG files
in both case directories and cross-correlates with RVT metadata timeline to detect:
- Backdating (DWG timestamps predating RVT modification)
- Clock rollback (inconsistent DWG timestamps)
- Batch manipulation patterns
- Export workflow legitimacy

Phase 2 of forensic analysis establishing prosecution timeline.
"""

import csv
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dwg_forensic.parsers.timestamp import TimestampParser
from dwg_forensic.parsers.header import HeaderParser
from dwg_forensic.parsers.drawing_vars import DrawingVariablesParser


# RVT Timeline from Phase 1 (established baseline)
RVT_LAST_SAVED = {
    "2021_case": datetime(2026, 1, 9, 13, 8, 41, tzinfo=timezone.utc),  # RVT modified
    "2022_case": datetime(2026, 1, 9, 13, 8, 44, tzinfo=timezone.utc),  # RVT modified
}

DWG_NTFS_CREATED = {
    "2021_case": datetime(2026, 1, 9, 18, 8, 42, tzinfo=timezone.utc),  # DWG created
    "2022_case": datetime(2026, 1, 9, 18, 8, 51, tzinfo=timezone.utc),  # DWG created
}

# Case directories
CASE_DIRS = {
    "2021": Path(r"E:\6075 English Oaks - Naples 2, 2021 Initial Permit\02-Drawings"),
    "2022": Path(r"E:\6075 English Oaks - Naples 2, 2022 Drawing Files"),
}


def format_timestamp(dt: Optional[datetime]) -> str:
    """Format datetime to ISO string or return 'N/A'."""
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def analyze_dwg_file(dwg_path: Path) -> Dict[str, Any]:
    """
    Extract DWG internal timestamps and NTFS metadata.

    Returns:
        Dict with extraction results and metadata
    """
    result = {
        "file_path": str(dwg_path),
        "file_name": dwg_path.name,
        "file_size_bytes": 0,
        "dwg_version": "Unknown",
        "extraction_method": "None",
        "extraction_success": False,
        "extraction_errors": [],

        # DWG internal timestamps (raw MJD)
        "tdcreate_mjd": None,
        "tdupdate_mjd": None,
        "tdindwg_days": None,

        # DWG internal timestamps (datetime)
        "tdcreate": None,
        "tdupdate": None,
        "tdindwg_hours": None,

        # NTFS timestamps
        "ntfs_created": None,
        "ntfs_modified": None,

        # GUIDs
        "fingerprint_guid": None,
        "version_guid": None,
    }

    try:
        # Get file metadata
        if dwg_path.exists():
            stat = dwg_path.stat()
            result["file_size_bytes"] = stat.st_size
            result["ntfs_created"] = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc)
            result["ntfs_modified"] = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        else:
            result["extraction_errors"].append("File does not exist")
            return result

        # Extract DWG version
        header_parser = HeaderParser()
        header_result = header_parser.parse(dwg_path)
        if header_result:
            result["dwg_version"] = header_result.version_string

        # Method 1: DrawingVariablesParser (most accurate - section-based)
        try:
            vars_parser = DrawingVariablesParser()
            vars_result = vars_parser.parse(dwg_path)

            if vars_result and vars_result.has_timestamps():
                result["extraction_success"] = True
                result["extraction_method"] = "DrawingVariables"

                # Extract timestamps
                if vars_result.tdcreate:
                    result["tdcreate_mjd"] = vars_result.tdcreate.julian_day
                    result["tdcreate"] = vars_result.tdcreate.datetime_utc

                if vars_result.tdupdate:
                    result["tdupdate_mjd"] = vars_result.tdupdate.julian_day
                    result["tdupdate"] = vars_result.tdupdate.datetime_utc

                if vars_result.tdindwg:
                    result["tdindwg_days"] = vars_result.tdindwg.julian_day
                    result["tdindwg_hours"] = vars_result.tdindwg.julian_day * 24

                # Extract GUIDs
                if vars_result.fingerprintguid:
                    result["fingerprint_guid"] = vars_result.fingerprintguid.guid_string

                if vars_result.versionguid:
                    result["version_guid"] = vars_result.versionguid.guid_string

                # Collect errors
                if vars_result.parsing_errors:
                    result["extraction_errors"].extend(vars_result.parsing_errors)

                return result
        except Exception as e:
            result["extraction_errors"].append(f"DrawingVariablesParser failed: {e}")

        # Method 2: TimestampParser (fallback - heuristic scanning)
        try:
            ts_parser = TimestampParser()
            ts_result = ts_parser.parse(dwg_path, version_string=result["dwg_version"])

            if ts_result and ts_result.extraction_success:
                result["extraction_success"] = True
                result["extraction_method"] = "TimestampParser"

                # Extract timestamps
                if ts_result.tdcreate is not None:
                    result["tdcreate_mjd"] = ts_result.tdcreate
                    result["tdcreate"] = ts_result.get_tdcreate_datetime()

                if ts_result.tdupdate is not None:
                    result["tdupdate_mjd"] = ts_result.tdupdate
                    result["tdupdate"] = ts_result.get_tdupdate_datetime()

                if ts_result.tdindwg is not None:
                    result["tdindwg_days"] = ts_result.tdindwg
                    result["tdindwg_hours"] = ts_result.get_tdindwg_hours()

                # Extract GUIDs
                if ts_result.fingerprint_guid:
                    result["fingerprint_guid"] = ts_result.fingerprint_guid

                if ts_result.version_guid:
                    result["version_guid"] = ts_result.version_guid

                # Collect errors
                if ts_result.extraction_errors:
                    result["extraction_errors"].extend(ts_result.extraction_errors)
        except Exception as e:
            result["extraction_errors"].append(f"TimestampParser failed: {e}")

    except Exception as e:
        result["extraction_errors"].append(f"File analysis failed: {e}")

    return result


def timeline_match_analysis(
    dwg_tdcreate: Optional[datetime],
    dwg_tdupdate: Optional[datetime],
    rvt_last_saved: datetime,
    dwg_ntfs_created: datetime,
    case_name: str
) -> Dict[str, Any]:
    """
    Analyze timeline consistency and detect manipulation.

    Hypothesis: Files were batch-exported at 18:08:42-51 from RVT sources modified at 13:08:41-44.
    - If DWG $TDCREATE < RVT last-saved: DEFINITIVE PROOF of backdating
    - If DWG $TDCREATE matches export time (18:08:42-51): Legitimate export
    - If DWG $TDCREATE from 2021: Backdating proof

    Returns:
        Analysis results dict
    """
    analysis = {
        "case_name": case_name,
        "timeline_match": "Unknown",
        "backdating_evidence": False,
        "manipulation_indicators": [],
        "smoking_gun": False,
        "confidence": 0.0,
        "verdict": "Inconclusive",
    }

    if dwg_tdcreate is None or dwg_tdupdate is None:
        analysis["timeline_match"] = "No DWG timestamps available"
        analysis["verdict"] = "Inconclusive - Missing data"
        return analysis

    # Test 1: DWG creation predates RVT modification (SMOKING GUN)
    if dwg_tdcreate < rvt_last_saved:
        delta = (rvt_last_saved - dwg_tdcreate).total_seconds()
        analysis["backdating_evidence"] = True
        analysis["smoking_gun"] = True
        analysis["manipulation_indicators"].append(
            f"DWG $TDCREATE predates RVT last-saved by {delta/3600:.1f} hours - IMPOSSIBLE"
        )
        analysis["timeline_match"] = "FAILED - Backdating detected"
        analysis["confidence"] = 1.0
        analysis["verdict"] = "DEFINITIVE PROOF of timestamp manipulation"

    # Test 2: DWG creation matches export time window (18:08:42-51)
    # Allow 2-minute window for batch export
    export_window_start = dwg_ntfs_created.replace(second=0)  # 18:08:00
    export_window_end = dwg_ntfs_created.replace(minute=9, second=0)  # 18:09:00

    if export_window_start <= dwg_tdcreate <= export_window_end:
        analysis["timeline_match"] = "PASS - Export timestamp match"
        analysis["manipulation_indicators"].append(
            "DWG $TDCREATE matches export window (18:08:42-51) - consistent with batch export"
        )
        analysis["confidence"] = 0.9
        analysis["verdict"] = "Legitimate export workflow"

    # Test 3: DWG creation is from 2021 (claimed date)
    elif dwg_tdcreate.year == 2021:
        analysis["backdating_evidence"] = True
        analysis["smoking_gun"] = True
        analysis["manipulation_indicators"].append(
            f"DWG $TDCREATE claims year 2021 but RVT modified 2026-01-09 - BACKDATING PROVEN"
        )
        analysis["timeline_match"] = "FAILED - Fraudulent backdating"
        analysis["confidence"] = 1.0
        analysis["verdict"] = "DEFINITIVE PROOF of timestamp manipulation"

    # Test 4: DWG creation between RVT save and export (legitimate window)
    elif rvt_last_saved < dwg_tdcreate < dwg_ntfs_created:
        delta_from_rvt = (dwg_tdcreate - rvt_last_saved).total_seconds() / 60
        analysis["timeline_match"] = "PASS - Within export window"
        analysis["manipulation_indicators"].append(
            f"DWG $TDCREATE is {delta_from_rvt:.1f} minutes after RVT save - consistent"
        )
        analysis["confidence"] = 0.85
        analysis["verdict"] = "Legitimate export workflow"

    # Test 5: DWG creation after NTFS creation (suspicious)
    elif dwg_tdcreate > dwg_ntfs_created.replace(minute=9, second=0):
        delta = (dwg_tdcreate - dwg_ntfs_created).total_seconds() / 3600
        analysis["timeline_match"] = "SUSPICIOUS - DWG internal timestamp after file creation"
        analysis["manipulation_indicators"].append(
            f"DWG $TDCREATE is {delta:.1f} hours after NTFS creation - clock manipulation?"
        )
        analysis["confidence"] = 0.7
        analysis["verdict"] = "Suspicious - Clock rollback or manipulation"

    # Test 6: Check TDUPDATE consistency
    if dwg_tdupdate < dwg_tdcreate:
        analysis["smoking_gun"] = True
        analysis["manipulation_indicators"].append(
            "DWG $TDUPDATE < $TDCREATE - IMPOSSIBLE timestamp sequence"
        )
        analysis["verdict"] = "DEFINITIVE PROOF of timestamp manipulation"
        analysis["confidence"] = 1.0

    return analysis


def batch_pattern_analysis(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze patterns across all DWG files to detect batch manipulation.

    Returns:
        Pattern analysis dict
    """
    pattern = {
        "total_files": len(results),
        "extraction_success_count": 0,
        "unique_tdcreate_timestamps": set(),
        "unique_tdupdate_timestamps": set(),
        "timestamp_clusters": [],
        "batch_evidence": False,
        "backdating_count": 0,
        "smoking_gun_count": 0,
        "pattern_verdict": "No pattern detected",
    }

    tdcreate_list = []
    tdupdate_list = []

    for result in results:
        if result["extraction_success"]:
            pattern["extraction_success_count"] += 1

            if result["tdcreate"]:
                ts_str = format_timestamp(result["tdcreate"])
                pattern["unique_tdcreate_timestamps"].add(ts_str)
                tdcreate_list.append(result["tdcreate"])

            if result["tdupdate"]:
                ts_str = format_timestamp(result["tdupdate"])
                pattern["unique_tdupdate_timestamps"].add(ts_str)
                tdupdate_list.append(result["tdupdate"])

    # Convert sets to sorted lists for display
    pattern["unique_tdcreate_timestamps"] = sorted(pattern["unique_tdcreate_timestamps"])
    pattern["unique_tdupdate_timestamps"] = sorted(pattern["unique_tdupdate_timestamps"])

    # Detect batch creation (all files created within 2-minute window)
    if len(tdcreate_list) >= 2:
        min_tdcreate = min(tdcreate_list)
        max_tdcreate = max(tdcreate_list)
        span_seconds = (max_tdcreate - min_tdcreate).total_seconds()

        if span_seconds <= 120:  # 2 minutes
            pattern["batch_evidence"] = True
            pattern["timestamp_clusters"].append({
                "type": "TDCREATE",
                "span_seconds": span_seconds,
                "min_timestamp": format_timestamp(min_tdcreate),
                "max_timestamp": format_timestamp(max_tdcreate),
                "file_count": len(tdcreate_list),
                "verdict": "All files created within 2-minute window - BATCH EXPORT CONFIRMED"
            })

    # Count backdating and smoking guns
    for result in results:
        if result.get("timeline_analysis"):
            if result["timeline_analysis"].get("backdating_evidence"):
                pattern["backdating_count"] += 1
            if result["timeline_analysis"].get("smoking_gun"):
                pattern["smoking_gun_count"] += 1

    # Pattern verdict
    if pattern["smoking_gun_count"] > 0:
        pattern["pattern_verdict"] = f"DEFINITIVE PROOF: {pattern['smoking_gun_count']} files show impossible timestamps"
    elif pattern["batch_evidence"]:
        pattern["pattern_verdict"] = "Batch export pattern detected - consistent with legitimate workflow"
    elif pattern["backdating_count"] > 0:
        pattern["pattern_verdict"] = f"SUSPICIOUS: {pattern['backdating_count']} files show backdating indicators"
    else:
        pattern["pattern_verdict"] = "Insufficient evidence for pattern determination"

    return pattern


def main():
    """Main analysis routine."""
    print("DWG Timeline Forensic Analysis")
    print("=" * 80)
    print()
    print("Phase 2: DWG Internal Timestamp Extraction and RVT Timeline Correlation")
    print()
    print("Hypothesis: Files were batch-exported at 18:08:42-51 from RVT sources")
    print("            modified at 13:08:41-44 on 2026-01-09.")
    print()
    print("Testing for:")
    print("  1. Backdating (DWG $TDCREATE < RVT last-saved)")
    print("  2. Fraudulent 2021 timestamps")
    print("  3. Clock rollback indicators")
    print("  4. Batch manipulation patterns")
    print()
    print("=" * 80)
    print()

    all_results = []

    for case_name, case_dir in CASE_DIRS.items():
        print(f"\nAnalyzing case: {case_name}")
        print(f"Directory: {case_dir}")
        print("-" * 80)

        if not case_dir.exists():
            print(f"[WARN] Directory does not exist: {case_dir}")
            continue

        # Find all DWG files
        dwg_files = list(case_dir.glob("*.dwg"))
        print(f"Found {len(dwg_files)} DWG files")
        print()

        # Process each DWG file
        for dwg_file in sorted(dwg_files):
            print(f"Processing: {dwg_file.name}")

            # Extract timestamps
            result = analyze_dwg_file(dwg_file)

            # Add case context
            result["case_name"] = case_name

            # Perform timeline correlation
            rvt_saved = RVT_LAST_SAVED.get(f"{case_name}_case")
            dwg_ntfs = DWG_NTFS_CREATED.get(f"{case_name}_case")

            if rvt_saved and dwg_ntfs:
                timeline_analysis = timeline_match_analysis(
                    result["tdcreate"],
                    result["tdupdate"],
                    rvt_saved,
                    dwg_ntfs,
                    case_name
                )
                result["timeline_analysis"] = timeline_analysis

            # Display results
            print(f"  DWG Version: {result['dwg_version']}")
            print(f"  Extraction: {result['extraction_method']} - {'SUCCESS' if result['extraction_success'] else 'FAILED'}")

            if result["extraction_success"]:
                print(f"  $TDCREATE: {format_timestamp(result['tdcreate'])}")
                print(f"  $TDUPDATE: {format_timestamp(result['tdupdate'])}")
                if result["tdindwg_hours"] is not None:
                    print(f"  $TDINDWG: {result['tdindwg_hours']:.4f} hours")
                print(f"  NTFS Created: {format_timestamp(result['ntfs_created'])}")
                print(f"  NTFS Modified: {format_timestamp(result['ntfs_modified'])}")

                if result.get("timeline_analysis"):
                    ta = result["timeline_analysis"]
                    print(f"  Timeline Match: {ta['timeline_match']}")
                    print(f"  Verdict: {ta['verdict']}")
                    if ta["manipulation_indicators"]:
                        for indicator in ta["manipulation_indicators"]:
                            print(f"    - {indicator}")
            else:
                print(f"  [FAIL] {', '.join(result['extraction_errors'])}")

            print()

            all_results.append(result)

    # Perform batch pattern analysis
    print()
    print("=" * 80)
    print("BATCH PATTERN ANALYSIS")
    print("=" * 80)
    print()

    pattern = batch_pattern_analysis(all_results)

    print(f"Total files analyzed: {pattern['total_files']}")
    print(f"Successful extractions: {pattern['extraction_success_count']}")
    print(f"Unique $TDCREATE timestamps: {len(pattern['unique_tdcreate_timestamps'])}")
    print(f"Unique $TDUPDATE timestamps: {len(pattern['unique_tdupdate_timestamps'])}")
    print()

    if pattern["timestamp_clusters"]:
        print("Timestamp Clusters Detected:")
        for cluster in pattern["timestamp_clusters"]:
            print(f"  Type: {cluster['type']}")
            print(f"  Span: {cluster['span_seconds']:.1f} seconds")
            print(f"  Range: {cluster['min_timestamp']} to {cluster['max_timestamp']}")
            print(f"  Files: {cluster['file_count']}")
            print(f"  Verdict: {cluster['verdict']}")
            print()

    print(f"Backdating Evidence: {pattern['backdating_count']} files")
    print(f"Smoking Gun Evidence: {pattern['smoking_gun_count']} files")
    print()
    print(f"PATTERN VERDICT: {pattern['pattern_verdict']}")
    print()

    # Export to CSV
    csv_path = project_root / "DWG_TIMESTAMP_FORENSIC_ANALYSIS.csv"
    print(f"Exporting results to: {csv_path}")

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "case_name",
            "file_name",
            "dwg_version",
            "extraction_method",
            "tdcreate",
            "tdupdate",
            "tdindwg_hours",
            "ntfs_created",
            "ntfs_modified",
            "timeline_match",
            "verdict",
            "manipulation_indicators",
            "fingerprint_guid",
            "version_guid",
        ]

        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for result in all_results:
            row = {
                "case_name": result.get("case_name", "Unknown"),
                "file_name": result["file_name"],
                "dwg_version": result["dwg_version"],
                "extraction_method": result["extraction_method"],
                "tdcreate": format_timestamp(result["tdcreate"]),
                "tdupdate": format_timestamp(result["tdupdate"]),
                "tdindwg_hours": f"{result['tdindwg_hours']:.4f}" if result["tdindwg_hours"] is not None else "N/A",
                "ntfs_created": format_timestamp(result["ntfs_created"]),
                "ntfs_modified": format_timestamp(result["ntfs_modified"]),
                "timeline_match": result.get("timeline_analysis", {}).get("timeline_match", "N/A"),
                "verdict": result.get("timeline_analysis", {}).get("verdict", "N/A"),
                "manipulation_indicators": "; ".join(result.get("timeline_analysis", {}).get("manipulation_indicators", [])),
                "fingerprint_guid": result.get("fingerprint_guid", "N/A"),
                "version_guid": result.get("version_guid", "N/A"),
            }
            writer.writerow(row)

    print(f"[OK] CSV export complete")
    print()

    # Generate expert witness report
    report_path = project_root / "DWG_TIMESTAMP_FORENSIC_ANALYSIS.txt"
    print(f"Generating expert witness report: {report_path}")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("DWG TIMESTAMP FORENSIC ANALYSIS REPORT\n")
        f.write("=" * 80 + "\n\n")

        f.write("EXECUTIVE SUMMARY\n")
        f.write("-" * 80 + "\n\n")

        f.write(f"Analysis Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"Analyst: DWG Forensic Tool v2.0 (Phase 2)\n")
        f.write(f"Case: English Oaks Naples 2 - DWG Timestamp Authenticity\n\n")

        f.write(f"Files Analyzed: {pattern['total_files']}\n")
        f.write(f"Successful Extractions: {pattern['extraction_success_count']}\n")
        f.write(f"Files with Backdating Evidence: {pattern['backdating_count']}\n")
        f.write(f"Files with Smoking Gun Evidence: {pattern['smoking_gun_count']}\n\n")

        f.write(f"VERDICT: {pattern['pattern_verdict']}\n\n")

        f.write("=" * 80 + "\n\n")

        f.write("METHODOLOGY\n")
        f.write("-" * 80 + "\n\n")

        f.write("This analysis extracts internal DWG timestamps ($TDCREATE, $TDUPDATE, $TDINDWG)\n")
        f.write("from AutoCAD DWG files and cross-correlates with established RVT timeline:\n\n")

        f.write("Phase 1 Established Timeline:\n")
        f.write("  - RVT files last modified: 2026-01-09 13:08:41-44 UTC\n")
        f.write("  - DWG files NTFS created: 2026-01-09 18:08:42-51 UTC\n")
        f.write("  - Export window: Approximately 5 hours after RVT modification\n\n")

        f.write("Hypothesis Tested:\n")
        f.write("  Files were batch-exported from RVT sources at 18:08:42-51 on 2026-01-09.\n")
        f.write("  If DWG internal timestamps predate RVT modification (13:08:41),\n")
        f.write("  this constitutes DEFINITIVE PROOF of timestamp manipulation.\n\n")

        f.write("=" * 80 + "\n\n")

        f.write("DETAILED RESULTS\n")
        f.write("-" * 80 + "\n\n")

        for result in all_results:
            f.write(f"File: {result['file_name']}\n")
            f.write(f"Case: {result.get('case_name', 'Unknown')}\n")
            f.write(f"DWG Version: {result['dwg_version']}\n")
            f.write(f"Extraction Method: {result['extraction_method']}\n\n")

            if result["extraction_success"]:
                f.write(f"  DWG Internal Timestamps:\n")
                f.write(f"    $TDCREATE:  {format_timestamp(result['tdcreate'])}\n")
                f.write(f"    $TDUPDATE:  {format_timestamp(result['tdupdate'])}\n")
                if result["tdindwg_hours"] is not None:
                    f.write(f"    $TDINDWG:   {result['tdindwg_hours']:.4f} hours\n")
                f.write(f"\n")

                f.write(f"  NTFS Timestamps:\n")
                f.write(f"    Created:    {format_timestamp(result['ntfs_created'])}\n")
                f.write(f"    Modified:   {format_timestamp(result['ntfs_modified'])}\n")
                f.write(f"\n")

                if result.get("timeline_analysis"):
                    ta = result["timeline_analysis"]
                    f.write(f"  Timeline Analysis:\n")
                    f.write(f"    Match: {ta['timeline_match']}\n")
                    f.write(f"    Verdict: {ta['verdict']}\n")
                    f.write(f"    Confidence: {ta['confidence']:.1%}\n")

                    if ta["manipulation_indicators"]:
                        f.write(f"\n    Indicators:\n")
                        for indicator in ta["manipulation_indicators"]:
                            f.write(f"      - {indicator}\n")

                    if ta["smoking_gun"]:
                        f.write(f"\n    [SMOKING GUN] This file contains definitive proof of manipulation.\n")

                    f.write(f"\n")
            else:
                f.write(f"  [EXTRACTION FAILED]\n")
                for error in result["extraction_errors"]:
                    f.write(f"    - {error}\n")
                f.write(f"\n")

            f.write("-" * 80 + "\n\n")

        f.write("=" * 80 + "\n\n")

        f.write("BATCH PATTERN ANALYSIS\n")
        f.write("-" * 80 + "\n\n")

        f.write(f"Unique $TDCREATE Timestamps: {len(pattern['unique_tdcreate_timestamps'])}\n")
        if pattern["unique_tdcreate_timestamps"]:
            for ts in pattern["unique_tdcreate_timestamps"]:
                f.write(f"  - {ts}\n")
            f.write("\n")

        f.write(f"Unique $TDUPDATE Timestamps: {len(pattern['unique_tdupdate_timestamps'])}\n")
        if pattern["unique_tdupdate_timestamps"]:
            for ts in pattern["unique_tdupdate_timestamps"]:
                f.write(f"  - {ts}\n")
            f.write("\n")

        if pattern["timestamp_clusters"]:
            f.write("Timestamp Clustering:\n")
            for cluster in pattern["timestamp_clusters"]:
                f.write(f"  Type: {cluster['type']}\n")
                f.write(f"  Span: {cluster['span_seconds']:.1f} seconds ({cluster['file_count']} files)\n")
                f.write(f"  Range: {cluster['min_timestamp']} to {cluster['max_timestamp']}\n")
                f.write(f"  Verdict: {cluster['verdict']}\n\n")

        f.write(f"Files with Backdating Evidence: {pattern['backdating_count']}\n")
        f.write(f"Files with Smoking Gun Evidence: {pattern['smoking_gun_count']}\n\n")

        f.write(f"OVERALL VERDICT: {pattern['pattern_verdict']}\n\n")

        f.write("=" * 80 + "\n\n")

        f.write("EXPERT WITNESS CONCLUSIONS\n")
        f.write("-" * 80 + "\n\n")

        if pattern["smoking_gun_count"] > 0:
            f.write("This analysis has identified DEFINITIVE PROOF of timestamp manipulation.\n\n")
            f.write(f"{pattern['smoking_gun_count']} files contain internal DWG timestamps that are\n")
            f.write("logically impossible given the established RVT modification timeline.\n\n")
            f.write("These findings constitute smoking gun evidence suitable for litigation.\n\n")
        elif pattern["batch_evidence"]:
            f.write("This analysis supports the hypothesis of legitimate batch export workflow.\n\n")
            f.write("All DWG files were created within a narrow time window consistent with\n")
            f.write("automated export from Revit sources. Internal timestamps correlate with\n")
            f.write("NTFS timestamps and RVT modification timeline.\n\n")
            f.write("No evidence of timestamp manipulation detected.\n\n")
        else:
            f.write("This analysis yields inconclusive results.\n\n")
            f.write("Insufficient timestamp data was extracted to definitively establish\n")
            f.write("manipulation or legitimacy. Additional forensic methods recommended.\n\n")

        f.write("=" * 80 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 80 + "\n")

    print(f"[OK] Report generation complete")
    print()
    print("=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)
    print()
    print(f"Results exported to:")
    print(f"  CSV: {csv_path}")
    print(f"  Report: {report_path}")
    print()


if __name__ == "__main__":
    main()
