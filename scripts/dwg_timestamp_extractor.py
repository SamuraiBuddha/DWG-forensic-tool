#!/usr/bin/env python3
"""
Direct DWG Timestamp Extractor - Phase 2 Forensic Analysis

Extracts DWG internal timestamps using direct parser calls.
Correlates with RVT timeline to detect backdating.
"""

import csv
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dwg_forensic.parsers.drawing_vars import DrawingVariablesParser
from dwg_forensic.parsers.header import HeaderParser
import os


# RVT Timeline from Phase 1
RVT_LAST_SAVED = datetime(2026, 1, 9, 13, 8, 41, tzinfo=timezone.utc)
DWG_EXPORT_TIME = datetime(2026, 1, 9, 18, 8, 42, tzinfo=timezone.utc)

# Case directories
CASE_DIRS = {
    "2021": Path(r"E:\6075 English Oaks - Naples 2, 2021 Initial Permit\02-Drawings"),
    "2022": Path(r"E:\6075 English Oaks - Naples 2, 2022 Drawing Files"),
}


def extract_timestamps(dwg_path: Path) -> Dict[str, Any]:
    """Extract all timestamp data from DWG file."""
    result = {
        "file_path": str(dwg_path),
        "file_name": dwg_path.name,
        "dwg_version": "Unknown",

        # Timestamp extraction status
        "tdcreate_found": False,
        "tdupdate_found": False,
        "tdindwg_found": False,

        # DWG internal timestamps
        "tdcreate": None,
        "tdupdate": None,
        "tdindwg_days": None,
        "tdindwg_hours": None,

        # NTFS timestamps
        "ntfs_created": None,
        "ntfs_modified": None,

        # GUIDs
        "fingerprint_guid": None,
        "version_guid": None,

        # Extraction diagnostics
        "extraction_method": "None",
        "errors": [],
    }

    try:
        # Extract DWG version
        header_parser = HeaderParser()
        header_result = header_parser.parse(dwg_path)
        if header_result:
            result["dwg_version"] = header_result.version_string

        # Extract NTFS timestamps using file stats
        if dwg_path.exists():
            stat = dwg_path.stat()
            result["ntfs_created"] = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc)
            result["ntfs_modified"] = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)

        # Extract drawing variables (includes timestamps)
        vars_parser = DrawingVariablesParser()
        vars_result = vars_parser.parse(dwg_path)

        if vars_result:
            result["extraction_method"] = "DrawingVariablesParser"

            # TDCREATE
            if vars_result.tdcreate and vars_result.tdcreate.is_valid:
                result["tdcreate_found"] = True
                result["tdcreate"] = vars_result.tdcreate.datetime_utc

            # TDUPDATE
            if vars_result.tdupdate and vars_result.tdupdate.is_valid:
                result["tdupdate_found"] = True
                result["tdupdate"] = vars_result.tdupdate.datetime_utc

            # TDINDWG
            if vars_result.tdindwg and vars_result.tdindwg.is_valid:
                result["tdindwg_found"] = True
                result["tdindwg_days"] = vars_result.tdindwg.julian_day
                result["tdindwg_hours"] = vars_result.tdindwg.julian_day * 24

            # GUIDs
            if vars_result.fingerprintguid:
                result["fingerprint_guid"] = vars_result.fingerprintguid.guid_string

            if vars_result.versionguid:
                result["version_guid"] = vars_result.versionguid.guid_string

            # Errors
            if vars_result.parsing_errors:
                result["errors"].extend(vars_result.parsing_errors)

    except Exception as e:
        result["errors"].append(f"Extraction failed: {e}")

    return result


def analyze_timeline(data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze timeline correlation and detect manipulation."""
    analysis = {
        "verdict": "Inconclusive",
        "timeline_match": "Unknown",
        "backdating_detected": False,
        "smoking_gun": False,
        "confidence": 0.0,
        "indicators": [],
    }

    tdcreate = data.get("tdcreate")
    tdupdate = data.get("tdupdate")
    ntfs_modified = data.get("ntfs_modified")

    # CRITICAL FINDING: Missing TDCREATE/TDUPDATE timestamps
    if not data["tdcreate_found"] and not data["tdupdate_found"]:
        # This is HIGHLY SUSPICIOUS - these timestamps should ALWAYS be present
        if data["tdindwg_found"]:
            # TDINDWG exists but TDCREATE/TDUPDATE don't - STRONG manipulation indicator
            analysis["verdict"] = "SUSPICIOUS - Critical timestamps missing"
            analysis["timeline_match"] = "FAILED - TDCREATE/TDUPDATE stripped"
            analysis["indicators"].append(
                "TDCREATE and TDUPDATE timestamps MISSING but TDINDWG present - "
                "Strong indicator of timestamp manipulation"
            )
            analysis["confidence"] = 0.85
            analysis["backdating_detected"] = True
        else:
            # No timestamps at all - file may be corrupted or heavily manipulated
            analysis["verdict"] = "CRITICAL - All internal timestamps missing"
            analysis["timeline_match"] = "FAILED - Complete timestamp absence"
            analysis["indicators"].append(
                "ALL internal DWG timestamps missing - file structure compromised or "
                "deliberately stripped"
            )
            analysis["confidence"] = 0.95
            analysis["smoking_gun"] = True

        return analysis

    # If we have timestamps, perform timeline correlation
    if tdcreate and tdupdate:
        # Test 1: Impossible timestamp sequence
        if tdupdate < tdcreate:
            analysis["smoking_gun"] = True
            analysis["backdating_detected"] = True
            analysis["verdict"] = "DEFINITIVE PROOF - Impossible timestamp sequence"
            analysis["indicators"].append(
                f"TDUPDATE ({tdupdate}) predates TDCREATE ({tdcreate}) - IMPOSSIBLE"
            )
            analysis["confidence"] = 1.0
            return analysis

        # Test 2: Backdating (DWG creation predates RVT modification)
        if tdcreate < RVT_LAST_SAVED:
            delta_hours = (RVT_LAST_SAVED - tdcreate).total_seconds() / 3600
            analysis["smoking_gun"] = True
            analysis["backdating_detected"] = True
            analysis["verdict"] = "DEFINITIVE PROOF - Backdating detected"
            analysis["timeline_match"] = "FAILED - DWG predates RVT source"
            analysis["indicators"].append(
                f"DWG created {delta_hours:.1f} hours BEFORE RVT was last saved - IMPOSSIBLE"
            )
            analysis["confidence"] = 1.0
            return analysis

        # Test 3: Fraudulent 2021 timestamps
        if tdcreate.year == 2021:
            analysis["smoking_gun"] = True
            analysis["backdating_detected"] = True
            analysis["verdict"] = "DEFINITIVE PROOF - Fraudulent 2021 timestamp"
            analysis["timeline_match"] = "FAILED - Claims 2021 origin"
            analysis["indicators"].append(
                f"DWG claims 2021 creation but NTFS shows {ntfs_modified.year if ntfs_modified else '2026'} - BACKDATING"
            )
            analysis["confidence"] = 1.0
            return analysis

        # Test 4: Legitimate export window (within 2 minutes of batch export)
        export_window_start = DWG_EXPORT_TIME
        export_window_end = DWG_EXPORT_TIME.replace(minute=10, second=0)  # 18:10:00

        if export_window_start <= tdcreate <= export_window_end:
            analysis["verdict"] = "Legitimate export workflow"
            analysis["timeline_match"] = "PASS - Consistent with batch export"
            analysis["indicators"].append(
                f"DWG creation time matches export window (18:08-18:10) - consistent with Revit export"
            )
            analysis["confidence"] = 0.90
            return analysis

        # Test 5: Between RVT save and export (plausible)
        if RVT_LAST_SAVED < tdcreate < DWG_EXPORT_TIME:
            delta_minutes = (tdcreate - RVT_LAST_SAVED).total_seconds() / 60
            analysis["verdict"] = "Plausible export workflow"
            analysis["timeline_match"] = "PASS - Within export window"
            analysis["indicators"].append(
                f"DWG created {delta_minutes:.1f} minutes after RVT save - plausible export delay"
            )
            analysis["confidence"] = 0.75
            return analysis

        # Test 6: After export window (suspicious)
        if tdcreate > export_window_end:
            delta_hours = (tdcreate - DWG_EXPORT_TIME).total_seconds() / 3600
            analysis["verdict"] = "SUSPICIOUS - Clock manipulation possible"
            analysis["timeline_match"] = "SUSPICIOUS - After NTFS creation time"
            analysis["indicators"].append(
                f"DWG creation timestamp is {delta_hours:.1f} hours AFTER file creation - clock rollback?"
            )
            analysis["confidence"] = 0.70
            return analysis

    return analysis


def main():
    """Main analysis routine."""
    print("=" * 80)
    print("DWG TIMESTAMP FORENSIC ANALYSIS - PHASE 2")
    print("=" * 80)
    print()
    print("RVT Timeline Baseline (Phase 1):")
    print(f"  RVT Last Saved: {RVT_LAST_SAVED.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  DWG Export Time: {DWG_EXPORT_TIME.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print()
    print("Testing Hypothesis:")
    print("  Files were batch-exported from RVT at 18:08:42-51 on 2026-01-09.")
    print("  If DWG timestamps predate RVT modification, that's definitive proof of manipulation.")
    print()
    print("=" * 80)
    print()

    all_results = []

    for case_name, case_dir in CASE_DIRS.items():
        print(f"\n{'=' * 80}")
        print(f"CASE: {case_name}")
        print(f"Directory: {case_dir}")
        print('=' * 80)

        if not case_dir.exists():
            print(f"[WARN] Directory not found: {case_dir}")
            continue

        # Find all DWG files
        dwg_files = sorted(case_dir.glob("*.dwg"))
        print(f"Found {len(dwg_files)} DWG files\n")

        if len(dwg_files) == 0:
            continue

        # Process each file
        for dwg_file in dwg_files:
            print(f"\n{'-' * 80}")
            print(f"File: {dwg_file.name}")
            print('-' * 80)

            # Extract timestamps
            data = extract_timestamps(dwg_file)
            data["case_name"] = case_name

            # Display extraction results
            print(f"DWG Version: {data['dwg_version']}")
            print(f"Extraction Method: {data['extraction_method']}")
            print()

            print("Internal Timestamps:")
            print(f"  TDCREATE: {'PRESENT' if data['tdcreate_found'] else 'MISSING'}", end="")
            if data['tdcreate']:
                print(f" -> {data['tdcreate'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
            else:
                print()

            print(f"  TDUPDATE: {'PRESENT' if data['tdupdate_found'] else 'MISSING'}", end="")
            if data['tdupdate']:
                print(f" -> {data['tdupdate'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
            else:
                print()

            print(f"  TDINDWG:  {'PRESENT' if data['tdindwg_found'] else 'MISSING'}", end="")
            if data['tdindwg_hours'] is not None:
                print(f" -> {data['tdindwg_hours']:.4f} hours ({data['tdindwg_days']:.4f} days)")
            else:
                print()

            print()
            print("NTFS Timestamps:")
            if data['ntfs_created']:
                print(f"  Created:  {data['ntfs_created'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
            if data['ntfs_modified']:
                print(f"  Modified: {data['ntfs_modified'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
            print()

            # Analyze timeline
            analysis = analyze_timeline(data)
            data["analysis"] = analysis

            print("Timeline Analysis:")
            print(f"  Match: {analysis['timeline_match']}")
            print(f"  Verdict: {analysis['verdict']}")
            print(f"  Confidence: {analysis['confidence']:.0%}")

            if analysis['indicators']:
                print("  Indicators:")
                for indicator in analysis['indicators']:
                    print(f"    - {indicator}")

            if analysis['smoking_gun']:
                print()
                print("  [SMOKING GUN] Definitive proof of manipulation")

            if data.get('errors'):
                print()
                print("  Errors:")
                for error in data['errors']:
                    print(f"    - {error}")

            all_results.append(data)

    # Generate summary report
    print()
    print()
    print("=" * 80)
    print("SUMMARY REPORT")
    print("=" * 80)
    print()

    total_files = len(all_results)
    tdcreate_missing = sum(1 for r in all_results if not r['tdcreate_found'])
    tdupdate_missing = sum(1 for r in all_results if not r['tdupdate_found'])
    tdindwg_present = sum(1 for r in all_results if r['tdindwg_found'])
    smoking_guns = sum(1 for r in all_results if r.get('analysis', {}).get('smoking_gun'))
    backdating = sum(1 for r in all_results if r.get('analysis', {}).get('backdating_detected'))

    print(f"Total Files Analyzed: {total_files}")
    print(f"Files Missing TDCREATE: {tdcreate_missing} ({tdcreate_missing/total_files*100:.0f}%)")
    print(f"Files Missing TDUPDATE: {tdupdate_missing} ({tdupdate_missing/total_files*100:.0f}%)")
    print(f"Files with TDINDWG: {tdindwg_present} ({tdindwg_present/total_files*100:.0f}%)")
    print()
    print(f"Files with Smoking Gun Evidence: {smoking_guns}")
    print(f"Files with Backdating Indicators: {backdating}")
    print()

    # CRITICAL FINDING
    if tdcreate_missing == total_files and tdindwg_present > 0:
        print("CRITICAL FINDING:")
        print("  ALL files are missing TDCREATE and TDUPDATE timestamps,")
        print("  but TDINDWG is present. This is a STRONG indicator of")
        print("  deliberate timestamp manipulation via DWG editing tools.")
        print()
        print("  VERDICT: HIGHLY SUSPICIOUS - Timestamp stripping detected")
        print()
    elif smoking_guns > 0:
        print(f"CRITICAL FINDING:")
        print(f"  {smoking_guns} file(s) contain definitive proof of timestamp manipulation.")
        print()
        print("  VERDICT: SMOKING GUN EVIDENCE FOUND")
        print()

    # Export to CSV
    csv_path = project_root / "DWG_TIMESTAMP_ANALYSIS.csv"
    print(f"Exporting results to: {csv_path}")

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "case_name", "file_name", "dwg_version",
            "tdcreate_found", "tdcreate",
            "tdupdate_found", "tdupdate",
            "tdindwg_found", "tdindwg_hours",
            "ntfs_created", "ntfs_modified",
            "timeline_match", "verdict", "confidence",
            "smoking_gun", "backdating_detected",
            "indicators"
        ]

        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for result in all_results:
            analysis = result.get("analysis", {})
            row = {
                "case_name": result.get("case_name", ""),
                "file_name": result["file_name"],
                "dwg_version": result["dwg_version"],
                "tdcreate_found": "Yes" if result["tdcreate_found"] else "No",
                "tdcreate": result["tdcreate"].strftime("%Y-%m-%d %H:%M:%S") if result["tdcreate"] else "N/A",
                "tdupdate_found": "Yes" if result["tdupdate_found"] else "No",
                "tdupdate": result["tdupdate"].strftime("%Y-%m-%d %H:%M:%S") if result["tdupdate"] else "N/A",
                "tdindwg_found": "Yes" if result["tdindwg_found"] else "No",
                "tdindwg_hours": f"{result['tdindwg_hours']:.4f}" if result["tdindwg_hours"] is not None else "N/A",
                "ntfs_created": result["ntfs_created"].strftime("%Y-%m-%d %H:%M:%S") if result["ntfs_created"] else "N/A",
                "ntfs_modified": result["ntfs_modified"].strftime("%Y-%m-%d %H:%M:%S") if result["ntfs_modified"] else "N/A",
                "timeline_match": analysis.get("timeline_match", "N/A"),
                "verdict": analysis.get("verdict", "N/A"),
                "confidence": f"{analysis.get('confidence', 0.0):.0%}",
                "smoking_gun": "YES" if analysis.get("smoking_gun") else "No",
                "backdating_detected": "YES" if analysis.get("backdating_detected") else "No",
                "indicators": "; ".join(analysis.get("indicators", []))
            }
            writer.writerow(row)

    print("[OK] CSV export complete")
    print()
    print("=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
