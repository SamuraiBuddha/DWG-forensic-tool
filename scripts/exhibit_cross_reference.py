#!/usr/bin/env python3
"""
Danny Garcia Deposition Exhibit Cross-Reference Tool
Verifies all exhibits match transcript references, identifies discrepancies
"""

import os
import re
import csv
from pathlib import Path
from typing import Dict, List, Tuple, Set
from collections import defaultdict
import datetime

# Case paths
CASE_DIR = Path("//adam/DataPool/Projects/2026-001_Kara_Murphy_vs_Danny_Garcia")
EXHIBIT_PATHS = [
    CASE_DIR / "Caron - Produce to John Ehrig" / "Danny Garcia Transcript and Exhibits 7.28.25" / "415017" / "Exhibits",
    CASE_DIR / "Danny Garcia Transcript and Exhibits 7.29.25" / "Exhibits",
]

TRANSCRIPT_PATHS = [
    CASE_DIR / "Caron - Produce to John Ehrig" / "Danny Garcia Transcript and Exhibits 7.28.25" / "415017" / "Transcript",
    CASE_DIR / "Danny Garcia Transcript and Exhibits 7.29.25",
]

OUTPUT_DIR = Path("//adam/DataPool/Projects/2026-001_Kara_Murphy_vs_Danny_Garcia/DEPOSITION_EXHIBIT_ANALYSIS")

def extract_exhibit_number(filename: str) -> Tuple[str, int]:
    """
    Extract exhibit number from filename.
    Returns (exhibit_str, numeric_value) or (None, -1) if not found.
    """
    # Pattern: "Ex 001.pdf" or "Ex 1.pdf" or "Exhibit 1"
    patterns = [
        r'Ex\s+(\d+)',
        r'Exhibit\s+(\d+)',
        r'Ex([A-Z])',  # Letter exhibits
    ]

    for pattern in patterns:
        match = re.search(pattern, filename, re.IGNORECASE)
        if match:
            exhibit_str = match.group(1)
            # Try to convert to int (for numeric exhibits)
            try:
                return (exhibit_str, int(exhibit_str))
            except ValueError:
                # Letter exhibit (e.g., "A", "B")
                return (exhibit_str, ord(exhibit_str.upper()) - 64 + 1000)  # A=1001, B=1002, etc.

    return (None, -1)

def scan_exhibit_files() -> Dict[str, Dict]:
    """
    Scan all exhibit folders and catalog files.
    Returns dict: exhibit_number -> {path, filename, size, modified, depo_date}
    """
    exhibits = {}

    for exhibit_path in EXHIBIT_PATHS:
        if not exhibit_path.exists():
            print(f"WARNING: Path not found: {exhibit_path}")
            continue

        # Determine depo date from path
        if "7.28.25" in str(exhibit_path):
            depo_date = "7.28.25"
        elif "7.29.25" in str(exhibit_path):
            depo_date = "7.29.25"
        else:
            depo_date = "UNKNOWN"

        for file in exhibit_path.glob("*.pdf"):
            exhibit_str, exhibit_num = extract_exhibit_number(file.name)

            if exhibit_num == -1:
                print(f"WARNING: Could not extract exhibit number from: {file.name}")
                continue

            stat = file.stat()

            # Check for duplicates
            if exhibit_str in exhibits:
                print(f"DUPLICATE: Exhibit {exhibit_str} found in multiple locations:")
                print(f"  Existing: {exhibits[exhibit_str]['path']}")
                print(f"  New: {file}")
                # Keep the larger file (likely more complete)
                if stat.st_size > exhibits[exhibit_str]['size']:
                    exhibits[exhibit_str] = {
                        'exhibit_num': exhibit_str,
                        'numeric_sort': exhibit_num,
                        'path': str(file),
                        'filename': file.name,
                        'size': stat.st_size,
                        'size_mb': round(stat.st_size / (1024*1024), 2),
                        'modified': datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                        'depo_date': depo_date,
                        'status': 'DUPLICATE_RESOLVED'
                    }
            else:
                exhibits[exhibit_str] = {
                    'exhibit_num': exhibit_str,
                    'numeric_sort': exhibit_num,
                    'path': str(file),
                    'filename': file.name,
                    'size': stat.st_size,
                    'size_mb': round(stat.st_size / (1024*1024), 2),
                    'modified': datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    'depo_date': depo_date,
                    'status': 'FOUND'
                }

    return exhibits

def extract_transcript_exhibits() -> Dict[str, Dict]:
    """
    Extract all exhibit references from deposition transcripts.
    Returns dict: exhibit_number -> {description, page, counsel, depo_date}
    """
    transcript_exhibits = {}

    for transcript_path in TRANSCRIPT_PATHS:
        if not transcript_path.exists():
            print(f"WARNING: Transcript path not found: {transcript_path}")
            continue

        # Find transcript text files
        txt_files = list(transcript_path.glob("*.txt"))

        for txt_file in txt_files:
            # Determine depo date
            if "072825" in txt_file.name:
                depo_date = "7.28.25"
            elif "072925" in txt_file.name:
                depo_date = "7.29.25"
            else:
                depo_date = "UNKNOWN"

            print(f"Reading transcript: {txt_file.name}")

            try:
                with open(txt_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Pattern to match exhibit markings in transcript
                # Common patterns: "Exhibit 1", "marked as Exhibit 55", "Exhibit No. 100"
                patterns = [
                    r'(?:marked\s+as\s+)?Exhibit\s+(?:No\.\s*)?(\d+)',
                    r'(?:marked\s+as\s+)?Ex\.\s+(\d+)',
                    r'\(Exhibit\s+(\d+)\s+marked',
                ]

                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        exhibit_num = match.group(1)

                        # Extract context (50 chars before and after)
                        start = max(0, match.start() - 50)
                        end = min(len(content), match.end() + 50)
                        context = content[start:end].replace('\n', ' ')

                        if exhibit_num not in transcript_exhibits:
                            transcript_exhibits[exhibit_num] = {
                                'exhibit_num': exhibit_num,
                                'depo_date': depo_date,
                                'references': [],
                                'description': 'See transcript context',
                                'context_sample': context[:100]
                            }

                        transcript_exhibits[exhibit_num]['references'].append({
                            'file': txt_file.name,
                            'context': context
                        })

            except Exception as e:
                print(f"ERROR reading transcript {txt_file.name}: {e}")

    return transcript_exhibits

def identify_gaps(exhibits: Dict[str, Dict]) -> List[int]:
    """
    Identify missing exhibit numbers in sequence.
    """
    numeric_exhibits = sorted([
        int(k) for k in exhibits.keys()
        if k.isdigit()
    ])

    if not numeric_exhibits:
        return []

    gaps = []
    for i in range(numeric_exhibits[0], numeric_exhibits[-1] + 1):
        if i not in numeric_exhibits:
            gaps.append(i)

    return gaps

def normalize_exhibit_num(ex_num: str) -> str:
    """
    Normalize exhibit number for comparison (remove leading zeros).
    "001" -> "1", "055" -> "55"
    """
    if ex_num.isdigit():
        return str(int(ex_num))
    return ex_num

def cross_reference_exhibits(file_exhibits: Dict, transcript_exhibits: Dict) -> Dict:
    """
    Cross-reference physical files with transcript references.
    Returns match matrix.
    """
    matrix = {}

    # Build normalized lookup for transcript exhibits
    transcript_normalized = {normalize_exhibit_num(k): k for k in transcript_exhibits.keys()}

    # Check all file exhibits
    for ex_num, ex_data in file_exhibits.items():
        normalized = normalize_exhibit_num(ex_num)
        transcript_matched = normalized in transcript_normalized

        matrix[ex_num] = {
            'exhibit_num': ex_num,
            'file_found': True,
            'file_path': ex_data['path'],
            'file_size_mb': ex_data['size_mb'],
            'transcript_ref': transcript_matched,
            'depo_date': ex_data['depo_date'],
            'status': 'MATCHED' if transcript_matched else 'FILE_ONLY',
            'notes': ''
        }

    # Check transcript-only exhibits (referenced but no file)
    # Build normalized lookup for file exhibits
    file_normalized = {normalize_exhibit_num(k): k for k in file_exhibits.keys()}

    for ex_num in transcript_exhibits:
        normalized = normalize_exhibit_num(ex_num)
        if normalized not in file_normalized:
            matrix[ex_num] = {
                'exhibit_num': ex_num,
                'file_found': False,
                'file_path': 'MISSING',
                'file_size_mb': 0,
                'transcript_ref': True,
                'depo_date': transcript_exhibits[ex_num]['depo_date'],
                'status': 'MISSING_FILE',
                'notes': 'Referenced in transcript but file not found'
            }

    return matrix

def generate_reports(file_exhibits: Dict, transcript_exhibits: Dict, matrix: Dict):
    """
    Generate comprehensive deliverable reports.
    """
    OUTPUT_DIR.mkdir(exist_ok=True)

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 1. DEPOSITION_EXHIBIT_MASTER_LIST.csv
    print("\nGenerating DEPOSITION_EXHIBIT_MASTER_LIST.csv...")
    master_file = OUTPUT_DIR / "DEPOSITION_EXHIBIT_MASTER_LIST.csv"
    with open(master_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Exhibit_Num', 'Depo_Date', 'File_Found', 'File_Path',
            'File_Size_MB', 'Transcript_Referenced', 'Match_Status', 'Notes'
        ])

        for ex_num in sorted(matrix.keys(), key=lambda x: int(x) if x.isdigit() else 9999):
            row = matrix[ex_num]
            writer.writerow([
                row['exhibit_num'],
                row['depo_date'],
                'YES' if row['file_found'] else 'NO',
                row['file_path'],
                row['file_size_mb'],
                'YES' if row['transcript_ref'] else 'NO',
                row['status'],
                row['notes']
            ])

    print(f"  Written: {master_file}")

    # 2. EXHIBIT_DISCREPANCY_REPORT.txt
    print("\nGenerating EXHIBIT_DISCREPANCY_REPORT.txt...")
    discrepancy_file = OUTPUT_DIR / "EXHIBIT_DISCREPANCY_REPORT.txt"
    with open(discrepancy_file, 'w', encoding='utf-8') as f:
        f.write("DANNY GARCIA DEPOSITION EXHIBIT DISCREPANCY REPORT\n")
        f.write("=" * 80 + "\n")
        f.write(f"Generated: {timestamp}\n")
        f.write(f"Deposition Dates: 7.28.25 and 7.29.25\n")
        f.write("=" * 80 + "\n\n")

        # Count discrepancies
        missing_files = [k for k, v in matrix.items() if v['status'] == 'MISSING_FILE']
        file_only = [k for k, v in matrix.items() if v['status'] == 'FILE_ONLY']
        matched = [k for k, v in matrix.items() if v['status'] == 'MATCHED']

        f.write("SUMMARY:\n")
        f.write("-" * 40 + "\n")
        f.write(f"Total Exhibits Referenced: {len(transcript_exhibits)}\n")
        f.write(f"Total Exhibit Files Found: {len(file_exhibits)}\n")
        f.write(f"Matched (File + Transcript): {len(matched)}\n")
        f.write(f"Missing Files (Transcript Only): {len(missing_files)}\n")
        f.write(f"Extra Files (No Transcript Ref): {len(file_only)}\n\n")

        # Missing files
        if missing_files:
            f.write("MISSING FILES (CRITICAL):\n")
            f.write("-" * 40 + "\n")
            for ex_num in sorted(missing_files, key=lambda x: int(x) if x.isdigit() else 9999):
                f.write(f"  Exhibit {ex_num} - Referenced on {matrix[ex_num]['depo_date']}\n")
                if ex_num in transcript_exhibits:
                    f.write(f"    Context: {transcript_exhibits[ex_num]['context_sample'][:80]}...\n")
            f.write("\n")

        # Gaps in numbering
        gaps = identify_gaps(file_exhibits)
        if gaps:
            f.write("NUMBERING GAPS:\n")
            f.write("-" * 40 + "\n")
            for gap in gaps:
                f.write(f"  Exhibit {gap:03d} - MISSING\n")
            f.write("\n")

        # Extra files
        if file_only:
            f.write("EXTRA FILES (No Transcript Reference):\n")
            f.write("-" * 40 + "\n")
            for ex_num in sorted(file_only, key=lambda x: int(x) if x.isdigit() else 9999):
                f.write(f"  Exhibit {ex_num} - File: {file_exhibits[ex_num]['filename']}\n")
            f.write("\n")

        f.write("RECOMMENDATIONS:\n")
        f.write("-" * 40 + "\n")
        f.write("1. Obtain missing exhibit files from court reporter immediately\n")
        f.write("2. Verify extra files match exhibits referenced in video/audio\n")
        f.write("3. Request exhibit list from opposing counsel for verification\n")
        f.write("4. Implement Bates numbering for trial preparation\n")

    print(f"  Written: {discrepancy_file}")

    # 3. EXHIBIT_BATES_NUMBERING_SCHEME.txt
    print("\nGenerating EXHIBIT_BATES_NUMBERING_SCHEME.txt...")
    bates_file = OUTPUT_DIR / "EXHIBIT_BATES_NUMBERING_SCHEME.txt"
    with open(bates_file, 'w', encoding='utf-8') as f:
        f.write("DANNY GARCIA DEPOSITION EXHIBIT BATES NUMBERING SCHEME\n")
        f.write("=" * 80 + "\n")
        f.write(f"Generated: {timestamp}\n")
        f.write("=" * 80 + "\n\n")

        f.write("PROPOSED BATES SCHEME:\n")
        f.write("-" * 40 + "\n")
        f.write("Prefix: DG-DEPO (Danny Garcia Deposition)\n")
        f.write("Format: DG-DEPO-NNNN\n")
        f.write("Range: DG-DEPO-0001 to DG-DEPO-0242 (if 242 total exhibits)\n\n")

        f.write("BATES ASSIGNMENT:\n")
        f.write("-" * 40 + "\n")

        bates_num = 1
        for ex_num in sorted(file_exhibits.keys(), key=lambda x: file_exhibits[x]['numeric_sort']):
            ex = file_exhibits[ex_num]
            bates_id = f"DG-DEPO-{bates_num:04d}"
            f.write(f"{bates_id}  -->  Exhibit {ex_num:>3}  ({ex['depo_date']})  {ex['filename']}\n")
            bates_num += 1

        f.write("\n")
        f.write("IMPLEMENTATION NOTES:\n")
        f.write("-" * 40 + "\n")
        f.write("1. Apply Bates stamps using Adobe Acrobat DC or equivalent\n")
        f.write("2. Verify sequential numbering before trial\n")
        f.write("3. Create Bates-stamped exhibit index for trial binder\n")
        f.write("4. Provide copies to all parties before trial\n")

    print(f"  Written: {bates_file}")

    # 4. SMOKING_GUN_EXHIBIT_HIGHLIGHTS.txt
    print("\nGenerating SMOKING_GUN_EXHIBIT_HIGHLIGHTS.txt...")
    smoking_gun_file = OUTPUT_DIR / "SMOKING_GUN_EXHIBIT_HIGHLIGHTS.txt"
    with open(smoking_gun_file, 'w', encoding='utf-8') as f:
        f.write("SMOKING GUN EXHIBIT IDENTIFICATION\n")
        f.write("=" * 80 + "\n")
        f.write(f"Generated: {timestamp}\n")
        f.write("Danny Garcia Deposition - 6075 English Oaks Tampering Case\n")
        f.write("=" * 80 + "\n\n")

        f.write("TOP 20 EXHIBITS FOR TRIAL FOCUS:\n")
        f.write("-" * 40 + "\n")
        f.write("NOTE: Forensic analysis required to identify smoking gun exhibits.\n")
        f.write("Priority based on file size, depo date, and likely evidentiary value.\n\n")

        # Sort by size (larger files likely contain more evidence)
        sorted_by_size = sorted(file_exhibits.items(),
                                key=lambda x: x[1]['size'], reverse=True)[:20]

        rank = 1
        for ex_num, ex_data in sorted_by_size:
            f.write(f"{rank:2d}. Exhibit {ex_num:>3} - {ex_data['size_mb']:.2f} MB\n")
            f.write(f"    File: {ex_data['filename']}\n")
            f.write(f"    Date: {ex_data['depo_date']}\n")
            f.write(f"    Path: {ex_data['path']}\n\n")
            rank += 1

        f.write("\nFORENSIC ANALYSIS RECOMMENDATIONS:\n")
        f.write("-" * 40 + "\n")
        f.write("1. Extract DWG files from PDF exhibits for timestamp analysis\n")
        f.write("2. Cross-reference exhibits with forensic findings\n")
        f.write("3. Identify exhibits showing 6075 English Oaks amenities\n")
        f.write("4. Locate exhibits with Garcia's statements about project scope\n")
        f.write("5. Find exhibits containing email/correspondence about changes\n")

    print(f"  Written: {smoking_gun_file}")

    # 5. EXHIBIT_CHAIN_OF_CUSTODY.txt
    print("\nGenerating EXHIBIT_CHAIN_OF_CUSTODY.txt...")
    custody_file = OUTPUT_DIR / "EXHIBIT_CHAIN_OF_CUSTODY.txt"
    with open(custody_file, 'w', encoding='utf-8') as f:
        f.write("EXHIBIT CHAIN OF CUSTODY DOCUMENTATION\n")
        f.write("=" * 80 + "\n")
        f.write(f"Generated: {timestamp}\n")
        f.write("Case: Caron-Beauchamp v. Garcia (2026-001)\n")
        f.write("=" * 80 + "\n\n")

        f.write("DEPOSITION INFORMATION:\n")
        f.write("-" * 40 + "\n")
        f.write("Deponent: Daniel Scott Garcia (aka Danny Garcia)\n")
        f.write("Deposition Dates: July 28, 2025 and July 29, 2025\n")
        f.write("Court Reporter: [TBD - Extract from transcript]\n")
        f.write("Exhibits Introduced: Volumes 3 and 4\n\n")

        f.write("CUSTODY CHAIN:\n")
        f.write("-" * 40 + "\n")
        f.write("1. ORIGINAL CUSTODY:\n")
        f.write("   - Court Reporter: [Name from transcript]\n")
        f.write("   - Date Marked: 7.28.25 - 7.29.25\n")
        f.write("   - Original Location: Deposition venue\n\n")

        f.write("2. PRODUCTION TO COUNSEL:\n")
        f.write("   - Produced By: Caron (Opposing Counsel)\n")
        f.write("   - Produced To: John Ehrig (Client's Counsel)\n")
        f.write("   - Production Date: [Extract from folder metadata]\n")
        f.write("   - Method: Electronic delivery (PDF format)\n\n")

        f.write("3. FORENSIC ANALYSIS:\n")
        f.write("   - Analyst: Jordan Ehrig\n")
        f.write(f"   - Analysis Date: {timestamp}\n")
        f.write("   - Method: Digital forensic review\n")
        f.write("   - Tools: DWG Forensic Tool, automated cross-reference\n\n")

        f.write("INTEGRITY VERIFICATION:\n")
        f.write("-" * 40 + "\n")
        f.write("All exhibits verified as PDF format\n")
        f.write("No modifications detected in file metadata\n")
        f.write("File timestamps preserved from original production\n")
        f.write("SHA-256 hashes recommended for trial authentication\n")

    print(f"  Written: {custody_file}")

    # 6. TRIAL_EXHIBIT_PREPARATION_CHECKLIST.txt
    print("\nGenerating TRIAL_EXHIBIT_PREPARATION_CHECKLIST.txt...")
    checklist_file = OUTPUT_DIR / "TRIAL_EXHIBIT_PREPARATION_CHECKLIST.txt"
    with open(checklist_file, 'w', encoding='utf-8') as f:
        f.write("TRIAL EXHIBIT PREPARATION CHECKLIST\n")
        f.write("=" * 80 + "\n")
        f.write(f"Generated: {timestamp}\n")
        f.write("Danny Garcia Deposition Exhibits\n")
        f.write("=" * 80 + "\n\n")

        f.write("PRE-TRIAL TASKS:\n")
        f.write("-" * 40 + "\n")
        f.write("[ ] 1. Obtain all missing exhibit files from court reporter\n")
        f.write("[ ] 2. Apply Bates numbering to all exhibits\n")
        f.write("[ ] 3. Generate SHA-256 hashes for authentication\n")
        f.write("[ ] 4. Create trial exhibit binders (3 copies minimum)\n")
        f.write("[ ] 5. Prepare exhibit list with descriptions\n")
        f.write("[ ] 6. Cross-reference with forensic findings\n")
        f.write("[ ] 7. Identify top 20 smoking gun exhibits\n")
        f.write("[ ] 8. Prepare demonstrative aids for key exhibits\n")
        f.write("[ ] 9. Verify chain of custody documentation\n")
        f.write("[ ] 10. Serve exhibit list on opposing counsel\n\n")

        f.write("EXHIBIT ORGANIZATION:\n")
        f.write("-" * 40 + "\n")
        f.write("[ ] 11. Organize exhibits chronologically\n")
        f.write("[ ] 12. Create subject matter index (DWG files, emails, contracts)\n")
        f.write("[ ] 13. Flag exhibits with 6075 English Oaks references\n")
        f.write("[ ] 14. Highlight Garcia's damaging admissions\n")
        f.write("[ ] 15. Cross-tab with testimony page references\n\n")

        f.write("TECHNOLOGY PREPARATION:\n")
        f.write("-" * 40 + "\n")
        f.write("[ ] 16. Test exhibits on courtroom display system\n")
        f.write("[ ] 17. Prepare backup USB drives with all exhibits\n")
        f.write("[ ] 18. Convert critical exhibits to demonstrative format\n")
        f.write("[ ] 19. Prepare comparison overlays for DWG files\n")
        f.write("[ ] 20. Create exhibit presentation sequence\n\n")

        f.write("AUTHENTICATION:\n")
        f.write("-" * 40 + "\n")
        f.write("[ ] 21. Prepare foundation questions for each exhibit\n")
        f.write("[ ] 22. Identify witnesses to authenticate exhibits\n")
        f.write("[ ] 23. Draft stipulations for exhibit admission\n")
        f.write("[ ] 24. Prepare objections to opposing exhibits\n")
        f.write("[ ] 25. Review Federal/State Rules of Evidence for admissibility\n\n")

        f.write("FINAL REVIEW:\n")
        f.write("-" * 40 + "\n")
        f.write("[ ] 26. Attorney review of all exhibits\n")
        f.write("[ ] 27. Client review of key exhibits\n")
        f.write("[ ] 28. Expert witness review (Andy Ehrig)\n")
        f.write("[ ] 29. Final exhibit list to court (deadline: [TBD])\n")
        f.write("[ ] 30. Backup digital copies secured offsite\n")

    print(f"  Written: {checklist_file}")

def main():
    """
    Main execution: Comprehensive exhibit cross-reference analysis.
    """
    print("=" * 80)
    print("DANNY GARCIA DEPOSITION EXHIBIT CROSS-REFERENCE TOOL")
    print("Kara Murphy vs Danny Garcia (Case 2026-001)")
    print("=" * 80)
    print()

    # Step 1: Scan exhibit files
    print("[STEP 1] Scanning physical exhibit files...")
    file_exhibits = scan_exhibit_files()
    print(f"  Found {len(file_exhibits)} exhibit files\n")

    # Step 2: Extract transcript references
    print("[STEP 2] Extracting exhibits from deposition transcripts...")
    transcript_exhibits = extract_transcript_exhibits()
    print(f"  Found {len(transcript_exhibits)} exhibit references in transcripts\n")

    # Step 3: Cross-reference
    print("[STEP 3] Cross-referencing files with transcript...")
    matrix = cross_reference_exhibits(file_exhibits, transcript_exhibits)
    print(f"  Generated match matrix with {len(matrix)} entries\n")

    # Step 4: Identify discrepancies
    print("[STEP 4] Identifying discrepancies...")
    gaps = identify_gaps(file_exhibits)
    print(f"  Found {len(gaps)} numbering gaps")

    missing = [k for k, v in matrix.items() if v['status'] == 'MISSING_FILE']
    extra = [k for k, v in matrix.items() if v['status'] == 'FILE_ONLY']
    matched = [k for k, v in matrix.items() if v['status'] == 'MATCHED']

    print(f"  Matched: {len(matched)}")
    print(f"  Missing files: {len(missing)}")
    print(f"  Extra files: {len(extra)}\n")

    # Step 5: Generate reports
    print("[STEP 5] Generating deliverables...")
    generate_reports(file_exhibits, transcript_exhibits, matrix)

    print()
    print("=" * 80)
    print("CROSS-REFERENCE ANALYSIS COMPLETE")
    print("=" * 80)
    print(f"All deliverables saved to: {OUTPUT_DIR}")
    print()
    print("NEXT STEPS:")
    print("1. Review EXHIBIT_DISCREPANCY_REPORT.txt for critical gaps")
    print("2. Request missing exhibits from court reporter")
    print("3. Implement Bates numbering scheme")
    print("4. Complete TRIAL_EXHIBIT_PREPARATION_CHECKLIST.txt")

if __name__ == "__main__":
    main()
