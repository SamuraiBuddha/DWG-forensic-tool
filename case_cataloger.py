#!/usr/bin/env python3
"""
Comprehensive Document Cataloger for Kara Murphy vs Danny Garcia Case
Generates litigation-ready document index with metadata, relevance scoring, and pattern analysis.
"""

import os
import csv
import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Set
from collections import defaultdict
import re

# Case directory
CASE_DIR = Path("//adam/DataPool/Projects/2026-001_Kara_Murphy_vs_Danny_Garcia")
OUTPUT_DIR = CASE_DIR / "DOCUMENT_CATALOG"

# File type mappings
DOCUMENT_EXTENSIONS = {
    'pdf': 'PDF',
    'docx': 'Word Document',
    'doc': 'Word Document (Legacy)',
    'xlsx': 'Excel Spreadsheet',
    'xls': 'Excel Spreadsheet (Legacy)',
    'msg': 'Outlook Email',
    'eml': 'Email',
    'dwg': 'AutoCAD Drawing',
    'rvt': 'Revit Model',
    'jpg': 'JPEG Image',
    'jpeg': 'JPEG Image',
    'png': 'PNG Image',
    'tif': 'TIFF Image',
    'tiff': 'TIFF Image',
    'txt': 'Text File',
    'csv': 'CSV Data',
    'zip': 'ZIP Archive',
    'pst': 'Outlook Archive',
    'mpp': 'MS Project',
    'vsd': 'Visio Diagram',
    'pptx': 'PowerPoint',
    'ppt': 'PowerPoint (Legacy)',
}

# Relevance keywords
HIGH_RELEVANCE_KEYWORDS = [
    '6075', 'english oaks', 'naples 2', 'naples2', 'amenities', 'pool',
    'outdoor kitchen', 'waterfall', 'fireplace', 'retaining wall',
    'fraud', 'tamper', 'modified', 'backdated', 'smoking gun'
]

MEDIUM_RELEVANCE_KEYWORDS = [
    'garcia', 'murphy', 'caron', 'beauchamp', 'andy', 'danny', 'kara',
    'deposition', 'transcript', 'exhibit', 'correspondence', 'contract',
    'invoice', 'payment', 'scope', 'change order'
]

# Document categories
def categorize_document(file_path: str, file_name: str) -> str:
    """Categorize document based on path and filename."""
    lower_path = file_path.lower()
    lower_name = file_name.lower()

    if 'deposition' in lower_path or 'transcript' in lower_path:
        return 'Deposition/Transcript'
    elif 'correspondence' in lower_path or 'letter' in lower_name or 'email' in lower_name:
        return 'Correspondence'
    elif 'contract' in lower_name or 'agreement' in lower_name or 'engagement' in lower_name:
        return 'Contract/Agreement'
    elif 'forensic' in lower_name or 'analysis' in lower_name or 'report' in lower_name:
        return 'Forensic Report/Analysis'
    elif 'dwg' in file_path.lower() or 'drawing' in lower_path or file_name.endswith('.dwg'):
        return 'Design Files (DWG/CAD)'
    elif 'rvt' in file_path.lower() or 'revit' in lower_path or file_name.endswith('.rvt'):
        return 'Design Files (Revit)'
    elif 'permit' in lower_path or 'permit' in lower_name:
        return 'Permits/Approvals'
    elif 'survey' in lower_path or 'survey' in lower_name:
        return 'Survey Documents'
    elif 'photo' in lower_path or 'image' in lower_path or file_name.endswith(('.jpg', '.jpeg', '.png', '.tif')):
        return 'Photographs/Images'
    elif 'invoice' in lower_name or 'payment' in lower_name:
        return 'Financial Records'
    elif 'exhibit' in lower_path or 'exhibit' in lower_name:
        return 'Exhibits'
    elif file_name.endswith('.msg') or file_name.endswith('.eml'):
        return 'Email'
    else:
        return 'Other'

def score_relevance(file_path: str, file_name: str) -> str:
    """Score document relevance to 6075 English Oaks case."""
    combined = (file_path + " " + file_name).lower()

    # HIGH: Direct reference to 6075 English Oaks
    for keyword in HIGH_RELEVANCE_KEYWORDS:
        if keyword in combined:
            return 'HIGH'

    # MEDIUM: References parties or case-related terms
    for keyword in MEDIUM_RELEVANCE_KEYWORDS:
        if keyword in combined:
            return 'MEDIUM'

    return 'LOW'

def extract_metadata(file_path: Path) -> Dict:
    """Extract comprehensive metadata from a file."""
    try:
        stat = file_path.stat()

        # Get timestamps
        created = datetime.datetime.fromtimestamp(stat.st_ctime)
        modified = datetime.datetime.fromtimestamp(stat.st_mtime)

        # Get file type
        ext = file_path.suffix.lower().lstrip('.')
        file_type = DOCUMENT_EXTENSIONS.get(ext, f'Unknown ({ext.upper() if ext else "NO EXTENSION"})')

        # Infer subject from filename
        subject = infer_subject(file_path.name)

        # Categorize
        category = categorize_document(str(file_path), file_path.name)

        # Score relevance
        relevance = score_relevance(str(file_path), file_path.name)

        return {
            'full_path': str(file_path),
            'file_name': file_path.name,
            'file_type': file_type,
            'extension': ext,
            'file_size_bytes': stat.st_size,
            'file_size_mb': round(stat.st_size / (1024 * 1024), 2),
            'created_date': created.strftime('%Y-%m-%d %H:%M:%S'),
            'modified_date': modified.strftime('%Y-%m-%d %H:%M:%S'),
            'subject': subject,
            'relevance': relevance,
            'category': category,
        }
    except Exception as e:
        return {
            'full_path': str(file_path),
            'file_name': file_path.name,
            'file_type': 'ERROR',
            'extension': '',
            'file_size_bytes': 0,
            'file_size_mb': 0,
            'created_date': 'N/A',
            'modified_date': 'N/A',
            'subject': f'ERROR: {str(e)}',
            'relevance': 'LOW',
            'category': 'Other',
        }

def infer_subject(filename: str) -> str:
    """Infer document subject from filename."""
    # Remove extension
    name = Path(filename).stem

    # Common patterns
    if 'engagement' in name.lower():
        return 'Legal Engagement Letter'
    elif 'deposition' in name.lower() or 'transcript' in name.lower():
        return 'Deposition Transcript'
    elif 'correspondence' in name.lower():
        return 'Legal Correspondence'
    elif 'exhibit' in name.lower():
        return 'Case Exhibit'
    elif '6075' in name or 'english oaks' in name.lower():
        return '6075 English Oaks Project Document'
    elif 'permit' in name.lower():
        return 'Building Permit'
    elif 'drawing' in name.lower() or 'autocad' in name.lower():
        return 'Architectural Drawing'
    else:
        # Clean up filename for display
        cleaned = name.replace('_', ' ').replace('-', ' ')
        return cleaned[:100]  # Truncate long names

def scan_directory(base_path: Path) -> List[Dict]:
    """Recursively scan directory and collect file metadata."""
    documents = []
    errors = []

    try:
        for item in base_path.rglob('*'):
            # Skip DOCUMENT_CATALOG output directory
            if 'DOCUMENT_CATALOG' in str(item):
                continue

            if item.is_file():
                metadata = extract_metadata(item)
                documents.append(metadata)

                if metadata['file_type'] == 'ERROR':
                    errors.append(metadata['full_path'])

    except Exception as e:
        print(f"Error scanning directory: {e}")

    return documents, errors

def generate_directory_map(base_path: Path, output_file: Path):
    """Generate hierarchical directory structure visualization."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("CASE DIRECTORY STRUCTURE MAP\n")
        f.write("=" * 80 + "\n")
        f.write(f"Base Path: {base_path}\n")
        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")

        def write_tree(path: Path, prefix: str = "", is_last: bool = True):
            """Recursive tree writer."""
            if 'DOCUMENT_CATALOG' in str(path):
                return

            try:
                items = sorted(path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))

                for i, item in enumerate(items):
                    is_last_item = (i == len(items) - 1)
                    current_prefix = "└── " if is_last_item else "├── "

                    if item.is_dir():
                        f.write(f"{prefix}{current_prefix}{item.name}/\n")
                        extension = "    " if is_last_item else "│   "
                        write_tree(item, prefix + extension, is_last_item)
                    else:
                        size_mb = item.stat().st_size / (1024 * 1024)
                        f.write(f"{prefix}{current_prefix}{item.name} ({size_mb:.2f} MB)\n")
            except PermissionError:
                f.write(f"{prefix}[PERMISSION DENIED]\n")

        f.write(f"{base_path.name}/\n")
        write_tree(base_path)

def generate_statistics(documents: List[Dict], output_file: Path):
    """Generate comprehensive statistics report."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("DOCUMENT SUMMARY STATISTICS\n")
        f.write("=" * 80 + "\n")
        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")

        # Overall counts
        f.write(f"TOTAL DOCUMENTS: {len(documents)}\n")
        total_size = sum(d['file_size_bytes'] for d in documents)
        f.write(f"TOTAL STORAGE: {total_size / (1024**3):.2f} GB\n\n")

        # By category
        f.write("DOCUMENTS BY CATEGORY:\n")
        f.write("-" * 40 + "\n")
        category_counts = defaultdict(int)
        for doc in documents:
            category_counts[doc['category']] += 1
        for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
            f.write(f"  {cat}: {count}\n")

        # By relevance
        f.write("\nDOCUMENTS BY RELEVANCE:\n")
        f.write("-" * 40 + "\n")
        relevance_counts = defaultdict(int)
        for doc in documents:
            relevance_counts[doc['relevance']] += 1
        for rel in ['HIGH', 'MEDIUM', 'LOW']:
            count = relevance_counts.get(rel, 0)
            f.write(f"  {rel}: {count}\n")

        # By file type
        f.write("\nDOCUMENTS BY FILE TYPE:\n")
        f.write("-" * 40 + "\n")
        type_counts = defaultdict(int)
        for doc in documents:
            type_counts[doc['file_type']] += 1
        for ftype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            f.write(f"  {ftype}: {count}\n")

        # Date range
        f.write("\nDATE RANGE:\n")
        f.write("-" * 40 + "\n")
        valid_dates = [d['created_date'] for d in documents if d['created_date'] != 'N/A']
        if valid_dates:
            earliest = min(valid_dates)
            latest = max(valid_dates)
            f.write(f"  Earliest Created: {earliest}\n")
            f.write(f"  Latest Created: {latest}\n")

def generate_key_findings(documents: List[Dict], output_file: Path):
    """Analyze patterns and generate key findings."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("KEY FINDINGS SUMMARY\n")
        f.write("=" * 80 + "\n")
        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")

        # Critical documents
        f.write("CRITICAL DOCUMENTS (HIGH RELEVANCE):\n")
        f.write("-" * 40 + "\n")
        high_rel = [d for d in documents if d['relevance'] == 'HIGH']
        f.write(f"Total: {len(high_rel)}\n\n")

        for doc in sorted(high_rel, key=lambda x: x['category']):
            f.write(f"  [{doc['category']}] {doc['file_name']}\n")
            f.write(f"    Path: {doc['full_path']}\n")
            f.write(f"    Modified: {doc['modified_date']}\n\n")

        # Extract parties mentioned
        f.write("\nPARTIES/ENTITIES MENTIONED:\n")
        f.write("-" * 40 + "\n")
        parties = set()
        for doc in documents:
            text = (doc['full_path'] + " " + doc['file_name']).lower()
            if 'garcia' in text:
                parties.add('Danny Garcia')
            if 'murphy' in text or 'kara' in text:
                parties.add('Kara Murphy')
            if 'caron' in text:
                parties.add('Caron')
            if 'beauchamp' in text:
                parties.add('Beauchamp')
            if 'andy' in text or 'ehrig' in text:
                parties.add('Andy Ehrig (Architect)')

        for party in sorted(parties):
            f.write(f"  - {party}\n")

        # Document gaps analysis
        f.write("\nTIMELINE ANALYSIS:\n")
        f.write("-" * 40 + "\n")

        # Parse dates
        date_objects = []
        for doc in documents:
            if doc['created_date'] != 'N/A':
                try:
                    date_objects.append(datetime.datetime.strptime(doc['created_date'], '%Y-%m-%d %H:%M:%S'))
                except:
                    pass

        if date_objects:
            date_objects.sort()
            f.write(f"  Earliest Document: {date_objects[0].strftime('%Y-%m-%d')}\n")
            f.write(f"  Latest Document: {date_objects[-1].strftime('%Y-%m-%d')}\n")
            f.write(f"  Span: {(date_objects[-1] - date_objects[0]).days} days\n\n")

            # Identify gaps (periods with no documents)
            f.write("  Potential Documentation Gaps (30+ days with no files):\n")
            for i in range(len(date_objects) - 1):
                gap = (date_objects[i+1] - date_objects[i]).days
                if gap > 30:
                    f.write(f"    {date_objects[i].strftime('%Y-%m-%d')} to {date_objects[i+1].strftime('%Y-%m-%d')} ({gap} days)\n")

        # Storage locations mentioned
        f.write("\nSTORAGE REFERENCES DETECTED:\n")
        f.write("-" * 40 + "\n")
        storage_refs = set()
        for doc in documents:
            text = (doc['full_path'] + " " + doc['file_name']).lower()
            if 'e:' in text or 'e drive' in text:
                storage_refs.add('E: Drive')
            if 'dropbox' in text:
                storage_refs.add('Dropbox')
            if 'onedrive' in text:
                storage_refs.add('OneDrive')
            if 'icloud' in text:
                storage_refs.add('iCloud')

        if storage_refs:
            for ref in sorted(storage_refs):
                f.write(f"  - {ref}\n")
        else:
            f.write("  [None detected]\n")

def main():
    """Main cataloging execution."""
    print("=" * 80)
    print("CASE DOCUMENT CATALOGER")
    print("Kara Murphy vs Danny Garcia (Case 2026-001)")
    print("=" * 80)
    print()

    # Verify paths
    if not CASE_DIR.exists():
        print(f"ERROR: Case directory not found: {CASE_DIR}")
        return

    OUTPUT_DIR.mkdir(exist_ok=True)
    print(f"Source: {CASE_DIR}")
    print(f"Output: {OUTPUT_DIR}")
    print()

    # Scan directory
    print("Scanning directory structure...")
    documents, errors = scan_directory(CASE_DIR)
    print(f"Found {len(documents)} documents")
    if errors:
        print(f"WARNING: {len(errors)} files had errors")
    print()

    # Generate CASE_DOCUMENT_INDEX.csv
    print("Generating CASE_DOCUMENT_INDEX.csv...")
    index_file = OUTPUT_DIR / "CASE_DOCUMENT_INDEX.csv"
    with open(index_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['full_path', 'file_name', 'file_type', 'extension',
                      'file_size_bytes', 'file_size_mb', 'created_date',
                      'modified_date', 'subject', 'relevance', 'category']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for doc in documents:
            writer.writerow(doc)
    print(f"  Written: {index_file}")

    # Generate DOCUMENT_DIRECTORY_MAP.txt
    print("Generating DOCUMENT_DIRECTORY_MAP.txt...")
    map_file = OUTPUT_DIR / "DOCUMENT_DIRECTORY_MAP.txt"
    generate_directory_map(CASE_DIR, map_file)
    print(f"  Written: {map_file}")

    # Generate 6075_ENGLISH_OAKS_DOCUMENTS.csv
    print("Generating 6075_ENGLISH_OAKS_DOCUMENTS.csv...")
    high_rel_file = OUTPUT_DIR / "6075_ENGLISH_OAKS_DOCUMENTS.csv"
    high_rel_docs = [d for d in documents if d['relevance'] == 'HIGH']
    with open(high_rel_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['full_path', 'file_name', 'file_type', 'extension',
                      'file_size_bytes', 'file_size_mb', 'created_date',
                      'modified_date', 'subject', 'category']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for doc in high_rel_docs:
            writer.writerow({k: v for k, v in doc.items() if k != 'relevance'})
    print(f"  Written: {high_rel_file} ({len(high_rel_docs)} HIGH relevance documents)")

    # Generate DOCUMENT_SUMMARY_STATISTICS.txt
    print("Generating DOCUMENT_SUMMARY_STATISTICS.txt...")
    stats_file = OUTPUT_DIR / "DOCUMENT_SUMMARY_STATISTICS.txt"
    generate_statistics(documents, stats_file)
    print(f"  Written: {stats_file}")

    # Generate KEY_FINDINGS_SUMMARY.txt
    print("Generating KEY_FINDINGS_SUMMARY.txt...")
    findings_file = OUTPUT_DIR / "KEY_FINDINGS_SUMMARY.txt"
    generate_key_findings(documents, findings_file)
    print(f"  Written: {findings_file}")

    # Generate CATALOGING_PROCESS_LOG.txt
    print("Generating CATALOGING_PROCESS_LOG.txt...")
    log_file = OUTPUT_DIR / "CATALOGING_PROCESS_LOG.txt"
    with open(log_file, 'w', encoding='utf-8') as f:
        f.write("CATALOGING PROCESS LOG\n")
        f.write("=" * 80 + "\n")
        f.write(f"Execution Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Case Directory: {CASE_DIR}\n")
        f.write(f"Output Directory: {OUTPUT_DIR}\n")
        f.write("=" * 80 + "\n\n")

        f.write("PROCESS SUMMARY:\n")
        f.write(f"  Total Files Scanned: {len(documents)}\n")
        f.write(f"  Successful: {len(documents) - len(errors)}\n")
        f.write(f"  Errors: {len(errors)}\n\n")

        f.write("DELIVERABLES GENERATED:\n")
        f.write("  1. CASE_DOCUMENT_INDEX.csv\n")
        f.write("  2. DOCUMENT_DIRECTORY_MAP.txt\n")
        f.write("  3. 6075_ENGLISH_OAKS_DOCUMENTS.csv\n")
        f.write("  4. DOCUMENT_SUMMARY_STATISTICS.txt\n")
        f.write("  5. KEY_FINDINGS_SUMMARY.txt\n")
        f.write("  6. CATALOGING_PROCESS_LOG.txt (this file)\n\n")

        if errors:
            f.write("FILES WITH ERRORS:\n")
            f.write("-" * 40 + "\n")
            for err in errors:
                f.write(f"  {err}\n")
            f.write("\n")

        f.write("RECOMMENDATIONS:\n")
        f.write("-" * 40 + "\n")
        f.write("  1. Review HIGH relevance documents in 6075_ENGLISH_OAKS_DOCUMENTS.csv\n")
        f.write("  2. Check KEY_FINDINGS_SUMMARY.txt for timeline gaps\n")
        f.write("  3. Verify all critical parties have document representation\n")
        f.write("  4. Cross-reference storage locations (E: drive, cloud) for missing files\n")
        f.write("  5. Ensure deposition exhibits are cataloged\n")

    print(f"  Written: {log_file}")
    print()
    print("=" * 80)
    print("CATALOGING COMPLETE")
    print("=" * 80)
    print(f"All deliverables saved to: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
