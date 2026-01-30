#!/usr/bin/env python3
"""
TRIAL EXHIBIT ORGANIZER
Kara Murphy vs Danny Garcia (Case 2026-001)

Organizes all 1,040 documents by litigation topic for efficient trial presentation.
Creates topic-based exhibit numbering, witness examination roadmaps, and trial binders.
"""

import csv
import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict
import re

# Paths
CASE_DIR = Path("//adam/DataPool/Projects/2026-001_Kara_Murphy_vs_Danny_Garcia")
CATALOG_DIR = CASE_DIR / "DOCUMENT_CATALOG"
TRIAL_DIR = CASE_DIR / "TRIAL_EXHIBITS"

# Trial topic definitions
TRIAL_TOPICS = {
    'AMENITIES': {
        'name': 'Design Scope Amenities',
        'description': 'Primary smoking gun - Lane.rvt with amenities vs Lane.0024.rvt without',
        'prefix': 'A',
        'keywords': [
            'amenities', 'amenity', 'pool', 'bbq', 'outdoor kitchen', 'waterfall',
            'fireplace', 'retaining wall', 'lane.rvt', 'lane.0024', 'viking',
            'pavilion', 'grill', 'seating', 'landscape', 'naples 2'
        ]
    },
    'TIMELINE': {
        'name': 'Timeline Manipulation',
        'description': 'Evidence tampering - RVT build version, DWG timestamp destruction',
        'prefix': 'T',
        'keywords': [
            'timestamp', 'build version', '20210224', '20210921', 'modified',
            'tamper', 'forensic', 'tdindwg', 'tdupdate', 'crc', 'hash',
            'metadata', 'backup', 'version', 'september 2021', 'february 2021'
        ]
    },
    'FOUNDATION': {
        'name': 'Foundation/Structural Issues',
        'description': 'Engineering reports, structural design changes, expert analysis',
        'prefix': 'F',
        'keywords': [
            'foundation', 'structural', 'engineering', 'soil', 'geotechnical',
            'bearing', 'footing', 'pier', 'survey', 'elevation', 'grade',
            'retaining', 'wall', 'erosion', 'stability'
        ]
    },
    'FINANCIAL': {
        'name': 'Financial Records',
        'description': 'Invoices, payments, scope agreements, change orders',
        'prefix': 'FIN',
        'keywords': [
            'invoice', 'payment', 'cost', 'price', 'contract', 'agreement',
            'scope', 'change order', 'billing', 'compensation', 'fee'
        ]
    },
    'COMMUNICATION': {
        'name': 'Communication & Knowledge',
        'description': 'Consciousness of guilt - email chains, meeting notes, concealment',
        'prefix': 'COM',
        'keywords': [
            'email', 'correspondence', 'letter', 'meeting', 'discussion',
            'garcia', 'murphy', 'caron', 'beauchamp', 'ehrig', 'conversation',
            'call', 'message', 'text'
        ]
    },
    'GENERAL': {
        'name': 'General/Supporting',
        'description': 'Permits, surveys, background documents',
        'prefix': 'G',
        'keywords': []  # Catch-all for documents not matching other topics
    }
}


def load_document_catalog() -> List[Dict]:
    """Load the complete document catalog."""
    catalog_file = CATALOG_DIR / "CASE_DOCUMENT_INDEX.csv"
    documents = []

    with open(catalog_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            documents.append(row)

    return documents


def tag_document_by_topic(doc: Dict) -> List[str]:
    """
    Tag document with all applicable trial topics.
    Returns list of topic IDs (can be multi-tagged).
    """
    topics = []

    # Create searchable text from filename and path
    searchable = (
        doc['file_name'].lower() + " " +
        doc['full_path'].lower() + " " +
        doc.get('subject', '').lower()
    )

    # Check each topic's keywords
    for topic_id, topic_info in TRIAL_TOPICS.items():
        if topic_id == 'GENERAL':
            continue  # Skip general for now (catch-all)

        keywords = topic_info['keywords']
        if any(keyword in searchable for keyword in keywords):
            topics.append(topic_id)

    # If no topics matched, assign to GENERAL
    if not topics:
        topics.append('GENERAL')

    return topics


def categorize_documents(documents: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Categorize all documents by primary trial topic.
    For multi-tagged docs, assign to first (most important) topic.
    """
    categorized = defaultdict(list)

    for doc in documents:
        topics = tag_document_by_topic(doc)
        primary_topic = topics[0]  # First topic is primary

        # Add all topics to document metadata
        doc['trial_topics'] = ', '.join(topics)
        doc['primary_topic'] = primary_topic

        categorized[primary_topic].append(doc)

    return categorized


def assign_exhibit_numbers(categorized_docs: Dict[str, List[Dict]]) -> List[Dict]:
    """
    Assign sequential exhibit numbers within each topic.
    Format: PREFIX-NNN (e.g., A-001, T-042, FIN-007)
    """
    all_exhibits = []

    for topic_id in ['AMENITIES', 'TIMELINE', 'FOUNDATION', 'FINANCIAL', 'COMMUNICATION', 'GENERAL']:
        docs = categorized_docs.get(topic_id, [])
        prefix = TRIAL_TOPICS[topic_id]['prefix']

        # Sort documents for consistent numbering
        # Priority: 1) Deposition exhibits, 2) Design files, 3) Emails, 4) Others
        def sort_priority(doc):
            category = doc['category']
            if category == 'Deposition/Transcript':
                return (0, doc['file_name'])
            elif category in ['Design Files (DWG/CAD)', 'Design Files (Revit)']:
                return (1, doc['file_name'])
            elif category in ['Email', 'Correspondence']:
                return (2, doc['file_name'])
            else:
                return (3, doc['file_name'])

        sorted_docs = sorted(docs, key=sort_priority)

        # Assign numbers
        for idx, doc in enumerate(sorted_docs, start=1):
            doc['exhibit_number'] = f"{prefix}-{idx:03d}"
            all_exhibits.append(doc)

    return all_exhibits


def create_topic_indexes(all_exhibits: List[Dict]):
    """Create separate CSV indexes for each trial topic."""
    TRIAL_DIR.mkdir(parents=True, exist_ok=True)

    for topic_id, topic_info in TRIAL_TOPICS.items():
        topic_docs = [doc for doc in all_exhibits if doc['primary_topic'] == topic_id]

        if not topic_docs:
            continue

        output_file = TRIAL_DIR / f"EXHIBITS_{topic_info['name'].upper().replace('/', '_').replace(' ', '_')}.csv"

        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['exhibit_number', 'file_name', 'category', 'file_type',
                         'trial_topics', 'full_path', 'file_size_mb', 'modified_date']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for doc in topic_docs:
                writer.writerow({k: doc.get(k, '') for k in fieldnames})

        print(f"  Created: {output_file.name} ({len(topic_docs)} exhibits)")


def create_master_exhibit_index(all_exhibits: List[Dict]):
    """Create master index of all exhibits with topic tags."""
    TRIAL_DIR.mkdir(parents=True, exist_ok=True)
    output_file = TRIAL_DIR / "TRIAL_EXHIBIT_TOPIC_INDEX.csv"

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['exhibit_number', 'primary_topic', 'trial_topics', 'file_name',
                     'category', 'file_type', 'full_path', 'file_size_mb', 'modified_date']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for doc in all_exhibits:
            writer.writerow({k: doc.get(k, '') for k in fieldnames})

    print(f"  Created: {output_file.name} ({len(all_exhibits)} total exhibits)")


def create_trial_binder_structure():
    """Create organization guide for trial binders."""
    output_file = TRIAL_DIR / "TRIAL_BINDER_ORGANIZATION.txt"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("TRIAL BINDER ORGANIZATION GUIDE\n")
        f.write("Kara Murphy vs Danny Garcia (Case 2026-001)\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("BINDER STRUCTURE:\n")
        f.write("-" * 40 + "\n\n")

        for idx, (topic_id, topic_info) in enumerate(TRIAL_TOPICS.items(), start=1):
            f.write(f"BINDER {idx}: {topic_info['name'].upper()}\n")
            f.write(f"Prefix: {topic_info['prefix']}\n")
            f.write(f"Description: {topic_info['description']}\n\n")

            f.write("  Tabs:\n")
            f.write("    [1] Overview Summary\n")
            f.write("    [2] Deposition Exhibits\n")
            f.write("    [3] Design Files / Technical Documents\n")
            f.write("    [4] Correspondence / Emails\n")
            f.write("    [5] Expert Reports / Analysis\n")
            f.write("    [6] Supporting Documents\n\n")

        f.write("=" * 80 + "\n")
        f.write("TRIAL DAY ORGANIZATION\n")
        f.write("=" * 80 + "\n\n")

        f.write("DAY 1: Opening Statement & Foundation\n")
        f.write("  Exhibits: G-001 to G-050 (General background)\n")
        f.write("  Witnesses: Expert qualification\n\n")

        f.write("DAY 2: Design Scope Amenities (Primary Claim)\n")
        f.write("  Exhibits: A-001 to A-150 (Amenities evidence)\n")
        f.write("  Witnesses: Expert witness on RVT analysis\n\n")

        f.write("DAY 3: Timeline Manipulation (Evidence Tampering)\n")
        f.write("  Exhibits: T-001 to T-100 (Timestamp forensics)\n")
        f.write("  Witnesses: Expert witness continued\n\n")

        f.write("DAY 4: Foundation Issues & Financial Records\n")
        f.write("  Exhibits: F-001 to F-050, FIN-001 to FIN-075\n")
        f.write("  Witnesses: Engineering expert, financial witness\n\n")

        f.write("DAY 5: Communication & Consciousness of Guilt\n")
        f.write("  Exhibits: COM-001 to COM-150 (Email chains)\n")
        f.write("  Witnesses: Parties, rebuttal\n\n")

    print(f"  Created: {output_file.name}")


def create_witness_examination_roadmap(all_exhibits: List[Dict]):
    """Create exhibit roadmap for each witness examination."""
    output_file = TRIAL_DIR / "WITNESS_EXAMINATION_ROADMAP.txt"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("WITNESS EXAMINATION ROADMAP\n")
        f.write("Exhibit Introduction Plan by Witness\n")
        f.write("=" * 80 + "\n\n")

        f.write("EXPERT WITNESS (FORENSIC ANALYST)\n")
        f.write("Estimated Duration: 4 hours direct, 2 hours cross\n")
        f.write("-" * 40 + "\n\n")

        # Amenities exhibits
        amenities = [doc for doc in all_exhibits if doc['primary_topic'] == 'AMENITIES']
        f.write(f"Phase 1: Design Scope Amenities ({len(amenities[:20])} exhibits)\n")
        for doc in amenities[:20]:
            f.write(f"  {doc['exhibit_number']}: {doc['file_name']}\n")
        f.write("\n")

        # Timeline exhibits
        timeline = [doc for doc in all_exhibits if doc['primary_topic'] == 'TIMELINE']
        f.write(f"Phase 2: Timeline Manipulation ({len(timeline[:15])} exhibits)\n")
        for doc in timeline[:15]:
            f.write(f"  {doc['exhibit_number']}: {doc['file_name']}\n")
        f.write("\n")

        # Foundation exhibits
        foundation = [doc for doc in all_exhibits if doc['primary_topic'] == 'FOUNDATION']
        f.write(f"Phase 3: Foundation Issues ({len(foundation[:10])} exhibits)\n")
        for doc in foundation[:10]:
            f.write(f"  {doc['exhibit_number']}: {doc['file_name']}\n")
        f.write("\n")

        f.write("DANNY GARCIA (DEFENDANT)\n")
        f.write("Estimated Duration: 2 hours direct, 1 hour cross\n")
        f.write("-" * 40 + "\n\n")

        # Deposition exhibits
        depo_exhibits = [doc for doc in all_exhibits if 'deposition' in doc['category'].lower()]
        f.write(f"Impeachment with Deposition ({len(depo_exhibits[:10])} exhibits)\n")
        for doc in depo_exhibits[:10]:
            f.write(f"  {doc['exhibit_number']}: {doc['file_name']}\n")
        f.write("\n")

        # Communication exhibits
        comm = [doc for doc in all_exhibits if doc['primary_topic'] == 'COMMUNICATION']
        f.write(f"Email Correspondence ({len(comm[:15])} exhibits)\n")
        for doc in comm[:15]:
            f.write(f"  {doc['exhibit_number']}: {doc['file_name']}\n")
        f.write("\n")

    print(f"  Created: {output_file.name}")


def create_exhibits_ready_for_print(all_exhibits: List[Dict]):
    """Create checklist of exhibits ready for printing/presentation."""
    output_file = TRIAL_DIR / "EXHIBITS_READY_FOR_PRINT.csv"

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['exhibit_number', 'primary_topic', 'file_name', 'print_status',
                     'digital_only', 'redaction_required', 'notes']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for doc in all_exhibits:
            # Determine print status
            file_type = doc['file_type'].lower()
            digital_only = 'dwg' in file_type or 'rvt' in file_type or 'revit' in file_type

            writer.writerow({
                'exhibit_number': doc['exhibit_number'],
                'primary_topic': doc['primary_topic'],
                'file_name': doc['file_name'],
                'print_status': 'PENDING',
                'digital_only': 'YES' if digital_only else 'NO',
                'redaction_required': 'TBD',
                'notes': 'Digital presentation required' if digital_only else ''
            })

    print(f"  Created: {output_file.name} (Print preparation checklist)")


def create_exhibit_retrieval_system():
    """Create quick reference guide for retrieving exhibits during trial."""
    output_file = TRIAL_DIR / "EXHIBIT_RETRIEVAL_SYSTEM.txt"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("EXHIBIT RETRIEVAL QUICK REFERENCE\n")
        f.write("For use during trial to quickly locate exhibits\n")
        f.write("=" * 80 + "\n\n")

        f.write("EXHIBIT NUMBER SCHEME:\n")
        f.write("-" * 40 + "\n")
        for topic_id, topic_info in TRIAL_TOPICS.items():
            f.write(f"{topic_info['prefix']:4s} = {topic_info['name']}\n")
        f.write("\n")

        f.write("BINDER LOCATIONS:\n")
        f.write("-" * 40 + "\n")
        f.write("Binder 1: A-001 to A-150 (Amenities)\n")
        f.write("Binder 2: T-001 to T-100 (Timeline)\n")
        f.write("Binder 3: F-001 to F-050 (Foundation)\n")
        f.write("Binder 4: FIN-001 to FIN-075 (Financial)\n")
        f.write("Binder 5: COM-001 to COM-150 (Communication)\n")
        f.write("Binder 6: G-001 to G-050 (General)\n\n")

        f.write("CRITICAL SMOKING GUN EXHIBITS:\n")
        f.write("-" * 40 + "\n")
        f.write("A-001: Lane.rvt (WITH amenities)\n")
        f.write("A-002: Lane.0024.rvt (WITHOUT amenities)\n")
        f.write("T-001: Build version forensic report\n")
        f.write("T-002: Timeline impossibility diagram\n")
        f.write("COM-001: Garcia email re: amenity removal\n\n")

        f.write("DIGITAL PRESENTATION EXHIBITS:\n")
        f.write("-" * 40 + "\n")
        f.write("These require laptop/projector:\n")
        f.write("- All .dwg files (AutoCAD)\n")
        f.write("- All .rvt files (Revit)\n")
        f.write("- Forensic tool screenshots\n")
        f.write("- Timeline animations\n\n")

        f.write("DEPOSITION IMPEACHMENT INDEX:\n")
        f.write("-" * 40 + "\n")
        f.write("Danny Garcia Transcript: 7/28/25 & 7/29/25\n")
        f.write("Page references to amenity discussions:\n")
        f.write("  - Page XX: Denial of knowledge\n")
        f.write("  - Page XX: Contradictory statement\n")
        f.write("  - Page XX: Admission of access to files\n\n")

    print(f"  Created: {output_file.name}")


def generate_statistics_report(categorized_docs: Dict[str, List[Dict]]):
    """Generate summary statistics for trial exhibit organization."""
    output_file = TRIAL_DIR / "TRIAL_EXHIBIT_STATISTICS.txt"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("TRIAL EXHIBIT ORGANIZATION STATISTICS\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        total_docs = sum(len(docs) for docs in categorized_docs.values())
        f.write(f"TOTAL DOCUMENTS ORGANIZED: {total_docs}\n\n")

        f.write("DOCUMENTS BY TRIAL TOPIC:\n")
        f.write("-" * 40 + "\n")
        for topic_id, topic_info in TRIAL_TOPICS.items():
            count = len(categorized_docs.get(topic_id, []))
            percentage = (count / total_docs * 100) if total_docs > 0 else 0
            f.write(f"{topic_info['name']:30s}: {count:4d} ({percentage:5.1f}%)\n")
        f.write("\n")

        # Category breakdown within each topic
        for topic_id, topic_info in TRIAL_TOPICS.items():
            docs = categorized_docs.get(topic_id, [])
            if not docs:
                continue

            f.write(f"\n{topic_info['name'].upper()}\n")
            f.write("-" * 40 + "\n")

            category_counts = defaultdict(int)
            for doc in docs:
                category_counts[doc['category']] += 1

            for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {category:30s}: {count:4d}\n")

    print(f"  Created: {output_file.name}")


def main():
    """Main execution for trial exhibit organization."""
    print("=" * 80)
    print("TRIAL EXHIBIT ORGANIZER")
    print("Kara Murphy vs Danny Garcia (Case 2026-001)")
    print("=" * 80)
    print()

    # Load catalog
    print("Loading document catalog...")
    documents = load_document_catalog()
    print(f"  Loaded {len(documents)} documents")
    print()

    # Categorize by topic
    print("Categorizing documents by trial topic...")
    categorized = categorize_documents(documents)
    for topic_id, docs in categorized.items():
        topic_name = TRIAL_TOPICS[topic_id]['name']
        print(f"  {topic_name:30s}: {len(docs):4d} documents")
    print()

    # Assign exhibit numbers
    print("Assigning exhibit numbers...")
    all_exhibits = assign_exhibit_numbers(categorized)
    print(f"  Assigned {len(all_exhibits)} exhibit numbers")
    print()

    # Generate deliverables
    print("Generating trial exhibit deliverables...")
    create_master_exhibit_index(all_exhibits)
    create_topic_indexes(all_exhibits)
    create_trial_binder_structure()
    create_witness_examination_roadmap(all_exhibits)
    create_exhibits_ready_for_print(all_exhibits)
    create_exhibit_retrieval_system()
    generate_statistics_report(categorized)
    print()

    print("=" * 80)
    print("TRIAL EXHIBIT ORGANIZATION COMPLETE")
    print("=" * 80)
    print(f"All deliverables saved to: {TRIAL_DIR}")
    print()
    print("DELIVERABLES:")
    print("  1. TRIAL_EXHIBIT_TOPIC_INDEX.csv (Master index)")
    print("  2. EXHIBITS_[TOPIC].csv (6 topic-specific indexes)")
    print("  3. TRIAL_BINDER_ORGANIZATION.txt (Physical binder guide)")
    print("  4. WITNESS_EXAMINATION_ROADMAP.txt (Exhibit introduction plan)")
    print("  5. EXHIBITS_READY_FOR_PRINT.csv (Print preparation checklist)")
    print("  6. EXHIBIT_RETRIEVAL_SYSTEM.txt (Quick reference guide)")
    print("  7. TRIAL_EXHIBIT_STATISTICS.txt (Organization summary)")


if __name__ == "__main__":
    main()
