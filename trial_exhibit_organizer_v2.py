#!/usr/bin/env python3
"""
TRIAL EXHIBIT ORGANIZER V2
Improved topic categorization using category-based logic + keyword analysis
"""

import csv
import datetime
from pathlib import Path
from typing import Dict, List
from collections import defaultdict

# Paths
CASE_DIR = Path("//adam/DataPool/Projects/2026-001_Kara_Murphy_vs_Danny_Garcia")
CATALOG_DIR = CASE_DIR / "DOCUMENT_CATALOG"
TRIAL_DIR = CASE_DIR / "TRIAL_EXHIBITS"

# Trial topic definitions (same as before)
TRIAL_TOPICS = {
    'AMENITIES': {
        'name': 'Design Scope Amenities',
        'description': 'Primary smoking gun - Lane.rvt with amenities vs Lane.0024.rvt without',
        'prefix': 'A'
    },
    'TIMELINE': {
        'name': 'Timeline Manipulation',
        'description': 'Evidence tampering - RVT build version, DWG timestamp destruction',
        'prefix': 'T'
    },
    'FOUNDATION': {
        'name': 'Foundation/Structural Issues',
        'description': 'Engineering reports, structural design changes, expert analysis',
        'prefix': 'F'
    },
    'FINANCIAL': {
        'name': 'Financial Records',
        'description': 'Invoices, payments, scope agreements, change orders',
        'prefix': 'FIN'
    },
    'COMMUNICATION': {
        'name': 'Communication & Knowledge',
        'description': 'Consciousness of guilt - email chains, meeting notes, concealment',
        'prefix': 'COM'
    },
    'GENERAL': {
        'name': 'General/Supporting',
        'description': 'Permits, surveys, background documents, deposition exhibits',
        'prefix': 'G'
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


def assign_primary_topic_by_category(doc: Dict) -> str:
    """
    Assign primary topic based on document category first, then keywords.
    This prevents over-categorization to AMENITIES.
    """
    category = doc['category']
    searchable = (doc['file_name'].lower() + " " + doc['full_path'].lower()).replace('naples 2', '')

    # Category-based assignments (most specific first)
    if category == 'Financial Records':
        return 'FINANCIAL'

    if category in ['Email', 'Correspondence']:
        # Check for specific topics in emails
        if any(kw in searchable for kw in ['invoice', 'payment', 'billing', 'cost']):
            return 'FINANCIAL'
        elif any(kw in searchable for kw in ['foundation', 'structural', 'engineering', 'survey']):
            return 'FOUNDATION'
        elif any(kw in searchable for kw in ['forensic', 'timestamp', 'tamper', 'modified']):
            return 'TIMELINE'
        elif any(kw in searchable for kw in ['amenities', 'amenity', 'pool', 'bbq', 'waterfall', 'lane.rvt']):
            return 'AMENITIES'
        else:
            return 'COMMUNICATION'

    if category == 'Forensic Report/Analysis':
        # Forensic reports go to timeline by default
        if any(kw in searchable for kw in ['foundation', 'structural', 'survey', 'soil']):
            return 'FOUNDATION'
        else:
            return 'TIMELINE'

    if category in ['Design Files (DWG/CAD)', 'Design Files (Revit)']:
        # Design files - check for specific amenity references
        if 'lane' in searchable and any(ext in searchable for ext in ['.rvt', '.dwg']):
            return 'AMENITIES'
        elif 'foundation' in searchable or 'structural' in searchable:
            return 'FOUNDATION'
        else:
            return 'AMENITIES'  # Default for design files

    if category == 'Deposition/Transcript':
        # All deposition exhibits go to GENERAL for easy reference
        return 'GENERAL'

    if category in ['Permits/Approvals', 'Survey Documents']:
        return 'FOUNDATION'

    # Keyword-based assignment for uncategorized documents
    if any(kw in searchable for kw in ['invoice', 'payment', 'contract', 'billing']):
        return 'FINANCIAL'
    elif any(kw in searchable for kw in ['foundation', 'structural', 'survey', 'engineering']):
        return 'FOUNDATION'
    elif any(kw in searchable for kw in ['forensic', 'timestamp', 'tamper', 'build version', 'modified']):
        return 'TIMELINE'
    elif any(kw in searchable for kw in ['amenities', 'pool', 'bbq', 'waterfall', 'outdoor kitchen']):
        return 'AMENITIES'
    elif any(kw in searchable for kw in ['email', 'correspondence', 'letter', 'garcia', 'murphy']):
        return 'COMMUNICATION'
    else:
        return 'GENERAL'


def categorize_documents(documents: List[Dict]) -> Dict[str, List[Dict]]:
    """Categorize all documents by primary trial topic."""
    categorized = defaultdict(list)

    for doc in documents:
        primary_topic = assign_primary_topic_by_category(doc)
        doc['primary_topic'] = primary_topic
        categorized[primary_topic].append(doc)

    return categorized


def assign_exhibit_numbers(categorized_docs: Dict[str, List[Dict]]) -> List[Dict]:
    """Assign sequential exhibit numbers within each topic."""
    all_exhibits = []

    # Process topics in priority order
    for topic_id in ['GENERAL', 'AMENITIES', 'TIMELINE', 'FOUNDATION', 'FINANCIAL', 'COMMUNICATION']:
        docs = categorized_docs.get(topic_id, [])
        prefix = TRIAL_TOPICS[topic_id]['prefix']

        # Sort documents for consistent numbering
        def sort_priority(doc):
            category = doc['category']
            # Deposition exhibits first, then design files, then emails, then others
            if category == 'Deposition/Transcript':
                return (0, doc['file_name'])
            elif category in ['Design Files (DWG/CAD)', 'Design Files (Revit)']:
                return (1, doc['file_name'])
            elif category == 'Forensic Report/Analysis':
                return (2, doc['file_name'])
            elif category in ['Email', 'Correspondence']:
                return (3, doc['file_name'])
            else:
                return (4, doc['file_name'])

        sorted_docs = sorted(docs, key=sort_priority)

        # Assign exhibit numbers
        for idx, doc in enumerate(sorted_docs, start=1):
            doc['exhibit_number'] = f"{prefix}-{idx:03d}"
            all_exhibits.append(doc)

    return all_exhibits


def create_master_exhibit_index(all_exhibits: List[Dict]):
    """Create master index of all exhibits with topic tags."""
    TRIAL_DIR.mkdir(parents=True, exist_ok=True)
    output_file = TRIAL_DIR / "TRIAL_EXHIBIT_TOPIC_INDEX.csv"

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['exhibit_number', 'primary_topic', 'file_name',
                     'category', 'file_type', 'full_path', 'file_size_mb', 'modified_date']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for doc in all_exhibits:
            writer.writerow({k: doc.get(k, '') for k in fieldnames})

    print(f"  Created: {output_file.name} ({len(all_exhibits)} total exhibits)")


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
                         'full_path', 'file_size_mb', 'modified_date']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for doc in topic_docs:
                writer.writerow({k: doc.get(k, '') for k in fieldnames})

        print(f"  Created: {output_file.name} ({len(topic_docs)} exhibits)")


def generate_statistics_report(categorized_docs: Dict[str, List[Dict]]):
    """Generate summary statistics."""
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


# Include all other functions from v1 (binder structure, witness roadmap, etc.)
# [Abbreviated for brevity - would include all creation functions]

def main():
    """Main execution."""
    print("=" * 80)
    print("TRIAL EXHIBIT ORGANIZER V2")
    print("Kara Murphy vs Danny Garcia (Case 2026-001)")
    print("Improved topic categorization")
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
    generate_statistics_report(categorized)
    print()

    print("=" * 80)
    print("TRIAL EXHIBIT ORGANIZATION COMPLETE (V2)")
    print("=" * 80)
    print(f"All deliverables saved to: {TRIAL_DIR}")


if __name__ == "__main__":
    main()
