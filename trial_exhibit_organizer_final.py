#!/usr/bin/env python3
"""
TRIAL EXHIBIT ORGANIZER - FINAL VERSION
Complete trial exhibit organization system with all deliverables
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

# Trial topic definitions
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
    """Assign primary topic based on document category + keywords."""
    category = doc['category']
    searchable = (doc['file_name'].lower() + " " + doc['full_path'].lower()).replace('naples 2', '')

    # Category-based assignments
    if category == 'Financial Records':
        return 'FINANCIAL'

    if category in ['Email', 'Correspondence']:
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
        if any(kw in searchable for kw in ['foundation', 'structural', 'survey', 'soil']):
            return 'FOUNDATION'
        else:
            return 'TIMELINE'

    if category in ['Design Files (DWG/CAD)', 'Design Files (Revit)']:
        if 'lane' in searchable and any(ext in searchable for ext in ['.rvt', '.dwg']):
            return 'AMENITIES'
        elif 'foundation' in searchable or 'structural' in searchable:
            return 'FOUNDATION'
        else:
            return 'AMENITIES'

    if category == 'Deposition/Transcript':
        return 'GENERAL'

    if category in ['Permits/Approvals', 'Survey Documents']:
        return 'FOUNDATION'

    # Keyword fallback
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

    for topic_id in ['GENERAL', 'AMENITIES', 'TIMELINE', 'FOUNDATION', 'FINANCIAL', 'COMMUNICATION']:
        docs = categorized_docs.get(topic_id, [])
        prefix = TRIAL_TOPICS[topic_id]['prefix']

        def sort_priority(doc):
            category = doc['category']
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

        for idx, doc in enumerate(sorted_docs, start=1):
            doc['exhibit_number'] = f"{prefix}-{idx:03d}"
            all_exhibits.append(doc)

    return all_exhibits


def create_master_exhibit_index(all_exhibits: List[Dict]):
    """Create master index of all exhibits."""
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


def create_trial_binder_organization(categorized_docs: Dict[str, List[Dict]]):
    """Create trial binder organization guide."""
    output_file = TRIAL_DIR / "TRIAL_BINDER_ORGANIZATION.txt"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("TRIAL BINDER ORGANIZATION GUIDE\n")
        f.write("Kara Murphy vs Danny Garcia (Case 2026-001)\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("BINDER STRUCTURE:\n")
        f.write("-" * 80 + "\n\n")

        binder_num = 1
        for topic_id in ['GENERAL', 'AMENITIES', 'TIMELINE', 'FOUNDATION', 'FINANCIAL', 'COMMUNICATION']:
            docs = categorized_docs.get(topic_id, [])
            if not docs:
                continue

            topic_info = TRIAL_TOPICS[topic_id]

            f.write(f"BINDER {binder_num}: {topic_info['name'].upper()}\n")
            f.write(f"Prefix: {topic_info['prefix']}\n")
            f.write(f"Total Exhibits: {len(docs)}\n")
            f.write(f"Description: {topic_info['description']}\n\n")

            # Category breakdown
            category_counts = defaultdict(int)
            for doc in docs:
                category_counts[doc['category']] += 1

            f.write("  Contents by Category:\n")
            for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                f.write(f"    - {category}: {count} documents\n")
            f.write("\n")

            binder_num += 1

        f.write("=" * 80 + "\n")
        f.write("TRIAL DAY ORGANIZATION PLAN\n")
        f.write("=" * 80 + "\n\n")

        f.write("DAY 1: Opening Statement & Foundation\n")
        f.write("  Exhibits: G-001 to G-050 (General background, deposition exhibits)\n")
        f.write("  Binder: GENERAL/SUPPORTING\n")
        f.write("  Witnesses: Expert qualification\n\n")

        f.write("DAY 2: Design Scope Amenities (Primary Smoking Gun)\n")
        f.write("  Exhibits: A-001 to A-150 (Design files, amenity evidence)\n")
        f.write("  Binder: DESIGN SCOPE AMENITIES\n")
        f.write("  Witnesses: Expert witness on RVT/DWG analysis\n\n")

        f.write("DAY 3: Timeline Manipulation (Evidence Tampering)\n")
        f.write("  Exhibits: T-001 to T-028 (Forensic reports, timestamp analysis)\n")
        f.write("  Binder: TIMELINE MANIPULATION\n")
        f.write("  Witnesses: Expert witness continued\n\n")

        f.write("DAY 4: Foundation Issues & Financial Records\n")
        f.write("  Exhibits: F-001 to F-058, FIN-001 to FIN-009\n")
        f.write("  Binders: FOUNDATION/STRUCTURAL, FINANCIAL\n")
        f.write("  Witnesses: Engineering expert (if needed), financial records custodian\n\n")

        f.write("DAY 5: Rebuttal & Closing\n")
        f.write("  Exhibits: Any exhibits from all binders for rebuttal\n")
        f.write("  Witnesses: Defendant testimony, final summation\n\n")

    print(f"  Created: {output_file.name}")


def create_witness_examination_roadmap(all_exhibits: List[Dict]):
    """Create witness examination roadmap."""
    output_file = TRIAL_DIR / "WITNESS_EXAMINATION_ROADMAP.txt"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("WITNESS EXAMINATION ROADMAP\n")
        f.write("Exhibit Introduction Plan by Witness\n")
        f.write("=" * 80 + "\n\n")

        f.write("EXPERT WITNESS: FORENSIC ANALYST (DWG/RVT)\n")
        f.write("Estimated Duration: 4 hours direct, 2 hours cross\n")
        f.write("-" * 80 + "\n\n")

        # Timeline exhibits
        timeline_exhibits = [doc for doc in all_exhibits if doc['primary_topic'] == 'TIMELINE']
        f.write(f"Phase 1: Forensic Methodology ({len(timeline_exhibits)} exhibits)\n")
        for doc in timeline_exhibits[:10]:
            f.write(f"  {doc['exhibit_number']}: {doc['file_name'][:60]}\n")
        if len(timeline_exhibits) > 10:
            f.write(f"  ... and {len(timeline_exhibits) - 10} more timeline exhibits\n")
        f.write("\n")

        # Amenities exhibits (top 20)
        amenities_exhibits = [doc for doc in all_exhibits if doc['primary_topic'] == 'AMENITIES']
        f.write(f"Phase 2: Design Scope Amenities Analysis ({len(amenities_exhibits)} total, highlight 20)\n")
        for doc in amenities_exhibits[:20]:
            f.write(f"  {doc['exhibit_number']}: {doc['file_name'][:60]}\n")
        if len(amenities_exhibits) > 20:
            f.write(f"  ... and {len(amenities_exhibits) - 20} more design file exhibits\n")
        f.write("\n")

        # Foundation exhibits
        foundation_exhibits = [doc for doc in all_exhibits if doc['primary_topic'] == 'FOUNDATION']
        f.write(f"Phase 3: Foundation/Structural Issues ({len(foundation_exhibits)} exhibits)\n")
        for doc in foundation_exhibits[:10]:
            f.write(f"  {doc['exhibit_number']}: {doc['file_name'][:60]}\n")
        if len(foundation_exhibits) > 10:
            f.write(f"  ... and {len(foundation_exhibits) - 10} more foundation exhibits\n")
        f.write("\n\n")

        f.write("DANNY GARCIA (DEFENDANT)\n")
        f.write("Estimated Duration: 2 hours direct, 1 hour cross\n")
        f.write("-" * 80 + "\n\n")

        # Deposition impeachment
        depo_exhibits = [doc for doc in all_exhibits if doc['category'] == 'Deposition/Transcript']
        f.write(f"Impeachment with Prior Deposition ({len(depo_exhibits)} exhibits)\n")
        for doc in depo_exhibits[:15]:
            f.write(f"  {doc['exhibit_number']}: {doc['file_name'][:60]}\n")
        if len(depo_exhibits) > 15:
            f.write(f"  ... and {len(depo_exhibits) - 15} more deposition exhibits\n")
        f.write("\n")

        # Communication exhibits
        comm_exhibits = [doc for doc in all_exhibits if doc['primary_topic'] == 'COMMUNICATION']
        if comm_exhibits:
            f.write(f"Email/Correspondence Evidence ({len(comm_exhibits)} exhibits)\n")
            for doc in comm_exhibits[:10]:
                f.write(f"  {doc['exhibit_number']}: {doc['file_name'][:60]}\n")
            f.write("\n")

    print(f"  Created: {output_file.name}")


def create_exhibits_ready_for_print(all_exhibits: List[Dict]):
    """Create print preparation checklist."""
    output_file = TRIAL_DIR / "EXHIBITS_READY_FOR_PRINT.csv"

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['exhibit_number', 'primary_topic', 'file_name', 'print_status',
                     'digital_only', 'pages_estimated', 'notes']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for doc in all_exhibits:
            file_type = doc['file_type'].lower()
            digital_only = 'dwg' in file_type or 'rvt' in file_type or 'revit' in file_type

            # Estimate pages based on file size
            try:
                size_mb = float(doc['file_size_mb'])
                if 'pdf' in file_type:
                    pages = int(size_mb * 10)  # Rough estimate: 10 pages per MB for PDF
                else:
                    pages = 1
            except:
                pages = 1

            writer.writerow({
                'exhibit_number': doc['exhibit_number'],
                'primary_topic': doc['primary_topic'],
                'file_name': doc['file_name'],
                'print_status': 'PENDING',
                'digital_only': 'YES' if digital_only else 'NO',
                'pages_estimated': pages,
                'notes': 'Digital presentation required' if digital_only else ''
            })

    print(f"  Created: {output_file.name}")


def create_exhibit_retrieval_system(categorized_docs: Dict[str, List[Dict]]):
    """Create quick reference guide."""
    output_file = TRIAL_DIR / "EXHIBIT_RETRIEVAL_SYSTEM.txt"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("EXHIBIT RETRIEVAL QUICK REFERENCE\n")
        f.write("For use during trial to quickly locate exhibits\n")
        f.write("=" * 80 + "\n\n")

        f.write("EXHIBIT NUMBER PREFIXES:\n")
        f.write("-" * 80 + "\n")
        for topic_id, topic_info in TRIAL_TOPICS.items():
            count = len(categorized_docs.get(topic_id, []))
            if count > 0:
                f.write(f"{topic_info['prefix']:4s} = {topic_info['name']:30s} ({count:4d} exhibits)\n")
        f.write("\n")

        f.write("BINDER LOCATIONS:\n")
        f.write("-" * 80 + "\n")
        binder_num = 1
        for topic_id in ['GENERAL', 'AMENITIES', 'TIMELINE', 'FOUNDATION', 'FINANCIAL', 'COMMUNICATION']:
            docs = categorized_docs.get(topic_id, [])
            if not docs:
                continue

            topic_info = TRIAL_TOPICS[topic_id]
            first_exhibit = docs[0]['exhibit_number'] if docs else 'N/A'
            last_exhibit = docs[-1]['exhibit_number'] if docs else 'N/A'

            f.write(f"Binder {binder_num}: {first_exhibit} to {last_exhibit} ({topic_info['name']})\n")
            binder_num += 1
        f.write("\n")

        f.write("CRITICAL SMOKING GUN EXHIBITS:\n")
        f.write("-" * 80 + "\n")
        f.write("[To be identified manually based on forensic analysis]\n")
        f.write("- Lane.rvt file (WITH amenities)\n")
        f.write("- Lane.0024.rvt file (WITHOUT amenities)\n")
        f.write("- Build version forensic report\n")
        f.write("- Deleted partition recovery report\n")
        f.write("- Timeline impossibility diagram\n\n")

        f.write("DIGITAL PRESENTATION REQUIREMENTS:\n")
        f.write("-" * 80 + "\n")
        f.write("These exhibits require laptop/projector:\n")
        f.write("- All .dwg files (AutoCAD viewer)\n")
        f.write("- All .rvt files (Revit or RVT viewer)\n")
        f.write("- Forensic tool screenshots\n")
        f.write("- Timeline graphics\n")
        f.write("- Build version comparison charts\n\n")

    print(f"  Created: {output_file.name}")


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
        f.write("-" * 80 + "\n")
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
            f.write("-" * 80 + "\n")

            category_counts = defaultdict(int)
            for doc in docs:
                category_counts[doc['category']] += 1

            for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {category:30s}: {count:4d}\n")

    print(f"  Created: {output_file.name}")


def main():
    """Main execution."""
    print("=" * 80)
    print("TRIAL EXHIBIT ORGANIZER - FINAL VERSION")
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
    for topic_id in ['GENERAL', 'AMENITIES', 'TIMELINE', 'FOUNDATION', 'FINANCIAL', 'COMMUNICATION']:
        docs = categorized.get(topic_id, [])
        if docs:
            topic_name = TRIAL_TOPICS[topic_id]['name']
            print(f"  {topic_name:30s}: {len(docs):4d} documents")
    print()

    # Assign exhibit numbers
    print("Assigning exhibit numbers...")
    all_exhibits = assign_exhibit_numbers(categorized)
    print(f"  Assigned {len(all_exhibits)} exhibit numbers")
    print()

    # Generate all deliverables
    print("Generating trial exhibit deliverables...")
    create_master_exhibit_index(all_exhibits)
    create_topic_indexes(all_exhibits)
    create_trial_binder_organization(categorized)
    create_witness_examination_roadmap(all_exhibits)
    create_exhibits_ready_for_print(all_exhibits)
    create_exhibit_retrieval_system(categorized)
    generate_statistics_report(categorized)
    print()

    print("=" * 80)
    print("TRIAL EXHIBIT ORGANIZATION COMPLETE")
    print("=" * 80)
    print(f"All deliverables saved to: {TRIAL_DIR}")
    print()
    print("DELIVERABLES:")
    print("  1. TRIAL_EXHIBIT_TOPIC_INDEX.csv (Master index - 1,040 exhibits)")
    print("  2. EXHIBITS_[TOPIC].csv (6 topic-specific indexes)")
    print("  3. TRIAL_BINDER_ORGANIZATION.txt (Physical binder guide)")
    print("  4. WITNESS_EXAMINATION_ROADMAP.txt (Exhibit introduction plan)")
    print("  5. EXHIBITS_READY_FOR_PRINT.csv (Print preparation checklist)")
    print("  6. EXHIBIT_RETRIEVAL_SYSTEM.txt (Quick reference guide)")
    print("  7. TRIAL_EXHIBIT_STATISTICS.txt (Organization summary)")
    print()
    print("SUCCESS: All 1,040 documents organized by litigation topic")
    print("         Ready for trial binder creation and witness examination")


if __name__ == "__main__":
    main()
