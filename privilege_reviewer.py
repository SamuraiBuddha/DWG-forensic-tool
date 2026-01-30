#!/usr/bin/env python3
"""
PRIVILEGE REVIEW TOOL
Automated attorney-client privilege and work product review for litigation discovery
FRCP 26(b)(3) Compliance Tool

Kara Murphy vs Danny Garcia (Case 2026-001)
Document Privilege Review - 1,040 Documents
"""

import csv
import datetime
import re
from pathlib import Path
from typing import Dict, List, Tuple, Set
from collections import defaultdict, Counter
from dataclasses import dataclass, field

# Case paths
CASE_DIR = Path("//adam/DataPool/Projects/2026-001_Kara_Murphy_vs_Danny_Garcia")
CATALOG_DIR = CASE_DIR / "DOCUMENT_CATALOG"
OUTPUT_DIR = CASE_DIR / "PRIVILEGE_REVIEW"

# Known attorneys and counsel
KNOWN_COUNSEL = {
    'caron', 'beauchamp', 'attorney', 'counsel', 'esquire', 'esq',
    'law firm', 'legal team', 'jpec'
}

# Privilege keywords (attorney-client privilege)
ATTORNEY_CLIENT_KEYWORDS = [
    'attorney', 'counsel', 'legal advice', 'privileged', 'confidential attorney',
    'attorney-client', 'legal opinion', 'caron', 'beauchamp', 'engagement letter',
    'retainer', 'legal services', 'attorney work product'
]

# Work product keywords
WORK_PRODUCT_KEYWORDS = [
    'work product', 'litigation strategy', 'case strategy', 'legal analysis',
    'expert opinion', 'litigation memo', 'trial preparation', 'deposition prep',
    'witness prep', 'case memo', 'legal research', 'discovery strategy',
    'trial strategy', 'case theory', 'mental impressions', 'legal conclusions'
]

# Confidential (NOT privileged) keywords
CONFIDENTIAL_KEYWORDS = [
    'confidential', 'proprietary', 'trade secret', 'internal use only',
    'business confidential', 'financial records', 'private'
]

# Email domains that may indicate attorney communications
ATTORNEY_DOMAINS = ['law', 'legal', 'esq', 'attorney', 'jpec']


@dataclass
class PrivilegeAnalysis:
    """Analysis result for a single document."""
    doc_id: int
    file_path: str
    file_name: str
    file_type: str
    category: str
    privilege_status: str = "DISCOVERABLE"  # PRIVILEGED, PARTIALLY_PRIVILEGED, CONFIDENTIAL, DISCOVERABLE
    privilege_basis: List[str] = field(default_factory=list)  # Attorney-Client, Work Product
    confidence_score: str = "LOW"  # HIGH, MEDIUM, LOW
    keywords_found: List[str] = field(default_factory=list)
    redaction_required: bool = False
    production_status: str = "PRODUCE"  # PRODUCE, WITHHOLD, REDACT
    notes: str = ""


class PrivilegeReviewer:
    """Automated privilege review engine."""

    def __init__(self):
        self.documents: List[Dict] = []
        self.privilege_analyses: List[PrivilegeAnalysis] = []
        self.stats = defaultdict(int)

    def load_document_catalog(self, catalog_path: Path):
        """Load document catalog CSV."""
        print(f"Loading document catalog from {catalog_path}...")
        with open(catalog_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            self.documents = list(reader)
        print(f"  Loaded {len(self.documents)} documents")
        return len(self.documents)

    def analyze_privilege(self, doc: Dict, doc_id: int) -> PrivilegeAnalysis:
        """Perform privilege analysis on a single document."""
        file_path = doc['full_path']
        file_name = doc['file_name']
        file_type = doc['file_type']
        category = doc['category']

        # Combine searchable text
        search_text = f"{file_path} {file_name}".lower()

        analysis = PrivilegeAnalysis(
            doc_id=doc_id,
            file_path=file_path,
            file_name=file_name,
            file_type=file_type,
            category=category
        )

        # Check for attorney-client privilege markers
        attorney_client_matches = []
        for keyword in ATTORNEY_CLIENT_KEYWORDS:
            if keyword in search_text:
                attorney_client_matches.append(keyword)

        # Check for work product markers
        work_product_matches = []
        for keyword in WORK_PRODUCT_KEYWORDS:
            if keyword in search_text:
                work_product_matches.append(keyword)

        # Check for confidential (not privileged) markers
        confidential_matches = []
        for keyword in CONFIDENTIAL_KEYWORDS:
            if keyword in search_text:
                confidential_matches.append(keyword)

        # RULE 1: Engagement letters are PRIVILEGED (attorney-client)
        if 'engagement' in search_text and ('letter' in search_text or 'agreement' in search_text):
            if 'caron' in search_text or 'beauchamp' in search_text or 'attorney' in search_text:
                analysis.privilege_status = "PRIVILEGED"
                analysis.privilege_basis.append("Attorney-Client Privilege")
                analysis.confidence_score = "HIGH"
                analysis.production_status = "WITHHOLD"
                analysis.keywords_found = attorney_client_matches
                analysis.notes = "Attorney engagement letter - creates attorney-client relationship"
                return analysis

        # RULE 2: Correspondence to/from counsel = PRIVILEGED
        if 'correspondence' in search_text:
            if 'caron' in search_text or 'beauchamp' in search_text or 'counsel' in search_text:
                analysis.privilege_status = "PRIVILEGED"
                analysis.privilege_basis.append("Attorney-Client Privilege")
                analysis.confidence_score = "HIGH"
                analysis.production_status = "WITHHOLD"
                analysis.keywords_found = attorney_client_matches
                analysis.notes = "Legal correspondence with counsel"
                return analysis

        # RULE 3: Litigation strategy documents = WORK PRODUCT
        if any(kw in search_text for kw in ['case strategy', 'litigation strategy',
                                              'case against', 'trial prep', 'deposition prep']):
            analysis.privilege_status = "PRIVILEGED"
            analysis.privilege_basis.append("Work Product Doctrine")
            analysis.confidence_score = "HIGH"
            analysis.production_status = "WITHHOLD"
            analysis.keywords_found = work_product_matches
            analysis.notes = "Work product prepared in anticipation of litigation"
            return analysis

        # RULE 4: Emails from "Caron" directory (produced by counsel) - REVIEW NEEDED
        if 'caron - produce' in search_text or 'caron' in search_text.split('\\'):
            # Documents in "Caron - Produce" folder were already produced by opposing counsel
            # These are likely DISCOVERABLE unless they contain privileged content
            if category == 'Email':
                # Email content would need manual review
                analysis.privilege_status = "PARTIALLY_PRIVILEGED"
                analysis.privilege_basis.append("Potential Attorney-Client (Review Required)")
                analysis.confidence_score = "MEDIUM"
                analysis.production_status = "REDACT"
                analysis.redaction_required = True
                analysis.notes = "Email from counsel's production - requires manual content review"
            else:
                # Non-email documents in produced set are likely discoverable
                analysis.privilege_status = "DISCOVERABLE"
                analysis.confidence_score = "HIGH"
                analysis.production_status = "PRODUCE"
                analysis.notes = "Document already produced by opposing counsel"
            return analysis

        # RULE 5: Deposition transcripts = DISCOVERABLE (testimony is not privileged)
        if category == 'Deposition/Transcript':
            if 'transcript' in search_text or 'exhibit' in search_text:
                analysis.privilege_status = "DISCOVERABLE"
                analysis.confidence_score = "HIGH"
                analysis.production_status = "PRODUCE"
                analysis.notes = "Deposition testimony/exhibit - not privileged"
            elif 'prep' in search_text or 'preparation' in search_text:
                # Deposition prep materials = work product
                analysis.privilege_status = "PRIVILEGED"
                analysis.privilege_basis.append("Work Product Doctrine")
                analysis.confidence_score = "HIGH"
                analysis.production_status = "WITHHOLD"
                analysis.notes = "Deposition preparation materials - work product"
            else:
                analysis.privilege_status = "DISCOVERABLE"
                analysis.confidence_score = "MEDIUM"
                analysis.production_status = "PRODUCE"
                analysis.notes = "Deposition-related document - likely discoverable"
            return analysis

        # RULE 6: Design files (DWG/CAD) = DISCOVERABLE (evidence, not privileged)
        if category in ['Design Files (DWG/CAD)', 'Design Files (Revit)']:
            analysis.privilege_status = "DISCOVERABLE"
            analysis.confidence_score = "HIGH"
            analysis.production_status = "PRODUCE"
            analysis.notes = "Design file - evidence, not privileged communication"
            return analysis

        # RULE 7: Strong attorney-client markers
        if len(attorney_client_matches) >= 2:
            analysis.privilege_status = "PRIVILEGED"
            analysis.privilege_basis.append("Attorney-Client Privilege")
            analysis.confidence_score = "MEDIUM"
            analysis.production_status = "WITHHOLD"
            analysis.keywords_found = attorney_client_matches
            analysis.notes = f"Multiple attorney-client keywords detected: {', '.join(attorney_client_matches[:3])}"
            return analysis

        # RULE 8: Strong work product markers
        if len(work_product_matches) >= 2:
            analysis.privilege_status = "PRIVILEGED"
            analysis.privilege_basis.append("Work Product Doctrine")
            analysis.confidence_score = "MEDIUM"
            analysis.production_status = "WITHHOLD"
            analysis.keywords_found = work_product_matches
            analysis.notes = f"Work product indicators: {', '.join(work_product_matches[:3])}"
            return analysis

        # RULE 9: Email files require content review
        if category == 'Email' or file_type in ['Outlook Email', 'Email']:
            if any(kw in search_text for kw in ['attorney', 'counsel', 'caron', 'beauchamp']):
                analysis.privilege_status = "PARTIALLY_PRIVILEGED"
                analysis.privilege_basis.append("Potential Attorney-Client (Review Required)")
                analysis.confidence_score = "LOW"
                analysis.production_status = "REDACT"
                analysis.redaction_required = True
                analysis.notes = "Email with counsel reference - requires full content review"
            else:
                analysis.privilege_status = "DISCOVERABLE"
                analysis.confidence_score = "MEDIUM"
                analysis.production_status = "PRODUCE"
                analysis.notes = "Email - no privilege markers detected"
            return analysis

        # RULE 10: Confidential but NOT privileged
        if len(confidential_matches) > 0 and len(attorney_client_matches) == 0:
            analysis.privilege_status = "CONFIDENTIAL"
            analysis.confidence_score = "MEDIUM"
            analysis.production_status = "PRODUCE"
            analysis.notes = "Confidential business information - NOT attorney-client privileged"
            return analysis

        # DEFAULT: Discoverable (no privilege detected)
        analysis.privilege_status = "DISCOVERABLE"
        analysis.confidence_score = "MEDIUM"
        analysis.production_status = "PRODUCE"
        analysis.notes = "No privilege markers detected - presumed discoverable"

        return analysis

    def analyze_all_documents(self):
        """Analyze all documents for privilege."""
        print("\nAnalyzing all documents for privilege...")
        for i, doc in enumerate(self.documents, 1):
            analysis = self.analyze_privilege(doc, i)
            self.privilege_analyses.append(analysis)

            # Update stats
            self.stats[analysis.privilege_status] += 1
            self.stats[f"confidence_{analysis.confidence_score}"] += 1
            self.stats[f"production_{analysis.production_status}"] += 1

        print(f"  Analyzed {len(self.privilege_analyses)} documents")
        print(f"\n  PRIVILEGE STATUS:")
        print(f"    PRIVILEGED:           {self.stats['PRIVILEGED']}")
        print(f"    PARTIALLY_PRIVILEGED: {self.stats['PARTIALLY_PRIVILEGED']}")
        print(f"    CONFIDENTIAL:         {self.stats['CONFIDENTIAL']}")
        print(f"    DISCOVERABLE:         {self.stats['DISCOVERABLE']}")
        print(f"\n  PRODUCTION STATUS:")
        print(f"    WITHHOLD: {self.stats['production_WITHHOLD']}")
        print(f"    REDACT:   {self.stats['production_REDACT']}")
        print(f"    PRODUCE:  {self.stats['production_PRODUCE']}")

    def generate_privilege_log(self, output_path: Path):
        """Generate PRIVILEGE_LOG.csv (FRCP 26(b)(5) compliance)."""
        print(f"\nGenerating privilege log: {output_path}")

        # Filter to privileged documents only
        privileged_docs = [a for a in self.privilege_analyses
                          if a.privilege_status in ['PRIVILEGED', 'PARTIALLY_PRIVILEGED']]

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'Entry_Number', 'Document_ID', 'Date', 'Author_Sender',
                'Recipients', 'Document_Type', 'Subject_Description',
                'Privilege_Claim', 'Basis_for_Claim', 'Withheld_in_Whole_or_Part',
                'File_Name', 'File_Path'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for i, analysis in enumerate(privileged_docs, 1):
                # Extract date from filename if possible
                date_match = re.search(r'(\d{2}[-./]\d{2}[-./]\d{2,4})', analysis.file_name)
                date_str = date_match.group(1) if date_match else "See File Metadata"

                writer.writerow({
                    'Entry_Number': i,
                    'Document_ID': f"PRIV-{analysis.doc_id:04d}",
                    'Date': date_str,
                    'Author_Sender': "Unknown (Requires Content Review)",
                    'Recipients': "Unknown (Requires Content Review)",
                    'Document_Type': analysis.file_type,
                    'Subject_Description': analysis.file_name[:100],
                    'Privilege_Claim': ", ".join(analysis.privilege_basis),
                    'Basis_for_Claim': analysis.notes,
                    'Withheld_in_Whole_or_Part': "Whole" if analysis.production_status == "WITHHOLD" else "Part",
                    'File_Name': analysis.file_name,
                    'File_Path': analysis.file_path
                })

        print(f"  Generated {len(privileged_docs)} privilege log entries")

    def generate_production_checklist(self, output_path: Path):
        """Generate DOCUMENT_PRODUCTION_CHECKLIST.csv for all 1,040 documents."""
        print(f"\nGenerating production checklist: {output_path}")

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'Document_ID', 'File_Name', 'File_Type', 'Category',
                'Privilege_Status', 'Production_Decision', 'Confidence',
                'Requires_Redaction', 'Review_Notes', 'Full_Path'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for analysis in self.privilege_analyses:
                writer.writerow({
                    'Document_ID': f"DOC-{analysis.doc_id:04d}",
                    'File_Name': analysis.file_name,
                    'File_Type': analysis.file_type,
                    'Category': analysis.category,
                    'Privilege_Status': analysis.privilege_status,
                    'Production_Decision': analysis.production_status,
                    'Confidence': analysis.confidence_score,
                    'Requires_Redaction': 'YES' if analysis.redaction_required else 'NO',
                    'Review_Notes': analysis.notes,
                    'Full_Path': analysis.file_path
                })

        print(f"  Generated checklist for {len(self.privilege_analyses)} documents")

    def generate_redaction_plan(self, output_path: Path):
        """Generate REDACTION_PLAN.txt for partially privileged documents."""
        print(f"\nGenerating redaction plan: {output_path}")

        redaction_docs = [a for a in self.privilege_analyses
                         if a.redaction_required or a.privilege_status == 'PARTIALLY_PRIVILEGED']

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("REDACTION PLAN\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Case: Kara Murphy vs Danny Garcia (2026-001)\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"DOCUMENTS REQUIRING REDACTION: {len(redaction_docs)}\n\n")

            f.write("REDACTION PROTOCOL:\n")
            f.write("-" * 80 + "\n")
            f.write("1. Open document in secure editing environment\n")
            f.write("2. Identify privileged sections (attorney advice, legal strategy)\n")
            f.write("3. Apply black redaction boxes with 'REDACTED - ATTORNEY-CLIENT PRIVILEGE'\n")
            f.write("4. Ensure redactions are permanent (not removable)\n")
            f.write("5. Save as NEW file: [FILENAME]_REDACTED.pdf\n")
            f.write("6. Log redaction in REDACTION_LOG.csv\n")
            f.write("7. Quality review by senior attorney\n\n")

            f.write("DOCUMENTS REQUIRING MANUAL REVIEW:\n")
            f.write("=" * 80 + "\n\n")

            for i, analysis in enumerate(redaction_docs, 1):
                f.write(f"[{i}] DOCUMENT ID: DOC-{analysis.doc_id:04d}\n")
                f.write(f"    File: {analysis.file_name}\n")
                f.write(f"    Type: {analysis.file_type}\n")
                f.write(f"    Status: {analysis.privilege_status}\n")
                f.write(f"    Privilege Basis: {', '.join(analysis.privilege_basis)}\n")
                f.write(f"    Review Instructions: {analysis.notes}\n")
                f.write(f"    Path: {analysis.file_path}\n")
                f.write("\n    REDACTION INSTRUCTIONS:\n")

                if analysis.category == 'Email':
                    f.write("    - Review email headers (To/From/CC/BCC)\n")
                    f.write("    - If TO or FROM attorney (Caron, Beauchamp), WITHHOLD ENTIRE EMAIL\n")
                    f.write("    - If CC'd to attorney with legal advice, REDACT advice portions\n")
                    f.write("    - If forwarding non-privileged info to attorney, PRODUCE\n")
                else:
                    f.write("    - Manual content review required\n")
                    f.write("    - Identify attorney communications or work product sections\n")
                    f.write("    - Redact privileged portions, produce remainder\n")

                f.write("\n" + "-" * 80 + "\n\n")

        print(f"  Generated redaction instructions for {len(redaction_docs)} documents")

    def generate_summary_report(self, output_path: Path):
        """Generate PRIVILEGE_REVIEW_SUMMARY.txt."""
        print(f"\nGenerating privilege review summary: {output_path}")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("PRIVILEGE REVIEW SUMMARY\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Case: Kara Murphy vs Danny Garcia (Case 2026-001)\n")
            f.write(f"Reviewed By: Automated Privilege Review Tool v1.0\n")
            f.write(f"Reviewer: Forensic Analysis Team (Attorney Review Required)\n")
            f.write("=" * 80 + "\n\n")

            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Documents Reviewed: {len(self.privilege_analyses)}\n\n")

            f.write("PRIVILEGE CLASSIFICATION:\n")
            f.write(f"  PRIVILEGED (Withhold):           {self.stats['PRIVILEGED']:4d} documents\n")
            f.write(f"  PARTIALLY PRIVILEGED (Redact):   {self.stats['PARTIALLY_PRIVILEGED']:4d} documents\n")
            f.write(f"  CONFIDENTIAL (Not Privileged):   {self.stats['CONFIDENTIAL']:4d} documents\n")
            f.write(f"  DISCOVERABLE (Produce):          {self.stats['DISCOVERABLE']:4d} documents\n\n")

            f.write("PRODUCTION RECOMMENDATIONS:\n")
            f.write(f"  WITHHOLD (Do Not Produce):       {self.stats['production_WITHHOLD']:4d} documents\n")
            f.write(f"  REDACT (Partial Production):     {self.stats['production_REDACT']:4d} documents\n")
            f.write(f"  PRODUCE (Full Production):       {self.stats['production_PRODUCE']:4d} documents\n\n")

            f.write("CONFIDENCE LEVELS:\n")
            f.write(f"  HIGH Confidence:   {self.stats['confidence_HIGH']:4d} documents\n")
            f.write(f"  MEDIUM Confidence: {self.stats['confidence_MEDIUM']:4d} documents\n")
            f.write(f"  LOW Confidence:    {self.stats['confidence_LOW']:4d} documents\n\n")

            # Breakdown by category
            f.write("PRIVILEGE BY DOCUMENT CATEGORY:\n")
            f.write("-" * 80 + "\n")
            category_stats = defaultdict(lambda: defaultdict(int))
            for analysis in self.privilege_analyses:
                category_stats[analysis.category][analysis.privilege_status] += 1

            for category in sorted(category_stats.keys()):
                f.write(f"\n{category}:\n")
                for status in ['PRIVILEGED', 'PARTIALLY_PRIVILEGED', 'CONFIDENTIAL', 'DISCOVERABLE']:
                    count = category_stats[category][status]
                    if count > 0:
                        f.write(f"  {status:25s}: {count:4d}\n")

            # Key privileged documents
            f.write("\n\nKEY PRIVILEGED DOCUMENTS (HIGH CONFIDENCE):\n")
            f.write("=" * 80 + "\n")
            high_priv = [a for a in self.privilege_analyses
                        if a.privilege_status == 'PRIVILEGED' and a.confidence_score == 'HIGH']

            for i, analysis in enumerate(high_priv[:20], 1):  # Top 20
                f.write(f"\n[{i}] {analysis.file_name}\n")
                f.write(f"    Privilege: {', '.join(analysis.privilege_basis)}\n")
                f.write(f"    Reason: {analysis.notes}\n")

            # Recommendations
            f.write("\n\n" + "=" * 80 + "\n")
            f.write("RECOMMENDATIONS FOR ATTORNEY REVIEW:\n")
            f.write("=" * 80 + "\n\n")

            f.write("IMMEDIATE ACTION REQUIRED:\n")
            f.write("-" * 80 + "\n")
            f.write(f"1. MANUALLY REVIEW {self.stats['production_REDACT']} documents flagged for REDACTION\n")
            f.write(f"   - See REDACTION_PLAN.txt for detailed instructions\n\n")

            f.write(f"2. VERIFY {self.stats['PRIVILEGED']} documents marked PRIVILEGED\n")
            f.write(f"   - Review privilege log (PRIVILEGE_LOG.csv)\n")
            f.write(f"   - Confirm attorney-client relationship and privilege basis\n\n")

            f.write(f"3. SPOT-CHECK {self.stats['DISCOVERABLE']} documents marked DISCOVERABLE\n")
            f.write(f"   - Sample 10% for quality assurance\n")
            f.write(f"   - Verify no inadvertent privilege disclosures\n\n")

            f.write("4. PREPARE PRIVILEGE ASSERTIONS\n")
            f.write("   - Use PRIVILEGE_ASSERTION_STATEMENT.txt as template\n")
            f.write("   - File with court per FRCP 26(b)(5)\n\n")

            f.write("NOTES:\n")
            f.write("-" * 80 + "\n")
            f.write("- This is an AUTOMATED PRELIMINARY REVIEW\n")
            f.write("- ATTORNEY REVIEW IS REQUIRED before final production\n")
            f.write("- Privilege claims must be certified by counsel\n")
            f.write("- Document content was NOT reviewed (filename/path analysis only)\n")
            f.write("- Email .msg files require FULL CONTENT REVIEW\n\n")

            f.write("RISK ASSESSMENT:\n")
            f.write("-" * 80 + "\n")
            low_conf = self.stats['confidence_LOW']
            if low_conf > 0:
                f.write(f"[!] WARNING: {low_conf} documents have LOW confidence scores\n")
                f.write("    These require immediate manual review to prevent inadvertent disclosure\n\n")

            redact_count = self.stats['production_REDACT']
            if redact_count > 50:
                f.write(f"[!] ALERT: {redact_count} documents require redaction\n")
                f.write("    This is a time-intensive process. Consider additional resources.\n\n")

            f.write("QUALITY ASSURANCE:\n")
            f.write("-" * 80 + "\n")
            f.write("- Estimated attorney review time: ")
            review_hours = (self.stats['production_REDACT'] * 10 +
                           self.stats['PRIVILEGED'] * 5 +
                           self.stats['DISCOVERABLE'] * 0.5) / 60
            f.write(f"{review_hours:.1f} hours\n")
            f.write("- Recommended: Two-attorney review for privileged documents\n")
            f.write("- Maintain privilege review decision log\n\n")

        print(f"  Summary report generated")

    def generate_clawback_notice(self, output_path: Path):
        """Generate CLAWBACK_NOTICE_TEMPLATE.txt."""
        print(f"\nGenerating clawback notice template: {output_path}")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("CLAWBACK NOTICE TEMPLATE\n")
            f.write("=" * 80 + "\n")
            f.write("Use this template if privileged documents are inadvertently produced\n")
            f.write("Per Federal Rule of Evidence 502(b)\n")
            f.write("=" * 80 + "\n\n")

            f.write("[DATE]\n\n")
            f.write("[OPPOSING COUNSEL NAME]\n")
            f.write("[LAW FIRM]\n")
            f.write("[ADDRESS]\n\n")

            f.write("Re: Kara Murphy vs Danny Garcia (Case No. 2026-001)\n")
            f.write("    NOTICE OF INADVERTENT PRODUCTION OF PRIVILEGED MATERIALS\n\n")

            f.write("Dear [OPPOSING COUNSEL]:\n\n")

            f.write("This letter serves as formal notice pursuant to Federal Rule of Evidence 502(b) ")
            f.write("that privileged documents were inadvertently produced to you on [DATE] as part ")
            f.write("of our document production in the above-referenced matter.\n\n")

            f.write("INADVERTENTLY PRODUCED DOCUMENTS:\n")
            f.write("-" * 80 + "\n")
            f.write("[LIST SPECIFIC DOCUMENT IDs AND FILENAMES]\n\n")

            f.write("PRIVILEGE CLAIM:\n")
            f.write("-" * 80 + "\n")
            f.write("The above-referenced documents are protected by:\n")
            f.write("[ ] Attorney-Client Privilege\n")
            f.write("[ ] Work Product Doctrine (FRCP 26(b)(3))\n")
            f.write("[ ] Other: _____________________\n\n")

            f.write("BASIS FOR PRIVILEGE:\n")
            f.write("[Detailed explanation of why documents are privileged]\n\n")

            f.write("INADVERTENT DISCLOSURE:\n")
            f.write("-" * 80 + "\n")
            f.write("The production of these documents was inadvertent and does not constitute a ")
            f.write("waiver of privilege. Our review process included:\n")
            f.write("1. Automated keyword screening of 1,040 documents\n")
            f.write("2. Attorney privilege review\n")
            f.write("3. Quality assurance sampling\n\n")

            f.write("The inadvertent production occurred due to [EXPLAIN CIRCUMSTANCES].\n\n")

            f.write("We took reasonable steps to prevent disclosure, including:\n")
            f.write("- Comprehensive privilege review protocol\n")
            f.write("- Keyword filtering and flagging\n")
            f.write("- Attorney review of flagged documents\n")
            f.write("- Secondary quality assurance review\n\n")

            f.write("IMMEDIATE REMEDIAL ACTION:\n")
            f.write("-" * 80 + "\n")
            f.write("We promptly identified the inadvertent production on [DATE] and are providing ")
            f.write("this notice within [NUMBER] days of discovery.\n\n")

            f.write("DEMAND FOR RETURN:\n")
            f.write("-" * 80 + "\n")
            f.write("Pursuant to FRE 502(b)(3), we hereby demand that you:\n\n")
            f.write("1. IMMEDIATELY SEQUESTER the inadvertently produced documents\n")
            f.write("2. REFRAIN from reviewing, copying, or disseminating the documents\n")
            f.write("3. RETURN all copies (paper and electronic) within 10 days\n")
            f.write("4. DELETE all electronic copies from your systems\n")
            f.write("5. CERTIFY compliance with this demand in writing\n")
            f.write("6. DESTROY any notes, summaries, or work product derived from the documents\n\n")

            f.write("If you have already reviewed these documents, please provide written confirmation ")
            f.write("of the extent of review and destruction of any derivative materials.\n\n")

            f.write("PRESERVATION OF PRIVILEGE:\n")
            f.write("-" * 80 + "\n")
            f.write("We assert that this inadvertent disclosure does NOT waive privilege under ")
            f.write("FRE 502(b) because:\n")
            f.write("1. The disclosure was inadvertent\n")
            f.write("2. We took reasonable steps to prevent disclosure\n")
            f.write("3. We are taking prompt remedial measures\n\n")

            f.write("Your cooperation in this matter is expected and required under applicable ")
            f.write("rules of professional conduct.\n\n")

            f.write("Please confirm receipt of this notice and your compliance with our demand by ")
            f.write("[DATE].\n\n")

            f.write("Respectfully,\n\n")
            f.write("[ATTORNEY NAME]\n")
            f.write("[LAW FIRM]\n")
            f.write("[CONTACT INFORMATION]\n\n")

            f.write("=" * 80 + "\n")
            f.write("CERTIFICATE OF SERVICE\n")
            f.write("=" * 80 + "\n")
            f.write("I certify that a true and correct copy of this Notice was served via ")
            f.write("[METHOD] on [DATE].\n\n")
            f.write("[ATTORNEY SIGNATURE]\n")

        print(f"  Clawback notice template generated")

    def generate_inadvertent_disclosure_report(self, output_path: Path):
        """Generate INADVERTENT_DISCLOSURE_REPORT.txt."""
        print(f"\nGenerating inadvertent disclosure report: {output_path}")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("INADVERTENT DISCLOSURE REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Case: Kara Murphy vs Danny Garcia (2026-001)\n")
            f.write("=" * 80 + "\n\n")

            f.write("INADVERTENT DISCLOSURE RISK ASSESSMENT\n")
            f.write("-" * 80 + "\n\n")

            # Check for documents already produced
            caron_produced = [a for a in self.privilege_analyses
                             if 'caron - produce' in a.file_path.lower()]

            f.write(f"DOCUMENTS IN 'CARON - PRODUCE' FOLDER: {len(caron_produced)}\n")
            f.write("These documents were already produced by opposing counsel (Caron).\n\n")

            # Check for privilege in produced documents
            priv_in_produced = [a for a in caron_produced
                               if a.privilege_status in ['PRIVILEGED', 'PARTIALLY_PRIVILEGED']]

            if priv_in_produced:
                f.write(f"[!] ALERT: {len(priv_in_produced)} potentially privileged documents ")
                f.write("found in CARON production\n\n")

                f.write("POTENTIALLY PRIVILEGED DOCUMENTS IN OPPOSING COUNSEL'S PRODUCTION:\n")
                f.write("-" * 80 + "\n")
                for analysis in priv_in_produced[:10]:  # Show first 10
                    f.write(f"\n- {analysis.file_name}\n")
                    f.write(f"  Status: {analysis.privilege_status}\n")
                    f.write(f"  Basis: {', '.join(analysis.privilege_basis)}\n")
                    f.write(f"  Notes: {analysis.notes}\n")

                f.write("\n\nRECOMMENDATION:\n")
                f.write("-" * 80 + "\n")
                f.write("These documents were produced BY opposing counsel (Caron) TO us.\n")
                f.write("If they contain privileged material, this may indicate:\n\n")
                f.write("1. Inadvertent waiver by opposing counsel\n")
                f.write("2. Documents are NOT privileged (despite keyword matches)\n")
                f.write("3. Privilege was intentionally waived\n\n")
                f.write("ACTION: Consult with counsel before asserting these as privileged.\n")
                f.write("        Do NOT return documents voluntarily.\n\n")
            else:
                f.write("[OK] No privileged documents detected in opposing counsel's production.\n\n")

            # Our potential inadvertent disclosures
            f.write("\n" + "=" * 80 + "\n")
            f.write("OUR POTENTIAL INADVERTENT DISCLOSURE RISKS\n")
            f.write("=" * 80 + "\n\n")

            low_confidence_priv = [a for a in self.privilege_analyses
                                  if a.privilege_status in ['PRIVILEGED', 'PARTIALLY_PRIVILEGED']
                                  and a.confidence_score == 'LOW']

            if low_confidence_priv:
                f.write(f"[!] WARNING: {len(low_confidence_priv)} privileged documents have ")
                f.write("LOW confidence scores\n\n")
                f.write("These documents require immediate manual review to prevent inadvertent ")
                f.write("disclosure during production.\n\n")

                f.write("LOW CONFIDENCE PRIVILEGED DOCUMENTS:\n")
                f.write("-" * 80 + "\n")
                for analysis in low_confidence_priv[:15]:
                    f.write(f"\n- DOC-{analysis.doc_id:04d}: {analysis.file_name}\n")
                    f.write(f"  Risk: May be incorrectly classified as privileged\n")
                    f.write(f"  Action: Manual attorney review required\n")
            else:
                f.write("[OK] No low-confidence privileged documents detected.\n\n")

            f.write("\n\nINADVERTENT DISCLOSURE PREVENTION PROTOCOL:\n")
            f.write("=" * 80 + "\n\n")

            f.write("1. PRE-PRODUCTION REVIEW:\n")
            f.write("   - Manual review of all WITHHOLD documents\n")
            f.write("   - Manual review of all REDACT documents\n")
            f.write("   - Spot-check 10% of PRODUCE documents\n\n")

            f.write("2. PRODUCTION PROTOCOL:\n")
            f.write("   - Produce documents in stages (batches of 200)\n")
            f.write("   - Quality assurance review of each batch\n")
            f.write("   - Document production log for each batch\n\n")

            f.write("3. POST-PRODUCTION MONITORING:\n")
            f.write("   - 30-day monitoring period after each production\n")
            f.write("   - Review opposing counsel's use of produced documents\n")
            f.write("   - Prepare clawback notice if needed\n\n")

            f.write("4. CLAWBACK AGREEMENT:\n")
            f.write("   - Consider entering FRE 502(d) order with court\n")
            f.write("   - Establish clawback protocol with opposing counsel\n")
            f.write("   - Document agreement in writing\n\n")

            f.write("CONCLUSION:\n")
            f.write("-" * 80 + "\n")
            if len(priv_in_produced) > 0 or len(low_confidence_priv) > 0:
                f.write("MODERATE RISK of inadvertent disclosure detected.\n")
                f.write("Immediate attorney review recommended before production.\n")
            else:
                f.write("LOW RISK of inadvertent disclosure.\n")
                f.write("Proceed with standard production protocol.\n")

        print(f"  Inadvertent disclosure report generated")

    def generate_privilege_assertion(self, output_path: Path):
        """Generate PRIVILEGE_ASSERTION_STATEMENT.txt."""
        print(f"\nGenerating privilege assertion statement: {output_path}")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("PRIVILEGE ASSERTION STATEMENT\n")
            f.write("=" * 80 + "\n")
            f.write("FRCP 26(b)(5) Privilege Claim Certification\n")
            f.write("=" * 80 + "\n\n")

            f.write("[COURT NAME]\n")
            f.write("[CASE NUMBER]\n\n")

            f.write("Kara Murphy, Plaintiff\n")
            f.write("vs.\n")
            f.write("Danny Garcia, Defendant\n\n")

            f.write("PRIVILEGE CLAIM AND WITHHOLDING STATEMENT\n")
            f.write("-" * 80 + "\n\n")

            f.write("Pursuant to Federal Rule of Civil Procedure 26(b)(5), [PARTY NAME] ")
            f.write("hereby provides notice that certain documents responsive to [OPPOSING PARTY]'s ")
            f.write("discovery requests are being withheld on the basis of attorney-client privilege ")
            f.write("and/or the attorney work product doctrine.\n\n")

            f.write("DOCUMENTS WITHHELD:\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Documents Withheld: {self.stats['production_WITHHOLD']}\n")
            f.write(f"Documents Redacted (Partial Production): {self.stats['production_REDACT']}\n\n")

            f.write("PRIVILEGE CLAIMS:\n")
            f.write("-" * 80 + "\n\n")

            # Count privilege types
            priv_count = Counter()
            for analysis in self.privilege_analyses:
                if analysis.privilege_status in ['PRIVILEGED', 'PARTIALLY_PRIVILEGED']:
                    for basis in analysis.privilege_basis:
                        priv_count[basis] += 1

            f.write("1. ATTORNEY-CLIENT PRIVILEGE:\n")
            ac_count = priv_count.get('Attorney-Client Privilege', 0)
            f.write(f"   Documents Withheld: {ac_count}\n\n")
            f.write("   These documents constitute confidential communications between ")
            f.write("[PARTY NAME] and counsel (including Caron and Beauchamp law firms) ")
            f.write("for the purpose of obtaining or providing legal advice. The communications ")
            f.write("were made in confidence with the expectation of privacy and for the purpose ")
            f.write("of securing legal advice or services.\n\n")

            f.write("2. ATTORNEY WORK PRODUCT DOCTRINE (FRCP 26(b)(3)):\n")
            wp_count = priv_count.get('Work Product Doctrine', 0)
            f.write(f"   Documents Withheld: {wp_count}\n\n")
            f.write("   These documents were prepared by or at the direction of counsel ")
            f.write("in anticipation of litigation. They contain counsel's mental impressions, ")
            f.write("conclusions, opinions, or legal theories concerning this litigation and ")
            f.write("are protected as work product.\n\n")

            f.write("PRIVILEGE LOG:\n")
            f.write("-" * 80 + "\n")
            f.write("A detailed privilege log identifying each withheld document is attached ")
            f.write("as Exhibit A (see PRIVILEGE_LOG.csv). For each withheld document, the ")
            f.write("privilege log provides:\n\n")
            f.write("- Document identification number\n")
            f.write("- Date of document\n")
            f.write("- Author/sender\n")
            f.write("- Recipients\n")
            f.write("- Document type\n")
            f.write("- Subject matter description\n")
            f.write("- Privilege claimed\n")
            f.write("- Basis for privilege claim\n\n")

            f.write("PARTIAL PRODUCTION (REDACTED DOCUMENTS):\n")
            f.write("-" * 80 + "\n")
            f.write(f"{self.stats['production_REDACT']} documents are being produced in ")
            f.write("redacted form. These documents contain both privileged and non-privileged ")
            f.write("information. Privileged portions have been redacted and are identified in ")
            f.write("the privilege log. Non-privileged portions are being produced.\n\n")

            f.write("CERTIFICATION:\n")
            f.write("-" * 80 + "\n")
            f.write("I certify that:\n\n")
            f.write("1. A reasonable inquiry has been made to identify documents responsive ")
            f.write("   to discovery requests.\n\n")
            f.write("2. Documents are being withheld solely on the basis of applicable privilege ")
            f.write("   and not for tactical advantage or to conceal unfavorable evidence.\n\n")
            f.write("3. The privilege log describes each withheld document with sufficient ")
            f.write("   detail to enable opposing counsel to assess the privilege claim.\n\n")
            f.write("4. All non-privileged responsive documents are being produced.\n\n")
            f.write("5. No privilege waiver has occurred with respect to the withheld documents.\n\n")

            f.write("This privilege assertion is made without waiving any privileges and with ")
            f.write("reservation of all rights.\n\n\n")

            f.write("Dated: ________________\n\n")
            f.write("_________________________________\n")
            f.write("[ATTORNEY NAME]\n")
            f.write("[BAR NUMBER]\n")
            f.write("[LAW FIRM]\n")
            f.write("[ADDRESS]\n")
            f.write("[PHONE]\n")
            f.write("[EMAIL]\n\n")
            f.write("Attorney for [PARTY NAME]\n")

        print(f"  Privilege assertion statement generated")


def main():
    """Main execution."""
    print("=" * 80)
    print("PRIVILEGE REVIEW TOOL")
    print("Kara Murphy vs Danny Garcia (Case 2026-001)")
    print("=" * 80)
    print()

    # Create output directory
    OUTPUT_DIR.mkdir(exist_ok=True)
    print(f"Output directory: {OUTPUT_DIR}\n")

    # Initialize reviewer
    reviewer = PrivilegeReviewer()

    # Load catalog
    catalog_path = CATALOG_DIR / "CASE_DOCUMENT_INDEX.csv"
    reviewer.load_document_catalog(catalog_path)

    # Analyze all documents
    reviewer.analyze_all_documents()

    # Generate deliverables
    print("\n" + "=" * 80)
    print("GENERATING DELIVERABLES")
    print("=" * 80)

    reviewer.generate_summary_report(OUTPUT_DIR / "PRIVILEGE_REVIEW_SUMMARY.txt")
    reviewer.generate_privilege_log(OUTPUT_DIR / "PRIVILEGE_LOG.csv")
    reviewer.generate_production_checklist(OUTPUT_DIR / "DOCUMENT_PRODUCTION_CHECKLIST.csv")
    reviewer.generate_redaction_plan(OUTPUT_DIR / "REDACTION_PLAN.txt")
    reviewer.generate_inadvertent_disclosure_report(OUTPUT_DIR / "INADVERTENT_DISCLOSURE_REPORT.txt")
    reviewer.generate_clawback_notice(OUTPUT_DIR / "CLAWBACK_NOTICE_TEMPLATE.txt")
    reviewer.generate_privilege_assertion(OUTPUT_DIR / "PRIVILEGE_ASSERTION_STATEMENT.txt")

    print("\n" + "=" * 80)
    print("PRIVILEGE REVIEW COMPLETE")
    print("=" * 80)
    print(f"\nAll deliverables saved to: {OUTPUT_DIR}")
    print("\nDELIVERABLES GENERATED:")
    print("  1. PRIVILEGE_REVIEW_SUMMARY.txt")
    print("  2. PRIVILEGE_LOG.csv")
    print("  3. DOCUMENT_PRODUCTION_CHECKLIST.csv")
    print("  4. REDACTION_PLAN.txt")
    print("  5. INADVERTENT_DISCLOSURE_REPORT.txt")
    print("  6. CLAWBACK_NOTICE_TEMPLATE.txt")
    print("  7. PRIVILEGE_ASSERTION_STATEMENT.txt")
    print("\n[!] ATTORNEY REVIEW REQUIRED BEFORE PRODUCTION")


if __name__ == "__main__":
    main()
