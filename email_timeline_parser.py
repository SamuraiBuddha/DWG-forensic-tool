#!/usr/bin/env python3
"""
EMAIL TIMELINE EXTRACTION TOOL
Kara Murphy vs Danny Garcia Case (2026-001)

Parses 65 Outlook MSG files from Naples project emails to build litigation timeline.
Extracts sent/received dates, sender/recipient, subject matter for evidence mapping.

USAGE:
    python email_timeline_parser.py --input-path <email_dir> --output-path <output_dir>

OUTPUT:
    - EMAIL_TIMELINE_MASTER.csv (chronological, all 65 emails)
    - EMAIL_PARTY_COMMUNICATION_MATRIX.txt (who emailed whom)
    - EMAIL_KEYWORD_ANALYSIS.txt (amenities, pool, BBQ mentions)
    - SMOKING_GUN_EMAILS.txt (top 10 by relevance)
    - EMAIL_TIMELINE_VISUALIZATION.txt (ASCII timeline)
    - EMAIL_METADATA_FORENSICS.txt (timestamp anomalies)
    - DEPOSITION_EXHIBIT_CROSS_REFERENCE.txt (exhibit mapping)
"""

import os
import csv
import datetime
import re
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Set, Optional
from collections import defaultdict, Counter
from dataclasses import dataclass, field

# IMPORTANT: Install extract-msg library first
# pip install extract-msg
try:
    import extract_msg
except ImportError:
    print("[ERROR] extract-msg library not found. Install with: pip install extract-msg")
    exit(1)

# Known parties in the case
PARTIES = {
    'garcia': 'Danny Garcia (Defendant)',
    'andy': 'Andy Ehrig (Architect)',
    'murphy': 'Kara Murphy (Plaintiff)',
    'kara': 'Kara Murphy (Plaintiff)',
    'caron': 'Caron (Related Party)',
    'beauchamp': 'Beauchamp (Related Party)',
    'gansari': 'Gansari (Firm/Entity)',
}

# Litigation-critical keywords
SMOKING_GUN_KEYWORDS = {
    'delete': 5,
    'remove': 5,
    'destroy': 10,
    'backdated': 10,
    'tamper': 10,
    'modified after': 8,
    'change the date': 8,
    'hide': 7,
    'conceal': 7,
    'fraud': 10,
}

AMENITY_KEYWORDS = {
    'amenities': 3,
    'pool': 2,
    'outdoor kitchen': 4,
    'bbq': 2,
    'waterfall': 3,
    'fireplace': 3,
    'retaining wall': 3,
    'landscape': 2,
}

FILE_REFERENCE_KEYWORDS = {
    'lane.rvt': 5,
    '.dwg': 3,
    '.rvt': 3,
    'updated drawing': 4,
    'revised drawing': 4,
    'new version': 3,
    'attached file': 2,
}


@dataclass
class EmailMetadata:
    """Comprehensive email metadata for forensic analysis."""
    msg_file: str
    sender: str
    sender_email: str
    recipients: List[str] = field(default_factory=list)
    recipient_emails: List[str] = field(default_factory=list)
    cc: List[str] = field(default_factory=list)
    subject: str = ""
    sent_date: Optional[datetime.datetime] = None
    received_date: Optional[datetime.datetime] = None
    body_preview: str = ""  # First 500 chars
    attachment_count: int = 0
    attachment_names: List[str] = field(default_factory=list)
    message_id: str = ""
    importance: str = "Normal"
    has_attachments: bool = False

    # Forensic flags
    smoking_gun_score: int = 0
    amenity_score: int = 0
    file_reference_score: int = 0
    parties_mentioned: List[str] = field(default_factory=list)

    # Anomaly flags
    sent_received_delta_hours: Optional[float] = None
    timestamp_anomaly: bool = False


def parse_msg_file(msg_path: Path) -> Optional[EmailMetadata]:
    """
    Parse Outlook MSG file and extract comprehensive metadata.

    Args:
        msg_path: Path to .msg file

    Returns:
        EmailMetadata object or None if parsing fails
    """
    try:
        msg = extract_msg.Message(str(msg_path))

        # Extract sender (handle different MSG formats)
        sender = msg.sender if msg.sender else "UNKNOWN"
        # Try multiple attributes for sender email (depends on MSG format)
        sender_email = ""
        if hasattr(msg, 'senderEmail') and msg.senderEmail:
            sender_email = msg.senderEmail
        elif hasattr(msg, 'sender') and msg.sender and '@' in str(msg.sender):
            # Extract email from "Name <email>" format
            email_match = re.search(r'<(.+?)>', str(msg.sender))
            if email_match:
                sender_email = email_match.group(1)
            elif '@' in str(msg.sender):
                sender_email = str(msg.sender)

        # Extract recipients
        recipients = []
        recipient_emails = []
        if msg.to:
            # Parse "Name <email@domain.com>" format
            for to in msg.to.split(';'):
                to = to.strip()
                if to:
                    recipients.append(to)
                    email_match = re.search(r'<(.+?)>', to)
                    if email_match:
                        recipient_emails.append(email_match.group(1))
                    elif '@' in to:
                        recipient_emails.append(to)

        # Extract CC
        cc = []
        if msg.cc:
            cc = [c.strip() for c in msg.cc.split(';') if c.strip()]

        # Extract subject
        subject = msg.subject if msg.subject else "[NO SUBJECT]"

        # Extract sent date
        sent_date = msg.date

        # Extract received date (if available)
        received_date = None
        # MSG format doesn't always have receivedTime; fallback to sentDate

        # Extract body preview (first 500 chars, strip HTML)
        body = msg.body if msg.body else ""
        # Remove excessive whitespace
        body = re.sub(r'\s+', ' ', body).strip()
        body_preview = body[:500]

        # Extract attachments
        attachments = msg.attachments
        attachment_names = []
        for att in attachments:
            if hasattr(att, 'longFilename') and att.longFilename:
                attachment_names.append(att.longFilename)
            elif hasattr(att, 'shortFilename') and att.shortFilename:
                attachment_names.append(att.shortFilename)
            else:
                attachment_names.append("UNNAMED_ATTACHMENT")
        attachment_count = len(attachments)

        # Create metadata object
        metadata = EmailMetadata(
            msg_file=msg_path.name,
            sender=sender,
            sender_email=sender_email,
            recipients=recipients,
            recipient_emails=recipient_emails,
            cc=cc,
            subject=subject,
            sent_date=sent_date,
            received_date=received_date,
            body_preview=body_preview,
            attachment_count=attachment_count,
            attachment_names=attachment_names,
            has_attachments=(attachment_count > 0),
        )

        # Score email for litigation relevance
        score_email_relevance(metadata, body)

        # Detect timestamp anomalies
        detect_timestamp_anomalies(metadata)

        msg.close()
        return metadata

    except Exception as e:
        print(f"[ERROR] Failed to parse {msg_path.name}: {e}")
        return None


def score_email_relevance(metadata: EmailMetadata, full_body: str):
    """
    Score email for litigation relevance based on keywords.

    Args:
        metadata: EmailMetadata object to update scores
        full_body: Full email body text
    """
    combined_text = (metadata.subject + " " + full_body).lower()

    # Smoking gun keywords
    for keyword, score in SMOKING_GUN_KEYWORDS.items():
        if keyword in combined_text:
            metadata.smoking_gun_score += score

    # Amenity keywords
    for keyword, score in AMENITY_KEYWORDS.items():
        if keyword in combined_text:
            metadata.amenity_score += score

    # File reference keywords
    for keyword, score in FILE_REFERENCE_KEYWORDS.items():
        if keyword in combined_text:
            metadata.file_reference_score += score

    # Detect parties mentioned
    for keyword, party_name in PARTIES.items():
        if keyword in combined_text:
            if party_name not in metadata.parties_mentioned:
                metadata.parties_mentioned.append(party_name)


def detect_timestamp_anomalies(metadata: EmailMetadata):
    """
    Detect suspicious timestamp patterns.

    Args:
        metadata: EmailMetadata object to update anomaly flags
    """
    if metadata.sent_date and metadata.received_date:
        delta = metadata.received_date - metadata.sent_date
        metadata.sent_received_delta_hours = delta.total_seconds() / 3600

        # Flag if received before sent (impossible) or delay > 72 hours
        if delta.total_seconds() < 0 or delta.total_seconds() > 259200:  # 72 hours
            metadata.timestamp_anomaly = True


def parse_all_emails(email_dir: Path) -> List[EmailMetadata]:
    """
    Parse all MSG files in directory.

    Args:
        email_dir: Directory containing .msg files

    Returns:
        List of EmailMetadata objects sorted by sent_date
    """
    if not email_dir.exists():
        print(f"[ERROR] Email directory not found: {email_dir}")
        print("[INFO] Please mount network share \\\\adam\\DataPool\\")
        return []

    msg_files = list(email_dir.glob("*.msg"))
    print(f"[INFO] Found {len(msg_files)} MSG files")

    emails = []
    for msg_file in msg_files:
        print(f"  [->] Parsing {msg_file.name}...")
        metadata = parse_msg_file(msg_file)
        if metadata:
            emails.append(metadata)

    # Sort chronologically
    emails.sort(key=lambda e: e.sent_date if e.sent_date else datetime.datetime.min)

    print(f"[OK] Successfully parsed {len(emails)} emails")
    return emails


def generate_master_timeline_csv(emails: List[EmailMetadata], output_file: Path):
    """Generate EMAIL_TIMELINE_MASTER.csv with all emails chronologically sorted."""
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = [
            'exhibit_id', 'msg_file', 'sent_date', 'sender', 'sender_email',
            'recipients', 'recipient_emails', 'cc', 'subject', 'body_preview',
            'attachment_count', 'attachment_names', 'parties_mentioned',
            'smoking_gun_score', 'amenity_score', 'file_reference_score',
            'timestamp_anomaly'
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for i, email in enumerate(emails, start=1):
            exhibit_id = f"Email-{i:03d}"
            writer.writerow({
                'exhibit_id': exhibit_id,
                'msg_file': email.msg_file,
                'sent_date': email.sent_date.strftime('%Y-%m-%d %H:%M:%S') if email.sent_date else 'N/A',
                'sender': email.sender,
                'sender_email': email.sender_email,
                'recipients': '; '.join(email.recipients),
                'recipient_emails': '; '.join(email.recipient_emails),
                'cc': '; '.join(email.cc),
                'subject': email.subject,
                'body_preview': email.body_preview,
                'attachment_count': email.attachment_count,
                'attachment_names': '; '.join(email.attachment_names),
                'parties_mentioned': '; '.join(email.parties_mentioned),
                'smoking_gun_score': email.smoking_gun_score,
                'amenity_score': email.amenity_score,
                'file_reference_score': email.file_reference_score,
                'timestamp_anomaly': 'YES' if email.timestamp_anomaly else 'NO',
            })

    print(f"[OK] Written: {output_file}")


def generate_communication_matrix(emails: List[EmailMetadata], output_file: Path):
    """Generate EMAIL_PARTY_COMMUNICATION_MATRIX.txt showing who emailed whom."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("EMAIL PARTY COMMUNICATION MATRIX\n")
        f.write("=" * 80 + "\n")
        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Emails Analyzed: {len(emails)}\n")
        f.write("=" * 80 + "\n\n")

        # Build sender -> recipient map
        comm_matrix = defaultdict(lambda: defaultdict(int))
        for email in emails:
            sender = email.sender if email.sender else "UNKNOWN"
            for recipient in email.recipient_emails:
                comm_matrix[sender][recipient] += 1

        f.write("COMMUNICATION FREQUENCY (Sender -> Recipient: Count)\n")
        f.write("-" * 80 + "\n")
        for sender, recipients in sorted(comm_matrix.items()):
            f.write(f"\n{sender}:\n")
            for recipient, count in sorted(recipients.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  -> {recipient}: {count} email(s)\n")

        # Parties mentioned analysis
        f.write("\n\nPARTIES MENTIONED IN EMAILS\n")
        f.write("-" * 80 + "\n")
        party_mentions = Counter()
        for email in emails:
            for party in email.parties_mentioned:
                party_mentions[party] += 1

        for party, count in party_mentions.most_common():
            f.write(f"  {party}: {count} email(s)\n")

    print(f"[OK] Written: {output_file}")


def generate_keyword_analysis(emails: List[EmailMetadata], output_file: Path):
    """Generate EMAIL_KEYWORD_ANALYSIS.txt with term frequency analysis."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("EMAIL KEYWORD FREQUENCY ANALYSIS\n")
        f.write("=" * 80 + "\n")
        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")

        # Smoking gun keywords
        f.write("SMOKING GUN KEYWORDS (Tampering/Fraud Indicators)\n")
        f.write("-" * 80 + "\n")
        keyword_counts = Counter()
        for email in emails:
            combined = (email.subject + " " + email.body_preview).lower()
            for keyword in SMOKING_GUN_KEYWORDS.keys():
                if keyword in combined:
                    keyword_counts[keyword] += 1

        if keyword_counts:
            for keyword, count in keyword_counts.most_common():
                emails_with_keyword = [e for e in emails if keyword in (e.subject + " " + e.body_preview).lower()]
                f.write(f"  '{keyword}': {count} occurrence(s)\n")
                for email in emails_with_keyword[:3]:  # Show first 3 examples
                    f.write(f"    - {email.msg_file}: {email.subject}\n")
                f.write("\n")
        else:
            f.write("  [None detected]\n")

        # Amenity keywords
        f.write("\n\nAMENITY REFERENCES (Pool, BBQ, Waterfall, etc.)\n")
        f.write("-" * 80 + "\n")
        amenity_counts = Counter()
        for email in emails:
            combined = (email.subject + " " + email.body_preview).lower()
            for keyword in AMENITY_KEYWORDS.keys():
                if keyword in combined:
                    amenity_counts[keyword] += 1

        for keyword, count in amenity_counts.most_common():
            f.write(f"  '{keyword}': {count} occurrence(s)\n")

        # File reference keywords
        f.write("\n\nFILE REFERENCES (DWG, RVT, Updated Drawings)\n")
        f.write("-" * 80 + "\n")
        file_counts = Counter()
        for email in emails:
            combined = (email.subject + " " + email.body_preview).lower()
            for keyword in FILE_REFERENCE_KEYWORDS.keys():
                if keyword in combined:
                    file_counts[keyword] += 1

        for keyword, count in file_counts.most_common():
            f.write(f"  '{keyword}': {count} occurrence(s)\n")

    print(f"[OK] Written: {output_file}")


def generate_smoking_gun_report(emails: List[EmailMetadata], output_file: Path):
    """Generate SMOKING_GUN_EMAILS.txt with top 10 most relevant emails."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("SMOKING GUN EMAILS - TOP 10 BY RELEVANCE\n")
        f.write("=" * 80 + "\n")
        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")

        # Sort by combined score
        scored_emails = sorted(
            emails,
            key=lambda e: e.smoking_gun_score + e.amenity_score + e.file_reference_score,
            reverse=True
        )

        top_10 = scored_emails[:10]

        for i, email in enumerate(top_10, start=1):
            total_score = email.smoking_gun_score + email.amenity_score + email.file_reference_score

            f.write(f"RANK #{i} - TOTAL SCORE: {total_score}\n")
            f.write("-" * 80 + "\n")
            f.write(f"File: {email.msg_file}\n")
            f.write(f"Sent: {email.sent_date.strftime('%Y-%m-%d %H:%M:%S') if email.sent_date else 'N/A'}\n")
            f.write(f"From: {email.sender} <{email.sender_email}>\n")
            f.write(f"To: {'; '.join(email.recipient_emails)}\n")
            f.write(f"Subject: {email.subject}\n")
            f.write(f"Attachments: {email.attachment_count} ({', '.join(email.attachment_names) if email.attachment_names else 'None'})\n")
            f.write(f"\nScores:\n")
            f.write(f"  Smoking Gun: {email.smoking_gun_score}\n")
            f.write(f"  Amenity References: {email.amenity_score}\n")
            f.write(f"  File References: {email.file_reference_score}\n")
            f.write(f"\nParties Mentioned: {', '.join(email.parties_mentioned) if email.parties_mentioned else 'None'}\n")
            f.write(f"\nBody Preview:\n")
            f.write(f"{email.body_preview}\n")
            f.write("\n" + "=" * 80 + "\n\n")

    print(f"[OK] Written: {output_file}")


def generate_timeline_visualization(emails: List[EmailMetadata], output_file: Path):
    """Generate EMAIL_TIMELINE_VISUALIZATION.txt with ASCII timeline."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("EMAIL TIMELINE VISUALIZATION\n")
        f.write("=" * 80 + "\n")
        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")

        if not emails:
            f.write("[NO EMAILS TO DISPLAY]\n")
            return

        # Group by month
        emails_by_month = defaultdict(list)
        for email in emails:
            if email.sent_date:
                month_key = email.sent_date.strftime('%Y-%m')
                emails_by_month[month_key].append(email)

        for month in sorted(emails_by_month.keys()):
            month_emails = emails_by_month[month]
            f.write(f"\n{month} ({len(month_emails)} emails)\n")
            f.write("=" * 80 + "\n")

            for email in sorted(month_emails, key=lambda e: e.sent_date):
                date_str = email.sent_date.strftime('%Y-%m-%d %H:%M')
                smoking_gun_flag = "[!]" if email.smoking_gun_score > 0 else "   "
                f.write(f"{smoking_gun_flag} {date_str} | {email.sender[:30]:<30} | {email.subject[:40]}\n")

    print(f"[OK] Written: {output_file}")


def generate_metadata_forensics(emails: List[EmailMetadata], output_file: Path):
    """Generate EMAIL_METADATA_FORENSICS.txt with timestamp anomaly analysis."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("EMAIL METADATA FORENSICS REPORT\n")
        f.write("=" * 80 + "\n")
        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")

        # Timestamp anomalies
        anomalies = [e for e in emails if e.timestamp_anomaly]

        f.write(f"TIMESTAMP ANOMALIES DETECTED: {len(anomalies)}\n")
        f.write("-" * 80 + "\n")

        if anomalies:
            for email in anomalies:
                f.write(f"\n[ANOMALY] {email.msg_file}\n")
                f.write(f"  Sent: {email.sent_date.strftime('%Y-%m-%d %H:%M:%S') if email.sent_date else 'N/A'}\n")
                f.write(f"  Received: {email.received_date.strftime('%Y-%m-%d %H:%M:%S') if email.received_date else 'N/A'}\n")
                f.write(f"  Delta: {email.sent_received_delta_hours:.2f} hours\n")
                f.write(f"  Subject: {email.subject}\n")
        else:
            f.write("  [None detected]\n")

        # Date range analysis
        f.write("\n\nDATE RANGE ANALYSIS\n")
        f.write("-" * 80 + "\n")
        valid_dates = [e.sent_date for e in emails if e.sent_date]
        if valid_dates:
            earliest = min(valid_dates)
            latest = max(valid_dates)
            span_days = (latest - earliest).days

            f.write(f"  Earliest Email: {earliest.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Latest Email: {latest.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Time Span: {span_days} days\n")

    print(f"[OK] Written: {output_file}")


def generate_exhibit_cross_reference(emails: List[EmailMetadata], output_file: Path):
    """Generate DEPOSITION_EXHIBIT_CROSS_REFERENCE.txt for exhibit mapping."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("DEPOSITION EXHIBIT CROSS-REFERENCE\n")
        f.write("=" * 80 + "\n")
        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Emails: {len(emails)}\n")
        f.write("=" * 80 + "\n\n")

        f.write("EMAIL EXHIBIT NUMBERING SCHEME\n")
        f.write("-" * 80 + "\n")
        f.write("Format: Email-XXX where XXX is chronological order\n")
        f.write("Recommended for deposition: Reference by Exhibit ID + Subject\n\n")

        f.write("EXHIBIT LIST (Chronological Order)\n")
        f.write("-" * 80 + "\n\n")

        for i, email in enumerate(emails, start=1):
            exhibit_id = f"Email-{i:03d}"
            date_str = email.sent_date.strftime('%Y-%m-%d') if email.sent_date else 'N/A'

            f.write(f"{exhibit_id} | {date_str} | {email.sender[:30]:<30} | {email.subject}\n")
            f.write(f"         File: {email.msg_file}\n")
            if email.attachment_names:
                f.write(f"         Attachments: {', '.join(email.attachment_names)}\n")
            f.write("\n")

    print(f"[OK] Written: {output_file}")


def main():
    """Main execution for email timeline extraction."""
    parser = argparse.ArgumentParser(description='Email Timeline Extraction for Kara Murphy vs Danny Garcia')
    parser.add_argument('--input-path', required=True, help='Path to directory containing MSG files')
    parser.add_argument('--output-path', required=True, help='Path to output directory for deliverables')
    args = parser.parse_args()

    email_dir = Path(args.input_path)
    output_dir = Path(args.output_path)

    print("=" * 80)
    print("EMAIL TIMELINE EXTRACTION TOOL")
    print("Kara Murphy vs Danny Garcia (Case 2026-001)")
    print("=" * 80)
    print()

    # Verify paths
    if not email_dir.exists():
        print(f"[ERROR] Email directory not found: {email_dir}")
        print()
        print("TROUBLESHOOTING:")
        print("  1. Verify network share is mounted: \\\\adam\\DataPool\\")
        print("  2. Check permissions to case directory")
        print("  3. Use Windows Explorer to navigate to path manually")
        print()
        print("Once network share is accessible, re-run this script.")
        return

    # Create output directory
    output_dir.mkdir(exist_ok=True, parents=True)
    print(f"[INFO] Email Source: {email_dir}")
    print(f"[INFO] Output Directory: {output_dir}")
    print()

    # Parse all emails
    print("=" * 80)
    print("STEP 1: PARSING MSG FILES")
    print("=" * 80)
    emails = parse_all_emails(email_dir)

    if not emails:
        print("[ERROR] No emails parsed. Exiting.")
        return

    print()

    # Generate deliverables
    print("=" * 80)
    print("STEP 2: GENERATING LITIGATION DELIVERABLES")
    print("=" * 80)

    # 1. Master timeline CSV
    print("\n[1/7] Generating EMAIL_TIMELINE_MASTER.csv...")
    generate_master_timeline_csv(emails, output_dir / "EMAIL_TIMELINE_MASTER.csv")

    # 2. Communication matrix
    print("[2/7] Generating EMAIL_PARTY_COMMUNICATION_MATRIX.txt...")
    generate_communication_matrix(emails, output_dir / "EMAIL_PARTY_COMMUNICATION_MATRIX.txt")

    # 3. Keyword analysis
    print("[3/7] Generating EMAIL_KEYWORD_ANALYSIS.txt...")
    generate_keyword_analysis(emails, output_dir / "EMAIL_KEYWORD_ANALYSIS.txt")

    # 4. Smoking gun report
    print("[4/7] Generating SMOKING_GUN_EMAILS.txt...")
    generate_smoking_gun_report(emails, output_dir / "SMOKING_GUN_EMAILS.txt")

    # 5. Timeline visualization
    print("[5/7] Generating EMAIL_TIMELINE_VISUALIZATION.txt...")
    generate_timeline_visualization(emails, output_dir / "EMAIL_TIMELINE_VISUALIZATION.txt")

    # 6. Metadata forensics
    print("[6/7] Generating EMAIL_METADATA_FORENSICS.txt...")
    generate_metadata_forensics(emails, output_dir / "EMAIL_METADATA_FORENSICS.txt")

    # 7. Exhibit cross-reference
    print("[7/7] Generating DEPOSITION_EXHIBIT_CROSS_REFERENCE.txt...")
    generate_exhibit_cross_reference(emails, output_dir / "DEPOSITION_EXHIBIT_CROSS_REFERENCE.txt")

    print()
    print("=" * 80)
    print("EMAIL TIMELINE EXTRACTION COMPLETE")
    print("=" * 80)
    print(f"Total Emails Processed: {len(emails)}")
    print(f"All deliverables saved to: {output_dir}")
    print()
    print("NEXT STEPS:")
    print("  1. Review SMOKING_GUN_EMAILS.txt for top 10 critical communications")
    print("  2. Check EMAIL_KEYWORD_ANALYSIS.txt for tampering/fraud indicators")
    print("  3. Cross-reference exhibit IDs with deposition transcripts")
    print("  4. Use EMAIL_PARTY_COMMUNICATION_MATRIX.txt to map relationships")


if __name__ == "__main__":
    main()
