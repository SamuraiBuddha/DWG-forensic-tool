EMAIL TIMELINE EXTRACTION TOOL - SETUP AND USAGE
================================================================================

PROJECT: Kara Murphy vs Danny Garcia (Case 2026-001)
PURPOSE: Parse 65 Outlook MSG emails to build litigation timeline
CREATED: 2026-01-30

================================================================================
INSTALLATION REQUIREMENTS
================================================================================

1. PYTHON LIBRARY INSTALLATION
   -----------------------------------------
   The tool requires the 'extract-msg' library to parse Outlook MSG files.

   Installation command:

   pip install extract-msg

   VERIFY INSTALLATION:

   python -c "import extract_msg; print('extract-msg library installed successfully')"


2. NETWORK SHARE ACCESS
   -----------------------------------------
   The tool requires access to the network share:

   \\adam\DataPool\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia\Gansari\Naples\emails\

   VERIFY ACCESS:

   1. Open Windows Explorer
   2. Navigate to: \\adam\DataPool\
   3. Browse to: Projects\2026-001_Kara_Murphy_vs_Danny_Garcia\Gansari\Naples\emails\
   4. Verify you can see .msg files in the directory

   TROUBLESHOOTING ACCESS ISSUES:

   - Ensure network share is online
   - Verify you have read permissions to the case directory
   - If prompted, enter network credentials
   - Try mapping the share to a drive letter (e.g., Z:\)

   To map drive:

   net use Z: \\adam\DataPool\ /persistent:yes


================================================================================
USAGE
================================================================================

STEP 1: Install Python library

   pip install extract-msg

STEP 2: Verify network access

   dir \\adam\DataPool\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia\Gansari\Naples\emails\

STEP 3: Run the email parser

   python email_timeline_parser.py

STEP 4: Review output files in:

   \\adam\DataPool\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia\EMAIL_TIMELINE_ANALYSIS\


================================================================================
OUTPUT DELIVERABLES
================================================================================

The tool generates 7 litigation-ready deliverables:

1. EMAIL_TIMELINE_MASTER.csv
   - Comprehensive CSV with all 65 emails chronologically sorted
   - Columns: exhibit_id, sent_date, sender, recipients, subject, body_preview,
     attachments, parties_mentioned, smoking_gun_score, anomaly flags
   - Ready for import into Excel/database

2. EMAIL_PARTY_COMMUNICATION_MATRIX.txt
   - Shows who emailed whom and how many times
   - Identifies communication patterns between parties
   - Maps: Danny Garcia, Andy Ehrig, Kara Murphy, Caron, Beauchamp, Gansari

3. EMAIL_KEYWORD_ANALYSIS.txt
   - Frequency analysis of critical terms:
     * SMOKING GUN: delete, tamper, fraud, backdated, conceal
     * AMENITIES: pool, bbq, waterfall, fireplace, outdoor kitchen
     * FILES: Lane.rvt, .dwg, updated drawing, revised drawing
   - Shows which emails contain each keyword

4. SMOKING_GUN_EMAILS.txt
   - Top 10 most relevant emails ranked by litigation score
   - Detailed metadata: sender, recipients, subject, body preview
   - Scoring breakdown: smoking gun indicators + amenity refs + file refs

5. EMAIL_TIMELINE_VISUALIZATION.txt
   - ASCII timeline showing chronological flow
   - Grouped by month
   - Flags emails with smoking gun keywords [!]

6. EMAIL_METADATA_FORENSICS.txt
   - Timestamp anomaly detection (sent before received, excessive delays)
   - Date range analysis (earliest to latest email)
   - Forensic metadata red flags

7. DEPOSITION_EXHIBIT_CROSS_REFERENCE.txt
   - Exhibit numbering: Email-001 through Email-065
   - Ready for deposition exhibit labeling
   - Cross-reference by date, sender, subject


================================================================================
LITIGATION WORKFLOW
================================================================================

PHASE 1: EMAIL EXTRACTION (THIS TOOL)
   [OK] Parse 65 MSG files
   [OK] Extract metadata (dates, parties, subjects)
   [OK] Build chronological timeline
   [OK] Identify smoking gun communications

PHASE 2: PRIVILEGE REVIEW
   [ ] Review EMAIL_TIMELINE_MASTER.csv for attorney-client privilege
   [ ] Redact privileged communications
   [ ] Generate privilege log

PHASE 3: DEPOSITION PREPARATION
   [ ] Use DEPOSITION_EXHIBIT_CROSS_REFERENCE.txt to label exhibits
   [ ] Cross-reference with deposition transcripts
   [ ] Prepare exhibit binders (Email-001 to Email-065)

PHASE 4: EXPERT WITNESS REPORT
   [ ] Include email timeline in forensic report
   [ ] Reference SMOKING_GUN_EMAILS.txt findings
   [ ] Cite EMAIL_METADATA_FORENSICS.txt for timestamp anomalies


================================================================================
TROUBLESHOOTING
================================================================================

ISSUE: "Email directory not found"
   FIX: Verify network share is mounted and accessible

   Test command:
   dir \\adam\DataPool\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia\Gansari\Naples\emails\

ISSUE: "extract-msg library not found"
   FIX: Install Python library

   pip install extract-msg

ISSUE: "Failed to parse MSG file"
   CAUSE: Corrupted or non-standard MSG format
   FIX: Note the error and manually review the problematic file

ISSUE: "No emails parsed"
   CAUSE: No .msg files in directory or all failed to parse
   FIX: Verify directory contains .msg files

   dir \\adam\DataPool\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia\Gansari\Naples\emails\*.msg

ISSUE: "Permission denied"
   CAUSE: Insufficient permissions to case directory
   FIX: Contact IT to grant read access to case files


================================================================================
FORENSIC VALIDATION
================================================================================

EXPECTED RESULTS:
   - Total emails parsed: 65
   - Date range: [TO BE DETERMINED AFTER RUN]
   - Top parties: Danny Garcia, Andy Ehrig, Kara Murphy
   - Smoking gun keywords: [Varies by case content]

QUALITY CHECKS:
   1. Verify EMAIL_TIMELINE_MASTER.csv has 65 rows (+ header)
   2. Check all sent_date values are chronologically sorted
   3. Confirm no duplicate exhibit IDs (Email-001 to Email-065)
   4. Review SMOKING_GUN_EMAILS.txt top 10 for relevance


================================================================================
CONTACT
================================================================================

Tool Author: Ehrig BIM & IT Consultation, Inc.
Case: 2026-001 Kara Murphy vs Danny Garcia
For issues: Review error messages and check troubleshooting section above


================================================================================
END OF README
================================================================================
