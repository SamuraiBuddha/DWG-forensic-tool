# Product Requirements Document (PRD)
# DWG Forensic Tool

**Version:** 2.0
**Date:** January 10, 2025
**Author:** Jordan Paul Ehrig / Ehrig BIM & IT Consultation, Inc.
**Status:** Development - Deep Parsing Implementation Required

---

## 1. Executive Summary

### 1.1 Problem Statement

Digital forensics professionals and legal teams frequently need to analyze AutoCAD DWG files in litigation contexts (construction disputes, IP theft, contract violations, insurance claims). Currently:

- **No turnkey DWG forensics solution exists** in the market
- General forensic tools (EnCase, FTK, X-Ways) lack deep DWG-specific analysis
- The only existing EnCase EnScript for DWG is limited to versions 2004-2013 and only extracts basic metadata
- Experts must manually inspect files with hex editors or write custom scripts
- Chain of custody documentation for DWG files is ad-hoc

### 1.2 Solution

DWG Forensic Tool is an open-source Python-based toolkit that provides:

1. **Deep binary forensic analysis** of DWG file internals (NO external dependencies)
2. **CAD application fingerprinting** to identify authoring software
3. **Chain of custody** documentation with cryptographic verification
4. **Tampering detection** through CRC validation, timestamp cross-validation, and structural analysis
5. **Litigation-ready reports** suitable for court submission
6. **Expert witness support** documentation

### 1.3 Critical Architecture Decision: Direct Binary Parsing

**This tool performs ALL parsing directly from binary data. NO external libraries (LibreDWG, ODA SDK) are used for parsing.** This ensures:

- Forensic integrity (no third-party code modifying data)
- Complete control over what bytes are read
- Reproducible analysis methodology
- No licensing complications

### 1.4 Target Users

| User Type | Primary Needs |
|-----------|---------------|
| Digital Forensic Examiners | Deep file analysis, chain of custody |
| Litigation Support Teams | Evidence documentation, court-ready reports |
| Expert Witnesses | Technical documentation, defensible methodology |
| Law Firms | Easy-to-understand summaries, hash verification |
| Insurance Investigators | Timestamp verification, modification detection |
| IP/Trade Secret Investigators | Origin analysis, software fingerprinting |

---

## 2. Current Implementation Status

### 2.1 What Works

| Feature | Status | Notes |
|---------|--------|-------|
| File intake with SHA-256 | [OK] | Working |
| Header version detection | [OK] | AC1024, AC1027, AC1032 supported |
| Header CRC32 validation | [OK] | Validates header checksum |
| TrustedDWG watermark detection | [OK] | String-based detection |
| CAD application fingerprinting | [OK] | 15+ applications supported |
| NTFS timestamp extraction | [OK] | Cross-validation with DWG timestamps |
| Chain of custody logging | [OK] | SQLite with audit trail |
| PDF report generation | [OK] | With LLM narration option |
| 40 tampering rules | [OK] | TAMPER-001 through TAMPER-040 |

### 2.2 What Does NOT Work (Critical Gaps)

| Feature | Status | Problem |
|---------|--------|---------|
| Section map parsing | [FAIL] | Cannot locate internal sections in AC1032 |
| TDCREATE extraction | [FAIL] | Reading from wrong offset, returns None |
| TDUPDATE extraction | [FAIL] | Reading from wrong offset, returns None |
| TDINDWG extraction | [FAIL] | Reading garbage data (version string) |
| Section decompression | [FAIL] | Not implemented for R2010+ format |
| Handle map analysis | [PARTIAL] | Finds gaps but data may be invalid |
| Drawing variables parsing | [FAIL] | Cannot locate AcDb:Header section |

### 2.3 Root Cause Analysis

The deep parsing modules exist but fail because:

1. **Section map address calculation is wrong for AC1032**
   - Current code reads from offset 0x34
   - Returns address 0x202 but data there is compressed/encrypted
   - Need to implement proper R2010+ section locator parsing

2. **Section data is compressed but not decompressed**
   - R2004+ uses compression (possibly encryption in R2018+)
   - Current code reads raw bytes without decompression
   - Need to implement section decompression algorithm

3. **Drawing variables offset calculation is wrong**
   - Without valid section map, cannot locate AcDb:Header
   - Fallback code reads from file start (gets version string instead)

---

## 3. Goals & Success Metrics

### 3.1 Primary Goals

| Goal | Metric | Target |
|------|--------|--------|
| G1: Deep timestamp extraction | TDCREATE/TDUPDATE successfully extracted | 100% for AC1024/AC1027/AC1032 |
| G2: Section decompression | All sections successfully decompressed | 100% for supported versions |
| G3: CRC validation (all levels) | Header + all section CRCs validated | 100% accuracy |
| G4: Handle map forensics | Accurate deleted object detection | <5% false positive rate |
| G5: CAD fingerprinting | Correct application identification | >95% accuracy |
| G6: Analysis depth | Time to analyze 1MB file | 2-5 seconds (real parsing, not skipping) |

### 3.2 Non-Goals (Out of Scope for v2.0)

- DWG file repair or modification
- Visual rendering of DWG content
- Real-time monitoring/watching directories
- Cloud-based analysis
- Mobile application
- DXF forensics (separate tool)

---

## 4. Technical Requirements

### 4.1 Core Dependencies

| Component | Version | Purpose | License |
|-----------|---------|---------|--------|
| Python | 3.10+ | Runtime | PSF |
| ReportLab | 4.0+ | PDF generation | BSD |
| Click | 8.0+ | CLI framework | BSD |
| SQLite | 3.35+ | Audit database | Public Domain |
| Pydantic | 2.0+ | Data validation | MIT |
| Rich | 13.0+ | CLI output formatting | MIT |
| zlib | builtin | Section decompression | Python stdlib |

**NO EXTERNAL DWG LIBRARIES** - All parsing is direct binary.

### 4.2 System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Windows 10+, Linux, macOS | Windows 11 |
| RAM | 4 GB | 16 GB |
| Storage | 500 MB (tool) | 10 GB (with evidence cache) |
| Python | 3.10 | 3.12+ |

---

## 5. DWG Version Support Requirements

### 5.1 Version Coverage Matrix

**ALL versions from R13 onwards MUST be supported. Older versions are MORE important for litigation (historical evidence).**

| Version Code | AutoCAD Version | Years | Priority | Status |
|--------------|-----------------|-------|----------|--------|
| AC1012 | R13 | 1994-1997 | P1 | NOT IMPLEMENTED |
| AC1014 | R14 | 1997-1999 | P1 | NOT IMPLEMENTED |
| AC1015 | 2000/2000i/2002 | 1999-2003 | P0 | NOT IMPLEMENTED |
| AC1018 | 2004/2005/2006 | 2003-2007 | P0 | PARTIAL |
| AC1021 | 2007/2008/2009 | 2007-2010 | P0 | PARTIAL |
| AC1024 | 2010/2011/2012 | 2010-2013 | P0 | PARTIAL |
| AC1027 | 2013-2017 | 2013-2018 | P0 | PARTIAL |
| AC1032 | 2018+ | 2018-present | P0 | PARTIAL |

### 5.2 Version-Specific Parsing Requirements

#### FR-VERSION-001: R13/R14 Support (AC1012/AC1014)
**Priority:** P1 (HIGH)
**Status:** NOT IMPLEMENTED
**Description:** Support pre-2000 DWG format

**Technical Specification:**
```
R13/R14 Format Differences:
- No TrustedDWG watermark (not introduced until 2006)
- Different header structure (shorter)
- 8-bit CRC instead of 32-bit
- No section compression
- Simpler object encoding

Header Structure:
  0x00-0x05: Version string "AC1012" or "AC1014"
  0x06-0x0A: Unknown
  0x0B: Maintenance version
  0x0C-0x0F: Preview address
  0x13-0x14: Codepage
  No header CRC32 at 0x68 (different location)
```

**Forensic Significance:**
- R13/R14 files may be critical evidence in older construction disputes
- Many legacy files still exist in archives
- Timestamp format differs from modern versions

#### FR-VERSION-002: R2000 Family Support (AC1015)
**Priority:** P0 (CRITICAL)
**Status:** NOT IMPLEMENTED
**Description:** Support AutoCAD 2000/2000i/2002 format

**Technical Specification:**
```
R2000 Format (AC1015):
- First version with 32-bit header CRC
- CRC at offset 0x5C (not 0x68)
- Header length 0x5C bytes
- Introduced object-level CRCs
- No TrustedDWG watermark

Timestamp Variables Present:
- TDCREATE (MJD format)
- TDUPDATE (MJD format)
- TDINDWG (days fraction)
- No TDUCREATE/TDUUPDATE (UTC versions not yet added)
```

**Forensic Significance:**
- Critical transition version
- Many legacy files from early 2000s
- Construction projects from this era in litigation

#### FR-VERSION-003: R2004 Family Support (AC1018)
**Priority:** P0 (CRITICAL)
**Status:** PARTIAL
**Description:** Support AutoCAD 2004/2005/2006 format

**Technical Specification:**
```
R2004 Format (AC1018):
- CRC at offset 0x5C
- Introduced section-based compression
- Compression type 2 (LZ-like)
- First version with potential for TrustedDWG (2006)

Section Structure:
- System section pages
- Data section pages
- Gap and recovery pages
```

#### FR-VERSION-004: R2007 Family Support (AC1021)
**Priority:** P0 (CRITICAL)
**Status:** PARTIAL
**Description:** Support AutoCAD 2007/2008/2009 format

**Technical Specification:**
```
R2007 Format (AC1021):
- CRC at offset 0x68
- Header length 0x68 bytes
- Full TrustedDWG watermark support
- Introduced TDUCREATE/TDUUPDATE (UTC timestamps)
- Enhanced compression

New Forensic Fields:
- TDUCREATE: UTC creation time
- TDUUPDATE: UTC modification time
- These allow timezone cross-validation
```

#### FR-VERSION-005: R2010+ Family Support (AC1024/AC1027/AC1032)
**Priority:** P0 (CRITICAL)
**Status:** PARTIAL (see Section 6)
**Description:** Support modern DWG format

**See Section 6 for detailed requirements.**

---

## 6. Deep Parsing Requirements (CRITICAL)

### 6.1 Module: Section Map Parser (FR-SECTION)

**This is the foundation for all deep analysis. Without correct section parsing, nothing else works.**

#### FR-SECTION-001: R2010+ Section Locator Parsing
**Priority:** P0 (CRITICAL)
**Status:** NOT IMPLEMENTED
**Description:** Parse the section locator structure for AC1024/AC1027/AC1032

**Technical Specification:**
```
For AC1024/AC1027/AC1032 (R2010+):

File Header Structure (first 0x100 bytes):
  0x00-0x05: Version string "AC1032"
  0x06:      Unknown
  0x07-0x0A: Maintenance version
  0x0B:      Unknown
  0x0C-0x0F: Preview address (little-endian)
  0x10-0x11: App version
  0x12-0x13: App maintenance version
  0x14-0x17: Codepage
  0x18-0x1F: Unknown

  0x20-0x3F: Section Locator Records (encrypted in R2018+)
    - For R2018+: Need to decrypt using file-specific key

  0x68-0x6B: Header CRC32 (calculated over 0x00-0x67)

  0x80+: Encrypted/compressed data pages
```

**Acceptance Criteria:**
- Correctly parse section locator from R2010+ headers
- Handle R2018+ encryption if present
- Return valid section map addresses
- Report parsing errors clearly

#### FR-SECTION-002: Section Page Decompression
**Priority:** P0 (CRITICAL)
**Status:** NOT IMPLEMENTED
**Description:** Decompress section data pages

**Technical Specification:**
```
R2004+ Section Compression:

1. System pages use compression type 2 (LZ-like)
2. Data pages may be compressed or uncompressed
3. Decompression algorithm:
   - Read compressed size and decompressed size
   - Apply decompression (similar to LZ77)
   - Verify decompressed size matches expected

Page Header (for each page):
  - Page type (4 bytes): 0x41630E3B = System, 0x4163003B = Data
  - Decompressed size (4 bytes)
  - Compressed size (4 bytes)
  - Compression type (4 bytes): 0 = none, 2 = compressed
  - CRC32 (4 bytes)
```

**Acceptance Criteria:**
- Successfully decompress all section pages
- Verify CRC32 after decompression
- Handle both compressed and uncompressed pages
- Report decompression failures with byte offset

#### FR-SECTION-003: Section Enumeration
**Priority:** P0 (CRITICAL)
**Status:** PARTIAL (finds sections but data is wrong)
**Description:** Enumerate all sections in the file

**Required Sections to Locate:**
| Section Type | Name | Forensic Use |
|--------------|------|--------------|
| 0x01 | AcDb:Header | TDCREATE, TDUPDATE, TDINDWG, GUIDs |
| 0x02 | AcDb:Classes | Class version validation |
| 0x03 | AcDb:Handles | Deleted object detection |
| 0x06 | AcDb:AuxHeader | Auxiliary timestamps |
| 0x08 | AcDb:AppInfo | Application fingerprinting |
| 0x0B | AcDb:Security | Digital signatures |
| 0x0D | AcDb:Signature | TrustedDWG signature data |
| 0x0F | SummaryInfo | DWGPROPS metadata |

**Acceptance Criteria:**
- Locate all sections in file
- Return correct offset, compressed size, decompressed size for each
- Handle missing sections gracefully
- Provide decompressed data for each section

---

### 6.2 Module: Drawing Variables Parser (FR-DRAWVAR)

**Extracts timestamps and GUIDs from the AcDb:Header section.**

#### FR-DRAWVAR-001: Locate AcDb:Header Section
**Priority:** P0 (CRITICAL)
**Status:** NOT WORKING
**Description:** Find and decompress the Header section

**Dependency:** Requires FR-SECTION-002 (decompression)

**Acceptance Criteria:**
- Use section map to locate AcDb:Header
- Decompress section data
- Return raw bytes for variable parsing

#### FR-DRAWVAR-002: Parse TDCREATE (Creation Timestamp)
**Priority:** P0 (CRITICAL)
**Status:** NOT WORKING (returns None)
**Description:** Extract creation timestamp as Modified Julian Date

**Technical Specification:**
```
TDCREATE format:
  - 8 bytes: IEEE 754 double-precision float
  - Value: Modified Julian Date
    - Integer part: Days since November 17, 1858
    - Fractional part: Fraction of day elapsed
  - Example: 59964.583333 = February 23, 2023, 2:00 PM

Location in AcDb:Header:
  - Variable code: Group code 40 with variable name
  - Offset varies by version, must search or use variable table
```

**Acceptance Criteria:**
- Extract raw 8-byte double from correct offset
- Convert MJD to datetime
- Handle timezone (TDCREATE is local time)
- Report if variable not found

#### FR-DRAWVAR-003: Parse TDUPDATE (Last Save Timestamp)
**Priority:** P0 (CRITICAL)
**Status:** NOT WORKING (returns None)
**Description:** Extract last save timestamp as Modified Julian Date

**Same format as TDCREATE. Must cross-validate:**
- TDUPDATE >= TDCREATE (otherwise tampering)
- TDUPDATE <= current date (no future dates)

#### FR-DRAWVAR-004: Parse TDINDWG (Cumulative Edit Time)
**Priority:** P0 (CRITICAL)
**Status:** NOT WORKING (returns garbage)
**Description:** Extract cumulative editing time

**Technical Specification:**
```
TDINDWG format:
  - 8 bytes: IEEE 754 double-precision float
  - Value: Days of editing time
  - Example: 0.125 = 3 hours of editing

Critical Forensic Rule:
  TDINDWG CANNOT exceed (TDUPDATE - TDCREATE)
  If it does, file has been backdated (TAMPER-036)
```

**Acceptance Criteria:**
- Extract from correct offset (NOT file header!)
- Convert to hours/minutes for display
- Cross-validate against TDCREATE/TDUPDATE span

#### FR-DRAWVAR-005: Parse FINGERPRINTGUID
**Priority:** P1 (HIGH)
**Status:** NOT WORKING
**Description:** Extract file fingerprint GUID

**Technical Specification:**
```
FINGERPRINTGUID:
  - 16 bytes: Raw GUID
  - Persists across saves (identifies file lineage)
  - Format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
```

#### FR-DRAWVAR-006: Parse VERSIONGUID
**Priority:** P1 (HIGH)
**Status:** NOT WORKING
**Description:** Extract version GUID (changes each save)

---

### 6.3 Module: Handle Map Parser (FR-HANDLES)

**Analyzes object handles for deleted object detection.**

#### FR-HANDLES-001: Locate AcDb:Handles Section
**Priority:** P1 (HIGH)
**Status:** NOT WORKING (data is invalid)
**Description:** Find and decompress the Handles section

**Dependency:** Requires FR-SECTION-002 (decompression)

#### FR-HANDLES-002: Parse Handle Table
**Priority:** P1 (HIGH)
**Status:** NOT WORKING
**Description:** Parse the handle allocation table

**Technical Specification:**
```
Handle Table Structure:
  - Handles are allocated sequentially
  - Gaps indicate deleted objects
  - Large gaps may indicate mass deletion (evidence destruction)

Forensic Significance:
  - Normal: Small scattered gaps from editing
  - Suspicious: Large contiguous gaps (bulk deletion)
  - Critical: Gaps in specific object types (drawings, blocks)
```

**Acceptance Criteria:**
- Parse handle table correctly
- Identify gaps in handle sequence
- Classify gaps by size and location
- Report suspicious patterns

---

### 6.4 Module: R2018+ Encryption Handler (FR-ENCRYPT)

**AC1032 (AutoCAD 2018+) may use encryption on header data.**

#### FR-ENCRYPT-001: Detect Encryption
**Priority:** P0 (CRITICAL)
**Status:** NOT IMPLEMENTED
**Description:** Detect if file uses R2018+ encryption

**Technical Specification:**
```
R2018+ Encryption Indicators:
  - Section locator data at 0x20-0x3F appears random
  - Specific byte patterns at 0x480+
  - File metadata indicates R2018+ version
```

#### FR-ENCRYPT-002: Decrypt Header Data
**Priority:** P0 (CRITICAL)
**Status:** NOT IMPLEMENTED
**Description:** Decrypt header/section locator if encrypted

**Note:** Encryption key derivation method must be researched. May require:
- File-specific seed value
- Known algorithm (likely proprietary)
- Reference to ODA SDK implementation

---

## 7. CAD Ecosystem Fingerprinting Requirements (CRITICAL)

**Identifying the authoring application is ESSENTIAL for forensic analysis. Tampering rules must be adjusted based on the detected application.**

### 7.1 CAD Application Categories

#### Category 1: Genuine Autodesk Software
**TrustedDWG watermark expected. Full tampering rules apply.**

| Application | Detection Method | ACAD ID Pattern | Notes |
|-------------|------------------|-----------------|-------|
| AutoCAD | TrustedDWG + ACAD ID | ACAD0001xxx | Base product |
| AutoCAD LT | TrustedDWG + ACAD ID | ACLT0001xxx | Limited version |
| AutoCAD Architecture | TrustedDWG | ACA00001xxx | Vertical |
| AutoCAD Civil 3D | TrustedDWG | C3D00001xxx | Vertical |
| AutoCAD MEP | TrustedDWG | MEP00001xxx | Vertical |
| AutoCAD Electrical | TrustedDWG | ACE00001xxx | Vertical |
| AutoCAD Plant 3D | TrustedDWG | PLNT0001xxx | Vertical |
| AutoCAD Map 3D | TrustedDWG | MAP00001xxx | Vertical |
| Autodesk Inventor | TrustedDWG | INV00001xxx | 3D CAD |
| Revit (DWG export) | TrustedDWG | RVT00001xxx | BIM export |

#### Category 2: ODA SDK-Based Applications
**NO TrustedDWG watermark possible. Missing watermark is EXPECTED, not suspicious.**

| Application | Company | Detection Method | Market |
|-------------|---------|------------------|--------|
| BricsCAD | Bricsys | "BRICSCAD" string, ACAD_BRICSCAD_INFO dict | Global |
| DraftSight | Dassault | "DRAFTSIGHT" APPID, DS_LICENSE_TYPE | Global |
| NanoCAD | Nanosoft | CP1251 codepage, Cyrillic strings | Russia/CIS |
| ZWCAD | ZWSOFT | "ZWCAD" APPID | China/Global |
| GstarCAD | Gstarsoft | "GSTARCAD" string | China |
| progeCAD | ProgeSOFT | "PROGECAD" string | Italy/Global |
| CorelCAD | Corel | "CORELCAD" string | Global |
| ActCAD | ActCAD | "ACTCAD" string | India/Global |
| CMS IntelliCAD | CMS | ITC signatures | Global |
| 4MCAD | CADian | "4MCAD" string | Korea |
| SolidEdge 2D | Siemens | ODA patterns | Industrial |
| TurboCAD | IMSI | "TURBOCAD" string | Consumer |

#### Category 3: Open Source Applications
**Various DWG handling methods. Signatures may be subtle.**

| Application | DWG Method | Detection Method | Notes |
|-------------|------------|------------------|-------|
| LibreCAD | No native (DXF only) | Conversion artifacts | Uses external converters |
| FreeCAD | ODA or LibreDWG | ODA/LibreDWG signatures | Depends on build |
| QCAD | DXF only (Pro has DWG) | Conversion artifacts | Pro uses Teigha |
| OpenSCAD | No DWG support | N/A | 3D only |
| Blender | Limited via addons | Addon signatures | 3D focused |

#### Category 4: LibreDWG-Based Applications
**Open source DWG library. Specific binary patterns.**

| Application | Detection Method | Notes |
|-------------|------------------|-------|
| LibreDWG tools | "GNU LibreDWG" string | CLI tools |
| FreeCAD (LibreDWG build) | LibreDWG version string | Open source build |
| Custom tools | LibreDWG patterns | Developer tools |

### 7.2 Fingerprinting Detection Methods

#### FR-FINGER-001: TrustedDWG Watermark Analysis
**Priority:** P0 (CRITICAL)
**Status:** [OK] - Working

**Detection Logic:**
```
1. Search for "Autodesk DWG. This file is a Trusted DWG" string
2. If found and complete: File is genuine Autodesk
3. If found but truncated: Possible tampering (watermark stripped)
4. If not found: File from non-Autodesk application (or pre-2006)
```

**Watermark Locations:**
- Typically at offset 0x5B-0xCF in header area
- May also appear in AcDb:Signature section

#### FR-FINGER-002: ACAD ID Extraction
**Priority:** P0 (CRITICAL)
**Status:** NOT IMPLEMENTED

**Detection Logic:**
```
1. Search for pattern: "ACAD" followed by digits
2. Parse format: [APP][VERSION][BUILD]
3. Map to specific Autodesk product

ACAD ID Format Examples:
- ACAD00014092: AutoCAD 2020 build 14092
- ACLT00014092: AutoCAD LT 2020
- C3D00014092: Civil 3D 2020
```

#### FR-FINGER-003: ODA SDK Detection
**Priority:** P0 (CRITICAL)
**Status:** [OK] - Working

**Detection Indicators:**
```
1. Missing TrustedDWG (post-2006 file)
2. ODA-specific byte patterns in header
3. Specific CRC calculation differences
4. Handle allocation patterns
5. String encoding differences
```

#### FR-FINGER-004: Application-Specific String Signatures
**Priority:** P0 (CRITICAL)
**Status:** [OK] - Working

**Signature Database:**
```python
SIGNATURES = {
    "bricscad": {
        "patterns": ["BRICSCAD", "ACAD_BRICSCAD_INFO", "Bricsys"],
        "confidence": 1.0,
        "is_oda": True
    },
    "draftsight": {
        "patterns": ["DRAFTSIGHT", "DS_LICENSE_TYPE", "Dassault"],
        "confidence": 1.0,
        "is_oda": True
    },
    "nanocad": {
        "patterns": ["NANOCAD", "Nanosoft"],
        "codepage": "CP1251",  # Cyrillic indicator
        "confidence": 0.9,
        "is_oda": True
    },
    "zwcad": {
        "patterns": ["ZWCAD", "ZWSOFT"],
        "confidence": 1.0,
        "is_oda": True
    },
    # ... etc
}
```

#### FR-FINGER-005: Codepage Analysis
**Priority:** P1 (HIGH)
**Status:** PARTIAL

**Detection Logic:**
```
Codepage forensic indicators:
- CP1251 (Cyrillic): Likely Russian origin (NanoCAD, Russian AutoCAD)
- CP936 (Chinese): Likely Chinese origin (ZWCAD, GstarCAD)
- CP949 (Korean): Likely Korean origin (4MCAD)
- CP1252 (Western): Default for US/EU applications
```

#### FR-FINGER-006: CRC Pattern Analysis
**Priority:** P1 (HIGH)
**Status:** NOT IMPLEMENTED

**Detection Logic:**
```
Different applications may calculate CRC differently:
- Zero CRC: Possible non-Autodesk or stripped
- ODA CRC patterns: Specific polynomial usage
- Invalid CRC with valid watermark: Tampering indicator
```

### 7.3 Fingerprint-Based Rule Adjustment

**CRITICAL: Tampering rules MUST be adjusted based on detected application.**

#### Rule Adjustments for ODA-Based Applications

| Rule | AutoCAD Behavior | ODA App Behavior |
|------|------------------|------------------|
| TAMPER-003 (Missing TrustedDWG) | SUSPICIOUS | EXPECTED (disable rule) |
| TAMPER-004 (Invalid TrustedDWG) | CRITICAL | N/A (never present) |
| TAMPER-005 (Timestamp Reversal) | CRITICAL | CRITICAL (same) |
| CRC validation | Required | May differ |

#### Implementation Requirement

```python
def evaluate_tampering_rules(analysis, fingerprint):
    """Adjust rules based on detected application."""

    if fingerprint.is_oda_based:
        # Disable TrustedDWG rules for ODA apps
        disable_rules(["TAMPER-003", "TAMPER-004"])
        add_note("TrustedDWG rules disabled: ODA-based application detected")

    if not fingerprint.is_autodesk:
        # Adjust CRC expectations
        relax_crc_validation()
        add_note("CRC validation relaxed: non-Autodesk application")

    # Always apply timestamp rules regardless of application
    apply_timestamp_rules()  # These are universal
```

### 7.4 Fingerprint Report Section

**Every forensic report MUST include:**

1. **Detected Application**: Name and confidence
2. **Application Category**: Autodesk/ODA/Open Source/Unknown
3. **TrustedDWG Status**: Present/Absent/Invalid
4. **Rule Adjustments**: Which rules were modified and why
5. **Forensic Significance**: What this means for the investigation

**Example Report Section:**
```
APPLICATION FINGERPRINT ANALYSIS
================================
Detected Application: BricsCAD V23
Detection Confidence: 98%
Application Category: ODA SDK-based (Bricsys)
TrustedDWG Status: Not Present (EXPECTED for this application)

Forensic Significance:
This file was created by BricsCAD, which uses the Open Design Alliance
SDK for DWG file handling. ODA-based applications CANNOT produce
TrustedDWG watermarks, which are proprietary to Autodesk. Therefore,
the absence of a TrustedDWG watermark is EXPECTED and should NOT be
considered evidence of tampering.

Rule Adjustments Applied:
- TAMPER-003 (Missing TrustedDWG): DISABLED - Expected for ODA apps
- TAMPER-004 (Invalid TrustedDWG): DISABLED - N/A for ODA apps
- All timestamp rules: ACTIVE - Universal applicability
```

---

## 8. Tampering Detection Rules

### 8.1 Timestamp Manipulation Rules (CRITICAL)

| Rule ID | Name | Severity | Requires Deep Parsing |
|---------|------|----------|----------------------|
| TAMPER-036 | TDINDWG Exceeds Calendar Span | CRITICAL | YES - needs real TDINDWG |
| TAMPER-037 | Version Anachronism | CRITICAL | YES - needs TDCREATE |
| TAMPER-038 | NTFS/DWG Timestamp Contradiction | CRITICAL | YES - needs TDCREATE/TDUPDATE |
| TAMPER-039 | Timezone Manipulation | HIGH | YES - needs TDUCREATE |
| TAMPER-040 | Precision Anomaly | MEDIUM | YES - needs raw timestamp bytes |

### 8.2 Current Rules (Working)

| Rule ID | Name | Severity | Status |
|---------|------|----------|--------|
| TAMPER-001 | CRC Header Mismatch | CRITICAL | [OK] |
| TAMPER-002 | CRC Section Mismatch | CRITICAL | PARTIAL |
| TAMPER-003 | Missing TrustedDWG | WARNING | [OK] |
| TAMPER-004 | Invalid TrustedDWG | CRITICAL | [OK] |
| TAMPER-005 | Timestamp Reversal | CRITICAL | NEEDS DEEP PARSING |
| ... | ... | ... | ... |

---

## 9. Implementation Priorities

### 9.1 Phase 1: Section Map Decompression (BLOCKING)

**Without this, nothing else works.**

| Task | Priority | Blocked By |
|------|----------|------------|
| Implement R2010+ section locator parsing | P0 | None |
| Implement section page decompression (LZ) | P0 | Section locator |
| Implement section CRC validation | P0 | Decompression |
| Test with real AC1032 files | P0 | All above |

### 9.2 Phase 2: Drawing Variables Extraction

| Task | Priority | Blocked By |
|------|----------|------------|
| Locate AcDb:Header in decompressed sections | P0 | Phase 1 |
| Parse TDCREATE from header | P0 | Header location |
| Parse TDUPDATE from header | P0 | Header location |
| Parse TDINDWG from header | P0 | Header location |
| Parse GUIDs from header | P1 | Header location |
| Validate cross-timestamp rules | P0 | All timestamps |

### 9.3 Phase 3: Handle Map Analysis

| Task | Priority | Blocked By |
|------|----------|------------|
| Locate AcDb:Handles in decompressed sections | P1 | Phase 1 |
| Parse handle table | P1 | Handles location |
| Implement gap detection | P1 | Handle parsing |
| Implement suspicious pattern detection | P1 | Gap detection |

### 9.4 Phase 4: R2018+ Encryption (If Needed)

| Task | Priority | Blocked By |
|------|----------|------------|
| Research R2018+ encryption method | P1 | None |
| Implement detection | P1 | Research |
| Implement decryption (if legally possible) | P1 | Research |

---

## 9. Reference Documentation

### 9.1 Primary References

1. **Open Design Specification for .dwg files v5.4.1**
   - https://www.opendesign.com/files/guestdownloads/OpenDesign_Specification_for_.dwg_files.pdf
   - Section 4: File Structure
   - Section 5: System Section Page Map
   - Section 6: Data Section Page

2. **LibreDWG Source Code**
   - https://github.com/LibreDWG/libredwg
   - `src/decode_r2004.c` - R2004+ decoding
   - `src/decode_r2007.c` - R2007+ specifics
   - `src/bits.c` - Bit reading utilities

3. **ODA Teigha SDK Documentation** (if available)
   - Section decompression algorithms
   - Handle table parsing

### 9.2 Key Binary Offsets (AC1032)

```
Header:
  0x00-0x05: "AC1032" version string
  0x0C-0x0F: Preview image address
  0x20-0x3F: Section locator records (may be encrypted)
  0x68-0x6B: Header CRC32
  0x6C-0x7F: Sentinel data
  0x80+: Section pages (compressed)

Section Page Header:
  0x00-0x03: Page type marker
  0x04-0x07: Decompressed size
  0x08-0x0B: Compressed size
  0x0C-0x0F: Compression type
  0x10-0x13: Section CRC32
  0x14+: Page data
```

---

## 10. Testing Requirements

### 10.1 Test Files Required

| File | Description | Purpose |
|------|-------------|---------|
| autocad_2018.dwg | Real AutoCAD 2018 file | AC1032 baseline |
| autocad_2021.dwg | Real AutoCAD 2021 file | Newer AC1032 |
| bricscad_2023.dwg | Real BricsCAD file | ODA-based comparison |
| nanocad_file.dwg | Real NanoCAD file | Russian origin testing |
| tampered_timestamps.dwg | Manually backdated | Tampering detection |
| large_file.dwg | 10MB+ real file | Performance testing |

### 10.2 Validation Criteria

| Test | Pass Criteria |
|------|---------------|
| TDCREATE extraction | Matches known creation date |
| TDUPDATE extraction | Matches file save date |
| TDINDWG extraction | Reasonable edit time (not garbage) |
| Section count | Matches expected sections |
| Decompression | All sections decompress without error |
| CRC validation | All section CRCs valid for clean files |

---

## 11. Glossary

| Term | Definition |
|------|------------|
| **MJD** | Modified Julian Date - days since Nov 17, 1858 |
| **TDCREATE** | Drawing creation timestamp (MJD, local time) |
| **TDUPDATE** | Last save timestamp (MJD, local time) |
| **TDINDWG** | Cumulative editing time (MJD fraction) |
| **ODA** | Open Design Alliance - DWG specification maintainer |
| **TrustedDWG** | Autodesk watermark proving genuine origin |
| **Section Map** | Index of all sections in file |
| **Handle** | Unique object identifier in DWG |
| **R2010+** | AutoCAD 2010 and later (AC1024, AC1027, AC1032) |

---

## 12. Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-01-05 | J. Ehrig | Initial draft |
| 2.0 | 2025-01-10 | J. Ehrig | Added deep parsing requirements, current status, implementation gaps |

---

## 13. Agent Implementation Notes

**For agent crews implementing this specification:**

1. **Start with FR-SECTION-001 and FR-SECTION-002** - these are blocking everything else
2. **Reference LibreDWG source code** for decompression algorithm
3. **Test incrementally** - verify section map before attempting variable extraction
4. **Log extensively** - byte offsets, raw values, parsing decisions
5. **Handle errors gracefully** - corrupted files should not crash
6. **Update progress callback** - user needs to see deep analysis is happening
7. **Validate against known files** - timestamps should match file properties

**Current failure point:** `dwg_forensic/parsers/sections.py` line 194 - section_map_addr calculation is wrong for AC1032. Fix this first.
