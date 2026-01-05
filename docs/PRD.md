# Product Requirements Document (PRD)
# DWG Forensic Tool

**Version:** 1.0  
**Date:** January 5, 2025  
**Author:** Jordan Paul Ehrig / Ehrig BIM & IT Consultation, Inc.  
**Status:** Development

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

1. **Automated forensic analysis** of DWG file internals
2. **Chain of custody** documentation with cryptographic verification
3. **Tampering detection** through CRC validation, watermark analysis, and anomaly detection
4. **Litigation-ready reports** suitable for court submission
5. **Expert witness support** documentation

### 1.3 Target Users

| User Type | Primary Needs |
|-----------|---------------|
| Digital Forensic Examiners | Deep file analysis, chain of custody |
| Litigation Support Teams | Evidence documentation, court-ready reports |
| Expert Witnesses | Technical documentation, defensible methodology |
| Law Firms | Easy-to-understand summaries, hash verification |
| Insurance Investigators | Timestamp verification, modification detection |
| IP/Trade Secret Investigators | Origin analysis, software fingerprinting |

---

## 2. Goals & Success Metrics

### 2.1 Primary Goals

| Goal | Metric | Target |
|------|--------|--------|
| G1: Complete metadata extraction | Fields extracted vs. available | 100% of DWGPROPS fields |
| G2: Accurate CRC validation | False positive/negative rate | <0.1% |
| G3: TrustedDWG detection | Detection accuracy | 100% for supported versions |
| G4: Chain of custody integrity | Audit log completeness | 100% of operations logged |
| G5: Report generation | Time to generate report | <30 seconds per file |
| G6: Version coverage | DWG versions supported | R13 through R2021 |

### 2.2 Non-Goals (Out of Scope for v1.0)

- DWG file repair or modification
- Visual rendering of DWG content
- Real-time monitoring/watching directories
- Cloud-based analysis
- Mobile application
- DXF forensics (separate tool)

---

## 3. Technical Requirements

### 3.1 Core Dependencies

| Component | Version | Purpose | License |
|-----------|---------|---------|--------|
| Python | 3.10+ | Runtime | PSF |
| LibreDWG | 0.13+ | DWG parsing | GPLv3 |
| ReportLab | 4.0+ | PDF generation | BSD |
| Click | 8.0+ | CLI framework | BSD |
| SQLite | 3.35+ | Audit database | Public Domain |
| Pydantic | 2.0+ | Data validation | MIT |
| Rich | 13.0+ | CLI output formatting | MIT |

### 3.2 System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Linux, macOS, Windows 10+ | Ubuntu 22.04 LTS |
| RAM | 4 GB | 16 GB |
| Storage | 500 MB (tool) | 10 GB (with evidence cache) |
| Python | 3.10 | 3.12 |

---

## 4. Functional Requirements

### 4.1 Module: File Intake (FR-INTAKE)

#### FR-INTAKE-001: Secure File Ingestion
**Priority:** P0 (Critical)  
**Description:** System shall ingest DWG files with immediate SHA-256 hash calculation  
**Acceptance Criteria:**
- Hash calculated before any parsing operations
- Original file never modified
- Hash stored in audit log with timestamp
- Support for single file and batch intake

#### FR-INTAKE-002: Chain of Custody Record Creation
**Priority:** P0 (Critical)  
**Description:** System shall create a chain of custody record upon intake  
**Acceptance Criteria:**
- Unique evidence ID generated (UUID v4)
- Case ID association (user-provided)
- Examiner identification captured
- Timestamp in ISO 8601 format with timezone
- Record stored in SQLite database
- Record exportable to JSON/PDF

#### FR-INTAKE-003: Write Protection Verification
**Priority:** P1 (High)  
**Description:** System shall verify file is not modified during analysis  
**Acceptance Criteria:**
- Pre-analysis hash recorded
- Post-analysis hash calculated
- Mismatch triggers immediate alert
- Analysis aborted if file changes detected

---

### 4.2 Module: Header Parsing (FR-HEADER)

#### FR-HEADER-001: Version String Extraction
**Priority:** P0 (Critical)  
**Description:** System shall extract and decode the DWG version string  
**Acceptance Criteria:**
- Read bytes 0x00-0x05
- Map to human-readable version (e.g., AC1027 → "AutoCAD 2013-2017")
- Support versions R13 through R2021
- Flag unknown version strings as anomalies

#### FR-HEADER-002: Maintenance Version Extraction
**Priority:** P1 (High)  
**Description:** System shall extract maintenance/patch version  
**Acceptance Criteria:**
- Read byte 0x0B
- Include in metadata output
- Document known maintenance version meanings

#### FR-HEADER-003: Codepage Extraction
**Priority:** P1 (High)  
**Description:** System shall extract DWGCODEPAGE value  
**Acceptance Criteria:**
- Read bytes 0x13-0x14
- Map to encoding name (e.g., ANSI_1252, UTF-8)
- Use for proper string decoding in metadata

#### FR-HEADER-004: Preview Address Extraction
**Priority:** P2 (Medium)  
**Description:** System shall locate and extract thumbnail preview  
**Acceptance Criteria:**
- Read preview seeker at 0x0D
- Extract BMP/PNG thumbnail if present
- Save as separate file with evidence ID prefix

---

### 4.3 Module: CRC Validation (FR-CRC)

#### FR-CRC-001: Header CRC32 Validation
**Priority:** P0 (Critical)  
**Description:** System shall validate the header CRC32 checksum  
**Acceptance Criteria:**
- Calculate CRC32 over header bytes per ODA specification
- Compare against stored CRC32 at offset 0x68
- Report match/mismatch status
- For R18+, use 32-bit CRC algorithm
- For pre-R18, use 8-bit CRC algorithm

#### FR-CRC-002: Section CRC Validation
**Priority:** P1 (High)  
**Description:** System shall validate CRCs for all file sections  
**Acceptance Criteria:**
- Identify all sections with CRC protection
- Validate each section's CRC
- Report per-section validation results
- Flag sections with CRC mismatches

#### FR-CRC-003: CRC Mismatch Analysis
**Priority:** P1 (High)  
**Description:** System shall analyze CRC mismatches for tampering indicators  
**Acceptance Criteria:**
- Identify which sections have mismatches
- Estimate likelihood of intentional vs. corruption
- Generate tampering probability score

---

### 4.4 Module: TrustedDWG Detection (FR-TRUST)

#### FR-TRUST-001: Watermark Presence Detection
**Priority:** P0 (Critical)  
**Description:** System shall detect presence of TrustedDWG watermark  
**Acceptance Criteria:**
- Search for "Autodesk DWG" string in file
- Extract full watermark text if present
- Report presence/absence
- Note: Only applicable for AC1021 (R2007) and later

#### FR-TRUST-002: Watermark Validity Analysis
**Priority:** P1 (High)  
**Description:** System shall analyze TrustedDWG watermark validity  
**Acceptance Criteria:**
- Verify watermark format matches expected pattern
- Detect partial or corrupted watermarks
- Identify non-Autodesk watermarks (e.g., ODA files pre-2007 lawsuit)

#### FR-TRUST-003: Application Origin Detection
**Priority:** P0 (Critical)  
**Description:** System shall identify the application that created/modified the file  
**Acceptance Criteria:**
- Extract ACAD ID string (e.g., ACAD0001409)
- Map to application (AutoCAD, Inventor, verticals)
- Detect ODA-based applications
- Detect other third-party applications

---

### 4.5 Module: Metadata Extraction (FR-META)

#### FR-META-001: DWGPROPS Extraction
**Priority:** P0 (Critical)  
**Description:** System shall extract all DWGPROPS fields  
**Acceptance Criteria:**
- Extract: Title, Subject, Author, Keywords, Comments
- Extract: Last Saved By, Revision Number, Hyperlink Base
- Extract: Created Date, Modified Date
- Handle missing/empty fields gracefully

#### FR-META-002: Editing Time Extraction
**Priority:** P1 (High)  
**Description:** System shall extract total editing time  
**Acceptance Criteria:**
- Extract cumulative editing time in hours/minutes
- Convert to human-readable format
- Include in metadata output

#### FR-META-003: Application Fingerprint Extraction
**Priority:** P0 (Critical)  
**Description:** System shall extract application fingerprint data  
**Acceptance Criteria:**
- Extract "Created By" application and version
- Extract application ID (ACAD ID)
- Extract build number
- Extract registry version indicator

#### FR-META-004: Custom Properties Extraction
**Priority:** P2 (Medium)  
**Description:** System shall extract custom DWGPROPS  
**Acceptance Criteria:**
- Enumerate all custom property names
- Extract custom property values
- Preserve data types

---

### 4.6 Module: Anomaly Detection (FR-ANOMALY)

#### FR-ANOMALY-001: Timestamp Anomaly Detection
**Priority:** P0 (Critical)  
**Description:** System shall detect timestamp anomalies  
**Acceptance Criteria:**
- Flag if Created Date > Modified Date
- Flag if Modified Date is in the future
- Flag if editing time inconsistent with date range
- Flag if filesystem timestamps don't match internal timestamps

#### FR-ANOMALY-002: Version Anomaly Detection
**Priority:** P1 (High)  
**Description:** System shall detect version inconsistencies  
**Acceptance Criteria:**
- Compare header version vs. internal object versions
- Flag downgraded files (newer objects in older format)
- Flag version mismatches

#### FR-ANOMALY-003: Structural Anomaly Detection
**Priority:** P1 (High)  
**Description:** System shall detect structural anomalies  
**Acceptance Criteria:**
- Detect orphaned objects
- Detect corrupted object handles
- Detect incomplete sections
- Detect unusual padding or slack space

---

### 4.7 Module: Tampering Analysis (FR-TAMPER)

#### FR-TAMPER-001: Tampering Rule Engine
**Priority:** P0 (Critical)  
**Description:** System shall apply tampering detection rules  
**Acceptance Criteria:**
- Configurable rule definitions (YAML/JSON)
- Each rule has: ID, description, severity, detection logic
- Rules return: passed, failed, inconclusive
- Support for custom rules

#### FR-TAMPER-002: Risk Scoring
**Priority:** P1 (High)  
**Description:** System shall calculate tampering risk score  
**Acceptance Criteria:**
- Aggregate individual rule results
- Weight by severity
- Output: LOW, MEDIUM, HIGH, CRITICAL
- Include confidence percentage

#### FR-TAMPER-003: Tampering Evidence Documentation
**Priority:** P0 (Critical)  
**Description:** System shall document tampering evidence  
**Acceptance Criteria:**
- For each failed rule, document:
  - What was expected
  - What was found
  - Byte offset (if applicable)
  - Hex dump of relevant section
- Export to forensic report

---

### 4.8 Module: Report Generation (FR-REPORT)

#### FR-REPORT-001: PDF Forensic Report
**Priority:** P0 (Critical)  
**Description:** System shall generate PDF forensic reports  
**Acceptance Criteria:**
- Executive summary (1 page, non-technical)
- Technical findings section
- Metadata table
- Anomaly/tampering findings
- Hash attestation page
- Chain of custody log
- Appendix with hex dumps (optional)

#### FR-REPORT-002: JSON Export
**Priority:** P0 (Critical)  
**Description:** System shall export analysis to JSON  
**Acceptance Criteria:**
- Complete analysis data in JSON format
- Schema documented
- Valid JSON output
- Support for pretty-print and compact modes

#### FR-REPORT-003: Expert Witness Summary
**Priority:** P1 (High)  
**Description:** System shall generate expert witness documentation  
**Acceptance Criteria:**
- Methodology description
- Tool version and dependencies
- Reproducibility instructions
- Limitations statement
- Opinion support framework

#### FR-REPORT-004: Timeline Visualization
**Priority:** P2 (Medium)  
**Description:** System shall generate visual timeline  
**Acceptance Criteria:**
- Show creation date, modifications, saves
- SVG or PNG output
- Include in PDF report

---

### 4.9 Module: CLI Interface (FR-CLI)

#### FR-CLI-001: Analyze Command
**Priority:** P0 (Critical)  
**Description:** Primary analysis command  
**Syntax:** `dwg-forensic analyze <file.dwg> [options]`  
**Options:**
- `--output, -o`: Output file path
- `--format, -f`: Output format (pdf, json, both)
- `--verbose, -v`: Verbosity level (0-3)
- `--rules`: Custom rules file path
- `--no-hash`: Skip hash calculation (not recommended)

#### FR-CLI-002: Intake Command
**Priority:** P0 (Critical)  
**Description:** Evidence intake command  
**Syntax:** `dwg-forensic intake <file.dwg> --case-id <id> --examiner <name>`  
**Options:**
- `--case-id`: Case identifier (required)
- `--examiner`: Examiner name (required)
- `--notes`: Intake notes
- `--copy-to`: Copy file to evidence store

#### FR-CLI-003: Metadata Command
**Priority:** P1 (High)  
**Description:** Quick metadata extraction  
**Syntax:** `dwg-forensic metadata <file.dwg> [--format json|yaml|table]`

#### FR-CLI-004: Validate-CRC Command
**Priority:** P1 (High)  
**Description:** CRC-only validation  
**Syntax:** `dwg-forensic validate-crc <file.dwg>`

#### FR-CLI-005: Check-Watermark Command
**Priority:** P1 (High)  
**Description:** TrustedDWG check only  
**Syntax:** `dwg-forensic check-watermark <file.dwg>`

#### FR-CLI-006: Compare Command
**Priority:** P2 (Medium)  
**Description:** Compare two DWG files  
**Syntax:** `dwg-forensic compare <file1.dwg> <file2.dwg> [--report diff.pdf]`

#### FR-CLI-007: Batch Command
**Priority:** P1 (High)  
**Description:** Batch analysis  
**Syntax:** `dwg-forensic batch <directory> [--recursive] [--output-dir reports/]`

---

## 5. Non-Functional Requirements

### 5.1 Performance (NFR-PERF)

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-PERF-001 | Single file analysis time | <10 seconds for <50MB file |
| NFR-PERF-002 | Batch throughput | >100 files/hour |
| NFR-PERF-003 | Memory usage | <500MB for single file analysis |
| NFR-PERF-004 | Report generation | <30 seconds per report |

### 5.2 Reliability (NFR-REL)

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-REL-001 | Analysis completion rate | 99.9% (graceful failure on corrupt files) |
| NFR-REL-002 | Hash accuracy | 100% (verified against reference implementations) |
| NFR-REL-003 | Audit log durability | SQLite with WAL mode, ACID compliance |

### 5.3 Security (NFR-SEC)

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-SEC-001 | Read-only operation | Tool never modifies input files |
| NFR-SEC-002 | Audit log integrity | HMAC signing of log entries |
| NFR-SEC-003 | Evidence isolation | Each case in separate SQLite database |

### 5.4 Maintainability (NFR-MAINT)

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-MAINT-001 | Code coverage | >80% unit test coverage |
| NFR-MAINT-002 | Documentation | All public APIs documented |
| NFR-MAINT-003 | Modularity | Each module independently testable |

---

## 6. Data Models

### 6.1 ForensicAnalysis Schema

```python
class ForensicAnalysis(BaseModel):
    """Root model for forensic analysis output"""
    
    # Identification
    analysis_id: UUID
    tool_version: str
    analysis_timestamp: datetime
    
    # File Information
    file_info: FileInfo
    
    # Analysis Results
    header_analysis: HeaderAnalysis
    crc_validation: CRCValidation
    trusted_dwg: TrustedDWGAnalysis
    metadata: DWGMetadata
    application_fingerprint: ApplicationFingerprint
    
    # Findings
    anomalies: List[Anomaly]
    tampering_indicators: List[TamperingIndicator]
    risk_assessment: RiskAssessment
    
    # Chain of Custody
    custody_chain: Optional[CustodyChain]
```

### 6.2 CustodyChain Schema

```python
class CustodyChain(BaseModel):
    """Chain of custody record"""
    
    evidence_id: UUID
    case_id: str
    
    intake: CustodyEvent
    events: List[CustodyEvent]
    
    file_hash_sha256: str
    file_hash_verified: bool

class CustodyEvent(BaseModel):
    """Single chain of custody event"""
    
    event_id: UUID
    event_type: Literal["intake", "analysis", "export", "transfer"]
    timestamp: datetime
    examiner: str
    notes: Optional[str]
    hash_at_event: str
```

### 6.3 TamperingIndicator Schema

```python
class TamperingIndicator(BaseModel):
    """Single tampering indicator"""
    
    rule_id: str
    rule_name: str
    severity: Literal["info", "warning", "critical"]
    status: Literal["passed", "failed", "inconclusive"]
    
    description: str
    expected: str
    found: str
    
    byte_offset: Optional[int]
    hex_dump: Optional[str]
    
    confidence: float  # 0.0 - 1.0
```

---

## 7. Tampering Detection Rules

### 7.1 Built-in Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| TAMPER-001 | CRC Header Mismatch | Critical | Header CRC32 doesn't match calculated value |
| TAMPER-002 | CRC Section Mismatch | Critical | Section CRC doesn't match calculated value |
| TAMPER-003 | Missing TrustedDWG | Warning | TrustedDWG watermark absent (R2007+) |
| TAMPER-004 | Invalid TrustedDWG | Critical | TrustedDWG watermark present but malformed |
| TAMPER-005 | Timestamp Reversal | Critical | Created date is after modified date |
| TAMPER-006 | Future Timestamp | Critical | Modified date is in the future |
| TAMPER-007 | Edit Time Mismatch | Warning | Editing time inconsistent with date range |
| TAMPER-008 | Version Downgrade | Warning | Newer objects saved in older format |
| TAMPER-009 | Version Mismatch | Warning | Header version doesn't match internal versions |
| TAMPER-010 | Non-Autodesk Origin | Info | File created by non-Autodesk application |
| TAMPER-011 | Orphaned Objects | Warning | Objects with invalid handle references |
| TAMPER-012 | Unusual Slack Space | Info | Unexpected data in padding areas |

### 7.2 Custom Rule Format

```yaml
# custom_rules.yaml
rules:
  - id: CUSTOM-001
    name: "Specific Author Check"
    severity: warning
    description: "Check if author matches expected value"
    condition:
      field: metadata.author
      operator: not_equals
      value: "John Smith"
    message: "Author is not the expected 'John Smith'"
```

---

## 8. Integration Points

### 8.1 LibreDWG Integration

```python
# Primary integration via subprocess + JSON output
def parse_dwg_with_libredwg(filepath: Path) -> dict:
    result = subprocess.run(
        ["dwgread", "-O", "json", str(filepath)],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)
```

### 8.2 Direct Binary Parsing (for header forensics)

```python
# Direct binary access for header-level forensics
def parse_header_binary(filepath: Path) -> HeaderAnalysis:
    with open(filepath, 'rb') as f:
        version = f.read(6).decode('ascii')
        f.seek(0x0B)
        maintenance = struct.unpack('B', f.read(1))[0]
        # ... etc
```

### 8.3 Future API Integration

- REST API endpoint for remote analysis
- Integration with EnCase via EnScript wrapper
- Integration with Relativity for eDiscovery workflows

---

## 9. Development Phases

### Phase 1: Core MVP (Week 1)
**Goal:** Basic analysis and reporting

| Task | Priority | Estimate |
|------|----------|----------|
| Project scaffolding | P0 | 2h |
| Header parser (binary) | P0 | 4h |
| CRC validation | P0 | 6h |
| TrustedDWG detection | P0 | 4h |
| DWGPROPS extraction (via LibreDWG JSON) | P0 | 4h |
| Basic CLI (analyze command) | P0 | 4h |
| JSON output | P0 | 2h |
| Unit tests for core modules | P0 | 4h |

**Deliverable:** CLI tool that extracts metadata and validates CRC

### Phase 2: Chain of Custody (Week 1-2)
**Goal:** Evidence handling infrastructure

| Task | Priority | Estimate |
|------|----------|----------|
| SQLite schema design | P0 | 2h |
| Intake module | P0 | 4h |
| Custody chain logging | P0 | 4h |
| Hash verification | P0 | 2h |
| CLI intake command | P0 | 2h |
| Custody export (JSON/PDF) | P1 | 4h |

**Deliverable:** Evidence intake with chain of custody

### Phase 3: Tampering Detection (Week 2)
**Goal:** Advanced analysis capabilities

| Task | Priority | Estimate |
|------|----------|----------|
| Anomaly detection module | P0 | 6h |
| Tampering rule engine | P0 | 6h |
| Built-in rules implementation | P0 | 4h |
| Risk scoring | P1 | 3h |
| Custom rules support | P1 | 4h |

**Deliverable:** Automated tampering detection

### Phase 4: Reporting (Week 2)
**Goal:** Litigation-ready output

| Task | Priority | Estimate |
|------|----------|----------|
| PDF report template | P0 | 4h |
| Report generator | P0 | 6h |
| Executive summary generator | P1 | 3h |
| Hex dump formatter | P1 | 2h |
| Timeline visualization | P2 | 4h |
| Expert witness template | P1 | 3h |

**Deliverable:** Professional forensic reports

### Phase 5: Polish & Testing (Week 2-3)
**Goal:** Production readiness

| Task | Priority | Estimate |
|------|----------|----------|
| Integration tests | P0 | 6h |
| Test with real-world samples | P0 | 4h |
| Documentation | P1 | 4h |
| Error handling improvements | P1 | 4h |
| Performance optimization | P2 | 4h |
| Package for distribution | P1 | 2h |

**Deliverable:** v1.0 release

---

## 10. Testing Strategy

### 10.1 Test Categories

| Category | Description | Tools |
|----------|-------------|-------|
| Unit | Individual function testing | pytest |
| Integration | Module interaction testing | pytest |
| Regression | Ensure fixes don't break | pytest + CI |
| Forensic Validation | Compare against known samples | Manual + automated |
| Performance | Throughput and memory | pytest-benchmark |

### 10.2 Test Fixtures Required

| Fixture | Description | Source |
|---------|-------------|--------|
| valid_r2013.dwg | Clean R2013 file | AutoCAD 2017 |
| valid_r2018.dwg | Clean R2018 file | AutoCAD 2020 |
| tampered_crc.dwg | File with modified CRC | Hex edited |
| no_watermark.dwg | R2007+ without TrustedDWG | Third-party CAD |
| backdated.dwg | File with timestamp manipulation | Manually created |
| corrupted.dwg | Partially corrupted file | Truncated |

### 10.3 Continuous Integration

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install LibreDWG
        run: sudo apt-get install libredwg-tools
      - name: Install dependencies
        run: pip install -r requirements.txt -r requirements-dev.txt
      - name: Run tests
        run: pytest tests/ -v --cov=dwg_forensic
```

---

## 11. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| LibreDWG doesn't parse newer versions | Medium | High | Fallback to binary header parsing |
| CRC algorithm undocumented | Low | High | Reference ODA specification |
| TrustedDWG format changes | Low | Medium | Version-specific detection logic |
| Performance issues with large files | Medium | Medium | Streaming parsing, memory limits |
| Legal concerns with reverse engineering | Low | High | GPL license, clean-room implementation |

---

## 12. Glossary

| Term | Definition |
|------|------------|
| **DWG** | Drawing file format, native to AutoCAD |
| **DWGPROPS** | Drawing properties (metadata) stored in DWG |
| **TrustedDWG** | Autodesk watermark embedded in DWG files |
| **CRC** | Cyclic Redundancy Check, error-detecting code |
| **ODA** | Open Design Alliance, creators of DWG specification |
| **LibreDWG** | GNU open-source DWG library |
| **Chain of Custody** | Documentation of evidence handling |
| **R2013** | AutoCAD 2013 file format version (AC1027) |

---

## 13. References

1. [Open Design Specification for .dwg files v5.4.1](https://www.opendesign.com/files/guestdownloads/OpenDesign_Specification_for_.dwg_files.pdf)
2. [GNU LibreDWG Documentation](https://www.gnu.org/software/libredwg/manual/)
3. [Autodesk TrustedDWG Documentation](https://www.autodesk.com/blogs/autocad/trusteddwg-exploring-features-benefits-autocad/)
4. [EnCase DWG EnScript](https://security.opentext.com/appDetails/AutoCAD-DWG-Summary-Info-Reader)
5. [DWG File Format - Library of Congress](https://www.loc.gov/preservation/digital/formats/fdd/fdd000445.shtml)

---

## 14. Approval

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Product Owner | Jordan Paul Ehrig | 2025-01-05 | ✓ |
| Technical Lead | TBD | | |
| QA Lead | TBD | | |

---

**Document Version History**

| Version | Date | Author | Changes |
|---------|------|--------|----------|
| 1.0 | 2025-01-05 | J. Ehrig | Initial draft |