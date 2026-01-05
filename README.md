# DWG Forensic Tool

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![LibreDWG](https://img.shields.io/badge/LibreDWG-0.13+-green.svg)](https://www.gnu.org/software/libredwg/)

**Open-source forensic analysis toolkit for AutoCAD DWG files designed for litigation support, chain of custody documentation, and tampering detection.**

## 🎯 Purpose

DWG Forensic Tool fills a critical gap in digital forensics: there is no existing turnkey solution for forensic analysis of AutoCAD DWG files. While tools like EnCase and FTK handle general forensics, they lack deep DWG-specific analysis capabilities. This tool provides:

- **Chain of Custody**: Cryptographically verified intake and handling
- **Tampering Detection**: CRC validation, timestamp anomaly detection, watermark verification
- **Metadata Extraction**: Complete DWGPROPS, application fingerprints, edit history
- **Litigation-Ready Reports**: PDF reports with hash attestation for court submission

## 🔍 What It Detects

| Indicator | Detection Method | Forensic Value |
|-----------|------------------|----------------|
| File modified after save | CRC32 mismatch | Direct evidence of tampering |
| Non-Autodesk software used | TrustedDWG watermark missing/invalid | Shows file touched by third-party tool |
| Timestamp manipulation | Creation > Modification date | Indicates backdating attempt |
| Version inconsistency | Header vs internal object versions | Suggests conversion or modification |
| Suspicious edit time | Editing time vs date range mismatch | Potential fabrication indicator |
| Application fingerprint | ACAD ID, build number analysis | Identifies exact software used |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    DWG Forensic Analyzer                         │
├─────────────────────────────────────────────────────────────────┤
│  INPUT LAYER                                                     │
│  ├── dwg_intake.py      - File ingestion with SHA-256           │
│  ├── custody_chain.py   - Audit logging & timestamps            │
│  └── file_guard.py      - Write-protection verification         │
├─────────────────────────────────────────────────────────────────┤
│  PARSING LAYER                                                   │
│  ├── header_parser.py   - Binary header extraction              │
│  ├── crc_validator.py   - CRC validation across sections        │
│  ├── watermark_detector.py - TrustedDWG detection               │
│  └── metadata_extractor.py - DWGPROPS extraction                │
├─────────────────────────────────────────────────────────────────┤
│  ANALYSIS LAYER                                                  │
│  ├── anomaly_detector.py - Version/timestamp anomalies          │
│  ├── tampering_rules.py  - Rule engine for flagging             │
│  ├── fingerprint_analyzer.py - Application identification       │
│  └── timeline_builder.py - Edit history reconstruction          │
├─────────────────────────────────────────────────────────────────┤
│  OUTPUT LAYER                                                    │
│  ├── report_generator.py - PDF forensic reports                 │
│  ├── json_exporter.py    - Structured data export               │
│  ├── timeline_viz.py     - Visual timeline generation           │
│  └── witness_summary.py  - Expert witness documentation         │
└─────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/SamuraiBuddha/DWG-forensic-tool.git
cd DWG-forensic-tool

# Install dependencies
pip install -r requirements.txt

# Install LibreDWG (Ubuntu/Debian)
sudo apt-get install libredwg-tools

# Run forensic analysis
python -m dwg_forensic analyze /path/to/suspect.dwg --output report.pdf

# Chain of custody intake
python -m dwg_forensic intake /path/to/evidence.dwg --case-id "2025-CV-1234"
```

## 📋 CLI Commands

```bash
# Full forensic analysis
dwg-forensic analyze <file.dwg> [--output report.pdf] [--json] [--verbose]

# Chain of custody intake (creates audit record)
dwg-forensic intake <file.dwg> --case-id <id> --examiner <name>

# Quick metadata extraction
dwg-forensic metadata <file.dwg> [--format json|yaml|table]

# CRC validation only
dwg-forensic validate-crc <file.dwg>

# TrustedDWG check
dwg-forensic check-watermark <file.dwg>

# Compare two versions of a file
dwg-forensic compare <file1.dwg> <file2.dwg> --report diff.pdf

# Batch analysis
dwg-forensic batch <directory> --recursive --output-dir reports/
```

## 📊 Sample Output

```json
{
  "file_info": {
    "filename": "floorplan_v3.dwg",
    "sha256": "a1b2c3d4e5f6...",
    "file_size_bytes": 2458624,
    "intake_timestamp": "2025-01-05T14:32:00Z"
  },
  "header_analysis": {
    "version_string": "AC1027",
    "version_name": "AutoCAD 2013-2017",
    "maintenance_version": 3,
    "codepage": "ANSI_1252"
  },
  "trusted_dwg": {
    "watermark_present": true,
    "watermark_text": "Autodesk DWG. This file is a Trusted DWG...",
    "watermark_valid": true
  },
  "crc_validation": {
    "header_crc_stored": "0x4A2B3C1D",
    "header_crc_calculated": "0x4A2B3C1D",
    "crc_valid": true
  },
  "metadata": {
    "title": "Building A - Floor 3",
    "author": "John Smith",
    "last_saved_by": "Jane Doe",
    "created_date": "2024-03-15T09:00:00Z",
    "modified_date": "2024-11-20T16:45:00Z",
    "revision_number": 47,
    "total_editing_time_hours": 156.5
  },
  "application_fingerprint": {
    "created_by": "AutoCAD 2024",
    "application_id": "ACAD0001427",
    "build_number": "U.51.0.0"
  },
  "anomalies": [],
  "tampering_indicators": [],
  "risk_assessment": "LOW"
}
```

## 🔬 Technical Details

### DWG File Structure (Forensic Perspective)

| Offset | Length | Field | Forensic Use |
|--------|--------|-------|-------------|
| 0x00 | 6 | Version string | Identifies AutoCAD version |
| 0x06 | 5 | Zero bytes | Anomaly if non-zero |
| 0x0B | 1 | Maintenance version | Specific patch level |
| 0x0D | 4 | Preview address | Points to thumbnail |
| 0x13 | 2 | DWGCODEPAGE | Language/encoding |
| 0x68 | 4 | CRC32 | Integrity verification |

### Supported DWG Versions

- ✅ R13 (AC1012) - Full support
- ✅ R14 (AC1014) - Full support
- ✅ R2000 (AC1015) - Full support
- ✅ R2004 (AC1018) - Full support
- ✅ R2007 (AC1021) - Full support
- ✅ R2010 (AC1024) - Full support
- ✅ R2013 (AC1027) - Full support
- ✅ R2018 (AC1032) - Full support
- ⚠️ R2021+ - Partial (read-only analysis)

## 📁 Project Structure

```
DWG-forensic-tool/
├── dwg_forensic/
│   ├── __init__.py
│   ├── cli.py                 # Command-line interface
│   ├── core/
│   │   ├── __init__.py
│   │   ├── intake.py          # File ingestion
│   │   ├── custody.py         # Chain of custody
│   │   └── file_guard.py      # Write protection
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── header.py          # Header parsing
│   │   ├── crc.py             # CRC validation
│   │   ├── watermark.py       # TrustedDWG detection
│   │   └── metadata.py        # DWGPROPS extraction
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── anomaly.py         # Anomaly detection
│   │   ├── tampering.py       # Tampering rules
│   │   ├── fingerprint.py     # App identification
│   │   └── timeline.py        # Edit history
│   ├── output/
│   │   ├── __init__.py
│   │   ├── report.py          # PDF generation
│   │   ├── json_export.py     # JSON export
│   │   └── visualization.py   # Timeline viz
│   └── utils/
│       ├── __init__.py
│       ├── hashing.py         # SHA-256 utilities
│       └── logging.py         # Audit logging
├── tests/
│   ├── __init__.py
│   ├── test_header_parser.py
│   ├── test_crc_validator.py
│   ├── test_watermark.py
│   ├── test_tampering_rules.py
│   └── fixtures/              # Test DWG files
├── docs/
│   ├── PRD.md                 # Product Requirements
│   ├── ARCHITECTURE.md
│   └── FORENSIC_GUIDE.md      # For expert witnesses
├── requirements.txt
├── setup.py
├── pyproject.toml
└── README.md
```

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=dwg_forensic --cov-report=html

# Test specific module
pytest tests/test_crc_validator.py -v
```

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## 📜 License

GPL v3 - This project uses LibreDWG which is GPL-licensed.

## ⚠️ Legal Disclaimer

This tool is designed to assist forensic examiners and legal professionals. Results should be interpreted by qualified experts. The tool does not make legal determinations about document authenticity.

## 🔗 Related Resources

- [Open Design Specification for .dwg files](https://www.opendesign.com/files/guestdownloads/OpenDesign_Specification_for_.dwg_files.pdf)
- [GNU LibreDWG](https://www.gnu.org/software/libredwg/)
- [Autodesk TrustedDWG Documentation](https://www.autodesk.com/blogs/autocad/trusteddwg-exploring-features-benefits-autocad/)

---

**Built for litigation support by [Ehrig BIM & IT Consultation, Inc.](https://github.com/SamuraiBuddha)**