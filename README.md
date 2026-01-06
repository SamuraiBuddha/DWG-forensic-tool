# DWG Forensic Tool

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/SamuraiBuddha/DWG-forensic-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/SamuraiBuddha/DWG-forensic-tool/actions/workflows/ci.yml)

**Open-source forensic analysis toolkit for AutoCAD DWG files designed for litigation support, chain of custody documentation, and tampering detection.**

## Purpose

DWG Forensic Tool fills a critical gap in digital forensics: there is no existing turnkey solution for forensic analysis of AutoCAD DWG files. While tools like EnCase and FTK handle general forensics, they lack deep DWG-specific analysis capabilities. This tool provides:

- **Chain of Custody**: Cryptographically verified intake and handling
- **Tampering Detection**: CRC validation, timestamp anomaly detection, watermark verification
- **Metadata Extraction**: Complete DWGPROPS, application fingerprints, edit history
- **Litigation-Ready Reports**: PDF reports with hash attestation for court submission

## What It Detects

| Indicator | Detection Method | Forensic Value |
|-----------|------------------|----------------|
| File modified after save | CRC32 mismatch | Direct evidence of tampering |
| Non-Autodesk software used | TrustedDWG watermark missing/invalid | Shows file touched by third-party tool |
| Timestamp manipulation | Creation > Modification date | Indicates backdating attempt |
| Version inconsistency | Header vs internal object versions | Suggests conversion or modification |
| Suspicious edit time | Editing time vs date range mismatch | Potential fabrication indicator |
| Application fingerprint | ACAD ID, build number analysis | Identifies exact software used |

## Installation

```bash
# Clone repository
git clone https://github.com/SamuraiBuddha/DWG-forensic-tool.git
cd DWG-forensic-tool

# Install package with dependencies
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

## Quick Start

```bash
# Full forensic analysis (table output)
dwg-forensic analyze /path/to/file.dwg

# Full forensic analysis (JSON output)
dwg-forensic analyze /path/to/file.dwg -f json

# Generate PDF forensic report
dwg-forensic report /path/to/file.dwg -o report.pdf --case-id "2025-CV-1234"

# Generate expert witness methodology document
dwg-forensic expert-witness /path/to/file.dwg -o witness.pdf --expert-name "Dr. Smith"

# Generate visual timeline
dwg-forensic timeline /path/to/file.dwg -o timeline.svg

# Run tampering analysis
dwg-forensic tampering /path/to/file.dwg

# CRC validation only
dwg-forensic validate-crc /path/to/file.dwg

# TrustedDWG watermark check
dwg-forensic check-watermark /path/to/file.dwg

# Extract metadata
dwg-forensic metadata /path/to/file.dwg

# Chain of custody intake
dwg-forensic intake /path/to/evidence.dwg --case-id "2025-CV-1234" --examiner "John Doe"
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `analyze` | Full forensic analysis with CRC, watermark, and risk assessment |
| `report` | Generate litigation-ready PDF forensic report |
| `expert-witness` | Generate expert witness methodology document |
| `timeline` | Generate visual timeline of file events |
| `tampering` | Run tampering detection rule engine |
| `validate-crc` | Validate header CRC checksum |
| `check-watermark` | Check TrustedDWG watermark presence and validity |
| `metadata` | Extract and display file metadata |
| `intake` | Securely intake evidence file with chain of custody |
| `list-rules` | List all tampering detection rules |
| `info` | Show tool version and system information |

## Sample Output

```json
{
  "file_info": {
    "filename": "floorplan_v3.dwg",
    "sha256": "a1b2c3d4e5f6...",
    "file_size_bytes": 2458624,
    "intake_timestamp": "2025-01-05T14:32:00Z"
  },
  "header_analysis": {
    "version_string": "AC1032",
    "version_name": "AutoCAD 2018-2024",
    "maintenance_version": 3,
    "codepage": 30
  },
  "trusted_dwg": {
    "watermark_present": true,
    "watermark_text": "Autodesk DWG. This file is a Trusted DWG...",
    "watermark_valid": true
  },
  "crc_validation": {
    "header_crc_stored": "0x4A2B3C1D",
    "header_crc_calculated": "0x4A2B3C1D",
    "is_valid": true
  },
  "risk_assessment": {
    "overall_risk": "LOW",
    "tampering_score": 0.0,
    "risk_factors": []
  }
}
```

## Supported DWG Versions

| Version | Code | AutoCAD Version | Support Level |
|---------|------|-----------------|---------------|
| R18 | AC1024 | AutoCAD 2010-2012 | Full |
| R21 | AC1027 | AutoCAD 2013-2017 | Full |
| R24 | AC1032 | AutoCAD 2018-2024 | Full |

**Note:** Earlier versions (R13-R14, AC1012-AC1014) can be read but have limited analysis capabilities.

## Project Structure

```
DWG-forensic-tool/
|-- dwg_forensic/
|   |-- __init__.py
|   |-- cli.py                 # Command-line interface
|   |-- models.py              # Data models (Pydantic)
|   |-- core/
|   |   |-- analyzer.py        # Main forensic analyzer
|   |   |-- intake.py          # Evidence intake
|   |   |-- custody.py         # Chain of custody
|   |   |-- file_guard.py      # Write protection
|   |   +-- database.py        # SQLite database
|   |-- parsers/
|   |   |-- header.py          # Header parsing
|   |   |-- crc.py             # CRC validation
|   |   +-- watermark.py       # TrustedDWG detection
|   |-- analysis/
|   |   |-- anomaly.py         # Anomaly detection
|   |   |-- rules.py           # Tampering rules engine
|   |   +-- risk.py            # Risk scoring
|   |-- output/
|   |   |-- pdf_report.py      # PDF generation
|   |   |-- expert_witness.py  # Expert witness docs
|   |   |-- json_export.py     # JSON export
|   |   |-- hex_dump.py        # Hex dump formatting
|   |   +-- timeline.py        # Timeline visualization
|   +-- utils/
|       |-- audit.py           # Forensic audit logging
|       +-- exceptions.py      # Custom exceptions
|-- tests/                     # Comprehensive test suite
|-- docs/
|   +-- PRD.md                 # Product Requirements Document
|-- pyproject.toml
+-- README.md
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=dwg_forensic --cov-report=html

# Run specific test module
pytest tests/test_analyzer.py -v

# Run integration tests only
pytest tests/test_integration.py -v
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run linter
ruff check dwg_forensic/

# Format code
ruff format dwg_forensic/

# Type checking
mypy dwg_forensic/
```

## Technical Details

### DWG File Structure (Forensic Perspective)

| Offset | Length | Field | Forensic Use |
|--------|--------|-------|-------------|
| 0x00 | 6 | Version string | Identifies AutoCAD version |
| 0x06 | 5 | Zero bytes | Anomaly if non-zero |
| 0x0B | 1 | Maintenance version | Specific patch level |
| 0x0D | 4 | Preview address | Points to thumbnail |
| 0x13 | 2 | DWGCODEPAGE | Language/encoding |
| 0x68 | 4 | CRC32 | Integrity verification |

### Tampering Detection Rules

The tool includes 12 built-in tampering detection rules:

- `TAMPER-001`: Header CRC Mismatch
- `TAMPER-002`: Missing TrustedDWG Watermark
- `TAMPER-003`: Invalid TrustedDWG Watermark
- `TAMPER-004`: Unsupported DWG Version
- `TAMPER-005`: Timestamp Anomaly
- `TAMPER-006`: Suspicious File Size
- `TAMPER-007`: Version String Anomaly
- And more...

## License

GPL v3 - See [LICENSE](LICENSE) for details.

## Legal Disclaimer

This tool is designed to assist forensic examiners and legal professionals. Results should be interpreted by qualified experts. The tool does not make legal determinations about document authenticity.

## Related Resources

- [Open Design Specification for .dwg files](https://www.opendesign.com/files/guestdownloads/OpenDesign_Specification_for_.dwg_files.pdf)
- [Autodesk TrustedDWG Documentation](https://www.autodesk.com/blogs/autocad/trusteddwg-exploring-features-benefits-autocad/)

---

**Built for litigation support by [Ehrig BIM & IT Consultation, Inc.](https://github.com/SamuraiBuddha)**
