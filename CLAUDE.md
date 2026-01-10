# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DWG Forensic Tool is a Python-based forensic analysis toolkit for AutoCAD DWG files. It provides chain of custody documentation, tampering detection, and litigation-ready PDF reports. The tool performs direct binary parsing of DWG files (no external DWG libraries required for core analysis).

## Build & Development Commands

```bash
# Install package (editable mode)
pip install -e .

# Install with dev dependencies
pip install -e ".[dev]"

# Run all tests with coverage
pytest tests/ -v

# Run specific test file
pytest tests/test_analyzer.py -v

# Lint and format
ruff check dwg_forensic/
ruff format dwg_forensic/

# Type checking
mypy dwg_forensic/ --ignore-missing-imports
```

## CLI Commands

```bash
dwg-forensic analyze /path/to/file.dwg           # Full analysis
dwg-forensic analyze /path/to/file.dwg -f json   # JSON output
dwg-forensic report /path/to/file.dwg -o out.pdf # PDF report
dwg-forensic tampering /path/to/file.dwg         # Tampering analysis
dwg-forensic validate-crc /path/to/file.dwg      # CRC validation
dwg-forensic check-watermark /path/to/file.dwg   # TrustedDWG check
dwg-forensic intake /path/to/file.dwg --case-id "ID" --examiner "Name"
dwg-forensic gui                                  # Tkinter GUI
```

## Architecture

The codebase is organized by functional layers:

- **dwg_forensic/core/** - Core forensic operations: `analyzer.py` (main orchestrator), `intake.py` (file intake with SHA-256), `custody.py` (chain of custody), `database.py` (SQLite audit DB), `file_guard.py` (write protection)

- **dwg_forensic/parsers/** - Binary DWG parsing: `header.py` (R18+ header parsing at specific offsets), `crc.py` (CRC32 validation), `watermark.py` (TrustedDWG detection)

- **dwg_forensic/analysis/** - Tampering detection: `anomaly.py` (timestamp/version anomalies), `rules.py` (12 built-in rules + custom YAML/JSON), `risk.py` (risk scoring)

- **dwg_forensic/output/** - Report generation: `pdf_report.py` (ReportLab), `expert_witness.py`, `timeline.py` (SVG), `json_export.py`, `hex_dump.py`

- **dwg_forensic/models.py** - Pydantic models: `ForensicAnalysis` (root output), `RiskLevel` enum, `AnomalyType` enum

- **dwg_forensic/utils/exceptions.py** - Exception hierarchy: `DWGForensicError` base, `UnsupportedVersionError`, `InvalidDWGError`, `CRCMismatchError`, `ParseError`, `IntakeError`

## Key Implementation Details

**Binary Header Parsing** (parsers/header.py):
- 0x00: Version string (6 bytes, e.g., "AC1032")
- 0x0B: Maintenance version (1 byte)
- 0x13: Codepage (2 bytes)
- 0x68: CRC32 checksum (4 bytes)

**Supported DWG Versions**:
- AC1024: AutoCAD 2010-2012 (R18)
- AC1027: AutoCAD 2013-2017 (R21)
- AC1032: AutoCAD 2018+ (R24)

**Tampering Rules** (analysis/rules.py): 12 built-in rules (TAMPER-001 through TAMPER-012) covering CRC mismatch, missing/invalid watermarks, timestamp anomalies, version inconsistencies. Custom rules loaded from YAML/JSON.

## Code Style

- Python 3.10+ with type hints required
- Line length: 100 characters (Ruff enforced)
- Commit format: `type(scope): description` (feat, fix, docs, test, refactor, style, chore)

## Output Formatting

**Do not use Unicode emoji.** Use ASCII-safe alternatives:
- `[OK]` instead of checkmarks
- `[FAIL]` or `[X]` instead of x-marks
- `[WARN]` or `[!]` instead of warning symbols
- `[->]` or `-->` instead of arrows

This ensures compatibility with PowerShell and Windows terminals where UTF-8 emoji may not render correctly.
