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

**Tampering Rules** (analysis/rules/): 40 built-in rules (TAMPER-001 through TAMPER-040) organized into modular mixin classes:
- `rules_basic.py`: TAMPER-001 to 012 - CRC, watermarks, basic timestamps
- `rules_timestamp.py`: TAMPER-013 to 018 - Advanced timestamp manipulation (TDINDWG, version anachronism)
- `rules_ntfs.py`: TAMPER-019 to 028 - NTFS cross-validation ("smoking gun" indicators)
- `rules_fingerprint.py`: TAMPER-029 to 035 - CAD application fingerprinting (ODA, BricsCAD, NanoCAD)
- `rules_structure.py`: TAMPER-036 to 040 - Deep DWG structure analysis (handle gaps, section maps)

Custom rules loaded from YAML/JSON via `TamperingRuleEngine.load_rules()`.

## Code Style

- Python 3.10+ with type hints required
- Line length: 100 characters (Ruff enforced)
- Commit format: `type(scope): description` (feat, fix, docs, test, refactor, style, chore)

## File Size Limits

**Maximum file size: 1,500 lines** (soft limit) / **2,000 lines** (hard limit)

Files exceeding these limits should be modularized:
- Extract logical groupings into separate modules
- Use mixin classes for large class hierarchies
- Create subpackages for related functionality

Rationale:
1. Maintains readability and navigability
2. Reduces merge conflicts in collaborative development
3. Enables better code review granularity
4. Ensures files fit within LLM context windows for AI-assisted development

## Output Formatting

**Do not use Unicode emoji.** Use ASCII-safe alternatives:
- `[OK]` instead of checkmarks
- `[FAIL]` or `[X]` instead of x-marks
- `[WARN]` or `[!]` instead of warning symbols
- `[->]` or `-->` instead of arrows

This ensures compatibility with PowerShell and Windows terminals where UTF-8 emoji may not render correctly.
