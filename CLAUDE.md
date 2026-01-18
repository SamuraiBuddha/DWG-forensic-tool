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

# Run single test function
pytest tests/test_analyzer.py::test_function_name -v

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

### LLM-Enhanced Analysis (Ollama)

```bash
# Run with LLM reasoning (requires Ollama running locally)
dwg-forensic analyze /path/to/file.dwg --use-llm --llm-model llama3.2

# With knowledge graph enrichment (requires Neo4j)
dwg-forensic analyze /path/to/file.dwg --neo4j-uri bolt://localhost:7687
```

## Architecture

The codebase is organized by functional layers:

- **dwg_forensic/core/** - Core forensic operations: `analyzer.py` (main orchestrator), `intake.py` (file intake with SHA-256), `custody.py` (chain of custody), `database.py` (SQLite audit DB), `file_guard.py` (write protection)

- **dwg_forensic/parsers/** - Binary DWG parsing: `header.py` (R18+ header parsing at specific offsets), `crc.py` (CRC32 validation), `sections.py` (section map parsing), `handles.py` (handle gap detection), `drawing_vars.py` (drawing variables extraction), `ntfs.py` (NTFS timestamp extraction), `timestamp.py` (DWG internal timestamps)

- **dwg_forensic/analysis/** - Tampering detection: `anomaly.py` (timestamp/version anomalies), `rules/` (40 modular rules), `risk.py` (risk scoring), `cad_fingerprinting.py` (application identification), `smoking_gun.py` (definitive proof synthesis)

- **dwg_forensic/output/** - Report generation: `pdf_report.py` (ReportLab), `expert_witness.py`, `timeline.py` (SVG), `json_export.py`, `hex_dump.py`

- **dwg_forensic/knowledge/** - Neo4j knowledge graph integration: `client.py` (Neo4j connection), `enrichment.py` (legal citations, forensic standards)

- **dwg_forensic/llm/** - LLM integration (Ollama): `forensic_reasoner.py` (evidence reasoning), `forensic_narrator.py` (report narratives), `ollama_client.py` (API client)

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

**Tampering Rules** (analysis/rules/): 40 built-in rules organized into modular mixin classes:
- `rules_basic.py`: TAMPER-001 to 012 - CRC, watermarks, basic timestamps
- `rules_timestamp.py`: TAMPER-013 to 018 - Advanced timestamp manipulation (TDINDWG, version anachronism)
- `rules_ntfs.py`: TAMPER-019 to 028 - NTFS cross-validation ("smoking gun" indicators)
- `rules_fingerprint.py`: TAMPER-029 to 035 - CAD application fingerprinting (ODA, BricsCAD, NanoCAD)
- `rules_structure.py`: TAMPER-036 to 040 - Deep DWG structure analysis (handle gaps, section maps)

The `TamperingRuleEngine` composes all mixin classes and supports custom rules via `load_rules()` from YAML/JSON.

**LLM Integration** (llm/):
- `ForensicReasoner`: Uses LLM to evaluate evidence, filter red herrings (e.g., TrustedDWG absence), and identify true smoking guns through logical reasoning
- `ForensicNarrator`: Generates expert-level narrative explanations for reports
- Falls back gracefully when Ollama is unavailable

## Code Style

- Python 3.10+ with type hints required
- Line length: 100 characters (Ruff enforced)
- Commit format: `type(scope): description` (feat, fix, docs, test, refactor, style, chore)

## File Size Limits

**Maximum file size: 1,500 lines** (soft limit) / **2,000 lines** (hard limit)

Files exceeding these limits should be modularized:
- Extract logical groupings into separate modules
- Use mixin classes for large class hierarchies (see analysis/rules/ for example)
- Create subpackages for related functionality

## Output Formatting

**Do not use Unicode emoji.** Use ASCII-safe alternatives:
- `[OK]` instead of checkmarks
- `[FAIL]` or `[X]` instead of x-marks
- `[WARN]` or `[!]` instead of warning symbols
- `[->]` or `-->` instead of arrows

This ensures compatibility with PowerShell and Windows terminals where UTF-8 emoji may not render correctly.

## External Tools

**tools/libredwg/**: Contains LibreDWG integration for supplementary DWG parsing. Used to generate comparison JSON files in exampleCAD/ for validation.
