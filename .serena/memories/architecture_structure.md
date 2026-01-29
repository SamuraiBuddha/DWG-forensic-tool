# Architecture & Codebase Structure

## Module Organization
```
dwg_forensic/
├── core/                  # Core forensic operations
│   ├── analyzer.py       # Main orchestrator
│   ├── intake.py         # File intake with SHA-256
│   ├── custody.py        # Chain of custody
│   ├── database.py       # SQLite audit DB
│   └── file_guard.py     # Write protection
├── parsers/              # Binary DWG parsing
│   ├── header.py         # R18+ header (offsets: 0x00, 0x0B, 0x13, 0x68)
│   ├── crc.py            # CRC32 validation
│   ├── sections.py       # Section map parsing
│   ├── handles.py        # Handle gap detection
│   ├── drawing_vars.py   # Drawing variables
│   ├── ntfs.py           # NTFS timestamp extraction
│   ├── timestamp.py      # DWG internal timestamps
│   ├── revit_detection.py # Revit export detection
│   ├── structure_analysis.py
│   ├── compression.py
│   ├── encryption.py
│   └── metadata.py
├── analysis/             # Tampering detection
│   ├── anomaly.py        # Timestamp/version anomalies
│   ├── rules/            # 40 modular rules
│   │   ├── engine.py     # TamperingRuleEngine
│   │   ├── rules_basic.py        # TAMPER-001 to 012
│   │   ├── rules_timestamp.py    # TAMPER-013 to 018
│   │   ├── rules_ntfs.py         # TAMPER-019 to 028
│   │   ├── rules_fingerprint.py  # TAMPER-029 to 035
│   │   └── rules_structure.py    # TAMPER-036 to 040
│   ├── cad_fingerprinting.py # App identification
│   ├── smoking_gun.py        # Definitive proof synthesis
│   ├── risk.py               # Risk scoring
│   └── version_dates.py
├── output/               # Report generation
│   ├── pdf_report.py     # ReportLab PDF
│   ├── expert_witness.py
│   ├── timeline.py       # SVG timelines
│   ├── json_export.py
│   ├── hex_dump.py
│   └── text_utils.py
├── knowledge/            # Neo4j integration (optional)
│   ├── client.py         # Neo4j connection
│   ├── enrichment.py     # Citations, standards
│   └── models.py
├── llm/                  # LLM integration (optional)
│   ├── forensic_reasoner.py  # Evidence reasoning
│   ├── forensic_narrator.py  # Report narratives
│   └── ollama_client.py      # API client
├── utils/                # Utilities
│   ├── exceptions.py     # DWGForensicError hierarchy
│   ├── audit.py
│   └── diagnostics.py
├── models.py             # Pydantic data models
├── cli.py                # Click CLI entrypoint
└── gui.py                # Tkinter GUI entrypoint
```

## Key Data Models (pydantic)
- `ForensicAnalysis`: Root output model
- `RiskLevel`: Enum (CRITICAL, HIGH, MEDIUM, LOW)
- `AnomalyType`: Enum (timestamp manipulation, version mismatch, etc.)

## Supported DWG Versions
- AC1024: AutoCAD 2010-2012 (R18)
- AC1027: AutoCAD 2013-2017 (R21)
- AC1032: AutoCAD 2018+ (R24)

## Rule Engine Pattern
Uses mixin classes (rules_basic, rules_timestamp, rules_ntfs, rules_fingerprint, rules_structure) composed by TamperingRuleEngine. Custom rules loadable via YAML/JSON.