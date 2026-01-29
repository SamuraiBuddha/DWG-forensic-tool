# DWG Forensic Tool - Project Overview

## Purpose
Open-source forensic analysis toolkit for AutoCAD DWG files. Provides:
- Chain of custody documentation
- Tampering detection (40+ rules)
- Litigation-ready PDF reports
- Direct binary parsing (no external DWG libraries required for core analysis)

## Tech Stack
- **Language**: Python 3.10+ with type hints required
- **CLI Framework**: Click 8.0+
- **Data Validation**: Pydantic 2.0+
- **Binary Parsing**: Custom parsers (no DWG libraries)
- **Reporting**: ReportLab 4.0+ (PDF), Rich (console)
- **Database**: SQLAlchemy 2.0+ with SQLite
- **Config**: PyYAML 6.0+
- **GUI**: Tkinter (standard library)
- **Optional**: Ollama (LLM), Neo4j (knowledge graph)

## Key Metadata
- **Author**: Jordan Paul Ehrig (jordan@ehrigbim.com)
- **License**: GPL-3.0-or-later
- **Repository**: https://github.com/SamuraiBuddha/DWG-forensic-tool
- **Version**: 0.1.0 (Alpha)
- **Platform**: Windows (target), Cross-platform support (Python)

## Python Version Support
- Python 3.10, 3.11, 3.12 (via pyproject.toml classifiers)