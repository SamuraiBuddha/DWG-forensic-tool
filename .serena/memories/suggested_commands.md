# Suggested Commands for DWG Forensic Tool

## Installation & Setup
```bash
pip install -e .                    # Install in editable mode
pip install -e ".[dev]"             # Install with dev dependencies
```

## Development & Linting
```bash
ruff check dwg_forensic/            # Lint code
ruff format dwg_forensic/           # Format code
mypy dwg_forensic/ --ignore-missing-imports  # Type checking
```

## Testing
```bash
pytest tests/ -v                    # Run all tests with verbose output
pytest tests/test_analyzer.py -v    # Run specific test file
pytest tests/test_analyzer.py::test_function_name -v  # Run single test
pytest tests/ -v --cov=dwg_forensic --cov-report=html # Coverage report (HTML)
```

## CLI Commands
```bash
dwg-forensic analyze /path/to/file.dwg                    # Full analysis
dwg-forensic analyze /path/to/file.dwg -f json            # JSON output
dwg-forensic report /path/to/file.dwg -o out.pdf          # PDF report
dwg-forensic tampering /path/to/file.dwg                  # Tampering analysis
dwg-forensic validate-crc /path/to/file.dwg               # CRC validation
dwg-forensic check-watermark /path/to/file.dwg            # TrustedDWG check
dwg-forensic intake /path/to/file.dwg --case-id "ID" --examiner "Name"  # Intake
dwg-forensic gui                                          # Tkinter GUI
```

## Advanced Features (Optional)
```bash
# With LLM reasoning (requires Ollama running)
dwg-forensic analyze /path/to/file.dwg --use-llm --llm-model llama3.2

# With Neo4j knowledge graph enrichment
dwg-forensic analyze /path/to/file.dwg --neo4j-uri bolt://localhost:7687
```

## Git/Version Control
```bash
git status                          # Check current branch and changes
git add <files>                     # Stage changes
git commit -m "type(scope): desc"   # Commit with conventional format
git log --oneline                   # View recent commits
```

## File Size Limits
- **Soft limit**: 1,500 lines per file
- **Hard limit**: 2,000 lines per file
- When exceeded: modularize using separate modules or mixin classes