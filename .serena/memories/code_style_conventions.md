# Code Style & Conventions

## General Rules
- **Language**: Python 3.10+ with mandatory type hints
- **Line Length**: 100 characters (enforced by Ruff)
- **Formatter**: Ruff (configured in pyproject.toml)
- **Type Checker**: MyPy (ignore-missing-imports allowed)
- **Import Order**: isort (first-party: dwg_forensic)

## Ruff Configuration
Selected rules:
- E, W: pycodestyle errors/warnings
- F: Pyflakes
- I: isort
- B: flake8-bugbear
- C4: flake8-comprehensions
- UP: pyupgrade

Ignored:
- E501: line too long (handled by formatter)
- B008: function calls in default arguments

## Naming Conventions
- Classes: PascalCase (e.g., ForensicAnalysis, DWGParser)
- Functions/Methods: snake_case (e.g., analyze_file, validate_crc)
- Constants: SCREAMING_SNAKE_CASE (e.g., CRC32_SEED)
- Private: prefix with _ (e.g., _internal_helper)

## Type Hints
- All function signatures require type hints
- Return types must be specified
- Use `Optional[T]` for nullable values
- Use Union for multiple types (avoid bare Optional)
- Leverage Pydantic models for data structures

## Docstrings
- Module-level docstring required for each file
- Function docstrings for public APIs (especially core modules)
- Format: Google style (one-liner + detailed description for complex functions)

## Output Formatting
**CRITICAL**: No Unicode emoji - use ASCII alternatives:
- `[OK]` instead of checkmarks
- `[FAIL]` or `[X]` instead of x-marks
- `[WARN]` or `[!]` instead of warning symbols
- `[->]` or `-->` instead of arrows
- Reason: PowerShell/Windows terminal UTF-8 compatibility

## Commit Message Format
Conventional Commits:
```
type(scope): description
[body]
[footer]
```

Types: feat, fix, docs, test, refactor, style, chore
Scope: dwg_forensic subsystem (e.g., parsers, analysis, output)