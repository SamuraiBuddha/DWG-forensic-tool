# Task Completion Workflow

## Before Committing Code
1. **Format & Lint**:
   ```bash
   ruff format dwg_forensic/
   ruff check dwg_forensic/
   ```

2. **Type Check**:
   ```bash
   mypy dwg_forensic/ --ignore-missing-imports
   ```

3. **Run Tests**:
   ```bash
   pytest tests/ -v
   ```
   - All tests must pass
   - Coverage should be maintained or improved
   - No pseudocode in production

4. **Verify Code Quality**:
   - No emoji in output (use ASCII alternatives)
   - Line length <= 100 characters
   - Type hints present on all public APIs

## Commit Guidelines
- Write one semantic commit per logical change
- Use conventional commit format: `type(scope): description`
- Reference issue numbers if applicable
- Keep commits focused and reviewable

## File Modularization
If a file exceeds 1,500 lines:
1. Extract logical groupings into separate modules
2. Use mixin classes for large class hierarchies (see analysis/rules/ pattern)
3. Create subpackages for related functionality
4. Update __init__.py imports

## Documentation Updates
- Update CLAUDE.md if architecture changes
- Add comments for non-obvious logic
- Update README.md for new features
- Keep API documentation in docstrings

## Final Checks
- All tests passing
- No type errors from mypy
- Ruff check and format clean
- No uncommitted changes (except .coverage, .pytest_cache)
- Commit messages follow conventional format