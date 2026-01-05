# Contributing to DWG Forensic Tool

Thank you for your interest in contributing to the DWG Forensic Tool! This document provides guidelines for contributing to the project.

## Development Setup

### Prerequisites

- Python 3.10+
- LibreDWG 0.13+ (`sudo apt-get install libredwg-tools` on Ubuntu)
- Git

### Getting Started

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/DWG-forensic-tool.git
cd DWG-forensic-tool

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run tests to verify setup
pytest tests/ -v
```

## Code Style

- Follow PEP 8 style guidelines
- Use type hints for all function signatures
- Maximum line length: 100 characters
- Use Black for formatting: `black dwg_forensic/`
- Use isort for imports: `isort dwg_forensic/`

## Testing

- Write tests for all new functionality
- Maintain >80% code coverage
- Run tests before submitting PR: `pytest tests/ -v --cov=dwg_forensic`

## Pull Request Process

1. Create a feature branch: `git checkout -b feature/your-feature-name`
2. Make your changes with clear commit messages
3. Add tests for new functionality
4. Update documentation if needed
5. Run linting and tests
6. Submit PR with clear description

## Commit Message Format

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
- `feat(parser): add CRC32 validation for R2018 format`
- `fix(report): correct timestamp formatting in PDF output`
- `docs(readme): add installation instructions for Windows`

## Reporting Issues

When reporting issues, please include:

- Operating system and version
- Python version
- LibreDWG version
- Steps to reproduce
- Expected vs actual behavior
- Sample DWG file (if possible and non-confidential)

## Security

If you discover a security vulnerability, please email security@ehrigbim.com instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the GPL v3 License.