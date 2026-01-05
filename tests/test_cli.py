"""Tests for CLI module."""

from click.testing import CliRunner

from dwg_forensic.cli import main


def test_cli_version():
    """Test that CLI shows version."""
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "dwg-forensic" in result.output


def test_cli_help():
    """Test that CLI shows help."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "DWG Forensic Tool" in result.output
