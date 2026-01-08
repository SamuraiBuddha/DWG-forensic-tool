"""Tests for CLI module."""

import pytest
from click.testing import CliRunner

from dwg_forensic.cli import main


@pytest.fixture
def runner():
    """Create a CLI runner."""
    return CliRunner()


class TestCLIBasic:
    """Basic CLI tests."""

    def test_cli_version(self, runner):
        """Test that CLI shows version."""
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "dwg-forensic" in result.output

    def test_cli_help(self, runner):
        """Test that CLI shows help."""
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "DWG Forensic Tool" in result.output

    def test_cli_info_command(self, runner):
        """Test info command."""
        result = runner.invoke(main, ["info"])
        assert result.exit_code == 0
        assert "DWG Forensic Tool" in result.output
        assert "AC1024" in result.output
        assert "AC1027" in result.output
        assert "AC1032" in result.output


class TestAnalyzeCommand:
    """Tests for analyze command."""

    def test_analyze_valid_file(self, runner, valid_dwg_ac1032):
        """Test analyzing a valid DWG file."""
        result = runner.invoke(main, ["analyze", str(valid_dwg_ac1032)])
        assert result.exit_code == 0

    def test_analyze_json_output(self, runner, valid_dwg_ac1032):
        """Test analyze with JSON output format."""
        result = runner.invoke(main, ["analyze", str(valid_dwg_ac1032), "-f", "json"])
        assert result.exit_code == 0
        assert "file_info" in result.output

    def test_analyze_legacy_version(self, runner, unsupported_dwg_ac1015):
        """Test analyzing legacy version file with limited support."""
        result = runner.invoke(main, ["analyze", str(unsupported_dwg_ac1015)])
        # AC1015 is now analyzed with limited support
        assert result.exit_code == 0

    def test_analyze_truly_unsupported_version(self, runner, temp_dir):
        """Test analyzing truly unsupported version file."""
        # Create an AC1009 (R11-R12) file which is truly unsupported
        dwg_path = temp_dir / "old_r11.dwg"
        header = bytearray(32)
        header[0:6] = b"AC1009"
        dwg_path.write_bytes(bytes(header))

        result = runner.invoke(main, ["analyze", str(dwg_path)])
        assert result.exit_code == 1
        assert "Unsupported version" in result.output or "[ERROR]" in result.output

    def test_analyze_nonexistent_file(self, runner):
        """Test analyzing nonexistent file."""
        result = runner.invoke(main, ["analyze", "/nonexistent/file.dwg"])
        assert result.exit_code != 0


class TestValidateCRCCommand:
    """Tests for validate-crc command."""

    def test_validate_crc_valid(self, runner, valid_dwg_ac1032):
        """Test CRC validation on valid file."""
        result = runner.invoke(main, ["validate-crc", str(valid_dwg_ac1032)])
        assert result.exit_code == 0
        assert "[OK]" in result.output

    def test_validate_crc_invalid(self, runner, corrupted_crc_dwg):
        """Test CRC validation on corrupted file."""
        result = runner.invoke(main, ["validate-crc", str(corrupted_crc_dwg)])
        assert result.exit_code == 1
        assert "[FAIL]" in result.output


class TestCheckWatermarkCommand:
    """Tests for check-watermark command."""

    def test_check_watermark_present(self, runner, dwg_with_watermark):
        """Test watermark check on file with watermark."""
        result = runner.invoke(main, ["check-watermark", str(dwg_with_watermark)])
        assert result.exit_code == 0
        # Should find watermark
        assert "[OK]" in result.output or "watermark" in result.output.lower()

    def test_check_watermark_absent(self, runner, dwg_without_watermark):
        """Test watermark check on file without watermark."""
        result = runner.invoke(main, ["check-watermark", str(dwg_without_watermark)])
        # Should indicate no watermark found (not an error, just a warning)
        assert result.exit_code == 0
        assert "[WARN]" in result.output or "No" in result.output


class TestMetadataCommand:
    """Tests for metadata command."""

    def test_metadata_table_output(self, runner, valid_dwg_ac1032):
        """Test metadata extraction with table output."""
        result = runner.invoke(main, ["metadata", str(valid_dwg_ac1032)])
        assert result.exit_code == 0
        assert "AC1032" in result.output

    def test_metadata_json_output(self, runner, valid_dwg_ac1032):
        """Test metadata extraction with JSON output."""
        result = runner.invoke(main, ["metadata", str(valid_dwg_ac1032), "-f", "json"])
        assert result.exit_code == 0
        assert "version_string" in result.output
