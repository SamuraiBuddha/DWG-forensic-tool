"""Tests for CLI module."""

import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from dwg_forensic.cli import main, print_status


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

    def test_print_status_function(self, capsys):
        """Test print_status helper function."""
        from dwg_forensic.cli import console
        # Just ensure it doesn't raise
        print_status("[OK]", "Test message")
        print_status("[FAIL]", "Error message")
        print_status("[WARN]", "Warning message")
        print_status("[INFO]", "Info message")
        print_status("[ERROR]", "Error message")
        print_status("[UNKNOWN]", "Unknown status")


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

    def test_analyze_with_output_file(self, runner, valid_dwg_ac1032, temp_dir):
        """Test analyze with output to file."""
        output_path = temp_dir / "report.json"
        result = runner.invoke(main, ["analyze", str(valid_dwg_ac1032), "-o", str(output_path)])
        assert result.exit_code == 0
        assert output_path.exists()
        assert "Report saved" in result.output

    def test_analyze_verbose_mode(self, runner, valid_dwg_ac1032):
        """Test analyze with verbose mode."""
        result = runner.invoke(main, ["analyze", str(valid_dwg_ac1032), "-v"])
        assert result.exit_code == 0

    def test_analyze_verbose_with_error(self, runner, temp_dir):
        """Test analyze verbose mode shows exception details."""
        # Create an invalid file that will cause an unexpected error
        bad_file = temp_dir / "invalid.dwg"
        bad_file.write_bytes(b"NOTDWG")

        result = runner.invoke(main, ["analyze", str(bad_file), "-v"])
        assert result.exit_code == 1


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

    def test_metadata_unsupported_version(self, runner, temp_dir):
        """Test metadata extraction on unsupported version."""
        dwg_path = temp_dir / "old.dwg"
        header = bytearray(32)
        header[0:6] = b"AC1009"
        dwg_path.write_bytes(bytes(header))

        result = runner.invoke(main, ["metadata", str(dwg_path)])
        assert result.exit_code == 1


class TestTamperingCommand:
    """Tests for tampering analysis command."""

    def test_tampering_table_output(self, runner, valid_dwg_ac1032):
        """Test tampering analysis with table output."""
        result = runner.invoke(main, ["tampering", str(valid_dwg_ac1032)])
        assert result.exit_code == 0
        assert "Risk" in result.output

    def test_tampering_json_output(self, runner, valid_dwg_ac1032):
        """Test tampering analysis with JSON output."""
        result = runner.invoke(main, ["tampering", str(valid_dwg_ac1032), "-f", "json"])
        assert result.exit_code == 0
        assert "risk_level" in result.output

    def test_tampering_with_output_file(self, runner, valid_dwg_ac1032, temp_dir):
        """Test tampering analysis with output to file."""
        output_path = temp_dir / "tampering_report.json"
        result = runner.invoke(main, ["tampering", str(valid_dwg_ac1032), "-o", str(output_path)])
        assert result.exit_code == 0
        assert output_path.exists()

    def test_tampering_verbose_mode(self, runner, valid_dwg_ac1032):
        """Test tampering analysis with verbose mode."""
        result = runner.invoke(main, ["tampering", str(valid_dwg_ac1032), "-v"])
        assert result.exit_code == 0


class TestListRulesCommand:
    """Tests for list-rules command."""

    def test_list_rules_table(self, runner):
        """Test listing rules in table format."""
        result = runner.invoke(main, ["list-rules"])
        assert result.exit_code == 0
        assert "TAMPER-001" in result.output
        assert "CRC" in result.output

    def test_list_rules_json(self, runner):
        """Test listing rules in JSON format."""
        result = runner.invoke(main, ["list-rules", "--format", "json"])
        assert result.exit_code == 0
        # Verify JSON-like output is present
        assert "TAMPER-001" in result.output
        assert '"id"' in result.output or "id" in result.output


class TestCompareCommand:
    """Tests for compare command."""

    def test_compare_two_files(self, runner, valid_dwg_ac1032, temp_dir):
        """Test comparing two DWG files."""
        # Create a second file
        file2 = temp_dir / "file2.dwg"
        file2.write_bytes(valid_dwg_ac1032.read_bytes())

        result = runner.invoke(main, ["compare", str(valid_dwg_ac1032), str(file2)])
        assert result.exit_code == 0


class TestBatchCommand:
    """Tests for batch command."""

    def test_batch_directory(self, runner, temp_dir):
        """Test batch processing a directory."""
        result = runner.invoke(main, ["batch", str(temp_dir)])
        assert result.exit_code == 0

    def test_batch_recursive(self, runner, temp_dir):
        """Test batch processing with recursive flag."""
        result = runner.invoke(main, ["batch", str(temp_dir), "--recursive"])
        assert result.exit_code == 0


class TestProtectCommand:
    """Tests for protect command."""

    def test_protect_file(self, runner, temp_dir):
        """Test setting write protection on a file."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("test content")

        result = runner.invoke(main, ["protect", str(test_file)])
        # May succeed or warn if already protected
        assert result.exit_code == 0 or "[INFO]" in result.output

    def test_protect_already_protected(self, runner, temp_dir):
        """Test protecting an already protected file."""
        test_file = temp_dir / "protected.txt"
        test_file.write_text("test content")

        # First protection
        runner.invoke(main, ["protect", str(test_file)])
        # Second should indicate already protected
        result = runner.invoke(main, ["protect", str(test_file)])
        assert result.exit_code == 0


class TestCheckProtectionCommand:
    """Tests for check-protection command."""

    def test_check_protection_unprotected(self, runner, temp_dir):
        """Test checking protection status of unprotected file."""
        test_file = temp_dir / "unprotected.txt"
        test_file.write_text("test content")

        result = runner.invoke(main, ["check-protection", str(test_file)])
        # Unprotected file returns exit code 1
        assert "[WARN]" in result.output or result.exit_code == 1


class TestIntakeCommand:
    """Tests for intake command."""

    def test_intake_help(self, runner):
        """Test intake command help."""
        result = runner.invoke(main, ["intake", "--help"])
        assert result.exit_code == 0
        assert "case-id" in result.output
        assert "examiner" in result.output

    def test_intake_missing_args(self, runner, valid_dwg_ac1032):
        """Test intake command with missing required arguments."""
        result = runner.invoke(main, ["intake", str(valid_dwg_ac1032)])
        # Should fail due to missing required options
        assert result.exit_code != 0


class TestVerifyCommand:
    """Tests for verify command."""

    def test_verify_help(self, runner):
        """Test verify command help."""
        result = runner.invoke(main, ["verify", "--help"])
        assert result.exit_code == 0
        assert "EVIDENCE-ID" in result.output


class TestCustodyChainCommand:
    """Tests for custody-chain command."""

    def test_custody_chain_help(self, runner):
        """Test custody-chain command help."""
        result = runner.invoke(main, ["custody-chain", "--help"])
        assert result.exit_code == 0
        assert "EVIDENCE-ID" in result.output


class TestLogEventCommand:
    """Tests for log-event command."""

    def test_log_event_help(self, runner):
        """Test log-event command help."""
        result = runner.invoke(main, ["log-event", "--help"])
        assert result.exit_code == 0
        assert "event-type" in result.output
        assert "examiner" in result.output
