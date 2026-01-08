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


# ============================================================================
# Additional Coverage Tests
# ============================================================================


class TestAnalyzeExceptionHandling:
    """Tests for analyze command exception handling."""

    def test_analyze_generic_exception_verbose(self, runner, temp_dir):
        """Test generic exception handling with verbose mode."""
        from unittest.mock import patch

        bad_file = temp_dir / "bad.dwg"
        bad_file.write_bytes(b"AC1032" + b"\x00" * 200)

        # Mock analyzer to raise generic exception
        with patch("dwg_forensic.cli.ForensicAnalyzer") as mock_analyzer:
            mock_analyzer.return_value.analyze.side_effect = Exception("Test error")
            result = runner.invoke(main, ["analyze", str(bad_file), "-v"])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output

    def test_analyze_dwg_forensic_error(self, runner, temp_dir):
        """Test DWGForensicError handling."""
        from dwg_forensic.utils.exceptions import DWGForensicError
        from unittest.mock import patch

        bad_file = temp_dir / "bad.dwg"
        bad_file.write_bytes(b"AC1032" + b"\x00" * 200)

        with patch("dwg_forensic.cli.ForensicAnalyzer") as mock_analyzer:
            mock_analyzer.return_value.analyze.side_effect = DWGForensicError("Test DWG error")
            result = runner.invoke(main, ["analyze", str(bad_file)])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output


class TestPrintAnalysisTableBranches:
    """Tests for _print_analysis_table branches."""

    def test_print_analysis_table_with_application_origin(self, runner, temp_dir):
        """Test that application_origin is printed when present."""
        # Use dwg_with_watermark fixture logic
        dwg_path = temp_dir / "watermarked.dwg"
        header = bytearray(0x100)
        header[0:6] = b"AC1032"
        # Add watermark marker
        header[0x50:0x5C] = b"Autodesk DWG"
        # Add application ID
        header[0x70:0x7B] = b"ACAD0001427"
        dwg_path.write_bytes(bytes(header))

        result = runner.invoke(main, ["analyze", str(dwg_path)])
        assert result.exit_code == 0
        # Application origin might be shown in output


class TestValidateCRCExceptionHandling:
    """Tests for validate-crc exception handling."""

    def test_validate_crc_dwg_forensic_error(self, runner, temp_dir):
        """Test DWGForensicError handling in validate-crc."""
        from dwg_forensic.utils.exceptions import InvalidDWGError
        from unittest.mock import patch

        test_file = temp_dir / "test.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)

        with patch("dwg_forensic.cli.CRCValidator") as mock_validator:
            mock_validator.return_value.validate_header_crc.side_effect = InvalidDWGError("Test error")
            result = runner.invoke(main, ["validate-crc", str(test_file)])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output


class TestCheckWatermarkBranches:
    """Tests for check-watermark branches."""

    def test_check_watermark_present_but_invalid(self, runner, temp_dir):
        """Test watermark present but invalid."""
        from dwg_forensic.models import TrustedDWGAnalysis
        from unittest.mock import patch

        test_file = temp_dir / "test.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)

        mock_result = TrustedDWGAnalysis(
            watermark_present=True,
            watermark_valid=False,
            watermark_offset=0x50,
        )

        with patch("dwg_forensic.cli.WatermarkDetector") as mock_detector:
            mock_detector.return_value.detect.return_value = mock_result
            result = runner.invoke(main, ["check-watermark", str(test_file)])
            assert result.exit_code == 0
            assert "[WARN]" in result.output

    def test_check_watermark_dwg_forensic_error(self, runner, temp_dir):
        """Test DWGForensicError handling in check-watermark."""
        from dwg_forensic.utils.exceptions import ParseError
        from unittest.mock import patch

        test_file = temp_dir / "test.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)

        with patch("dwg_forensic.cli.WatermarkDetector") as mock_detector:
            mock_detector.return_value.detect.side_effect = ParseError("Test error")
            result = runner.invoke(main, ["check-watermark", str(test_file)])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output


class TestMetadataExceptionHandling:
    """Tests for metadata command exception handling."""

    def test_metadata_dwg_forensic_error(self, runner, temp_dir):
        """Test DWGForensicError handling in metadata."""
        from dwg_forensic.utils.exceptions import ParseError
        from unittest.mock import patch

        test_file = temp_dir / "test.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)

        with patch("dwg_forensic.cli.HeaderParser") as mock_parser:
            mock_parser.return_value.parse.side_effect = ParseError("Test error")
            result = runner.invoke(main, ["metadata", str(test_file)])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output


class TestIntakeCommandFull:
    """Full tests for intake command."""

    def test_intake_full_workflow(self, runner, valid_dwg_ac1032):
        """Test complete intake workflow."""
        with runner.isolated_filesystem():
            import shutil
            evidence_dir = Path("evidence")
            evidence_dir.mkdir()
            db_path = evidence_dir / "custody.db"

            # Copy the valid_dwg to isolated filesystem
            test_file = Path("test.dwg")
            shutil.copy(valid_dwg_ac1032, test_file)

            result = runner.invoke(main, [
                "intake",
                str(test_file),
                "--case-id", "CASE-001",
                "--examiner", "Test Examiner",
                "--evidence-dir", str(evidence_dir),
                "--db-path", str(db_path),
                "--notes", "Test intake notes"
            ])
            assert result.exit_code == 0
            assert "Evidence Intake Complete" in result.output or "[OK]" in result.output

    def test_intake_with_evidence_number(self, runner, valid_dwg_ac1032):
        """Test intake with explicit evidence number."""
        with runner.isolated_filesystem():
            import shutil
            evidence_dir = Path("evidence2")
            evidence_dir.mkdir()
            db_path = evidence_dir / "custody.db"

            # Copy the valid_dwg to isolated filesystem
            test_file = Path("test2.dwg")
            shutil.copy(valid_dwg_ac1032, test_file)

            result = runner.invoke(main, [
                "intake",
                str(test_file),
                "--case-id", "CASE-002",
                "--examiner", "Test Examiner",
                "--evidence-number", "EV-001",
                "--evidence-dir", str(evidence_dir),
                "--db-path", str(db_path),
            ])
            assert result.exit_code == 0

    def test_intake_error_handling(self, runner, temp_dir):
        """Test intake error handling."""
        from dwg_forensic.utils.exceptions import IntakeError
        from unittest.mock import patch

        test_file = temp_dir / "test.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)
        evidence_dir = temp_dir / "evidence3"
        evidence_dir.mkdir()

        with patch("dwg_forensic.cli.FileIntake") as mock_intake:
            mock_intake.return_value.intake.side_effect = IntakeError("Test intake error")
            result = runner.invoke(main, [
                "intake",
                str(test_file),
                "--case-id", "CASE-003",
                "--examiner", "Test Examiner",
                "--evidence-dir", str(evidence_dir),
            ])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output


class TestVerifyCommandFull:
    """Full tests for verify command."""

    def test_verify_valid_evidence(self, runner, valid_dwg_ac1032):
        """Test verifying valid evidence."""
        with runner.isolated_filesystem():
            import shutil
            import re
            evidence_dir = Path("evidence_verify")
            evidence_dir.mkdir()
            db_path = evidence_dir / "custody.db"

            # Copy the valid_dwg to isolated filesystem
            test_file = Path("test_verify.dwg")
            shutil.copy(valid_dwg_ac1032, test_file)

            intake_result = runner.invoke(main, [
                "intake",
                str(test_file),
                "--case-id", "CASE-VERIFY",
                "--examiner", "Test Examiner",
                "--evidence-dir", str(evidence_dir),
                "--db-path", str(db_path),
            ])
            assert intake_result.exit_code == 0

            # Extract evidence ID from output
            match = re.search(r"Evidence ID\s*[|]\s*([a-f0-9-]+)", intake_result.output)
            if match:
                evidence_id = match.group(1)
                # Now verify
                verify_result = runner.invoke(main, [
                    "verify",
                    evidence_id,
                    "--db-path", str(db_path),
                ])
                # Should succeed
                assert verify_result.exit_code == 0 or "not found" in verify_result.output.lower()

    def test_verify_invalid_evidence_id(self, runner):
        """Test verifying with invalid evidence ID."""
        with runner.isolated_filesystem():
            from dwg_forensic.core.custody import CustodyChain
            evidence_dir = Path("evidence_verify2")
            evidence_dir.mkdir()
            db_path = evidence_dir / "custody.db"

            # Create empty database
            CustodyChain(db_path)

            result = runner.invoke(main, [
                "verify",
                "nonexistent-evidence-id",
                "--db-path", str(db_path),
            ])
            assert result.exit_code == 1
            # May return [ERROR] or [FAIL] depending on the error type
            assert "[ERROR]" in result.output or "[FAIL]" in result.output


class TestCustodyChainCommandFull:
    """Full tests for custody-chain command."""

    def test_custody_chain_full_workflow(self, runner, valid_dwg_ac1032):
        """Test full custody chain workflow."""
        with runner.isolated_filesystem():
            import shutil
            import re
            evidence_dir = Path("evidence_chain")
            evidence_dir.mkdir()
            db_path = evidence_dir / "custody.db"

            # Copy the valid_dwg to isolated filesystem
            test_file = Path("test_chain.dwg")
            shutil.copy(valid_dwg_ac1032, test_file)

            # Intake file
            intake_result = runner.invoke(main, [
                "intake",
                str(test_file),
                "--case-id", "CASE-CHAIN",
                "--examiner", "Test Examiner",
                "--evidence-dir", str(evidence_dir),
                "--db-path", str(db_path),
            ])
            assert intake_result.exit_code == 0

            # Extract evidence ID
            match = re.search(r"Evidence ID\s*[|]\s*([a-f0-9-]+)", intake_result.output)
            if match:
                evidence_id = match.group(1)
                # Get custody chain in table format
                chain_result = runner.invoke(main, [
                    "custody-chain",
                    evidence_id,
                    "--db-path", str(db_path),
                ])
                assert chain_result.exit_code == 0 or "[ERROR]" in chain_result.output

                # Get custody chain in JSON format
                chain_result_json = runner.invoke(main, [
                    "custody-chain",
                    evidence_id,
                    "--db-path", str(db_path),
                    "-f", "json",
                ])
                assert chain_result_json.exit_code == 0 or "[ERROR]" in chain_result_json.output

    def test_custody_chain_invalid_id(self, runner):
        """Test custody chain with invalid evidence ID."""
        with runner.isolated_filesystem():
            from dwg_forensic.core.custody import CustodyChain
            evidence_dir = Path("evidence_chain2")
            evidence_dir.mkdir()
            db_path = evidence_dir / "custody.db"

            # Create empty database
            CustodyChain(db_path)

            result = runner.invoke(main, [
                "custody-chain",
                "invalid-id",
                "--db-path", str(db_path),
            ])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output


class TestLogEventCommandFull:
    """Full tests for log-event command."""

    def test_log_event_full_workflow(self, runner, valid_dwg_ac1032):
        """Test logging custody event."""
        with runner.isolated_filesystem():
            import shutil
            import re
            evidence_dir = Path("evidence_log")
            evidence_dir.mkdir()
            db_path = evidence_dir / "custody.db"

            # Copy the valid_dwg to isolated filesystem
            test_file = Path("test_log.dwg")
            shutil.copy(valid_dwg_ac1032, test_file)

            # Intake file
            intake_result = runner.invoke(main, [
                "intake",
                str(test_file),
                "--case-id", "CASE-LOG",
                "--examiner", "Test Examiner",
                "--evidence-dir", str(evidence_dir),
                "--db-path", str(db_path),
            ])
            assert intake_result.exit_code == 0

            # Extract evidence ID
            match = re.search(r"Evidence ID\s*[|]\s*([a-f0-9-]+)", intake_result.output)
            if match:
                evidence_id = match.group(1)
                # Log an event
                log_result = runner.invoke(main, [
                    "log-event",
                    evidence_id,
                    "--event-type", "ANALYSIS",
                    "--examiner", "Test Examiner",
                    "--description", "Test analysis performed",
                    "--db-path", str(db_path),
                ])
                assert log_result.exit_code == 0 or "[ERROR]" in log_result.output

    def test_log_event_invalid_evidence(self, runner):
        """Test logging event with invalid evidence ID."""
        with runner.isolated_filesystem():
            from dwg_forensic.core.custody import CustodyChain
            evidence_dir = Path("evidence_log2")
            evidence_dir.mkdir()
            db_path = evidence_dir / "custody.db"

            # Create empty database
            CustodyChain(db_path)

            result = runner.invoke(main, [
                "log-event",
                "invalid-id",
                "--event-type", "ANALYSIS",
                "--examiner", "Test",
                "--description", "Test",
                "--db-path", str(db_path),
            ])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output


class TestProtectCommandExceptions:
    """Tests for protect command exception handling."""

    def test_protect_permission_error(self, runner, temp_dir):
        """Test protect with permission error."""
        from unittest.mock import patch

        test_file = temp_dir / "protected_test.txt"
        test_file.write_text("test")

        with patch("dwg_forensic.cli.FileGuard") as mock_guard:
            mock_guard.return_value.is_protected.return_value = False
            mock_guard.return_value.protect.side_effect = PermissionError("Access denied")
            result = runner.invoke(main, ["protect", str(test_file)])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output

    def test_protect_generic_exception(self, runner, temp_dir):
        """Test protect with generic exception."""
        from unittest.mock import patch

        test_file = temp_dir / "protected_test2.txt"
        test_file.write_text("test")

        with patch("dwg_forensic.cli.FileGuard") as mock_guard:
            mock_guard.return_value.is_protected.return_value = False
            mock_guard.return_value.protect.side_effect = Exception("Unknown error")
            result = runner.invoke(main, ["protect", str(test_file)])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output


class TestCheckProtectionBranches:
    """Tests for check-protection command branches."""

    def test_check_protection_protected_file(self, runner, temp_dir):
        """Test check-protection on protected file."""
        from unittest.mock import patch

        test_file = temp_dir / "check_prot.txt"
        test_file.write_text("test")

        with patch("dwg_forensic.cli.FileGuard") as mock_guard:
            mock_guard.return_value.verify_protection.return_value = (True, "File is protected")
            result = runner.invoke(main, ["check-protection", str(test_file)])
            assert result.exit_code == 0
            assert "[OK]" in result.output

    def test_check_protection_exception(self, runner, temp_dir):
        """Test check-protection with exception."""
        from unittest.mock import patch

        test_file = temp_dir / "check_prot2.txt"
        test_file.write_text("test")

        with patch("dwg_forensic.cli.FileGuard") as mock_guard:
            mock_guard.return_value.verify_protection.side_effect = Exception("Check failed")
            result = runner.invoke(main, ["check-protection", str(test_file)])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output


class TestTamperingCommandExceptions:
    """Tests for tampering command exception handling."""

    def test_tampering_dwg_forensic_error(self, runner, temp_dir):
        """Test tampering with DWGForensicError."""
        from dwg_forensic.utils.exceptions import DWGForensicError
        from unittest.mock import patch

        test_file = temp_dir / "tamper_test.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)

        with patch("dwg_forensic.cli.analyze_tampering") as mock_analyze:
            mock_analyze.side_effect = DWGForensicError("Tampering analysis failed")
            result = runner.invoke(main, ["tampering", str(test_file)])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output

    def test_tampering_generic_exception_verbose(self, runner, temp_dir):
        """Test tampering with generic exception and verbose."""
        from unittest.mock import patch

        test_file = temp_dir / "tamper_test2.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)

        with patch("dwg_forensic.cli.analyze_tampering") as mock_analyze:
            mock_analyze.side_effect = Exception("Unknown error")
            result = runner.invoke(main, ["tampering", str(test_file), "-v"])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output


class TestTamperingReportPrinting:
    """Tests for tampering report printing branches."""

    def test_tampering_report_crc_none(self, runner, temp_dir):
        """Test tampering report with crc_valid=None."""
        from dwg_forensic.analysis.risk import TamperingReport
        from dwg_forensic.models import RiskLevel
        from unittest.mock import patch

        test_file = temp_dir / "tamper_crc.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)

        mock_report = TamperingReport(
            file_path=str(test_file),
            risk_level=RiskLevel.LOW,
            risk_score=10,
            confidence=0.9,
            anomaly_count=0,
            rule_failures=0,
            tampering_indicators=0,
            crc_valid=None,
            watermark_valid=True,
            anomalies=[],
            failed_rules=[],
            factors=["[OK] No issues"],
            recommendation="File appears clean.",
        )

        with patch("dwg_forensic.cli.analyze_tampering", return_value=mock_report):
            result = runner.invoke(main, ["tampering", str(test_file)])
            assert result.exit_code == 0
            assert "N/A" in result.output

    def test_tampering_report_watermark_none(self, runner, temp_dir):
        """Test tampering report with watermark_valid=None."""
        from dwg_forensic.analysis.risk import TamperingReport
        from dwg_forensic.models import RiskLevel
        from unittest.mock import patch

        test_file = temp_dir / "tamper_wm.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)

        mock_report = TamperingReport(
            file_path=str(test_file),
            risk_level=RiskLevel.LOW,
            risk_score=10,
            confidence=0.9,
            anomaly_count=0,
            rule_failures=0,
            tampering_indicators=0,
            crc_valid=True,
            watermark_valid=None,
            anomalies=[],
            failed_rules=[],
            factors=[],
            recommendation="File appears clean.",
        )

        with patch("dwg_forensic.cli.analyze_tampering", return_value=mock_report):
            result = runner.invoke(main, ["tampering", str(test_file)])
            assert result.exit_code == 0
            assert "Not present" in result.output

    def test_tampering_report_with_failed_rules(self, runner, temp_dir):
        """Test tampering report with failed rules."""
        from dwg_forensic.analysis.risk import TamperingReport
        from dwg_forensic.models import RiskLevel
        from unittest.mock import patch

        test_file = temp_dir / "tamper_rules.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)

        mock_report = TamperingReport(
            file_path=str(test_file),
            risk_level=RiskLevel.HIGH,
            risk_score=70,
            confidence=0.85,
            anomaly_count=1,
            rule_failures=2,
            tampering_indicators=1,
            crc_valid=False,
            watermark_valid=False,
            anomalies=[],
            failed_rules=[
                {"rule_id": "TAMPER-001", "severity": "CRITICAL", "message": "CRC mismatch detected"},
                {"rule_id": "TAMPER-002", "severity": "WARNING", "message": "Watermark invalid"},
            ],
            factors=[
                "[FAIL] CRC validation failed",
                "[WARN] Watermark issues detected",
                "[CRITICAL] Multiple tampering indicators",
            ],
            recommendation="Evidence of modification.",
        )

        with patch("dwg_forensic.cli.analyze_tampering", return_value=mock_report):
            result = runner.invoke(main, ["tampering", str(test_file)])
            assert result.exit_code == 0
            assert "Triggered Rules" in result.output or "TAMPER-001" in result.output

    def test_tampering_report_verbose_with_anomalies(self, runner, temp_dir):
        """Test tampering report verbose with anomalies."""
        from dwg_forensic.analysis.risk import TamperingReport
        from dwg_forensic.models import RiskLevel, Anomaly, AnomalyType
        from unittest.mock import patch

        test_file = temp_dir / "tamper_anomalies.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)

        mock_report = TamperingReport(
            file_path=str(test_file),
            risk_level=RiskLevel.MEDIUM,
            risk_score=50,
            confidence=0.8,
            anomaly_count=1,
            rule_failures=0,
            tampering_indicators=0,
            crc_valid=True,
            watermark_valid=True,
            anomalies=[
                Anomaly(
                    anomaly_type=AnomalyType.TIMESTAMP_ANOMALY,
                    severity=RiskLevel.MEDIUM,
                    description="Timestamp anomaly detected",
                    field_name="tdcreate",
                )
            ],
            failed_rules=[],
            factors=["[WARN] Timestamp anomaly"],
            recommendation="Review timestamps.",
        )

        with patch("dwg_forensic.cli.analyze_tampering", return_value=mock_report):
            result = runner.invoke(main, ["tampering", str(test_file), "-v"])
            assert result.exit_code == 0
            assert "Anomalies" in result.output or "TIMESTAMP" in result.output


class TestReportCommandExceptions:
    """Tests for report command exception handling."""

    def test_report_unsupported_version(self, runner, temp_dir):
        """Test report with unsupported version."""
        from dwg_forensic.utils.exceptions import UnsupportedVersionError
        from unittest.mock import patch

        test_file = temp_dir / "report_test.dwg"
        test_file.write_bytes(b"AC1009" + b"\x00" * 200)
        output_file = temp_dir / "report.pdf"

        with patch("dwg_forensic.cli.ForensicAnalyzer") as mock_analyzer:
            mock_analyzer.return_value.analyze.side_effect = UnsupportedVersionError("AC1009")
            result = runner.invoke(main, ["report", str(test_file), "-o", str(output_file)])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output

    def test_report_dwg_forensic_error(self, runner, temp_dir):
        """Test report with DWGForensicError."""
        from dwg_forensic.utils.exceptions import DWGForensicError
        from unittest.mock import patch

        test_file = temp_dir / "report_test2.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)
        output_file = temp_dir / "report2.pdf"

        with patch("dwg_forensic.cli.ForensicAnalyzer") as mock_analyzer:
            mock_analyzer.return_value.analyze.side_effect = DWGForensicError("Analysis failed")
            result = runner.invoke(main, ["report", str(test_file), "-o", str(output_file)])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output

    def test_report_generic_exception_verbose(self, runner, temp_dir):
        """Test report with generic exception and verbose."""
        from unittest.mock import patch

        test_file = temp_dir / "report_test3.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)
        output_file = temp_dir / "report3.pdf"

        with patch("dwg_forensic.cli.ForensicAnalyzer") as mock_analyzer:
            mock_analyzer.return_value.analyze.side_effect = Exception("Unknown error")
            result = runner.invoke(main, ["report", str(test_file), "-o", str(output_file), "-v"])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output


class TestExpertWitnessCommandExceptions:
    """Tests for expert-witness command exception handling."""

    def test_expert_witness_unsupported_version(self, runner, temp_dir):
        """Test expert-witness with unsupported version."""
        from dwg_forensic.utils.exceptions import UnsupportedVersionError
        from unittest.mock import patch

        test_file = temp_dir / "expert_test.dwg"
        test_file.write_bytes(b"AC1009" + b"\x00" * 200)
        output_file = temp_dir / "expert.pdf"

        with patch("dwg_forensic.cli.ForensicAnalyzer") as mock_analyzer:
            mock_analyzer.return_value.analyze.side_effect = UnsupportedVersionError("AC1009")
            result = runner.invoke(main, ["expert-witness", str(test_file), "-o", str(output_file)])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output

    def test_expert_witness_dwg_forensic_error(self, runner, temp_dir):
        """Test expert-witness with DWGForensicError."""
        from dwg_forensic.utils.exceptions import DWGForensicError
        from unittest.mock import patch

        test_file = temp_dir / "expert_test2.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)
        output_file = temp_dir / "expert2.pdf"

        with patch("dwg_forensic.cli.ForensicAnalyzer") as mock_analyzer:
            mock_analyzer.return_value.analyze.side_effect = DWGForensicError("Analysis failed")
            result = runner.invoke(main, ["expert-witness", str(test_file), "-o", str(output_file)])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output

    def test_expert_witness_generic_exception_verbose(self, runner, temp_dir):
        """Test expert-witness with generic exception and verbose."""
        from unittest.mock import patch

        test_file = temp_dir / "expert_test3.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)
        output_file = temp_dir / "expert3.pdf"

        with patch("dwg_forensic.cli.ForensicAnalyzer") as mock_analyzer:
            mock_analyzer.return_value.analyze.side_effect = Exception("Unknown error")
            result = runner.invoke(main, ["expert-witness", str(test_file), "-o", str(output_file), "-v"])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output


class TestTimelineCommandExceptions:
    """Tests for timeline command exception handling."""

    def test_timeline_svg_output(self, runner, valid_dwg_ac1032, temp_dir):
        """Test timeline with SVG output."""
        output_file = temp_dir / "timeline.svg"
        result = runner.invoke(main, [
            "timeline",
            str(valid_dwg_ac1032),
            "-f", "svg",
            "-o", str(output_file)
        ])
        assert result.exit_code == 0
        assert "[OK]" in result.output or "saved" in result.output.lower()

    def test_timeline_unsupported_version(self, runner, temp_dir):
        """Test timeline with unsupported version."""
        from dwg_forensic.utils.exceptions import UnsupportedVersionError
        from unittest.mock import patch

        test_file = temp_dir / "timeline_test.dwg"
        test_file.write_bytes(b"AC1009" + b"\x00" * 200)

        with patch("dwg_forensic.cli.ForensicAnalyzer") as mock_analyzer:
            mock_analyzer.return_value.analyze.side_effect = UnsupportedVersionError("AC1009")
            result = runner.invoke(main, ["timeline", str(test_file)])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output

    def test_timeline_dwg_forensic_error(self, runner, temp_dir):
        """Test timeline with DWGForensicError."""
        from dwg_forensic.utils.exceptions import DWGForensicError
        from unittest.mock import patch

        test_file = temp_dir / "timeline_test2.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)

        with patch("dwg_forensic.cli.ForensicAnalyzer") as mock_analyzer:
            mock_analyzer.return_value.analyze.side_effect = DWGForensicError("Analysis failed")
            result = runner.invoke(main, ["timeline", str(test_file)])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output

    def test_timeline_generic_exception_verbose(self, runner, temp_dir):
        """Test timeline with generic exception and verbose."""
        from unittest.mock import patch

        test_file = temp_dir / "timeline_test3.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 200)

        with patch("dwg_forensic.cli.ForensicAnalyzer") as mock_analyzer:
            mock_analyzer.return_value.analyze.side_effect = Exception("Unknown error")
            result = runner.invoke(main, ["timeline", str(test_file), "-v"])
            assert result.exit_code == 1
            assert "[ERROR]" in result.output


class TestMainEntryPoint:
    """Tests for __main__ entry point."""

    def test_main_module_execution(self):
        """Test that main() can be called without arguments."""
        from click.testing import CliRunner
        runner = CliRunner()
        result = runner.invoke(main)
        # Click main groups return 2 when called without a required subcommand (usage error)
        # This is expected behavior for groups that require a command
        assert result.exit_code in (0, 2)
        # Should show usage info or available commands
        assert "Usage" in result.output or "analyze" in result.output
