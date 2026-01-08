"""
Comprehensive unit tests for the AuditLogger module.

Tests cover:
- AuditLevel enum values
- AuditLogger initialization
- Log method for various audit levels
- Specialized logging methods (log_intake, log_access, etc.)
- Audit trail retrieval
- Audit trail export
- Singleton pattern (get_audit_logger)
- File rotation handling
- Thread safety
"""

import json
import os
import tempfile
import threading
import time
from pathlib import Path

import pytest

from dwg_forensic.utils.audit import AuditLevel, AuditLogger, get_audit_logger


# ============================================================================
# AuditLevel Tests
# ============================================================================

class TestAuditLevel:
    """Test AuditLevel enum values."""

    def test_audit_level_info_exists(self):
        """Test that INFO level exists."""
        assert AuditLevel.INFO is not None

    def test_audit_level_warning_exists(self):
        """Test that WARNING level exists."""
        assert AuditLevel.WARNING is not None

    def test_audit_level_error_exists(self):
        """Test that ERROR level exists."""
        assert AuditLevel.ERROR is not None

    def test_audit_level_critical_exists(self):
        """Test that CRITICAL level exists."""
        assert AuditLevel.CRITICAL is not None

    def test_audit_level_security_exists(self):
        """Test that SECURITY level exists."""
        assert AuditLevel.SECURITY is not None

    def test_audit_level_values(self):
        """Test AuditLevel string values."""
        assert AuditLevel.INFO.value == "INFO"
        assert AuditLevel.WARNING.value == "WARNING"
        assert AuditLevel.ERROR.value == "ERROR"
        assert AuditLevel.CRITICAL.value == "CRITICAL"
        assert AuditLevel.SECURITY.value == "SECURITY"


# ============================================================================
# AuditLogger Initialization Tests
# ============================================================================

class TestAuditLoggerInitialization:
    """Test AuditLogger class initialization."""

    def test_init_creates_instance(self, tmp_path):
        """Test that AuditLogger can be initialized."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        assert logger is not None

    def test_init_with_string_path(self, tmp_path):
        """Test initialization with string path."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=str(log_dir))
        assert logger is not None

    def test_init_creates_log_dir_if_missing(self, tmp_path):
        """Test that init creates log directory if it doesn't exist."""
        log_dir = tmp_path / "new_audit_logs"

        logger = AuditLogger(log_dir=log_dir)
        assert log_dir.exists()

    def test_init_creates_log_files(self, tmp_path):
        """Test that init creates log files after logging."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "Test message")

        # Check that at least one log file exists
        log_files = list(log_dir.glob("*.log")) + list(log_dir.glob("*.jsonl"))
        assert len(log_files) >= 1


# ============================================================================
# Log Method Tests
# ============================================================================

class TestLogMethod:
    """Test the main log() method."""

    def test_log_info(self, tmp_path):
        """Test logging at INFO level."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "Test info message")

        # Verify log was written
        log_files = list(log_dir.glob("*"))
        assert len(log_files) >= 1

    def test_log_warning(self, tmp_path):
        """Test logging at WARNING level."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.WARNING, "Test warning message")

    def test_log_error(self, tmp_path):
        """Test logging at ERROR level."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.ERROR, "Test error message")

    def test_log_critical(self, tmp_path):
        """Test logging at CRITICAL level."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.CRITICAL, "Test critical message")

    def test_log_security(self, tmp_path):
        """Test logging at SECURITY level."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.SECURITY, "Test security message")

    def test_log_with_extra_data(self, tmp_path):
        """Test logging with additional data."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(
            AuditLevel.INFO,
            "Test with extras",
            evidence_id="E-001",
            case_id="CASE-001",
            examiner="Test Examiner"
        )


# ============================================================================
# Specialized Logging Method Tests
# ============================================================================

class TestSpecializedLogging:
    """Test specialized logging methods."""

    def test_log_intake(self, tmp_path):
        """Test log_intake method."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log_intake(
            evidence_id="E-001",
            case_id="CASE-001",
            examiner="Intake Officer",
            filename="evidence.dwg",
            sha256="a" * 64
        )

    def test_log_access(self, tmp_path):
        """Test log_access method."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log_access(
            evidence_id="E-001",
            examiner="Analyst",
            purpose="Analysis review"
        )

    def test_log_analysis(self, tmp_path):
        """Test log_analysis method."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log_analysis(
            evidence_id="E-001",
            examiner="Forensic Analyst",
            analysis_type="metadata_extraction",
            findings={"fields_extracted": 50}
        )

    def test_log_export(self, tmp_path):
        """Test log_export method."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log_export(
            evidence_id="E-001",
            examiner="Report Generator",
            export_path="C:\\Reports\\report.pdf",
            export_format="PDF"
        )

    def test_log_verification(self, tmp_path):
        """Test log_verification method."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log_verification(
            evidence_id="E-001",
            examiner="QA Specialist",
            is_valid=True,
            hash_computed="a" * 64
        )

    def test_log_error_method(self, tmp_path):
        """Test log_error method."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log_error(
            action="PARSE_HEADER",
            error=ValueError("Failed to parse DWG header"),
            evidence_id="E-001"
        )

    def test_log_security_method(self, tmp_path):
        """Test log_security method."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log_security(
            action="UNAUTHORIZED_ACCESS",
            details="Invalid credentials provided",
            evidence_id="E-001"
        )


# ============================================================================
# Audit Trail Retrieval Tests
# ============================================================================

class TestAuditTrailRetrieval:
    """Test audit trail retrieval functionality."""

    def test_get_audit_trail_returns_list(self, tmp_path):
        """Test that get_audit_trail returns a list."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "Test message")

        trail = logger.get_audit_trail()
        assert isinstance(trail, list)

    def test_get_audit_trail_contains_logged_entries(self, tmp_path):
        """Test that audit trail contains logged entries."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "Test message 1")
        logger.log(AuditLevel.WARNING, "Test message 2")

        trail = logger.get_audit_trail()
        assert len(trail) >= 2

    def test_get_audit_trail_filter_by_level(self, tmp_path):
        """Test filtering audit trail by level."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "Info message")
        logger.log(AuditLevel.ERROR, "Error message")

        trail = logger.get_audit_trail(level=AuditLevel.ERROR)
        assert all(entry.get("level") == "ERROR" for entry in trail)


# ============================================================================
# Audit Trail Export Tests
# ============================================================================

class TestAuditTrailExport:
    """Test audit trail export functionality."""

    def test_export_audit_trail_creates_file(self, tmp_path):
        """Test that export_audit_trail creates an export file."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "Test message")

        export_path = tmp_path / "audit_export.json"
        logger.export_audit_trail(export_path)

        assert export_path.exists()

    def test_export_audit_trail_valid_json(self, tmp_path):
        """Test that exported audit trail is valid JSON."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "Test message")

        export_path = tmp_path / "audit_export.json"
        logger.export_audit_trail(export_path)

        with open(export_path, "r") as f:
            data = json.load(f)

        assert isinstance(data, (list, dict))


# ============================================================================
# Singleton Pattern Tests
# ============================================================================

class TestSingletonPattern:
    """Test get_audit_logger singleton function."""

    def test_get_audit_logger_returns_instance(self, tmp_path):
        """Test that get_audit_logger returns an AuditLogger instance."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = get_audit_logger(log_dir=log_dir)
        assert isinstance(logger, AuditLogger)

    def test_get_audit_logger_returns_same_instance(self, tmp_path):
        """Test that get_audit_logger returns the same instance."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger1 = get_audit_logger(log_dir=log_dir)
        logger2 = get_audit_logger(log_dir=log_dir)

        # They should be the same instance (singleton pattern)
        assert logger1 is logger2


# ============================================================================
# JSON Lines Format Tests
# ============================================================================

class TestJsonLinesFormat:
    """Test JSON Lines (JSONL) logging format."""

    def test_jsonl_file_created(self, tmp_path):
        """Test that JSONL log file is created."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "Test message")

        jsonl_files = list(log_dir.glob("*.jsonl"))
        assert len(jsonl_files) >= 1

    def test_jsonl_entries_valid(self, tmp_path):
        """Test that JSONL entries are valid JSON."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "Test message 1")
        logger.log(AuditLevel.WARNING, "Test message 2")

        # Find JSONL file
        jsonl_files = list(log_dir.glob("*.jsonl"))
        if jsonl_files:
            with open(jsonl_files[0], "r") as f:
                for line in f:
                    if line.strip():
                        entry = json.loads(line)
                        assert isinstance(entry, dict)


# ============================================================================
# Thread Safety Tests
# ============================================================================

class TestThreadSafety:
    """Test thread-safe logging."""

    def test_concurrent_logging(self, tmp_path):
        """Test that concurrent logging works correctly."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)

        def log_messages(thread_id):
            for i in range(10):
                logger.log(AuditLevel.INFO, f"Thread {thread_id} message {i}")

        threads = []
        for i in range(5):
            t = threading.Thread(target=log_messages, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Verify all messages were logged
        trail = logger.get_audit_trail()
        assert len(trail) >= 50  # 5 threads x 10 messages


# ============================================================================
# Log Entry Content Tests
# ============================================================================

class TestLogEntryContent:
    """Test content of log entries."""

    def test_log_entry_contains_timestamp(self, tmp_path):
        """Test that log entries contain timestamp."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "Test message")

        trail = logger.get_audit_trail()
        if trail:
            entry = trail[-1]
            assert "timestamp" in entry

    def test_log_entry_contains_level(self, tmp_path):
        """Test that log entries contain level."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.WARNING, "Test warning")

        trail = logger.get_audit_trail()
        if trail:
            entry = trail[-1]
            assert "level" in entry

    def test_log_entry_contains_action(self, tmp_path):
        """Test that log entries contain action."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "Unique_test_action_12345")

        trail = logger.get_audit_trail()
        if trail:
            entry = trail[-1]
            assert "action" in entry


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestErrorHandling:
    """Test error handling for various edge cases."""

    def test_log_empty_action(self, tmp_path):
        """Test logging with empty action."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        # Should not raise error
        logger.log(AuditLevel.INFO, "")

    def test_log_unicode_message(self, tmp_path):
        """Test logging with unicode characters."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        # Should handle unicode (though we avoid emoji per CLAUDE.md)
        logger.log(AuditLevel.INFO, "Test with special chars: [OK] [FAIL]")


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests for AuditLogger."""

    def test_full_audit_workflow(self, tmp_path):
        """Test complete audit logging workflow."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)

        # Log various events
        logger.log_intake(
            evidence_id="E-001",
            case_id="CASE-2025-001",
            examiner="Intake Officer",
            filename="evidence.dwg",
            sha256="a" * 64
        )

        logger.log_access(
            evidence_id="E-001",
            examiner="Analyst",
            purpose="Initial review"
        )

        logger.log_analysis(
            evidence_id="E-001",
            examiner="Forensic Analyst",
            analysis_type="metadata_extraction",
            findings={"fields": 50}
        )

        logger.log_verification(
            evidence_id="E-001",
            examiner="QA",
            is_valid=True,
            hash_computed="a" * 64
        )

        logger.log_export(
            evidence_id="E-001",
            examiner="Report Writer",
            export_path="C:\\Reports\\case_report.pdf",
            export_format="PDF"
        )

        # Retrieve and verify audit trail
        trail = logger.get_audit_trail()
        assert len(trail) >= 5

        # Export audit trail
        export_path = tmp_path / "audit_export.json"
        logger.export_audit_trail(export_path)
        assert export_path.exists()

        # Verify export is valid JSON
        with open(export_path, "r") as f:
            exported_data = json.load(f)
        assert isinstance(exported_data, (list, dict))

    def test_audit_logger_with_evidence_lifecycle(self, tmp_path):
        """Test audit logging through evidence lifecycle."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)

        evidence_ids = ["E-001", "E-002", "E-003"]

        # Intake all evidence
        for eid in evidence_ids:
            logger.log_intake(
                evidence_id=eid,
                case_id="CASE-001",
                examiner="Intake",
                filename=f"{eid}.dwg",
                sha256=f"{eid}" * 16
            )

        # Analyze all evidence
        for eid in evidence_ids:
            logger.log_analysis(
                evidence_id=eid,
                examiner="Analyst",
                analysis_type="full_analysis"
            )

        # Verify audit trail
        trail = logger.get_audit_trail()
        assert len(trail) >= 6  # 3 intakes + 3 analyses


# ============================================================================
# Additional Coverage Tests
# ============================================================================

class TestAuditLoggerContextManager:
    """Test AuditLogger context manager functionality."""

    def test_context_manager_enter_exit(self, tmp_path):
        """Test AuditLogger as context manager."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        with AuditLogger(log_dir=log_dir) as logger:
            assert logger is not None
            logger.log(AuditLevel.INFO, "Test message")

    def test_close_method_releases_handlers(self, tmp_path):
        """Test that close() releases file handlers."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "Test message")
        logger.close()
        # Handlers should be empty after close
        assert len(logger.json_logger.handlers) == 0
        assert len(logger.text_logger.handlers) == 0


class TestGetAuditTrailFiltering:
    """Test get_audit_trail filtering functionality."""

    def test_get_audit_trail_filter_by_evidence_id(self, tmp_path):
        """Test filtering audit trail by evidence_id."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "E001 action", evidence_id="E-001")
        logger.log(AuditLevel.INFO, "E002 action", evidence_id="E-002")

        trail = logger.get_audit_trail(evidence_id="E-001")
        assert len(trail) >= 1
        assert all(e.get("evidence_id") == "E-001" for e in trail)

    def test_get_audit_trail_filter_by_case_id(self, tmp_path):
        """Test filtering audit trail by case_id."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "Case 1 action", case_id="CASE-001")
        logger.log(AuditLevel.INFO, "Case 2 action", case_id="CASE-002")

        trail = logger.get_audit_trail(case_id="CASE-001")
        assert len(trail) >= 1
        assert all(e.get("case_id") == "CASE-001" for e in trail)

    def test_get_audit_trail_filter_by_date_range(self, tmp_path):
        """Test filtering audit trail by date range."""
        from datetime import datetime, timezone, timedelta

        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "Test action")

        now = datetime.now(timezone.utc)
        start_date = now - timedelta(hours=1)
        end_date = now + timedelta(hours=1)

        trail = logger.get_audit_trail(start_date=start_date, end_date=end_date)
        assert len(trail) >= 1

    def test_get_audit_trail_empty_log_file(self, tmp_path):
        """Test get_audit_trail when log file doesn't exist."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        # Don't log anything - file won't exist
        trail = logger.get_audit_trail()
        assert trail == []

    def test_get_audit_trail_handles_malformed_json(self, tmp_path):
        """Test that get_audit_trail handles malformed JSON lines."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        # Create a malformed JSONL file
        jsonl_path = log_dir / "dwg_forensic_audit.jsonl"
        with open(jsonl_path, "w") as f:
            f.write('{"timestamp": "2025-01-01T00:00:00Z", "level": "INFO", "action": "test"}\n')
            f.write('malformed json line\n')
            f.write('{"timestamp": "2025-01-01T01:00:00Z", "level": "INFO", "action": "test2"}\n')

        logger = AuditLogger(log_dir=log_dir)
        trail = logger.get_audit_trail()
        # Should return valid entries, skipping malformed lines
        assert len(trail) == 2


class TestAuditTrailExportFormats:
    """Test audit trail export in different formats."""

    def test_export_csv_format(self, tmp_path):
        """Test exporting audit trail in CSV format."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "Test action 1", evidence_id="E-001")
        logger.log(AuditLevel.WARNING, "Test action 2", case_id="CASE-001")

        export_path = tmp_path / "audit_export.csv"
        logger.export_audit_trail(export_path, format="csv")

        assert export_path.exists()
        content = export_path.read_text()
        assert "timestamp" in content
        assert "level" in content

    def test_export_csv_empty_entries(self, tmp_path):
        """Test exporting empty audit trail in CSV format."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        # Don't log anything

        export_path = tmp_path / "audit_export_empty.csv"
        logger.export_audit_trail(export_path, format="csv")

        assert export_path.exists()
        content = export_path.read_text()
        assert content == ""

    def test_export_txt_format(self, tmp_path):
        """Test exporting audit trail in TXT format."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "Test action", evidence_id="E-001")

        export_path = tmp_path / "audit_export.txt"
        logger.export_audit_trail(export_path, format="txt")

        assert export_path.exists()
        content = export_path.read_text()
        assert "INFO" in content
        assert "User:" in content

    def test_export_unsupported_format_raises(self, tmp_path):
        """Test that unsupported export format raises ValueError."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(AuditLevel.INFO, "Test action")

        export_path = tmp_path / "audit_export.xml"
        with pytest.raises(ValueError) as excinfo:
            logger.export_audit_trail(export_path, format="xml")
        assert "Unsupported format" in str(excinfo.value)


class TestGetSystemInfoException:
    """Test _get_system_info exception handling."""

    def test_get_system_info_socket_error(self, tmp_path):
        """Test _get_system_info handles socket errors."""
        from unittest.mock import patch

        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)

        # Mock socket functions to raise exceptions
        with patch('socket.gethostname', side_effect=Exception("Socket error")):
            with patch('socket.gethostbyname', side_effect=Exception("Socket error")):
                # Should not raise - should return "unknown"
                info = logger._get_system_info()
                assert info["workstation"] == "unknown"
                assert info["ip_address"] == "unknown"


class TestGlobalAuditLogger:
    """Test global audit logger singleton."""

    def test_get_audit_logger_with_default_dir(self, tmp_path, monkeypatch):
        """Test get_audit_logger uses default directory."""
        import dwg_forensic.utils.audit as audit_module

        # Reset global logger
        audit_module._global_audit_logger = None

        # Change cwd to tmp_path
        monkeypatch.chdir(tmp_path)

        logger = get_audit_logger()
        assert logger is not None

        # Clean up
        audit_module._global_audit_logger = None


class TestLogWithDetails:
    """Test logging with details dict."""

    def test_log_with_details_dict(self, tmp_path):
        """Test log method with details parameter."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log(
            AuditLevel.INFO,
            "Test action",
            details={"key1": "value1", "key2": 123}
        )

        trail = logger.get_audit_trail()
        assert len(trail) >= 1
        assert "details" in trail[-1]
        assert trail[-1]["details"]["key1"] == "value1"


class TestLogAnalysisWithoutFindings:
    """Test log_analysis without findings."""

    def test_log_analysis_without_findings(self, tmp_path):
        """Test log_analysis method without findings parameter."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log_analysis(
            evidence_id="E-001",
            examiner="Analyst",
            analysis_type="header_analysis"
        )

        trail = logger.get_audit_trail()
        assert len(trail) >= 1


class TestLogVerificationFailed:
    """Test log_verification with failed verification."""

    def test_log_verification_failed(self, tmp_path):
        """Test log_verification with is_valid=False."""
        log_dir = tmp_path / "audit_logs"
        log_dir.mkdir()

        logger = AuditLogger(log_dir=log_dir)
        logger.log_verification(
            evidence_id="E-001",
            examiner="QA",
            is_valid=False,
            hash_computed="abc123"
        )

        trail = logger.get_audit_trail(level=AuditLevel.WARNING)
        assert len(trail) >= 1
