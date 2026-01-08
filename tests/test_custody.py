"""
Comprehensive unit tests for the CustodyChain module.

Tests cover:
- CustodyChain initialization
- Event logging (all EventType values)
- Chain retrieval and filtering
- Evidence retrieval
- Integrity verification
- Custody report generation
- Error handling
"""

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from dwg_forensic.core.custody import CustodyChain, EventType, IntegrityError
from dwg_forensic.core.database import (
    CaseInfo,
    CustodyEvent,
    EvidenceFile,
    get_engine,
    get_session,
    init_db,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def temp_db_path(tmp_path):
    """Create a temporary database file path."""
    return str(tmp_path / "test_custody.db")


@pytest.fixture
def temp_evidence_dir(tmp_path):
    """Create a temporary evidence directory."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    return evidence_dir


@pytest.fixture
def custody_chain(temp_db_path):
    """Create a CustodyChain instance for testing."""
    return CustodyChain(db_path=temp_db_path)


@pytest.fixture
def sample_evidence_file(tmp_path):
    """Create a sample DWG-like file for testing."""
    test_file = tmp_path / "test_evidence.dwg"
    # Create minimal content (at least 108 bytes needed)
    test_file.write_bytes(b"AC1032" + b"\x00" * 110)
    return test_file


@pytest.fixture
def sample_evidence_record(custody_chain, sample_evidence_file):
    """Create a sample evidence record in the database."""
    import hashlib

    content = sample_evidence_file.read_bytes()
    sha256 = hashlib.sha256(content).hexdigest()
    sha1 = hashlib.sha1(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()

    engine = custody_chain._engine
    with get_session(engine) as session:
        # Create case
        case = CaseInfo(
            id="CASE-TEST-001",
            case_name="Test Case",
            examiner_assigned="Test Examiner"
        )
        session.add(case)
        session.flush()

        # Create evidence
        evidence = EvidenceFile(
            filename=sample_evidence_file.name,
            file_path=str(sample_evidence_file.absolute()),
            file_size_bytes=sample_evidence_file.stat().st_size,
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            case_id="CASE-TEST-001",
            evidence_number="E-001",
            intake_timestamp=datetime.now(timezone.utc)
        )
        session.add(evidence)
        session.commit()
        session.refresh(evidence)
        return evidence.id


# ============================================================================
# EventType Tests
# ============================================================================

class TestEventType:
    """Test EventType enum values."""

    def test_event_type_values_exist(self):
        """Test that all expected EventType values exist."""
        assert EventType.INTAKE is not None
        assert EventType.ACCESS is not None
        assert EventType.ANALYSIS is not None
        assert EventType.EXPORT is not None
        assert EventType.TRANSFER is not None
        assert EventType.VERIFICATION is not None
        assert EventType.RELEASE is not None

    def test_event_type_string_values(self):
        """Test EventType string representation."""
        assert EventType.INTAKE.value == "INTAKE"
        assert EventType.ACCESS.value == "ACCESS"
        assert EventType.ANALYSIS.value == "ANALYSIS"


# ============================================================================
# CustodyChain Initialization Tests
# ============================================================================

class TestCustodyChainInitialization:
    """Test CustodyChain class initialization."""

    def test_init_creates_instance(self, temp_db_path):
        """Test that CustodyChain can be initialized."""
        chain = CustodyChain(db_path=temp_db_path)
        assert chain is not None

    def test_init_creates_database(self, temp_db_path):
        """Test that CustodyChain creates database file."""
        chain = CustodyChain(db_path=temp_db_path)
        assert Path(temp_db_path).exists()


# ============================================================================
# Event Logging Tests
# ============================================================================

class TestEventLogging:
    """Test custody event logging functionality."""

    def test_log_event_creates_record(self, custody_chain, sample_evidence_record):
        """Test that log_event creates a custody event record."""
        event = custody_chain.log_event(
            evidence_id=sample_evidence_record,
            event_type=EventType.ACCESS,
            examiner="Test Examiner",
            description="Accessed for review",
            verify_hash=True
        )

        assert event is not None
        assert event.event_type == "ACCESS"
        assert event.examiner == "Test Examiner"

    def test_log_event_with_notes(self, custody_chain, sample_evidence_record):
        """Test log_event with notes."""
        event = custody_chain.log_event(
            evidence_id=sample_evidence_record,
            event_type=EventType.ANALYSIS,
            examiner="Analyst",
            description="Analysis performed",
            notes="Additional notes here"
        )

        assert event.notes == "Additional notes here"

    def test_log_event_sets_timestamp(self, custody_chain, sample_evidence_record):
        """Test that log_event sets timestamp automatically."""
        event = custody_chain.log_event(
            evidence_id=sample_evidence_record,
            event_type=EventType.ACCESS,
            examiner="Examiner",
            description="Test access"
        )

        assert event.timestamp is not None
        assert isinstance(event.timestamp, datetime)

    def test_log_event_records_workstation(self, custody_chain, sample_evidence_record):
        """Test that log_event records workstation info."""
        event = custody_chain.log_event(
            evidence_id=sample_evidence_record,
            event_type=EventType.ACCESS,
            examiner="Examiner",
            description="Test"
        )

        assert event.workstation is not None

    def test_log_event_invalid_evidence_raises_error(self, custody_chain):
        """Test that log_event raises error for invalid evidence ID."""
        with pytest.raises(ValueError):
            custody_chain.log_event(
                evidence_id="invalid-id",
                event_type=EventType.ACCESS,
                examiner="Examiner",
                description="Test"
            )


# ============================================================================
# Chain Retrieval Tests
# ============================================================================

class TestChainRetrieval:
    """Test chain of custody retrieval functionality."""

    def test_get_chain_returns_events(self, custody_chain, sample_evidence_record):
        """Test that get_chain returns all events for evidence."""
        # Create multiple events
        for i in range(3):
            custody_chain.log_event(
                evidence_id=sample_evidence_record,
                event_type=EventType.ACCESS,
                examiner=f"Examiner {i}",
                description=f"Access {i}"
            )

        chain = custody_chain.get_chain(sample_evidence_record)

        assert len(chain) == 3

    def test_get_chain_empty_for_invalid_id(self, custody_chain):
        """Test that get_chain returns empty list for invalid ID."""
        chain = custody_chain.get_chain("nonexistent-id")
        assert chain == []


# ============================================================================
# Evidence Retrieval Tests
# ============================================================================

class TestEvidenceRetrieval:
    """Test evidence retrieval functionality."""

    def test_get_evidence_returns_record(self, custody_chain, sample_evidence_record):
        """Test that get_evidence returns the evidence record."""
        evidence = custody_chain.get_evidence(sample_evidence_record)

        assert evidence is not None
        assert evidence.id == sample_evidence_record

    def test_get_evidence_nonexistent_returns_none(self, custody_chain):
        """Test that get_evidence returns None for nonexistent ID."""
        result = custody_chain.get_evidence("nonexistent-id")
        assert result is None


# ============================================================================
# Integrity Verification Tests
# ============================================================================

class TestIntegrityVerification:
    """Test evidence integrity verification functionality."""

    def test_verify_integrity_valid_file(self, custody_chain, sample_evidence_record):
        """Test that verify_integrity returns True for valid file."""
        is_valid, message = custody_chain.verify_integrity(sample_evidence_record)
        assert is_valid is True
        assert "[OK]" in message

    def test_verify_integrity_nonexistent_evidence(self, custody_chain):
        """Test that verify_integrity returns False for nonexistent evidence."""
        is_valid, message = custody_chain.verify_integrity("nonexistent-id")
        assert is_valid is False


# ============================================================================
# Custody Report Generation Tests
# ============================================================================

class TestCustodyReportGeneration:
    """Test custody report generation functionality."""

    def test_generate_custody_report_returns_dict(self, custody_chain, sample_evidence_record):
        """Test that generate_custody_report returns a dictionary."""
        report = custody_chain.generate_custody_report(sample_evidence_record)

        assert isinstance(report, dict)
        assert "evidence" in report
        assert "chain" in report
        assert "integrity_status" in report

    def test_generate_custody_report_contains_evidence_info(self, custody_chain, sample_evidence_record):
        """Test that report contains evidence information."""
        report = custody_chain.generate_custody_report(sample_evidence_record)

        assert "evidence" in report
        assert "id" in report["evidence"]
        assert "sha256" in report["evidence"]

    def test_generate_custody_report_nonexistent_raises_error(self, custody_chain):
        """Test that report raises error for nonexistent evidence."""
        with pytest.raises(ValueError):
            custody_chain.generate_custody_report("nonexistent-id")


# ============================================================================
# IntegrityError Tests
# ============================================================================

class TestIntegrityError:
    """Test IntegrityError exception class."""

    def test_integrity_error_is_exception(self):
        """Test that IntegrityError is an Exception."""
        assert issubclass(IntegrityError, Exception)

    def test_integrity_error_can_be_raised(self):
        """Test that IntegrityError can be raised and caught."""
        with pytest.raises(IntegrityError):
            raise IntegrityError("E-001", "Test integrity failure")

    def test_integrity_error_message(self):
        """Test that IntegrityError preserves message."""
        error = IntegrityError("E-001", "Hash mismatch detected")
        assert "Hash mismatch" in str(error)
        assert "E-001" in str(error)


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests combining multiple operations."""

    def test_full_custody_lifecycle(self, custody_chain, sample_evidence_record):
        """Test complete custody lifecycle."""
        # Log multiple events
        custody_chain.log_event(
            evidence_id=sample_evidence_record,
            event_type=EventType.ACCESS,
            examiner="Analyst",
            description="Analysis review"
        )

        custody_chain.log_event(
            evidence_id=sample_evidence_record,
            event_type=EventType.VERIFICATION,
            examiner="QA",
            description="Hash verification"
        )

        # Get chain
        chain = custody_chain.get_chain(sample_evidence_record)
        assert len(chain) == 2

        # Verify integrity
        is_valid, message = custody_chain.verify_integrity(sample_evidence_record)
        assert is_valid is True

        # Generate report
        report = custody_chain.generate_custody_report(sample_evidence_record)
        assert report["total_events"] == 2


# ============================================================================
# Additional Coverage Tests
# ============================================================================

class TestGetEvidenceByHash:
    """Test get_evidence_by_hash method."""

    def test_get_evidence_by_hash_found(self, custody_chain, sample_evidence_record, sample_evidence_file):
        """Test get_evidence_by_hash returns evidence when found."""
        import hashlib
        content = sample_evidence_file.read_bytes()
        sha256 = hashlib.sha256(content).hexdigest()

        evidence = custody_chain.get_evidence_by_hash(sha256)
        assert evidence is not None
        assert evidence.sha256.lower() == sha256.lower()

    def test_get_evidence_by_hash_not_found(self, custody_chain):
        """Test get_evidence_by_hash returns None when not found."""
        result = custody_chain.get_evidence_by_hash("nonexistent" * 8)
        assert result is None


class TestSearchEvidence:
    """Test search_evidence method."""

    def test_search_evidence_by_case_id(self, custody_chain, sample_evidence_record):
        """Test searching evidence by case_id."""
        results = custody_chain.search_evidence(case_id="TEST")
        assert len(results) >= 1

    def test_search_evidence_by_filename(self, custody_chain, sample_evidence_record):
        """Test searching evidence by filename."""
        results = custody_chain.search_evidence(filename="evidence")
        assert len(results) >= 1

    def test_search_evidence_by_examiner(self, custody_chain, sample_evidence_record):
        """Test searching evidence by examiner."""
        # First log an event to associate examiner
        custody_chain.log_event(
            evidence_id=sample_evidence_record,
            event_type=EventType.ACCESS,
            examiner="Unique Examiner 12345",
            description="Test access"
        )
        results = custody_chain.search_evidence(examiner="Unique Examiner")
        assert len(results) >= 1

    def test_search_evidence_no_results(self, custody_chain):
        """Test searching evidence with no results."""
        results = custody_chain.search_evidence(case_id="NONEXISTENT_CASE_XYZ")
        assert len(results) == 0


class TestIntegrityVerificationAdvanced:
    """Advanced integrity verification tests."""

    def test_verify_integrity_file_not_on_disk(self, custody_chain, tmp_path):
        """Test verify_integrity when file no longer exists on disk."""
        import hashlib

        # Create a file and evidence record
        test_file = tmp_path / "temp_evidence.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 110)

        content = test_file.read_bytes()
        sha256 = hashlib.sha256(content).hexdigest()

        engine = custody_chain._engine
        with get_session(engine) as session:
            case = CaseInfo(
                id="CASE-TEMP-001",
                case_name="Temp Case",
                examiner_assigned="Temp Examiner"
            )
            session.add(case)
            session.flush()

            evidence = EvidenceFile(
                filename=test_file.name,
                file_path=str(test_file.absolute()),
                file_size_bytes=test_file.stat().st_size,
                sha256=sha256,
                sha1=hashlib.sha1(content).hexdigest(),
                md5=hashlib.md5(content).hexdigest(),
                case_id="CASE-TEMP-001",
                evidence_number="E-TEMP-001",
                intake_timestamp=datetime.now(timezone.utc)
            )
            session.add(evidence)
            session.commit()
            evidence_id = evidence.id

        # Delete the file
        test_file.unlink()

        # Now verify - should fail because file is missing
        is_valid, message = custody_chain.verify_integrity(evidence_id)
        assert is_valid is False
        assert "not found on disk" in message

    def test_verify_integrity_hash_mismatch(self, custody_chain, tmp_path):
        """Test verify_integrity when file has been modified."""
        import hashlib

        # Create a file and evidence record
        test_file = tmp_path / "modified_evidence.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 110)

        content = test_file.read_bytes()

        engine = custody_chain._engine
        with get_session(engine) as session:
            case = CaseInfo(
                id="CASE-MOD-001",
                case_name="Modified Case",
                examiner_assigned="Test Examiner"
            )
            session.add(case)
            session.flush()

            # Store a wrong hash intentionally
            evidence = EvidenceFile(
                filename=test_file.name,
                file_path=str(test_file.absolute()),
                file_size_bytes=test_file.stat().st_size,
                sha256="wrong_hash_" + "a" * 54,  # Wrong hash
                sha1=hashlib.sha1(content).hexdigest(),
                md5=hashlib.md5(content).hexdigest(),
                case_id="CASE-MOD-001",
                evidence_number="E-MOD-001",
                intake_timestamp=datetime.now(timezone.utc)
            )
            session.add(evidence)
            session.commit()
            evidence_id = evidence.id

        # Verify - should fail because hash doesn't match
        is_valid, message = custody_chain.verify_integrity(evidence_id)
        assert is_valid is False
        assert "[FAIL]" in message


class TestLogEventIntegrityError:
    """Test log_event with integrity failures."""

    def test_log_event_raises_integrity_error_when_hash_fails(self, custody_chain, tmp_path):
        """Test that log_event raises IntegrityError when hash verification fails."""
        import hashlib

        # Create a file and evidence record with wrong hash
        test_file = tmp_path / "bad_hash_evidence.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 110)
        content = test_file.read_bytes()

        engine = custody_chain._engine
        with get_session(engine) as session:
            case = CaseInfo(
                id="CASE-BAD-001",
                case_name="Bad Hash Case",
                examiner_assigned="Test"
            )
            session.add(case)
            session.flush()

            evidence = EvidenceFile(
                filename=test_file.name,
                file_path=str(test_file.absolute()),
                file_size_bytes=test_file.stat().st_size,
                sha256="bad_hash_" + "x" * 55,  # Wrong hash
                sha1=hashlib.sha1(content).hexdigest(),
                md5=hashlib.md5(content).hexdigest(),
                case_id="CASE-BAD-001",
                evidence_number="E-BAD-001",
                intake_timestamp=datetime.now(timezone.utc)
            )
            session.add(evidence)
            session.commit()
            evidence_id = evidence.id

        # Try to log event with hash verification - should raise IntegrityError
        with pytest.raises(IntegrityError):
            custody_chain.log_event(
                evidence_id=evidence_id,
                event_type=EventType.ACCESS,
                examiner="Test",
                description="Test access",
                verify_hash=True
            )

    def test_log_event_without_hash_verification(self, custody_chain, sample_evidence_record):
        """Test log_event without hash verification."""
        event = custody_chain.log_event(
            evidence_id=sample_evidence_record,
            event_type=EventType.ACCESS,
            examiner="Test",
            description="Access without hash check",
            verify_hash=False
        )
        assert event is not None
        assert event.hash_verified is False


class TestContextManager:
    """Test context manager functionality."""

    def test_custody_chain_context_manager(self, temp_db_path):
        """Test CustodyChain as context manager."""
        with CustodyChain(db_path=temp_db_path) as chain:
            assert chain is not None

    def test_custody_chain_close_method(self, temp_db_path):
        """Test CustodyChain close method."""
        chain = CustodyChain(db_path=temp_db_path)
        chain.close()
        # Should not raise error when called


class TestCustodyReportWithVerification:
    """Test custody report with verification events."""

    def test_report_last_verified_found(self, custody_chain, sample_evidence_record):
        """Test that report includes last_verified when verification events exist."""
        # Log a verification event
        custody_chain.log_event(
            evidence_id=sample_evidence_record,
            event_type=EventType.VERIFICATION,
            examiner="QA",
            description="Verification check"
        )

        report = custody_chain.generate_custody_report(sample_evidence_record)
        assert report["last_verified"] is not None
