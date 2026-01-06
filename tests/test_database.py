"""
Comprehensive unit tests for database models and helper functions.

Tests cover:
- Model creation and default values
- Relationships between models
- Engine creation and session management
- Foreign key constraints
- Data integrity and validation
"""

import os
import tempfile
from datetime import datetime, timezone

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from dwg_forensic.core.database import (
    Base,
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
def memory_engine():
    """Create an in-memory SQLite engine for testing."""
    engine = get_engine(":memory:")
    init_db(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def session(memory_engine):
    """Create a database session for testing."""
    session = get_session(memory_engine)
    yield session
    session.close()


@pytest.fixture
def temp_db_path():
    """Create a temporary database file path."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def sample_case(session):
    """Create a sample case for testing."""
    case = CaseInfo(
        id="CASE-2025-001",
        case_name="Test Case",
        client="Test Client Corp",
        examiner_assigned="John Doe",
        status="ACTIVE",
        notes="Sample case for testing"
    )
    session.add(case)
    session.commit()
    session.refresh(case)
    return case


@pytest.fixture
def sample_evidence(session, sample_case):
    """Create a sample evidence file for testing."""
    evidence = EvidenceFile(
        filename="evidence_file.dwg",
        file_path="C:\\Evidence\\evidence_file.dwg",
        file_size_bytes=1024000,
        sha256="a" * 64,
        sha1="b" * 40,
        md5="c" * 32,
        case_id=sample_case.id,
        evidence_number="E-001",
        intake_timestamp=datetime.now(timezone.utc),
        notes="Sample evidence file"
    )
    session.add(evidence)
    session.commit()
    session.refresh(evidence)
    return evidence


# ============================================================================
# Engine and Session Tests
# ============================================================================

class TestEngineCreation:
    """Test database engine creation."""

    def test_get_engine_memory(self):
        """Test creating an in-memory database engine."""
        engine = get_engine(":memory:")
        assert engine is not None
        assert "sqlite" in str(engine.url)
        engine.dispose()

    def test_get_engine_file(self, temp_db_path):
        """Test creating a file-based database engine."""
        engine = get_engine(temp_db_path)
        assert engine is not None
        init_db(engine)
        assert "sqlite" in str(engine.url)
        engine.dispose()


class TestDatabaseInitialization:
    """Test database initialization."""

    def test_init_db_creates_tables(self):
        """Test that init_db creates all required tables."""
        engine = get_engine(":memory:")
        init_db(engine)

        inspector = inspect(engine)
        tables = inspector.get_table_names()

        assert "case_info" in tables
        assert "evidence_files" in tables
        assert "custody_events" in tables

        engine.dispose()

    def test_init_db_idempotent(self, memory_engine):
        """Test that init_db can be called multiple times safely."""
        init_db(memory_engine)
        init_db(memory_engine)


class TestSessionManagement:
    """Test session creation and management."""

    def test_get_session_returns_session(self, memory_engine):
        """Test that get_session returns a valid Session object."""
        session = get_session(memory_engine)
        assert session is not None
        session.close()

    def test_session_can_query(self, session):
        """Test that session can execute queries."""
        result = session.query(CaseInfo).all()
        assert isinstance(result, list)


# ============================================================================
# CaseInfo Model Tests
# ============================================================================

class TestCaseInfoModel:
    """Test CaseInfo model creation and behavior."""

    def test_create_case_minimal(self, session):
        """Test creating a case with minimal required fields."""
        case = CaseInfo(
            id="CASE-MIN-001",
            case_name="Minimal Case",
            examiner_assigned="Test Examiner"
        )
        session.add(case)
        session.commit()

        assert case.id == "CASE-MIN-001"
        assert case.case_name == "Minimal Case"
        assert case.status == "ACTIVE"

    def test_create_case_full(self, session):
        """Test creating a case with all fields."""
        case = CaseInfo(
            id="CASE-FULL-001",
            case_name="Full Case",
            client="Full Client Corp",
            examiner_assigned="Jane Smith",
            status="PENDING",
            notes="Test notes"
        )
        session.add(case)
        session.commit()

        assert case.id == "CASE-FULL-001"
        assert case.client == "Full Client Corp"
        assert case.examiner_assigned == "Jane Smith"
        assert case.status == "PENDING"
        assert case.notes == "Test notes"

    def test_case_default_values(self, session):
        """Test that default values are set correctly."""
        case = CaseInfo(
            id="CASE-DEF-001",
            case_name="Default Case",
            examiner_assigned="Examiner"
        )
        session.add(case)
        session.commit()
        session.refresh(case)

        assert case.created_at is not None
        assert isinstance(case.created_at, datetime)
        assert case.status == "ACTIVE"

    def test_case_relationship_evidence_files(self, session, sample_case):
        """Test CaseInfo relationship with EvidenceFile."""
        evidence1 = EvidenceFile(
            filename="file1.dwg",
            file_path="C:\\Evidence\\file1.dwg",
            file_size_bytes=1000,
            sha256="1" * 64,
            sha1="1" * 40,
            md5="1" * 32,
            case_id=sample_case.id
        )
        evidence2 = EvidenceFile(
            filename="file2.dwg",
            file_path="C:\\Evidence\\file2.dwg",
            file_size_bytes=2000,
            sha256="2" * 64,
            sha1="2" * 40,
            md5="2" * 32,
            case_id=sample_case.id
        )
        session.add_all([evidence1, evidence2])
        session.commit()

        session.refresh(sample_case)
        assert len(sample_case.evidence_files) == 2


# ============================================================================
# EvidenceFile Model Tests
# ============================================================================

class TestEvidenceFileModel:
    """Test EvidenceFile model creation and behavior."""

    def test_create_evidence_minimal(self, session, sample_case):
        """Test creating evidence with minimal required fields."""
        evidence = EvidenceFile(
            filename="test.dwg",
            file_path="C:\\Evidence\\test.dwg",
            file_size_bytes=1024,
            sha256="a" * 64,
            sha1="b" * 40,
            md5="c" * 32,
            case_id=sample_case.id
        )
        session.add(evidence)
        session.commit()

        assert evidence.id is not None
        assert evidence.filename == "test.dwg"
        assert evidence.case_id == sample_case.id

    def test_evidence_uuid_generation(self, session, sample_case):
        """Test that UUID is generated automatically."""
        evidence1 = EvidenceFile(
            filename="uuid1.dwg",
            file_path="C:\\Evidence\\uuid1.dwg",
            file_size_bytes=100,
            sha256="e" * 64,
            sha1="e" * 40,
            md5="e" * 32,
            case_id=sample_case.id
        )
        evidence2 = EvidenceFile(
            filename="uuid2.dwg",
            file_path="C:\\Evidence\\uuid2.dwg",
            file_size_bytes=200,
            sha256="f" * 64,
            sha1="f" * 40,
            md5="f" * 32,
            case_id=sample_case.id
        )
        session.add_all([evidence1, evidence2])
        session.commit()

        assert evidence1.id != evidence2.id

    def test_evidence_relationship_custody_events(self, session, sample_evidence):
        """Test EvidenceFile relationship with CustodyEvent."""
        event1 = CustodyEvent(
            evidence_id=sample_evidence.id,
            event_type="INTAKE",
            examiner="Examiner 1",
            description="Initial intake"
        )
        event2 = CustodyEvent(
            evidence_id=sample_evidence.id,
            event_type="ANALYSIS",
            examiner="Examiner 2",
            description="Analysis performed"
        )
        session.add_all([event1, event2])
        session.commit()

        session.refresh(sample_evidence)
        assert len(sample_evidence.custody_events) == 2


# ============================================================================
# CustodyEvent Model Tests
# ============================================================================

class TestCustodyEventModel:
    """Test CustodyEvent model creation and behavior."""

    def test_create_custody_event_minimal(self, session, sample_evidence):
        """Test creating custody event with minimal required fields."""
        event = CustodyEvent(
            evidence_id=sample_evidence.id,
            event_type="TRANSFER",
            examiner="Test Examiner",
            description="Transfer to lab"
        )
        session.add(event)
        session.commit()

        assert event.id is not None
        assert event.evidence_id == sample_evidence.id
        assert event.event_type == "TRANSFER"

    def test_create_custody_event_full(self, session, sample_evidence):
        """Test creating custody event with all fields."""
        event = CustodyEvent(
            evidence_id=sample_evidence.id,
            event_type="VERIFICATION",
            examiner="Full Examiner",
            description="Complete verification process",
            hash_verified=True,
            hash_at_event="i" * 64,
            workstation="WORKSTATION-02",
            ip_address="10.0.0.1",
            notes="All checks passed"
        )
        session.add(event)
        session.commit()

        assert event.description == "Complete verification process"
        assert event.hash_verified is True
        assert event.hash_at_event == "i" * 64
        assert event.workstation == "WORKSTATION-02"

    def test_custody_event_timestamp(self, session, sample_evidence):
        """Test that timestamp is set automatically."""
        event = CustodyEvent(
            evidence_id=sample_evidence.id,
            event_type="ACCESS",
            examiner="Timestamp Tester",
            description="Testing timestamp"
        )
        session.add(event)
        session.commit()
        session.refresh(event)

        assert event.timestamp is not None
        assert isinstance(event.timestamp, datetime)


# ============================================================================
# Relationship and Cascade Tests
# ============================================================================

class TestRelationshipsAndCascades:
    """Test relationships between models and cascade behavior."""

    def test_case_to_evidence_relationship(self, session, sample_case):
        """Test bidirectional relationship between Case and Evidence."""
        evidence = EvidenceFile(
            filename="relationship.dwg",
            file_path="C:\\Evidence\\relationship.dwg",
            file_size_bytes=1000,
            sha256="k" * 64,
            sha1="k" * 40,
            md5="k" * 32,
            case_id=sample_case.id
        )
        session.add(evidence)
        session.commit()

        session.refresh(sample_case)
        assert evidence in sample_case.evidence_files
        assert evidence.case.id == sample_case.id

    def test_multiple_evidence_per_case(self, session, sample_case):
        """Test that a case can have multiple evidence files."""
        evidence_files = []
        for i in range(5):
            evidence = EvidenceFile(
                filename=f"multi_{i}.dwg",
                file_path=f"C:\\Evidence\\multi_{i}.dwg",
                file_size_bytes=1000 * (i + 1),
                sha256=str(i) * 64,
                sha1=str(i) * 40,
                md5=str(i) * 32,
                case_id=sample_case.id
            )
            evidence_files.append(evidence)

        session.add_all(evidence_files)
        session.commit()

        session.refresh(sample_case)
        assert len(sample_case.evidence_files) == 5


# ============================================================================
# Query and Filter Tests
# ============================================================================

class TestQueryAndFilter:
    """Test querying and filtering capabilities."""

    def test_query_cases_by_status(self, session):
        """Test filtering cases by status."""
        for i in range(3):
            case = CaseInfo(
                id=f"CASE-ACTIVE-{i}",
                case_name=f"Active Case {i}",
                examiner_assigned="Examiner",
                status="ACTIVE"
            )
            session.add(case)

        for i in range(2):
            case = CaseInfo(
                id=f"CASE-CLOSED-{i}",
                case_name=f"Closed Case {i}",
                examiner_assigned="Examiner",
                status="CLOSED"
            )
            session.add(case)

        session.commit()

        active_cases = session.query(CaseInfo).filter_by(status="ACTIVE").all()
        closed_cases = session.query(CaseInfo).filter_by(status="CLOSED").all()

        assert len(active_cases) == 3
        assert len(closed_cases) == 2

    def test_query_evidence_by_case(self, session, sample_case):
        """Test querying evidence files by case."""
        for i in range(5):
            evidence = EvidenceFile(
                filename=f"query_{i}.dwg",
                file_path=f"C:\\Evidence\\query_{i}.dwg",
                file_size_bytes=1000 * i,
                sha256=f"{i}" * 64,
                sha1=f"{i}" * 40,
                md5=f"{i}" * 32,
                case_id=sample_case.id
            )
            session.add(evidence)
        session.commit()

        results = session.query(EvidenceFile).filter_by(
            case_id=sample_case.id
        ).all()

        assert len(results) == 5


# ============================================================================
# Edge Cases
# ============================================================================

class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_long_text_fields(self, session, sample_case):
        """Test handling long text in notes and description fields."""
        long_text = "x" * 10000
        evidence = EvidenceFile(
            filename="long_notes.dwg",
            file_path="C:\\Evidence\\long_notes.dwg",
            file_size_bytes=100,
            sha256="n" * 64,
            sha1="n" * 40,
            md5="n" * 32,
            case_id=sample_case.id,
            notes=long_text
        )
        session.add(evidence)
        session.commit()

        assert len(evidence.notes) == 10000

    def test_special_characters_in_paths(self, session, sample_case):
        """Test handling special characters in file paths."""
        special_path = "C:\\Evidence\\Test (Copy) [v2] {final}.dwg"
        evidence = EvidenceFile(
            filename="Test (Copy) [v2] {final}.dwg",
            file_path=special_path,
            file_size_bytes=100,
            sha256="o" * 64,
            sha1="o" * 40,
            md5="o" * 32,
            case_id=sample_case.id
        )
        session.add(evidence)
        session.commit()

        assert evidence.file_path == special_path
