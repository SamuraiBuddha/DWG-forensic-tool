"""
Comprehensive unit tests for the FileIntake module.

Tests cover:
- FileIntake initialization
- Hash calculation (SHA-256, SHA-1, MD5)
- Evidence file copying
- Read-only protection setting
- Copy verification
- Full intake workflow
- Error handling for missing files and invalid inputs
"""

import hashlib
import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dwg_forensic.core.intake import FileIntake, intake_file
from dwg_forensic.utils.exceptions import IntakeError


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def temp_db_path(tmp_path):
    """Create a temporary database file path."""
    return str(tmp_path / "test.db")


@pytest.fixture
def temp_evidence_dir(tmp_path):
    """Create a temporary evidence directory."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    return evidence_dir


@pytest.fixture
def valid_dwg_file(tmp_path):
    """Create a valid DWG file for testing (AC1032 - 2018 format)."""
    test_file = tmp_path / "test.dwg"
    # Create minimal valid DWG header (needs at least 108 bytes)
    # AC1032 magic bytes + padding to meet minimum size requirement
    header = b"AC1032" + b"\x00" * 110
    test_file.write_bytes(header)
    return test_file


@pytest.fixture
def file_intake(temp_evidence_dir, temp_db_path):
    """Create a FileIntake instance for testing."""
    return FileIntake(evidence_dir=temp_evidence_dir, db_path=temp_db_path)


# ============================================================================
# Initialization Tests
# ============================================================================

class TestFileIntakeInitialization:
    """Test FileIntake class initialization."""

    def test_init_creates_instance(self, temp_evidence_dir, temp_db_path):
        """Test that FileIntake can be initialized."""
        intake = FileIntake(evidence_dir=temp_evidence_dir, db_path=temp_db_path)
        assert intake is not None

    def test_init_with_string_paths(self, tmp_path, temp_db_path):
        """Test initialization with string paths."""
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir()

        intake = FileIntake(evidence_dir=str(evidence_dir), db_path=str(temp_db_path))
        assert intake is not None

    def test_init_creates_evidence_dir_if_missing(self, tmp_path, temp_db_path):
        """Test that init creates evidence directory if it doesn't exist."""
        evidence_dir = tmp_path / "new_evidence"

        intake = FileIntake(evidence_dir=evidence_dir, db_path=temp_db_path)
        assert evidence_dir.exists()


# ============================================================================
# Hash Calculation Tests
# ============================================================================

class TestHashCalculation:
    """Test hash calculation functionality."""

    def test_calculate_hashes_returns_all_algorithms(self, file_intake, tmp_path):
        """Test that _calculate_hashes returns SHA-256, SHA-1, and MD5."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Test content")

        hashes = file_intake._calculate_hashes(test_file)

        assert "sha256" in hashes
        assert "sha1" in hashes
        assert "md5" in hashes

    def test_calculate_hashes_correct_values(self, file_intake, tmp_path):
        """Test that hashes are calculated correctly."""
        test_file = tmp_path / "test.bin"
        content = b"Known content for hash verification"
        test_file.write_bytes(content)

        expected_sha256 = hashlib.sha256(content).hexdigest()
        expected_sha1 = hashlib.sha1(content).hexdigest()
        expected_md5 = hashlib.md5(content).hexdigest()

        hashes = file_intake._calculate_hashes(test_file)

        assert hashes["sha256"] == expected_sha256
        assert hashes["sha1"] == expected_sha1
        assert hashes["md5"] == expected_md5


# ============================================================================
# Evidence Copying Tests
# ============================================================================

class TestEvidenceCopying:
    """Test evidence file copying functionality."""

    def test_copy_to_evidence_creates_file(self, file_intake, valid_dwg_file):
        """Test that _copy_to_evidence creates the destination file."""
        dest_path = file_intake._copy_to_evidence(
            valid_dwg_file,
            case_id="CASE-001",
            evidence_number="E-001"
        )

        assert dest_path.exists()
        assert dest_path.read_bytes() == valid_dwg_file.read_bytes()

    def test_copy_to_evidence_creates_directory_structure(self, file_intake, valid_dwg_file):
        """Test that copying creates case/evidence_number directory structure."""
        dest_path = file_intake._copy_to_evidence(
            valid_dwg_file,
            case_id="CASE-2025-001",
            evidence_number="E-001"
        )

        assert "CASE-2025-001" in str(dest_path)
        assert "E-001" in str(dest_path)

    def test_copy_preserves_filename(self, file_intake, valid_dwg_file):
        """Test that original filename is preserved."""
        dest_path = file_intake._copy_to_evidence(
            valid_dwg_file,
            case_id="CASE-001",
            evidence_number="E-001"
        )

        assert dest_path.name == valid_dwg_file.name


# ============================================================================
# Read-Only Protection Tests
# ============================================================================

class TestReadOnlyProtection:
    """Test read-only protection setting functionality."""

    def test_set_read_only_removes_write_permission(self, file_intake, tmp_path):
        """Test that _set_read_only removes write permissions."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        file_intake._set_read_only(test_file)

        file_stat = os.stat(test_file)
        assert not (file_stat.st_mode & stat.S_IWUSR)


# ============================================================================
# Copy Verification Tests
# ============================================================================

class TestCopyVerification:
    """Test copy verification functionality."""

    def test_verify_copy_returns_true_for_identical(self, file_intake, tmp_path):
        """Test verification returns True for identical files."""
        test_file = tmp_path / "test.bin"
        content = b"test content"
        test_file.write_bytes(content)

        original_hash = hashlib.sha256(content).hexdigest()
        assert file_intake._verify_copy(original_hash, test_file)

    def test_verify_copy_returns_false_for_different(self, file_intake, tmp_path):
        """Test verification returns False for different content."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"different content")

        wrong_hash = hashlib.sha256(b"original content").hexdigest()
        assert not file_intake._verify_copy(wrong_hash, test_file)


# ============================================================================
# Full Intake Workflow Tests
# ============================================================================

class TestFullIntakeWorkflow:
    """Test complete intake workflow."""

    def test_intake_creates_evidence_record(self, file_intake, valid_dwg_file):
        """Test that intake() creates a complete evidence record."""
        result = file_intake.intake(
            source_path=valid_dwg_file,
            case_id="CASE-2025-001",
            examiner="Test Examiner"
        )

        assert result is not None
        assert result.filename == valid_dwg_file.name
        assert result.sha256 is not None

    def test_intake_protects_evidence_file(self, file_intake, valid_dwg_file):
        """Test that intake sets evidence file to read-only."""
        result = file_intake.intake(
            source_path=valid_dwg_file,
            case_id="CASE-2025-001",
            examiner="Test Examiner"
        )

        evidence_path = Path(result.file_path)
        file_stat = os.stat(evidence_path)
        assert not (file_stat.st_mode & stat.S_IWUSR)

    def test_intake_calculates_correct_hashes(self, file_intake, valid_dwg_file):
        """Test that intake calculates correct hash values."""
        content = valid_dwg_file.read_bytes()
        expected_sha256 = hashlib.sha256(content).hexdigest()

        result = file_intake.intake(
            source_path=valid_dwg_file,
            case_id="CASE-001",
            examiner="Examiner"
        )

        assert result.sha256 == expected_sha256

    def test_intake_with_evidence_number(self, file_intake, valid_dwg_file):
        """Test intake with custom evidence number."""
        result = file_intake.intake(
            source_path=valid_dwg_file,
            case_id="CASE-001",
            examiner="Examiner",
            evidence_number="E-CUSTOM-001"
        )

        assert result.evidence_number == "E-CUSTOM-001"

    def test_intake_with_notes(self, file_intake, valid_dwg_file):
        """Test intake with notes."""
        result = file_intake.intake(
            source_path=valid_dwg_file,
            case_id="CASE-001",
            examiner="Examiner",
            notes="Test intake notes"
        )

        assert result.notes == "Test intake notes"


# ============================================================================
# Convenience Function Tests
# ============================================================================

class TestIntakeFileFunction:
    """Test the intake_file convenience function."""

    def test_intake_file_function_works(self, temp_evidence_dir, temp_db_path, valid_dwg_file):
        """Test that intake_file() convenience function works."""
        result = intake_file(
            source_path=valid_dwg_file,
            case_id="CASE-001",
            examiner="Examiner",
            evidence_dir=temp_evidence_dir,
            db_path=temp_db_path
        )

        assert result is not None
        assert result.filename == valid_dwg_file.name


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestErrorHandling:
    """Test error handling for various edge cases."""

    def test_intake_nonexistent_file_raises_error(self, file_intake, tmp_path):
        """Test that intake raises error for missing source file."""
        nonexistent = tmp_path / "nonexistent.dwg"

        with pytest.raises(IntakeError):
            file_intake.intake(
                source_path=nonexistent,
                case_id="CASE-001",
                examiner="Examiner"
            )

    def test_intake_invalid_dwg_raises_error(self, file_intake, tmp_path):
        """Test that intake raises error for non-DWG file."""
        invalid_file = tmp_path / "invalid.dwg"
        invalid_file.write_bytes(b"This is not a DWG file")

        with pytest.raises(IntakeError):
            file_intake.intake(
                source_path=invalid_file,
                case_id="CASE-001",
                examiner="Examiner"
            )

    def test_intake_directory_raises_error(self, file_intake, tmp_path):
        """Test that intake raises error for directory path."""
        test_dir = tmp_path / "test_dir"
        test_dir.mkdir()

        with pytest.raises(IntakeError):
            file_intake.intake(
                source_path=test_dir,
                case_id="CASE-001",
                examiner="Examiner"
            )


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests for FileIntake."""

    def test_full_intake_cycle(self, temp_evidence_dir, temp_db_path, valid_dwg_file):
        """Test complete intake cycle from source to protected evidence."""
        content = valid_dwg_file.read_bytes()

        # Perform intake
        intake = FileIntake(evidence_dir=temp_evidence_dir, db_path=temp_db_path)
        result = intake.intake(
            source_path=valid_dwg_file,
            case_id="CASE-2025-001",
            examiner="John Doe",
            evidence_number="E-001",
            notes="Test intake"
        )

        # Verify result
        assert result is not None
        assert result.filename == valid_dwg_file.name

        # Verify evidence file exists
        evidence_path = Path(result.file_path)
        assert evidence_path.exists()

        # Verify content matches
        assert evidence_path.read_bytes() == content

        # Verify file is protected
        file_stat = os.stat(evidence_path)
        assert not (file_stat.st_mode & stat.S_IWUSR)

        # Verify hashes
        assert result.sha256 == hashlib.sha256(content).hexdigest()

    def test_multiple_evidence_same_case(self, temp_evidence_dir, temp_db_path, tmp_path):
        """Test intaking multiple evidence files for the same case."""
        intake = FileIntake(evidence_dir=temp_evidence_dir, db_path=temp_db_path)

        results = []
        for i in range(3):
            # Create separate DWG file (needs at least 108 bytes)
            dwg_file = tmp_path / f"evidence_{i}.dwg"
            dwg_file.write_bytes(b"AC1032" + f"Content {i}".encode() + b"\x00" * 110)

            result = intake.intake(
                source_path=dwg_file,
                case_id="CASE-MULTI-001",
                examiner="Examiner",
                evidence_number=f"E-00{i+1}"
            )
            results.append(result)

        # Verify all intakes succeeded
        assert len(results) == 3

        # Verify each has unique evidence path
        paths = [r.file_path for r in results]
        assert len(set(paths)) == 3
