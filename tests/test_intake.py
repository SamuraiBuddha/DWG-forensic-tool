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


# ============================================================================
# Additional Coverage Tests
# ============================================================================

class TestEvidenceDirectoryCreationError:
    """Test evidence directory creation failures."""

    def test_init_raises_intake_error_when_dir_creation_fails(self, tmp_path, temp_db_path):
        """Test that IntakeError is raised when directory creation fails."""
        # Create a file where directory should be (to cause mkdir to fail)
        blocker = tmp_path / "evidence"
        blocker.write_text("blocking file")

        with pytest.raises(IntakeError):
            FileIntake(evidence_dir=blocker / "subdir", db_path=temp_db_path)


class TestDuplicateEvidenceFile:
    """Test handling of duplicate evidence files."""

    def test_intake_raises_error_for_duplicate(self, file_intake, valid_dwg_file):
        """Test that intake raises error when evidence file already exists."""
        # First intake
        file_intake.intake(
            source_path=valid_dwg_file,
            case_id="CASE-DUP-001",
            examiner="Examiner",
            evidence_number="E-DUP-001"
        )

        # Create a new source file with same name to try to intake
        new_file = valid_dwg_file.parent / "test2.dwg"
        new_file.write_bytes(valid_dwg_file.read_bytes())

        # Rename to same name as original
        original_name = valid_dwg_file
        new_source = original_name.parent / original_name.name

        # Try to intake again with same case/evidence number
        # This should fail because the destination file already exists
        with pytest.raises(IntakeError) as excinfo:
            file_intake.intake(
                source_path=new_source,
                case_id="CASE-DUP-001",
                examiner="Examiner",
                evidence_number="E-DUP-001"
            )
        assert "already exists" in str(excinfo.value)


class TestCleanupMethod:
    """Test _cleanup method."""

    def test_cleanup_removes_read_only_file(self, file_intake, tmp_path):
        """Test that _cleanup removes read-only file."""
        test_file = tmp_path / "cleanup_test.txt"
        test_file.write_text("test content")

        # Set read-only
        file_intake._set_read_only(test_file)

        # Cleanup should remove it
        file_intake._cleanup(test_file)
        assert not test_file.exists()

    def test_cleanup_handles_nonexistent_file(self, file_intake, tmp_path):
        """Test that _cleanup handles nonexistent file gracefully."""
        nonexistent = tmp_path / "nonexistent.txt"
        # Should not raise error
        file_intake._cleanup(nonexistent)


class TestContextManagerIntake:
    """Test FileIntake context manager."""

    def test_file_intake_context_manager(self, temp_evidence_dir, temp_db_path):
        """Test FileIntake as context manager."""
        with FileIntake(evidence_dir=temp_evidence_dir, db_path=temp_db_path) as intake:
            assert intake is not None

    def test_file_intake_close_method(self, temp_evidence_dir, temp_db_path):
        """Test FileIntake close method."""
        intake = FileIntake(evidence_dir=temp_evidence_dir, db_path=temp_db_path)
        intake.close()
        # Should not raise error


class TestIntakeErrorPaths:
    """Test various error paths during intake."""

    def test_intake_with_hash_calculation_error(self, file_intake, tmp_path):
        """Test intake when hash calculation fails."""
        from unittest.mock import patch

        # Create a valid DWG file
        test_file = tmp_path / "test_hash_error.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 110)

        # Mock _calculate_hashes to raise an exception
        with patch.object(file_intake, '_calculate_hashes', side_effect=IOError("Hash calculation failed")):
            with pytest.raises(IntakeError) as excinfo:
                file_intake.intake(
                    source_path=test_file,
                    case_id="CASE-001",
                    examiner="Examiner"
                )
            assert "Failed to calculate hashes" in str(excinfo.value)

    def test_intake_with_copy_error(self, file_intake, tmp_path):
        """Test intake when file copy fails."""
        from unittest.mock import patch

        test_file = tmp_path / "test_copy_error.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 110)

        with patch.object(file_intake, '_copy_to_evidence', side_effect=IOError("Copy failed")):
            with pytest.raises(IntakeError) as excinfo:
                file_intake.intake(
                    source_path=test_file,
                    case_id="CASE-001",
                    examiner="Examiner"
                )
            assert "Failed to copy" in str(excinfo.value)

    def test_intake_with_read_only_error(self, file_intake, tmp_path):
        """Test intake when set_read_only fails."""
        from unittest.mock import patch

        test_file = tmp_path / "test_readonly_error.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 110)

        # We need to mock _set_read_only to fail, but after _copy_to_evidence succeeds
        original_copy = file_intake._copy_to_evidence
        copied_path = [None]

        def mock_copy(*args, **kwargs):
            result = original_copy(*args, **kwargs)
            copied_path[0] = result
            return result

        with patch.object(file_intake, '_copy_to_evidence', side_effect=mock_copy):
            with patch.object(file_intake, '_set_read_only', side_effect=PermissionError("Cannot set read-only")):
                with pytest.raises(IntakeError) as excinfo:
                    file_intake.intake(
                        source_path=test_file,
                        case_id="CASE-RO-001",
                        examiner="Examiner"
                    )
                assert "Failed to set read-only" in str(excinfo.value)

    def test_intake_with_verify_error(self, file_intake, tmp_path):
        """Test intake when copy verification fails."""
        from unittest.mock import patch

        test_file = tmp_path / "test_verify_error.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 110)

        # Mock _verify_copy to raise an exception (not return False)
        with patch.object(file_intake, '_verify_copy', side_effect=IOError("Verify failed")):
            with pytest.raises(IntakeError) as excinfo:
                file_intake.intake(
                    source_path=test_file,
                    case_id="CASE-VER-001",
                    examiner="Examiner"
                )
            assert "Failed to verify copy" in str(excinfo.value)

    def test_intake_with_hash_mismatch(self, file_intake, tmp_path):
        """Test intake when copy hash doesn't match original."""
        from unittest.mock import patch

        test_file = tmp_path / "test_mismatch.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 110)

        # Mock _verify_copy to return False (hash mismatch)
        with patch.object(file_intake, '_verify_copy', return_value=False):
            with pytest.raises(IntakeError) as excinfo:
                file_intake.intake(
                    source_path=test_file,
                    case_id="CASE-MIS-001",
                    examiner="Examiner"
                )
            assert "verification failed" in str(excinfo.value).lower()

    def test_intake_with_database_error(self, file_intake, tmp_path):
        """Test intake when database operation fails."""
        from unittest.mock import patch, MagicMock
        from dwg_forensic.core import intake as intake_module

        test_file = tmp_path / "test_db_error.dwg"
        test_file.write_bytes(b"AC1032" + b"\x00" * 110)

        # Mock get_session to raise an exception during the database operation
        with patch.object(intake_module, 'get_session') as mock_session:
            mock_cm = MagicMock()
            mock_cm.__enter__ = MagicMock(side_effect=Exception("Database error"))
            mock_cm.__exit__ = MagicMock(return_value=False)
            mock_session.return_value = mock_cm

            with pytest.raises(IntakeError) as excinfo:
                file_intake.intake(
                    source_path=test_file,
                    case_id="CASE-DB-001",
                    examiner="Examiner"
                )
            assert "Failed to create database record" in str(excinfo.value)
