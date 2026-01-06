"""
Comprehensive unit tests for the FileGuard module.

Tests cover:
- FileGuard initialization and platform detection
- File protection (read-only) and unprotection
- Protection status verification
- File attribute retrieval
- Integrity snapshot creation and comparison
- ProtectedFileContext context manager
- Error handling for missing files and permission issues
"""

import hashlib
import os
import stat
import time
from pathlib import Path

import pytest

from dwg_forensic.core.file_guard import FileGuard, ProtectedFileContext


class TestFileGuardInitialization:
    """Test FileGuard class initialization."""

    def test_init_creates_instance(self):
        """Test that FileGuard can be initialized."""
        guard = FileGuard()
        assert guard is not None

    def test_init_detects_windows(self):
        """Test that FileGuard detects Windows platform."""
        guard = FileGuard()
        assert hasattr(guard, "_is_windows")


class TestFileProtection:
    """Test file protection (read-only) functionality."""

    def test_protect_makes_file_read_only(self, tmp_path):
        """Test that protect() removes write permissions from a file."""
        test_file = tmp_path / "test_protect.txt"
        test_file.write_text("Test content")

        guard = FileGuard()
        guard.protect(test_file)

        file_stat = os.stat(test_file)
        mode = file_stat.st_mode
        assert not (mode & stat.S_IWUSR)

    def test_protect_with_path_object(self, tmp_path):
        """Test that protect() works with Path objects."""
        test_file = tmp_path / "test_path.txt"
        test_file.write_text("Test content")

        guard = FileGuard()
        guard.protect(test_file)

        file_stat = os.stat(test_file)
        assert not (file_stat.st_mode & stat.S_IWUSR)

    def test_protect_nonexistent_file_raises_error(self, tmp_path):
        """Test that protect() raises FileNotFoundError for missing files."""
        guard = FileGuard()
        nonexistent = tmp_path / "nonexistent.txt"

        with pytest.raises(FileNotFoundError):
            guard.protect(nonexistent)


class TestFileUnprotection:
    """Test file unprotection (restoring write permissions) functionality."""

    def test_unprotect_restores_write_permission(self, tmp_path):
        """Test that unprotect() restores write permissions."""
        test_file = tmp_path / "test_unprotect.txt"
        test_file.write_text("Test content")

        guard = FileGuard()
        guard.protect(test_file)
        assert not (os.stat(test_file).st_mode & stat.S_IWUSR)

        guard.unprotect(test_file)
        assert os.stat(test_file).st_mode & stat.S_IWUSR

    def test_unprotect_nonexistent_file_raises_error(self, tmp_path):
        """Test that unprotect() raises FileNotFoundError for missing files."""
        guard = FileGuard()
        nonexistent = tmp_path / "nonexistent.txt"

        with pytest.raises(FileNotFoundError):
            guard.unprotect(nonexistent)


class TestProtectionStatusChecking:
    """Test protection status checking functionality."""

    def test_is_protected_on_protected_file(self, tmp_path):
        """Test that is_protected() returns True for read-only files."""
        test_file = tmp_path / "test_protected.txt"
        test_file.write_text("Test content")

        guard = FileGuard()
        guard.protect(test_file)

        assert guard.is_protected(test_file) is True

    def test_is_protected_on_writable_file(self, tmp_path):
        """Test that is_protected() returns False for writable files."""
        test_file = tmp_path / "test_writable.txt"
        test_file.write_text("Test content")

        guard = FileGuard()
        assert guard.is_protected(test_file) is False

    def test_verify_protection_on_protected_file(self, tmp_path):
        """Test verify_protection() returns correct status for protected files."""
        test_file = tmp_path / "test_verify.txt"
        test_file.write_text("Test content")

        guard = FileGuard()
        guard.protect(test_file)

        is_protected, message = guard.verify_protection(test_file)
        assert is_protected is True
        assert "[OK]" in message

    def test_verify_protection_on_writable_file(self, tmp_path):
        """Test verify_protection() returns correct status for writable files."""
        test_file = tmp_path / "test_verify_write.txt"
        test_file.write_text("Test content")

        guard = FileGuard()

        is_protected, message = guard.verify_protection(test_file)
        assert is_protected is False
        assert "[WARN]" in message


class TestFileAttributes:
    """Test file attribute retrieval functionality."""

    def test_get_file_attributes_returns_complete_dict(self, tmp_path):
        """Test that get_file_attributes() returns all expected attributes."""
        test_file = tmp_path / "test_attrs.txt"
        test_file.write_text("Test content for attributes")

        guard = FileGuard()
        attrs = guard.get_file_attributes(test_file)

        assert isinstance(attrs, dict)
        assert "is_read_only" in attrs
        assert "permissions" in attrs
        assert "created" in attrs
        assert "modified" in attrs
        assert "size" in attrs

    def test_get_file_attributes_protected_file(self, tmp_path):
        """Test that get_file_attributes() correctly identifies protected files."""
        test_file = tmp_path / "test_protected_attrs.txt"
        test_file.write_text("Protected content")

        guard = FileGuard()
        guard.protect(test_file)

        attrs = guard.get_file_attributes(test_file)
        assert attrs["is_read_only"] is True

    def test_get_file_attributes_nonexistent_file(self, tmp_path):
        """Test that get_file_attributes() raises error for missing files."""
        guard = FileGuard()
        nonexistent = tmp_path / "nonexistent.txt"

        with pytest.raises(FileNotFoundError):
            guard.get_file_attributes(nonexistent)


class TestIntegritySnapshot:
    """Test integrity snapshot creation and comparison functionality."""

    def test_create_integrity_snapshot_returns_complete_dict(self, tmp_path):
        """Test that create_integrity_snapshot() returns all expected data."""
        test_file = tmp_path / "test_snapshot.txt"
        test_file.write_text("Snapshot test content")

        guard = FileGuard()
        snapshot = guard.create_integrity_snapshot(test_file)

        assert isinstance(snapshot, dict)
        assert "file_path" in snapshot
        assert "snapshot_timestamp" in snapshot
        assert "hashes" in snapshot
        assert "size" in snapshot
        assert "protection_status" in snapshot

        assert "sha256" in snapshot["hashes"]
        assert "sha1" in snapshot["hashes"]
        assert "md5" in snapshot["hashes"]

    def test_create_integrity_snapshot_calculates_correct_hashes(self, tmp_path):
        """Test that snapshot calculates correct hash values."""
        test_file = tmp_path / "test_hash.txt"
        content = b"Known content for hash verification"
        test_file.write_bytes(content)

        expected_sha256 = hashlib.sha256(content).hexdigest()
        expected_sha1 = hashlib.sha1(content).hexdigest()
        expected_md5 = hashlib.md5(content).hexdigest()

        guard = FileGuard()
        snapshot = guard.create_integrity_snapshot(test_file)

        assert snapshot["hashes"]["sha256"] == expected_sha256
        assert snapshot["hashes"]["sha1"] == expected_sha1
        assert snapshot["hashes"]["md5"] == expected_md5

    def test_compare_snapshots_identical_files(self, tmp_path):
        """Test that compare_snapshots() returns no differences for identical files."""
        test_file = tmp_path / "test_compare.txt"
        test_file.write_text("Comparison test")

        guard = FileGuard()
        snapshot1 = guard.create_integrity_snapshot(test_file)
        time.sleep(0.01)
        snapshot2 = guard.create_integrity_snapshot(test_file)

        differences = guard.compare_snapshots(snapshot1, snapshot2)

        assert differences["is_identical"] is True
        assert differences["hash_changed"] is False

    def test_compare_snapshots_detects_content_change(self, tmp_path):
        """Test that compare_snapshots() detects content modifications."""
        test_file = tmp_path / "test_content_change.txt"
        test_file.write_text("Original content")

        guard = FileGuard()
        snapshot1 = guard.create_integrity_snapshot(test_file)

        test_file.write_text("Modified content")
        snapshot2 = guard.create_integrity_snapshot(test_file)

        differences = guard.compare_snapshots(snapshot1, snapshot2)

        assert differences["is_identical"] is False
        assert differences["hash_changed"] is True

    def test_compare_snapshots_detects_protection_change(self, tmp_path):
        """Test that compare_snapshots() detects protection status changes."""
        test_file = tmp_path / "test_protection_change.txt"
        test_file.write_text("Protection test")

        guard = FileGuard()
        snapshot1 = guard.create_integrity_snapshot(test_file)

        guard.protect(test_file)
        snapshot2 = guard.create_integrity_snapshot(test_file)

        differences = guard.compare_snapshots(snapshot1, snapshot2)

        assert differences["protection_changed"] is True


class TestProtectedFileContext:
    """Test ProtectedFileContext context manager functionality."""

    def test_context_manager_temporarily_unprotects(self, tmp_path):
        """Test that context manager temporarily removes protection."""
        test_file = tmp_path / "test_context.txt"
        test_file.write_text("Context test")

        guard = FileGuard()
        guard.protect(test_file)

        assert guard.is_protected(test_file) is True

        with ProtectedFileContext(guard, test_file, "Testing"):
            assert guard.is_protected(test_file) is False
            test_file.write_text("Modified in context")

        assert guard.is_protected(test_file) is True

    def test_context_manager_restores_on_exception(self, tmp_path):
        """Test that context manager restores protection even on exception."""
        test_file = tmp_path / "test_exception.txt"
        test_file.write_text("Exception test")

        guard = FileGuard()
        guard.protect(test_file)

        try:
            with ProtectedFileContext(guard, test_file, "Testing"):
                assert guard.is_protected(test_file) is False
                raise ValueError("Test exception")
        except ValueError:
            pass

        assert guard.is_protected(test_file) is True

    def test_context_manager_handles_initially_unprotected_file(self, tmp_path):
        """Test context manager with initially unprotected file."""
        test_file = tmp_path / "test_unprotected_context.txt"
        test_file.write_text("Unprotected test")

        guard = FileGuard()
        assert guard.is_protected(test_file) is False

        with ProtectedFileContext(guard, test_file, "Testing"):
            assert guard.is_protected(test_file) is False

        assert guard.is_protected(test_file) is False


class TestErrorHandling:
    """Test error handling for various edge cases."""

    def test_protect_already_protected_file(self, tmp_path):
        """Test that protect() handles already protected files."""
        test_file = tmp_path / "test_already_protected.txt"
        test_file.write_text("Test content")

        guard = FileGuard()
        guard.protect(test_file)
        guard.protect(test_file)

        assert guard.is_protected(test_file) is True


class TestIntegration:
    """Integration tests combining multiple operations."""

    def test_full_protection_cycle(self, tmp_path):
        """Test complete cycle: create, protect, verify, modify, unprotect."""
        test_file = tmp_path / "test_cycle.txt"
        test_file.write_text("Initial content")

        guard = FileGuard()

        assert guard.is_protected(test_file) is False

        guard.protect(test_file)
        assert guard.is_protected(test_file) is True

        is_protected, message = guard.verify_protection(test_file)
        assert is_protected is True

        attrs = guard.get_file_attributes(test_file)
        assert attrs["is_read_only"] is True

        snapshot1 = guard.create_integrity_snapshot(test_file)
        assert snapshot1["protection_status"] is True

        guard.unprotect(test_file)
        assert guard.is_protected(test_file) is False

        test_file.write_text("Modified content")

        snapshot2 = guard.create_integrity_snapshot(test_file)

        differences = guard.compare_snapshots(snapshot1, snapshot2)
        assert differences["hash_changed"] is True
        assert differences["protection_changed"] is True
