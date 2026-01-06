"""
File Guard Module

Provides write-protection verification for evidence files. Ensures files
haven't been modified and manages read-only attributes.
"""

import hashlib
import os
import platform
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


class FileGuard:
    """Guards evidence files against unauthorized modification."""

    def __init__(self):
        """Initialize the file guard."""
        self._is_windows = platform.system() == "Windows"

    def protect(self, file_path: Path) -> None:
        """
        Set file as read-only (write-protected).

        Args:
            file_path: Path to the file to protect

        Raises:
            PermissionError: If cannot set read-only
            FileNotFoundError: If file doesn't exist
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            current_permissions = file_path.stat().st_mode
            new_permissions = current_permissions & ~(
                stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
            )
            os.chmod(file_path, new_permissions)
        except OSError as e:
            raise PermissionError(f"Cannot set read-only on {file_path}: {e}")

    def unprotect(self, file_path: Path) -> None:
        """
        Remove read-only protection (for authorized operations).

        CAUTION: Should only be used for legitimate operations like
        transferring evidence. Always re-protect after.

        Args:
            file_path: Path to the file to unprotect

        Raises:
            PermissionError: If cannot remove protection
            FileNotFoundError: If file doesn't exist
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            current_permissions = file_path.stat().st_mode
            new_permissions = current_permissions | stat.S_IWUSR
            os.chmod(file_path, new_permissions)
        except OSError as e:
            raise PermissionError(f"Cannot remove read-only from {file_path}: {e}")

    def is_protected(self, file_path: Path) -> bool:
        """Check if file is currently write-protected (read-only)."""
        file_path = Path(file_path)
        if not file_path.exists():
            return False

        file_stat = file_path.stat()
        mode = file_stat.st_mode

        # Check if any write bits are set
        return not bool(mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))

    def verify_protection(self, file_path: Path) -> Tuple[bool, str]:
        """Verify file protection status and return status with message."""
        file_path = Path(file_path)
        if not file_path.exists():
            return False, f"[FAIL] File not found: {file_path}"

        is_protected = self.is_protected(file_path)

        if is_protected:
            return True, f"[OK] File is write-protected: {file_path}"
        else:
            return False, f"[WARN] File is NOT write-protected: {file_path}"

    def get_file_attributes(self, file_path: Path) -> Dict[str, Any]:
        """Get detailed file attributes."""
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        file_stat = file_path.stat()
        mode = file_stat.st_mode

        attributes = {
            "is_read_only": self.is_protected(file_path),
            "permissions": oct(stat.S_IMODE(mode)),
            "created": datetime.fromtimestamp(file_stat.st_ctime),
            "modified": datetime.fromtimestamp(file_stat.st_mtime),
            "accessed": datetime.fromtimestamp(file_stat.st_atime),
            "size": file_stat.st_size,
            "is_hidden": file_path.name.startswith("."),
            "is_system": False,
        }

        # Windows-specific attributes
        if self._is_windows:
            try:
                import ctypes
                FILE_ATTRIBUTE_HIDDEN = 0x02
                FILE_ATTRIBUTE_SYSTEM = 0x04

                attrs = ctypes.windll.kernel32.GetFileAttributesW(str(file_path))
                if attrs != -1:
                    attributes["is_hidden"] = bool(attrs & FILE_ATTRIBUTE_HIDDEN)
                    attributes["is_system"] = bool(attrs & FILE_ATTRIBUTE_SYSTEM)
            except Exception:
                pass

        # Owner information
        attributes["owner"] = str(file_stat.st_uid)

        return attributes

    def create_integrity_snapshot(self, file_path: Path) -> Dict[str, Any]:
        """Create a complete integrity snapshot of a file."""
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        sha256_hash = hashlib.sha256()
        sha1_hash = hashlib.sha1()
        md5_hash = hashlib.md5()

        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256_hash.update(chunk)
                sha1_hash.update(chunk)
                md5_hash.update(chunk)

        return {
            "file_path": str(file_path.absolute()),
            "snapshot_timestamp": datetime.now(),
            "hashes": {
                "sha256": sha256_hash.hexdigest(),
                "sha1": sha1_hash.hexdigest(),
                "md5": md5_hash.hexdigest(),
            },
            "size": file_path.stat().st_size,
            "protection_status": self.is_protected(file_path),
            "attributes": self.get_file_attributes(file_path),
        }

    def compare_snapshots(
        self,
        snapshot1: Dict[str, Any],
        snapshot2: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Compare two integrity snapshots and return differences."""
        differences = []

        # Compare hashes
        hash_changed = snapshot1["hashes"] != snapshot2["hashes"]
        if hash_changed:
            for hash_type in ["sha256", "sha1", "md5"]:
                if snapshot1["hashes"][hash_type] != snapshot2["hashes"][hash_type]:
                    differences.append(f"{hash_type} hash changed")

        # Compare size
        size_changed = snapshot1["size"] != snapshot2["size"]
        if size_changed:
            differences.append(
                f"Size changed: {snapshot1['size']} -> {snapshot2['size']}"
            )

        # Compare protection status
        protection_changed = (
            snapshot1["protection_status"] != snapshot2["protection_status"]
        )
        if protection_changed:
            differences.append(
                f"Protection changed: {snapshot1['protection_status']} -> "
                f"{snapshot2['protection_status']}"
            )

        return {
            "is_identical": len(differences) == 0,
            "differences": differences,
            "hash_changed": hash_changed,
            "size_changed": size_changed,
            "protection_changed": protection_changed,
            "comparison_timestamp": datetime.now(),
        }


class ProtectedFileContext:
    """Context manager for temporarily unprotecting a file."""

    def __init__(self, guard: FileGuard, file_path: Path, reason: str):
        """Initialize context for temporary unprotection."""
        self.guard = guard
        self.file_path = Path(file_path)
        self.reason = reason
        self._was_protected = False

    def __enter__(self) -> Path:
        """Unprotect file and return path."""
        self._was_protected = self.guard.is_protected(self.file_path)

        if self._was_protected:
            self.guard.unprotect(self.file_path)

        return self.file_path

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[Exception],
        exc_tb: Optional[Any]
    ) -> None:
        """Re-protect file on exit."""
        if self._was_protected:
            try:
                self.guard.protect(self.file_path)
            except Exception:
                raise
