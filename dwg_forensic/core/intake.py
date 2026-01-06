"""
File intake module for DWG forensic tool.

Handles secure intake of DWG files into evidence with:
- Multi-hash verification (SHA-256, SHA-1, MD5)
- Evidence storage with write protection
- Chain of custody tracking
- Database record creation
"""

import hashlib
import os
import shutil
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dwg_forensic.core.database import (
    CaseInfo,
    CustodyEvent,
    EvidenceFile,
    get_engine,
    get_session,
    init_db,
)
from dwg_forensic.parsers.header import HeaderParser
from dwg_forensic.utils.exceptions import IntakeError


class FileIntake:
    """Handles secure intake of DWG files into evidence."""

    def __init__(self, evidence_dir: Path, db_path: Path):
        """
        Initialize file intake handler.

        Args:
            evidence_dir: Root directory for evidence storage
            db_path: Path to SQLite database file

        Raises:
            IntakeError: If evidence directory cannot be created
        """
        self.evidence_dir = Path(evidence_dir)
        self.db_path = Path(db_path)

        # Ensure evidence directory exists
        try:
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            raise IntakeError(str(self.evidence_dir), f"Failed to create evidence directory: {e}")

        # Initialize database
        self._engine = get_engine(str(self.db_path))
        init_db(self._engine)

    def intake(
        self,
        source_path: Path,
        case_id: str,
        examiner: str,
        evidence_number: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> EvidenceFile:
        """
        Intake a DWG file into evidence.

        Process:
        1. Validate file exists and is a DWG (check header)
        2. Calculate hashes (SHA-256, SHA-1, MD5)
        3. Copy to evidence directory: {case_id}/{evidence_number}/filename.dwg
        4. Set file as read-only
        5. Verify copy hash matches original
        6. Create database record
        7. Log custody event (INTAKE)

        Args:
            source_path: Path to source DWG file
            case_id: Case identifier
            examiner: Name of examiner performing intake
            evidence_number: Optional evidence number (UUID generated if not provided)
            notes: Optional notes about the evidence

        Returns:
            EvidenceFile record

        Raises:
            IntakeError: On any failure during intake process
        """
        source_path = Path(source_path)

        # Step 1: Validate file exists
        if not source_path.exists():
            raise IntakeError(str(source_path), "Source file does not exist")

        if not source_path.is_file():
            raise IntakeError(str(source_path), "Source path is not a file")

        # Validate DWG file format
        try:
            parser = HeaderParser()
            parser.parse(source_path)
        except Exception as e:
            raise IntakeError(str(source_path), f"Not a valid DWG file: {e}")

        # Step 2: Calculate hashes
        try:
            hashes = self._calculate_hashes(source_path)
        except Exception as e:
            raise IntakeError(str(source_path), f"Failed to calculate hashes: {e}")

        # Generate evidence number if not provided
        if not evidence_number:
            evidence_number = str(uuid.uuid4())[:8].upper()

        # Step 3: Copy to evidence directory
        try:
            evidence_path = self._copy_to_evidence(source_path, case_id, evidence_number)
        except Exception as e:
            raise IntakeError(str(source_path), f"Failed to copy to evidence: {e}")

        # Step 4: Set file as read-only
        try:
            self._set_read_only(evidence_path)
        except Exception as e:
            self._cleanup(evidence_path)
            raise IntakeError(str(source_path), f"Failed to set read-only: {e}")

        # Step 5: Verify copy
        try:
            if not self._verify_copy(hashes["sha256"], evidence_path):
                self._cleanup(evidence_path)
                raise IntakeError(str(source_path), "Copy verification failed - hash mismatch")
        except IntakeError:
            raise
        except Exception as e:
            self._cleanup(evidence_path)
            raise IntakeError(str(source_path), f"Failed to verify copy: {e}")

        # Step 6 & 7: Create database records
        try:
            with get_session(self._engine) as session:
                # Ensure case exists
                case = session.get(CaseInfo, case_id)
                if not case:
                    case = CaseInfo(
                        id=case_id,
                        case_name=f"Case {case_id}",
                        examiner_assigned=examiner,
                    )
                    session.add(case)
                    session.flush()

                # Create evidence file record
                evidence_file = EvidenceFile(
                    filename=source_path.name,
                    file_path=str(evidence_path.absolute()),
                    file_size_bytes=source_path.stat().st_size,
                    sha256=hashes["sha256"],
                    sha1=hashes["sha1"],
                    md5=hashes["md5"],
                    case_id=case_id,
                    evidence_number=evidence_number,
                    intake_timestamp=datetime.now(timezone.utc),
                    notes=notes,
                )
                session.add(evidence_file)
                session.flush()

                # Create custody event
                custody_event = CustodyEvent(
                    evidence_id=evidence_file.id,
                    event_type="INTAKE",
                    examiner=examiner,
                    description=f"File intake from: {source_path}",
                    hash_verified=True,
                    hash_at_event=hashes["sha256"],
                )
                session.add(custody_event)
                session.commit()

                # Refresh to get all data
                session.refresh(evidence_file)
                return evidence_file

        except Exception as e:
            self._cleanup(evidence_path)
            raise IntakeError(str(source_path), f"Failed to create database record: {e}")

    def _calculate_hashes(self, file_path: Path) -> dict:
        """Calculate SHA-256, SHA-1, and MD5 hashes of file."""
        sha256 = hashlib.sha256()
        sha1 = hashlib.sha1()
        md5 = hashlib.md5()

        chunk_size = 65536  # 64KB chunks

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                sha256.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)

        return {
            "sha256": sha256.hexdigest(),
            "sha1": sha1.hexdigest(),
            "md5": md5.hexdigest(),
        }

    def _copy_to_evidence(
        self, source: Path, case_id: str, evidence_number: str
    ) -> Path:
        """Copy file to evidence directory structure."""
        evidence_case_dir = self.evidence_dir / case_id / evidence_number
        evidence_case_dir.mkdir(parents=True, exist_ok=True)

        dest_path = evidence_case_dir / source.name

        if dest_path.exists():
            raise IntakeError(
                str(source),
                f"Evidence file already exists: {dest_path}"
            )

        shutil.copy2(source, dest_path)
        return dest_path

    def _set_read_only(self, file_path: Path) -> None:
        """Set file as read-only (Windows compatible)."""
        current_permissions = file_path.stat().st_mode
        read_only_permissions = current_permissions & ~(
            stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
        )
        os.chmod(file_path, read_only_permissions)

    def _verify_copy(self, original_hash: str, copy_path: Path) -> bool:
        """Verify copy matches original by comparing SHA-256 hashes."""
        copy_hashes = self._calculate_hashes(copy_path)
        return copy_hashes["sha256"] == original_hash

    def _cleanup(self, file_path: Path) -> None:
        """Clean up file on failure."""
        try:
            if file_path.exists():
                # Remove read-only if set
                current = file_path.stat().st_mode
                os.chmod(file_path, current | stat.S_IWUSR)
                file_path.unlink()
        except Exception:
            pass

    def close(self) -> None:
        """Close database connections and release resources.

        This is important on Windows where file handles must be
        explicitly closed to allow file deletion.
        """
        if hasattr(self, '_engine') and self._engine:
            self._engine.dispose()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close connections."""
        self.close()
        return False


def intake_file(
    source_path: Path,
    case_id: str,
    examiner: str,
    evidence_dir: Path,
    db_path: Path,
    evidence_number: Optional[str] = None,
    notes: Optional[str] = None,
) -> EvidenceFile:
    """Convenience function for file intake."""
    intake_handler = FileIntake(evidence_dir, db_path)
    return intake_handler.intake(
        source_path=source_path,
        case_id=case_id,
        examiner=examiner,
        evidence_number=evidence_number,
        notes=notes,
    )
