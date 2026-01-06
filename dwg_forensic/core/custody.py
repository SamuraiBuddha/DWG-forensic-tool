"""
Chain of Custody Tracker

Manages the complete chain of custody for evidence files in the DWG forensic tool.
Tracks all access, analysis, and transfer events with automatic integrity verification.
"""

import hashlib
import platform
import socket
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional
from uuid import UUID

from dwg_forensic.core.database import (
    CustodyEvent,
    EvidenceFile,
    get_engine,
    get_session,
    init_db,
)
from dwg_forensic.utils.exceptions import DWGForensicError


class IntegrityError(DWGForensicError):
    """Exception raised when evidence integrity verification fails."""

    def __init__(self, evidence_id: str, message: str):
        self.evidence_id = evidence_id
        super().__init__(f"Integrity error for evidence {evidence_id}: {message}")


class EventType(str, Enum):
    """Types of custody events."""
    INTAKE = "INTAKE"
    ACCESS = "ACCESS"
    ANALYSIS = "ANALYSIS"
    EXPORT = "EXPORT"
    TRANSFER = "TRANSFER"
    VERIFICATION = "VERIFICATION"
    RELEASE = "RELEASE"


class CustodyChain:
    """Manages chain of custody for evidence files."""

    def __init__(self, db_path: Path):
        """Initialize chain of custody manager."""
        self.db_path = Path(db_path)
        self._engine = get_engine(str(self.db_path))
        init_db(self._engine)

    def log_event(
        self,
        evidence_id: str,
        event_type: EventType,
        examiner: str,
        description: str,
        verify_hash: bool = True,
        notes: Optional[str] = None,
    ) -> CustodyEvent:
        """
        Log a custody event for an evidence file.

        Args:
            evidence_id: ID of the evidence file
            event_type: Type of custody event
            examiner: Name of the person performing the action
            description: Detailed description of the event
            verify_hash: Whether to verify file integrity
            notes: Optional additional notes

        Returns:
            CustodyEvent record

        Raises:
            IntegrityError: If hash verification fails
            ValueError: If evidence file not found
        """
        with get_session(self._engine) as session:
            evidence = session.get(EvidenceFile, evidence_id)
            if not evidence:
                raise ValueError(f"Evidence file not found: {evidence_id}")

            current_hash = None
            hash_verified = False

            if verify_hash:
                is_valid, message = self.verify_integrity(evidence_id)
                if not is_valid:
                    raise IntegrityError(evidence_id, message)
                hash_verified = True
                current_hash = self._calculate_current_hash(Path(evidence.file_path))

            workstation, ip_address = self._get_workstation_info()

            event = CustodyEvent(
                evidence_id=evidence_id,
                event_type=event_type.value,
                timestamp=datetime.now(timezone.utc),
                examiner=examiner,
                description=description,
                hash_verified=hash_verified,
                hash_at_event=current_hash,
                workstation=workstation,
                ip_address=ip_address,
                notes=notes,
            )

            session.add(event)
            session.commit()
            session.refresh(event)
            return event

    def get_chain(self, evidence_id: str) -> list[CustodyEvent]:
        """Get complete custody chain for an evidence file."""
        with get_session(self._engine) as session:
            evidence = session.get(EvidenceFile, evidence_id)
            if not evidence:
                return []
            return sorted(evidence.custody_events, key=lambda e: e.timestamp)

    def get_evidence(self, evidence_id: str) -> Optional[EvidenceFile]:
        """Get evidence file record by ID."""
        with get_session(self._engine) as session:
            return session.get(EvidenceFile, evidence_id)

    def get_evidence_by_hash(self, sha256: str) -> Optional[EvidenceFile]:
        """Get evidence file record by SHA-256 hash."""
        with get_session(self._engine) as session:
            from sqlalchemy import select
            stmt = select(EvidenceFile).where(EvidenceFile.sha256 == sha256)
            return session.scalar(stmt)

    def search_evidence(
        self,
        case_id: Optional[str] = None,
        filename: Optional[str] = None,
        examiner: Optional[str] = None,
    ) -> list[EvidenceFile]:
        """Search evidence files by criteria."""
        with get_session(self._engine) as session:
            from sqlalchemy import select
            stmt = select(EvidenceFile)

            if case_id:
                stmt = stmt.where(EvidenceFile.case_id.contains(case_id))
            if filename:
                stmt = stmt.where(EvidenceFile.filename.contains(filename))

            results = list(session.scalars(stmt))

            if examiner:
                # Filter by examiner from custody events
                filtered = []
                for ev in results:
                    events = session.query(CustodyEvent).filter(
                        CustodyEvent.evidence_id == ev.id,
                        CustodyEvent.examiner.contains(examiner)
                    ).first()
                    if events:
                        filtered.append(ev)
                return filtered

            return results

    def verify_integrity(self, evidence_id: str) -> tuple[bool, str]:
        """Verify evidence file integrity by comparing current hash to stored hash."""
        with get_session(self._engine) as session:
            evidence = session.get(EvidenceFile, evidence_id)
            if not evidence:
                return False, f"Evidence file not found: {evidence_id}"

            file_path = Path(evidence.file_path)
            if not file_path.exists():
                return False, f"Evidence file not found on disk: {evidence.file_path}"

            try:
                current_hash = self._calculate_current_hash(file_path)
            except Exception as e:
                return False, f"Error calculating hash: {str(e)}"

            if current_hash.lower() == evidence.sha256.lower():
                return True, "[OK] Hash verification successful"
            else:
                return False, (
                    f"[FAIL] Hash mismatch detected. "
                    f"Expected: {evidence.sha256}, Current: {current_hash}"
                )

    def generate_custody_report(self, evidence_id: str) -> dict:
        """Generate a complete custody report for an evidence file."""
        with get_session(self._engine) as session:
            evidence = session.get(EvidenceFile, evidence_id)
            if not evidence:
                raise ValueError(f"Evidence file not found: {evidence_id}")

            chain = sorted(evidence.custody_events, key=lambda e: e.timestamp)
            is_valid, message = self.verify_integrity(evidence_id)

            last_verified = None
            for event in reversed(chain):
                if event.event_type == EventType.VERIFICATION.value:
                    last_verified = event.timestamp
                    break

            return {
                "evidence": {
                    "id": evidence.id,
                    "filename": evidence.filename,
                    "file_path": evidence.file_path,
                    "case_id": evidence.case_id,
                    "evidence_number": evidence.evidence_number,
                    "sha256": evidence.sha256,
                    "sha1": evidence.sha1,
                    "md5": evidence.md5,
                    "file_size_bytes": evidence.file_size_bytes,
                    "intake_timestamp": evidence.intake_timestamp.isoformat(),
                    "notes": evidence.notes,
                },
                "chain": [
                    {
                        "id": event.id,
                        "event_type": event.event_type,
                        "timestamp": event.timestamp.isoformat(),
                        "examiner": event.examiner,
                        "description": event.description,
                        "hash_verified": event.hash_verified,
                        "hash_at_event": event.hash_at_event,
                        "workstation": event.workstation,
                        "ip_address": event.ip_address,
                        "notes": event.notes,
                    }
                    for event in chain
                ],
                "integrity_status": {
                    "is_valid": is_valid,
                    "message": message,
                    "verified_at": datetime.now(timezone.utc).isoformat(),
                },
                "total_events": len(chain),
                "last_verified": last_verified.isoformat() if last_verified else None,
            }

    def _get_workstation_info(self) -> tuple[str, str]:
        """Get current workstation name and IP address."""
        try:
            workstation = platform.node()
        except Exception:
            workstation = "unknown"

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                ip_address = s.getsockname()[0]
            finally:
                s.close()
        except Exception:
            try:
                ip_address = socket.gethostbyname(socket.gethostname())
            except Exception:
                ip_address = "unknown"

        return workstation, ip_address

    def _calculate_current_hash(self, file_path: Path) -> str:
        """Calculate current SHA-256 hash of evidence file."""
        sha256_hash = hashlib.sha256()
        chunk_size = 8192

        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256_hash.update(chunk)

        return sha256_hash.hexdigest()

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
