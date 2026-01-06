"""Forensic-grade audit logging for chain of custody.

This module provides comprehensive audit logging capabilities required for
digital forensic investigations. All operations are logged with timestamps,
system information, and chain of custody metadata.
"""

import csv
import json
import logging
import logging.handlers
import os
import platform
import socket
import threading
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


class AuditLevel(str, Enum):
    """Audit event severity levels for forensic logging."""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    SECURITY = "SECURITY"


class AuditLogger:
    """Forensic-grade audit logger for chain of custody."""

    def __init__(
        self,
        log_dir: Path,
        log_name: str = "dwg_forensic_audit",
        max_bytes: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 10,
    ):
        """Initialize audit logger with rotating file handlers."""
        self.log_dir = Path(log_dir)
        self.log_name = log_name
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self._lock = threading.Lock()

        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.json_logger = self._setup_json_logger()
        self.text_logger = self._setup_text_logger()

    def _setup_json_logger(self) -> logging.Logger:
        """Setup JSON logger with rotating file handler."""
        logger = logging.getLogger(f"{self.log_name}_json")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()

        json_path = self.log_dir / f"{self.log_name}.jsonl"
        handler = logging.handlers.RotatingFileHandler(
            json_path,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding="utf-8"
        )
        handler.setLevel(logging.INFO)
        logger.addHandler(handler)
        logger.propagate = False

        return logger

    def _setup_text_logger(self) -> logging.Logger:
        """Setup text logger with rotating file handler."""
        logger = logging.getLogger(f"{self.log_name}_text")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()

        text_path = self.log_dir / f"{self.log_name}.log"
        handler = logging.handlers.RotatingFileHandler(
            text_path,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding="utf-8"
        )
        handler.setLevel(logging.INFO)
        logger.addHandler(handler)
        logger.propagate = False

        return logger

    def _get_system_info(self) -> dict:
        """Get current system information for audit entry."""
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            hostname = "unknown"
            ip_address = "unknown"

        return {
            "workstation": hostname,
            "ip_address": ip_address,
            "user": os.environ.get("USERNAME") or os.environ.get("USER", "unknown"),
            "pid": os.getpid(),
            "platform": platform.system(),
        }

    def _format_json_entry(self, entry: dict) -> str:
        """Format audit entry as JSON line."""
        return json.dumps(entry, ensure_ascii=False, default=str)

    def _format_text_entry(self, entry: dict) -> str:
        """Format audit entry as human-readable text."""
        status = "[OK]" if entry.get("success", True) else "[FAIL]"

        parts = [
            entry["timestamp"],
            entry["level"],
            status,
            f"User: {entry['system_info']['user']}",
            f"Action: {entry['action']}",
        ]

        if entry.get("evidence_id"):
            parts.append(f"Evidence: {entry['evidence_id']}")
        if entry.get("case_id"):
            parts.append(f"Case: {entry['case_id']}")
        if entry.get("examiner"):
            parts.append(f"Examiner: {entry['examiner']}")

        return " | ".join(parts)

    def log(
        self,
        level: AuditLevel,
        action: str,
        details: dict = None,
        evidence_id: str = None,
        case_id: str = None,
        examiner: str = None,
        success: bool = True,
    ) -> None:
        """Log an audit event."""
        with self._lock:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": level.value,
                "action": action,
                "success": success,
                "system_info": self._get_system_info(),
            }

            if details:
                entry["details"] = details
            if evidence_id:
                entry["evidence_id"] = evidence_id
            if case_id:
                entry["case_id"] = case_id
            if examiner:
                entry["examiner"] = examiner

            self.json_logger.info(self._format_json_entry(entry))
            self.text_logger.info(self._format_text_entry(entry))

    def log_intake(
        self,
        evidence_id: str,
        case_id: str,
        examiner: str,
        filename: str,
        sha256: str
    ) -> None:
        """Log evidence intake event."""
        self.log(
            level=AuditLevel.INFO,
            action="EVIDENCE_INTAKE",
            details={"filename": filename, "sha256": sha256},
            evidence_id=evidence_id,
            case_id=case_id,
            examiner=examiner,
            success=True,
        )

    def log_access(self, evidence_id: str, examiner: str, purpose: str) -> None:
        """Log evidence access event."""
        self.log(
            level=AuditLevel.INFO,
            action="EVIDENCE_ACCESS",
            details={"purpose": purpose},
            evidence_id=evidence_id,
            examiner=examiner,
            success=True,
        )

    def log_analysis(
        self,
        evidence_id: str,
        examiner: str,
        analysis_type: str,
        findings: dict = None
    ) -> None:
        """Log analysis performed on evidence."""
        details = {"analysis_type": analysis_type}
        if findings:
            details["findings"] = findings

        self.log(
            level=AuditLevel.INFO,
            action="EVIDENCE_ANALYSIS",
            details=details,
            evidence_id=evidence_id,
            examiner=examiner,
            success=True,
        )

    def log_export(
        self,
        evidence_id: str,
        examiner: str,
        export_path: str,
        export_format: str
    ) -> None:
        """Log report or data export."""
        self.log(
            level=AuditLevel.INFO,
            action="DATA_EXPORT",
            details={"export_path": str(export_path), "export_format": export_format},
            evidence_id=evidence_id,
            examiner=examiner,
            success=True,
        )

    def log_verification(
        self,
        evidence_id: str,
        examiner: str,
        is_valid: bool,
        hash_computed: str
    ) -> None:
        """Log hash verification event."""
        level = AuditLevel.INFO if is_valid else AuditLevel.WARNING

        self.log(
            level=level,
            action="HASH_VERIFICATION",
            details={"is_valid": is_valid, "hash_computed": hash_computed},
            evidence_id=evidence_id,
            examiner=examiner,
            success=is_valid,
        )

    def log_error(self, action: str, error: Exception, evidence_id: str = None) -> None:
        """Log error event with exception details."""
        self.log(
            level=AuditLevel.ERROR,
            action=action,
            details={"error_type": type(error).__name__, "error_message": str(error)},
            evidence_id=evidence_id,
            success=False,
        )

    def log_security(self, action: str, details: str, evidence_id: str = None) -> None:
        """Log security-relevant event."""
        self.log(
            level=AuditLevel.SECURITY,
            action=action,
            details={"security_details": details},
            evidence_id=evidence_id,
            success=False,
        )

    def get_audit_trail(
        self,
        evidence_id: str = None,
        case_id: str = None,
        start_date: datetime = None,
        end_date: datetime = None,
        level: AuditLevel = None,
    ) -> list[dict]:
        """Query audit trail from JSON log file."""
        json_path = self.log_dir / f"{self.log_name}.jsonl"

        if not json_path.exists():
            return []

        entries = []

        with open(json_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line)

                    if evidence_id and entry.get("evidence_id") != evidence_id:
                        continue
                    if case_id and entry.get("case_id") != case_id:
                        continue
                    if level and entry.get("level") != level.value:
                        continue

                    entry_time = datetime.fromisoformat(entry["timestamp"])
                    if start_date and entry_time < start_date:
                        continue
                    if end_date and entry_time > end_date:
                        continue

                    entries.append(entry)

                except json.JSONDecodeError:
                    continue

        return entries

    def export_audit_trail(
        self,
        output_path: Path,
        evidence_id: str = None,
        case_id: str = None,
        format: str = "json",
    ) -> None:
        """Export filtered audit trail to file."""
        entries = self.get_audit_trail(evidence_id=evidence_id, case_id=case_id)

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(entries, f, indent=2, ensure_ascii=False, default=str)

        elif format == "csv":
            if not entries:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write("")
                return

            flat_entries = []
            for entry in entries:
                flat = {
                    "timestamp": entry["timestamp"],
                    "level": entry["level"],
                    "action": entry["action"],
                    "success": entry["success"],
                    "workstation": entry["system_info"]["workstation"],
                    "user": entry["system_info"]["user"],
                    "evidence_id": entry.get("evidence_id", ""),
                    "case_id": entry.get("case_id", ""),
                    "examiner": entry.get("examiner", ""),
                    "details": json.dumps(entry.get("details", {})),
                }
                flat_entries.append(flat)

            with open(output_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=flat_entries[0].keys())
                writer.writeheader()
                writer.writerows(flat_entries)

        elif format == "txt":
            with open(output_path, "w", encoding="utf-8") as f:
                for entry in entries:
                    f.write(self._format_text_entry(entry))
                    f.write("\n\n")

        else:
            raise ValueError(f"Unsupported format: {format}. Use json, csv, or txt.")


_global_audit_logger: Optional[AuditLogger] = None
_logger_lock = threading.Lock()


def get_audit_logger(log_dir: Path = None) -> AuditLogger:
    """Get or create the global audit logger instance."""
    global _global_audit_logger

    with _logger_lock:
        if _global_audit_logger is None:
            if log_dir is None:
                log_dir = Path.cwd() / "logs"

            _global_audit_logger = AuditLogger(log_dir)

        return _global_audit_logger
