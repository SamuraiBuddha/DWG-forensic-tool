"""
Database models for DWG forensic tool chain of custody.

This module provides SQLAlchemy 2.0+ models for tracking evidence files,
custody events, and case information to maintain a complete audit trail
for litigation support.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    String,
    Integer,
    DateTime,
    Boolean,
    Text,
    ForeignKey,
    create_engine,
    Engine,
    event,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    Session,
)


class Base(DeclarativeBase):
    """Base class for all database models."""
    pass


class CaseInfo(Base):
    """
    Case metadata and management information.

    This model tracks case-level information including case identification,
    assigned examiners, and case status. All evidence files are associated
    with a case.
    """
    __tablename__ = "case_info"

    # Primary identification (case number like "2025-CV-1234")
    id: Mapped[str] = mapped_column(String(50), primary_key=True)

    # Case details
    case_name: Mapped[str] = mapped_column(String(255), nullable=False)
    client: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    examiner_assigned: Mapped[str] = mapped_column(String(100), nullable=False)

    # Status tracking
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="ACTIVE",
        index=True,
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    # Optional notes
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    evidence_files: Mapped[list["EvidenceFile"]] = relationship(
        "EvidenceFile",
        back_populates="case",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<CaseInfo(id={self.id}, case_name={self.case_name}, "
            f"status={self.status}, examiner={self.examiner_assigned})>"
        )


class EvidenceFile(Base):
    """
    Represents an ingested DWG file with complete hash verification.

    This model tracks all metadata necessary for evidence integrity
    including multiple hash algorithms for maximum compatibility with
    various forensic systems.
    """
    __tablename__ = "evidence_files"

    # Primary identification
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    # File information
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)

    # Hash verification (multiple algorithms for maximum compatibility)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    sha1: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    md5: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    # Case association
    case_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("case_info.id"),
        nullable=False,
        index=True
    )
    evidence_number: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Timestamps
    intake_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    # Optional notes
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    custody_events: Mapped[list["CustodyEvent"]] = relationship(
        "CustodyEvent",
        back_populates="evidence",
        cascade="all, delete-orphan",
    )
    case: Mapped["CaseInfo"] = relationship("CaseInfo", back_populates="evidence_files")

    def __repr__(self) -> str:
        return (
            f"<EvidenceFile(id={self.id}, filename={self.filename}, "
            f"case_id={self.case_id}, sha256={self.sha256[:16]}...)>"
        )


class CustodyEvent(Base):
    """
    Audit trail entry for every action performed on evidence.

    This model provides a complete chain of custody by logging every
    access, analysis, export, or other action performed on evidence files.
    Each event includes hash verification to detect any tampering.
    """
    __tablename__ = "custody_events"

    # Primary identification
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    # Evidence reference
    evidence_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_files.id"),
        nullable=False,
        index=True
    )

    # Event details
    event_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True
    )

    # Who performed the action
    examiner: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Hash verification at event time
    hash_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    hash_at_event: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # System information
    workstation: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    # Optional notes
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    evidence: Mapped["EvidenceFile"] = relationship(
        "EvidenceFile",
        back_populates="custody_events"
    )

    def __repr__(self) -> str:
        return (
            f"<CustodyEvent(id={self.id}, event_type={self.event_type}, "
            f"examiner={self.examiner}, timestamp={self.timestamp})>"
        )


def get_engine(db_path: str) -> Engine:
    """
    Create a SQLAlchemy engine for the specified database path.

    Args:
        db_path: Path to the SQLite database file. Can be ":memory:" for
                 in-memory database or absolute path to file.

    Returns:
        Configured SQLAlchemy Engine instance.
    """
    connect_args = {"check_same_thread": False}

    if db_path == ":memory:":
        db_url = "sqlite:///:memory:"
    else:
        db_url = f"sqlite:///{db_path}"

    engine = create_engine(
        db_url,
        connect_args=connect_args,
        echo=False,
    )

    # Enable foreign key constraints for SQLite
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


def init_db(engine: Engine) -> None:
    """
    Initialize the database by creating all tables.

    This function creates all tables defined in the Base metadata.
    It is idempotent - calling it multiple times is safe.

    Args:
        engine: SQLAlchemy Engine instance.
    """
    Base.metadata.create_all(engine)


def get_session(engine: Engine) -> Session:
    """
    Create a new database session.

    Args:
        engine: SQLAlchemy Engine instance.

    Returns:
        SQLAlchemy Session instance.
    """
    return Session(engine)
