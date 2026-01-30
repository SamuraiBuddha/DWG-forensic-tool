"""Core analysis modules for DWG forensic analysis.

This package provides the main forensic analyzer that combines all parsing
and analysis components, along with chain of custody management.
"""

from dwg_forensic.core.analyzer import ForensicAnalyzer, analyze_file
from dwg_forensic.core.custody import CustodyChain, EventType, IntegrityError
from dwg_forensic.core.database import (
    Base,
    CaseInfo,
    CustodyEvent,
    EvidenceFile,
    get_engine,
    get_session,
    init_db,
)
from dwg_forensic.core.file_guard import FileGuard, ProtectedFileContext
from dwg_forensic.core.intake import FileIntake, intake_file
from dwg_forensic.core.batch_processor import (
    BatchProcessor,
    BatchAnalysisResult,
    BatchFileResult,
    process_batch,
)

__all__ = [
    # Analyzer
    "ForensicAnalyzer",
    "analyze_file",
    # Chain of Custody
    "CustodyChain",
    "EventType",
    "IntegrityError",
    # Database
    "Base",
    "CaseInfo",
    "CustodyEvent",
    "EvidenceFile",
    "get_engine",
    "get_session",
    "init_db",
    # File Guard
    "FileGuard",
    "ProtectedFileContext",
    # Intake
    "FileIntake",
    "intake_file",
    # Batch Processing
    "BatchProcessor",
    "BatchAnalysisResult",
    "BatchFileResult",
    "process_batch",
]
