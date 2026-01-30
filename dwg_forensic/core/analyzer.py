"""Main forensic analyzer for DWG files.

This module provides the primary analysis workflow, combining header parsing,
CRC validation, anomaly detection, tampering rules, and risk assessment.

Phase 3 Integration:
- AnomalyDetector: Timestamp, version, and structural anomaly detection
- TamperingRuleEngine: 12 built-in rules + custom YAML/JSON rules
- RiskScorer: Weighted risk scoring algorithm
"""

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from dwg_forensic import __version__
from dwg_forensic.models import (
    Anomaly,
    AnomalyType,
    ApplicationFingerprint,
    CRCValidation,
    FileInfo,
    ForensicAnalysis,
    HeaderAnalysis,
    NTFSTimestampAnalysis,
    RiskAssessment,
    RiskLevel,
    TamperingIndicator,
    TamperingIndicatorType,
    DWGMetadata,
)
from dwg_forensic.parsers import (
    CRCValidator,
    HeaderParser,
    TimestampParser,
    TimestampData,
    NTFSTimestampParser,
    NTFSForensicData,
    # Deep parsing modules for AC1018+ support
    SectionType,
    SectionMapParser,
    SectionMapResult,
    DrawingVariablesParser,
    DrawingVariablesResult,
    HandleMapParser,
    HandleMapResult,
)
from dwg_forensic.analysis.cad_fingerprinting import (
    CADFingerprinter,
    FingerprintResult,
    CADApplication,
)
from dwg_forensic.parsers.revit_detection import RevitDetector, RevitDetectionResult
from dwg_forensic.parsers.structure_analysis import (
    DWGStructureAnalyzer,
    StructureAnalysisResult,
    DWGStructureType,
)
from dwg_forensic.utils.exceptions import DWGForensicError

# Phase 3 imports
from dwg_forensic.analysis import (
    AnomalyDetector,
    TamperingRuleEngine,
    RiskScorer,
    TamperingReport,
)
from dwg_forensic.analysis.provenance_detector import ProvenanceDetector
from dwg_forensic.analysis.version_dates import get_version_release_date
from dwg_forensic.knowledge import KnowledgeEnricher, Neo4jKnowledgeClient

# LLM integration (optional - gracefully degrades if unavailable)
try:
    from dwg_forensic.llm import ForensicNarrator, ForensicReasoner, LLMModeManager, LLMMode
    # Phase 4.2: Import anomaly filtering models
    from dwg_forensic.llm.anomaly_models import (
        Anomaly as LLMAnomaly,
        ProvenanceInfo,
        FilteredAnomalies,
    )
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    ForensicNarrator = None  # type: ignore
    ForensicReasoner = None  # type: ignore
    LLMModeManager = None  # type: ignore
    LLMMode = None  # type: ignore
    LLMAnomaly = None  # type: ignore
    ProvenanceInfo = None  # type: ignore
    FilteredAnomalies = None  # type: ignore

# Smoking gun synthesis for definitive proof filtering
try:
    from dwg_forensic.analysis import SmokingGunSynthesizer
    SMOKING_GUN_AVAILABLE = True
except ImportError:
    SMOKING_GUN_AVAILABLE = False
    SmokingGunSynthesizer = None  # type: ignore


class ForensicAnalyzer:
    """Main forensic analyzer for DWG files.

    Combines all parsing and analysis components to produce a complete
    forensic analysis report including Phase 3 tampering detection.
    """

    def __init__(
        self,
        custom_rules_path: Optional[Path] = None,
        progress_callback: Optional[callable] = None,
        neo4j_uri: Optional[str] = None,
        neo4j_user: Optional[str] = None,
        neo4j_password: Optional[str] = None,
        enable_knowledge_enrichment: bool = True,
        use_llm: bool = False,
        llm_model: Optional[str] = None,
        expert_name: str = "Digital Forensics Expert",
        llm_mode: Optional["LLMMode"] = None,
    ):
        """Initialize the forensic analyzer with all required parsers.

        Args:
            custom_rules_path: Optional path to custom tampering rules YAML/JSON file
            progress_callback: Optional callback for progress updates.
                Signature: callback(step: str, status: str, message: str)
                step: Current analysis step name
                status: "start", "complete", "skip", "error"
                message: Human-readable description
            neo4j_uri: Optional Neo4j connection URI (defaults to NEO4J_URI env var)
            neo4j_user: Optional Neo4j username (defaults to NEO4J_USER env var)
            neo4j_password: Optional Neo4j password (defaults to NEO4J_PASSWORD env var)
            enable_knowledge_enrichment: Whether to enrich analysis with forensic knowledge
            use_llm: Whether to use LLM for expert narrative generation (legacy param)
            llm_model: Optional Ollama model name (e.g., 'mistral', 'llama3')
            expert_name: Name of the expert witness for LLM narrative
            llm_mode: LLM operating mode (AUTO/FORCE/OFF). Overrides use_llm if specified.
        """
        # Progress callback for terminal display
        self._progress_callback = progress_callback

        # Forensic error tracking - ALL errors are potential evidence in forensic analysis
        self._analysis_errors: List[Dict[str, Any]] = []

        # Phase 4.1: LLM mode manager (AUTO/FORCE/OFF with graceful fallback)
        self.llm_mode_manager: Optional["LLMModeManager"] = None
        if LLMModeManager:
            # Determine mode from parameters
            if llm_mode is not None:
                # Explicit mode specified
                mode = llm_mode
            elif use_llm:
                # Legacy use_llm=True maps to FORCE mode
                mode = LLMMode.FORCE if LLMMode else None
            else:
                # Default to AUTO mode (detect Ollama availability)
                mode = LLMMode.AUTO if LLMMode else None

            if mode is not None:
                self.llm_mode_manager = LLMModeManager(mode=mode)

        # Property for checking if LLM is enabled
        self._llm_enabled_cached: Optional[bool] = None

        # Phase 1 parsers
        self.header_parser = HeaderParser()
        self.crc_validator = CRCValidator()

        # Timestamp parser for advanced forensic analysis
        self.timestamp_parser = TimestampParser()

        # NTFS timestamp parser for cross-validation forensics
        self.ntfs_parser = NTFSTimestampParser()

        # Deep parsing modules for AC1018+ support
        self.section_parser = SectionMapParser()
        self.drawing_vars_parser = DrawingVariablesParser()
        self.handle_parser = HandleMapParser()

        # CAD application fingerprinting (identifies authoring software)
        self.fingerprinter = CADFingerprinter()

        # Revit detection for export-specific behavior identification
        self.revit_detector = RevitDetector()

        # DWG structure analyzer for non-standard file detection
        self.structure_analyzer = DWGStructureAnalyzer()

        # Phase 3 analyzers
        self.anomaly_detector = AnomalyDetector()
        self.rule_engine = TamperingRuleEngine()
        self.risk_scorer = RiskScorer()

        # Knowledge graph enrichment
        self._enable_knowledge_enrichment = enable_knowledge_enrichment
        self._knowledge_client: Optional[Neo4jKnowledgeClient] = None
        self._knowledge_enricher: Optional[KnowledgeEnricher] = None

        if enable_knowledge_enrichment:
            # Initialize Neo4j client (will connect on first use)
            if neo4j_uri or neo4j_user or neo4j_password:
                self._knowledge_client = Neo4jKnowledgeClient(
                    uri=neo4j_uri,
                    user=neo4j_user,
                    password=neo4j_password,
                )
            else:
                # Try to connect with environment variables
                self._knowledge_client = Neo4jKnowledgeClient()

            # Initialize enricher with fallback support
            self._knowledge_enricher = KnowledgeEnricher(
                neo4j_client=self._knowledge_client,
                use_fallback=True,  # Always use fallback when Neo4j unavailable
            )

        # LLM narrator for expert narrative generation
        self._use_llm = use_llm and LLM_AVAILABLE
        self._llm_model = llm_model
        self._expert_name = expert_name
        self._narrator: Optional["ForensicNarrator"] = None
        self._reasoner: Optional["ForensicReasoner"] = None
        self._smoking_gun_synthesizer: Optional["SmokingGunSynthesizer"] = None

        if self._use_llm and ForensicNarrator:
            try:
                self._narrator = ForensicNarrator(
                    model=llm_model,
                    enabled=True,
                    expert_name=expert_name,
                )
                if not self._narrator.is_available():
                    self._narrator = None
                    self._use_llm = False
            except Exception as e:
                import traceback
                self._analysis_errors.append({
                    "operation": "forensic_narrator_init",
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "traceback": traceback.format_exc(),
                    "timestamp": datetime.now().isoformat(),
                })
                self._narrator = None
                self._use_llm = False

        # LLM forensic reasoner - uses LLM to REASON about evidence, not just generate narratives
        if self._use_llm and ForensicReasoner:
            try:
                self._reasoner = ForensicReasoner(
                    llm_model=llm_model or "mistral",
                    ollama_host="http://localhost:11434",
                )
            except Exception as e:
                import traceback
                self._analysis_errors.append({
                    "operation": "forensic_reasoner_init",
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "traceback": traceback.format_exc(),
                    "timestamp": datetime.now().isoformat(),
                })
                self._reasoner = None

        # Smoking gun synthesizer - filters to ONLY definitive proof
        if SMOKING_GUN_AVAILABLE and SmokingGunSynthesizer:
            self._smoking_gun_synthesizer = SmokingGunSynthesizer()

        # Load custom rules if provided
        if custom_rules_path:
            self.rule_engine.load_rules(custom_rules_path)

    @property
    def llm_enabled(self) -> bool:
        """
        Check if LLM reasoning is enabled.

        Returns True if mode manager is initialized and LLM is enabled,
        False otherwise (graceful fallback).

        Returns:
            True if LLM should be used, False otherwise
        """
        if self._llm_enabled_cached is None:
            if self.llm_mode_manager:
                self._llm_enabled_cached = self.llm_mode_manager.is_enabled()
            else:
                self._llm_enabled_cached = False
        return self._llm_enabled_cached

    def _report_progress(self, step: str, status: str, message: str) -> None:
        """Report progress to callback if registered.

        Args:
            step: Current analysis step name
            status: "start", "complete", "skip", "error"
            message: Human-readable description
        """
        if self._progress_callback:
            try:
                self._progress_callback(step, status, message)
            except Exception as e:
                # Record callback failure but don't halt analysis
                # In forensic software, even callback failures are logged
                self._analysis_errors.append({
                    "operation": "progress_callback",
                    "step": step,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                })

    def analyze(self, file_path: Path) -> ForensicAnalysis:
        """Perform complete forensic analysis on a DWG file.

        Includes Phase 3 tampering detection:
        - Anomaly detection (timestamp, version, structural)
        - Tampering rule evaluation (40 built-in + custom rules)
        - Risk scoring with weighted algorithm
        - Deep DWG parsing (section map, drawing variables, handle gaps)

        Args:
            file_path: Path to the DWG file to analyze

        Returns:
            ForensicAnalysis model containing complete analysis results

        Raises:
            DWGForensicError: If analysis fails
        """
        file_path = Path(file_path)

        # Phase 1: Basic file analysis
        self._report_progress("file_info", "start", "Collecting file information")
        file_info = self._collect_file_info(file_path)
        self._report_progress("file_info", "complete", f"SHA-256: {file_info.sha256[:16]}...")

        # Parse header first to get version
        self._report_progress("header", "start", "Parsing DWG header")
        header_analysis = self.header_parser.parse(file_path)
        version_string = header_analysis.version_string
        self._report_progress("header", "complete", f"Version: {version_string} ({header_analysis.version_name})")

        # Validate CRC (version-aware)
        self._report_progress("crc", "start", "Validating CRC32 checksum")
        crc_validation = self.crc_validator.validate_header_crc(
            file_path, version_string=version_string
        )
        crc_status = "valid" if crc_validation.is_valid else "MISMATCH"
        self._report_progress("crc", "complete", f"CRC: {crc_status}")

        # CAD Application Fingerprinting - informational only
        # Note: Application origin does NOT indicate tampering
        self._report_progress("fingerprint", "start", "Identifying CAD application")
        fingerprint_result: Optional[FingerprintResult] = None
        try:
            fingerprint_result = self.fingerprinter.fingerprint(
                file_path=file_path,
                header_crc=crc_validation.header_crc_stored,
            )
            app_name = fingerprint_result.detected_application.value
            confidence = f"{fingerprint_result.confidence:.0%}"
            self._report_progress(
                "fingerprint", "complete",
                f"{app_name.upper()} (confidence: {confidence})"
            )
        except Exception as e:
            import traceback
            self._analysis_errors.append({
                "operation": "fingerprinting",
                "error_type": type(e).__name__,
                "error_message": str(e),
                "traceback": traceback.format_exc(),
                "timestamp": datetime.now().isoformat(),
            })
            self._report_progress("fingerprint", "error", f"Fingerprinting failed: {e}")

        # Revit Export Detection - critical for interpreting CRC and timestamp behavior
        self._report_progress("revit", "start", "Detecting Revit export characteristics")
        revit_detection: Optional[RevitDetectionResult] = None
        try:
            revit_detection = self.revit_detector.detect(file_path)
            if revit_detection.is_revit_export:
                version_info = f" ({revit_detection.revit_version})" if revit_detection.revit_version else ""
                self._report_progress(
                    "revit", "complete",
                    f"Revit export detected{version_info} - confidence {revit_detection.confidence_score:.0%}"
                )
            else:
                self._report_progress("revit", "complete", "Not a Revit export")
        except Exception as e:
            import traceback
            self._analysis_errors.append({
                "operation": "revit_detection",
                "error_type": type(e).__name__,
                "error_message": str(e),
                "traceback": traceback.format_exc(),
                "timestamp": datetime.now().isoformat(),
            })
            self._report_progress("revit", "error", f"Revit detection failed: {e}")

        # DWG Structure Analysis - detect non-standard or stripped DWG files
        self._report_progress("structure", "start", "Analyzing DWG internal structure")
        structure_analysis: Optional[StructureAnalysisResult] = None
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            structure_analysis = self.structure_analyzer.analyze(file_data, version_string)

            if structure_analysis.structure_type == DWGStructureType.STANDARD:
                self._report_progress("structure", "complete", "Standard DWG structure")
            elif structure_analysis.structure_type == DWGStructureType.NON_AUTOCAD:
                tool = structure_analysis.detected_tool or "unknown tool"
                self._report_progress(
                    "structure", "complete",
                    f"NON-STANDARD: Created by {tool} - missing AcDb sections"
                )
            elif structure_analysis.structure_type == DWGStructureType.STRIPPED:
                self._report_progress(
                    "structure", "complete",
                    "STRIPPED: Standard DWG sections missing - possible metadata removal"
                )
            else:
                self._report_progress(
                    "structure", "complete",
                    f"Structure type: {structure_analysis.structure_type.value}"
                )
        except Exception as e:
            import traceback
            self._analysis_errors.append({
                "operation": "structure_analysis",
                "error_type": type(e).__name__,
                "error_message": str(e),
                "traceback": traceback.format_exc(),
                "timestamp": datetime.now().isoformat(),
            })
            self._report_progress("structure", "error", f"Structure analysis failed: {e}")

        # Parse timestamps for advanced forensic analysis
        self._report_progress("timestamps", "start", "Extracting embedded timestamps")
        timestamp_data = self.timestamp_parser.parse(file_path, version_string)
        self._report_progress("timestamps", "complete", "Timestamps extracted")

        # Build metadata from timestamp data
        metadata = self._build_metadata_from_timestamps(timestamp_data)

        # Parse NTFS filesystem timestamps for cross-validation forensics
        self._report_progress("ntfs", "start", "Parsing NTFS filesystem timestamps")
        ntfs_data = self.ntfs_parser.parse(file_path)
        ntfs_status = "SI/FN mismatch detected" if ntfs_data and ntfs_data.si_fn_mismatch else "normal"
        self._report_progress("ntfs", "complete", f"NTFS: {ntfs_status}")

        # Cross-validate DWG timestamps against NTFS filesystem timestamps
        ntfs_contradictions = self._cross_validate_ntfs_timestamps(
            timestamp_data, ntfs_data, metadata
        )

        # Deep DWG Parsing: Section Map Analysis
        self._report_progress("sections", "start", "Parsing DWG section map (deep analysis)")
        section_map: Optional[SectionMapResult] = None
        try:
            section_map = self.section_parser.parse(file_path)
            section_count = section_map.section_count if section_map else 0
            if section_map and section_map.parsing_errors:
                self._report_progress("sections", "error", section_map.parsing_errors[0])
            else:
                self._report_progress("sections", "complete", f"Sections found: {section_count}")
        except Exception as e:
            import traceback
            self._analysis_errors.append({
                "operation": "section_parsing",
                "error_type": type(e).__name__,
                "error_message": str(e),
                "traceback": traceback.format_exc(),
                "timestamp": datetime.now().isoformat(),
            })
            self._report_progress("sections", "error", f"Section parsing failed: {e}")

        # Deep DWG Parsing: Drawing Variables Extraction
        self._report_progress("drawing_vars", "start", "Extracting drawing variables (TDCREATE/TDUPDATE)")
        drawing_vars: Optional[DrawingVariablesResult] = None
        try:
            drawing_vars = self.drawing_vars_parser.parse(file_path, section_map=section_map)

            # If structure analysis detected non-standard DWG and no timestamps found,
            # try raw header extraction as a fallback
            if (structure_analysis and
                structure_analysis.structure_type in [
                    DWGStructureType.NON_AUTOCAD,
                    DWGStructureType.STRIPPED,
                    DWGStructureType.UNKNOWN
                ] and
                not drawing_vars.has_timestamps()):

                self._report_progress(
                    "drawing_vars", "start",
                    "Standard extraction failed, trying raw header scan"
                )
                # Use raw header scan for non-standard files
                drawing_vars = self.drawing_vars_parser.extract_from_raw_header(
                    file_data, drawing_vars
                )

            ts_count = sum([
                1 if drawing_vars.tdcreate else 0,
                1 if drawing_vars.tdupdate else 0,
            ])
            if ts_count > 0:
                self._report_progress("drawing_vars", "complete", f"Timestamps found: {ts_count}")
            else:
                method = "section"
                if drawing_vars.diagnostics:
                    method = drawing_vars.diagnostics.timestamp_extraction_method
                self._report_progress(
                    "drawing_vars", "complete",
                    f"No timestamps found (method: {method})"
                )
        except Exception as e:
            import traceback
            self._analysis_errors.append({
                "operation": "drawing_vars_extraction",
                "error_type": type(e).__name__,
                "error_message": str(e),
                "traceback": traceback.format_exc(),
                "timestamp": datetime.now().isoformat(),
            })
            self._report_progress("drawing_vars", "error", f"Drawing vars extraction failed: {e}")

        # Deep DWG Parsing: Handle Gap Analysis
        self._report_progress("handles", "start", "Analyzing handle map for deleted objects")
        handle_map: Optional[HandleMapResult] = None
        try:
            handle_map = self.handle_parser.parse(file_path, section_map=section_map)
            gap_count = len(handle_map.gaps) if handle_map.gaps else 0
            critical_gaps = sum(1 for g in (handle_map.gaps or []) if g.severity == "critical")
            if critical_gaps > 0:
                self._report_progress("handles", "complete", f"Gaps: {gap_count} ({critical_gaps} critical)")
            else:
                self._report_progress("handles", "complete", f"Handle gaps: {gap_count}")
        except Exception as e:
            import traceback
            self._analysis_errors.append({
                "operation": "handle_analysis",
                "error_type": type(e).__name__,
                "error_message": str(e),
                "traceback": traceback.format_exc(),
                "timestamp": datetime.now().isoformat(),
            })
            self._report_progress("handles", "error", f"Handle analysis failed: {e}")

        # Phase 2.5: File Provenance Detection (BEFORE anomaly detection to prevent false positives)
        self._report_progress("provenance", "start", "Detecting file provenance")
        file_provenance = None
        file_provenance_dict = None
        try:
            provenance_detector = ProvenanceDetector()
            file_provenance = provenance_detector.detect(file_path)

            # Convert to dict for ForensicAnalysis output
            file_provenance_dict = {
                "source_application": file_provenance.source_application,
                "is_export": file_provenance.is_export,
                "is_transferred": file_provenance.is_transferred,
                "confidence": file_provenance.confidence,
                "rules_to_skip": file_provenance.rules_to_skip,
                "detection_notes": file_provenance.detection_notes,
                "is_revit_export": file_provenance.is_revit_export,
                "is_oda_tool": file_provenance.is_oda_tool,
                "is_native_autocad": file_provenance.is_native_autocad,
                "revit_confidence": file_provenance.revit_confidence,
                "fingerprint_confidence": file_provenance.fingerprint_confidence,
                "transfer_indicators": file_provenance.transfer_indicators,
            }

            self._report_progress(
                "provenance",
                "complete",
                f"Provenance: {file_provenance.source_application} (confidence: {file_provenance.confidence:.2f})"
            )
        except Exception as e:
            error_msg = f"Provenance detection failed: {str(e)}"
            self._analysis_errors.append({
                "phase": "provenance_detection",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
            self._report_progress("provenance", "error", error_msg)

        # Phase 3: Anomaly detection (provenance-aware, including advanced timestamp anomalies)
        self._report_progress("anomalies", "start", "Detecting anomalies")
        anomalies = self._detect_all_anomalies(
            header_analysis, crc_validation, file_path,
            timestamp_data=timestamp_data, metadata=metadata,
            ntfs_data=ntfs_data, ntfs_contradictions=ntfs_contradictions,
            file_provenance=file_provenance
        )
        self._report_progress("anomalies", "complete", f"Anomalies detected: {len(anomalies)}")

        # Phase 3: Tampering rule evaluation (with NTFS cross-validation data + deep parsing)
        self._report_progress("rules", "start", "Evaluating tampering rules")
        rule_context = self._build_rule_context(
            header_analysis, crc_validation, file_path,
            timestamp_data=timestamp_data, anomalies=anomalies, metadata=metadata,
            ntfs_data=ntfs_data, ntfs_contradictions=ntfs_contradictions,
            section_map=section_map, drawing_vars=drawing_vars, handle_map=handle_map,
            fingerprint=fingerprint_result, structure_analysis=structure_analysis,
        )

        # Pass skip_rules from provenance to prevent false positives
        skip_rules = file_provenance.rules_to_skip if file_provenance else []
        rule_results = self.rule_engine.evaluate_all(rule_context, skip_rules=skip_rules)
        failed_rules = self.rule_engine.get_failed_rules(rule_results)
        self._report_progress("rules", "complete", f"Rules triggered: {len(failed_rules)}")

        # Phase 4.2: LLM/Heuristic anomaly filtering
        import logging
        logger = logging.getLogger(__name__)

        filtered_anomalies_result: Optional[Any] = None
        anomaly_filter_method = "none"

        if self.llm_enabled and self._reasoner and LLM_AVAILABLE and failed_rules:
            self._report_progress("filtering", "start", "Filtering anomalies with LLM reasoner")
            try:
                # Convert failed rules to LLM Anomaly objects
                llm_anomalies = []
                for rule in failed_rules:
                    llm_anomalies.append(LLMAnomaly.from_rule_result({
                        "rule_id": rule.rule_id,
                        "description": rule.description,
                        "severity": rule.severity.value if hasattr(rule.severity, 'value') else str(rule.severity),
                        "evidence_strength": getattr(rule, 'evidence_strength', 'CIRCUMSTANTIAL'),
                        "details": {
                            "expected": getattr(rule, 'expected', None),
                            "found": getattr(rule, 'found', None),
                        },
                    }))

                # Build provenance info
                if file_provenance and ProvenanceInfo:
                    provenance_info = ProvenanceInfo.from_provenance_result({
                        "source_application": file_provenance.source_application,
                        "version": getattr(file_provenance, 'version', None),
                        "confidence": file_provenance.confidence,
                        "is_revit_export": file_provenance.is_revit_export,
                        "is_oda_tool": file_provenance.is_oda_tool,
                        "is_transferred": file_provenance.is_transferred,
                        "is_native_autocad": file_provenance.is_native_autocad,
                        "rules_to_skip": file_provenance.rules_to_skip,
                        "detection_notes": file_provenance.detection_notes,
                    })
                else:
                    # Default provenance if detector not available
                    provenance_info = ProvenanceInfo(
                        cad_app="Unknown",
                        provenance_path="Unknown Origin",
                        confidence=0.0,
                    )

                # Run async filtering in sync context
                import asyncio
                loop = asyncio.new_event_loop()
                try:
                    filtered_result = loop.run_until_complete(
                        self._reasoner.filter_anomalies(
                            anomalies=llm_anomalies,
                            provenance=provenance_info,
                            dwg_version=version_string,
                            batch_mode=False,
                        )
                    )
                finally:
                    loop.close()

                # Replace failed_rules with kept anomalies
                kept_rule_ids = {a.rule_id for a in filtered_result.kept_anomalies}
                original_count = len(failed_rules)
                failed_rules = [r for r in failed_rules if r.rule_id in kept_rule_ids]
                filtered_count = original_count - len(failed_rules)

                filtered_anomalies_result = filtered_result.to_dict()
                anomaly_filter_method = filtered_result.method

                logger.info(
                    f"LLM filtered {filtered_count} of {original_count} anomalies "
                    f"(method: {filtered_result.method}, confidence: {filtered_result.llm_confidence:.1%})"
                )

                if filtered_result.low_confidence_warning:
                    logger.warning(
                        f"Low confidence ({filtered_result.llm_confidence:.1%}) in filtering - manual review recommended"
                    )

                self._report_progress("filtering", "complete", f"Filtered {filtered_count} anomalies")

            except Exception as e:
                logger.error(f"LLM anomaly filtering failed: {e}, keeping all anomalies")
                anomaly_filter_method = "error"
        elif failed_rules and file_provenance:
            # Fallback: Use heuristic filter without LLM
            self._report_progress("filtering", "start", "Filtering anomalies with heuristic rules")
            try:
                from dwg_forensic.llm.heuristic_filter import HeuristicAnomalyFilter
                from dwg_forensic.llm.anomaly_models import Anomaly as LLMAnomaly, ProvenanceInfo

                heuristic_filter = HeuristicAnomalyFilter()

                # Convert failed rules to LLM Anomaly objects
                llm_anomalies = []
                for rule in failed_rules:
                    llm_anomalies.append(LLMAnomaly.from_rule_result({
                        "rule_id": rule.rule_id,
                        "description": rule.description,
                        "severity": rule.severity.value if hasattr(rule.severity, 'value') else str(rule.severity),
                        "evidence_strength": getattr(rule, 'evidence_strength', 'CIRCUMSTANTIAL'),
                        "details": {
                            "expected": getattr(rule, 'expected', None),
                            "found": getattr(rule, 'found', None),
                        },
                    }))

                # Build provenance info
                provenance_info = ProvenanceInfo.from_provenance_result({
                    "source_application": file_provenance.source_application,
                    "version": getattr(file_provenance, 'version', None),
                    "confidence": file_provenance.confidence,
                    "is_revit_export": file_provenance.is_revit_export,
                    "is_oda_tool": file_provenance.is_oda_tool,
                    "is_transferred": file_provenance.is_transferred,
                    "is_native_autocad": file_provenance.is_native_autocad,
                    "rules_to_skip": file_provenance.rules_to_skip,
                    "detection_notes": file_provenance.detection_notes,
                })

                # Apply heuristic filtering
                filtered_result = heuristic_filter.filter_anomalies(llm_anomalies, provenance_info)

                # Replace failed_rules with kept anomalies
                kept_rule_ids = {a.rule_id for a in filtered_result.kept_anomalies}
                original_count = len(failed_rules)
                failed_rules = [r for r in failed_rules if r.rule_id in kept_rule_ids]
                filtered_count = original_count - len(failed_rules)

                filtered_anomalies_result = filtered_result.to_dict()
                anomaly_filter_method = filtered_result.method

                logger.info(
                    f"Heuristic filtered {filtered_count} of {original_count} anomalies "
                    f"(confidence: {filtered_result.llm_confidence:.1%})"
                )

                self._report_progress("filtering", "complete", f"Filtered {filtered_count} anomalies")

            except Exception as e:
                logger.error(f"Heuristic anomaly filtering failed: {e}, keeping all anomalies")
                anomaly_filter_method = "error"
        else:
            logger.info("Anomaly filtering disabled or no anomalies to filter")

        # Phase 3: Detect tampering indicators (version-aware, with NTFS cross-validation)
        self._report_progress("tampering", "start", "Analyzing tampering indicators")
        tampering_indicators = self._detect_tampering(
            crc_validation, failed_rules, version_string,
            timestamp_data=timestamp_data, ntfs_data=ntfs_data,
            ntfs_contradictions=ntfs_contradictions,
            structure_analysis=structure_analysis,
        )
        self._report_progress("tampering", "complete", f"Indicators: {len(tampering_indicators)}")

        # Build NTFS analysis model for output
        ntfs_analysis = self._build_ntfs_analysis(ntfs_data, ntfs_contradictions, metadata)

        # Phase 3: Risk assessment with scoring
        self._report_progress("risk", "start", "Calculating risk score")
        risk_assessment = self._assess_risk_phase3(
            anomalies, tampering_indicators, failed_rules, crc_validation
        )
        self._report_progress("risk", "complete", f"Risk level: {risk_assessment.overall_risk.value}")

        # Build application fingerprint model from result
        app_fingerprint: Optional[ApplicationFingerprint] = None
        if fingerprint_result:
            app_fingerprint = ApplicationFingerprint(
                detected_application=fingerprint_result.detected_application.value,
                confidence=fingerprint_result.confidence,
                is_autodesk=fingerprint_result.is_autodesk,
                is_oda_based=fingerprint_result.is_oda_based,
                forensic_summary=fingerprint_result.forensic_summary,
                created_by=fingerprint_result.detected_application.value,
            )

        # Knowledge enrichment: retrieve forensic standards, legal citations, techniques
        forensic_knowledge_dict: Optional[Dict[str, Any]] = None
        if self._enable_knowledge_enrichment and self._knowledge_enricher:
            self._report_progress("knowledge", "start", "Enriching with forensic knowledge")
            try:
                # Get failed rule IDs for knowledge enrichment
                failed_rule_ids = [r.rule_id for r in failed_rules]
                knowledge = self._knowledge_enricher.enrich_analysis(
                    failed_rule_ids=failed_rule_ids,
                    include_admissibility=True,
                )
                # Convert to dict for JSON serialization
                forensic_knowledge_dict = knowledge.model_dump()
                source = "Neo4j" if (self._knowledge_client and self._knowledge_client.is_connected) else "fallback"
                self._report_progress("knowledge", "complete", f"Knowledge enriched ({source})")
            except Exception as e:
                import traceback
                self._analysis_errors.append({
                    "operation": "knowledge_enrichment",
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "traceback": traceback.format_exc(),
                    "timestamp": datetime.now().isoformat(),
                })
                self._report_progress("knowledge", "error", f"Knowledge enrichment failed: {str(e)}")

        # SMOKING GUN SYNTHESIS: Filter to ONLY definitive proof
        # Only mathematically impossible conditions should be reported as proof
        smoking_gun_report_dict: Optional[Dict[str, Any]] = None
        has_definitive_proof = False

        if self._smoking_gun_synthesizer:
            self._report_progress("smoking_gun", "start", "Filtering definitive proof (smoking guns)")
            try:
                smoking_gun_report = self._smoking_gun_synthesizer.synthesize(rule_results)
                has_definitive_proof = smoking_gun_report.has_definitive_proof
                smoking_gun_report_dict = {
                    "has_definitive_proof": smoking_gun_report.has_definitive_proof,
                    "smoking_gun_count": len(smoking_gun_report.smoking_guns),
                    "smoking_guns": [
                        {
                            "rule_id": sg.rule_id,
                            "rule_name": sg.rule_name,
                            "description": sg.description,
                            "forensic_reasoning": sg.forensic_reasoning,
                            "legal_significance": sg.legal_significance,
                            "confidence": sg.confidence,
                        }
                        for sg in smoking_gun_report.smoking_guns
                    ],
                    "expert_summary": smoking_gun_report.expert_summary,
                    "legal_conclusion": smoking_gun_report.legal_conclusion,
                    "recommendation": smoking_gun_report.recommendation,
                }
                if has_definitive_proof:
                    self._report_progress(
                        "smoking_gun", "complete",
                        f"[!!] DEFINITIVE PROOF: {len(smoking_gun_report.smoking_guns)} smoking gun(s)"
                    )
                else:
                    self._report_progress(
                        "smoking_gun", "complete",
                        "No definitive proof of tampering (red herrings filtered)"
                    )
            except Exception as e:
                import traceback
                self._analysis_errors.append({
                    "operation": "smoking_gun_synthesis",
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "traceback": traceback.format_exc(),
                    "timestamp": datetime.now().isoformat(),
                })
                self._report_progress("smoking_gun", "error", f"Smoking gun synthesis failed: {str(e)}")

        # LLM FORENSIC REASONING: Use LLM to actually REASON about evidence
        # This is different from narrative generation - the LLM evaluates evidence significance,
        # identifies true smoking guns through logical reasoning, and filters red herrings
        llm_reasoning_dict: Optional[Dict[str, Any]] = None

        if self._reasoner:
            self._report_progress("reasoning", "start", f"LLM forensic reasoning ({self._llm_model or 'default'})")
            try:
                import asyncio
                # Build analysis data for LLM reasoning
                analysis_data = {
                    "file": {"filename": file_info.filename, "size": file_info.file_size_bytes},
                    "header": {"version_string": header_analysis.version_string},
                    "metadata": {
                        "tdcreate": metadata.tdcreate if metadata else None,
                        "tdupdate": metadata.tdupdate if metadata else None,
                        "tdindwg": metadata.tdindwg if metadata else None,
                    } if metadata else {},
                    "crc_validation": {"is_valid": crc_validation.is_valid},
                    "ntfs_data": {
                        "si_fn_mismatch": ntfs_data.si_fn_mismatch if ntfs_data else False,
                        "nanoseconds_truncated": ntfs_data.nanoseconds_truncated if ntfs_data else False,
                    } if ntfs_data else {},
                    "anomalies": [
                        {"anomaly_type": a.anomaly_type.value, "description": a.description}
                        for a in anomalies[:10]  # Limit to first 10 for context
                    ],
                    "rule_results": [
                        {"rule_id": r.rule_id, "status": r.status.value, "description": r.description}
                        for r in failed_rules[:10]  # Limit to first 10
                    ],
                }

                # Add parsing diagnostics if available (critical for LLM reasoning about parse failures)
                if drawing_vars and drawing_vars.diagnostics:
                    analysis_data["parse_diagnostics"] = drawing_vars.diagnostics.to_dict()

                # Add Revit detection results if available (critical for interpreting CRC and timestamps)
                if revit_detection:
                    analysis_data["revit_detection"] = {
                        "is_revit_export": revit_detection.is_revit_export,
                        "export_type": revit_detection.export_type.value,
                        "confidence_score": revit_detection.confidence_score,
                        "revit_version": revit_detection.revit_version,
                        "forensic_notes": revit_detection.forensic_notes,
                    }

                # Run async reasoning in sync context
                loop = asyncio.new_event_loop()
                try:
                    reasoning = loop.run_until_complete(
                        self._reasoner.reason_about_evidence(analysis_data)
                    )
                finally:
                    loop.close()

                llm_reasoning_dict = {
                    "has_definitive_proof": reasoning.has_definitive_proof,
                    "smoking_guns": reasoning.smoking_guns,
                    "filtered_red_herrings": reasoning.filtered_red_herrings,
                    "reasoning_chain": reasoning.reasoning_chain,
                    "expert_conclusion": reasoning.expert_conclusion,
                    "confidence": reasoning.confidence,
                    "model_used": reasoning.model_used,
                }

                # Update has_definitive_proof from LLM reasoning if available
                if reasoning.has_definitive_proof:
                    has_definitive_proof = True
                    self._report_progress(
                        "reasoning", "complete",
                        f"[!!] LLM confirms DEFINITIVE PROOF ({len(reasoning.smoking_guns)} finding(s))"
                    )
                else:
                    self._report_progress(
                        "reasoning", "complete",
                        f"LLM: No definitive proof ({len(reasoning.filtered_red_herrings)} red herrings filtered)"
                    )
            except Exception as e:
                import traceback
                self._analysis_errors.append({
                    "operation": "llm_reasoning",
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "traceback": traceback.format_exc(),
                    "timestamp": datetime.now().isoformat(),
                })
                self._report_progress("reasoning", "error", f"LLM reasoning failed: {str(e)}")

        # Build partial analysis for LLM narrative generation
        # (needed before final ForensicAnalysis object is created)
        llm_narrative: Optional[str] = None
        llm_model_used: Optional[str] = None

        if self._use_llm and self._narrator:
            self._report_progress("llm", "start", f"Generating expert narrative ({self._llm_model or 'default model'})")
            try:
                # Build Revit detection dict for analysis object
                revit_detection_dict = None
                if revit_detection:
                    revit_detection_dict = {
                        "is_revit_export": revit_detection.is_revit_export,
                        "export_type": revit_detection.export_type.value,
                        "confidence_score": revit_detection.confidence_score,
                        "revit_version": revit_detection.revit_version,
                        "export_timestamp": revit_detection.export_timestamp,
                        "forensic_notes": revit_detection.forensic_notes,
                        "signatures": [
                            {
                                "signature_type": sig.signature_type,
                                "location": sig.location,
                                "confidence": sig.confidence,
                                "details": sig.details,
                            }
                            for sig in revit_detection.signatures
                        ],
                    }

                # Create temporary analysis object for LLM
                temp_analysis = ForensicAnalysis(
                    file_info=file_info,
                    header_analysis=header_analysis,
                    crc_validation=crc_validation,
                    metadata=metadata,
                    ntfs_analysis=ntfs_analysis,
                    application_fingerprint=app_fingerprint,
                    anomalies=anomalies,
                    tampering_indicators=tampering_indicators,
                    risk_assessment=risk_assessment,
                    forensic_knowledge=forensic_knowledge_dict,
                    analysis_timestamp=datetime.now(),
                    analyzer_version=__version__,
                )
                # Add Revit detection as attribute for LLM narrator access
                temp_analysis.revit_detection = revit_detection_dict

                # Generate LLM narrative
                narrative_result = self._narrator.generate_full_analysis(temp_analysis)

                if narrative_result.success:
                    llm_narrative = narrative_result.narrative
                    llm_model_used = narrative_result.model_used
                    gen_time = f" ({narrative_result.generation_time_ms}ms)" if narrative_result.generation_time_ms else ""
                    self._report_progress(
                        "llm", "complete",
                        f"Narrative generated by {narrative_result.model_used}{gen_time}"
                    )
                else:
                    error_msg = narrative_result.error or "Unknown error"
                    self._report_progress("llm", "error", f"LLM generation failed: {error_msg}")
            except Exception as e:
                import traceback
                self._analysis_errors.append({
                    "operation": "llm_narrative",
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "traceback": traceback.format_exc(),
                    "timestamp": datetime.now().isoformat(),
                })
                self._report_progress("llm", "error", f"LLM narrative failed: {str(e)}")

        # Build Revit detection dict for final analysis (if not already created for LLM)
        if 'revit_detection_dict' not in locals() and revit_detection:
            revit_detection_dict = {
                "is_revit_export": revit_detection.is_revit_export,
                "export_type": revit_detection.export_type.value,
                "confidence_score": revit_detection.confidence_score,
                "revit_version": revit_detection.revit_version,
                "export_timestamp": revit_detection.export_timestamp,
                "forensic_notes": revit_detection.forensic_notes,
                "signatures": [
                    {
                        "signature_type": sig.signature_type,
                        "location": sig.location,
                        "confidence": sig.confidence,
                        "details": sig.details,
                    }
                    for sig in revit_detection.signatures
                ],
            }
        elif 'revit_detection_dict' not in locals():
            revit_detection_dict = None

        # Build structure analysis dict
        structure_analysis_dict = None
        if structure_analysis:
            structure_analysis_dict = structure_analysis.to_dict()

        return ForensicAnalysis(
            file_info=file_info,
            header_analysis=header_analysis,
            crc_validation=crc_validation,
            metadata=metadata,
            ntfs_analysis=ntfs_analysis,
            file_provenance=file_provenance_dict,
            application_fingerprint=app_fingerprint,
            revit_detection=revit_detection_dict,
            structure_analysis=structure_analysis_dict,
            anomalies=anomalies,
            tampering_indicators=tampering_indicators,
            risk_assessment=risk_assessment,
            forensic_knowledge=forensic_knowledge_dict,
            llm_narrative=llm_narrative,
            llm_model_used=llm_model_used,
            smoking_gun_report=smoking_gun_report_dict,
            has_definitive_proof=has_definitive_proof,
            llm_reasoning=llm_reasoning_dict,
            filtered_anomalies=filtered_anomalies_result,
            anomaly_filter_method=anomaly_filter_method,
            analysis_errors=self._analysis_errors if self._analysis_errors else None,
            analysis_timestamp=datetime.now(),
            analyzer_version=__version__,
        )

    def analyze_tampering(self, file_path: Path) -> TamperingReport:
        """Perform focused tampering analysis on a DWG file.

        This method provides a detailed tampering-focused report with
        risk scoring and recommendations.

        Args:
            file_path: Path to the DWG file to analyze

        Returns:
            TamperingReport with detailed tampering analysis
        """
        file_path = Path(file_path)

        # Parse header first to get version
        header_analysis = self.header_parser.parse(file_path)
        version_string = header_analysis.version_string

        # Validate CRC (version-aware)
        crc_validation = self.crc_validator.validate_header_crc(
            file_path, version_string=version_string
        )

        # File provenance detection (for context-aware anomaly detection)
        file_provenance = None
        try:
            provenance_detector = ProvenanceDetector()
            file_provenance = provenance_detector.detect(file_path)
        except Exception:
            # Provenance detection is optional - continue without it
            pass

        # Anomaly detection (provenance-aware)
        anomalies = self._detect_all_anomalies(
            header_analysis, crc_validation, file_path,
            file_provenance=file_provenance
        )

        # Tampering rule evaluation
        rule_context = self._build_rule_context(
            header_analysis, crc_validation, file_path
        )
        rule_results = self.rule_engine.evaluate_all(rule_context)
        failed_rules = self.rule_engine.get_failed_rules(rule_results)

        # Convert failed rules to dict format for report
        failed_rules_dicts = []
        for r in failed_rules:
            evidence_parts = []
            if r.expected:
                evidence_parts.append(f"Expected: {r.expected}")
            if r.found:
                evidence_parts.append(f"Found: {r.found}")
            evidence = "; ".join(evidence_parts) if evidence_parts else r.description

            failed_rules_dicts.append({
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "severity": r.severity.value if hasattr(r.severity, 'value') else str(r.severity),
                "message": r.description,
                "evidence": evidence,
            })

        # Detect tampering indicators (version-aware)
        tampering_indicators = self._detect_tampering(
            crc_validation, failed_rules, version_string
        )

        # Knowledge enrichment for tampering analysis
        forensic_knowledge_dict: Optional[Dict[str, Any]] = None
        if self._enable_knowledge_enrichment and self._knowledge_enricher:
            try:
                failed_rule_ids = [r.rule_id for r in failed_rules]
                knowledge = self._knowledge_enricher.enrich_analysis(
                    failed_rule_ids=failed_rule_ids,
                    include_admissibility=True,
                )
                forensic_knowledge_dict = knowledge.model_dump()
            except Exception as e:
                import traceback
                self._analysis_errors.append({
                    "operation": "analyze_tampering_knowledge_enrichment",
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "traceback": traceback.format_exc(),
                    "timestamp": datetime.now().isoformat(),
                })
                # Continue without knowledge on error

        # Generate comprehensive report
        report = self.risk_scorer.generate_report(
            file_path=file_path,
            header=header_analysis,
            crc_validation=crc_validation,
            metadata=None,
            anomalies=anomalies,
            rule_failures=failed_rules_dicts,
            tampering_indicators=tampering_indicators,
        )

        # Add forensic knowledge to report
        if forensic_knowledge_dict:
            report.forensic_knowledge = forensic_knowledge_dict

        return report

    def _collect_file_info(self, file_path: Path) -> FileInfo:
        """Collect basic file information including SHA-256 hash.

        Args:
            file_path: Path to the file

        Returns:
            FileInfo model with file metadata
        """
        # Calculate SHA-256 hash
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)

        file_stat = file_path.stat()

        return FileInfo(
            filename=file_path.name,
            sha256=sha256_hash.hexdigest(),
            file_size_bytes=file_stat.st_size,
            intake_timestamp=datetime.now(),
        )

    def _build_metadata_from_timestamps(
        self, timestamp_data: TimestampData
    ) -> Optional[DWGMetadata]:
        """Build DWGMetadata from parsed timestamp data.

        Args:
            timestamp_data: Parsed timestamp data from the DWG file

        Returns:
            DWGMetadata model or None if no timestamp data available
        """
        from dwg_forensic.parsers.timestamp import mjd_to_datetime

        # Convert MJD timestamps to datetime for metadata
        created_date = None
        modified_date = None

        if timestamp_data.tdcreate is not None:
            try:
                created_date = mjd_to_datetime(timestamp_data.tdcreate)
            except (ValueError, OverflowError):
                pass

        if timestamp_data.tdupdate is not None:
            try:
                modified_date = mjd_to_datetime(timestamp_data.tdupdate)
            except (ValueError, OverflowError):
                pass

        # Calculate total editing time in hours from TDINDWG (days)
        total_editing_hours = None
        if timestamp_data.tdindwg is not None:
            total_editing_hours = timestamp_data.tdindwg * 24.0

        return DWGMetadata(
            created_date=created_date,
            modified_date=modified_date,
            total_editing_time_hours=total_editing_hours,
            last_saved_by=timestamp_data.login_name,
            # MJD fields
            tdcreate=timestamp_data.tdcreate,
            tdupdate=timestamp_data.tdupdate,
            tducreate=timestamp_data.tducreate,
            tduupdate=timestamp_data.tduupdate,
            tdindwg=timestamp_data.tdindwg,
            tdusrtimer=timestamp_data.tdusrtimer,
            # GUID fields
            fingerprint_guid=timestamp_data.fingerprint_guid,
            version_guid=timestamp_data.version_guid,
            # User identity
            login_name=timestamp_data.login_name,
            educational_watermark=timestamp_data.educational_watermark,
        )

    def _detect_all_anomalies(
        self,
        header_analysis: HeaderAnalysis,
        crc_validation: CRCValidation,
        file_path: Path,
        timestamp_data: Optional[TimestampData] = None,
        metadata: Optional[DWGMetadata] = None,
        ntfs_data: Optional[NTFSForensicData] = None,
        ntfs_contradictions: Optional[Dict[str, Any]] = None,
        file_provenance = None,
    ) -> List[Anomaly]:
        """Detect all anomalies using Phase 3 AnomalyDetector.

        Phase 2: Now uses provenance-aware detection to eliminate false positives
        for Revit exports, ODA tools, and file transfers.

        Args:
            header_analysis: Header analysis results
            crc_validation: CRC validation results
            file_path: Path to the DWG file
            timestamp_data: Optional parsed timestamp data for advanced detection
            metadata: Optional DWG metadata
            ntfs_data: Optional NTFS forensic data for cross-validation
            ntfs_contradictions: Optional dict of NTFS/DWG contradictions
            file_provenance: Optional FileProvenance for context-aware detection

        Returns:
            List of detected anomalies
        """
        anomalies = []

        # Create provenance-aware anomaly detector
        # If provenance is available, use it to adjust tolerances
        provenance_aware_detector = AnomalyDetector(provenance=file_provenance)

        # Use Phase 3 anomaly detector for version and structural anomalies
        version_anomalies = provenance_aware_detector.detect_version_anomalies(
            header_analysis, file_path
        )
        anomalies.extend(version_anomalies)

        structural_anomalies = provenance_aware_detector.detect_structural_anomalies(file_path)
        anomalies.extend(structural_anomalies)

        # Timestamp anomalies (if metadata available)
        if metadata:
            timestamp_anomalies = provenance_aware_detector.detect_timestamp_anomalies(
                metadata, file_path
            )
            anomalies.extend(timestamp_anomalies)

        # Advanced timestamp manipulation detection (if timestamp_data available)
        if timestamp_data:
            advanced_anomalies = provenance_aware_detector.detect_advanced_timestamp_anomalies(
                header_analysis.version_string, timestamp_data, metadata
            )
            anomalies.extend(advanced_anomalies)

        # CRC mismatch anomaly
        if not crc_validation.is_valid:
            anomalies.append(
                Anomaly(
                    anomaly_type=AnomalyType.CRC_MISMATCH,
                    description="Header CRC checksum does not match calculated value",
                    severity=RiskLevel.HIGH,
                    details={
                        "stored_crc": crc_validation.header_crc_stored,
                        "calculated_crc": crc_validation.header_crc_calculated,
                    },
                )
            )

        # NTFS cross-validation anomalies (SMOKING GUN INDICATORS)
        if ntfs_data:
            # SI/FN mismatch = DEFINITIVE timestomping proof
            if ntfs_data.si_fn_mismatch:
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.NTFS_SI_FN_MISMATCH,
                        description=(
                            "DEFINITIVE TIMESTOMPING: $STANDARD_INFORMATION timestamps "
                            "are earlier than kernel-protected $FILE_NAME timestamps. "
                            "This is impossible without deliberate manipulation tools."
                        ),
                        severity=RiskLevel.CRITICAL,
                        details={
                            "si_created": str(ntfs_data.si_timestamps.created) if ntfs_data.si_timestamps.created else None,
                            "fn_created": str(ntfs_data.fn_timestamps.created) if ntfs_data.fn_timestamps and ntfs_data.fn_timestamps.created else None,
                            "forensic_conclusion": "File timestamps have been manipulated using timestomping tools",
                        },
                    )
                )

            # Nanosecond truncation = Tool signature (but NOT for Revit exports)
            if ntfs_data.nanoseconds_truncated:
                # Check if this is a Revit export - truncated nanoseconds are EXPECTED
                is_revit = crc_validation.is_revit_export if crc_validation else False

                if is_revit:
                    # Revit exports commonly have truncated nanoseconds due to file transfers
                    anomalies.append(
                        Anomaly(
                            anomaly_type=AnomalyType.NTFS_NANOSECOND_TRUNCATION,
                            description=(
                                "REVIT EXPORT - EXPECTED: NTFS timestamps have zero nanoseconds. "
                                "This is NORMAL for Revit exports which are commonly transferred "
                                "between systems. File copy operations reset nanosecond values."
                            ),
                            severity=RiskLevel.INFO,  # INFO level for Revit exports
                            details={
                                "created_nanoseconds": ntfs_data.si_timestamps.created_nanoseconds,
                                "modified_nanoseconds": ntfs_data.si_timestamps.modified_nanoseconds,
                                "forensic_conclusion": "Normal for Revit export - not evidence of tampering",
                                "is_revit_export": True,
                            },
                        )
                    )
                else:
                    anomalies.append(
                        Anomaly(
                            anomaly_type=AnomalyType.NTFS_NANOSECOND_TRUNCATION,
                            description=(
                                "TOOL SIGNATURE DETECTED: NTFS timestamps have nanosecond values "
                                "of exactly zero. Natural filesystem operations always include "
                                "non-zero nanoseconds. This indicates use of timestamp manipulation tools."
                            ),
                            severity=RiskLevel.HIGH,
                            details={
                                "created_nanoseconds": ntfs_data.si_timestamps.created_nanoseconds,
                                "modified_nanoseconds": ntfs_data.si_timestamps.modified_nanoseconds,
                                "forensic_conclusion": "Timestamps were set programmatically, not by normal file operations",
                            },
                        )
                    )

            # Creation after modification = NORMAL for copied files (informational only)
            if ntfs_data.creation_after_modification:
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.NTFS_CREATION_AFTER_MODIFICATION,
                        description=(
                            "INFORMATIONAL: File was copied to this machine. NTFS Created timestamp "
                            "is newer than Modified timestamp. This is NORMAL Windows copy behavior - "
                            "the operating system sets Created to time of copy but preserves the "
                            "original Modified timestamp from the source."
                        ),
                        severity=RiskLevel.INFO,  # Changed from CRITICAL - this is normal behavior
                        details={
                            "created": str(ntfs_data.si_timestamps.created) if ntfs_data.si_timestamps.created else None,
                            "modified": str(ntfs_data.si_timestamps.modified) if ntfs_data.si_timestamps.modified else None,
                            "forensic_conclusion": "Normal Windows file copy behavior - NOT evidence of tampering",
                            "is_normal_copy_behavior": True,
                        },
                    )
                )

        # DWG vs NTFS creation time differences (NORMAL for transferred files)
        if ntfs_contradictions:
            if ntfs_contradictions.get("creation_time_difference"):
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.DWG_NTFS_CREATION_DIFFERENCE,
                        description=(
                            "File transfer detected: DWG internal creation timestamp predates "
                            "NTFS filesystem timestamp. This is normal for copied/transferred files - "
                            "NTFS 'Created' reflects when the file arrived on this machine."
                        ),
                        severity=RiskLevel.INFO,  # Changed from CRITICAL - this is normal behavior
                        details=ntfs_contradictions.get("creation_details", {}),
                    )
                )

            if ntfs_contradictions.get("modification_contradiction"):
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.DWG_NTFS_MODIFICATION_CONTRADICTION,
                        description=(
                            "TIMESTAMP MANIPULATION: DWG internal modification timestamp "
                            "contradicts NTFS modification timestamp beyond acceptable tolerance."
                        ),
                        severity=RiskLevel.HIGH,
                        details=ntfs_contradictions.get("modification_details", {}),
                    )
                )

        return anomalies

    def _build_rule_context(
        self,
        header_analysis: HeaderAnalysis,
        crc_validation: CRCValidation,
        file_path: Path,
        timestamp_data: Optional[TimestampData] = None,
        anomalies: Optional[List[Anomaly]] = None,
        metadata: Optional[DWGMetadata] = None,
        ntfs_data: Optional[NTFSForensicData] = None,
        ntfs_contradictions: Optional[Dict[str, Any]] = None,
        section_map: Optional[SectionMapResult] = None,
        drawing_vars: Optional[DrawingVariablesResult] = None,
        handle_map: Optional[HandleMapResult] = None,
        fingerprint: Optional[FingerprintResult] = None,
        structure_analysis: Optional["StructureAnalysisResult"] = None,
    ) -> Dict[str, Any]:
        """Build context dictionary for tampering rule evaluation.

        Args:
            header_analysis: Header analysis results
            crc_validation: CRC validation results
            file_path: Path to the DWG file
            timestamp_data: Optional parsed timestamp data
            anomalies: Optional list of detected anomalies
            metadata: Optional DWG metadata
            ntfs_data: Optional NTFS forensic data for cross-validation
            ntfs_contradictions: Optional dict of NTFS/DWG contradictions
            section_map: Optional deep parsing section map results
            drawing_vars: Optional deep parsing drawing variables results
            handle_map: Optional deep parsing handle map results
            fingerprint: Optional CAD application fingerprint result
            structure_analysis: Optional structure analysis result for ODA detection

        Returns:
            Context dictionary for rule evaluation
        """
        context = {
            "header": {
                "version_string": header_analysis.version_string,
                "version_name": header_analysis.version_name,
                "is_supported": header_analysis.is_supported,
                "maintenance_version": header_analysis.maintenance_version,
            },
            "crc": {
                "is_valid": crc_validation.is_valid,
                "header_crc_stored": crc_validation.header_crc_stored,
                "header_crc_calculated": crc_validation.header_crc_calculated,
                "section_results": [
                    {
                        "section_name": s.section_name,
                        "is_valid": s.is_valid,
                        "stored_crc": s.stored_crc,
                        "calculated_crc": s.calculated_crc,
                    }
                    for s in (crc_validation.section_results or [])
                ],
                "is_revit_export": crc_validation.is_revit_export,
                "is_oda_export": crc_validation.is_oda_export,
                "forensic_notes": crc_validation.forensic_notes,
            },
            "file": {
                "path": str(file_path),
                "size": file_path.stat().st_size,
            },
        }

        # Add timestamp data for advanced tampering rules
        if timestamp_data:
            context["timestamp_data"] = {
                "tdcreate": timestamp_data.tdcreate,
                "tdupdate": timestamp_data.tdupdate,
                "tducreate": timestamp_data.tducreate,
                "tduupdate": timestamp_data.tduupdate,
                "tdindwg": timestamp_data.tdindwg,
                "tdusrtimer": timestamp_data.tdusrtimer,
                "fingerprint_guid": timestamp_data.fingerprint_guid,
                "version_guid": timestamp_data.version_guid,
                "login_name": timestamp_data.login_name,
                "educational_watermark": timestamp_data.educational_watermark,
                "calendar_span_days": timestamp_data.get_calendar_span_days(),
                "timezone_offset_hours": timestamp_data.get_timezone_offset_hours(),
            }

        # Add version release date for anachronism detection
        version_release = get_version_release_date(header_analysis.version_string)
        if version_release:
            context["version_release_date"] = version_release.isoformat()

        # Add metadata if available
        if metadata:
            context["metadata"] = {
                "created_date": metadata.created_date.isoformat() if metadata.created_date else None,
                "modified_date": metadata.modified_date.isoformat() if metadata.modified_date else None,
                "total_editing_time_hours": metadata.total_editing_time_hours,
                "educational_watermark": metadata.educational_watermark,
            }

        # Add anomalies for rule cross-referencing
        if anomalies:
            context["anomalies"] = [
                {
                    "anomaly_type": a.anomaly_type.value if hasattr(a.anomaly_type, 'value') else str(a.anomaly_type),
                    "description": a.description,
                    "severity": a.severity.value if hasattr(a.severity, 'value') else str(a.severity),
                    "details": a.details,
                }
                for a in anomalies
            ]

        # Add NTFS forensic data for cross-validation rules
        if ntfs_data:
            context["ntfs_data"] = {
                "si_created": ntfs_data.si_timestamps.created.isoformat() if ntfs_data.si_timestamps.created else None,
                "si_modified": ntfs_data.si_timestamps.modified.isoformat() if ntfs_data.si_timestamps.modified else None,
                "si_accessed": ntfs_data.si_timestamps.accessed.isoformat() if ntfs_data.si_timestamps.accessed else None,
                "si_created_nanoseconds": ntfs_data.si_timestamps.created_nanoseconds,
                "si_modified_nanoseconds": ntfs_data.si_timestamps.modified_nanoseconds,
                "fn_created": ntfs_data.fn_timestamps.created.isoformat() if ntfs_data.fn_timestamps and ntfs_data.fn_timestamps.created else None,
                "fn_modified": ntfs_data.fn_timestamps.modified.isoformat() if ntfs_data.fn_timestamps and ntfs_data.fn_timestamps.modified else None,
                "si_fn_mismatch": ntfs_data.si_fn_mismatch,
                "nanoseconds_truncated": ntfs_data.nanoseconds_truncated,
                "creation_after_modification": ntfs_data.creation_after_modification,
            }

        # Add NTFS contradictions for cross-validation rules
        if ntfs_contradictions:
            context["ntfs_contradictions"] = ntfs_contradictions

        # Add deep parsing results for advanced rules (TAMPER-036 to TAMPER-040)
        # Section map data
        if section_map:
            # Check success by absence of parsing errors
            has_errors = bool(section_map.parsing_errors)
            sections_list = list(section_map.sections.values()) if section_map.sections else []
            context["section_map"] = {
                "success": not has_errors,
                "section_count": len(sections_list),
                "has_header_section": any(
                    s.section_type == SectionType.HEADER for s in sections_list
                ),
                "has_handles_section": any(
                    s.section_type == SectionType.HANDLES for s in sections_list
                ),
                "error": section_map.parsing_errors[0] if section_map.parsing_errors else None,
                "version_format": section_map.file_version,
            }

        # Drawing variables data (extracted TDCREATE/TDUPDATE from binary)
        if drawing_vars:
            context["drawing_vars"] = {
                "tdcreate": {
                    "julian_day": drawing_vars.tdcreate.julian_day if drawing_vars.tdcreate else None,
                    "milliseconds": drawing_vars.tdcreate.milliseconds if drawing_vars.tdcreate else None,
                    "datetime": drawing_vars.tdcreate.datetime_utc.isoformat() if drawing_vars.tdcreate and drawing_vars.tdcreate.datetime_utc else None,
                } if drawing_vars.tdcreate else None,
                "tdupdate": {
                    "julian_day": drawing_vars.tdupdate.julian_day if drawing_vars.tdupdate else None,
                    "milliseconds": drawing_vars.tdupdate.milliseconds if drawing_vars.tdupdate else None,
                    "datetime": drawing_vars.tdupdate.datetime_utc.isoformat() if drawing_vars.tdupdate and drawing_vars.tdupdate.datetime_utc else None,
                } if drawing_vars.tdupdate else None,
                # Note: attribute names are fingerprintguid/versionguid (no underscore)
                "fingerprint_guid": drawing_vars.fingerprintguid.guid_string if drawing_vars.fingerprintguid else None,
                "version_guid": drawing_vars.versionguid.guid_string if drawing_vars.versionguid else None,
                "timestamp_contradiction": drawing_vars.has_timestamp_contradiction() if hasattr(drawing_vars, 'has_timestamp_contradiction') else False,
            }

        # Handle map data for gap analysis
        if handle_map:
            gap_list = handle_map.gaps or []
            critical_gaps = [g for g in gap_list if g.severity == "critical"]
            high_gaps = [g for g in gap_list if g.severity == "high"]
            has_errors = bool(handle_map.parsing_errors)
            context["handle_map"] = {
                "success": not has_errors,
                "total_handles": handle_map.statistics.total_handles if handle_map.statistics else 0,
                "gap_count": len(gap_list),
                "critical_gap_count": len(critical_gaps),
                "high_gap_count": len(high_gaps),
                "gap_ratio": handle_map.statistics.gap_ratio if handle_map.statistics else 0.0,
                "largest_gap": max((g.gap_size for g in gap_list), default=0) if gap_list else 0,
                "error": handle_map.parsing_errors[0] if handle_map.parsing_errors else None,
            }

        # Add CAD application fingerprint for software-specific rules
        if fingerprint:
            context["application_fingerprint"] = {
                "detected_application": fingerprint.detected_application.value,
                "confidence": fingerprint.confidence,
                "is_autodesk": fingerprint.is_autodesk,
                "is_oda_based": fingerprint.is_oda_based,
                "forensic_summary": fingerprint.forensic_summary,
                "matching_signatures": [
                    {
                        "application": sig.application.value,
                        "pattern_type": sig.pattern_type,
                        "description": sig.description,
                        "confidence": sig.confidence,
                    }
                    for sig in fingerprint.matching_signatures
                ],
            }

        # Add structure analysis for ODA/non-AutoCAD detection
        if structure_analysis:
            context["structure_analysis"] = {
                "structure_type": structure_analysis.structure_type.value if structure_analysis.structure_type else "unknown",
                "detected_tool": structure_analysis.detected_tool or "unknown",
                "confidence": structure_analysis.confidence,
                "is_oda_based": structure_analysis.structure_type.value == "non_autocad" if structure_analysis.structure_type else False,
            }

        return context

    def _detect_tampering(
        self,
        crc_validation: CRCValidation,
        failed_rules: List[Any],
        version_string: Optional[str] = None,
        timestamp_data: Optional[TimestampData] = None,
        ntfs_data: Optional[NTFSForensicData] = None,
        ntfs_contradictions: Optional[Dict[str, Any]] = None,
        structure_analysis: Optional["StructureAnalysisResult"] = None,
    ) -> List[TamperingIndicator]:
        """Detect tampering indicators with definitive forensic conclusions.

        Args:
            crc_validation: CRC validation results
            failed_rules: List of failed tampering rules
            version_string: DWG version string for version-aware detection
            timestamp_data: Optional parsed timestamp data
            ntfs_data: Optional NTFS forensic data for cross-validation
            ntfs_contradictions: Optional dict of NTFS/DWG contradictions
            structure_analysis: Optional structure analysis for ODA detection

        Returns:
            List of tampering indicators with forensic conclusions
        """
        indicators = []

        # Check if this is an ODA/Revit file where CRC=0 is normal
        is_oda_file = (
            structure_analysis and
            structure_analysis.structure_type and
            structure_analysis.structure_type.value == "non_autocad"
        )
        is_revit_file = crc_validation.is_revit_export

        # CRC modification (only if CRC is available for this version)
        # "N/A" indicates version doesn't support CRC
        # Skip for ODA/Revit files where CRC=0 is expected
        if (crc_validation.header_crc_stored != "N/A" and
            not crc_validation.is_valid and
            not is_oda_file and
            not is_revit_file):
            indicators.append(
                TamperingIndicator(
                    indicator_type=TamperingIndicatorType.CRC_MODIFIED,
                    description="File header CRC does not match, indicating modification after save",
                    confidence=0.9,
                    evidence=f"Stored CRC: {crc_validation.header_crc_stored}, "
                    f"Calculated CRC: {crc_validation.header_crc_calculated}",
                )
            )

        # Advanced timestamp manipulation indicators
        if timestamp_data:
            # TDINDWG manipulation detection
            calendar_span = timestamp_data.get_calendar_span_days()
            if (timestamp_data.tdindwg is not None and
                calendar_span is not None and
                timestamp_data.tdindwg > calendar_span):
                indicators.append(
                    TamperingIndicator(
                        indicator_type=TamperingIndicatorType.TDINDWG_MANIPULATION,
                        description=(
                            "Cumulative editing time exceeds calendar span - "
                            "proves timestamp manipulation"
                        ),
                        confidence=1.0,
                        evidence=(
                            f"TDINDWG: {round(timestamp_data.tdindwg * 24, 1)} hours, "
                            f"Calendar span: {round(calendar_span * 24, 1)} hours"
                        ),
                    )
                )

            # Timezone manipulation detection
            offset = timestamp_data.get_timezone_offset_hours()
            if offset is not None and (offset < -12 or offset > 14):
                indicators.append(
                    TamperingIndicator(
                        indicator_type=TamperingIndicatorType.TIMEZONE_MANIPULATION,
                        description="Invalid UTC/local timezone offset indicates manipulation",
                        confidence=0.9,
                        evidence=f"Timezone offset: {round(offset, 2)} hours (valid: -12 to +14)",
                    )
                )

            # Educational watermark detection
            if timestamp_data.educational_watermark:
                indicators.append(
                    TamperingIndicator(
                        indicator_type=TamperingIndicatorType.EDUCATIONAL_VERSION,
                        description="File created with educational/student license",
                        confidence=1.0,
                        evidence="Educational Version watermark present in file",
                    )
                )

        # NTFS cross-validation tampering indicators (DEFINITIVE PROOF)
        if ntfs_data:
            # SI/FN mismatch = PROVEN timestomping
            if ntfs_data.si_fn_mismatch:
                indicators.append(
                    TamperingIndicator(
                        indicator_type=TamperingIndicatorType.NTFS_TIMESTOMPING_DETECTED,
                        description=(
                            "DEFINITIVE PROOF OF TIMESTOMPING: $STANDARD_INFORMATION timestamps "
                            "predate kernel-protected $FILE_NAME timestamps. This is forensically "
                            "impossible without deliberate manipulation."
                        ),
                        confidence=1.0,
                        evidence=(
                            f"SI Created: {ntfs_data.si_timestamps.created}, "
                            f"FN Created: {ntfs_data.fn_timestamps.created if ntfs_data.fn_timestamps else 'N/A'}"
                        ),
                    )
                )

            # Nanosecond truncation = Tool signature (but NOT for Revit exports)
            if ntfs_data.nanoseconds_truncated:
                # Skip this indicator for Revit exports - truncated nanoseconds are expected
                if not is_revit_file:
                    indicators.append(
                        TamperingIndicator(
                            indicator_type=TamperingIndicatorType.NTFS_TOOL_SIGNATURE,
                            description=(
                                "TIMESTAMP MANIPULATION TOOL DETECTED: NTFS timestamps have "
                                "nanosecond values of exactly zero. Natural filesystem operations "
                                "always include random nanosecond values."
                            ),
                            confidence=0.95,
                            evidence=(
                                f"Created nanoseconds: {ntfs_data.si_timestamps.created_nanoseconds}, "
                                f"Modified nanoseconds: {ntfs_data.si_timestamps.modified_nanoseconds}"
                            ),
                        )
                    )
                # For Revit exports, this is normal - don't add as tampering indicator

            # Creation after modification = NORMAL for copied files (informational)
            # NOTE: This is NOT included as a tampering indicator anymore
            # It's now tracked as informational context in anomalies only
            # if ntfs_data.creation_after_modification: # REMOVED - not tampering evidence

        # DWG vs NTFS creation time differences (NORMAL for file transfers)
        if ntfs_contradictions:
            if ntfs_contradictions.get("creation_time_difference"):
                indicators.append(
                    TamperingIndicator(
                        indicator_type=TamperingIndicatorType.FILE_TRANSFER_DETECTED,
                        description=(
                            "File transfer context: DWG authorship predates arrival on this filesystem. "
                            "This is expected behavior for any file that was copied or transferred."
                        ),
                        confidence=0.95,  # High confidence this is a transfer, not tampering
                        evidence=str(ntfs_contradictions.get("creation_details", {})),
                    )
                )

            if ntfs_contradictions.get("modification_contradiction"):
                indicators.append(
                    TamperingIndicator(
                        indicator_type=TamperingIndicatorType.DWG_NTFS_CONTRADICTION,
                        description=(
                            "DWG/NTFS TIMESTAMP CONTRADICTION: Internal DWG timestamps "
                            "contradict filesystem timestamps beyond acceptable tolerance."
                        ),
                        confidence=0.9,
                        evidence=str(ntfs_contradictions.get("modification_details", {})),
                    )
                )

        # Add indicators from failed tampering rules
        for rule_result in failed_rules:
            # High severity rules indicate stronger tampering evidence
            confidence = 0.8 if rule_result.severity.value == "critical" else 0.6
            # Build evidence string from available fields
            evidence_parts = []
            if rule_result.expected:
                evidence_parts.append(f"Expected: {rule_result.expected}")
            if rule_result.found:
                evidence_parts.append(f"Found: {rule_result.found}")
            evidence = "; ".join(evidence_parts) if evidence_parts else rule_result.description

            # Map specific rule IDs to indicator types
            indicator_type = TamperingIndicatorType.SUSPICIOUS_PATTERN
            if rule_result.rule_id == "TAMPER-013":
                indicator_type = TamperingIndicatorType.TDINDWG_MANIPULATION
            elif rule_result.rule_id == "TAMPER-014":
                indicator_type = TamperingIndicatorType.VERSION_ANACHRONISM
            elif rule_result.rule_id == "TAMPER-015":
                indicator_type = TamperingIndicatorType.TIMEZONE_MANIPULATION
            elif rule_result.rule_id == "TAMPER-016":
                indicator_type = TamperingIndicatorType.EDUCATIONAL_VERSION
            # NTFS Cross-Validation Rules (Smoking Gun Indicators)
            elif rule_result.rule_id == "TAMPER-019":
                indicator_type = TamperingIndicatorType.NTFS_TIMESTOMPING_DETECTED
            elif rule_result.rule_id == "TAMPER-020":
                indicator_type = TamperingIndicatorType.NTFS_TOOL_SIGNATURE
            elif rule_result.rule_id == "TAMPER-021":
                indicator_type = TamperingIndicatorType.NTFS_IMPOSSIBLE_TIMESTAMP
            elif rule_result.rule_id == "TAMPER-022":
                indicator_type = TamperingIndicatorType.PROVEN_BACKDATING
            elif rule_result.rule_id == "TAMPER-023":
                indicator_type = TamperingIndicatorType.DWG_NTFS_CONTRADICTION
            elif rule_result.rule_id in ("TAMPER-024", "TAMPER-025"):
                indicator_type = TamperingIndicatorType.TDINDWG_MANIPULATION
            elif rule_result.rule_id == "TAMPER-026":
                indicator_type = TamperingIndicatorType.SUSPICIOUS_PATTERN
            elif rule_result.rule_id in ("TAMPER-027", "TAMPER-028"):
                indicator_type = TamperingIndicatorType.PROVEN_BACKDATING

            indicators.append(
                TamperingIndicator(
                    indicator_type=indicator_type,
                    description=f"Tampering rule triggered: {rule_result.rule_name}",
                    confidence=confidence,
                    evidence=evidence,
                )
            )

        return indicators

    def _assess_risk_phase3(
        self,
        anomalies: List[Anomaly],
        tampering_indicators: List[TamperingIndicator],
        failed_rules: List[Any],
        crc_validation: CRCValidation,
    ) -> RiskAssessment:
        """Assess overall risk level using Phase 3 scoring algorithm.

        Args:
            anomalies: List of detected anomalies
            tampering_indicators: List of tampering indicators
            failed_rules: List of failed tampering rules
            crc_validation: CRC validation results

        Returns:
            RiskAssessment model with overall risk evaluation
        """
        # Convert failed rules to dict format for scoring
        failed_rules_dicts = [
            {
                "rule_id": r.rule_id,
                "severity": r.severity.value if hasattr(r.severity, 'value') else str(r.severity),
            }
            for r in failed_rules
        ]

        # Calculate score using Phase 3 RiskScorer
        score = self.risk_scorer.calculate_score(
            anomalies, failed_rules_dicts, tampering_indicators
        )
        risk_level = self.risk_scorer.score_to_risk_level(score)

        # Generate factors
        factors = self.risk_scorer.generate_factors(
            anomalies, failed_rules_dicts, tampering_indicators, crc_validation
        )

        # Generate recommendation
        recommendation = self.risk_scorer.generate_recommendation(risk_level, score)

        return RiskAssessment(
            overall_risk=risk_level,
            factors=factors,
            recommendation=recommendation,
        )

    def _cross_validate_ntfs_timestamps(
        self,
        timestamp_data: Optional[TimestampData],
        ntfs_data: Optional[NTFSForensicData],
        metadata: Optional[DWGMetadata],
    ) -> Dict[str, Any]:
        """Cross-validate DWG internal timestamps against NTFS filesystem timestamps.

        This is critical for detecting backdating attacks where DWG internal
        timestamps claim an earlier date than the filesystem allows.

        Args:
            timestamp_data: Parsed DWG timestamp data
            ntfs_data: NTFS forensic data from filesystem
            metadata: DWG metadata with converted timestamps

        Returns:
            Dictionary containing contradiction flags and details
        """
        from dwg_forensic.parsers.timestamp import mjd_to_datetime

        contradictions = {
            "creation_time_difference": False,  # Renamed from creation_contradiction
            "modification_contradiction": False,
            "creation_details": {},
            "modification_details": {},
        }

        if not timestamp_data or not ntfs_data:
            return contradictions

        # Get DWG creation timestamp
        dwg_created = None
        if timestamp_data.tdcreate is not None:
            try:
                dwg_created = mjd_to_datetime(timestamp_data.tdcreate)
            except (ValueError, OverflowError):
                pass

        # Get DWG modification timestamp
        dwg_modified = None
        if timestamp_data.tdupdate is not None:
            try:
                dwg_modified = mjd_to_datetime(timestamp_data.tdupdate)
            except (ValueError, OverflowError):
                pass

        # Cross-validate creation timestamps
        # If DWG claims earlier creation than NTFS filesystem, it's backdated
        if dwg_created and ntfs_data.si_timestamps.created:
            ntfs_created = ntfs_data.si_timestamps.created
            # Allow 1 hour tolerance for timezone differences
            tolerance_hours = 1
            time_diff = (ntfs_created - dwg_created).total_seconds() / 3600

            if time_diff > tolerance_hours:
                # DWG internal timestamp predates NTFS filesystem timestamp
                # This is NORMAL for transferred/copied files - NTFS Created reflects
                # when file arrived on THIS machine, not original authorship date
                contradictions["creation_time_difference"] = True  # Renamed - not a "contradiction"
                contradictions["creation_details"] = {
                    "dwg_created": dwg_created.isoformat(),
                    "ntfs_created": ntfs_created.isoformat(),
                    "difference_hours": round(time_diff, 2),
                    "forensic_note": (
                        f"DWG internal creation timestamp predates NTFS filesystem timestamp by "
                        f"{round(time_diff / 24, 1)} days. This is EXPECTED for files that were "
                        f"copied or transferred to this machine. The NTFS 'Created' timestamp "
                        f"reflects when the file arrived on this system, not original authorship."
                    ),
                    "is_normal_for_transferred_files": True,
                }

        # Cross-validate modification timestamps
        if dwg_modified and ntfs_data.si_timestamps.modified:
            ntfs_modified = ntfs_data.si_timestamps.modified
            # Allow 24 hour tolerance for normal file operations
            tolerance_hours = 24
            time_diff = abs((ntfs_modified - dwg_modified).total_seconds()) / 3600

            if time_diff > tolerance_hours:
                contradictions["modification_contradiction"] = True
                contradictions["modification_details"] = {
                    "dwg_modified": dwg_modified.isoformat(),
                    "ntfs_modified": ntfs_modified.isoformat(),
                    "difference_hours": round(time_diff, 2),
                    "forensic_conclusion": (
                        f"DWG internal modification timestamp differs from NTFS by "
                        f"{round(time_diff, 1)} hours. This indicates timestamp manipulation."
                    ),
                }

        return contradictions

    def _build_ntfs_analysis(
        self,
        ntfs_data: Optional[NTFSForensicData],
        ntfs_contradictions: Optional[Dict[str, Any]],
        metadata: Optional[DWGMetadata],
    ) -> Optional[NTFSTimestampAnalysis]:
        """Build NTFSTimestampAnalysis model from parsed NTFS data.

        Args:
            ntfs_data: Parsed NTFS forensic data
            ntfs_contradictions: Cross-validation contradiction results
            metadata: DWG metadata for reference

        Returns:
            NTFSTimestampAnalysis model or None if no NTFS data available
        """
        if not ntfs_data:
            return None

        # Build forensic conclusion based on findings
        conclusions = []
        if ntfs_data.si_fn_mismatch:
            conclusions.append(
                "DEFINITIVE TIMESTOMPING: $STANDARD_INFORMATION timestamps predate "
                "$FILE_NAME timestamps, which is impossible without manipulation tools."
            )
        if ntfs_data.nanoseconds_truncated:
            conclusions.append(
                "TOOL SIGNATURE: Nanosecond values are exactly zero, indicating "
                "programmatic timestamp manipulation rather than normal file operations."
            )
        if ntfs_data.creation_after_modification:
            conclusions.append(
                "FILE COPY DETECTED: Creation timestamp is later than modification timestamp - "
                "this is NORMAL Windows copy behavior, NOT evidence of tampering."
            )

        contradiction_details = None
        dwg_ntfs_contradiction = False
        if ntfs_contradictions:
            # Note: creation_time_difference is NORMAL for transferred files, not a contradiction
            if ntfs_contradictions.get("creation_time_difference"):
                # This is informational, not a contradiction - don't set dwg_ntfs_contradiction flag
                conclusions.append(
                    ntfs_contradictions.get("creation_details", {}).get(
                        "forensic_note", "DWG internal timestamp predates NTFS timestamp (normal for transferred files)."
                    )
                )
            if ntfs_contradictions.get("modification_contradiction"):
                dwg_ntfs_contradiction = True
                conclusions.append(
                    ntfs_contradictions.get("modification_details", {}).get(
                        "forensic_conclusion", "DWG/NTFS modification timestamp contradiction."
                    )
                )
            contradiction_details = str(ntfs_contradictions) if dwg_ntfs_contradiction else None

        forensic_conclusion = " ".join(conclusions) if conclusions else None

        return NTFSTimestampAnalysis(
            si_created=ntfs_data.si_timestamps.created,
            si_modified=ntfs_data.si_timestamps.modified,
            si_accessed=ntfs_data.si_timestamps.accessed,
            si_created_nanoseconds=ntfs_data.si_timestamps.created_nanoseconds,
            si_modified_nanoseconds=ntfs_data.si_timestamps.modified_nanoseconds,
            fn_created=ntfs_data.fn_timestamps.created if ntfs_data.fn_timestamps else None,
            fn_modified=ntfs_data.fn_timestamps.modified if ntfs_data.fn_timestamps else None,
            timestomping_detected=ntfs_data.si_fn_mismatch,
            nanosecond_truncation=ntfs_data.nanoseconds_truncated,
            impossible_timestamps=ntfs_data.creation_after_modification,
            dwg_ntfs_contradiction=dwg_ntfs_contradiction,
            contradiction_details=contradiction_details,
            forensic_conclusion=forensic_conclusion,
        )


def analyze_file(file_path: Path) -> ForensicAnalysis:
    """Convenience function to analyze a DWG file.

    Args:
        file_path: Path to the DWG file to analyze

    Returns:
        ForensicAnalysis model containing complete analysis results
    """
    analyzer = ForensicAnalyzer()
    return analyzer.analyze(file_path)


def analyze_tampering(
    file_path: Path,
    custom_rules_path: Optional[Path] = None,
) -> TamperingReport:
    """Convenience function for focused tampering analysis.

    Args:
        file_path: Path to the DWG file to analyze
        custom_rules_path: Optional path to custom rules YAML/JSON file

    Returns:
        TamperingReport with detailed tampering analysis
    """
    analyzer = ForensicAnalyzer(custom_rules_path=custom_rules_path)
    return analyzer.analyze_tampering(file_path)
