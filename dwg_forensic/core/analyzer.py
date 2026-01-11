"""Main forensic analyzer for DWG files.

This module provides the primary analysis workflow, combining header parsing,
CRC validation, watermark detection, anomaly detection, tampering rules,
and risk assessment.

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
    TrustedDWGAnalysis,
    DWGMetadata,
)
from dwg_forensic.parsers import (
    CRCValidator,
    HeaderParser,
    WatermarkDetector,
    TimestampParser,
    TimestampData,
    NTFSTimestampParser,
    NTFSForensicData,
    # Deep parsing modules for AC1018+ support
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
from dwg_forensic.utils.exceptions import DWGForensicError

# Phase 3 imports
from dwg_forensic.analysis import (
    AnomalyDetector,
    TamperingRuleEngine,
    RiskScorer,
    TamperingReport,
)
from dwg_forensic.analysis.version_dates import get_version_release_date


class ForensicAnalyzer:
    """Main forensic analyzer for DWG files.

    Combines all parsing and analysis components to produce a complete
    forensic analysis report including Phase 3 tampering detection.
    """

    def __init__(
        self,
        custom_rules_path: Optional[Path] = None,
        progress_callback: Optional[callable] = None,
    ):
        """Initialize the forensic analyzer with all required parsers.

        Args:
            custom_rules_path: Optional path to custom tampering rules YAML/JSON file
            progress_callback: Optional callback for progress updates.
                Signature: callback(step: str, status: str, message: str)
                step: Current analysis step name
                status: "start", "complete", "skip", "error"
                message: Human-readable description
        """
        # Progress callback for terminal display
        self._progress_callback = progress_callback

        # Phase 1 parsers
        self.header_parser = HeaderParser()
        self.crc_validator = CRCValidator()
        self.watermark_detector = WatermarkDetector()

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

        # Phase 3 analyzers
        self.anomaly_detector = AnomalyDetector()
        self.rule_engine = TamperingRuleEngine()
        self.risk_scorer = RiskScorer()

        # Load custom rules if provided
        if custom_rules_path:
            self.rule_engine.load_rules(custom_rules_path)

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
            except Exception:
                pass  # Don't let callback errors affect analysis

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

        # Detect watermark (version-aware)
        self._report_progress("watermark", "start", "Detecting TrustedDWG watermark")
        trusted_dwg = self.watermark_detector.detect(
            file_path, version_string=version_string
        )
        wm_status = "present" if trusted_dwg.watermark_present else "not found"
        self._report_progress("watermark", "complete", f"Watermark: {wm_status}")

        # CAD Application Fingerprinting - CRITICAL: identifies authoring software
        # This must run early as it informs all subsequent tampering analysis
        self._report_progress("fingerprint", "start", "Identifying CAD application")
        fingerprint_result: Optional[FingerprintResult] = None
        try:
            fingerprint_result = self.fingerprinter.fingerprint(
                file_path=file_path,
                header_crc=crc_validation.header_crc_stored,
                has_trusted_dwg=trusted_dwg.watermark_present and trusted_dwg.watermark_valid,
            )
            app_name = fingerprint_result.detected_application.value
            confidence = f"{fingerprint_result.confidence:.0%}"
            self._report_progress(
                "fingerprint", "complete",
                f"{app_name.upper()} (confidence: {confidence})"
            )
        except Exception as e:
            self._report_progress("fingerprint", "error", f"Fingerprinting failed: {e}")

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
            self._report_progress("sections", "error", f"Section parsing failed: {e}")

        # Deep DWG Parsing: Drawing Variables Extraction
        self._report_progress("drawing_vars", "start", "Extracting drawing variables (TDCREATE/TDUPDATE)")
        drawing_vars: Optional[DrawingVariablesResult] = None
        try:
            drawing_vars = self.drawing_vars_parser.parse(file_path)
            ts_count = sum([
                1 if drawing_vars.tdcreate else 0,
                1 if drawing_vars.tdupdate else 0,
            ])
            self._report_progress("drawing_vars", "complete", f"Timestamps found: {ts_count}")
        except Exception as e:
            self._report_progress("drawing_vars", "error", f"Drawing vars extraction failed: {e}")

        # Deep DWG Parsing: Handle Gap Analysis
        self._report_progress("handles", "start", "Analyzing handle map for deleted objects")
        handle_map: Optional[HandleMapResult] = None
        try:
            handle_map = self.handle_parser.parse(file_path)
            gap_count = len(handle_map.gaps) if handle_map.gaps else 0
            critical_gaps = sum(1 for g in (handle_map.gaps or []) if g.severity == "critical")
            if critical_gaps > 0:
                self._report_progress("handles", "complete", f"Gaps: {gap_count} ({critical_gaps} critical)")
            else:
                self._report_progress("handles", "complete", f"Handle gaps: {gap_count}")
        except Exception as e:
            self._report_progress("handles", "error", f"Handle analysis failed: {e}")

        # Phase 3: Anomaly detection (including advanced timestamp anomalies and NTFS cross-validation)
        self._report_progress("anomalies", "start", "Detecting anomalies")
        anomalies = self._detect_all_anomalies(
            header_analysis, crc_validation, trusted_dwg, file_path,
            timestamp_data=timestamp_data, metadata=metadata,
            ntfs_data=ntfs_data, ntfs_contradictions=ntfs_contradictions
        )
        self._report_progress("anomalies", "complete", f"Anomalies detected: {len(anomalies)}")

        # Phase 3: Tampering rule evaluation (with NTFS cross-validation data + deep parsing)
        self._report_progress("rules", "start", "Evaluating tampering rules")
        rule_context = self._build_rule_context(
            header_analysis, crc_validation, trusted_dwg, file_path,
            timestamp_data=timestamp_data, anomalies=anomalies, metadata=metadata,
            ntfs_data=ntfs_data, ntfs_contradictions=ntfs_contradictions,
            section_map=section_map, drawing_vars=drawing_vars, handle_map=handle_map,
            fingerprint=fingerprint_result,
        )
        rule_results = self.rule_engine.evaluate_all(rule_context)
        failed_rules = self.rule_engine.get_failed_rules(rule_results)
        self._report_progress("rules", "complete", f"Rules triggered: {len(failed_rules)}")

        # Phase 3: Detect tampering indicators (version-aware, with NTFS cross-validation)
        self._report_progress("tampering", "start", "Analyzing tampering indicators")
        tampering_indicators = self._detect_tampering(
            crc_validation, trusted_dwg, failed_rules, version_string,
            timestamp_data=timestamp_data, ntfs_data=ntfs_data,
            ntfs_contradictions=ntfs_contradictions
        )
        self._report_progress("tampering", "complete", f"Indicators: {len(tampering_indicators)}")

        # Build NTFS analysis model for output
        ntfs_analysis = self._build_ntfs_analysis(ntfs_data, ntfs_contradictions, metadata)

        # Phase 3: Risk assessment with scoring
        self._report_progress("risk", "start", "Calculating risk score")
        risk_assessment = self._assess_risk_phase3(
            anomalies, tampering_indicators, failed_rules,
            crc_validation, trusted_dwg
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

        return ForensicAnalysis(
            file_info=file_info,
            header_analysis=header_analysis,
            trusted_dwg=trusted_dwg,
            crc_validation=crc_validation,
            metadata=metadata,
            ntfs_analysis=ntfs_analysis,
            application_fingerprint=app_fingerprint,
            anomalies=anomalies,
            tampering_indicators=tampering_indicators,
            risk_assessment=risk_assessment,
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

        # Detect watermark (version-aware)
        trusted_dwg = self.watermark_detector.detect(
            file_path, version_string=version_string
        )

        # Anomaly detection
        anomalies = self._detect_all_anomalies(
            header_analysis, crc_validation, trusted_dwg, file_path
        )

        # Tampering rule evaluation
        rule_context = self._build_rule_context(
            header_analysis, crc_validation, trusted_dwg, file_path
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
            crc_validation, trusted_dwg, failed_rules, version_string
        )

        # Generate comprehensive report
        return self.risk_scorer.generate_report(
            file_path=file_path,
            header=header_analysis,
            crc_validation=crc_validation,
            trusted_dwg=trusted_dwg,
            metadata=None,
            anomalies=anomalies,
            rule_failures=failed_rules_dicts,
            tampering_indicators=tampering_indicators,
        )

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
        trusted_dwg: TrustedDWGAnalysis,
        file_path: Path,
        timestamp_data: Optional[TimestampData] = None,
        metadata: Optional[DWGMetadata] = None,
        ntfs_data: Optional[NTFSForensicData] = None,
        ntfs_contradictions: Optional[Dict[str, Any]] = None,
    ) -> List[Anomaly]:
        """Detect all anomalies using Phase 3 AnomalyDetector.

        Args:
            header_analysis: Header analysis results
            crc_validation: CRC validation results
            trusted_dwg: TrustedDWG analysis results
            file_path: Path to the DWG file
            timestamp_data: Optional parsed timestamp data for advanced detection
            metadata: Optional DWG metadata
            ntfs_data: Optional NTFS forensic data for cross-validation
            ntfs_contradictions: Optional dict of NTFS/DWG contradictions

        Returns:
            List of detected anomalies
        """
        anomalies = []

        # Use Phase 3 anomaly detector for version and structural anomalies
        version_anomalies = self.anomaly_detector.detect_version_anomalies(
            header_analysis, file_path
        )
        anomalies.extend(version_anomalies)

        structural_anomalies = self.anomaly_detector.detect_structural_anomalies(file_path)
        anomalies.extend(structural_anomalies)

        # Timestamp anomalies (if metadata available)
        if metadata:
            timestamp_anomalies = self.anomaly_detector.detect_timestamp_anomalies(
                metadata, file_path
            )
            anomalies.extend(timestamp_anomalies)

        # Advanced timestamp manipulation detection (if timestamp_data available)
        if timestamp_data:
            advanced_anomalies = self.anomaly_detector.detect_advanced_timestamp_anomalies(
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

        # Invalid watermark anomaly
        if trusted_dwg.watermark_present and not trusted_dwg.watermark_valid:
            anomalies.append(
                Anomaly(
                    anomaly_type=AnomalyType.WATERMARK_INVALID,
                    description="TrustedDWG watermark present but invalid",
                    severity=RiskLevel.MEDIUM,
                    details={"watermark_text": trusted_dwg.watermark_text},
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

            # Nanosecond truncation = Tool signature
            if ntfs_data.nanoseconds_truncated:
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

            # Creation after modification = Impossible condition
            if ntfs_data.creation_after_modification:
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.NTFS_CREATION_AFTER_MODIFICATION,
                        description=(
                            "IMPOSSIBLE TIMESTAMP ORDER: File creation timestamp is later than "
                            "modification timestamp. This is physically impossible and proves "
                            "deliberate timestamp manipulation."
                        ),
                        severity=RiskLevel.CRITICAL,
                        details={
                            "created": str(ntfs_data.si_timestamps.created) if ntfs_data.si_timestamps.created else None,
                            "modified": str(ntfs_data.si_timestamps.modified) if ntfs_data.si_timestamps.modified else None,
                            "forensic_conclusion": "Timestamps have been manipulated to create an impossible state",
                        },
                    )
                )

        # DWG vs NTFS contradictions
        if ntfs_contradictions:
            if ntfs_contradictions.get("creation_contradiction"):
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.DWG_NTFS_CREATION_CONTRADICTION,
                        description=(
                            "PROVEN BACKDATING: DWG internal creation timestamp predates the "
                            "NTFS filesystem creation timestamp. The file claims to have been "
                            "created before it existed on this filesystem."
                        ),
                        severity=RiskLevel.CRITICAL,
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
        trusted_dwg: TrustedDWGAnalysis,
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
    ) -> Dict[str, Any]:
        """Build context dictionary for tampering rule evaluation.

        Args:
            header_analysis: Header analysis results
            crc_validation: CRC validation results
            trusted_dwg: TrustedDWG analysis results
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

        Returns:
            Context dictionary for rule evaluation
        """
        # Derive is_autodesk from watermark validity
        # A valid TrustedDWG watermark indicates Autodesk origin
        is_autodesk = (
            trusted_dwg.watermark_present and
            trusted_dwg.watermark_valid
        )

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
            },
            "watermark": {
                "present": trusted_dwg.watermark_present,
                "valid": trusted_dwg.watermark_valid,
                "text": trusted_dwg.watermark_text,
                "is_autodesk": is_autodesk,
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
                    s.section_type.name == "HEADER" for s in sections_list
                ),
                "has_handles_section": any(
                    s.section_type.name == "HANDLES" for s in sections_list
                ),
                "error": section_map.parsing_errors[0] if section_map.parsing_errors else None,
                "version_format": section_map.file_version,
            }

        # Drawing variables data (extracted TDCREATE/TDUPDATE from binary)
        if drawing_vars:
            context["drawing_vars"] = {
                "tdcreate": {
                    "julian_day": drawing_vars.tdcreate.julian_day if drawing_vars.tdcreate else None,
                    "fraction": drawing_vars.tdcreate.fraction if drawing_vars.tdcreate else None,
                    "datetime": drawing_vars.tdcreate.datetime.isoformat() if drawing_vars.tdcreate and drawing_vars.tdcreate.datetime else None,
                } if drawing_vars.tdcreate else None,
                "tdupdate": {
                    "julian_day": drawing_vars.tdupdate.julian_day if drawing_vars.tdupdate else None,
                    "fraction": drawing_vars.tdupdate.fraction if drawing_vars.tdupdate else None,
                    "datetime": drawing_vars.tdupdate.datetime.isoformat() if drawing_vars.tdupdate and drawing_vars.tdupdate.datetime else None,
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
            context["fingerprint"] = {
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

        return context

    def _detect_tampering(
        self,
        crc_validation: CRCValidation,
        trusted_dwg: TrustedDWGAnalysis,
        failed_rules: List[Any],
        version_string: Optional[str] = None,
        timestamp_data: Optional[TimestampData] = None,
        ntfs_data: Optional[NTFSForensicData] = None,
        ntfs_contradictions: Optional[Dict[str, Any]] = None,
    ) -> List[TamperingIndicator]:
        """Detect tampering indicators with definitive forensic conclusions.

        Args:
            crc_validation: CRC validation results
            trusted_dwg: TrustedDWG analysis results
            failed_rules: List of failed tampering rules
            version_string: DWG version string for version-aware detection
            timestamp_data: Optional parsed timestamp data
            ntfs_data: Optional NTFS forensic data for cross-validation
            ntfs_contradictions: Optional dict of NTFS/DWG contradictions

        Returns:
            List of tampering indicators with forensic conclusions
        """
        indicators = []

        # CRC modification (only if CRC is available for this version)
        # "N/A" indicates version doesn't support CRC
        if crc_validation.header_crc_stored != "N/A" and not crc_validation.is_valid:
            indicators.append(
                TamperingIndicator(
                    indicator_type=TamperingIndicatorType.CRC_MODIFIED,
                    description="File header CRC does not match, indicating modification after save",
                    confidence=0.9,
                    evidence=f"Stored CRC: {crc_validation.header_crc_stored}, "
                    f"Calculated CRC: {crc_validation.header_crc_calculated}",
                )
            )

        # Missing watermark (only for versions that support TrustedDWG - AC1021+)
        # Check if watermark is expected for this version
        watermark_expected = self.watermark_detector.has_watermark_support(
            version_string
        ) if version_string else True

        if watermark_expected and not trusted_dwg.watermark_present:
            indicators.append(
                TamperingIndicator(
                    indicator_type=TamperingIndicatorType.WATERMARK_REMOVED,
                    description="TrustedDWG watermark not found - file may have been modified by "
                    "third-party software or watermark was removed",
                    confidence=0.7,
                    evidence="No Autodesk DWG watermark marker found in file",
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

            # Nanosecond truncation = Tool signature
            if ntfs_data.nanoseconds_truncated:
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

            # Creation after modification = Impossible
            if ntfs_data.creation_after_modification:
                indicators.append(
                    TamperingIndicator(
                        indicator_type=TamperingIndicatorType.NTFS_IMPOSSIBLE_TIMESTAMP,
                        description=(
                            "IMPOSSIBLE TIMESTAMP CONDITION: File creation timestamp is later "
                            "than modification timestamp. This proves deliberate manipulation."
                        ),
                        confidence=1.0,
                        evidence=(
                            f"Created: {ntfs_data.si_timestamps.created}, "
                            f"Modified: {ntfs_data.si_timestamps.modified}"
                        ),
                    )
                )

        # DWG vs NTFS contradictions = Backdating proof
        if ntfs_contradictions:
            if ntfs_contradictions.get("creation_contradiction"):
                indicators.append(
                    TamperingIndicator(
                        indicator_type=TamperingIndicatorType.PROVEN_BACKDATING,
                        description=(
                            "PROVEN BACKDATING: DWG internal creation timestamp predates NTFS "
                            "filesystem creation. The file claims to exist before it was created."
                        ),
                        confidence=1.0,
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
        trusted_dwg: TrustedDWGAnalysis,
    ) -> RiskAssessment:
        """Assess overall risk level using Phase 3 scoring algorithm.

        Args:
            anomalies: List of detected anomalies
            tampering_indicators: List of tampering indicators
            failed_rules: List of failed tampering rules
            crc_validation: CRC validation results
            trusted_dwg: TrustedDWG analysis results

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
            anomalies, failed_rules_dicts, tampering_indicators,
            crc_validation, trusted_dwg
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
            "creation_contradiction": False,
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
                # DWG claims creation BEFORE filesystem creation = BACKDATING
                contradictions["creation_contradiction"] = True
                contradictions["creation_details"] = {
                    "dwg_created": dwg_created.isoformat(),
                    "ntfs_created": ntfs_created.isoformat(),
                    "difference_hours": round(time_diff, 2),
                    "forensic_conclusion": (
                        f"DWG claims creation {round(time_diff, 1)} hours before "
                        f"filesystem creation. This is PROVEN BACKDATING."
                    ),
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
                "IMPOSSIBLE STATE: Creation timestamp is later than modification timestamp."
            )

        contradiction_details = None
        dwg_ntfs_contradiction = False
        if ntfs_contradictions:
            if ntfs_contradictions.get("creation_contradiction"):
                dwg_ntfs_contradiction = True
                conclusions.append(
                    ntfs_contradictions.get("creation_details", {}).get(
                        "forensic_conclusion", "DWG/NTFS creation timestamp contradiction."
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
