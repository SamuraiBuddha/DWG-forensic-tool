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
    CRCValidation,
    FileInfo,
    ForensicAnalysis,
    HeaderAnalysis,
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

    def __init__(self, custom_rules_path: Optional[Path] = None):
        """Initialize the forensic analyzer with all required parsers.

        Args:
            custom_rules_path: Optional path to custom tampering rules YAML/JSON file
        """
        # Phase 1 parsers
        self.header_parser = HeaderParser()
        self.crc_validator = CRCValidator()
        self.watermark_detector = WatermarkDetector()

        # Timestamp parser for advanced forensic analysis
        self.timestamp_parser = TimestampParser()

        # Phase 3 analyzers
        self.anomaly_detector = AnomalyDetector()
        self.rule_engine = TamperingRuleEngine()
        self.risk_scorer = RiskScorer()

        # Load custom rules if provided
        if custom_rules_path:
            self.rule_engine.load_rules(custom_rules_path)

    def analyze(self, file_path: Path) -> ForensicAnalysis:
        """Perform complete forensic analysis on a DWG file.

        Includes Phase 3 tampering detection:
        - Anomaly detection (timestamp, version, structural)
        - Tampering rule evaluation (12 built-in + custom rules)
        - Risk scoring with weighted algorithm

        Args:
            file_path: Path to the DWG file to analyze

        Returns:
            ForensicAnalysis model containing complete analysis results

        Raises:
            DWGForensicError: If analysis fails
        """
        file_path = Path(file_path)

        # Collect file info
        file_info = self._collect_file_info(file_path)

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

        # Parse timestamps for advanced forensic analysis
        timestamp_data = self.timestamp_parser.parse(file_path, version_string)

        # Build metadata from timestamp data
        metadata = self._build_metadata_from_timestamps(timestamp_data)

        # Phase 3: Anomaly detection (including advanced timestamp anomalies)
        anomalies = self._detect_all_anomalies(
            header_analysis, crc_validation, trusted_dwg, file_path,
            timestamp_data=timestamp_data, metadata=metadata
        )

        # Phase 3: Tampering rule evaluation
        rule_context = self._build_rule_context(
            header_analysis, crc_validation, trusted_dwg, file_path,
            timestamp_data=timestamp_data, anomalies=anomalies, metadata=metadata
        )
        rule_results = self.rule_engine.evaluate_all(rule_context)
        failed_rules = self.rule_engine.get_failed_rules(rule_results)

        # Phase 3: Detect tampering indicators (version-aware)
        tampering_indicators = self._detect_tampering(
            crc_validation, trusted_dwg, failed_rules, version_string,
            timestamp_data=timestamp_data
        )

        # Phase 3: Risk assessment with scoring
        risk_assessment = self._assess_risk_phase3(
            anomalies, tampering_indicators, failed_rules,
            crc_validation, trusted_dwg
        )

        return ForensicAnalysis(
            file_info=file_info,
            header_analysis=header_analysis,
            trusted_dwg=trusted_dwg,
            crc_validation=crc_validation,
            metadata=metadata,
            application_fingerprint=None,  # Application fingerprinting in future phase
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
    ) -> List[Anomaly]:
        """Detect all anomalies using Phase 3 AnomalyDetector.

        Args:
            header_analysis: Header analysis results
            crc_validation: CRC validation results
            trusted_dwg: TrustedDWG analysis results
            file_path: Path to the DWG file
            timestamp_data: Optional parsed timestamp data for advanced detection
            metadata: Optional DWG metadata

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

        return context

    def _detect_tampering(
        self,
        crc_validation: CRCValidation,
        trusted_dwg: TrustedDWGAnalysis,
        failed_rules: List[Any],
        version_string: Optional[str] = None,
        timestamp_data: Optional[TimestampData] = None,
    ) -> List[TamperingIndicator]:
        """Detect potential tampering indicators.

        Args:
            crc_validation: CRC validation results
            trusted_dwg: TrustedDWG analysis results
            failed_rules: List of failed tampering rules
            version_string: DWG version string for version-aware detection
            timestamp_data: Optional parsed timestamp data

        Returns:
            List of tampering indicators
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
