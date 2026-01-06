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
from dwg_forensic.parsers import CRCValidator, HeaderParser, WatermarkDetector
from dwg_forensic.utils.exceptions import DWGForensicError

# Phase 3 imports
from dwg_forensic.analysis import (
    AnomalyDetector,
    TamperingRuleEngine,
    RiskScorer,
    TamperingReport,
)


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

        # Parse header
        header_analysis = self.header_parser.parse(file_path)

        # Validate CRC
        crc_validation = self.crc_validator.validate_header_crc(file_path)

        # Detect watermark
        trusted_dwg = self.watermark_detector.detect(file_path)

        # Phase 3: Anomaly detection
        anomalies = self._detect_all_anomalies(
            header_analysis, crc_validation, trusted_dwg, file_path
        )

        # Phase 3: Tampering rule evaluation
        rule_context = self._build_rule_context(
            header_analysis, crc_validation, trusted_dwg, file_path
        )
        rule_results = self.rule_engine.evaluate_all(rule_context)
        failed_rules = self.rule_engine.get_failed_rules(rule_results)

        # Phase 3: Detect tampering indicators
        tampering_indicators = self._detect_tampering(
            crc_validation, trusted_dwg, failed_rules
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
            metadata=None,  # Metadata extraction handled by metadata module
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

        # Parse header
        header_analysis = self.header_parser.parse(file_path)

        # Validate CRC
        crc_validation = self.crc_validator.validate_header_crc(file_path)

        # Detect watermark
        trusted_dwg = self.watermark_detector.detect(file_path)

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

        # Detect tampering indicators
        tampering_indicators = self._detect_tampering(
            crc_validation, trusted_dwg, failed_rules
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

    def _detect_all_anomalies(
        self,
        header_analysis: HeaderAnalysis,
        crc_validation: CRCValidation,
        trusted_dwg: TrustedDWGAnalysis,
        file_path: Path,
    ) -> List[Anomaly]:
        """Detect all anomalies using Phase 3 AnomalyDetector.

        Args:
            header_analysis: Header analysis results
            crc_validation: CRC validation results
            trusted_dwg: TrustedDWG analysis results
            file_path: Path to the DWG file

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
    ) -> Dict[str, Any]:
        """Build context dictionary for tampering rule evaluation.

        Args:
            header_analysis: Header analysis results
            crc_validation: CRC validation results
            trusted_dwg: TrustedDWG analysis results
            file_path: Path to the DWG file

        Returns:
            Context dictionary for rule evaluation
        """
        # Derive is_autodesk from watermark validity
        # A valid TrustedDWG watermark indicates Autodesk origin
        is_autodesk = (
            trusted_dwg.watermark_present and
            trusted_dwg.watermark_valid
        )

        return {
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

    def _detect_tampering(
        self,
        crc_validation: CRCValidation,
        trusted_dwg: TrustedDWGAnalysis,
        failed_rules: List[Any],
    ) -> List[TamperingIndicator]:
        """Detect potential tampering indicators.

        Args:
            crc_validation: CRC validation results
            trusted_dwg: TrustedDWG analysis results
            failed_rules: List of failed tampering rules

        Returns:
            List of tampering indicators
        """
        indicators = []

        # CRC modification
        if not crc_validation.is_valid:
            indicators.append(
                TamperingIndicator(
                    indicator_type=TamperingIndicatorType.CRC_MODIFIED,
                    description="File header CRC does not match, indicating modification after save",
                    confidence=0.9,
                    evidence=f"Stored CRC: {crc_validation.header_crc_stored}, "
                    f"Calculated CRC: {crc_validation.header_crc_calculated}",
                )
            )

        # Missing watermark (potential third-party modification)
        if not trusted_dwg.watermark_present:
            indicators.append(
                TamperingIndicator(
                    indicator_type=TamperingIndicatorType.WATERMARK_REMOVED,
                    description="TrustedDWG watermark not found - file may have been modified by "
                    "third-party software or watermark was removed",
                    confidence=0.7,
                    evidence="No Autodesk DWG watermark marker found in file",
                )
            )

        # Add indicators from failed tampering rules
        for rule_result in failed_rules:
            # High severity rules indicate stronger tampering evidence
            confidence = 0.8 if rule_result.severity.value == "CRITICAL" else 0.6
            # Build evidence string from available fields
            evidence_parts = []
            if rule_result.expected:
                evidence_parts.append(f"Expected: {rule_result.expected}")
            if rule_result.found:
                evidence_parts.append(f"Found: {rule_result.found}")
            evidence = "; ".join(evidence_parts) if evidence_parts else rule_result.description
            indicators.append(
                TamperingIndicator(
                    indicator_type=TamperingIndicatorType.SUSPICIOUS_PATTERN,
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
