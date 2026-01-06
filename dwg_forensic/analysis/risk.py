"""
DWG Forensic Tool - Risk Scoring Module

Implements risk assessment per PRD requirements:
- FR-TAMPER-003: Risk scoring with weighted algorithm
- Severity weights: INFO=1, WARNING=2, CRITICAL=4
- Risk thresholds: LOW (0), MEDIUM (1-3), HIGH (4-7), CRITICAL (8+)
"""

from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, ConfigDict, Field

from dwg_forensic.models import (
    Anomaly,
    RiskLevel,
    RiskAssessment,
    HeaderAnalysis,
    CRCValidation,
    TrustedDWGAnalysis,
    DWGMetadata,
    TamperingIndicator,
)


class TamperingReport(BaseModel):
    """Complete tampering analysis report."""

    file_path: str = Field(description="Path to analyzed file")
    analysis_timestamp: datetime = Field(default_factory=datetime.now)

    # Risk assessment
    risk_level: RiskLevel = Field(description="Overall risk level")
    risk_score: int = Field(description="Numeric risk score")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in assessment")

    # Analysis summaries
    anomaly_count: int = Field(default=0)
    rule_failures: int = Field(default=0)
    tampering_indicators: int = Field(default=0)

    # Detailed findings
    anomalies: List[Anomaly] = Field(default_factory=list)
    failed_rules: List[Dict[str, Any]] = Field(default_factory=list)
    indicators: List[TamperingIndicator] = Field(default_factory=list)

    # Risk factors
    factors: List[str] = Field(default_factory=list)
    recommendation: str = Field(default="")

    # Evidence integrity
    crc_valid: Optional[bool] = None
    watermark_valid: Optional[bool] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)


class RiskScorer:
    """
    Calculates risk scores based on anomalies, rule failures, and tampering indicators.

    Implements weighted scoring per PRD:
    - INFO severity: 1 point
    - WARNING severity: 2 points
    - CRITICAL severity: 4 points

    Risk level thresholds:
    - LOW: 0 points
    - MEDIUM: 1-3 points
    - HIGH: 4-7 points
    - CRITICAL: 8+ points
    """

    # Severity weights
    SEVERITY_WEIGHTS = {
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }

    # Risk level thresholds
    RISK_THRESHOLDS = {
        RiskLevel.LOW: 0,
        RiskLevel.MEDIUM: 1,
        RiskLevel.HIGH: 4,
        RiskLevel.CRITICAL: 8,
    }

    def __init__(self):
        """Initialize the risk scorer."""
        pass

    def calculate_score(
        self,
        anomalies: List[Anomaly],
        rule_failures: List[Dict[str, Any]],
        tampering_indicators: List[TamperingIndicator],
    ) -> int:
        """
        Calculate total risk score from all findings.

        Args:
            anomalies: List of detected anomalies
            rule_failures: List of failed tampering rules
            tampering_indicators: List of tampering indicators

        Returns:
            Total risk score
        """
        score = 0

        # Score from anomalies
        for anomaly in anomalies:
            weight = self.SEVERITY_WEIGHTS.get(anomaly.severity, 1)
            score += weight

        # Score from rule failures
        for failure in rule_failures:
            severity_str = failure.get("severity", "WARNING")
            # Convert string severity to RiskLevel if needed
            if isinstance(severity_str, str):
                severity_map = {
                    "INFO": RiskLevel.LOW,
                    "WARNING": RiskLevel.MEDIUM,
                    "CRITICAL": RiskLevel.CRITICAL,
                }
                severity = severity_map.get(severity_str.upper(), RiskLevel.MEDIUM)
            else:
                severity = severity_str
            weight = self.SEVERITY_WEIGHTS.get(severity, 2)
            score += weight

        # Score from tampering indicators (weighted by confidence)
        for indicator in tampering_indicators:
            base_weight = 3  # Default weight for tampering indicators
            confidence_factor = indicator.confidence if indicator.confidence else 0.5
            score += int(base_weight * confidence_factor)

        return score

    def score_to_risk_level(self, score: int) -> RiskLevel:
        """
        Convert numeric score to risk level.

        Args:
            score: Numeric risk score

        Returns:
            Corresponding RiskLevel
        """
        if score >= self.RISK_THRESHOLDS[RiskLevel.CRITICAL]:
            return RiskLevel.CRITICAL
        elif score >= self.RISK_THRESHOLDS[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        elif score >= self.RISK_THRESHOLDS[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def calculate_confidence(
        self,
        header: HeaderAnalysis,
        crc_validation: Optional[CRCValidation],
        metadata: Optional[DWGMetadata],
        anomaly_count: int,
    ) -> float:
        """
        Calculate confidence level in the assessment.

        Confidence is based on:
        - Amount of data available for analysis
        - Consistency of findings
        - File format support level

        Args:
            header: Header analysis results
            crc_validation: CRC validation results
            metadata: DWG metadata (if available)
            anomaly_count: Number of anomalies detected

        Returns:
            Confidence level between 0.0 and 1.0
        """
        confidence = 0.5  # Base confidence

        # Supported version increases confidence
        if header.is_supported:
            confidence += 0.2

        # CRC validation available
        if crc_validation is not None:
            confidence += 0.1
            if crc_validation.is_valid:
                confidence += 0.1

        # Metadata available
        if metadata is not None:
            confidence += 0.1

        # Many anomalies might indicate thorough analysis
        if anomaly_count > 3:
            confidence += 0.05

        # Cap at 0.95 - never 100% certain
        return min(confidence, 0.95)

    def generate_factors(
        self,
        anomalies: List[Anomaly],
        rule_failures: List[Dict[str, Any]],
        tampering_indicators: List[TamperingIndicator],
        crc_validation: Optional[CRCValidation],
        trusted_dwg: Optional[TrustedDWGAnalysis],
    ) -> List[str]:
        """
        Generate human-readable risk factors.

        Args:
            anomalies: List of detected anomalies
            rule_failures: List of failed tampering rules
            tampering_indicators: List of tampering indicators
            crc_validation: CRC validation results
            trusted_dwg: TrustedDWG analysis results

        Returns:
            List of risk factor descriptions
        """
        factors = []

        # CRC status
        if crc_validation:
            if crc_validation.is_valid:
                factors.append("[OK] Header CRC validation passed")
            else:
                factors.append("[FAIL] Header CRC validation failed - file may be modified")

        # Watermark status
        if trusted_dwg:
            if trusted_dwg.watermark_present and trusted_dwg.watermark_valid:
                factors.append("[OK] Valid TrustedDWG watermark found")
            elif trusted_dwg.watermark_present and not trusted_dwg.watermark_valid:
                factors.append("[WARN] TrustedDWG watermark present but invalid")
            else:
                factors.append("[INFO] No TrustedDWG watermark found")

        # Anomaly summary
        if anomalies:
            critical_count = sum(1 for a in anomalies if a.severity == RiskLevel.CRITICAL)
            high_count = sum(1 for a in anomalies if a.severity == RiskLevel.HIGH)

            if critical_count > 0:
                factors.append(f"[CRITICAL] {critical_count} critical anomaly(ies) detected")
            if high_count > 0:
                factors.append(f"[WARN] {high_count} high-severity anomaly(ies) detected")
            if len(anomalies) > critical_count + high_count:
                other_count = len(anomalies) - critical_count - high_count
                factors.append(f"[INFO] {other_count} other anomaly(ies) detected")

        # Rule failure summary
        if rule_failures:
            factors.append(f"[WARN] {len(rule_failures)} tampering rule(s) triggered")
            # List specific rule IDs
            rule_ids = [f.get("rule_id", "unknown") for f in rule_failures[:3]]
            factors.append(f"[INFO] Failed rules: {', '.join(rule_ids)}")

        # Tampering indicator summary
        if tampering_indicators:
            high_confidence = [i for i in tampering_indicators if i.confidence >= 0.8]
            if high_confidence:
                factors.append(
                    f"[CRITICAL] {len(high_confidence)} high-confidence tampering indicator(s)"
                )

        if not factors:
            factors.append("[OK] No significant issues detected")

        return factors

    def generate_recommendation(self, risk_level: RiskLevel, score: int) -> str:
        """
        Generate recommendation based on risk level.

        Args:
            risk_level: Calculated risk level
            score: Numeric risk score

        Returns:
            Recommendation text
        """
        recommendations = {
            RiskLevel.LOW: (
                "File appears authentic and unmodified. "
                "Standard handling procedures apply."
            ),
            RiskLevel.MEDIUM: (
                "Some anomalies detected (score: {score}). "
                "Recommend additional verification and documentation of findings "
                "before use in legal proceedings."
            ),
            RiskLevel.HIGH: (
                "Significant integrity issues detected (score: {score}). "
                "File may have been modified. Recommend expert review and "
                "comparison with known-good copies if available."
            ),
            RiskLevel.CRITICAL: (
                "Critical integrity failures detected (score: {score}). "
                "File should not be used as evidence without extensive forensic "
                "investigation and expert testimony."
            ),
        }

        return recommendations.get(risk_level, recommendations[RiskLevel.MEDIUM]).format(
            score=score
        )

    def generate_report(
        self,
        file_path: Path,
        header: HeaderAnalysis,
        crc_validation: Optional[CRCValidation],
        trusted_dwg: Optional[TrustedDWGAnalysis],
        metadata: Optional[DWGMetadata],
        anomalies: List[Anomaly],
        rule_failures: List[Dict[str, Any]],
        tampering_indicators: List[TamperingIndicator],
    ) -> TamperingReport:
        """
        Generate a complete tampering report.

        Args:
            file_path: Path to the analyzed file
            header: Header analysis results
            crc_validation: CRC validation results
            trusted_dwg: TrustedDWG analysis results
            metadata: DWG metadata
            anomalies: List of detected anomalies
            rule_failures: List of failed tampering rules
            tampering_indicators: List of tampering indicators

        Returns:
            Complete TamperingReport
        """
        # Calculate score and risk level
        score = self.calculate_score(anomalies, rule_failures, tampering_indicators)
        risk_level = self.score_to_risk_level(score)

        # Calculate confidence
        confidence = self.calculate_confidence(
            header, crc_validation, metadata, len(anomalies)
        )

        # Generate factors and recommendation
        factors = self.generate_factors(
            anomalies, rule_failures, tampering_indicators, crc_validation, trusted_dwg
        )
        recommendation = self.generate_recommendation(risk_level, score)

        return TamperingReport(
            file_path=str(file_path),
            analysis_timestamp=datetime.now(),
            risk_level=risk_level,
            risk_score=score,
            confidence=confidence,
            anomaly_count=len(anomalies),
            rule_failures=len(rule_failures),
            tampering_indicators=len(tampering_indicators),
            anomalies=anomalies,
            failed_rules=rule_failures,
            indicators=tampering_indicators,
            factors=factors,
            recommendation=recommendation,
            crc_valid=crc_validation.is_valid if crc_validation else None,
            watermark_valid=(
                trusted_dwg.watermark_valid if trusted_dwg and trusted_dwg.watermark_present else None
            ),
        )
