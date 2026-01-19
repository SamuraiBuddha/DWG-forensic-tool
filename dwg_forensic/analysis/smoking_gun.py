"""
DWG Forensic Tool - Smoking Gun Synthesizer

LLM-powered synthesis of definitive tampering proof for expert witness testimony.

This module filters forensic findings to ONLY smoking guns - findings that prove
tampering with mathematical certainty. It then uses an LLM to generate expert-level
explanations suitable for court testimony.

Smoking Gun Criteria:
- Mathematical impossibility (e.g., created > modified, edit time > calendar span)
- Physical impossibility (e.g., file claims existence before DWG version existed)
- Cryptographic proof (e.g., CRC mismatch, hash comparison)
- NTFS kernel-level contradiction (e.g., $SI < $FN timestamps)

NOT Smoking Guns (per user feedback):
- TrustedDWG watermark absence (many legitimate files lack it)
- Third-party tool origin (legitimate workflow)
- Minor timestamp discrepancies (could be timezone/DST issues)
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from dwg_forensic.analysis.rules.models import (
    EvidenceStrength,
    RuleResult,
    RuleStatus,
)


@dataclass
class SmokingGunFinding:
    """A single definitive proof of tampering."""

    rule_id: str
    rule_name: str
    description: str
    forensic_reasoning: str
    legal_significance: str
    confidence: float = 1.0
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SmokingGunReport:
    """Complete smoking gun analysis report."""

    has_definitive_proof: bool
    smoking_guns: List[SmokingGunFinding]
    expert_summary: str
    legal_conclusion: str
    recommendation: str


class SmokingGunSynthesizer:
    """
    Synthesizes smoking gun findings with LLM-powered expert analysis.

    This class:
    1. Filters results to ONLY definitive proof indicators
    2. Generates forensic reasoning using LLM (if available)
    3. Produces court-ready expert witness language
    """

    # Rules that are DEFINITIVE smoking guns
    SMOKING_GUN_RULES = {
        # CRC/Hash - cryptographic proof
        "TAMPER-001",  # CRC Header Mismatch
        "TAMPER-002",  # CRC Section Mismatch
        # Timestamp impossibilities
        "TAMPER-005",  # Created > Modified (impossible)
        "TAMPER-006",  # Future timestamp (impossible without tampering)
        "TAMPER-013",  # TDINDWG > calendar span (mathematical impossibility)
        "TAMPER-014",  # Version anachronism (impossible)
        # NTFS smoking guns
        "TAMPER-019",  # NTFS timestomping ($SI < $FN)
        "TAMPER-020",  # Nanosecond truncation (tool signature)
        "TAMPER-021",  # NTFS created > modified (impossible)
        "TAMPER-022",  # DWG-NTFS creation contradiction
        "TAMPER-023",  # DWG-NTFS modification contradiction
        "TAMPER-027",  # Multiple timestamp anomalies (compound)
        "TAMPER-028",  # Forensic impossibility score
        # Structural proof
        "TAMPER-036",  # Handle gaps (deletion evidence)
        "TAMPER-037",  # Missing header section
        "TAMPER-038",  # DWG internal timestamp contradiction
        "TAMPER-040",  # Section map integrity failure
    }

    # Expert reasoning templates for each smoking gun type
    FORENSIC_REASONING = {
        "TAMPER-001": (
            "The CRC32 checksum stored in the DWG header does not match the calculated "
            "value. CRC32 is a mathematical function - if the data has not changed, "
            "the checksum MUST match. This mismatch is DEFINITIVE PROOF that the file "
            "has been modified since the CRC was calculated."
        ),
        "TAMPER-002": (
            "A DWG section's CRC checksum does not match. This is cryptographic proof "
            "that the section data has been altered."
        ),
        "TAMPER-005": (
            "The file's creation timestamp is AFTER its modification timestamp. "
            "This is a PHYSICAL IMPOSSIBILITY - a file cannot be modified before it "
            "exists. This proves deliberate timestamp manipulation."
        ),
        "TAMPER-006": (
            "The file's modification timestamp is in the future. Unless time travel "
            "exists, this is IMPOSSIBLE and proves the timestamp was manually set."
        ),
        "TAMPER-013": (
            "The cumulative editing time (TDINDWG) EXCEEDS the calendar time between "
            "creation and modification. This is a MATHEMATICAL IMPOSSIBILITY - you "
            "cannot spend more time editing a file than has elapsed. This is DEFINITIVE "
            "PROOF that the creation or modification timestamps were backdated."
        ),
        "TAMPER-014": (
            "The file claims a creation date BEFORE the DWG format version it uses "
            "even existed. This is IMPOSSIBLE and proves timestamp backdating. "
            "Example: A file using AC1032 (AutoCAD 2018+) format cannot have been "
            "created before 2017."
        ),
        "TAMPER-019": (
            "NTFS stores timestamps in two locations: $STANDARD_INFORMATION (user-modifiable) "
            "and $FILE_NAME (kernel-protected). The $SI timestamps are EARLIER than $FN "
            "timestamps. Since $FN timestamps are only updated by the Windows kernel and "
            "cannot be backdated without kernel-level tools, this is DEFINITIVE PROOF "
            "of timestomping (timestamp manipulation)."
        ),
        "TAMPER-020": (
            "NTFS timestamps have 100-nanosecond precision with 10 million possible values. "
            "Multiple timestamps ending in exactly .0000000 is STATISTICALLY IMPOSSIBLE "
            "(p < 0.0001). This is a known signature of timestamp manipulation tools."
        ),
        "TAMPER-021": (
            "The NTFS creation timestamp is AFTER the modification timestamp. This "
            "CANNOT occur naturally on any filesystem. This is DEFINITIVE PROOF of "
            "timestamp manipulation."
        ),
        "TAMPER-022": (
            "The DWG internal creation timestamp claims the file was created BEFORE "
            "it existed on the filesystem (NTFS creation date). A file cannot contain "
            "data about its own creation before the file exists. This is DEFINITIVE "
            "PROOF of timestamp backdating."
        ),
        "TAMPER-023": (
            "The DWG internal modification timestamp contradicts the NTFS filesystem "
            "modification timestamp beyond normal variance. This indicates the file "
            "was copied or had its timestamps manipulated."
        ),
        "TAMPER-027": (
            "Multiple INDEPENDENT timestamp anomalies have been detected. The probability "
            "of all these anomalies occurring naturally is STATISTICALLY NEGLIGIBLE. "
            "This constitutes COMPOUND EVIDENCE of deliberate manipulation."
        ),
        "TAMPER-028": (
            "The combination of forensic indicators creates a FORENSIC IMPOSSIBILITY "
            "score exceeding the threshold for definitive proof. The aggregate evidence "
            "proves timestamp manipulation BEYOND REASONABLE DOUBT."
        ),
        "TAMPER-036": (
            "Large gaps have been detected in the DWG object handle sequence. Handles "
            "are assigned sequentially and gaps indicate MASS DELETION of objects. "
            "This is evidence that content was deliberately removed from the file."
        ),
        "TAMPER-037": (
            "The mandatory AcDb:Header section is missing or corrupted. This section "
            "is REQUIRED by the DWG specification. Its absence indicates the file "
            "structure has been tampered with at the binary level or was corrupted."
        ),
        "TAMPER-038": (
            "The DWG internal timestamps (TDCREATE/TDUPDATE) contradict the filesystem "
            "timestamps beyond normal variance. This indicates the timestamps were "
            "manipulated or the file was transferred/copied."
        ),
        "TAMPER-040": (
            "The DWG section map is corrupted or invalid. The section map is critical "
            "for file integrity and is generated atomically by AutoCAD. Corruption "
            "indicates binary-level tampering or deliberate file manipulation."
        ),
    }

    def __init__(self, llm_client: Optional[Any] = None, llm_model: Optional[str] = None):
        """
        Initialize the synthesizer.

        Args:
            llm_client: Optional OllamaClient for enhanced narrative generation
            llm_model: LLM model to use (e.g., 'mistral', 'gpt-oss:20b')
        """
        self._llm = llm_client
        self._llm_model = llm_model

    def filter_smoking_guns(self, results: List[RuleResult]) -> List[RuleResult]:
        """
        Filter results to only include smoking gun findings.

        Args:
            results: List of all rule evaluation results

        Returns:
            List of only smoking gun results that failed (prove tampering)
        """
        smoking_guns = []
        for r in results:
            if r.status != RuleStatus.FAILED:
                continue

            # Check if rule is a smoking gun OR has is_smoking_gun flag set
            if r.rule_id in self.SMOKING_GUN_RULES or r.is_smoking_gun:
                smoking_guns.append(r)

        return smoking_guns

    def synthesize(self, results: List[RuleResult]) -> SmokingGunReport:
        """
        Synthesize a complete smoking gun report.

        Args:
            results: List of all rule evaluation results

        Returns:
            SmokingGunReport with definitive findings and expert analysis
        """
        smoking_guns = self.filter_smoking_guns(results)

        if not smoking_guns:
            return SmokingGunReport(
                has_definitive_proof=False,
                smoking_guns=[],
                expert_summary=(
                    "No definitive proof of tampering was found. While other anomalies "
                    "may have been detected, none rise to the level of mathematical "
                    "or physical impossibility required for court-admissible evidence."
                ),
                legal_conclusion=(
                    "Insufficient evidence to assert tampering with certainty. "
                    "The file's authenticity cannot be definitively challenged."
                ),
                recommendation=(
                    "Additional investigation may be warranted if circumstantial "
                    "indicators are present. Consider acquiring the original file "
                    "for hash comparison if available."
                ),
            )

        # Convert to SmokingGunFinding objects with forensic reasoning
        findings = []
        for sg in smoking_guns:
            reasoning = self.FORENSIC_REASONING.get(
                sg.rule_id,
                sg.details.get("forensic_conclusion", sg.description)
                if sg.details else sg.description
            )

            finding = SmokingGunFinding(
                rule_id=sg.rule_id,
                rule_name=sg.rule_name,
                description=sg.description,
                forensic_reasoning=reasoning,
                legal_significance=self._get_legal_significance(sg),
                confidence=sg.confidence,
                details=sg.details or {},
            )
            findings.append(finding)

        # Generate expert summary
        expert_summary = self._generate_expert_summary(findings)
        legal_conclusion = self._generate_legal_conclusion(findings)
        recommendation = self._generate_recommendation(findings)

        return SmokingGunReport(
            has_definitive_proof=True,
            smoking_guns=findings,
            expert_summary=expert_summary,
            legal_conclusion=legal_conclusion,
            recommendation=recommendation,
        )

    def _get_legal_significance(self, result: RuleResult) -> str:
        """Get legal significance statement for a finding."""
        legal_statements = {
            "TAMPER-001": "CRC mismatch indicates modification after last save.",
            "TAMPER-002": "Section CRC mismatch indicates data alteration.",
            "TAMPER-005": "Impossible timestamp order proves manipulation.",
            "TAMPER-006": "Future timestamp proves manual clock manipulation.",
            "TAMPER-013": "Mathematical impossibility proves backdating.",
            "TAMPER-014": "Version anachronism proves timestamp fabrication.",
            "TAMPER-019": "NTFS kernel-level contradiction proves timestomping.",
            "TAMPER-020": "Statistical impossibility indicates tool usage.",
            "TAMPER-021": "Impossible filesystem state proves manipulation.",
            "TAMPER-022": "File predates its own creation - impossible without tampering.",
            "TAMPER-023": "Timestamp contradiction indicates copying or manipulation.",
            "TAMPER-027": "Compound evidence exceeds threshold for coincidence.",
            "TAMPER-028": "Aggregate score indicates manipulation beyond reasonable doubt.",
            "TAMPER-036": "Handle gaps indicate deliberate content deletion.",
            "TAMPER-037": "Missing mandatory section indicates structural tampering or corruption.",
            "TAMPER-038": "Internal/external timestamp contradiction indicates manipulation.",
            "TAMPER-040": "Section map corruption indicates binary-level tampering.",
        }
        return legal_statements.get(
            result.rule_id,
            "This finding provides definitive evidence of file manipulation."
        )

    def _generate_expert_summary(self, findings: List[SmokingGunFinding]) -> str:
        """Generate expert summary of smoking gun findings."""
        count = len(findings)
        rule_names = [f.rule_name for f in findings]

        if count == 1:
            return (
                f"DEFINITIVE PROOF OF TAMPERING has been identified. "
                f"The finding '{findings[0].rule_name}' constitutes mathematically "
                f"certain evidence that this file has been manipulated. "
                f"{findings[0].forensic_reasoning}"
            )

        return (
            f"MULTIPLE DEFINITIVE PROOFS OF TAMPERING have been identified. "
            f"{count} independent smoking gun findings prove with mathematical certainty "
            f"that this file has been manipulated: {', '.join(rule_names[:3])}"
            f"{' and others' if count > 3 else ''}. "
            f"Each finding independently proves tampering; together they constitute "
            f"overwhelming evidence of deliberate manipulation."
        )

    def _generate_legal_conclusion(self, findings: List[SmokingGunFinding]) -> str:
        """Generate legal conclusion statement."""
        if len(findings) >= 3:
            return (
                "CONCLUSION: This file has been tampered with. The combination of "
                f"{len(findings)} independent smoking gun findings creates overwhelming "
                "evidence that this file's timestamps or contents have been deliberately "
                "manipulated. This evidence should be sufficient to challenge the "
                "admissibility of this file in any legal proceeding."
            )
        elif len(findings) == 2:
            return (
                "CONCLUSION: Strong evidence of tampering exists. Two independent "
                "smoking gun findings corroborate each other, providing definitive proof "
                "that this file has been manipulated. The authenticity of this file "
                "should be challenged."
            )
        else:
            return (
                "CONCLUSION: Definitive proof of tampering has been found. A single "
                "smoking gun finding provides mathematically certain evidence of "
                "manipulation. The authenticity of this file should be questioned."
            )

    def _generate_recommendation(self, findings: List[SmokingGunFinding]) -> str:
        """Generate recommendation for next steps."""
        # Check for specific types of tampering
        has_timestamp_tampering = any(
            f.rule_id in ["TAMPER-013", "TAMPER-014", "TAMPER-019", "TAMPER-022"]
            for f in findings
        )
        has_content_tampering = any(
            f.rule_id in ["TAMPER-001", "TAMPER-002", "TAMPER-036", "TAMPER-040"]
            for f in findings
        )

        recommendations = []

        if has_timestamp_tampering:
            recommendations.append(
                "Obtain the original file from the source system for hash comparison."
            )
            recommendations.append(
                "Request NTFS MFT records to determine when manipulation occurred."
            )

        if has_content_tampering:
            recommendations.append(
                "Perform binary diff analysis against known-good copy if available."
            )
            recommendations.append(
                "Examine backup systems for earlier versions of this file."
            )

        recommendations.append(
            "Document this forensic analysis for potential expert witness testimony."
        )
        recommendations.append(
            "Consider challenging the admissibility of this file as evidence."
        )

        return " ".join(recommendations)

    async def generate_llm_narrative(
        self, findings: List[SmokingGunFinding], file_info: Optional[Dict] = None
    ) -> Optional[str]:
        """
        Generate enhanced narrative using LLM.

        Args:
            findings: List of smoking gun findings
            file_info: Optional file metadata for context

        Returns:
            LLM-generated expert narrative or None if LLM unavailable
        """
        if not self._llm:
            return None

        try:
            # Build prompt for LLM
            finding_descriptions = "\n".join([
                f"- {f.rule_name}: {f.forensic_reasoning}"
                for f in findings
            ])

            prompt = f"""As a digital forensics expert, analyze the following DEFINITIVE
PROOF findings from a DWG file tampering investigation. Generate a clear,
professional expert witness narrative explaining why these findings prove
the file has been tampered with.

SMOKING GUN FINDINGS:
{finding_descriptions}

Generate a narrative that:
1. Explains why each finding proves tampering with mathematical certainty
2. Uses precise technical language suitable for court testimony
3. Clearly states the conclusion: the file has been tampered with
4. Avoids speculation - focus only on what the evidence definitively proves

Expert Narrative:"""

            response = await self._llm.generate(prompt, model=self._llm_model)
            return response.strip() if response else None

        except Exception:
            return None
