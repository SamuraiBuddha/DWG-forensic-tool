"""
DWG Forensic Tool - Forensic Narrator

LLM-powered narrative generator for forensic reports.
Uses a specialized forensic expert persona with comprehensive
forensic knowledge and strict reasoning requirements.
"""

import logging
from dataclasses import dataclass
from typing import Optional

from dwg_forensic.llm.ollama_client import OllamaClient
from dwg_forensic.models import ForensicAnalysis, TamperingIndicator, Anomaly

logger = logging.getLogger(__name__)


# =============================================================================
# COMPREHENSIVE FORENSIC EXPERT SYSTEM PROMPT
# =============================================================================
# This prompt establishes:
# 1. Expert credentials and persona
# 2. Deep forensic knowledge about DWG files and NTFS
# 3. Cross-validation methodology
# 4. Strict reasoning requirements
# 5. "Show your work" output format
# =============================================================================

FORENSIC_EXPERT_SYSTEM_PROMPT = """You are Dr. Sarah Chen, a Digital Forensics Expert with the following credentials:
- Ph.D. in Computer Science, specializing in Digital Forensics (Stanford University)
- Certified Computer Examiner (CCE), EnCase Certified Examiner (EnCE), Certified Forensic Computer Examiner (CFCE)
- 15 years of experience in CAD file forensics and litigation support
- Expert witness testimony in over 200 cases involving digital evidence
- Published researcher on timestamp forensics and file integrity analysis

=============================================================================
FORENSIC KNOWLEDGE BASE - DWG FILE ANALYSIS
=============================================================================

## CRC (Cyclic Redundancy Check) Validation

The DWG file format includes a CRC32 checksum stored at offset 0x68 in the header. This checksum is calculated over bytes 0x00-0x67 of the file header.

CRITICAL FORENSIC FACT: AutoCAD recalculates and updates this CRC value EVERY time it saves the file. This means:
- A MATCHING CRC proves the file was last saved by software that correctly implements DWG format (AutoCAD or compatible)
- A MISMATCHED CRC proves the file was modified AFTER its last legitimate save by something that did NOT update the CRC
- Possible causes of mismatch: hex editor modification, non-compliant software, deliberate binary tampering, file corruption

CRC mismatch is DEFINITIVE PROOF of post-save modification - not speculation.

## TrustedDWG Watermark

Since AutoCAD 2007, Autodesk embeds a cryptographic digital watermark in every DWG file saved by genuine Autodesk applications. This watermark:
- Uses proprietary Autodesk cryptography that CANNOT be forged by third-party software
- Identifies which Autodesk application created/saved the file
- Is checked by AutoCAD when opening files (affects "TrustedDWG" status display)

Forensic interpretation:
- VALID watermark: File was last saved by genuine Autodesk software
- INVALID/CORRUPTED watermark: File was modified after Autodesk save (watermark region damaged)
- ABSENT watermark: File was created by non-Autodesk software OR predates 2007 OR watermark was stripped

Absence alone does NOT prove tampering - many legitimate CAD applications don't create this watermark.

## AutoCAD Internal Timestamps (DWGPROPS Variables)

AutoCAD stores several timestamp variables inside DWG files:

1. TDCREATE - Creation timestamp (Modified Julian Date format)
   - Set when drawing is first created
   - CAN be modified by LISP scripts or direct variable manipulation

2. TDUPDATE - Last update timestamp (Modified Julian Date format)
   - Updated each time file is saved
   - CAN be modified by LISP scripts or direct variable manipulation

3. TDINDWG - Total editing time (fractional days)
   - CUMULATIVE counter of time spent with file open in AutoCAD
   - CANNOT be reset through normal AutoCAD operations
   - Only increases, never decreases
   - This is the KEY variable for detecting clock manipulation

4. TDUSRTIMER - User-resettable timer
   - CAN be reset by user via LISP or menu
   - Less forensically reliable than TDINDWG

CRITICAL CROSS-VALIDATION: If TDINDWG (editing time) EXCEEDS the calendar span between TDCREATE and TDUPDATE, this is MATHEMATICALLY IMPOSSIBLE under normal circumstances. This proves:
- The system clock was manipulated, OR
- TDCREATE was backdated to make the file appear older than it is

This is DEFINITIVE PROOF of timestamp falsification.

## NTFS Filesystem Timestamps

Windows NTFS stores TWO sets of timestamps for every file:

1. $STANDARD_INFORMATION (SI) Timestamps:
   - Creation time, Modification time, Access time, MFT entry modification time
   - CAN be modified by users with tools like timestomp, SetMACE, or PowerShell
   - These are what Windows Explorer displays

2. $FILE_NAME (FN) Timestamps:
   - Stored in a separate MFT attribute
   - PROTECTED by Windows - much harder to modify
   - Updated by Windows kernel during specific operations
   - Require raw disk access or specialized tools to modify

CRITICAL FORENSIC TECHNIQUE - TIMESTOMPING DETECTION:
When SI and FN timestamps DISAGREE significantly (especially for creation time), this proves:
- Someone used timestomping tools to modify the SI timestamps
- The FN timestamp reveals the TRUE creation/modification time
- This is DEFINITIVE PROOF of timestamp manipulation

Nanosecond Precision Analysis:
- NTFS stores timestamps with 100-nanosecond precision
- Normal file operations produce timestamps with seemingly random nanosecond values
- Timestamps with truncated nanoseconds (ending in zeros) indicate manipulation tools that don't preserve full precision

## Cross-Validation Between Sources

The most powerful forensic technique is comparing timestamps from INDEPENDENT sources:

1. NTFS Creation Time vs DWG TDCREATE
   - Should be within seconds for a file created and saved once
   - Large discrepancies indicate manipulation of one or both

2. NTFS Modification Time vs DWG TDUPDATE
   - Should match closely for a normally saved file
   - Discrepancy indicates manipulation or file copying

3. TDINDWG vs Calendar Span
   - Editing time cannot exceed available calendar time
   - If it does, creation timestamp was falsified

4. SI vs FN Timestamps
   - Should match for unmanipulated files
   - Discrepancy proves timestomping

## Information Leakage

DWG files may contain embedded information revealing their origin:

1. Network Paths - UNC paths (\\\\server\\share) embedded in external references reveal:
   - Original network environment
   - Server names and share structures
   - Can prove file originated from specific organization

2. Username Metadata - Author and LastSavedBy fields may contain:
   - Windows username of creator
   - Organizational naming conventions
   - Can contradict claimed authorship

3. FINGERPRINTGUID - Persists across saves and copies
   - Identifies the original drawing even after copying
   - Can link "different" files as copies of the same original

4. VERSIONGUID - Changes with each save
   - Can verify if two files are identical versions
   - Tracks save history

=============================================================================
YOUR ANALYSIS METHODOLOGY
=============================================================================

When analyzing forensic data, you MUST follow this structured approach:

1. EVIDENCE INVENTORY
   List every piece of raw data you were given, with exact values and their sources.

2. TECHNICAL INTERPRETATION
   For each piece of evidence, explain what it represents technically.

3. CROSS-VALIDATION
   Compare values from different sources that should agree. Identify discrepancies.

4. REASONING CHAIN
   Walk through the logical implications step by step:
   - "Value X is [value]. This means [interpretation]."
   - "Comparing X to Y, we see [relationship]."
   - "This discrepancy can only occur if [cause]."

5. CONCLUSION
   State what the evidence PROVES (definitive) vs what it SUGGESTS (probable) vs what it is CONSISTENT WITH (possible).

=============================================================================
ABSOLUTE RULES
=============================================================================

1. ONLY state facts DIRECTLY SUPPORTED by the data provided. You have NO knowledge of this case beyond what is explicitly given.

2. NEVER speculate about intent, motive, or who performed actions. Only describe WHAT the evidence shows.

3. SHOW YOUR WORK - Always cite the specific values that lead to your conclusions.

4. Use precise forensic language:
   - "proves" = mathematical/logical certainty, no other explanation possible
   - "indicates" = strong evidence, most likely explanation
   - "suggests" = possible interpretation, other explanations exist
   - "is consistent with" = does not contradict, but doesn't prove

5. When evidence is DEFINITIVE (CRC mismatch, impossible timestamps, SI/FN discrepancy), state it clearly and explain WHY it is definitive.

6. Format your response as clear, professional prose suitable for court documentation."""


# =============================================================================
# COMPREHENSIVE ANALYSIS PROMPT
# =============================================================================

FULL_ANALYSIS_PROMPT = """Perform a complete forensic analysis of this DWG file. You have been provided with ALL available forensic data below. Analyze it thoroughly using cross-validation between different evidence sources.

=============================================================================
RAW FORENSIC DATA
=============================================================================

## FILE IDENTIFICATION
- Filename: {filename}
- File size: {file_size} bytes
- SHA-256 hash: {sha256}
- Analysis timestamp: {analysis_timestamp}

## DWG HEADER ANALYSIS
- Version string (bytes 0x00-0x05): {version_string}
- Version name: {version_name}
- Maintenance version (byte 0x0B): {maintenance_version}
- Codepage (bytes 0x13-0x14): {codepage}

## CRC VALIDATION
- Stored CRC value (at offset 0x68): {stored_crc}
- Calculated CRC (computed from bytes 0x00-0x67): {calculated_crc}
- Match status: {crc_match}

## TRUSTEDDWG WATERMARK
- Watermark present in file: {watermark_present}
- Watermark cryptographically valid: {watermark_valid}
- Watermark text content: {watermark_text}
- Identified application: {application_origin}

## AUTOCAD INTERNAL TIMESTAMPS (DWGPROPS)
- TDCREATE (creation): {tdcreate}
- TDUPDATE (last save): {tdupdate}
- TDINDWG (cumulative editing time): {tdindwg}
- TDUSRTIMER (user timer): {tdusrtimer}
- Calculated calendar span (TDUPDATE - TDCREATE): {calendar_span}
- Editing time vs calendar span: {time_comparison}

## NTFS FILESYSTEM TIMESTAMPS
- NTFS Creation time ($SI): {ntfs_created}
- NTFS Modification time ($SI): {ntfs_modified}
- NTFS $FILE_NAME creation time: {ntfs_fn_created}
- SI vs FN creation time match: {si_fn_match}
- Nanosecond precision analysis: {nanosecond_analysis}

## CROSS-VALIDATION RESULTS
- NTFS Created vs DWG TDCREATE difference: {ntfs_vs_tdcreate}
- NTFS Modified vs DWG TDUPDATE difference: {ntfs_vs_tdupdate}

## METADATA
- Author: {author}
- Last saved by: {last_saved_by}
- Title: {title}
- FINGERPRINTGUID: {fingerprint_guid}
- VERSIONGUID: {version_guid}

## DETECTED NETWORK PATHS
{network_paths}

## ANOMALIES DETECTED
{anomalies}

## TAMPERING INDICATORS TRIGGERED
{tampering_indicators}

## RISK ASSESSMENT
- Overall risk level: {risk_level}
- Risk factors identified: {risk_factors}

=============================================================================
YOUR ANALYSIS TASK
=============================================================================

Analyze ALL the evidence above using the following structure:

1. EVIDENCE SUMMARY
   Briefly inventory the key pieces of evidence and their values.

2. CRC INTEGRITY ANALYSIS
   - State the stored and calculated CRC values
   - Explain what match/mismatch definitively proves
   - If mismatched, explain what this means for file integrity

3. WATERMARK ANALYSIS
   - State the watermark status
   - Explain what this indicates about the file's origin
   - Note any limitations of this evidence

4. TIMESTAMP CROSS-VALIDATION
   - Compare TDINDWG to calendar span - is it possible?
   - Compare NTFS timestamps to DWG internal timestamps
   - Compare SI to FN timestamps if available
   - Identify any impossibilities or significant discrepancies

5. INFORMATION LEAKAGE ANALYSIS
   - Note any network paths, usernames, or identifying information
   - Explain what this reveals about the file's origin

6. SYNTHESIS AND CONCLUSIONS
   - What does the evidence PROVE definitively?
   - What does the evidence INDICATE with high confidence?
   - What remains uncertain or requires further investigation?
   - Overall assessment of file authenticity

Write in clear, professional prose suitable for presentation to a judge and jury. Show your reasoning for every conclusion."""


@dataclass
class NarrativeResult:
    """Result from narrative generation."""
    narrative: str
    success: bool
    model_used: str
    error: Optional[str] = None
    generation_time_ms: Optional[int] = None


class ForensicNarrator:
    """
    LLM-powered forensic narrative generator.

    Generates comprehensive, reasoned analysis of forensic findings
    using structured data and cross-validation methodology.
    """

    def __init__(
        self,
        ollama_client: Optional[OllamaClient] = None,
        model: Optional[str] = None,
        enabled: bool = True,
    ):
        """
        Initialize the forensic narrator.

        Args:
            ollama_client: Pre-configured Ollama client (creates default if None)
            model: Model to use for generation
            enabled: Whether LLM narration is enabled
        """
        self.client = ollama_client or OllamaClient(model=model)
        self.enabled = enabled
        self._ollama_available: Optional[bool] = None

    def is_available(self) -> bool:
        """Check if LLM narration is available."""
        if not self.enabled:
            return False
        if self._ollama_available is None:
            self._ollama_available = self.client.is_available()
        return self._ollama_available

    def generate_full_analysis(self, analysis: ForensicAnalysis) -> NarrativeResult:
        """
        Generate a comprehensive forensic analysis narrative.

        This is the primary method - it passes ALL forensic data to the LLM
        and requests a complete, reasoned analysis.

        Args:
            analysis: Complete forensic analysis with all data

        Returns:
            NarrativeResult with the full analysis narrative
        """
        if not self.is_available():
            return NarrativeResult(
                narrative="LLM analysis not available. Ollama may not be running.",
                success=False,
                model_used="none",
                error="Ollama not available"
            )

        # Build comprehensive data payload
        prompt = self._build_full_analysis_prompt(analysis)

        response = self.client.generate(
            prompt=prompt,
            system_prompt=FORENSIC_EXPERT_SYSTEM_PROMPT,
            temperature=0.1,  # Low for factual accuracy
        )

        if response.success and response.response.strip():
            return NarrativeResult(
                narrative=response.response.strip(),
                success=True,
                model_used=response.model,
                generation_time_ms=response.total_duration // 1_000_000 if response.total_duration else None
            )
        else:
            return NarrativeResult(
                narrative="",
                success=False,
                model_used=response.model,
                error=response.error
            )

    def _build_full_analysis_prompt(self, analysis: ForensicAnalysis) -> str:
        """Build the comprehensive analysis prompt with all raw data."""

        meta = analysis.metadata

        # Calculate derived values
        calendar_span = "N/A"
        time_comparison = "N/A"
        if meta and meta.created_date and meta.modified_date:
            span_hours = (meta.modified_date - meta.created_date).total_seconds() / 3600
            calendar_span = f"{span_hours:.2f} hours"
            if meta.tdindwg is not None:
                editing_hours = meta.tdindwg * 24
                if editing_hours > span_hours * 1.1:
                    excess = editing_hours - span_hours
                    time_comparison = f"IMPOSSIBLE - Editing time ({editing_hours:.2f}h) exceeds calendar span ({span_hours:.2f}h) by {excess:.2f} hours"
                else:
                    time_comparison = f"VALID - Editing time ({editing_hours:.2f}h) is within calendar span ({span_hours:.2f}h)"

        # Format anomalies
        anomalies_text = "None detected"
        if analysis.anomalies:
            anomalies_list = []
            for a in analysis.anomalies:
                anomalies_list.append(f"- [{a.severity.value}] {a.anomaly_type.value}: {a.description}")
            anomalies_text = "\n".join(anomalies_list)

        # Format tampering indicators
        indicators_text = "None triggered"
        if analysis.tampering_indicators:
            indicators_list = []
            for t in analysis.tampering_indicators:
                indicators_list.append(f"- {t.indicator_type.value} (Confidence: {t.confidence:.0%}): {t.description}")
                if t.evidence:
                    indicators_list.append(f"  Evidence: {t.evidence}")
            indicators_text = "\n".join(indicators_list)

        # Format network paths
        network_paths_text = "None detected"
        if meta and meta.network_paths_detected:
            network_paths_text = "\n".join([f"- {p}" for p in meta.network_paths_detected[:10]])
            if len(meta.network_paths_detected) > 10:
                network_paths_text += f"\n- ... and {len(meta.network_paths_detected) - 10} more"

        # Format risk factors
        risk_factors_text = "\n".join([f"- {f}" for f in analysis.risk_assessment.factors]) if analysis.risk_assessment.factors else "None identified"

        # NTFS data from analysis (critical for cross-validation)
        ntfs = analysis.ntfs_analysis
        ntfs_created = "Not available"
        ntfs_modified = "Not available"
        ntfs_fn_created = "Not available"
        si_fn_match = "Not analyzed"
        nanosecond_analysis = "Not analyzed"
        ntfs_vs_tdcreate = "Not compared"
        ntfs_vs_tdupdate = "Not compared"

        if ntfs:
            # $STANDARD_INFORMATION timestamps
            if ntfs.si_created:
                ntfs_created = ntfs.si_created.strftime("%Y-%m-%d %H:%M:%S UTC")
                if ntfs.si_created_nanoseconds is not None:
                    ntfs_created += f" (nanoseconds: {ntfs.si_created_nanoseconds})"
            if ntfs.si_modified:
                ntfs_modified = ntfs.si_modified.strftime("%Y-%m-%d %H:%M:%S UTC")
                if ntfs.si_modified_nanoseconds is not None:
                    ntfs_modified += f" (nanoseconds: {ntfs.si_modified_nanoseconds})"

            # $FILE_NAME timestamps (kernel-protected, harder to fake)
            if ntfs.fn_created:
                ntfs_fn_created = ntfs.fn_created.strftime("%Y-%m-%d %H:%M:%S UTC")

            # SI vs FN comparison (timestomping detection)
            if ntfs.timestomping_detected:
                si_fn_match = "[!!!] TIMESTOMPING DETECTED - $SI timestamps differ from $FN timestamps"
            elif ntfs.fn_created:
                si_fn_match = "[OK] $SI and $FN timestamps are consistent"
            else:
                si_fn_match = "Unable to compare (no $FN data - requires admin access)"

            # Nanosecond truncation analysis
            if ntfs.nanosecond_truncation:
                nanosecond_analysis = "[!!!] TOOL SIGNATURE DETECTED - Timestamps have zero nanoseconds (indicates timestomping tool)"
            elif ntfs.si_created_nanoseconds is not None:
                nanosecond_analysis = f"[OK] Normal nanosecond values present (created: {ntfs.si_created_nanoseconds}, modified: {ntfs.si_modified_nanoseconds})"

            # Impossible timestamp detection
            if ntfs.impossible_timestamps:
                nanosecond_analysis += " | [!!!] IMPOSSIBLE: Creation timestamp AFTER modification timestamp"

            # Cross-validation with DWG internal timestamps
            if meta and meta.created_date and ntfs.si_created:
                dwg_created = meta.created_date
                si_created = ntfs.si_created
                if hasattr(dwg_created, 'tzinfo') and dwg_created.tzinfo is None:
                    from datetime import timezone
                    dwg_created = dwg_created.replace(tzinfo=timezone.utc)
                if hasattr(si_created, 'tzinfo') and si_created.tzinfo is None:
                    from datetime import timezone
                    si_created = si_created.replace(tzinfo=timezone.utc)
                diff_hours = (si_created - dwg_created).total_seconds() / 3600
                if dwg_created < si_created:
                    ntfs_vs_tdcreate = f"[!!!] BACKDATING PROOF: DWG claims creation {abs(diff_hours):.1f} hours BEFORE file existed on disk"
                else:
                    ntfs_vs_tdcreate = f"[OK] Consistent - DWG created {abs(diff_hours):.1f} hours after filesystem creation"

            if meta and meta.modified_date and ntfs.si_modified:
                dwg_modified = meta.modified_date
                si_modified = ntfs.si_modified
                if hasattr(dwg_modified, 'tzinfo') and dwg_modified.tzinfo is None:
                    from datetime import timezone
                    dwg_modified = dwg_modified.replace(tzinfo=timezone.utc)
                if hasattr(si_modified, 'tzinfo') and si_modified.tzinfo is None:
                    from datetime import timezone
                    si_modified = si_modified.replace(tzinfo=timezone.utc)
                diff_hours = abs((si_modified - dwg_modified).total_seconds()) / 3600
                if diff_hours < 1:
                    ntfs_vs_tdupdate = f"[OK] Consistent - {diff_hours * 60:.1f} minutes difference"
                else:
                    ntfs_vs_tdupdate = f"[WARN] {diff_hours:.1f} hour difference - may indicate file copy/transfer"

            # DWG vs NTFS contradiction flag
            if ntfs.dwg_ntfs_contradiction:
                ntfs_vs_tdcreate = "[!!!] CONTRADICTION DETECTED - " + (ntfs.contradiction_details or "DWG timestamps contradict NTFS")

        prompt = FULL_ANALYSIS_PROMPT.format(
            filename=analysis.file_info.filename,
            file_size=f"{analysis.file_info.file_size_bytes:,}",
            sha256=analysis.file_info.sha256,
            analysis_timestamp=analysis.analysis_timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
            version_string=analysis.header_analysis.version_string,
            version_name=analysis.header_analysis.version_name,
            maintenance_version=analysis.header_analysis.maintenance_version,
            codepage=analysis.header_analysis.codepage,
            stored_crc=analysis.crc_validation.header_crc_stored,
            calculated_crc=analysis.crc_validation.header_crc_calculated,
            crc_match="MATCH - Values are identical" if analysis.crc_validation.is_valid else "MISMATCH - Values differ",
            watermark_present="Yes" if analysis.trusted_dwg.watermark_present else "No",
            watermark_valid="Yes" if analysis.trusted_dwg.watermark_valid else "No",
            watermark_text=analysis.trusted_dwg.watermark_text or "N/A",
            application_origin=analysis.trusted_dwg.application_origin or "Unknown",
            tdcreate=meta.created_date.strftime("%Y-%m-%d %H:%M:%S") if meta and meta.created_date else "Not available",
            tdupdate=meta.modified_date.strftime("%Y-%m-%d %H:%M:%S") if meta and meta.modified_date else "Not available",
            tdindwg=f"{meta.tdindwg * 24:.2f} hours ({meta.tdindwg:.6f} days)" if meta and meta.tdindwg else "Not available",
            tdusrtimer=f"{meta.tdusrtimer * 24:.2f} hours" if meta and meta.tdusrtimer else "Not available",
            calendar_span=calendar_span,
            time_comparison=time_comparison,
            ntfs_created=ntfs_created,
            ntfs_modified=ntfs_modified,
            ntfs_fn_created=ntfs_fn_created,
            si_fn_match=si_fn_match,
            nanosecond_analysis=nanosecond_analysis,
            ntfs_vs_tdcreate=ntfs_vs_tdcreate,
            ntfs_vs_tdupdate=ntfs_vs_tdupdate,
            author=meta.author if meta and meta.author else "Not specified",
            last_saved_by=meta.last_saved_by if meta and meta.last_saved_by else "Not specified",
            title=meta.title if meta and meta.title else "Not specified",
            fingerprint_guid=meta.fingerprint_guid if meta and meta.fingerprint_guid else "Not available",
            version_guid=meta.version_guid if meta and meta.version_guid else "Not available",
            network_paths=network_paths_text,
            anomalies=anomalies_text,
            tampering_indicators=indicators_text,
            risk_level=analysis.risk_assessment.overall_risk.value,
            risk_factors=risk_factors_text,
        )

        return prompt

    def generate_section_analysis(
        self,
        analysis: ForensicAnalysis,
        section: str,
    ) -> NarrativeResult:
        """
        Generate analysis for a specific section.

        Args:
            analysis: Complete forensic analysis
            section: Section to analyze ("crc", "watermark", "timestamps", "summary")

        Returns:
            NarrativeResult with section-specific analysis
        """
        if not self.is_available():
            return NarrativeResult(
                narrative="LLM analysis not available.",
                success=False,
                model_used="none",
                error="Ollama not available"
            )

        prompt = self._build_section_prompt(analysis, section)

        response = self.client.generate(
            prompt=prompt,
            system_prompt=FORENSIC_EXPERT_SYSTEM_PROMPT,
            temperature=0.1,
        )

        if response.success and response.response.strip():
            return NarrativeResult(
                narrative=response.response.strip(),
                success=True,
                model_used=response.model,
            )
        else:
            return NarrativeResult(
                narrative="",
                success=False,
                model_used=response.model,
                error=response.error
            )

    def _build_section_prompt(self, analysis: ForensicAnalysis, section: str) -> str:
        """Build a section-specific analysis prompt."""

        meta = analysis.metadata

        if section == "crc":
            return f"""Analyze the CRC validation results for this DWG file.

RAW EVIDENCE:
- Stored CRC value (read from file offset 0x68): {analysis.crc_validation.header_crc_stored}
- Calculated CRC value (computed from header bytes 0x00-0x67): {analysis.crc_validation.header_crc_calculated}
- Values match: {"YES" if analysis.crc_validation.is_valid else "NO"}

ANALYSIS REQUIREMENTS:
1. State the exact CRC values found
2. Explain technically what CRC validation checks
3. Explain what a match or mismatch DEFINITIVELY PROVES
4. If mismatched, explain the possible causes and why this is conclusive evidence of tampering
5. Be explicit about showing your reasoning

Write 2-3 paragraphs suitable for a court document."""

        elif section == "watermark":
            return f"""Analyze the TrustedDWG watermark status for this DWG file.

RAW EVIDENCE:
- Watermark present in file: {"YES" if analysis.trusted_dwg.watermark_present else "NO"}
- Watermark cryptographically valid: {"YES" if analysis.trusted_dwg.watermark_valid else "NO"}
- Watermark text content: {analysis.trusted_dwg.watermark_text or "N/A"}
- Identified source application: {analysis.trusted_dwg.application_origin or "Unknown"}

ANALYSIS REQUIREMENTS:
1. State the exact watermark findings
2. Explain what the TrustedDWG watermark is and how it works
3. Explain what the presence/absence/validity status indicates about file origin
4. Be clear about what this evidence PROVES vs what it merely SUGGESTS
5. Note any limitations of this evidence

Write 2-3 paragraphs suitable for a court document."""

        elif section == "timestamps":
            calendar_span = "N/A"
            editing_hours = 0
            if meta and meta.created_date and meta.modified_date:
                span_hours = (meta.modified_date - meta.created_date).total_seconds() / 3600
                calendar_span = f"{span_hours:.2f} hours"
                if meta.tdindwg:
                    editing_hours = meta.tdindwg * 24

            return f"""Analyze the timestamp evidence for this DWG file using cross-validation.

RAW EVIDENCE - AUTOCAD INTERNAL TIMESTAMPS:
- TDCREATE (file creation): {meta.created_date.strftime("%Y-%m-%d %H:%M:%S") if meta and meta.created_date else "Not available"}
- TDUPDATE (last save): {meta.modified_date.strftime("%Y-%m-%d %H:%M:%S") if meta and meta.modified_date else "Not available"}
- TDINDWG (cumulative editing time): {f"{meta.tdindwg * 24:.2f} hours ({meta.tdindwg:.6f} days)" if meta and meta.tdindwg else "Not available"}
- TDUSRTIMER (user-resettable timer): {f"{meta.tdusrtimer * 24:.2f} hours" if meta and meta.tdusrtimer else "Not available"}

DERIVED CALCULATIONS:
- Calendar span between TDCREATE and TDUPDATE: {calendar_span}
- TDINDWG editing time: {f"{editing_hours:.2f} hours" if editing_hours else "Not available"}
- Is editing time <= calendar span: {"Cannot determine" if calendar_span == "N/A" else ("YES - VALID" if editing_hours <= float(calendar_span.split()[0]) * 1.1 else "NO - IMPOSSIBLE")}

ANALYSIS REQUIREMENTS:
1. State the exact timestamp values
2. Explain what TDINDWG is and why it's forensically significant (cannot be reset)
3. Perform the calendar span vs editing time comparison explicitly
4. If impossible, explain clearly WHY this proves clock manipulation
5. Show your mathematical reasoning step by step

Write 2-3 paragraphs suitable for a court document."""

        elif section == "summary":
            return f"""Provide an executive summary of the forensic analysis findings.

KEY FINDINGS:
- CRC Validation: {"PASSED" if analysis.crc_validation.is_valid else "FAILED"} (Stored: {analysis.crc_validation.header_crc_stored}, Calculated: {analysis.crc_validation.header_crc_calculated})
- TrustedDWG Watermark: {"Valid" if analysis.trusted_dwg.watermark_valid else "Invalid/Absent"}
- Anomalies detected: {len(analysis.anomalies)}
- Tampering indicators triggered: {len(analysis.tampering_indicators)}
- Overall risk level: {analysis.risk_assessment.overall_risk.value}

TAMPERING INDICATORS:
{chr(10).join([f"- {t.indicator_type.value}: {t.description}" for t in analysis.tampering_indicators]) or "None"}

ANALYSIS REQUIREMENTS:
1. Summarize what the evidence shows
2. Be explicit about what is PROVEN vs what is INDICATED vs what is UNCERTAIN
3. Provide a clear conclusion about file authenticity
4. Recommend any further investigation if needed

Write 3-4 paragraphs suitable for a court document executive summary."""

        else:
            return f"Analyze the {section} section of this forensic report."
