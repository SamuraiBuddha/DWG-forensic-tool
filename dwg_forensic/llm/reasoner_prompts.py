"""
LLM prompts for forensic anomaly filtering.

These prompts guide the LLM to evaluate whether detected anomalies are
expected for the file's provenance context (red herrings) or represent
true evidence of tampering (smoking guns).
"""

# Core filtering prompt template
FILTER_ANOMALIES_PROMPT = """You are a DWG forensic expert evaluating detected anomalies for tampering significance.

FILE CONTEXT:
CAD Application: {cad_fingerprint}
Provenance Path: {provenance_path}
DWG Version: {dwg_version}
Detection Confidence: {confidence:.1%}

DETECTED ANOMALIES:
{anomalies_list}

CRITICAL FILTERING RULES:

1. NEVER FILTER these smoking gun rules (DEFINITIVE proof):
   - TAMPER-001: CRC mismatch (mathematical proof of modification)
   - TAMPER-019 to 028: NTFS timestamp violations (kernel-level proof)
   - TAMPER-014: TDINDWG exceeds calendar span (mathematical impossibility)
   - TAMPER-015: Version anachronism (temporal impossibility)

2. ALWAYS FILTER these for Revit exports:
   - TAMPER-013: TDINDWG zero or missing (Revit normal behavior)
   - TAMPER-006: Zero firmware version (Revit doesn't track this)
   - TAMPER-003: TrustedDWG missing (Revit doesn't use watermarks)
   - TAMPER-029: Third-party origin flags (Revit is legitimate Autodesk)

3. ADJUST FILTERING for ODA SDK tools (BricsCAD, NanoCAD):
   - TAMPER-003: TrustedDWG missing (ODA tools don't use this)
   - TAMPER-029-035: Application fingerprint flags (legitimate software)
   - Keep: NTFS violations, CRC mismatches (still suspicious)

4. ADJUST FILTERING for file transfers:
   - TAMPER-020: NTFS creation after modification (normal for copy/move)
   - Keep: SI/FN mismatches (still proves timestomping)

TASK: Evaluate each anomaly and return JSON:

{{
  "keep": ["TAMPER-001", "TAMPER-019"],
  "filter": ["TAMPER-013", "TAMPER-006"],
  "reasoning": "Detailed explanation of filtering decisions for this specific file context",
  "confidence": 0.85
}}

Your reasoning should explain:
- Why specific anomalies are expected for this provenance
- Which anomalies remain suspicious despite provenance
- Any contradictions or red flags that override expected patterns

Be rigorous. Do not filter smoking guns. Focus on the SPECIFIC file context provided."""

# Simplified prompt for batch processing (lower token count)
FILTER_ANOMALIES_BATCH_PROMPT = """DWG Forensic Expert: Filter anomalies for {provenance_path}.

Context: {cad_fingerprint} | Version: {dwg_version}

Anomalies:
{anomalies_list}

Rules:
- Never filter: TAMPER-001, TAMPER-014, TAMPER-015, TAMPER-019-028 (smoking guns)
- Revit: Filter TAMPER-013, TAMPER-006, TAMPER-003, TAMPER-029
- ODA: Filter TAMPER-003, TAMPER-029-035
- Transfer: Filter TAMPER-020 (normal copy behavior)

JSON response:
{{"keep": [...], "filter": [...], "reasoning": "...", "confidence": 0.0-1.0}}"""

# Confidence validation prompt
CONFIDENCE_CHECK_PROMPT = """You filtered {filtered_count} of {total_count} anomalies for a {provenance_path} file.

Filtered anomalies: {filtered_ids}
Kept anomalies: {kept_ids}

Rate your confidence (0.0-1.0) in these filtering decisions:
- 1.0: Completely certain based on known provenance patterns
- 0.8: High confidence, standard patterns
- 0.6: Moderate confidence, some ambiguity
- 0.4: Low confidence, unusual patterns
- 0.2: Very uncertain, manual review needed

Return only a JSON object: {{"confidence": 0.85, "explanation": "..."}}"""

# Red herring explanation prompt
RED_HERRING_EXPLANATION = """For each filtered anomaly, explain WHY it's a red herring for {provenance_path}:

Filtered anomalies:
{filtered_list}

Format: Array of objects with "rule_id", "finding", and "why_not_significant".

Example:
[
  {{
    "rule_id": "TAMPER-013",
    "finding": "TDINDWG is zero",
    "why_not_significant": "Revit does not track cumulative edit time during DWG export. This is expected behavior, not tampering."
  }}
]

Provide JSON array only."""

# Smoking gun preservation validation
SMOKING_GUN_VALIDATION = """CRITICAL VALIDATION: Check if any smoking gun rules were incorrectly filtered.

Smoking gun rules (NEVER filter):
- TAMPER-001: CRC mismatch
- TAMPER-014: TDINDWG exceeds span
- TAMPER-015: Version anachronism
- TAMPER-019 to 028: NTFS violations

Filtered anomalies: {filtered_ids}

If ANY smoking gun was filtered, return:
{{"error": "CRITICAL: Smoking gun [rule_id] was filtered", "valid": false}}

If all clear, return:
{{"valid": true, "message": "No smoking guns filtered"}}"""


def format_anomalies_for_prompt(anomalies: list, max_anomalies: int = 20) -> str:
    """
    Format anomalies list for LLM prompt.

    Args:
        anomalies: List of Anomaly objects
        max_anomalies: Maximum number to include (truncate if exceeded)

    Returns:
        Formatted string of anomalies with rule IDs and descriptions
    """
    lines = []
    for i, anomaly in enumerate(anomalies[:max_anomalies], 1):
        lines.append(
            f"{i}. [{anomaly.rule_id}] {anomaly.description} "
            f"(Severity: {anomaly.severity.value}, Strength: {anomaly.evidence_strength})"
        )

    if len(anomalies) > max_anomalies:
        lines.append(f"... and {len(anomalies) - max_anomalies} more anomalies")

    return "\n".join(lines)


def format_filter_prompt(
    anomalies: list,
    provenance: dict,
    dwg_version: str,
    batch_mode: bool = False,
) -> str:
    """
    Format the main filtering prompt with file context.

    Args:
        anomalies: List of Anomaly objects
        provenance: ProvenanceInfo dict
        dwg_version: DWG version string (e.g., "AC1032")
        batch_mode: Use simplified batch prompt for faster processing

    Returns:
        Formatted prompt string
    """
    template = FILTER_ANOMALIES_BATCH_PROMPT if batch_mode else FILTER_ANOMALIES_PROMPT

    return template.format(
        cad_fingerprint=provenance.get("cad_app", "Unknown"),
        provenance_path=provenance.get("provenance_path", "Unknown"),
        dwg_version=dwg_version,
        confidence=provenance.get("confidence", 0.0),
        anomalies_list=format_anomalies_for_prompt(anomalies),
    )


def format_confidence_check(
    filtered_count: int,
    total_count: int,
    filtered_ids: list,
    kept_ids: list,
    provenance_path: str,
) -> str:
    """Format confidence validation prompt."""
    return CONFIDENCE_CHECK_PROMPT.format(
        filtered_count=filtered_count,
        total_count=total_count,
        filtered_ids=", ".join(filtered_ids),
        kept_ids=", ".join(kept_ids),
        provenance_path=provenance_path,
    )


def format_red_herring_explanation(filtered_anomalies: list, provenance_path: str) -> str:
    """Format red herring explanation prompt."""
    filtered_list = "\n".join(
        f"- [{a.rule_id}] {a.description}" for a in filtered_anomalies
    )

    return RED_HERRING_EXPLANATION.format(
        provenance_path=provenance_path,
        filtered_list=filtered_list,
    )


def format_smoking_gun_validation(filtered_ids: list) -> str:
    """Format smoking gun preservation validation prompt."""
    return SMOKING_GUN_VALIDATION.format(
        filtered_ids=", ".join(filtered_ids),
    )
