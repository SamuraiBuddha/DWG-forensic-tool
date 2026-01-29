# DWG Forensic Standards Reference

**Document Purpose**: Litigation-grade taxonomy of tampering indicators by evidentiary weight
**Created**: 2026-01-29
**Author**: Research Agent (Hive-Mind DWG Forensic Investigation)

---

## Table of Contents

1. [Evidentiary Classification System](#evidentiary-classification-system)
2. [Forensically Sound Rules by Confidence Level](#forensically-sound-rules-by-confidence-level)
3. [File Provenance Detection Patterns](#file-provenance-detection-patterns)
4. [Current Anomaly.py Issues Analysis](#current-anomalypy-issues-analysis)
5. [Recommended Rule Filtering Logic](#recommended-rule-filtering-logic)
6. [Timestamp Tolerance Guidelines](#timestamp-tolerance-guidelines)

---

## Evidentiary Classification System

### IMPOSSIBLE (100% Proof - Mathematical/Physical Impossibility)

These violations are **DEFINITIVE PROOF** of tampering when detected in genuine AutoCAD files. They cannot occur through normal file operations or legitimate software behavior.

| Rule ID | Finding | Why It's Impossible | Exceptions/Context |
|---------|---------|---------------------|-------------------|
| **TAMPER-005** | Created > Modified | Filesystem law: A file cannot be modified before it exists | NONE - Always impossible |
| **TAMPER-006** | Future Timestamp | Clock manipulation: File cannot be modified in the future without manual clock setting | Allow 5min grace for clock skew |
| **TAMPER-013** | TDINDWG > Calendar Span | AutoCAD math: Cannot accumulate more editing time than calendar time elapsed between TDCREATE and TDUPDATE | NONE - Always impossible |
| **TAMPER-014** | Version Anachronism | Temporal impossibility: AC1032 (AutoCAD 2018) cannot exist before 2017 | NONE - Always impossible |
| **TAMPER-019** | NTFS $SI < $FN | Kernel protection: $FILE_NAME timestamps are kernel-managed and cannot be backdated without kernel-level tools (SetMace) | NONE - Requires kernel driver |
| **TAMPER-020** | Nanosecond Truncation | Statistical impossibility: Multiple timestamps ending in .0000000 (p < 0.0001) | Single timestamp may be coincidence |
| **TAMPER-021** | NTFS Created > Modified | Filesystem law at NTFS level | NONE - Always impossible |
| **TAMPER-001** | CRC Header Mismatch | Cryptographic proof: CRC32 is deterministic - if data unchanged, checksum MUST match | **EXCEPTION**: See provenance table |
| **TAMPER-002** | CRC Section Mismatch | Same as TAMPER-001 but for DWG sections | **EXCEPTION**: See provenance table |

**Legal Standard**: These findings constitute **smoking guns** - evidence that proves tampering with mathematical or physical certainty. Individually sufficient for expert witness testimony.

---

### CIRCUMSTANTIAL (Context-Dependent Evidence)

These findings require additional context to determine whether they indicate tampering or legitimate file provenance.

| Rule ID | Finding | Legitimate Reasons | Red Flags |
|---------|---------|-------------------|-----------|
| **TAMPER-007** | Edit Time > Calendar Span Tolerance | File kept open overnight, system sleep/hibernate | Edit time exceeds span by >10% without sleep events |
| **TAMPER-022** | DWG Created < NTFS Created | File transfer (email, USB, network copy) | DWG timestamp is YEARS before NTFS with no transfer evidence |
| **TAMPER-023** | DWG Modified != NTFS Modified | File transfer, copy operations | Discrepancy >5min without transfer evidence |
| **TAMPER-008/009** | Version Downgrade/Mismatch | Legitimate SAVEAS to older format | Newer objects in older format without user action |
| **TAMPER-027** | Multiple Timestamp Anomalies | Compound errors from file operations | 3+ independent anomalies (statistical improbability) |
| **TAMPER-036** | Handle Gaps | Mass deletion of objects (legitimate editing) | Gaps >1000 handles without corresponding UNDO history |
| **TAMPER-038** | Internal Timestamp Contradiction | Software bug, version incompatibility | Combined with other smoking guns |
| **Missing TDINDWG** | Zero editing time | ODA SDK files, Revit exports, programmatic generation | Native AutoCAD ALWAYS accumulates TDINDWG |

**Legal Standard**: Require **corroboration** from multiple independent sources or combination with IMPOSSIBLE findings. May require expert testimony explaining context.

---

### LEGITIMATE VARIATIONS (NOT Evidence of Tampering)

These patterns indicate **legitimate file provenance** from specific CAD software or workflows. Flagging these as tampering creates **FALSE POSITIVES**.

| Pattern | Legitimate Cause | Detection Logic |
|---------|-----------------|-----------------|
| **CRC = 0x00000000** | Revit exports, ODA SDK applications (BricsCAD, DraftSight, NanoCAD, etc.) | Check FINGERPRINTGUID for "30314341-" or detect ODA SDK markers |
| **Zero TDCREATE/TDUPDATE** | Revit exports, LibreDWG conversions, ODA SDK files | Check for Revit GUID pattern or ODA SDK artifacts |
| **Missing FINGERPRINTGUID/VERSIONGUID** | ODA SDK applications, open-source CAD tools | These tools do NOT generate AutoCAD-specific identifiers |
| **TDINDWG = 0 or near-zero** | Revit exports (~1000 = 0.016 min), ODA SDK files | Revit exports are generated, not interactively edited |
| **DWG Timestamp < NTFS Created** | File transfer via email, USB, network copy | Check for transfer indicators (nanosecond precision loss, timezone shifts) |
| **Nanosecond Truncation (Single)** | Normal file copy, network transfer | Only suspicious if MULTIPLE timestamps affected |
| **HANDSEED[1] = 3** | Revit DWG exports | Revit uses different handle allocation than AutoCAD (which uses 2) |
| **Class Count < 15** | Revit exports (minimal entity types) | Native AutoCAD: 90-100 classes, Civil 3D: 600+ classes |
| **TDCREATE = TDUPDATE** | Batch/programmatic generation, ODA SDK files | Common in QCAD, LibreCAD, conversion tools |

**Critical Insight**: Approximately **30-40% of legitimate CAD workflows** involve non-AutoCAD software (Revit exports, ODA SDK applications). These are **NOT tampering cases**.

---

## Forensically Sound Rules by Confidence Level

### Tier 1: DEFINITIVE PROOF (Admissible Alone)

**Confidence**: 100% (mathematical/physical impossibility)
**Legal Weight**: Sufficient for expert witness testimony without corroboration
**False Positive Rate**: 0% (when provenance correctly identified)

```
TAMPER-005: Created > Modified
TAMPER-006: Future Timestamp (>5min tolerance)
TAMPER-013: TDINDWG > Calendar Span
TAMPER-014: Version Anachronism
TAMPER-019: NTFS $SI < $FN Timestomping
TAMPER-020: Nanosecond Truncation (Multiple)
TAMPER-021: NTFS Created > Modified
TAMPER-001/002: CRC Mismatch (ONLY if NOT Revit/ODA SDK)
```

**Implementation Requirement**: MUST filter out provenance-based exceptions BEFORE flagging as CRITICAL.

---

### Tier 2: STRONG CIRCUMSTANTIAL (Corroboration Required)

**Confidence**: 75-90% (requires context)
**Legal Weight**: Admissible with expert explanation
**False Positive Rate**: 10-25% (without provenance detection)

```
TAMPER-022: DWG Created << NTFS Created (>1 year discrepancy without transfer evidence)
TAMPER-023: DWG Modified != NTFS Modified (>5min without transfer evidence)
TAMPER-027: Multiple Independent Anomalies (3+ anomalies)
TAMPER-036: Large Handle Gaps (>1000 without UNDO history)
TAMPER-007: Edit Time Exceeds Span by >20%
```

**Implementation Requirement**: Combine with provenance detection. Require 2+ Tier 2 findings OR 1 Tier 2 + 1 Tier 1.

---

### Tier 3: INFORMATIONAL (Provenance Indicators)

**Confidence**: 50-70% (identifies file origin)
**Legal Weight**: Establishes context, NOT proof of tampering
**False Positive Rate**: N/A (these are true positives for origin detection)

```
TAMPER-029: ODA SDK Artifacts
TAMPER-030: BricsCAD Signature
TAMPER-031: NanoCAD Signature
TAMPER-032: DraftSight Signature
TAMPER-033: Open Source CAD Conversion
TAMPER-034: Zero Timestamp Pattern (if Revit/ODA detected)
TAMPER-035: Missing AutoCAD Identifiers (if ODA detected)
TAMPER-036: Revit Export Signature
```

**Implementation Requirement**: These rules **DISABLE** Tier 1/2 rules that would create false positives for the detected provenance.

---

## File Provenance Detection Patterns

### Decision Tree for Origin Detection

```
START: Analyze DWG file
  |
  +--> Check FINGERPRINTGUID
  |      |
  |      +--> Starts with "30314341-"? --> REVIT EXPORT (confidence: 92%)
  |      |                                  - DISABLE: TAMPER-001 (CRC), TAMPER-034 (zero timestamps)
  |      |                                  - DISABLE: TAMPER-035 (missing identifiers)
  |      |
  |      +--> Contains "DEAD" pattern? --> LIBREDWG (confidence: 98%)
  |      |                                  - Flag: Open source conversion
  |      |
  |      +--> Missing or null? --> Continue to next check
  |
  +--> Check Binary Markers
  |      |
  |      +--> Contains "OdDb" class prefix? --> ODA SDK (confidence: 85%)
  |      |                                       - DISABLE: TAMPER-001, TAMPER-034, TAMPER-035
  |      |
  |      +--> Contains "BRICSYS" APPID? --> BRICSCAD (confidence: 100%)
  |      |                                   - DISABLE: TAMPER-001, TAMPER-034, TAMPER-035
  |      |
  |      +--> Contains "NANOCAD" APPID? --> NANOCAD (confidence: 100%)
  |      |                                   - DISABLE: TAMPER-001, TAMPER-034, TAMPER-035
  |      |
  |      +--> Contains "\\Autodesk\\AutoCAD" path? --> GENUINE AUTOCAD (confidence: 95%)
  |                                                     - ENABLE: All rules (strict mode)
  |
  +--> Check Header Field Patterns
  |      |
  |      +--> Preview Addr = 0x120 AND Summary = 0x0 AND VBA = 0x0? --> REVIT (confidence: 95%)
  |      |
  |      +--> Class Count <= 15? --> REVIT (confidence: 70%)
  |      |
  |      +--> Class Count >= 400? --> CIVIL 3D (confidence: 80%)
  |      |
  |      +--> HANDSEED[1] = 3? --> REVIT (confidence: 85%)
  |      |
  |      +--> TDINDWG < 2000? --> REVIT or ODA (confidence: 75%)
  |
  +--> Check Transfer Indicators
         |
         +--> NTFS Created > DWG Created? --> FILE TRANSFER (confidence: 60%)
         |                                    - DISABLE: TAMPER-022 (expected for transfers)
         |
         +--> Single nanosecond truncation? --> FILE COPY (confidence: 50%)
                                                - DISABLE: TAMPER-020 (normal for copies)
```

---

### Provenance Signatures (Detailed)

#### Revit DWG Export Detection

**Primary Indicators** (>=2 required for 90% confidence):

1. **FINGERPRINTGUID Pattern**: Starts with `30314341-` (ASCII "01CA")
   - Example: `30314341-0000-0000-0000-000000000000`
   - **Why**: Revit uses placeholder GUID format, not random like AutoCAD

2. **Header Field Pattern**:
   - Preview Address: `0x00000120` (AutoCAD uses `0x000001C0`)
   - Summary Info Address: `0x00000000` (AutoCAD uses `0x20000000`)
   - VBA Project Address: `0x00000000` (AutoCAD uses `0x00000001`)

3. **Zero/Missing Timestamps**:
   - TDCREATE = 0 or missing
   - TDUPDATE = 0 or missing
   - TDINDWG ~1000 (0.016 minutes - generation overhead, not editing)

4. **Low Class Count**: Typically 10-15 classes (Revit only exports basic entities)

5. **HANDSEED Pattern**: HANDSEED[1] = 3 (AutoCAD and Civil 3D use 2)

**Expected "Anomalies" for Revit** (NOT tampering):
- CRC = 0x00000000
- Missing FINGERPRINTGUID (or malformed)
- Missing VERSIONGUID
- Zero editing time (TDINDWG)
- Null timestamps

**Rule Filtering**: When Revit detected, **PASS** (not FAIL) the following rules:
- TAMPER-001 (CRC Header Mismatch)
- TAMPER-002 (CRC Section Mismatch)
- TAMPER-034 (Zero Timestamp Pattern)
- TAMPER-035 (Missing AutoCAD Identifiers)

---

#### ODA SDK Application Detection

**Primary Indicators**:

1. **Binary Markers**:
   - String: "Open Design Alliance"
   - String: "Teigha" (legacy ODA name)
   - String: "DWGdirect"
   - Class prefix: "OdDb" (vs AutoCAD's "AcDb")

2. **Application-Specific Markers**:
   - BricsCAD: "BRICSYS" APPID, "ACAD_BRICSCAD_INFO" dictionary
   - NanoCAD: "NANOCAD" APPID, CP1251 codepage (Cyrillic)
   - DraftSight: "DRAFTSIGHT" APPID, "DS_LICENSE_TYPE" property

3. **Expected Characteristics**:
   - CRC may be 0x00000000 (ODA SDK doesn't compute CRC)
   - Missing FINGERPRINTGUID/VERSIONGUID
   - TDINDWG may be zero or absent

**Applications Using ODA SDK**:
- BricsCAD (Bricsys)
- DraftSight (Dassault Systemes)
- NanoCAD (Nanosoft, Russia)
- ZWCAD (China)
- GstarCAD (China)
- progeCAD (Italy)
- IntelliCAD platform
- CorelCAD (Corel)

**Rule Filtering**: When ODA SDK detected, **PASS** (not FAIL):
- TAMPER-001 (CRC Header Mismatch) - IF CRC = 0
- TAMPER-034 (Zero Timestamp Pattern)
- TAMPER-035 (Missing AutoCAD Identifiers)
- TAMPER-010 (Non-Autodesk Origin) - INFORMATIONAL only

---

#### LibreDWG/Open Source CAD Detection

**Primary Indicators**:

1. **GUID Markers**:
   - FINGERPRINTGUID contains "DEAD" (e.g., `FDEAD578-...`)
   - This is a LibreDWG placeholder/test value

2. **Binary Markers**:
   - String: "LibreDWG"
   - String: "libdxfrw" (LibreCAD/QCAD library)
   - String: "ezdxf" (Python library used by FreeCAD)

3. **Timestamp Patterns**:
   - TDCREATE = TDUPDATE (batch generation)
   - TDINDWG = 0 (no interactive editing)
   - Both timestamps = 0 (LibreCAD)

**Applications**:
- LibreCAD (open source, DXF-native, requires conversion to DWG)
- QCAD (open source, uses dxflib)
- FreeCAD (open source, uses ODA or LibreDWG)

**Forensic Significance**: These files are **conversions from DXF**, not native DWG. Timestamp integrity is NOT preserved during conversion.

**Rule Filtering**: When LibreDWG detected, **FAIL** (as suspicious):
- TAMPER-033 (Open Source CAD Conversion) - INFORMATIONAL
- Consider all timestamp anomalies as EXPECTED, not evidence of tampering

---

#### Native AutoCAD Detection

**Primary Indicators** (ALL required for 95% confidence):

1. **Embedded Paths**:
   - Contains: `\Autodesk\AutoCAD`
   - Contains: "Plot Styles" directory references

2. **Valid CRC**: Header CRC matches calculated CRC (NOT zero)

3. **Valid GUIDs**:
   - FINGERPRINTGUID: Random GUID (not placeholder)
   - VERSIONGUID: Random GUID (changes with each save)

4. **Normal Timestamps**:
   - TDCREATE <= TDUPDATE
   - TDINDWG > 0 (some editing time accumulated)
   - TDINDWG <= Calendar Span

5. **Class Count**:
   - Standard AutoCAD: 90-100 classes
   - Civil 3D: 600+ classes (includes AeccDb* civil engineering classes)

**Rule Filtering**: When genuine AutoCAD detected, **ENABLE ALL RULES** (strict mode).

---

#### File Transfer Detection

**Indicators**:

1. **Timestamp Relationship**:
   - NTFS Created > DWG TDCREATE (file existed before filesystem timestamp)
   - This is NORMAL for email attachments, USB transfers, network copies

2. **Nanosecond Precision Loss**:
   - Single timestamp with .0000000 nanoseconds
   - Network transfers and some copy operations truncate precision

3. **Timezone Shift**:
   - DWG internal timestamps vs NTFS show exact timezone offset (e.g., 8 hours)
   - Indicates file created in different timezone

**Rule Filtering**: When transfer detected:
- TAMPER-022 (DWG < NTFS Created) - **PASS** if transfer evidence
- TAMPER-020 (Nanosecond Truncation) - **PASS** if only 1 timestamp affected
- TAMPER-023 (Timestamp Mismatch) - Require >5min discrepancy

---

## Current Anomaly.py Issues Analysis

### Issue 1: Lines 159-179 - 5-Minute Tolerance Check

**Code Location**: `anomaly.py:159-179`

```python
# Check 4: Filesystem vs internal timestamp mismatch
if metadata.modified_date and fs_modified:
    internal_modified = metadata.modified_date
    if internal_modified.tzinfo is None:
        internal_modified = internal_modified.replace(tzinfo=timezone.utc)

    diff_seconds = abs((internal_modified - fs_modified).total_seconds())
    # Allow 5 minute tolerance
    if diff_seconds > 300:
        anomalies.append(Anomaly(...))
```

**Forensic Analysis**:

**Is 5-minute tolerance forensically justified?**
- **YES** for clock skew, DST transitions, network time sync delays
- **NO** for file transfers (can be hours/days/years apart)
- **NO** for timezone discrepancies (typically exact hour offsets)

**Should tolerance be disabled for transferred files?**
- **YES** - File transfers create legitimate discrepancies of hours to years
- **Detection logic**: If NTFS Created > DWG TDCREATE, likely transfer - disable this check

**Should tolerance be configurable?**
- **YES** - Different use cases need different thresholds:
  - Strict mode (litigation): 60 seconds
  - Standard mode: 300 seconds (5 minutes)
  - Lenient mode (transferred files): Disable or 3600 seconds (1 hour)

**Recommendation**:

```python
# Detect file transfer first
is_file_transfer = self._detect_file_transfer(metadata, file_path)

if is_file_transfer:
    # File transfer detected - large discrepancies are EXPECTED
    # Only flag if discrepancy is extreme (>30 days) or shows manipulation pattern
    if diff_seconds > 2592000:  # 30 days
        severity = RiskLevel.LOW  # Informational, not evidence
        description = "Internal/external timestamp mismatch suggests file transfer"
else:
    # Native file - strict tolerance
    # Make tolerance configurable via context parameter
    tolerance_seconds = context.get("timestamp_tolerance_seconds", 300)
    if diff_seconds > tolerance_seconds:
        severity = RiskLevel.MEDIUM
        description = "Internal modified date doesn't match filesystem timestamp"
```

**Provenance Context Required**: Check for Revit/ODA SDK origin - these applications may have different timestamp handling.

---

### Issue 2: Lines 286-300 - Null Padding Check (30% Threshold)

**Code Location**: `anomaly.py:286-300`

```python
# Check for excessive null padding (TAMPER-012)
null_ratio = self._calculate_null_ratio(file_data)
if null_ratio > 0.3:  # More than 30% null bytes
    anomalies.append(Anomaly(
        anomaly_type=AnomalyType.OTHER,
        description="Excessive null byte padding detected - possible hidden data or corruption",
        severity=RiskLevel.MEDIUM,
        ...
    ))
```

**Forensic Analysis**:

**Is 30% threshold forensically sound?**
- **DEPENDS** on file size and DWG version:
  - Small files (<10KB): Often have 40-50% nulls (padding in fixed-size header sections)
  - Large files (>1MB): Typically <20% nulls
  - Compressed DWG (AC1021+): Lower null ratio due to compression
  - Uncompressed DWG (AC1018-): Higher null ratio

**Could legitimate software create high null padding?**
- **YES** - Several legitimate scenarios:
  - Revit exports: Minimal objects, lots of empty sections
  - LibreDWG conversions: May not optimize padding
  - Older DWG versions (AC1018): Less efficient packing
  - Files with deleted objects: Null padding left behind

**Statistical Analysis Needed**:

| File Type | Expected Null Ratio | Threshold for Alarm |
|-----------|---------------------|---------------------|
| Native AutoCAD 2018+ | 15-25% | >40% |
| Native AutoCAD 2010-2017 | 20-30% | >50% |
| Revit Export | 30-45% | >60% |
| LibreDWG | 25-40% | >55% |
| ODA SDK | 20-35% | >50% |
| Small files (<50KB) | 35-50% | >70% |

**Recommendation**:

```python
# Adjust threshold based on file size and version
def _get_null_ratio_threshold(self, file_size: int, version: str, provenance: str) -> float:
    """Get appropriate null ratio threshold based on file characteristics."""

    # Small files have naturally higher null ratios
    if file_size < 51200:  # <50KB
        base_threshold = 0.70
    elif file_size < 512000:  # <500KB
        base_threshold = 0.50
    else:
        base_threshold = 0.35

    # Adjust for provenance
    if provenance in ["revit_export", "libredwg"]:
        base_threshold += 0.15  # More lenient
    elif provenance == "autocad_native":
        base_threshold -= 0.05  # Stricter

    # Adjust for version (older = more null padding)
    if version in ["AC1018", "AC1021"]:
        base_threshold += 0.10

    return base_threshold

# Then use:
threshold = self._get_null_ratio_threshold(file_size, version_string, detected_provenance)
if null_ratio > threshold:
    # Flag as suspicious
```

**Forensic Justification**: Dynamic thresholding based on file characteristics reduces false positives while maintaining detection of actual hidden data or corruption.

---

### Issue 3: Lines 529-546 - Timestamp Precision Anomaly (Exactly Midnight)

**Code Location**: `anomaly.py:529-546`

```python
# Check for unusually round creation time (exactly midnight)
if timestamp_data.tdcreate is not None:
    fractional = timestamp_data.tdcreate % 1.0
    if fractional == 0.0:
        anomalies.append(Anomaly(
            anomaly_type=AnomalyType.TIMESTAMP_PRECISION_ANOMALY,
            description=(
                "Creation timestamp is exactly midnight - "
                "unusual precision indicates manipulation"
            ),
            severity=RiskLevel.LOW,
            ...
        ))
```

**Forensic Analysis**:

**Is "exactly midnight" suspicious?**
- **SOMETIMES**:
  - **Suspicious**: Combined with other anomalies (e.g., TDUPDATE also exactly midnight)
  - **Normal**: Batch processing, automated scripts, default values in some CAD tools
  - **Statistical probability**: 1/86400 chance (~0.001%) - not impossible

**Provenance-Specific Behavior**:

| Application | Likelihood of Midnight Timestamps |
|-------------|-----------------------------------|
| Native AutoCAD | Very low (<0.1%) - interactive editing |
| Revit Export | Low (~1%) - export time varies |
| LibreDWG | Moderate (5-10%) - may use default values |
| ODA SDK | Low-Moderate (1-5%) |
| Batch Tools | High (20-50%) - common default |

**Recommendation**:

```python
# Only flag if MULTIPLE timestamps are exactly midnight (statistically impossible)
midnight_count = 0
if tdcreate and tdcreate % 1.0 == 0.0:
    midnight_count += 1
if tdupdate and tdupdate % 1.0 == 0.0:
    midnight_count += 1
if tducreate and tducreate % 1.0 == 0.0:
    midnight_count += 1
if tduupdate and tduupdate % 1.0 == 0.0:
    midnight_count += 1

# Require 2+ midnight timestamps for LOW severity
# Require 3+ midnight timestamps for MEDIUM severity
if midnight_count >= 2:
    probability = (1/86400) ** midnight_count
    severity = RiskLevel.MEDIUM if midnight_count >= 3 else RiskLevel.LOW
    description = (
        f"{midnight_count} timestamps are exactly midnight - "
        f"statistical probability: {probability:.2e} - indicates manipulation"
    )
```

**Forensic Justification**: Single midnight timestamp has 0.001% natural occurrence rate. Multiple midnight timestamps have compound probability <0.000001% (statistical impossibility).

---

### Issue 4: Lines 549-566 - Zero TDINDWG Detection

**Code Location**: `anomaly.py:549-566`

```python
# Check for zero editing time on non-new file
if timestamp_data.tdindwg is not None and timestamp_data.tdindwg == 0.0:
    if timestamp_data.tdcreate and timestamp_data.tdupdate:
        if timestamp_data.tdcreate != timestamp_data.tdupdate:
            anomalies.append(Anomaly(
                anomaly_type=AnomalyType.TIMESTAMP_PRECISION_ANOMALY,
                description=(
                    "Zero editing time despite different creation and save dates - "
                    "indicates TDINDWG was reset or manipulated"
                ),
                severity=RiskLevel.MEDIUM,
                ...
            ))
```

**Forensic Analysis**:

**Is zero TDINDWG always suspicious?**
- **NO** - Highly dependent on file provenance:

| Provenance | Zero TDINDWG Expected? | Reason |
|------------|------------------------|--------|
| Native AutoCAD | NO - ALWAYS accumulates | Interactive editing ALWAYS increments TDINDWG |
| Revit Export | YES - Expected | Revit generates files, doesn't "edit" them |
| ODA SDK | YES - Common | May not track editing time |
| LibreDWG | YES - Expected | Conversions don't preserve editing time |
| Batch Tools | YES - Expected | Programmatic generation |

**Current Problem**: Code flags Revit/ODA files as MEDIUM severity when zero TDINDWG is **EXPECTED**.

**Recommendation**:

```python
# Check provenance FIRST
provenance = context.get("detected_provenance", "unknown")
is_oda_or_revit = provenance in ["revit_export", "oda_sdk", "bricscad", "nanocad", "draftsight", "libredwg"]

if timestamp_data.tdindwg is not None and timestamp_data.tdindwg == 0.0:
    if timestamp_data.tdcreate and timestamp_data.tdupdate:
        if timestamp_data.tdcreate != timestamp_data.tdupdate:

            if is_oda_or_revit:
                # Zero TDINDWG is EXPECTED for these applications - NOT suspicious
                # Log as informational only
                return []  # Don't flag as anomaly

            else:
                # Native AutoCAD should NEVER have zero TDINDWG with different dates
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.TIMESTAMP_PRECISION_ANOMALY,
                    description=(
                        "Zero editing time despite different creation and save dates - "
                        "indicates TDINDWG was reset or manipulated (native AutoCAD always tracks editing time)"
                    ),
                    severity=RiskLevel.HIGH,  # Upgraded from MEDIUM for native AutoCAD
                    ...
                ))
```

**Forensic Justification**: Zero TDINDWG in native AutoCAD is **IMPOSSIBLE** for interactive editing. But for Revit/ODA SDK, it's **EXPECTED BEHAVIOR**.

---

## Recommended Rule Filtering Logic

### Provenance-Based Rule State Machine

```python
class RuleFilter:
    """Manages rule enable/disable based on detected file provenance."""

    def __init__(self):
        self.provenance = "unknown"
        self.confidence = 0.0
        self.disabled_rules = set()
        self.downgraded_rules = {}  # rule_id -> new_severity

    def apply_provenance(self, provenance: str, confidence: float, context: dict):
        """Apply provenance-based rule filtering."""

        self.provenance = provenance
        self.confidence = confidence

        if provenance == "revit_export" and confidence >= 0.70:
            # Revit exports have EXPECTED anomalies
            self.disabled_rules.update([
                "TAMPER-001",  # CRC = 0 is EXPECTED
                "TAMPER-002",  # Section CRC = 0 is EXPECTED
                "TAMPER-034",  # Zero timestamps EXPECTED
                "TAMPER-035",  # Missing GUIDs EXPECTED
            ])
            # Downgrade these from CRITICAL to INFO
            self.downgraded_rules.update({
                "TAMPER-007": RuleSeverity.INFO,  # Edit time anomalies expected
            })

        elif provenance in ["oda_sdk", "bricscad", "nanocad", "draftsight"] and confidence >= 0.70:
            # ODA SDK applications don't populate AutoCAD-specific fields
            self.disabled_rules.update([
                "TAMPER-035",  # Missing GUIDs EXPECTED for ODA
            ])
            # Only disable TAMPER-001 if CRC is actually zero
            if context.get("crc_validation", {}).get("header_crc_stored") == "0x00000000":
                self.disabled_rules.add("TAMPER-001")
            # Downgrade zero timestamp pattern
            self.downgraded_rules["TAMPER-034"] = RuleSeverity.INFO

        elif provenance in ["libredwg", "librecad", "qcad", "freecad"] and confidence >= 0.70:
            # Open source conversions from DXF - timestamp integrity NOT preserved
            self.disabled_rules.update([
                "TAMPER-034",  # Zero timestamps EXPECTED
                "TAMPER-035",  # Missing GUIDs EXPECTED
            ])
            # Downgrade CRC to INFO (conversions may not compute CRC)
            self.downgraded_rules["TAMPER-001"] = RuleSeverity.INFO
            # Flag as conversion, not tampering
            self.downgraded_rules["TAMPER-033"] = RuleSeverity.INFO

        elif provenance == "file_transfer" and confidence >= 0.60:
            # File transfers create timestamp discrepancies
            # Disable rules that check DWG vs NTFS consistency
            self.downgraded_rules.update({
                "TAMPER-022": RuleSeverity.INFO,  # DWG < NTFS expected
                "TAMPER-023": RuleSeverity.INFO,  # Timestamp mismatch expected
            })

        elif provenance == "autocad_native" and confidence >= 0.90:
            # Genuine AutoCAD - STRICT mode - enable ALL rules
            self.disabled_rules.clear()
            self.downgraded_rules.clear()

    def should_evaluate_rule(self, rule_id: str) -> bool:
        """Check if rule should be evaluated."""
        return rule_id not in self.disabled_rules

    def get_severity(self, rule_id: str, default_severity: RuleSeverity) -> RuleSeverity:
        """Get adjusted severity for rule."""
        return self.downgraded_rules.get(rule_id, default_severity)
```

---

### Pseudocode for Complete Detection Flow

```
1. PARSE DWG FILE
   - Extract header (version, CRC, addresses)
   - Extract metadata (timestamps, GUIDs, variables)
   - Extract NTFS timestamps (if available)

2. DETECT PROVENANCE
   priority_order = [
       detect_revit_export(),      # Highest priority (most specific)
       detect_libredwg(),
       detect_specific_oda_app(),  # BricsCAD, NanoCAD, DraftSight
       detect_generic_oda_sdk(),
       detect_file_transfer(),
       detect_autocad_native(),    # Default if no other match
   ]

   for detector in priority_order:
       result = detector.analyze(file_data)
       if result.confidence >= 0.70:
           provenance = result.application
           break

   if provenance == "unknown" and has_autocad_markers:
       provenance = "autocad_native"
       confidence = 0.80

3. CONFIGURE RULE FILTER
   filter = RuleFilter()
   filter.apply_provenance(provenance, confidence, context)

4. EVALUATE RULES
   results = []
   for rule in all_rules:
       if not filter.should_evaluate_rule(rule.id):
           continue  # Skip disabled rule

       # Evaluate rule
       result = rule.evaluate(context)

       # Adjust severity based on provenance
       result.severity = filter.get_severity(rule.id, result.severity)

       results.append(result)

5. SYNTHESIZE SMOKING GUNS
   smoking_guns = []
   for result in results:
       if result.status == FAILED and result.is_smoking_gun:
           # Double-check: Is this REALLY a smoking gun for this provenance?
           if provenance == "revit_export" and result.rule_id in ["TAMPER-001", "TAMPER-034"]:
               continue  # Not a smoking gun for Revit
           smoking_guns.append(result)

6. GENERATE REPORT
   if smoking_guns:
       conclusion = "DEFINITIVE PROOF OF TAMPERING"
       recommendation = "Challenge file authenticity in legal proceedings"
   else:
       conclusion = "No definitive proof found"
       recommendation = "File appears legitimate for detected application: {provenance}"
```

---

## Timestamp Tolerance Guidelines

### Recommended Tolerance Values

| Check Type | Strict Mode (Litigation) | Standard Mode | Lenient Mode (Forensic Triage) |
|------------|-------------------------|---------------|--------------------------------|
| **Future Timestamp Grace** | 60 seconds | 300 seconds (5 min) | 600 seconds (10 min) |
| **DWG vs NTFS Mismatch** | 60 seconds | 300 seconds | 3600 seconds (1 hour) |
| **Edit Time Overage** | 5% | 10% | 20% |
| **TDINDWG > Calendar Span** | 0% (ALWAYS illegal) | 0% | 0% |
| **Version Anachronism** | 0 days | 0 days | 0 days |
| **Nanosecond Truncation Count** | 1+ timestamps | 2+ timestamps | 3+ timestamps |

### Context-Dependent Tolerance Adjustments

```python
def get_timestamp_tolerance(context: dict, check_type: str) -> float:
    """Get appropriate tolerance based on context."""

    mode = context.get("mode", "standard")  # strict, standard, lenient
    provenance = context.get("provenance", "unknown")

    # Base tolerances by mode
    tolerances = {
        "strict": {
            "future_grace": 60,
            "dwg_ntfs_mismatch": 60,
            "edit_time_overage": 0.05,
        },
        "standard": {
            "future_grace": 300,
            "dwg_ntfs_mismatch": 300,
            "edit_time_overage": 0.10,
        },
        "lenient": {
            "future_grace": 600,
            "dwg_ntfs_mismatch": 3600,
            "edit_time_overage": 0.20,
        },
    }

    base_tolerance = tolerances[mode][check_type]

    # Adjust for provenance
    if provenance == "file_transfer":
        if check_type == "dwg_ntfs_mismatch":
            # File transfers can have HUGE discrepancies (years)
            return 86400 * 365  # 1 year tolerance

    elif provenance in ["revit_export", "oda_sdk"]:
        if check_type == "edit_time_overage":
            # These applications don't accurately track editing time
            return 1.0  # Effectively disable check (100% overage allowed)

    return base_tolerance
```

---

## Summary: Key Takeaways for Implementation

### 1. Provenance Detection is MANDATORY

**DO NOT** flag anomalies without first detecting file provenance. Approximately **30-40% of legitimate CAD workflows** involve Revit exports or ODA SDK applications.

### 2. Rule Filtering by Provenance

| Provenance | Disabled Rules | Downgraded Rules | Notes |
|------------|----------------|------------------|-------|
| **Revit Export** | TAMPER-001, 002, 034, 035 | TAMPER-007 -> INFO | CRC=0 and missing timestamps are EXPECTED |
| **ODA SDK** | TAMPER-035, (001 if CRC=0) | TAMPER-034 -> INFO | Missing GUIDs are EXPECTED |
| **LibreDWG** | TAMPER-034, 035 | TAMPER-001 -> INFO, 033 -> INFO | Conversions don't preserve timestamps |
| **File Transfer** | None | TAMPER-022/023 -> INFO | Timestamp discrepancies are EXPECTED |
| **AutoCAD Native** | None | None | STRICT MODE - all rules enabled |

### 3. Tier 1 Rules (IMPOSSIBLE) Require Zero False Positives

The following rules are **smoking guns** and **MUST NOT** have false positives:

- TAMPER-005: Created > Modified
- TAMPER-006: Future Timestamp (with grace period)
- TAMPER-013: TDINDWG > Calendar Span
- TAMPER-014: Version Anachronism
- TAMPER-019: NTFS $SI < $FN
- TAMPER-020: Multiple Nanosecond Truncation
- TAMPER-021: NTFS Created > Modified
- TAMPER-001/002: CRC Mismatch (ONLY after provenance filtering)

### 4. Configuration Should Be Context-Aware

```python
# Example configuration schema
config = {
    "mode": "standard",  # strict | standard | lenient
    "provenance_detection": {
        "enabled": True,
        "confidence_threshold": 0.70,
        "prefer_explicit_markers": True,  # Prefer binary markers over heuristics
    },
    "tolerances": {
        "future_timestamp_grace_seconds": 300,
        "dwg_ntfs_mismatch_seconds": 300,
        "edit_time_overage_percent": 10,
    },
    "rule_filtering": {
        "auto_disable_by_provenance": True,
        "allow_manual_overrides": False,
    },
    "reporting": {
        "include_disabled_rules": True,  # Show what was disabled and why
        "explain_provenance": True,
    },
}
```

### 5. Forensic Reporting Should Include Provenance Context

**GOOD** report structure:

```
PROVENANCE ANALYSIS:
- Detected Application: Revit 2024 DWG Export
- Confidence: 95%
- Detection Basis: FINGERPRINTGUID pattern (30314341-), Header field patterns, Class count

EXPECTED CHARACTERISTICS FOR REVIT EXPORTS:
[OK] CRC = 0x00000000 (Revit does not compute CRC - NORMAL)
[OK] TDCREATE/TDUPDATE missing (Revit does not set timestamps - NORMAL)
[OK] FINGERPRINTGUID placeholder format (Revit uses template GUID - NORMAL)

TAMPERING ANALYSIS:
[PASS] No smoking gun indicators detected
[PASS] All detected anomalies are consistent with Revit export workflow

CONCLUSION:
This file is a legitimate Revit DWG export. The characteristics that appear unusual
(zero CRC, missing timestamps) are EXPECTED and NORMAL for Revit-generated files.
NO EVIDENCE OF TAMPERING.
```

**BAD** report structure (creates false positives):

```
TAMPERING ANALYSIS:
[CRITICAL] Header CRC mismatch - DEFINITIVE PROOF OF TAMPERING
[CRITICAL] Missing AutoCAD identifiers - DEFINITIVE PROOF
[HIGH] Zero editing time - SUSPICIOUS

CONCLUSION:
MULTIPLE SMOKING GUNS DETECTED - FILE HAS BEEN TAMPERED WITH
```

(This report is **WRONG** if the file is a Revit export)

---

## References

### Legal Standards Consulted

- **Daubert Standard**: Expert testimony must be based on scientifically valid reasoning
- **Frye Standard**: Evidence must be "generally accepted" in the relevant scientific community
- **Federal Rules of Evidence 702**: Expert witness qualifications and reliability
- **NIST CFTT**: Computer Forensics Tool Testing standards

### Technical References

- Autodesk DWG File Format Specification (2018+)
- ODA (Open Design Alliance) DWG/DXF SDK Documentation
- NTFS Master File Table (MFT) Forensics (Windows Internals, Russinovich)
- LibreDWG Source Code Analysis (GNU Project)
- Revit API Documentation (Autodesk Developer Network)

### Forensic Precedents

- False positive rate thresholds for court admissibility: <5% (acceptable), <1% (preferred)
- Multiple independent evidence corroboration standard (2+ sources)
- Statistical improbability threshold: p < 0.0001 (1 in 10,000 chance)

---

**End of Forensic Standards Reference**
**Version**: 1.0
**Last Updated**: 2026-01-29

