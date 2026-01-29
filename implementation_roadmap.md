# DWG Forensic Tool: False Positive Fix Implementation Roadmap

## Executive Summary

This document provides a comprehensive design for eliminating false positives in the DWG Forensic Tool by introducing **file provenance detection** before tampering analysis. The solution calibrates tampering rules and anomaly detection based on file origin (AutoCAD native, Revit export, ODA SDK tools, file transfers).

**Key Problem**: Current implementation treats all anomalies as tampering indicators without considering legitimate file origins. Revit exports trigger CRC mismatches, ODA tools have different timestamp patterns, and file transfers cause filesystem/internal timestamp divergence.

**Solution**: Three-layer architecture:
1. **FileProvenance Module**: Detect file origin before rules run
2. **Context-Aware Rule Calibration**: Adjust confidence levels per provenance
3. **Dynamic Anomaly Tolerance**: Tolerances adapt to file context

---

## 1. FileProvenance Detection Module Design

### 1.1 Class Structure (Pseudocode)

```python
# File: dwg_forensic/analysis/file_provenance.py

from enum import Enum
from typing import Dict, Optional
from dataclasses import dataclass

class ProvenanceType(Enum):
    """File origin classification"""
    NATIVE_AUTOCAD = "native_autocad"
    REVIT_EXPORT = "revit_export"
    ODA_SDK_TOOL = "oda_sdk_tool"
    FILE_TRANSFER = "file_transfer"
    UNKNOWN = "unknown"

@dataclass
class ProvenanceContext:
    """Complete file provenance information"""
    provenance_type: ProvenanceType
    confidence: float  # 0.0 to 1.0
    evidence: List[str]
    recommended_timestamp_tolerance_seconds: int
    recommended_null_padding_threshold: float
    skip_rules: List[str]  # Rule IDs to skip (e.g., ["TAMPER-001", "TAMPER-002"])
    adjust_rule_confidence: Dict[str, float]  # Rule ID -> confidence multiplier

class FileProvenanceDetector:
    """Detect file origin before tampering analysis"""
    
    def __init__(self, fingerprinter: CADFingerprinter):
        self.fingerprinter = fingerprinter
        
    def detect_provenance(
        self, 
        file_path: str,
        header: DWGHeader,
        metadata: DWGMetadata,
        fingerprint_data: Dict
    ) -> ProvenanceContext:
        """
        Main detection method - orchestrates all checks
        
        Decision tree:
        1. Check Revit export signatures (highest priority)
        2. Check ODA SDK signatures
        3. Check file transfer indicators
        4. Default to native AutoCAD if no special patterns
        """
        # PRIORITY 1: Revit Export Detection
        if self.is_revit_export(header, metadata, fingerprint_data):
            return ProvenanceContext(
                provenance_type=ProvenanceType.REVIT_EXPORT,
                confidence=0.95,
                evidence=self._collect_revit_evidence(fingerprint_data),
                recommended_timestamp_tolerance_seconds=3600,  # 1 hour
                recommended_null_padding_threshold=0.5,  # 50% allowed
                skip_rules=["TAMPER-001", "TAMPER-002", "TAMPER-013"],
                adjust_rule_confidence={
                    "TAMPER-019": 0.3,  # NTFS cross-validation less reliable
                    "TAMPER-020": 0.3,
                }
            )
        
        # PRIORITY 2: ODA SDK Tool Detection
        oda_app = self.detect_oda_tool(fingerprint_data)
        if oda_app:
            return ProvenanceContext(
                provenance_type=ProvenanceType.ODA_SDK_TOOL,
                confidence=0.90,
                evidence=[f"ODA SDK application: {oda_app}"],
                recommended_timestamp_tolerance_seconds=600,  # 10 minutes
                recommended_null_padding_threshold=0.4,  # 40% allowed
                skip_rules=["TAMPER-001"],  # CRC may be zero
                adjust_rule_confidence={
                    "TAMPER-014": 0.5,  # Version anachronism less concerning
                }
            )
        
        # PRIORITY 3: File Transfer Detection
        if self.is_file_transfer(header, metadata):
            return ProvenanceContext(
                provenance_type=ProvenanceType.FILE_TRANSFER,
                confidence=0.80,
                evidence=self._collect_transfer_evidence(header, metadata),
                recommended_timestamp_tolerance_seconds=3600,  # 1 hour
                recommended_null_padding_threshold=0.3,  # 30% (unchanged)
                skip_rules=[],
                adjust_rule_confidence={
                    "TAMPER-019": 0.2,  # Filesystem mismatch expected
                    "TAMPER-020": 0.2,
                    "TAMPER-021": 0.2,
                }
            )
        
        # DEFAULT: Native AutoCAD
        return ProvenanceContext(
            provenance_type=ProvenanceType.NATIVE_AUTOCAD,
            confidence=0.70,
            evidence=["No special signatures detected"],
            recommended_timestamp_tolerance_seconds=300,  # 5 minutes
            recommended_null_padding_threshold=0.3,  # 30%
            skip_rules=[],
            adjust_rule_confidence={}  # No adjustments
        )
    
    def is_revit_export(self, header, metadata, fingerprint_data) -> bool:
        """
        Detect Revit export signatures
        
        Evidence (ANY of these indicates Revit):
        - FINGERPRINTGUID starts with "30314341-" (ASCII "01CA")
        - Zero CRC + TDINDWG < 5 minutes
        - HANDSEED[1] == 3 (Revit pattern)
        - TrustedDWG watermark absent + zero editing time
        """
        evidence_count = 0
        
        # Check 1: FINGERPRINTGUID pattern (STRONGEST indicator)
        fingerprint_guid = fingerprint_data.get("FINGERPRINTGUID", "")
        if fingerprint_guid.upper().startswith("30314341-"):
            evidence_count += 3  # Strong weight
        
        # Check 2: Zero CRC + minimal editing time
        if header.crc == 0 or header.crc is None:
            tdindwg = metadata.drawing_vars.get("TDINDWG")
            if tdindwg and self._parse_time_duration(tdindwg) < 300:  # <5 min
                evidence_count += 2
        
        # Check 3: HANDSEED pattern
        handseed = fingerprint_data.get("HANDSEED", [])
        if len(handseed) > 1 and handseed[1] == 3:
            evidence_count += 1
        
        # Check 4: Missing watermark + zero editing time
        if not fingerprint_data.get("has_trusteddwg"):
            tdindwg = metadata.drawing_vars.get("TDINDWG")
            if tdindwg and self._parse_time_duration(tdindwg) < 60:  # <1 min
                evidence_count += 1
        
        # Threshold: Need 3+ points of evidence
        return evidence_count >= 3
    
    def detect_oda_tool(self, fingerprint_data) -> Optional[str]:
        """
        Detect ODA SDK-based applications
        
        Returns: Application name or None
        Applications: BricsCAD, NanoCAD, DraftSight, ZWCAD, GStarCAD
        """
        # Use existing CADFingerprinter.detect_oda_based() logic
        if fingerprint_data.get("is_oda_based"):
            return fingerprint_data.get("likely_application", "ODA_SDK_UNKNOWN")
        return None
    
    def is_file_transfer(self, header, metadata) -> bool:
        """
        Detect file transfer scenarios
        
        Indicators:
        - Large filesystem vs internal timestamp divergence (>1 hour)
        - NTFS creation date significantly newer than DWG internal dates
        - Timezone discrepancies (UTC vs local time)
        """
        # Check filesystem metadata if available
        if hasattr(header, 'filesystem_modified') and metadata.modified_date:
            fs_modified = header.filesystem_modified
            internal_modified = metadata.modified_date
            
            diff_seconds = abs((internal_modified - fs_modified).total_seconds())
            
            # Large divergence indicates transfer
            if diff_seconds > 3600:  # >1 hour
                return True
        
        # Check NTFS vs DWG timestamp patterns
        # (Requires NTFS metadata from parsers/ntfs.py)
        # if ntfs_create_time > internal_create_time + 1 day: return True
        
        return False
    
    def get_provenance_summary(self, context: ProvenanceContext) -> str:
        """Generate human-readable summary"""
        summary = f"File Provenance: {context.provenance_type.value.upper()} "
        summary += f"(confidence: {context.confidence:.0%})\n"
        summary += f"Evidence: {', '.join(context.evidence)}\n"
        summary += f"Recommended timestamp tolerance: {context.recommended_timestamp_tolerance_seconds}s\n"
        if context.skip_rules:
            summary += f"Rules to skip: {', '.join(context.skip_rules)}\n"
        return summary
```

### 1.2 Integration Point

Insert provenance detection into `dwg_forensic/core/analyzer.py` immediately after CAD fingerprinting:

```python
# In ForensicAnalyzer.analyze()

# STEP 1: CAD fingerprinting (existing)
fingerprint_results = self.cad_fingerprinter.fingerprint(...)

# STEP 2: **NEW** Provenance detection
provenance_detector = FileProvenanceDetector(self.cad_fingerprinter)
provenance_context = provenance_detector.detect_provenance(
    file_path=file_path,
    header=header,
    metadata=metadata,
    fingerprint_data=fingerprint_results
)

# STEP 3: Pass context to downstream modules
anomaly_detector = AnomalyDetector(provenance_context=provenance_context)
rule_engine = TamperingRuleEngine(provenance_context=provenance_context)
```

---

## 2. Rule Calibration Strategy

### 2.1 Confidence Matrix

Table showing how each rule's confidence should be adjusted based on file provenance:

| Rule ID | Rule Name | AutoCAD | Revit Export | ODA SDK | File Transfer | Notes |
|---------|-----------|---------|--------------|---------|---------------|-------|
| TAMPER-001 | CRC Mismatch | 1.0 DEFINITIVE | **SKIP** | **SKIP** | 1.0 DEFINITIVE | Revit/ODA legitimately have zero CRC |
| TAMPER-002 | Missing CRC | 0.9 STRONG | **SKIP** | **SKIP** | 0.9 STRONG | Same as above |
| TAMPER-003 | Missing Watermark | 0.7 MODERATE | 0.2 LOW | 0.4 WEAK | 0.7 MODERATE | Revit exports don't have TrustedDWG |
| TAMPER-004 | Invalid Watermark | 0.9 STRONG | 0.3 WEAK | 0.5 MODERATE | 0.9 STRONG | Less significant for exports |
| TAMPER-013 | Zero Editing Time | 0.8 STRONG | **SKIP** | 0.3 WEAK | 0.8 STRONG | Revit exports have TDINDWG near zero |
| TAMPER-014 | Version Anachronism | 0.9 STRONG | 0.4 WEAK | 0.5 MODERATE | 0.9 STRONG | ODA tools may have version mismatches |
| TAMPER-015 | Timestamp Manipulation | 0.85 STRONG | 0.3 WEAK | 0.6 MODERATE | **0.2 LOW** | File transfer causes timestamp drift |
| TAMPER-016 | Future Timestamp | 1.0 DEFINITIVE | 0.7 MODERATE | 0.8 STRONG | 0.5 MODERATE | Less concerning after transfer |
| TAMPER-017 | Impossible Sequence | 0.95 STRONG | 0.5 MODERATE | 0.7 MODERATE | 0.4 WEAK | Transfers break sequence assumptions |
| TAMPER-018 | Retroactive Creation | 0.9 STRONG | 0.4 WEAK | 0.6 MODERATE | **0.3 WEAK** | Common in file transfers |
| TAMPER-019 | NTFS Cross-Validation | 0.95 STRONG | **0.3 WEAK** | 0.7 MODERATE | **0.2 LOW** | Filesystem metadata unreliable after transfer |
| TAMPER-020 | NTFS Mismatch | 0.9 STRONG | **0.3 WEAK** | 0.6 MODERATE | **0.2 LOW** | Same as above |
| TAMPER-021-028 | NTFS Rules | 0.85 STRONG | **0.3 WEAK** | 0.6 MODERATE | **0.2 LOW** | All NTFS rules downgraded for transfers |
| TAMPER-029-035 | Fingerprint Rules | 0.8 STRONG | 0.8 STRONG | 0.8 STRONG | 0.8 STRONG | Fingerprints remain valid evidence |
| TAMPER-036-040 | Structure Rules | 0.9 STRONG | 0.7 MODERATE | 0.7 MODERATE | 0.9 STRONG | Handle gaps less significant for ODA/Revit |
| TAMPER-041 | Revit Export Signature | N/A | 1.0 DEFINITIVE | 0.5 MODERATE | N/A | Positive confirmation of Revit origin |

**Legend**:
- **DEFINITIVE (1.0)**: Irrefutable proof
- **STRONG (0.85-0.95)**: Very high confidence
- **MODERATE (0.6-0.8)**: Significant but not conclusive
- **WEAK (0.3-0.5)**: Circumstantial evidence
- **LOW (0.1-0.2)**: Nearly irrelevant
- **SKIP**: Rule should not fire at all

### 2.2 Rule Engine Modification

Modify `dwg_forensic/analysis/rules/engine.py` to accept and apply provenance context:

```python
# In TamperingRuleEngine class

class TamperingRuleEngine:
    def __init__(self, provenance_context: Optional[ProvenanceContext] = None):
        self.provenance_context = provenance_context
        # ... existing initialization
    
    def evaluate_rule(self, rule_id: str, ...) -> TamperingRule:
        """Evaluate single rule with provenance-aware calibration"""
        
        # Check if rule should be skipped
        if self.provenance_context and rule_id in self.provenance_context.skip_rules:
            return None  # Skip this rule entirely
        
        # Execute rule logic (existing)
        result = self._execute_rule_logic(rule_id, ...)
        
        # Apply confidence adjustment
        if self.provenance_context and rule_id in self.provenance_context.adjust_rule_confidence:
            multiplier = self.provenance_context.adjust_rule_confidence[rule_id]
            result.confidence *= multiplier
            result.forensic_notes.append(
                f"Confidence adjusted to {result.confidence:.2f} based on file provenance "
                f"({self.provenance_context.provenance_type.value})"
            )
        
        return result
```

---

## 3. Anomaly Detection Refactor

### 3.1 Current Problems in `anomaly.py`

**Problem 1**: Lines 159-179 - Hardcoded 5-minute tolerance
```python
# CURRENT CODE (TOO STRICT)
if diff_seconds > 300:  # 5 minutes - fails for file transfers
    anomalies.append(...)
```

**Problem 2**: Lines 286-300 - Hardcoded 30% null padding threshold
```python
# CURRENT CODE (TOO AGGRESSIVE)
if null_ratio > 0.3:  # 30% - fails for legitimate exports
    anomalies.append(...)
```

### 3.2 Refactored Design (Context-Aware)

```python
# File: dwg_forensic/analysis/anomaly.py

class AnomalyDetector:
    def __init__(self, provenance_context: Optional[ProvenanceContext] = None):
        """Initialize with optional provenance context for dynamic tolerances"""
        self.provenance_context = provenance_context
        
        # Set dynamic tolerances based on provenance
        if provenance_context:
            self.timestamp_tolerance_seconds = provenance_context.recommended_timestamp_tolerance_seconds
            self.null_padding_threshold = provenance_context.recommended_null_padding_threshold
        else:
            # Default tolerances (legacy behavior)
            self.timestamp_tolerance_seconds = 300  # 5 minutes
            self.null_padding_threshold = 0.3  # 30%
    
    def detect_all_anomalies(self, file_path: str, ...) -> List[Anomaly]:
        """Main detection method with context-aware checks"""
        anomalies = []
        
        # Check 1: Header validation (unchanged)
        anomalies.extend(self._check_header_validity(header))
        
        # Check 2: Version consistency (unchanged)
        anomalies.extend(self._check_version_consistency(header, metadata))
        
        # Check 3: Timestamp consistency (MODIFIED - uses self.timestamp_tolerance_seconds)
        anomalies.extend(self._check_timestamp_consistency(metadata))
        
        # Check 4: Filesystem vs internal (MODIFIED - uses self.timestamp_tolerance_seconds)
        anomalies.extend(self._check_filesystem_mismatch(metadata, fs_metadata))
        
        # Check 5: Null padding (MODIFIED - uses self.null_padding_threshold)
        anomalies.extend(self._check_null_padding(file_data))
        
        # Apply provenance-based filtering
        if self.provenance_context:
            anomalies = self._filter_by_provenance(anomalies)
        
        return anomalies
    
    def _check_filesystem_mismatch(self, metadata, fs_metadata) -> List[Anomaly]:
        """Check 4 - REFACTORED with dynamic tolerance"""
        anomalies = []
        
        if metadata.modified_date and fs_metadata.modified_date:
            diff_seconds = abs((metadata.modified_date - fs_metadata.modified_date).total_seconds())
            
            # Use dynamic tolerance instead of hardcoded 300 seconds
            if diff_seconds > self.timestamp_tolerance_seconds:
                severity = self._calculate_mismatch_severity(diff_seconds)
                
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.TIMESTAMP_MISMATCH,
                        description=(
                            f"Filesystem modified time differs from internal by {diff_seconds:.0f} seconds "
                            f"(tolerance: {self.timestamp_tolerance_seconds}s)"
                        ),
                        severity=severity,
                        timestamp=metadata.modified_date,
                        details={
                            "internal_modified": metadata.modified_date.isoformat(),
                            "filesystem_modified": fs_metadata.modified_date.isoformat(),
                            "diff_seconds": diff_seconds,
                            "tolerance_seconds": self.timestamp_tolerance_seconds,
                            "provenance_adjusted": self.provenance_context is not None,
                        }
                    )
                )
        
        return anomalies
    
    def _check_null_padding(self, file_data: bytes) -> List[Anomaly]:
        """Check 5 - REFACTORED with dynamic threshold"""
        anomalies = []
        
        null_ratio = self._calculate_null_ratio(file_data)
        
        # Use dynamic threshold instead of hardcoded 0.3
        if null_ratio > self.null_padding_threshold:
            anomalies.append(
                Anomaly(
                    anomaly_type=AnomalyType.OTHER,
                    description=(
                        f"Excessive null byte padding: {null_ratio:.1%} "
                        f"(threshold: {self.null_padding_threshold:.1%})"
                    ),
                    severity=RiskLevel.MEDIUM,
                    details={
                        "null_ratio": null_ratio,
                        "threshold": self.null_padding_threshold,
                        "provenance_adjusted": self.provenance_context is not None,
                    }
                )
            )
        
        return anomalies
    
    def _calculate_mismatch_severity(self, diff_seconds: float) -> RiskLevel:
        """Calculate severity based on magnitude of mismatch"""
        if diff_seconds > 86400:  # >1 day
            return RiskLevel.HIGH
        elif diff_seconds > 3600:  # >1 hour
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _filter_by_provenance(self, anomalies: List[Anomaly]) -> List[Anomaly]:
        """Filter out expected anomalies based on provenance"""
        if not self.provenance_context:
            return anomalies
        
        filtered = []
        for anomaly in anomalies:
            # Example: Skip filesystem mismatches for file transfers
            if (self.provenance_context.provenance_type == ProvenanceType.FILE_TRANSFER and
                anomaly.anomaly_type == AnomalyType.TIMESTAMP_MISMATCH):
                # Downgrade severity instead of removing
                anomaly.severity = RiskLevel.LOW
                anomaly.description += " (expected for file transfer)"
            
            filtered.append(anomaly)
        
        return filtered
```

---

## 4. Implementation Roadmap

### Phase 1: Provenance Detection Foundation (Week 1-2)

**Objective**: Add file provenance detection module without breaking existing functionality.

**Tasks**:
1. Create `dwg_forensic/analysis/file_provenance.py`
   - Implement `ProvenanceType` enum
   - Implement `ProvenanceContext` dataclass
   - Implement `FileProvenanceDetector` class with all detection methods
   
2. Add unit tests for provenance detection
   - `tests/analysis/test_file_provenance.py`
   - Test cases: Revit export, ODA tools, file transfers, native AutoCAD
   - Use existing sample DWG files from `exampleCAD/`

3. Integrate into `analyzer.py` (optional flag initially)
   - Add `--enable-provenance` CLI flag for testing
   - Insert provenance detection step after fingerprinting
   - Pass context to anomaly detector and rule engine (but don't use it yet)

**Files to Modify**:
- NEW: `dwg_forensic/analysis/file_provenance.py` (~400 lines)
- MODIFY: `dwg_forensic/core/analyzer.py` (lines 150-200, add provenance step)
- MODIFY: `dwg_forensic/cli.py` (add `--enable-provenance` flag)
- NEW: `tests/analysis/test_file_provenance.py` (~300 lines)

**Risk Assessment**: **LOW**
- New module doesn't affect existing logic
- Optional flag prevents production impact
- Can be tested independently

**Success Criteria**:
- All provenance detection tests pass
- Analyzer runs with and without `--enable-provenance` flag
- No regressions in existing test suite

---

### Phase 2: Rule Calibration (Week 3-4)

**Objective**: Modify rule engine to apply provenance-based confidence adjustments.

**Tasks**:
1. Modify `TamperingRuleEngine` to accept `ProvenanceContext`
   - Update `__init__()` to store provenance context
   - Implement rule skipping logic in `evaluate_rule()`
   - Implement confidence adjustment logic
   
2. Create confidence matrix configuration
   - `dwg_forensic/analysis/rules/confidence_matrix.yaml`
   - Map each rule ID to confidence values per provenance type
   - Load matrix in rule engine initialization

3. Add provenance-aware forensic notes
   - When confidence is adjusted, append explanation to `forensic_notes`
   - Example: "Confidence reduced from 0.9 to 0.3 due to Revit export provenance"

4. Update existing rules to check provenance
   - Modify rules TAMPER-001, TAMPER-002 (CRC) to skip for Revit/ODA
   - Modify rules TAMPER-019-028 (NTFS) to downgrade for transfers
   - Modify rule TAMPER-013 (zero editing time) to skip for Revit

5. Add integration tests
   - Test Revit export file: CRC rules should be skipped
   - Test file transfer scenario: NTFS rules should have low confidence
   - Test native AutoCAD: No adjustments

**Files to Modify**:
- MODIFY: `dwg_forensic/analysis/rules/engine.py` (lines 50-100, add provenance logic)
- NEW: `dwg_forensic/analysis/rules/confidence_matrix.yaml` (~150 lines)
- MODIFY: `dwg_forensic/analysis/rules/rules_basic.py` (CRC rules, lines 58-89)
- MODIFY: `dwg_forensic/analysis/rules/rules_ntfs.py` (NTFS rules, lines 206-400)
- MODIFY: `dwg_forensic/analysis/rules/rules_timestamp.py` (timestamp rules, lines 100-200)
- NEW: `tests/analysis/rules/test_provenance_calibration.py` (~400 lines)

**Risk Assessment**: **MEDIUM**
- Changes core rule evaluation logic
- Must ensure backward compatibility
- Requires extensive testing with real-world files

**Success Criteria**:
- Revit export test file: No CRC mismatch false positives
- File transfer scenario: NTFS cross-validation downgraded to LOW confidence
- Native AutoCAD file: No behavior change
- All existing tests pass

---

### Phase 3: Anomaly Detection Refactor (Week 5)

**Objective**: Make anomaly detection context-aware with dynamic tolerances.

**Tasks**:
1. Refactor `AnomalyDetector.__init__()` to accept `ProvenanceContext`
   - Set `self.timestamp_tolerance_seconds` from context
   - Set `self.null_padding_threshold` from context
   - Maintain backward compatibility with default values

2. Update `_check_filesystem_mismatch()` method
   - Replace hardcoded 300 seconds with `self.timestamp_tolerance_seconds`
   - Add provenance information to anomaly details
   - Implement severity calculation based on magnitude

3. Update `_check_null_padding()` method
   - Replace hardcoded 0.3 with `self.null_padding_threshold`
   - Add provenance information to anomaly details

4. Implement `_filter_by_provenance()` method
   - Downgrade severity for expected anomalies
   - Add explanatory notes (e.g., "expected for file transfer")

5. Add unit tests for context-aware behavior
   - Test with different provenance contexts
   - Verify tolerance adjustments
   - Verify severity calculations

**Files to Modify**:
- MODIFY: `dwg_forensic/analysis/anomaly.py` (lines 45-60, 159-179, 286-300)
- NEW: `tests/analysis/test_anomaly_provenance.py` (~250 lines)

**Risk Assessment**: **MEDIUM-HIGH**
- Changes fundamental anomaly detection behavior
- Risk of introducing new false negatives
- Must carefully tune tolerances

**Success Criteria**:
- File transfer scenario: Filesystem mismatch uses 1-hour tolerance (not 5 minutes)
- Revit export: Null padding threshold at 50% (not 30%)
- Native AutoCAD: No behavior change (5-minute tolerance, 30% threshold)
- Zero new false negatives introduced

---

### Phase 4: Testing & Validation (Week 6)

**Objective**: Comprehensive end-to-end testing and performance validation.

**Tasks**:
1. Create comprehensive test suite
   - `tests/integration/test_provenance_e2e.py`
   - Test all provenance types end-to-end
   - Include real-world DWG files from `exampleCAD/`

2. Regression testing
   - Run full test suite against all existing test files
   - Verify no new false positives introduced
   - Verify no new false negatives introduced

3. Performance benchmarking
   - Measure provenance detection overhead (<5% acceptable)
   - Ensure total analysis time doesn't increase significantly

4. Documentation updates
   - Update README.md with provenance detection explanation
   - Add provenance section to PDF report template
   - Document confidence matrix in CLAUDE.md

5. Enable by default
   - Remove `--enable-provenance` flag
   - Make provenance detection default behavior
   - Add `--disable-provenance` flag for legacy mode (if needed)

**Files to Modify**:
- NEW: `tests/integration/test_provenance_e2e.py` (~500 lines)
- MODIFY: `README.md` (add provenance section)
- MODIFY: `dwg_forensic/output/pdf_report.py` (add provenance to report)
- MODIFY: `dwg_forensic/cli.py` (make provenance default)
- MODIFY: `CLAUDE.md` (document confidence matrix)

**Risk Assessment**: **LOW**
- Testing phase, minimal code changes
- Can roll back if critical issues found
- Provides confidence for production deployment

**Success Criteria**:
- All 200+ existing tests pass
- 50+ new provenance-specific tests pass
- Provenance detection overhead <5%
- Zero critical bugs found in manual testing
- Documentation complete and accurate

---

## 5. File & Function Modification Summary

### Files to Create (7 new files):
1. `dwg_forensic/analysis/file_provenance.py` (~400 lines)
2. `dwg_forensic/analysis/rules/confidence_matrix.yaml` (~150 lines)
3. `tests/analysis/test_file_provenance.py` (~300 lines)
4. `tests/analysis/rules/test_provenance_calibration.py` (~400 lines)
5. `tests/analysis/test_anomaly_provenance.py` (~250 lines)
6. `tests/integration/test_provenance_e2e.py` (~500 lines)
7. `implementation_roadmap.md` (this document)

### Files to Modify (10 existing files):

#### 1. `dwg_forensic/core/analyzer.py`
**Lines**: 150-200 (provenance integration point)
**Changes**: 
- Import `FileProvenanceDetector`
- Call `detect_provenance()` after fingerprinting
- Pass `provenance_context` to `AnomalyDetector` and `TamperingRuleEngine`

#### 2. `dwg_forensic/analysis/anomaly.py`
**Lines**: 45-60 (init), 159-179 (filesystem check), 286-300 (null padding)
**Changes**:
- Accept `provenance_context` parameter in `__init__()`
- Set dynamic tolerances from context
- Replace hardcoded values with instance variables
- Add provenance information to anomaly details

#### 3. `dwg_forensic/analysis/rules/engine.py`
**Lines**: 50-100 (init and evaluate methods)
**Changes**:
- Accept `provenance_context` parameter in `__init__()`
- Implement rule skipping logic in `evaluate_rule()`
- Implement confidence adjustment logic
- Load confidence matrix from YAML

#### 4. `dwg_forensic/analysis/rules/rules_basic.py`
**Lines**: 58-89 (TAMPER-001, TAMPER-002 CRC rules)
**Changes**:
- Check provenance before firing CRC rules
- Skip for Revit/ODA exports
- Add explanatory forensic notes

#### 5. `dwg_forensic/analysis/rules/rules_ntfs.py`
**Lines**: 206-400 (TAMPER-019 to TAMPER-028)
**Changes**:
- Downgrade confidence for file transfers
- Add provenance context to forensic notes

#### 6. `dwg_forensic/analysis/rules/rules_timestamp.py`
**Lines**: 100-200 (timestamp manipulation rules)
**Changes**:
- Skip TAMPER-013 (zero editing time) for Revit exports
- Downgrade TAMPER-015 (timestamp manipulation) for transfers

#### 7. `dwg_forensic/cli.py`
**Lines**: 30-50 (argument parsing)
**Changes**:
- Add `--enable-provenance` flag (Phase 1)
- Remove flag and make default (Phase 4)

#### 8. `dwg_forensic/output/pdf_report.py`
**Lines**: TBD (add new section)
**Changes**:
- Add "File Provenance" section to PDF report
- Display provenance type, confidence, evidence
- Show adjusted rule confidences

#### 9. `README.md`
**Lines**: 50-100 (Architecture section)
**Changes**:
- Add provenance detection explanation
- Document confidence matrix concept
- Add example of provenance-aware output

#### 10. `CLAUDE.md`
**Lines**: 40-60 (Key Implementation Details)
**Changes**:
- Document confidence matrix table
- Add provenance detection to architecture overview
- Update file size limits if needed

---

## 6. Risk Assessment Per Phase

### Phase 1 Risk: **LOW** (10% failure risk)
**Mitigation**:
- Provenance module is isolated (no side effects)
- Optional flag prevents production impact
- Extensive unit tests before integration

**Rollback Plan**: Remove new module, revert analyzer.py changes

---

### Phase 2 Risk: **MEDIUM** (30% failure risk)
**Mitigation**:
- Load confidence matrix from config (easy to tune without code changes)
- Gradual rollout: Enable for specific file types first
- A/B testing: Compare old vs new confidence values

**Rollback Plan**: Disable provenance context in rule engine, use legacy confidence values

---

### Phase 3 Risk: **MEDIUM-HIGH** (40% failure risk)
**Mitigation**:
- Start with conservative tolerances (1 hour for transfers, not 24 hours)
- Monitor false negative rate in testing
- Add telemetry to track tolerance effectiveness

**Rollback Plan**: Revert to hardcoded tolerances, disable provenance context in anomaly detector

---

### Phase 4 Risk: **LOW** (5% failure risk)
**Mitigation**:
- Extensive testing before enabling by default
- Canary deployment: Enable for subset of users first
- Keep `--disable-provenance` escape hatch

**Rollback Plan**: Change default to disabled, recommend users opt-in with flag

---

## 7. Expected Outcomes

### Quantitative Goals:
- **False Positive Reduction**: 80% reduction for Revit exports, 60% for ODA tools, 70% for file transfers
- **False Negative Rate**: <5% increase (acceptable trade-off)
- **Performance Overhead**: <5% increase in total analysis time
- **Test Coverage**: 90%+ for provenance module

### Qualitative Goals:
- Improved user trust in forensic reports
- Clearer explanations for rule confidence adjustments
- Better expert witness testimony support (provenance-aware reasoning)
- Reduced manual review burden

---

## 8. Critical Files for Implementation

1. **C:\Users\JordanEhrig\Documents\GitHub\DWG-forensic-tool\dwg_forensic\analysis\cad_fingerprinting.py**
   - Contains existing Revit/ODA detection logic to reuse
   - Lines 744-802: `detect_revit_export()` method
   - Lines 994-1005: FINGERPRINTGUID pattern detection
   - Lines 1106-1175: `detect_oda_based()` method

2. **C:\Users\JordanEhrig\Documents\GitHub\DWG-forensic-tool\dwg_forensic\analysis\anomaly.py**
   - Core anomaly detection module to refactor
   - Lines 159-179: Filesystem mismatch check (hardcoded 5-minute tolerance)
   - Lines 286-300: Null padding check (hardcoded 30% threshold)
   - Must add provenance-aware tolerance system

3. **C:\Users\JordanEhrig\Documents\GitHub\DWG-forensic-tool\dwg_forensic\analysis\rules\engine.py**
   - Rule evaluation engine to modify for confidence calibration
   - Lines 58-89: CRC mismatch rules (TAMPER-001, TAMPER-002)
   - Lines 537-583: Rule evaluation dispatcher
   - Must add provenance context and confidence adjustment logic

4. **C:\Users\JordanEhrig\Documents\GitHub\DWG-forensic-tool\dwg_forensic\core\analyzer.py**
   - Main orchestrator where provenance detection integrates
   - Integration point after CAD fingerprinting (~line 180)
   - Must pass provenance context to downstream modules

5. **C:\Users\JordanEhrig\Documents\GitHub\DWG-forensic-tool\dwg_forensic\analysis\rules\rules_ntfs.py**
   - NTFS cross-validation rules (TAMPER-019 to TAMPER-028)
   - Lines 206-400: All NTFS-based tampering detection
   - Must downgrade confidence for file transfer provenance

---

## End of Implementation Roadmap

**Report to Hive-Mind**: This design provides a comprehensive three-layer architecture to eliminate false positives while maintaining tampering detection accuracy. The phased approach allows for controlled rollout with rollback options at each stage. Estimated total implementation time: 6 weeks with one developer.

**Next Steps**: CODING AGENT should begin with Phase 1 (Provenance Detection Foundation) using this roadmap as specification.
