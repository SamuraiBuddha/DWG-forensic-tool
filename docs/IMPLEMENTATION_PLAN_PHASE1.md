# Phase 1 Implementation Plan: Core Parsing Fixes

**Status**: Ready for Implementation
**Priority**: CRITICAL - All forensic analysis depends on these fixes
**Estimated Scope**: 4 files, ~800 lines changed

---

## Executive Summary

The DWG Forensic Tool has sound architecture and methodology, but the core binary parsing is fundamentally broken. The `drawing_vars.py` module scans compressed data for Julian date patterns instead of properly decompressing DWG sections first. This means:

- TDCREATE/TDUPDATE return `None` (no timestamps extracted)
- TDINDWG returns garbage (version string bytes misinterpreted)
- 10+ smoking gun rules cannot fire because they depend on timestamp data
- The tool would fail a Daubert challenge in court

**Root Cause**: Heuristic scanning instead of section-based extraction.

---

## Implementation Tasks

### Task 1: Fix drawing_vars.py (CRITICAL)

**File**: `dwg_forensic/parsers/drawing_vars.py`
**Lines to modify**: 270-369 (the `_scan_for_timestamps()` method)
**Complexity**: HIGH

#### Current Broken Implementation

```python
def _scan_for_timestamps(self, data: bytes, result: DrawingVariablesResult) -> None:
    """Scans ENTIRE FILE for Julian date patterns - THIS IS WRONG"""
    for offset in range(0, len(data) - 16, 4):
        julian_day = struct.unpack_from("<d", data, offset)[0]
        if 2400000 < julian_day < 2500000:
            # Assumes any matching float is a timestamp - BROKEN
```

#### Required Fix

Replace heuristic scanning with proper section-based extraction:

1. **Get section map** from `sections.py:read_section_map()`
2. **Locate AcDb:Header section** in the section map
3. **Decompress section** using `compression.py:decompress_type2()`
4. **Parse drawing variables** from decompressed data at known offsets

#### Implementation Algorithm (from TECHNICAL_SPEC.md)

```python
def extract_drawing_variables(self, data: bytes, header: HeaderInfo) -> DrawingVariablesResult:
    """Section-based extraction (correct approach)"""
    result = DrawingVariablesResult()

    # Step 1: Read section map
    section_map = read_section_map(data, header)

    # Step 2: Find AcDb:Header section
    header_section = section_map.get_section("AcDb:Header")
    if not header_section:
        raise ParseError("AcDb:Header section not found")

    # Step 3: Read and decompress section data
    compressed_data = data[header_section.offset:header_section.offset + header_section.size]
    decompressed = decompress_type2(compressed_data)

    # Step 4: Parse drawing variables from KNOWN offsets
    # TDCREATE: offset 0x00 (8 bytes, Julian day as double)
    # TDUPDATE: offset 0x08 (8 bytes, Julian day as double)
    # TDINDWG:  offset 0x10 (8 bytes, editing time as double)
    result.tdcreate = struct.unpack_from("<d", decompressed, 0x00)[0]
    result.tdupdate = struct.unpack_from("<d", decompressed, 0x08)[0]
    result.tdindwg = struct.unpack_from("<d", decompressed, 0x10)[0]

    # Parse other variables (HANDSEED, DWGCODEPAGE, etc.)
    self._parse_additional_vars(decompressed, result)

    return result
```

#### Testing Requirements

- Test with AC1024, AC1027, AC1032 sample files
- Verify TDCREATE/TDUPDATE return valid Julian dates (2400000 < value < 2500000)
- Verify TDINDWG returns reasonable editing time (0 < hours < 100000)
- Regression test: ensure no false positives from heuristic matches

---

### Task 2: Fix handles.py (HIGH)

**File**: `dwg_forensic/parsers/handles.py`
**Issue**: Reads compressed AcDb:Handles data without decompression
**Complexity**: MEDIUM

#### Current Broken Code

```python
def parse_handle_map(self, data: bytes, header: HeaderInfo) -> HandleMapResult:
    # Reads raw bytes directly - COMPRESSED DATA
    handle_data = data[header.handle_offset:header.handle_offset + header.handle_size]
    # Parsing fails or produces garbage
```

#### Required Fix

```python
def parse_handle_map(self, data: bytes, header: HeaderInfo, section_map: SectionMap) -> HandleMapResult:
    # Get AcDb:Handles section
    handles_section = section_map.get_section("AcDb:Handles")
    if not handles_section:
        raise ParseError("AcDb:Handles section not found")

    # Read and decompress
    compressed = data[handles_section.offset:handles_section.offset + handles_section.size]
    decompressed = decompress_type2(compressed)

    # Now parse the decompressed handle map
    return self._parse_handle_entries(decompressed)
```

#### Handle Map Structure (Post-Decompression)

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 4 | Handle count |
| 0x04 | variable | Handle entries (handle_value, object_offset pairs) |

---

### Task 3: Fix Binary Parsing Error Handling (MEDIUM)

**Files**: Multiple parsers
**Issue**: Return 0/None instead of raising exceptions
**Impact**: Silent failures mask evidence

#### Files to Audit

1. `dwg_forensic/parsers/header.py` - Line 89: `return 0` on parse failure
2. `dwg_forensic/parsers/sections.py` - Line 156: Silent return on section not found
3. `dwg_forensic/parsers/handles.py` - Line 78: Returns empty list on failure

#### Required Changes

Replace silent failures with explicit exceptions:

```python
# BEFORE (broken)
if not section:
    return 0  # Silently fails

# AFTER (correct)
if not section:
    raise ParseError(
        f"Section '{section_name}' not found at expected offset 0x{offset:X}",
        offset=offset,
        section_name=section_name
    )
```

#### Exception Hierarchy (already exists in utils/exceptions.py)

```
DWGForensicError
├── InvalidDWGError      # File is not a valid DWG
├── UnsupportedVersionError  # Version not supported
├── ParseError           # Generic parse failure
├── CRCMismatchError     # CRC validation failed
└── IntakeError          # Chain of custody issues
```

---

### Task 4: R2018+ Header Encryption Support (MEDIUM) - COMPLETED

**File**: `dwg_forensic/parsers/encryption.py`
**Status**: ALREADY IMPLEMENTED (37 tests passing)

#### CORRECTION: Documentation Error Discovered

**Previous documentation stated:**
> R2018+ uses AES-256-CBC for section encryption

**Actual implementation (verified via LibreDWG research):**
> R2018+ (AC1032) uses **static XOR mask** for header encryption only.
> AES-256-CBC is only used for **password-protected** DWG files (separate feature).

#### What's Already Implemented

1. **AC1032 Header XOR Decryption** (encryption.py:119-151)
   - Encrypted region: 0x80-0x100 (128 bytes)
   - 32-byte repeating XOR mask
   - No key derivation needed (static mask)

2. **AC1021 Header XOR Decryption** (encryption.py:154-190)
   - Encrypted region: 0x20-0x80
   - 16-byte repeating XOR mask

3. **Version Detection & Auto-Decryption** (encryption.py:268-286)
   - `prepare_file_data()` handles encryption automatically
   - sections.py integrates via imports

#### Test Coverage

```
tests/test_encryption.py - 37 tests PASSED
- TestVersionDetection (8 tests)
- TestEncryptionDetection (6 tests)
- TestAC1032Decryption (7 tests)
- TestAC1021Decryption (2 tests)
- TestSectionLocatorOffsets (7 tests)
- TestPrepareFileData (3 tests)
- TestMaskProperties (4 tests)
```

#### Future Enhancement (Not Required for Phase 1)

Password-protected DWG file support would require:
- AES-256-CBC implementation via `pycryptodome`
- Key derivation from password/security structure
- This is a **separate feature**, not needed for standard R2018+ files

---

## Implementation Order

```
[1] drawing_vars.py (CRITICAL) ──────────────────────────┐
    └── Uses: sections.py (read_section_map)            │
    └── Uses: compression.py (decompress_type2)         │
                                                         │
[2] handles.py (HIGH) ──────────────────────────────────┼── Parallel after [1]
    └── Uses: sections.py (read_section_map)            │
    └── Uses: compression.py (decompress_type2)         │
                                                         │
[3] Error handling audit (MEDIUM) ──────────────────────┘
    └── All parsers: header.py, sections.py, handles.py

[4] R2018+ encryption (MEDIUM) ──────────────────────────── COMPLETED (pre-existing)
    └── Already implemented in encryption.py (XOR header decryption)
    └── 37 tests passing, no additional work needed
```

---

## Files Changed Summary

| File | Changes | Lines Est. |
|------|---------|------------|
| `dwg_forensic/parsers/drawing_vars.py` | Section-based extraction (DONE) | ~200 |
| `dwg_forensic/parsers/handles.py` | Section-based extraction (DONE) | ~120 |
| `dwg_forensic/parsers/sections.py` | Enhanced error messages (DONE) | ~10 |
| `dwg_forensic/parsers/header.py` | ParseError on bounds failures (DONE) | ~30 |
| `dwg_forensic/parsers/encryption.py` | R2018+ XOR decryption (pre-existing) | 0 |

**Total Actual**: ~360 lines changed (encryption was already implemented)

---

## Test Requirements

### Unit Tests

1. **test_drawing_vars_section_extraction.py**
   - Test TDCREATE extraction from decompressed AcDb:Header
   - Test TDUPDATE extraction
   - Test TDINDWG extraction
   - Test HANDSEED extraction
   - Test with AC1024, AC1027, AC1032 samples

2. **test_handles_decompression.py**
   - Test handle map parsing from decompressed data
   - Test handle gap detection
   - Test with various file sizes

3. **test_r2018_encryption.py**
   - Test section decryption
   - Test decrypt-then-decompress pipeline
   - Test with encrypted AC1032 samples

### Integration Tests

1. **test_full_analysis_pipeline.py**
   - End-to-end analysis of sample files
   - Verify all timestamps are extracted
   - Verify smoking gun rules can fire

---

## Success Criteria

Phase 1 is complete when:

1. [ ] TDCREATE returns valid Julian date (not None)
2. [ ] TDUPDATE returns valid Julian date (not None)
3. [ ] TDINDWG returns valid editing time (not version string)
4. [ ] Handle map parsing works on real DWG files
5. [ ] All 10+ smoking gun rules can fire when conditions met
6. [ ] R2018+ (AC1032) files parse correctly
7. [ ] All unit tests pass
8. [ ] No silent failures (all errors raise exceptions)

---

## Dependencies

**Existing (already working)**:
- `compression.py` - LZ-like Type 2 decompression (100% test coverage)
- `sections.py` - Section map parsing infrastructure
- `encryption.py` - R2018+ XOR header decryption (37 tests passing)
- `utils/exceptions.py` - Exception hierarchy

**No New Dependencies Required** (pycryptodome NOT needed for standard R2018+ files)

---

## Risk Mitigation

| Risk | Mitigation | Status |
|------|------------|--------|
| Section offsets vary by version | Version-specific offset tables | RESOLVED |
| Decompression may fail on corrupt files | Forensic alerts with fallback parsing | RESOLVED |
| R2018+ encryption complexity | XOR-based (not AES), already implemented | RESOLVED |
| Breaking existing tests | Regression testing maintained | RESOLVED |

---

## Notes

- compression.py is ALREADY IMPLEMENTED and working - do not modify
- The heuristic scanning code should be REMOVED entirely, not disabled
- All changes must maintain Python 3.10+ compatibility
- Follow existing code style (Ruff, 100 char lines, type hints)
