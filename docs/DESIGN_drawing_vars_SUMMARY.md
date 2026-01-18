# Drawing Variables Refactoring - Design Summary

## Overview
Refactoring `drawing_vars.py` from heuristic file scanning to section-based extraction for 100% accuracy.

## Key Architecture Changes

### 1. New Primary Method
```python
def extract_from_section(
    self,
    data: bytes,              # Raw file data
    header: HeaderAnalysis,   # Parsed header from header.py
    section_map: SectionMapResult  # Section map from sections.py
) -> DrawingVariablesResult:
```

**Purpose:** Replace unreliable heuristic scanning with structured section-based extraction.

### 2. Extraction Pipeline (4 Steps)

```
Step 1: Locate Section
  ├─> Get AcDb:Header from section_map.sections[SectionType.HEADER]
  └─> Validate offset and size

Step 2: Read Compressed Data
  ├─> Extract bytes from data[offset:offset+compressed_size]
  └─> Validate data length

Step 3: Decompress
  ├─> Check compression_type (0=none, 2=LZ)
  └─> Call decompress_section() from compression.py

Step 4: Parse Variables
  ├─> Read TDCREATE from known offset (double + double)
  ├─> Read TDUPDATE from known offset (double + double)
  ├─> Convert Julian dates to datetime
  └─> Extract GUIDs, HANDSEED, DWGCODEPAGE
```

### 3. Data Structure After Decompression

**AC1032 (R2018+) Typical Layout:**
```
Offset  Size  Variable         Description
------  ----  ---------------  ---------------------------
0x00    8     TDCREATE_DAY     Creation date (Julian day)
0x08    8     TDCREATE_MS      Creation time (milliseconds)
0x10    8     TDUPDATE_DAY     Modification date (Julian)
0x18    8     TDUPDATE_MS      Modification time (ms)
0x20    8     TDINDWG          Total editing time (days)
+???    16    FINGERPRINTGUID  Unique file identifier
+???    16    VERSIONGUID      Version identifier
```

**Note:** Exact offsets need discovery through test harness (Phase 2).

### 4. Julian Date Conversion

```python
def julian_to_datetime(julian_day: float, ms_fraction: float = 0.0) -> datetime:
    """
    Convert DWG Julian date to Python datetime.
    
    Formula:
        days_since_unix = julian_day - 2440587.5 + ms_fraction
        total_seconds = days_since_unix * 86400.0
        datetime = 1970-01-01 + total_seconds
    
    Validation:
        julian_day: 2415021 to 2488070 (1900-2100)
        ms_fraction: 0.0 to 1.0
    """
```

### 5. Error Handling Strategy

```python
# Three-tier fallback system:

Try: Section-based extraction
  └─> Success → Return complete result
  
Catch: DecompressionError
  └─> Fall back to heuristic scan → Return partial result + warning
  
Catch: ParseError
  └─> Return empty result + error details

# Always preserve backward compatibility
```

### 6. Backward Compatibility

**Zero Breaking Changes:**
- Existing `parse(file_path)` API preserved
- New `extract_from_section()` is ADDITIVE
- `parse()` wraps new implementation
- Legacy `_scan_for_timestamps()` kept as fallback
- All return types unchanged

## Implementation Phases

### Phase 1: Core Refactoring (CRITICAL)
- Add `extract_from_section()` method
- Add section location/reading/decompression helpers
- Update `parse()` to call new pipeline
- Preserve legacy fallback

**Files Modified:** `drawing_vars.py` (~200 new lines, ~100 modified)

### Phase 2: Offset Discovery (HIGH)
- Create test harness
- Decompress header sections from sample files
- Identify timestamp/GUID offsets
- Build version-specific offset table

**Deliverable:** Offset table for AC1032, AC1027, AC1024

### Phase 3: Testing (HIGH)
- Unit tests for each helper method
- Integration tests with real DWG files
- Regression tests vs old implementation
- Edge case tests

**Target:** >90% code coverage

### Phase 4: Documentation (MEDIUM)
- Update docstrings
- Add usage examples
- Update TECHNICAL_SPEC.md

## Success Criteria

| Metric | Current | Target | Improvement |
|--------|---------|--------|-------------|
| TDCREATE accuracy | ~70% | 100% | 43% gain |
| TDUPDATE accuracy | ~70% | 100% | 43% gain |
| False positives | ~30% | 0% | 100% reduction |
| Extraction time | ~500ms | <50ms | 10x faster |
| Memory usage | Full file scan | Section only | ~90% reduction |

## Key Dependencies

**Already Available:**
- `compression.py` → `decompress_section()`
- `sections.py` → `SectionMapParser`, `SectionInfo`
- `header.py` → `HeaderParser`, `HeaderAnalysis`
- `encryption.py` → `decrypt_header()`

**No New External Dependencies Required**

## Risk Mitigation

### High Risk: Offset Variation
- **Mitigation:** Build offset discovery tool, test with diverse samples
- **Fallback:** Pattern scanning within decompressed data only

### Medium Risk: Decompression Failures
- **Mitigation:** Extensive edge case testing
- **Fallback:** Preserve legacy heuristic scan

### Low Risk: API Breaking Changes
- **Mitigation:** Strict backward compatibility wrapper + regression tests
- **Guarantee:** 100% existing API preserved

## Next Steps

1. **Create Feature Branch:** `feature/drawing-vars-section-based`
2. **Implement Phase 1:** Core refactoring (~2-3 days)
3. **Implement Phase 2:** Offset discovery (~1-2 days)
4. **Implement Phase 3:** Testing (~2-3 days)
5. **Code Review:** Submit for review
6. **Merge:** After quality gates pass

## Quality Gates

**Must Pass Before Merge:**
- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] Zero regression in existing functionality
- [ ] Code coverage > 90%
- [ ] Documentation complete
- [ ] Peer review approved

---

**Status:** DESIGN READY FOR IMPLEMENTATION  
**Estimated Timeline:** 5-8 days  
**Confidence Level:** HIGH (well-scoped, clear dependencies, fallback strategy)
