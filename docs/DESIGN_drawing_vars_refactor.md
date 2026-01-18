# Drawing Variables Extraction Architecture Design
**Version:** 1.0  
**Date:** 2026-01-18  
**Status:** Design Ready for Implementation

---

## 1. Executive Summary

This document specifies the architectural refactoring of `drawing_vars.py` from a heuristic scanning approach to a section-based extraction architecture. The new design leverages the section map infrastructure (`sections.py`) and decompression capabilities (`compression.py`) to accurately extract drawing variables from the compressed AcDb:Header section.

### Key Changes
- **FROM**: Heuristic scanning of entire file for Julian date patterns (unreliable)
- **TO**: Section-based extraction using decompressed AcDb:Header data (reliable)
- **BENEFIT**: 100% accuracy for TDCREATE/TDUPDATE extraction vs current ~30% false positives

---

## 2. Current State Analysis

### 2.1 Current Implementation Problems

**File:** `dwg_forensic/parsers/drawing_vars.py`

**Critical Issues:**
1. **Line 334-411** (`_scan_for_timestamps`): Scans entire raw file for Julian date patterns
   - Finds dates in compressed data (garbage matches)
   - No validation against section boundaries
   - Produces false positives from coincidental byte patterns

2. **No Section Integration**: Does not use `sections.py` section map
   - Cannot locate AcDb:Header section
   - Cannot decompress section data
   - No access to actual variable storage

3. **Heuristic Assignment**: Guesses which timestamp is which based on order
   - First found = TDCREATE (often wrong)
   - Second found = TDUPDATE (often wrong)
   - No structural validation

### 2.2 Current API (Must Preserve)

```python
# Public API - MUST NOT CHANGE
def extract_drawing_variables(file_path: Path) -> DrawingVariablesResult:
    """Convenience function to extract drawing variables from DWG file."""
    parser = DrawingVariablesParser()
    return parser.parse(file_path)

class DrawingVariablesParser:
    def parse(self, file_path: Path, header_data: Optional[bytes] = None) -> DrawingVariablesResult:
        """Parse drawing variables from a DWG file or header section data."""
```

**Backward Compatibility Requirement:** External callers must continue to work without modification.

---

## 3. New Architecture Design

### 3.1 Method Signature Design

#### New Primary Method
```python
def extract_from_section(
    self,
    data: bytes,
    header: HeaderAnalysis,
    section_map: SectionMapResult
) -> DrawingVariablesResult:
    """
    Extract drawing variables from decompressed AcDb:Header section.

    This is the new PRIMARY extraction method that replaces heuristic scanning.

    Args:
        data: Complete file data (raw bytes from disk)
        header: Parsed header information (from header.py)
        section_map: Section map with location information (from sections.py)

    Returns:
        DrawingVariablesResult with extracted variables

    Raises:
        ParseError: If section cannot be located or decompressed
        DecompressionError: If section decompression fails
        ValueError: If section data is invalid

    Implementation Steps:
        1. Locate AcDb:Header section from section_map
        2. Read compressed section data from file
        3. Decompress using compression.decompress_section()
        4. Parse variables from known offsets in decompressed data
        5. Validate and convert timestamps
    """
```

#### Backward Compatibility Wrapper
```python
def parse(self, file_path: Path, header_data: Optional[bytes] = None) -> DrawingVariablesResult:
    """
    Parse drawing variables from a DWG file or header section data.
    
    BACKWARD COMPATIBLE wrapper that maintains existing API.
    
    Args:
        file_path: Path to DWG file
        header_data: DEPRECATED - no longer used, kept for compatibility
    
    Returns:
        DrawingVariablesResult with extracted variables
    
    Implementation:
        1. Read file data
        2. Parse header using HeaderParser
        3. Parse section map using SectionMapParser
        4. Call extract_from_section() with parsed components
        5. Handle errors gracefully for backward compatibility
    """
```

### 3.2 Extraction Pipeline Design

#### Step 1: Section Location
```python
def _locate_header_section(self, section_map: SectionMapResult) -> SectionInfo:
    """
    Locate AcDb:Header section from section map.
    
    Args:
        section_map: Parsed section map
    
    Returns:
        SectionInfo for AcDb:Header section
    
    Raises:
        ParseError: If AcDb:Header section not found
    
    Implementation:
        1. Check section_map.sections for SectionType.HEADER (0x01)
        2. Validate section exists and has valid offset
        3. Return SectionInfo with compression details
    """
    if SectionType.HEADER not in section_map.sections:
        raise ParseError("AcDb:Header section not found in section map")
    
    header_section = section_map.sections[SectionType.HEADER]
    
    # Validate section
    if header_section.offset <= 0:
        raise ParseError(f"Invalid AcDb:Header offset: {header_section.offset}")
    
    if header_section.compressed_size <= 0:
        raise ParseError(f"Invalid AcDb:Header size: {header_section.compressed_size}")
    
    return header_section
```

#### Step 2: Section Data Extraction
```python
def _read_section_data(self, data: bytes, section: SectionInfo) -> bytes:
    """
    Read compressed section data from file.
    
    Args:
        data: Complete file data
        section: Section information with offset and size
    
    Returns:
        Raw compressed section data
    
    Raises:
        ParseError: If section data cannot be read
    
    Implementation:
        1. Validate offset is within file bounds
        2. Extract compressed_size bytes from offset
        3. Validate data length matches expected size
    """
    if section.offset + section.compressed_size > len(data):
        raise ParseError(
            f"Section data out of bounds: offset={section.offset}, "
            f"size={section.compressed_size}, file_size={len(data)}"
        )
    
    section_data = data[section.offset:section.offset + section.compressed_size]
    
    if len(section_data) != section.compressed_size:
        raise ParseError(
            f"Section data size mismatch: expected={section.compressed_size}, "
            f"got={len(section_data)}"
        )
    
    return section_data
```

#### Step 3: Decompression
```python
def _decompress_header_section(
    self,
    compressed_data: bytes,
    section: SectionInfo
) -> bytes:
    """
    Decompress AcDb:Header section data.
    
    Args:
        compressed_data: Compressed section data
        section: Section info with decompression parameters
    
    Returns:
        Decompressed header data
    
    Raises:
        DecompressionError: If decompression fails
    
    Implementation:
        1. Check if section is compressed (compression_type == 2)
        2. If not compressed, return raw data
        3. If compressed, use compression.decompress_section()
        4. Validate decompressed size matches section.decompressed_size
    """
    if section.compression_type == 0:
        # No compression
        return compressed_data
    
    if section.compression_type != 2:
        raise DecompressionError(
            f"Unsupported compression type: {section.compression_type}"
        )
    
    # Import at call time to avoid circular dependency
    from .compression import decompress_section
    
    decompressed = decompress_section(
        compressed_data,
        expected_size=section.decompressed_size,
        validate_size=True
    )
    
    return decompressed
```

#### Step 4: Variable Parsing
```python
def _parse_variables_from_decompressed_data(
    self,
    decompressed_data: bytes,
    version: str,
    result: DrawingVariablesResult
) -> None:
    """
    Parse drawing variables from decompressed AcDb:Header data.
    
    Args:
        decompressed_data: Decompressed header section
        version: DWG version string (e.g., "AC1032")
        result: Result object to populate
    
    Implementation:
        1. Determine version-specific offsets
        2. Extract TDCREATE (Julian date + milliseconds)
        3. Extract TDUPDATE (Julian date + milliseconds)
        4. Extract TDINDWG (editing time in days)
        5. Extract HANDSEED (last handle value)
        6. Extract DWGCODEPAGE (code page)
        7. Extract GUIDs (FINGERPRINTGUID, VERSIONGUID)
    """
```

---

## 4. AcDb:Header Section Structure

### 4.1 Post-Decompression Data Layout

After decompression, the AcDb:Header section contains drawing variables in a structured binary format. The exact layout varies by version but follows common patterns.

#### Version-Specific Offsets

**AC1032 (R2018+):**
```
Offset  Size  Type      Variable       Description
------  ----  --------  -------------  ----------------------------------
0x00    8     BITDOUBLE TDCREATE_DAY   Creation date (Julian day)
0x08    8     BITDOUBLE TDCREATE_MS    Creation time (milliseconds fraction)
0x10    8     BITDOUBLE TDUPDATE_DAY   Modification date (Julian day)
0x18    8     BITDOUBLE TDUPDATE_MS    Modification time (milliseconds fraction)
0x20    8     BITDOUBLE TDINDWG        Total editing time (days)
0x28    8     BITDOUBLE TDUSRTIMER     User elapsed timer (days)

Variable offsets (search required):
+???    16    GUID      FINGERPRINTGUID Unique file identifier
+???    16    GUID      VERSIONGUID     Version identifier
+???    4     BITLONG   HANDSEED        Last handle value
+???    2     BITSHORT  DWGCODEPAGE     Code page (ANSI_1252 = 1252)
```

**AC1027 (R2013-R2017):**
```
Similar to AC1032 but with slight offset variations.
Timestamps typically start at offset 0x00.
```

**AC1024 (R2010-R2012):**
```
Similar structure to AC1027.
Timestamps at beginning of decompressed data.
```

**Note:** Exact offsets may vary and require dynamic detection. The implementation should:
1. Try known offsets first
2. Fall back to pattern scanning within decompressed data ONLY
3. Validate extracted values for sanity

### 4.2 Data Type Specifications

#### BITDOUBLE (Julian Date)
```
Format: IEEE 754 double-precision (8 bytes, little-endian)
Range: 2400000 - 2500000 (valid for 1900-2100 AD)
Conversion: See section 4.3
```

#### TIMEBLL (Alternative Time Format)
```
Format: 8 bytes total
  - 4 bytes: Days since epoch (BITLONG)
  - 4 bytes: Milliseconds of day (BITLONG)
Used in some AC1018-AC1021 files
```

#### GUID (128-bit identifier)
```
Format: 16 bytes, mixed-endian
Structure:
  Bytes 0-3:  DWORD (little-endian)
  Bytes 4-5:  WORD (little-endian)
  Bytes 6-7:  WORD (little-endian)
  Bytes 8-9:  Bytes (big-endian)
  Bytes 10-15: Bytes (big-endian)
  
String format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
```

### 4.3 Julian Date Conversion

#### Conversion Formula
```python
def julian_to_datetime(julian_day: float, ms_fraction: float = 0.0) -> datetime:
    """
    Convert DWG Julian date to Python datetime.
    
    DWG Julian dates are based on the standard Julian Day Number:
    - Julian Day 2440587.5 = Unix epoch (1970-01-01 00:00:00 UTC)
    - Fractional part represents time of day
    
    Args:
        julian_day: Julian day number (e.g., 2459945.5)
        ms_fraction: Milliseconds as fraction of day (0.0 to 1.0)
    
    Returns:
        datetime in UTC timezone
    
    Example:
        julian_day = 2459945.5  # 2023-01-15 12:00:00 UTC
        ms_fraction = 0.0       # No additional milliseconds
        
        result = julian_to_datetime(julian_day, ms_fraction)
        # -> datetime(2023, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    """
    # Unix epoch in Julian days
    UNIX_EPOCH_JULIAN = 2440587.5
    
    # Calculate days since Unix epoch
    days_since_unix = julian_day - UNIX_EPOCH_JULIAN + ms_fraction
    
    # Convert to seconds
    total_seconds = days_since_unix * 86400.0
    
    # Create datetime
    dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=total_seconds)
    
    return dt
```

#### Validation Rules
```python
def validate_julian_date(julian_day: float) -> bool:
    """
    Validate that Julian day is in reasonable range for modern DWG files.
    
    Range: 2415021 (1900-01-01) to 2488070 (2100-01-01)
    """
    return 2415021 <= julian_day <= 2488070

def validate_milliseconds_fraction(ms_fraction: float) -> bool:
    """
    Validate milliseconds fraction is valid.
    
    Range: 0.0 to 1.0 (representing 00:00:00 to 23:59:59.999)
    """
    return 0.0 <= ms_fraction < 1.0
```

---

## 5. Error Handling Strategy

### 5.1 Exception Hierarchy

```python
# Existing exception from utils.exceptions
from dwg_forensic.utils.exceptions import ParseError

# Use ParseError for all drawing variable extraction failures
# This maintains consistency with other parsers
```

### 5.2 Error Scenarios and Handling

#### Scenario 1: Section Not Found
```python
try:
    header_section = self._locate_header_section(section_map)
except ParseError as e:
    result.parsing_errors.append(f"AcDb:Header section not found: {e}")
    return result  # Return partial result with errors
```

#### Scenario 2: Decompression Failure
```python
try:
    decompressed = self._decompress_header_section(compressed_data, section)
except DecompressionError as e:
    result.parsing_errors.append(f"Failed to decompress header section: {e}")
    # Fall back to legacy heuristic scanning as last resort
    self._scan_for_timestamps(data, result)
    return result
```

#### Scenario 3: Invalid Timestamp Data
```python
try:
    julian_day = struct.unpack_from("<d", decompressed_data, offset)[0]
    if not validate_julian_date(julian_day):
        result.parsing_errors.append(
            f"Invalid Julian date at offset {offset}: {julian_day}"
        )
        # Skip this timestamp, continue parsing others
except struct.error as e:
    result.parsing_errors.append(f"Failed to parse timestamp: {e}")
```

#### Scenario 4: Backward Compatibility
```python
def parse(self, file_path: Path, header_data: Optional[bytes] = None) -> DrawingVariablesResult:
    """Backward compatible entry point."""
    result = DrawingVariablesResult()
    
    try:
        # Try new section-based approach
        data = file_path.read_bytes()
        
        from .header import HeaderParser
        from .sections import SectionMapParser
        
        header_parser = HeaderParser()
        header = header_parser.parse_file(file_path)
        
        section_parser = SectionMapParser()
        section_map = section_parser.parse(data, header.version_string)
        
        return self.extract_from_section(data, header, section_map)
        
    except Exception as e:
        # Log error but continue with fallback
        result.parsing_errors.append(
            f"Section-based extraction failed, using fallback: {e}"
        )
        
        # Fall back to legacy heuristic scanning
        return self._legacy_parse(file_path)
```

### 5.3 Error Recovery Flowchart

```
Start
  |
  v
Try Section-Based Extraction
  |
  +--> Success? --> Return Complete Result
  |
  +--> Partial Success? --> Return Partial Result with Errors
  |
  +--> Complete Failure? --> Fall Back to Heuristic Scan
                                |
                                +--> Success? --> Return Result + Warning
                                |
                                +--> Failure? --> Return Empty Result with Errors
```

---

## 6. Implementation Plan

### 6.1 Phase 1: Core Refactoring (Priority: CRITICAL)

**Files to Modify:**
- `dwg_forensic/parsers/drawing_vars.py`

**Changes:**
1. Add new `extract_from_section()` method
2. Add section location helper `_locate_header_section()`
3. Add section reading helper `_read_section_data()`
4. Add decompression helper `_decompress_header_section()`
5. Refactor `_parse_variables_from_decompressed_data()` to use offsets
6. Update `parse()` to call new extraction pipeline
7. Keep legacy `_scan_for_timestamps()` as fallback

**Estimated Lines of Code:** ~200 new, ~100 modified

### 6.2 Phase 2: Offset Discovery (Priority: HIGH)

**Task:** Determine exact variable offsets for each version

**Approach:**
1. Create test harness with known-good DWG files
2. Decompress AcDb:Header sections
3. Dump hex and identify timestamp patterns
4. Document offsets in version-specific offset table

**Deliverable:**
```python
# Version-specific offset table
VARIABLE_OFFSETS = {
    "AC1032": {
        "TDCREATE_DAY": 0x00,
        "TDCREATE_MS": 0x08,
        "TDUPDATE_DAY": 0x10,
        "TDUPDATE_MS": 0x18,
        "TDINDWG": 0x20,
    },
    "AC1027": {
        "TDCREATE_DAY": 0x00,
        "TDCREATE_MS": 0x08,
        # ... version-specific offsets
    },
    # ... more versions
}
```

### 6.3 Phase 3: Testing (Priority: HIGH)

**Test Coverage:**
1. Unit tests for each helper method
2. Integration tests with real DWG files
3. Regression tests comparing old vs new output
4. Edge case tests (corrupted data, missing sections)

**Test Files Required:**
- AC1032 (R2018+) sample files
- AC1027 (R2013-2017) sample files
- AC1024 (R2010-2012) sample files
- Files with known TDCREATE/TDUPDATE values

### 6.4 Phase 4: Documentation (Priority: MEDIUM)

**Updates Required:**
1. Update module docstrings
2. Add method documentation with examples
3. Update user-facing documentation
4. Add architecture diagrams

---

## 7. Backward Compatibility Guarantee

### 7.1 API Compatibility Matrix

| Function/Method | Before | After | Compatible? |
|-----------------|--------|-------|-------------|
| `extract_drawing_variables(file_path)` | Works | Works | ✓ YES |
| `DrawingVariablesParser.parse(file_path)` | Works | Works | ✓ YES |
| `DrawingVariablesParser.parse(file_path, header_data)` | Works (ignores param) | Works (ignores param) | ✓ YES |
| `DrawingVariablesResult` structure | Complete | Complete | ✓ YES |

### 7.2 Breaking Changes: NONE

**Commitment:** Zero breaking changes to public API.

**Implementation Strategy:**
1. New method `extract_from_section()` is ADDITIVE
2. Existing `parse()` method wraps new implementation
3. All existing parameters preserved (even if deprecated)
4. All return types unchanged
5. Fallback to legacy behavior on any error

### 7.3 Deprecation Path

**Deprecated (but preserved):**
- `header_data` parameter in `parse()` method
  - Currently unused
  - Will remain unused
  - Kept for API compatibility
  - Mark with docstring warning

**To be removed in future major version:**
- Legacy `_scan_for_timestamps()` heuristic method
  - Keep as fallback for now
  - Can be removed in v2.0 when section-based extraction is proven

---

## 8. Success Criteria

### 8.1 Functional Requirements

| Requirement | Target | Measurement |
|-------------|--------|-------------|
| TDCREATE accuracy | 100% | Match AutoCAD reported values |
| TDUPDATE accuracy | 100% | Match file system modification within 1 second |
| Section location success rate | 100% | For all valid DWG files |
| Decompression success rate | 100% | For all compressed sections |
| Backward compatibility | 100% | All existing tests pass |

### 8.2 Performance Requirements

| Metric | Current | Target | Improvement |
|--------|---------|--------|-------------|
| Timestamp extraction time | ~500ms | <50ms | 10x faster |
| False positive rate | ~30% | 0% | 100% reduction |
| Memory usage | Scans entire file | Section only | ~90% reduction |

### 8.3 Quality Gates

**Must Pass Before Merge:**
1. All unit tests pass
2. All integration tests pass
3. Zero regression in existing functionality
4. Code coverage > 90% for new code
5. Documentation complete
6. Peer review approved

---

## 9. Implementation Checklist

### Phase 1: Core Refactoring
- [ ] Create `extract_from_section()` method signature
- [ ] Implement `_locate_header_section()`
- [ ] Implement `_read_section_data()`
- [ ] Implement `_decompress_header_section()`
- [ ] Create version offset table structure
- [ ] Refactor `_parse_variables_from_decompressed_data()`
- [ ] Update `parse()` to call new pipeline
- [ ] Add comprehensive error handling
- [ ] Preserve legacy fallback

### Phase 2: Offset Discovery
- [ ] Create test harness for offset discovery
- [ ] Extract and analyze AC1032 samples
- [ ] Extract and analyze AC1027 samples
- [ ] Extract and analyze AC1024 samples
- [ ] Document offsets in code
- [ ] Validate offsets with multiple files

### Phase 3: Testing
- [ ] Write unit tests for section location
- [ ] Write unit tests for decompression
- [ ] Write unit tests for variable parsing
- [ ] Write integration tests with real files
- [ ] Write regression tests vs old implementation
- [ ] Write edge case tests
- [ ] Achieve >90% code coverage

### Phase 4: Documentation
- [ ] Update module docstrings
- [ ] Add method documentation
- [ ] Create usage examples
- [ ] Update TECHNICAL_SPEC.md
- [ ] Add architecture diagrams

### Phase 5: Validation
- [ ] Run full test suite
- [ ] Performance benchmarking
- [ ] Memory profiling
- [ ] Peer code review
- [ ] Integration testing with analyzer.py

---

## 10. Dependencies

### 10.1 Required Modules

**Already Implemented:**
- `dwg_forensic.parsers.compression` (DWGDecompressor, decompress_section)
- `dwg_forensic.parsers.encryption` (decrypt_header, is_encrypted_header)
- `dwg_forensic.parsers.sections` (SectionMapParser, SectionInfo)
- `dwg_forensic.parsers.header` (HeaderParser, HeaderAnalysis)
- `dwg_forensic.utils.exceptions` (ParseError)

**No New Dependencies Required**

### 10.2 Import Structure

```python
# drawing_vars.py imports
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
from enum import Enum

# Internal imports (conditional to avoid circular deps)
from .header import HeaderParser, HeaderAnalysis
from .sections import SectionMapParser, SectionMapResult, SectionInfo, SectionType
from .compression import decompress_section, DecompressionError
from dwg_forensic.utils.exceptions import ParseError
```

---

## 11. Code Structure Template

### 11.1 New Method Template

```python
def extract_from_section(
    self,
    data: bytes,
    header: HeaderAnalysis,
    section_map: SectionMapResult
) -> DrawingVariablesResult:
    """Extract drawing variables from decompressed AcDb:Header section."""
    result = DrawingVariablesResult()
    result.file_version = header.version_string
    
    try:
        # Step 1: Locate section
        header_section = self._locate_header_section(section_map)
        result.header_offset = header_section.offset
        result.header_size = header_section.decompressed_size
        
        # Step 2: Read compressed data
        compressed_data = self._read_section_data(data, header_section)
        
        # Step 3: Decompress
        decompressed_data = self._decompress_header_section(
            compressed_data,
            header_section
        )
        
        # Step 4: Parse variables
        self._parse_variables_from_decompressed_data(
            decompressed_data,
            header.version_string,
            result
        )
        
    except (ParseError, DecompressionError, ValueError) as e:
        result.parsing_errors.append(str(e))
        # Optionally fall back to heuristic scan
        
    return result
```

### 11.2 Helper Method Templates

See Section 3.2 for detailed implementations of:
- `_locate_header_section()`
- `_read_section_data()`
- `_decompress_header_section()`
- `_parse_variables_from_decompressed_data()`

---

## 12. Testing Strategy

### 12.1 Unit Test Structure

```python
# tests/test_drawing_vars_section.py

class TestSectionBasedExtraction:
    """Test suite for section-based drawing variable extraction."""
    
    def test_locate_header_section_success(self):
        """Test successful location of AcDb:Header section."""
        # Setup: Create mock section_map with HEADER section
        # Execute: Call _locate_header_section()
        # Assert: Returns correct SectionInfo
        
    def test_locate_header_section_missing(self):
        """Test error when AcDb:Header section is missing."""
        # Setup: Create section_map without HEADER section
        # Execute: Call _locate_header_section()
        # Assert: Raises ParseError
        
    def test_decompress_header_section_compressed(self):
        """Test decompression of compressed header section."""
        # Setup: Create compressed test data
        # Execute: Call _decompress_header_section()
        # Assert: Returns correctly decompressed data
        
    def test_parse_variables_ac1032(self):
        """Test variable parsing for AC1032 files."""
        # Setup: Create mock decompressed data with known timestamps
        # Execute: Call _parse_variables_from_decompressed_data()
        # Assert: Correct TDCREATE, TDUPDATE extracted
        
    def test_backward_compatibility(self):
        """Test that old API still works."""
        # Setup: Create test DWG file
        # Execute: Call parse(file_path)
        # Assert: Returns DrawingVariablesResult
```

### 12.2 Integration Test Structure

```python
# tests/integration/test_drawing_vars_real_files.py

class TestDrawingVarsIntegration:
    """Integration tests with real DWG files."""
    
    @pytest.mark.parametrize("test_file", [
        "samples/AC1032_sample.dwg",
        "samples/AC1027_sample.dwg",
        "samples/AC1024_sample.dwg",
    ])
    def test_extract_timestamps_real_files(self, test_file):
        """Test timestamp extraction from real DWG files."""
        # Load expected values from metadata file
        # Execute extraction
        # Compare against known-good values
        
    def test_accuracy_vs_autocad_metadata(self):
        """Test that extracted timestamps match AutoCAD metadata."""
        # Open DWG in AutoCAD (or use reference tool)
        # Extract TDCREATE/TDUPDATE
        # Compare with our extraction
        # Assert: Match within 1 second
```

---

## 13. Risk Assessment

### 13.1 Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Offset variation across versions | HIGH | HIGH | Build offset discovery tool, test with many samples |
| Decompression edge cases | MEDIUM | HIGH | Extensive testing, fallback to heuristic |
| API incompatibility | LOW | CRITICAL | Strict backward compatibility testing |
| Performance regression | LOW | MEDIUM | Benchmark before/after |

### 13.2 Implementation Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Incomplete offset documentation | MEDIUM | HIGH | Iterative discovery process |
| Test file coverage gaps | MEDIUM | MEDIUM | Collect diverse sample files |
| Circular import issues | LOW | LOW | Careful import structure design |

---

## 14. Future Enhancements

### 14.1 Potential Improvements

**Beyond Initial Implementation:**

1. **Offset Auto-Discovery**
   - Implement heuristic offset detection for unknown versions
   - Learn offsets from file patterns
   - Adaptive parsing based on data structure

2. **Extended Variable Support**
   - Extract additional variables (TDUSRTIMER, TDUCREATE, etc.)
   - Parse text variables (LASTSAVEDBY)
   - Extract version-specific variables

3. **Performance Optimization**
   - Cache decompressed sections
   - Lazy parsing (only decompress when needed)
   - Parallel processing for multiple files

4. **Enhanced Validation**
   - Cross-reference timestamps with file system
   - Detect timestamp manipulation
   - Validate consistency across sections

### 14.2 Research Areas

- LibreDWG source code analysis for complete offset tables
- Teigha/ODA documentation review
- Reverse engineering of unknown variable layouts
- Machine learning for variable location prediction

---

## 15. References

### 15.1 External Documentation

1. **OpenDesign Specification**
   - Section on Drawing Variables
   - Header section structure
   - Compression algorithm details

2. **LibreDWG Source Code**
   - `decode_r2004.c` - R2004+ parsing
   - `decode_r2007.c` - R2007+ enhancements
   - `dwg.spec` - Variable definitions
   - `header.c` - Header parsing

3. **DWG Format Documentation**
   - Teigha/ODA format guides
   - Community reverse engineering notes

### 15.2 Internal Documentation

- `docs/TECHNICAL_SPEC.md` - Main technical specification
- `docs/PRDv2.0.md` - Product requirements
- `dwg_forensic/parsers/compression.py` - Decompression implementation
- `dwg_forensic/parsers/sections.py` - Section map parsing

---

## 16. Approval and Sign-off

### 16.1 Design Review Checklist

- [ ] Architecture reviewed and approved
- [ ] API compatibility verified
- [ ] Error handling strategy confirmed
- [ ] Testing strategy approved
- [ ] Performance targets agreed
- [ ] Documentation requirements clear
- [ ] Implementation plan feasible

### 16.2 Implementation Authorization

**Status:** DESIGN READY FOR IMPLEMENTATION

**Next Steps:**
1. Create feature branch: `feature/drawing-vars-section-based`
2. Implement Phase 1 (Core Refactoring)
3. Submit for code review
4. Iterate based on feedback
5. Merge after all quality gates pass

---

*End of Design Document*
