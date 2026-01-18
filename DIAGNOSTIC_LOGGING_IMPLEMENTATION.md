# Diagnostic Logging Implementation

## Overview

Added comprehensive diagnostic logging to DWG parsing to capture detailed failure context for both debugging and LLM-based forensic reasoning.

## Files Created

### 1. `dwg_forensic/utils/diagnostics.py`

**ParseDiagnostics Dataclass** - Captures complete parsing context:

- **File Information**
  - `version: str` - DWG version string (e.g., "AC1032")
  - `file_size: int` - Total file size in bytes

- **Section Map Detection**
  - `section_map_address: Optional[int]` - Location where section map was found
  - `section_map_found: bool` - Whether section map parsing succeeded

- **Section Analysis**
  - `sections_found: List[str]` - Names of sections successfully located
  - `sections_missing: List[str]` - Expected sections that were not found

- **Encryption/Compression Status**
  - `decryption_applied: bool` - Whether file decryption was performed
  - `compression_errors: List[str]` - Decompression errors encountered

- **Timestamp Extraction Diagnostics**
  - `timestamp_extraction_method: str` - Method used: "section", "offset", "heuristic", or "failed"
  - `timestamp_scan_regions: List[Tuple[int, int]]` - Byte ranges scanned for timestamps

- **Special Detection**
  - `revit_detected: bool` - Whether file appears to be Revit-generated

- **Raw Debug Data**
  - `raw_header_hex: str` - First 256 bytes as hex string for manual inspection

**Helper Methods:**
- `add_scan_region(start: int, end: int)` - Track timestamp scan attempts
- `add_compression_error(error: str)` - Log decompression failures
- `mark_section_found(section_name: str)` - Record successful section detection
- `mark_section_missing(section_name: str)` - Record missing expected sections
- `to_dict() -> dict` - JSON-serializable dictionary output

## Files Modified

### 2. `dwg_forensic/parsers/drawing_vars.py`

**DrawingVariablesResult - Added Field:**
```python
diagnostics: Optional[ParseDiagnostics] = None
```

**Updated Methods:**

**parse()** - Populates diagnostics throughout parsing:
- Initializes `ParseDiagnostics` with version, file size, and raw header hex
- Tracks section map detection success/failure
- Records which sections were found vs. missing
- Logs decryption application
- Sets `timestamp_extraction_method` based on which extraction path succeeded
- Records scan regions for heuristic fallback methods

**extract_from_section()** - Tracks section-based extraction:
- Populates section map diagnostics
- Records decompression errors if they occur
- Tracks successful timestamp extraction from decompressed header section
- Sets extraction method to "section" on success

**to_dict()** - Serialization includes diagnostics:
```python
"diagnostics": self.diagnostics.to_dict() if self.diagnostics else None
```

### 3. `dwg_forensic/parsers/sections.py`

**SectionMapResult - Added Fields:**
```python
tried_offsets: List[int] = field(default_factory=list)  # Section locator offsets attempted
successful_offset: Optional[int] = None  # Which offset worked
```

These track which section map locator offsets were tried during parsing, enabling diagnosis of section map detection failures.

### 4. `dwg_forensic/core/analyzer.py`

**Updated LLM Reasoning Context:**

Modified `analyze()` method to include diagnostics in LLM reasoning data:
```python
# Add parsing diagnostics if available (critical for LLM reasoning about parse failures)
if drawing_vars and drawing_vars.diagnostics:
    analysis_data["parse_diagnostics"] = drawing_vars.diagnostics.to_dict()
```

This provides the LLM reasoner with detailed context about why parsing may have failed, enabling better reasoning about file anomalies.

## Testing

### 5. `tests/test_diagnostics.py`

Comprehensive test suite covering:
- **test_parse_diagnostics_creation** - Basic dataclass instantiation
- **test_parse_diagnostics_methods** - Helper method functionality
- **test_parse_diagnostics_to_dict** - JSON serialization
- **test_drawing_variables_result_includes_diagnostics** - Integration with DrawingVariablesResult
- **test_section_map_result_includes_tried_offsets** - SectionMapResult offset tracking

**Test Results:** All 5 tests passing

## Usage Examples

### Example 1: Successful Section-Based Extraction

```python
parser = DrawingVariablesParser()
result = parser.parse(file_path)

if result.diagnostics:
    print(f"Extraction method: {result.diagnostics.timestamp_extraction_method}")
    # Output: "section"

    print(f"Sections found: {result.diagnostics.sections_found}")
    # Output: ['AcDb:Header', 'AcDb:Classes', 'AcDb:Handles', ...]

    print(f"Decryption applied: {result.diagnostics.decryption_applied}")
    # Output: True (for AC1021/AC1032)
```

### Example 2: Parse Failure Diagnosis

```python
result = parser.parse(problematic_file)

if result.diagnostics:
    if result.diagnostics.timestamp_extraction_method == "failed":
        print(f"Parse failed for version: {result.diagnostics.version}")
        print(f"Section map found: {result.diagnostics.section_map_found}")
        print(f"Missing sections: {result.diagnostics.sections_missing}")
        print(f"Compression errors: {result.diagnostics.compression_errors}")
        print(f"Raw header: {result.diagnostics.raw_header_hex[:32]}...")
```

### Example 3: LLM Reasoning with Diagnostics

```python
analyzer = ForensicAnalyzer(use_llm=True)
analysis = analyzer.analyze(file_path)

# LLM reasoner automatically receives parse diagnostics
if analysis.llm_reasoning:
    # LLM can now reason about parse failures:
    # - Why section map wasn't found
    # - Which decompression method failed
    # - Whether file format is unusual
    # - If timestamp extraction fallback was necessary
    pass
```

## Benefits

1. **Debugging** - Immediate visibility into parsing failures without adding debug logging
2. **LLM Reasoning** - Provides LLM with context to reason about file anomalies
3. **Forensic Analysis** - Documents which extraction methods succeeded/failed
4. **User Feedback** - Clear diagnostic information for unsupported files
5. **Development** - Easier identification of edge cases and format variations

## Integration Points

Diagnostics are automatically populated during normal parsing flow. No code changes required for existing callers. The `diagnostics` field is `Optional`, so legacy code continues to work.

**Analyzer Integration:**
- `ForensicAnalyzer.analyze()` automatically passes diagnostics to LLM reasoner
- JSON export includes full diagnostic context
- PDF reports can optionally include diagnostic summary

## Future Enhancements

Potential additions to `ParseDiagnostics`:
- `revit_detected: bool` - Flag for Revit-generated files (common issue)
- `autocad_version_detected: str` - Detected AutoCAD version from fingerprinting
- `unusual_patterns: List[str]` - List of unexpected byte patterns found
- `encryption_method: str` - Which encryption algorithm was detected (R2004/R2007/R2018)
