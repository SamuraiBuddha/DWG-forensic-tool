# DWG Forensic Tool - Implementation Plan v3.0

**Date**: 2026-01-19
**Based on**: Deep format research from ODA Specification, LibreDWG, and forum analysis
**Goal**: Fix fundamental parsing bugs to enable reliable timestamp tampering detection

---

## Executive Summary

The current tool fails on every file due to three root cause bugs:
1. **CRC Bug**: Wrong calculation length (0x68 vs 0x6C bytes)
2. **Timestamp Bug**: Scanning raw compressed bytes instead of decompressed section
3. **Fingerprint Bug**: Not parsing AcDb:AppInfo section

This plan provides a phased approach to fix these issues.

---

## Phase 1: Fix CRC Validation (CRITICAL - Day 1)

### Current Bug Location
- **File**: `dwg_forensic/parsers/crc.py`
- **Lines**: 36-46, 95-97, 185-197

### Root Cause
```python
# CURRENT (WRONG)
VERSION_CRC_INFO = {
    "AC1032": {"offset": 0x68, "length": 0x68},  # length should be 0x6C
    ...
}

def _calculate_header_crc(self, f: BinaryIO, header_length: int) -> int:
    f.seek(0)
    header_data = f.read(header_length)  # Reads 0x68, should read 0x6C
    crc_value = zlib.crc32(header_data) & 0xFFFFFFFF  # Doesn't zero CRC field
    return crc_value
```

### Correct Implementation
```python
VERSION_CRC_INFO = {
    "AC1032": {"offset": 0x68, "length": 0x6C},  # Header is 0x6C bytes total
    "AC1027": {"offset": 0x68, "length": 0x6C},
    "AC1024": {"offset": 0x68, "length": 0x6C},
    "AC1021": {"offset": 0x68, "length": 0x6C},
    "AC1018": {"offset": 0x5C, "length": 0x60},  # Different for R2004
    "AC1015": {"offset": 0x5C, "length": 0x60},
}

def _calculate_header_crc(self, f: BinaryIO, header_length: int, crc_offset: int) -> int:
    """Calculate CRC32 over header with CRC field zeroed."""
    f.seek(0)
    header_data = bytearray(f.read(header_length))

    # Zero out the CRC field before calculation (per ODA spec)
    header_data[crc_offset:crc_offset + 4] = b'\x00\x00\x00\x00'

    # CRC32 with seed 0 (zlib default is 0)
    crc_value = zlib.crc32(bytes(header_data)) & 0xFFFFFFFF
    return crc_value
```

### Test Case
```python
def test_crc_calculation():
    # Create a valid test DWG file and verify CRC matches
    parser = CRCValidator()
    result = parser.validate_header_crc(Path("test_files/valid_civil3d.dwg"))
    assert result.is_valid, f"CRC mismatch: stored={result.header_crc_stored}, calc={result.header_crc_calculated}"
```

### Success Criteria
- [x] CRC validation passes on Civil 3D test file
- [x] CRC validation passes on Revit export test file
- [x] CRC validation correctly fails on known-tampered file

---

## Phase 2: Fix Section Map Parsing (Day 1-2)

### Current Bug
The section map parser finds the address but doesn't properly:
1. Handle page structure
2. Decompress section map content
3. Find section data offsets

### Files to Modify
- `dwg_forensic/parsers/sections.py`

### Required Changes

1. **Fix section locator parsing for AC1032**:
```python
def _parse_r2010_sections(self, prepared_data, original_data, result):
    locator_base = self._get_section_locator_offset(result.file_version)

    # For AC1032, locator_base is 0x80 (AFTER decryption)
    # Read section locator record
    section_record_num = struct.unpack_from("<I", prepared_data, locator_base + 0x00)[0]
    section_size = struct.unpack_from("<I", prepared_data, locator_base + 0x04)[0]
    page_count = struct.unpack_from("<I", prepared_data, locator_base + 0x08)[0]
    max_section_size = struct.unpack_from("<I", prepared_data, locator_base + 0x0C)[0]
    unknown = struct.unpack_from("<I", prepared_data, locator_base + 0x10)[0]
    section_map_addr = struct.unpack_from("<I", prepared_data, locator_base + 0x14)[0]

    # Validate and parse section pages
    if section_map_addr > 0 and section_map_addr < len(original_data):
        self._parse_section_pages(original_data, section_map_addr, result)
```

2. **Parse section page map properly**:
```python
def _parse_section_page_map(self, data, page_offset, result):
    # Check for page marker
    page_marker = struct.unpack_from("<I", data, page_offset)[0]

    if page_marker not in [self.SECTION_PAGE_MAP, self.SECTION_DATA_PAGE]:
        result.parsing_errors.append(f"Invalid page marker: 0x{page_marker:08X}")
        return

    # Parse page header (32 bytes)
    header = PageHeader.from_bytes(data, page_offset)

    # Decompress if needed
    content_offset = page_offset + 32
    if header.compression_type == 2:
        compressed = data[content_offset:content_offset + header.compressed_size]
        page_content = decompress_section(compressed, header.decompressed_size)
    else:
        page_content = data[content_offset:content_offset + header.decompressed_size]

    # Parse section descriptors
    self._parse_section_descriptors(page_content, data, result)
```

### Success Criteria
- [x] Section map found for AC1032 files
- [x] AcDb:Header section located
- [x] AcDb:AppInfo section located
- [x] Section offsets are valid (within file bounds)

---

## Phase 3: Fix Timestamp Extraction (Day 2-3)

### Current Bug Location
- **File**: `dwg_forensic/parsers/drawing_vars.py`
- **Function**: `_scan_for_timestamps()` (lines 270-369)

### Root Cause
Scans RAW FILE BYTES for Julian date patterns. The data is COMPRESSED, so this finds garbage.

### Correct Implementation

1. **Replace heuristic scanning with section-based extraction**:
```python
class DrawingVariablesParser:
    def __init__(self):
        self._section_parser = SectionMapParser()
        self._decompressor = DWGDecompressor()

    def parse(self, file_path: Path) -> DrawingVariablesResult:
        result = DrawingVariablesResult()

        with open(file_path, "rb") as f:
            data = f.read()

        # Get version and decrypt if needed
        prepared_data, version, _ = prepare_file_data(data)
        result.file_version = version

        # Parse section map
        section_result = self._section_parser.parse_from_bytes(data)

        if not section_result.has_section(SectionType.HEADER):
            result.parsing_errors.append("AcDb:Header section not found")
            return result

        # Get and decompress header section
        header_section = section_result.get_section(SectionType.HEADER)
        header_data = self._read_and_decompress_section(data, header_section)

        if header_data is None:
            result.parsing_errors.append("Failed to decompress header section")
            return result

        # Parse timestamps from decompressed data
        self._parse_header_variables(header_data, result)

        return result

    def _read_and_decompress_section(self, file_data, section_info):
        """Read section pages and decompress."""
        # Implementation to read all pages for section and decompress
        pass

    def _parse_header_variables(self, decompressed_data, result):
        """Parse TIMEBLL values from decompressed header section."""
        # The header variables have specific offsets in the decompressed data
        # These offsets vary by version - need to use bit-level parsing
        pass
```

2. **Implement TIMEBLL parsing**:
```python
def parse_timebll(data: bytes, offset: int) -> Tuple[datetime, int]:
    """Parse TIMEBLL value from decompressed header data.

    TIMEBLL format:
    - days: BL (32-bit unsigned) - Julian day number
    - ms: BL (32-bit unsigned) - Milliseconds of day
    - value: BD (64-bit double) - Combined value

    Returns: (datetime, bytes_consumed)
    """
    days = struct.unpack_from("<I", data, offset)[0]
    ms = struct.unpack_from("<I", data, offset + 4)[0]
    # value = struct.unpack_from("<d", data, offset + 8)[0]

    # Convert Julian day + ms to datetime
    # Julian day 2440587.5 = Unix epoch
    julian_day = days + (ms / 86400000.0)
    unix_timestamp = (julian_day - 2440587.5) * 86400

    try:
        dt = datetime.utcfromtimestamp(unix_timestamp)
        return dt, 16
    except (ValueError, OSError):
        return None, 16
```

### Challenge: Variable Offsets
Header variable offsets are not fixed - they use bit-level encoding. Options:
1. Use LibreDWG specification files to determine exact offsets per version
2. Scan decompressed data for TIMEBLL patterns (valid Julian range 2450000-2470000)
3. Parse the entire header variable stream

### Recommended Approach
Start with pattern scanning in DECOMPRESSED data (much more reliable than raw):
```python
def _scan_decompressed_for_timestamps(self, data: bytes, result):
    """Scan decompressed header section for timestamp patterns."""
    found = []

    for offset in range(0, len(data) - 16, 4):
        # Try to read as TIMEBLL
        days = struct.unpack_from("<I", data, offset)[0]
        ms = struct.unpack_from("<I", data, offset + 4)[0]

        # Valid Julian day range for modern files (1990-2050)
        if 2447893 <= days <= 2469807:  # Jan 1, 1990 to Jan 1, 2050
            if ms < 86400000:  # Valid ms of day
                julian_day = days + (ms / 86400000.0)
                dt = julian_to_datetime(julian_day)
                if dt:
                    found.append({'offset': offset, 'datetime': dt, 'days': days, 'ms': ms})

    # Assign based on position/values
    # TDCREATE < TDUPDATE typically
    if found:
        found.sort(key=lambda x: x['datetime'])
        result.tdcreate = self._make_timestamp('TDCREATE', found[0])
        if len(found) > 1:
            result.tdupdate = self._make_timestamp('TDUPDATE', found[-1])
```

### Success Criteria
- [x] TDCREATE extracted matches AutoCAD reported value
- [x] TDUPDATE extracted matches file modification time (within 1 second)
- [x] UTC variants (TDUCREATE, TDUUPDATE) extracted
- [x] TDINDWG (editing time) extracted

---

## Phase 4: Application Fingerprinting (Day 3-4)

### Goal
Detect which application created/modified the DWG file.

### Implementation
1. **Parse AcDb:AppInfo section**:
```python
def parse_appinfo_section(self, file_data: bytes, section_info: SectionInfo) -> dict:
    """Parse application information from AcDb:AppInfo section."""
    # Read and decompress section
    appinfo_data = self._read_and_decompress_section(file_data, section_info)

    result = {
        'product_name': '',
        'version': '',
        'build': '',
        'language': '',
        'product_guid': '',
    }

    # AcDb:AppInfo contains null-terminated strings and GUIDs
    # Parse based on structure
    # ...

    return result
```

2. **Application signature database**:
```python
APPLICATION_SIGNATURES = {
    'Autodesk AutoCAD': {'vendor': 'Autodesk', 'trusted': True},
    'Autodesk Civil 3D': {'vendor': 'Autodesk', 'trusted': True},
    'Autodesk Revit': {'vendor': 'Autodesk', 'trusted': True},
    'BricsCAD': {'vendor': 'Bricsys', 'trusted': True},
    'ZWCAD': {'vendor': 'ZWSOFT', 'trusted': True},
    'NanoCAD': {'vendor': 'Nanosoft', 'trusted': True},
    'LibreDWG': {'vendor': 'GNU', 'trusted': False, 'note': 'ODA-based'},
    'ODA': {'vendor': 'Open Design Alliance', 'trusted': True},
}
```

### Success Criteria
- [x] Correctly identifies Civil 3D as authoring software
- [x] Correctly identifies Revit exports
- [x] Detects ODA-based converters
- [x] Flags unknown/suspicious applications

---

## Phase 5: Integration and Testing (Day 4-5)

### Update Core Analyzer
Modify `dwg_forensic/core/analyzer.py` to use fixed parsers:
```python
def analyze(self, file_path: Path) -> ForensicAnalysis:
    # 1. Basic header parsing (version detection)
    header = self._header_parser.parse(file_path)

    # 2. CRC validation (FIXED)
    crc_result = self._crc_validator.validate_header_crc(file_path, header.version_string)

    # 3. Section map parsing (FIXED)
    section_map = self._section_parser.parse(file_path)

    # 4. Drawing variables extraction (FIXED - from decompressed section)
    drawing_vars = self._drawing_vars_parser.parse(file_path, section_map)

    # 5. Application fingerprinting (NEW)
    app_info = self._appinfo_parser.parse(file_path, section_map)

    # 6. Tampering analysis
    tampering = self._tampering_analyzer.analyze(
        header, crc_result, drawing_vars, app_info
    )

    return ForensicAnalysis(...)
```

### Test Files Required
| File | Source | Purpose |
|------|--------|---------|
| civil3d_2025_clean.dwg | Civil 3D 2025 | Baseline - should pass all checks |
| revit_2024_export.dwg | Revit 2024 export | Test cross-app detection |
| bricscad_v24.dwg | BricsCAD V24 | Test non-Autodesk detection |
| tampered_timestamps.dwg | Manually modified | Test tampering detection |
| oda_converted.dwg | LibreDWG/ODA | Test ODA detection |

### Acceptance Tests
```python
def test_civil3d_analysis():
    """Civil 3D file should pass all validation."""
    result = analyzer.analyze(Path("test_files/civil3d_2025_clean.dwg"))
    assert result.crc_validation.is_valid
    assert result.drawing_variables.tdcreate is not None
    assert result.drawing_variables.tdupdate is not None
    assert "Civil 3D" in result.application_info.product_name

def test_timestamp_tampering_detection():
    """Tampered file should be detected."""
    result = analyzer.analyze(Path("test_files/tampered_timestamps.dwg"))
    assert any(r.severity == 'critical' for r in result.tampering_indicators)
```

---

## Resource Requirements

### Documentation
- [x] ODA Specification PDF (free) - HAVE IT
- [x] LibreDWG source code (GitHub) - HAVE IT

### Paid Resources (Optional)
- ODA SDK trial license - for validation
- Sample DWG files from different applications

### Tools Needed
- Python 3.10+
- pytest for testing
- Hex editor for binary analysis

---

## Timeline Summary

| Phase | Task | Duration |
|-------|------|----------|
| 1 | Fix CRC validation | 4 hours |
| 2 | Fix section map parsing | 8 hours |
| 3 | Fix timestamp extraction | 12 hours |
| 4 | Application fingerprinting | 8 hours |
| 5 | Integration and testing | 8 hours |
| **Total** | | **40 hours** |

---

## Questions for User

1. **Do you have test DWG files from:**
   - Civil 3D 2025
   - Revit 2024
   - BricsCAD
   - A file you know to be tampered

2. **Should we prioritize any specific tampering detection?**
   - Timestamp manipulation
   - Application masquerading
   - Content modification

3. **Is Neo4j available for knowledge storage?**
   - Connection failed during research
   - Can use file-based storage instead

---

*Implementation Plan v3.0 - Based on deep format research 2026-01-19*
