# DWG Forensic Tool - Technical Specification v2.0

## Document Control
- **Version**: 2.0
- **Generated**: 2026-01-11
- **Source**: PRDv2.0 Gap Analysis
- **Status**: Implementation Ready

---

## 1. Executive Summary

This specification addresses critical parsing failures identified in the DWG Forensic Tool. The root cause analysis reveals that **all deep parsing modules fail because Section Page Decompression (FR-SECTION-002) is not implemented**.

### Critical Path
```
FR-SECTION-002 (Decompression) --> FR-HEADER-001 (Drawing Variables) --> FR-HANDLE-001 (Handle Map)
                               |
                               --> FR-SECTION-003 (R2018+ Encryption)
```

---

## 2. Gap Analysis Summary

### 2.1 Current State vs Required State

| Component | Current State | Required State | Gap Severity |
|-----------|--------------|----------------|--------------|
| Section Map Parsing | Reads wrong offset (0x34) for AC1032 | Proper offset calculation per version | CRITICAL |
| Section Decompression | Not implemented (zlib fallback fails) | Full LZ-like Type 2 decompression | CRITICAL |
| Drawing Variables | Heuristic scanning (garbage results) | Section-based extraction | HIGH |
| Handle Map | Invalid data from raw bytes | Decompressed AcDb:Handles parsing | HIGH |
| R2018+ Encryption | Not detected | Full decryption support | MEDIUM |

### 2.2 Code Location Analysis

| File | Line | Issue |
|------|------|-------|
| `parsers/sections.py` | 194 | `section_map_addr = struct.unpack_from("<I", data, 0x34)[0]` - WRONG for AC1032 |
| `parsers/sections.py` | 236-315 | Heuristic scanning instead of proper section map parsing |
| `parsers/sections.py` | 339-344 | `zlib.decompress()` fallback - DWG uses custom LZ, not zlib |
| `parsers/drawing_vars.py` | * | `_scan_for_timestamps()` scans entire file - fundamentally wrong |
| `parsers/handles.py` | * | Parses raw bytes instead of decompressed section |

---

## 3. Implementation Specifications

### 3.1 FR-SECTION-001: Section Map Location

#### 3.1.1 Problem Statement
Current code reads section map address from fixed offset 0x34, which is incorrect for AC1032 (R2018+).

#### 3.1.2 Correct Implementation

**R2010-R2017 (AC1024, AC1027):**
```
Offset 0x20: Section locator info starts
- 0x20: Section page map record number (4 bytes, RL)
- 0x24: Section page map size (4 bytes, RL)
- 0x28: Page count (4 bytes, RL)
- 0x2C: Max section size (4 bytes, RL)
- 0x30: Unknown (4 bytes, RL)
- 0x34: Section page map address (4 bytes, RL)
```

**R2018+ (AC1032):**
```
Header is encrypted with a static XOR mask.
After decryption:
- Section locator at offset 0x80
- Additional gap table at 0xB0
```

#### 3.1.3 Implementation Steps
1. Detect version from bytes 0x00-0x05
2. For AC1032: Apply XOR decryption mask to header
3. Read section locator from version-appropriate offset
4. Validate section map address bounds

### 3.2 FR-SECTION-002: Section Page Decompression (CRITICAL)

#### 3.2.1 Problem Statement
DWG uses a custom LZ-like compression algorithm (Type 2), not standard zlib. Current `zlib.decompress()` fails silently.

#### 3.2.2 Compression Algorithm Specification

**Page Header Structure (32 bytes):**
```c
struct SectionPageHeader {
    uint32_t page_type;        // 0x4163003B for data page
    uint32_t decompressed_size;
    uint32_t compressed_size;
    uint32_t compression_type; // 2 = LZ compressed
    uint32_t checksum;
    // ... padding to 32 bytes
};
```

**LZ Decompression Algorithm (Type 2):**
```
Input: compressed_data bytes
Output: decompressed_data bytes

opcode = read_byte()

if opcode == 0x00:
    // End of stream
    return

if opcode < 0x10:
    // Literal run: copy (opcode + 3) bytes
    copy_literal(opcode + 3)

elif opcode < 0x20:
    // Short back-reference
    length = ((opcode & 0x0F) >> 2) + 3
    offset = ((opcode & 0x03) << 8) | read_byte()
    copy_from_output(offset + 1, length)

elif opcode < 0x40:
    // Medium back-reference
    length = (opcode & 0x1F) + 2
    offset = read_uint16_le()
    copy_from_output(offset + 1, length)

else:
    // Long back-reference or literal
    if opcode >= 0x80:
        length = (opcode & 0x1F) + 2
        if opcode & 0x40:
            length += read_byte()
        offset = read_uint16_le()
        copy_from_output(offset + 1, length)
    else:
        // Extended literal run
        length = ((opcode - 0x40) << 8) | read_byte() + 0x103
        copy_literal(length)
```

#### 3.2.3 Implementation Requirements
- Create `dwg_forensic/parsers/compression.py`
- Implement `decompress_section(data: bytes) -> bytes`
- Handle page boundaries (sections span multiple pages)
- Validate decompressed size matches header
- Calculate and verify checksum

### 3.3 FR-HEADER-001: Drawing Variables Extraction

#### 3.3.1 Problem Statement
Current code scans entire file for Julian date patterns. This produces garbage because:
1. Section data is compressed
2. Julian dates in raw compressed bytes are coincidental matches

#### 3.3.2 Correct Implementation

**Step 1: Locate AcDb:Header section from section map**
```python
header_section = section_map.get_section(SectionType.HEADER)
```

**Step 2: Decompress section data**
```python
header_data = decompress_section(compressed_data)
```

**Step 3: Parse drawing variables from decompressed data**

**Variable Locations (post-decompression):**
```
TDCREATE: Offset varies by version, typically 0x00-0x10 region
TDUPDATE: Follows TDCREATE
TDINDWG: Drawing time duration
TDUSRTIMER: User elapsed timer
```

**Julian Date Format:**
```
8 bytes: IEEE 754 double
Julian Day Number where:
- 2440588.0 = 1970-01-01 00:00:00 UTC
- Fractional part = time of day
```

**Conversion:**
```python
def julian_to_datetime(julian: float) -> datetime:
    # Julian Day 2440587.5 = Unix epoch (1970-01-01 00:00:00)
    unix_timestamp = (julian - 2440587.5) * 86400
    return datetime.utcfromtimestamp(unix_timestamp)
```

### 3.4 FR-HANDLE-001: Handle Map Analysis

#### 3.4.1 Problem Statement
Handle map parsing reads raw bytes instead of decompressed AcDb:Handles section.

#### 3.4.2 Correct Implementation

**Step 1: Get decompressed AcDb:Handles section**
```python
handles_section = section_map.get_section(SectionType.HANDLES)
handles_data = decompress_section(compressed_data)
```

**Step 2: Parse handle entries**

**Handle Entry Structure:**
```
Variable-length encoding:
- Handle value: modular char encoding
- Offset to object: modular char encoding
```

**Modular Char Decoding:**
```python
def decode_modular_char(data: bytes, offset: int) -> tuple[int, int]:
    """Decode modular char, return (value, bytes_consumed)."""
    value = 0
    shift = 0
    consumed = 0

    while True:
        byte = data[offset + consumed]
        consumed += 1
        value |= (byte & 0x7F) << shift
        shift += 7

        if byte & 0x80 == 0:
            break

    return value, consumed
```

**Step 3: Detect gaps in handle sequence**
```python
def find_handle_gaps(handles: list[int]) -> list[tuple[int, int]]:
    """Find gaps indicating deleted objects."""
    gaps = []
    sorted_handles = sorted(handles)

    for i in range(1, len(sorted_handles)):
        gap = sorted_handles[i] - sorted_handles[i-1]
        if gap > 1:
            gaps.append((sorted_handles[i-1], sorted_handles[i]))

    return gaps
```

### 3.5 FR-SECTION-003: R2018+ Encryption

#### 3.5.1 Problem Statement
R2018+ files (AC1032) encrypt the file header and section locator.

#### 3.5.2 Encryption Detection
```python
def is_encrypted_header(data: bytes) -> bool:
    """Check if AC1032 file has encrypted header."""
    version = data[0:6].decode('ascii', errors='ignore')
    if version != 'AC1032':
        return False

    # Check for encryption flag at offset 0x06
    flags = struct.unpack_from('<H', data, 0x06)[0]
    return bool(flags & 0x0001)
```

#### 3.5.3 Decryption Implementation
```python
# Static XOR mask for AC1032 header decryption
AC1032_HEADER_MASK = bytes([
    0x29, 0x23, 0xBE, 0x84, 0xE1, 0x6C, 0xD6, 0xAE,
    # ... (32 bytes total, from LibreDWG)
])

def decrypt_ac1032_header(data: bytes) -> bytes:
    """Decrypt AC1032 header region."""
    decrypted = bytearray(data)

    # Header encrypted region: 0x80 to 0x100
    for i in range(0x80, 0x100):
        if i < len(decrypted):
            decrypted[i] ^= AC1032_HEADER_MASK[(i - 0x80) % len(AC1032_HEADER_MASK)]

    return bytes(decrypted)
```

---

## 4. File Structure Changes

### 4.1 New Files
```
dwg_forensic/parsers/compression.py    # LZ decompression algorithm
dwg_forensic/parsers/encryption.py     # R2018+ decryption
dwg_forensic/parsers/modular_char.py   # Modular char encoding utilities
```

### 4.2 Modified Files
```
dwg_forensic/parsers/sections.py       # Fix section map location, add decompression integration
dwg_forensic/parsers/drawing_vars.py   # Replace heuristic scanning with section-based extraction
dwg_forensic/parsers/handles.py        # Use decompressed section data
dwg_forensic/core/analyzer.py          # Update integration points
```

---

## 5. Test Requirements

### 5.1 Unit Tests
- `tests/test_compression.py` - LZ decompression with known test vectors
- `tests/test_encryption.py` - R2018+ decryption verification
- `tests/test_modular_char.py` - Encoding/decoding validation

### 5.2 Integration Tests
- `tests/test_sections_integration.py` - Full section map parsing flow
- `tests/test_drawing_vars_integration.py` - Variable extraction from real files
- `tests/test_handles_integration.py` - Handle map analysis accuracy

### 5.3 Validation Criteria
- TDCREATE extraction: Must match AutoCAD's reported creation date
- TDUPDATE extraction: Must match file system modification (within 1 second)
- Handle gaps: Must detect known deleted objects from test files

---

## 6. Implementation Priority

### Phase 1: Section Map Decompression (BLOCKING)
1. Create `compression.py` with LZ Type 2 algorithm
2. Fix section map offset calculation in `sections.py`
3. Add encryption detection for AC1032
4. Unit tests for compression

### Phase 2: Drawing Variables
1. Refactor `drawing_vars.py` to use section map
2. Implement Julian date parsing
3. Integration tests with real DWG files

### Phase 3: Handle Map
1. Refactor `handles.py` to use decompressed section
2. Implement modular char decoding
3. Add gap detection algorithm

### Phase 4: R2018+ Encryption
1. Create `encryption.py`
2. Integrate header decryption into `sections.py`
3. Full AC1032 parsing tests

---

## 7. Success Criteria

| Metric | Target |
|--------|--------|
| Section decompression success rate | 100% for valid DWG files |
| TDCREATE accuracy | Within 1 second of AutoCAD reported |
| TDUPDATE accuracy | Within 1 second of file modification |
| Handle gap detection | 100% of known deletions identified |
| AC1032 support | Full parsing without degradation |

---

## 8. References

1. OpenDesign Alliance DWG Specification
2. LibreDWG source code (decode_r2004.c, decode_r2007.c, bits.c)
3. Teigha/ODA documentation
4. DWG format reverse engineering notes

---

*End of Technical Specification*
