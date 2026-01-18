# DWG Forensic Tool - Implementation Plan

## Execution Strategy: Swarm-Based Development

### Agent Configuration
- **Orchestrator**: Task coordination and dependency management
- **Architect**: Code review and design decisions
- **Workers**: Implementation (1 per phase)
- **Testers**: Trailing verification (1 per worker)

---

## Phase 1: Section Page Decompression [BLOCKING]

### Task 1.1: Create compression.py
**Worker**: Section-Parser-Worker
**Estimated Complexity**: HIGH

```
File: dwg_forensic/parsers/compression.py
Functions:
- decompress_section(data: bytes, expected_size: int) -> bytes
- _decode_opcode(data: bytes, pos: int) -> tuple[int, int, int]
- _copy_literal(output: bytearray, data: bytes, pos: int, length: int) -> int
- _copy_backref(output: bytearray, offset: int, length: int) -> None
```

**Implementation Steps**:
1. Create file with class `DWGDecompressor`
2. Implement opcode parsing per spec section 3.2.2
3. Handle all opcode ranges (0x00-0xFF)
4. Add bounds checking and error handling
5. Implement checksum verification

### Task 1.2: Create compression tests
**Tester**: Section-Parser-Tester
**Dependency**: Task 1.1

```
File: tests/test_compression.py
Test Cases:
- test_decompress_empty_input
- test_decompress_literal_only
- test_decompress_backref_short
- test_decompress_backref_medium
- test_decompress_backref_long
- test_decompress_mixed_opcodes
- test_decompress_invalid_opcode
- test_decompress_size_mismatch
```

### Task 1.3: Fix section map offset calculation
**Worker**: Section-Parser-Worker
**Dependency**: Task 1.1

```
File: dwg_forensic/parsers/sections.py
Changes:
- Line 194: Version-specific offset calculation
- Add AC1032 offset handling (0x80 region)
- Add section locator validation
```

### Task 1.4: Integrate decompression into sections.py
**Worker**: Section-Parser-Worker
**Dependency**: Task 1.1, 1.3

```
File: dwg_forensic/parsers/sections.py
Changes:
- Import compression module
- Update read_section_data() to use DWGDecompressor
- Add page header parsing
- Handle multi-page sections
```

### Task 1.5: Section map integration tests
**Tester**: Section-Parser-Tester
**Dependency**: Task 1.3, 1.4

```
File: tests/test_sections_integration.py
Test Cases:
- test_parse_ac1024_section_map
- test_parse_ac1027_section_map
- test_parse_ac1032_section_map
- test_decompress_header_section
- test_decompress_handles_section
- test_section_not_found
```

---

## Phase 2: Drawing Variables Extraction

### Task 2.1: Refactor drawing_vars.py
**Worker**: Drawing-Vars-Worker
**Dependency**: Phase 1 complete

```
File: dwg_forensic/parsers/drawing_vars.py
Changes:
- Remove _scan_for_timestamps() heuristic method
- Add section map integration
- Implement _parse_header_section(data: bytes)
- Add Julian date conversion utilities
```

**New Functions**:
```python
def parse_from_section(self, section_data: bytes) -> DrawingVariablesResult
def _extract_tdcreate(self, data: bytes, offset: int) -> Optional[datetime]
def _extract_tdupdate(self, data: bytes, offset: int) -> Optional[datetime]
def _extract_tdindwg(self, data: bytes, offset: int) -> Optional[timedelta]
def _julian_to_datetime(self, julian: float) -> datetime
```

### Task 2.2: Drawing variables tests
**Tester**: Drawing-Vars-Tester
**Dependency**: Task 2.1

```
File: tests/test_drawing_vars_integration.py
Test Cases:
- test_extract_tdcreate_ac1024
- test_extract_tdcreate_ac1027
- test_extract_tdcreate_ac1032
- test_julian_date_conversion
- test_invalid_julian_date
- test_missing_timestamp
- test_tdindwg_duration
```

### Task 2.3: Integrate with analyzer
**Worker**: Drawing-Vars-Worker
**Dependency**: Task 2.1

```
File: dwg_forensic/core/analyzer.py
Changes:
- Update _analyze_drawing_vars() to use section map
- Pass decompressed header section to parser
- Add error handling for decompression failures
```

---

## Phase 3: Handle Map Analysis

### Task 3.1: Create modular_char.py
**Worker**: Handle-Map-Worker
**Dependency**: Phase 1 complete

```
File: dwg_forensic/parsers/modular_char.py
Functions:
- decode_modular_char(data: bytes, offset: int) -> tuple[int, int]
- encode_modular_char(value: int) -> bytes
- decode_handle(data: bytes, offset: int) -> tuple[int, int]
```

### Task 3.2: Refactor handles.py
**Worker**: Handle-Map-Worker
**Dependency**: Task 3.1

```
File: dwg_forensic/parsers/handles.py
Changes:
- Remove raw byte scanning
- Add section map integration
- Implement proper handle parsing from AcDb:Handles
- Add gap detection algorithm
```

**New Functions**:
```python
def parse_from_section(self, section_data: bytes) -> HandleMapResult
def _parse_handle_entries(self, data: bytes) -> list[HandleEntry]
def _find_gaps(self, handles: list[int]) -> list[HandleGap]
def _estimate_deleted_count(self, gaps: list[HandleGap]) -> int
```

### Task 3.3: Handle map tests
**Tester**: Handle-Map-Tester
**Dependency**: Task 3.2

```
File: tests/test_handles_integration.py
Test Cases:
- test_decode_modular_char_single_byte
- test_decode_modular_char_multi_byte
- test_parse_handle_entries
- test_find_gaps_none
- test_find_gaps_single
- test_find_gaps_multiple
- test_estimate_deleted_objects
```

---

## Phase 4: R2018+ Encryption Handler

### Task 4.1: Create encryption.py
**Worker**: Section-Parser-Worker
**Dependency**: Phase 1 complete

```
File: dwg_forensic/parsers/encryption.py
Functions:
- is_encrypted(data: bytes) -> bool
- decrypt_header(data: bytes) -> bytes
- get_xor_mask(version: str) -> bytes
```

**Constants**:
```python
AC1032_HEADER_MASK = bytes([...])  # 32-byte XOR mask
ENCRYPTED_REGION_START = 0x80
ENCRYPTED_REGION_END = 0x100
```

### Task 4.2: Integrate encryption into sections.py
**Worker**: Section-Parser-Worker
**Dependency**: Task 4.1

```
File: dwg_forensic/parsers/sections.py
Changes:
- Import encryption module
- Add encryption detection before parsing
- Decrypt header before section map location
- Update _parse_r2010_sections() for AC1032
```

### Task 4.3: Encryption tests
**Tester**: Section-Parser-Tester
**Dependency**: Task 4.1, 4.2

```
File: tests/test_encryption.py
Test Cases:
- test_is_encrypted_ac1032
- test_is_not_encrypted_ac1027
- test_decrypt_header_valid
- test_decrypt_header_already_decrypted
- test_full_ac1032_parsing
```

---

## Final Integration

### Task 5.1: Full integration test suite
**All Testers**

```
File: tests/test_full_integration.py
Test Cases:
- test_full_analysis_ac1024
- test_full_analysis_ac1027
- test_full_analysis_ac1032
- test_tampering_detection_with_new_parsers
- test_report_generation_accuracy
```

### Task 5.2: Performance validation
**Orchestrator**

```
Criteria:
- Parse time < 5s for 50MB file
- Memory usage < 500MB peak
- No regressions in existing tests
```

---

## Dependency Graph

```
Phase 1 (BLOCKING):
  Task 1.1 --> Task 1.2
         |
         +--> Task 1.3 --> Task 1.4 --> Task 1.5
         |
         +--> Task 4.1 (can start after 1.1)

Phase 2 (requires Phase 1):
  Task 2.1 --> Task 2.2
         |
         +--> Task 2.3

Phase 3 (requires Phase 1):
  Task 3.1 --> Task 3.2 --> Task 3.3

Phase 4 (parallel with Phase 2/3):
  Task 4.1 --> Task 4.2 --> Task 4.3

Final:
  All phases --> Task 5.1 --> Task 5.2
```

---

## Execution Order

1. [PARALLEL] Task 1.1 (compression.py) - COMPLETE
2. [SEQUENTIAL] Task 1.2 (compression tests) - COMPLETE
3. [PARALLEL] Task 1.3 (section offset fix) + Task 4.1 (encryption.py) - COMPLETE
4. [SEQUENTIAL] Task 1.4 (integration) - COMPLETE
5. [SEQUENTIAL] Task 1.5 (section tests) - COMPLETE
6. [PARALLEL] Task 2.1 + Task 3.1 + Task 4.2 - COMPLETE
7. [PARALLEL] Task 2.2 + Task 3.2 + Task 4.3 - COMPLETE
8. [SEQUENTIAL] Task 2.3 + Task 3.3 - COMPLETE
9. [FINAL] Task 5.1, Task 5.2 - COMPLETE

---

## Implementation Status (Updated 2026-01-18)

**ALL PHASES COMPLETE**

| Phase | Status | Tests | Commits |
|-------|--------|-------|---------|
| Phase 1: Section Decompression | COMPLETE | 60+ tests | 9212cd1 |
| Phase 2: Drawing Variables | COMPLETE | 62 tests | 9212cd1, 7aa7869 |
| Phase 3: Handle Map Analysis | COMPLETE | 54 tests | 9212cd1, 7aa7869 |
| Phase 4: R2018+ Encryption | COMPLETE | 37 tests | Pre-existing |
| Task 5.1: Integration Tests | COMPLETE | 5 tests | 7aa7869 |
| Task 5.2: Performance | COMPLETE | <1ms/parse | 7aa7869 |

**Total: 290 tests passing**

### Key Implementation Details

- `extract_from_section()` methods added to drawing_vars.py and handles.py
- Section map parsing uses decompression from compression.py
- Analyzer passes section_map to avoid redundant parsing (66% overhead reduction)
- All tampering rules can now fire with proper timestamp/handle data

---

*End of Implementation Plan*
