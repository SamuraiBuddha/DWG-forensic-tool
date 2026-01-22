# DWG File Format Research Findings

**Research Date**: 2026-01-19
**Purpose**: Forensic timestamp tampering detection
**Status**: Critical bugs identified in current implementation

---

## 1. Executive Summary - ROOT CAUSE ANALYSIS

The current DWG forensic tool fails on almost every file due to **three fundamental implementation errors**:

| Issue | Current Implementation | Correct Implementation | Impact |
|-------|----------------------|----------------------|--------|
| CRC Validation | Calculates CRC32 over 0x68 bytes | Must calculate over 0x6C bytes with CRC field zeroed | All files fail CRC |
| Timestamp Extraction | Scans RAW compressed bytes for Julian dates | Must decompress AcDb:Header section first | Garbage results |
| Application Detection | Unknown/missing | Parse decompressed AcDb:AppInfo section | No fingerprinting |

---

## 2. CRC Validation - CRITICAL FIX REQUIRED

### Current Bug
```python
# WRONG - crc.py line 96-97
crc_offset = crc_info["offset"]  # 0x68
header_length = crc_info["length"]  # 0x68 (WRONG!)
```

### Correct Specification (from ODA Spec)
- **Header size**: 0x6C (108) bytes total
- **CRC location**: Offset 0x68 (4 bytes)
- **CRC algorithm**: CRC-32 with **seed of ZERO**
- **CRC calculation**: Over ALL 0x6C bytes, with bytes 0x68-0x6B set to 0x00000000

### Fix Required
```python
# CORRECT implementation
def calculate_header_crc(data: bytes) -> int:
    # Make copy with CRC field zeroed
    header = bytearray(data[:0x6C])
    header[0x68:0x6C] = b'\x00\x00\x00\x00'  # Zero the CRC field
    return zlib.crc32(bytes(header)) & 0xFFFFFFFF
```

### Sources
- [Open Design Specification for .dwg files v5.4.1](https://www.opendesign.com/files/guestdownloads/OpenDesign_Specification_for_.dwg_files.pdf)
- LibreDWG mailing list discussions

---

## 3. Section Structure and Decompression

### Critical Data Flow
```
Raw File --> Decrypt Header (AC1032) --> Parse Section Locator -->
Find Section Map Address --> Read Section Pages --> Decompress (Type 2 LZ) -->
Parse Decompressed Data
```

### Section Locator Offsets by Version

| Version | Code | Locator Offset | Section Map Addr Offset | Encrypted |
|---------|------|---------------|------------------------|-----------|
| R2004 | AC1018 | 0x20 | +0x14 | No |
| R2007 | AC1021 | 0x20 | +0x14 | Yes (0x20-0x80) |
| R2010 | AC1024 | 0x20 | +0x14 | No |
| R2013 | AC1027 | 0x20 | +0x14 | No |
| R2018+ | AC1032 | 0x80 | +0x14 | Yes (0x80-0x100) |

### AC1032 Encryption XOR Mask
```python
AC1032_HEADER_MASK = bytes([
    0x29, 0x23, 0xBE, 0x84, 0xE1, 0x6C, 0xD6, 0xAE,
    0x52, 0x90, 0x49, 0xF1, 0xF1, 0xBB, 0xE9, 0xEB,
    0xB3, 0xA6, 0xDB, 0x3C, 0x87, 0x0C, 0x3E, 0x99,
    0x24, 0x5E, 0x0D, 0x1C, 0x06, 0xB7, 0x47, 0xDE,
])
# Applied to bytes 0x80-0x100 (128 bytes, mask repeats every 32 bytes)
```

### Section Types (SectionType enum)
| Value | Name | Contents |
|-------|------|----------|
| 0x01 | AcDb:Header | Drawing variables (TDCREATE, TDUPDATE, etc.) |
| 0x02 | AcDb:Classes | Class definitions |
| 0x03 | AcDb:Handles | Object handle map (for gap analysis) |
| 0x07 | AcDb:Preview | Thumbnail image |
| 0x08 | AcDb:AppInfo | Application fingerprint data |
| 0x0A | AcDb:FileDepList | External file dependencies |
| 0x0D | AcDb:Signature | TrustedDWG signature |

---

## 4. Timestamp Variables - WHERE THEY ACTUALLY LIVE

### Location: AcDb:Header Section (COMPRESSED!)

The current code scans raw file bytes for Julian date patterns. This is **fundamentally wrong** because:
1. The AcDb:Header section is **compressed** using Type 2 LZ
2. Random compressed bytes coincidentally match Julian date range
3. Results are garbage/random dates

### Correct Extraction Flow
1. Parse section map to locate AcDb:Header section
2. Read section pages
3. **Decompress** section data using Type 2 LZ algorithm
4. Parse TIMEBLL values from decompressed data

### TIMEBLL Data Type
```c
typedef struct _dwg_time_bll {
  BITCODE_BL days;      // 32-bit unsigned - Julian day number
  BITCODE_BL ms;        // 32-bit unsigned - Milliseconds of day
  BITCODE_BD value;     // 64-bit double - Combined value
} Dwg_Bitcode_TimeBLL;
```

### Timestamp Variables (DXF Group Code 40)
| Variable | Purpose | Type |
|----------|---------|------|
| TDCREATE | Drawing creation time (local) | TIMEBLL |
| TDUPDATE | Last modification time (local) | TIMEBLL |
| TDUCREATE | Creation time (UTC) | TIMEBLL |
| TDUUPDATE | Modification time (UTC) | TIMEBLL |
| TDINDWG | Total editing time (duration) | TIMEBLL |
| TDUSRTIMER | User timer | TIMEBLL |

### Julian Date Conversion
```python
def julian_to_datetime(julian_day: float) -> datetime:
    # Julian day 2440587.5 = Unix epoch (1970-01-01 00:00:00 UTC)
    unix_timestamp = (julian_day - 2440587.5) * 86400
    return datetime.utcfromtimestamp(unix_timestamp)
```

---

## 5. Application Fingerprinting - AcDb:AppInfo Section

### Location: AcDb:AppInfo Section (COMPRESSED!)

Contains:
- Application product name
- Version information
- Build number
- Language/localization
- Company name
- Product GUID

### Detection Signatures for Common Applications
| Application | Identifier Pattern |
|-------------|-------------------|
| AutoCAD | "Autodesk AutoCAD" |
| Revit | "Autodesk Revit" |
| Civil 3D | "Autodesk Civil 3D" |
| BricsCAD | "BricsCAD" |
| ZWCAD | "ZWCAD" |
| NanoCAD | "NanoCAD" |
| ODA (LibreDWG) | Various ODA markers |

---

## 6. Type 2 LZ Compression Algorithm

### Page Header Structure (32 bytes)
```
Offset  Size  Field
0x00    4     page_type (0x4163003B = data page, 0x41630E3B = page map)
0x04    4     decompressed_size
0x08    4     compressed_size
0x0C    4     compression_type (2 = compressed)
0x10    4     checksum
0x14-0x1F     padding
```

### Decompression Opcodes
| Opcode Range | Meaning |
|--------------|---------|
| 0x00 | End of stream |
| 0x01-0x0F | Literal run: copy (opcode + 3) bytes |
| 0x10-0x1F | Short back-reference |
| 0x20-0x3F | Medium back-reference |
| 0x40-0x7F | Extended literal run |
| 0x80-0xFF | Long back-reference |

---

## 7. Recommended Implementation Fixes

### Priority 1: Fix CRC Validation
1. Read 0x6C bytes (not 0x68)
2. Zero bytes 0x68-0x6B before calculation
3. Calculate CRC32 with seed=0
4. Compare to stored CRC at offset 0x68

### Priority 2: Fix Timestamp Extraction
1. Implement proper section map parsing
2. Locate AcDb:Header section
3. Decompress section data
4. Parse TIMEBLL values from known offsets in decompressed data

### Priority 3: Implement Application Fingerprinting
1. Locate AcDb:AppInfo section
2. Decompress section data
3. Parse application metadata strings

### Priority 4: Validate Decompression
1. Test Type 2 LZ algorithm against known test vectors
2. Verify checksum after decompression
3. Validate decompressed size matches header

---

## 8. Research Sources

### Primary
- [Open Design Specification for .dwg files v5.4.1 (ODA)](https://www.opendesign.com/files/guestdownloads/OpenDesign_Specification_for_.dwg_files.pdf)
- [LibreDWG Source Code (GitHub)](https://github.com/LibreDWG/libredwg)
- [LibreDWG Documentation](https://www.gnu.org/software/libredwg/manual/LibreDWG.html)

### Secondary
- [AutoCAD DXF Documentation (Autodesk)](https://help.autodesk.com/cloudhelp/2018/ENU/AutoCAD-DXF/files/GUID-6942BAF3-095F-4217-9F61-6931975D3A64.htm)
- [ACadSharp (C# DWG Library)](https://github.com/DomCR/ACadSharp)

### Forensic Research
- [Forensic Detection of Timestamp Manipulation (IEEE 2024)](https://ieeexplore.ieee.org/document/10516317/)
- [SANS Digital Forensics: Timestamp Manipulation Detection](https://www.sans.org/blog/digital-forensics-detecting-time-stamp-manipulation/)

---

## 9. Paid Resources (If Needed)

| Resource | Cost | Value |
|----------|------|-------|
| ODA SDK (Teigha) | Commercial license | Full DWG read/write, reference implementation |
| RealDWG SDK (Autodesk) | Commercial license | Official Autodesk DWG libraries |
| ODA Specification (Full) | Free download | Comprehensive format documentation |

**Note**: The ODA Specification PDF is freely available and contains the most detailed format documentation. LibreDWG source code provides working implementation reference.

---

*Document generated by DWG Forensic Tool research - 2026-01-19*
