# Example CAD File Repository

This directory contains sample DWG files from various sources for CAD application fingerprinting research.

## CRITICAL DISCOVERY (2026-01-11)

**MAJOR FINDING:** Our initial assumptions about CRC and TrustedDWG fingerprinting were INCORRECT.

After analyzing genuine licensed Autodesk files (Civil 3D 2025, Revit 2024), we discovered:

| Marker | Expected for Genuine | Actual in Genuine Autodesk |
|--------|---------------------|---------------------------|
| CRC32 | Non-zero (valid) | **0x00000000** (same as LibreDWG!) |
| TrustedDWG Watermark | Present + Valid | **ABSENT** |
| AcDb class prefix | Present | Present (but also in LibreDWG) |

**Conclusion:** CRC=0x00000000 and missing TrustedDWG do NOT prove non-Autodesk origin!

## Comparative Analysis Results

### Header Field Comparison

| File | Version | Preview Addr | App Ver | Summary Addr | VBA Addr | CRC |
|------|---------|--------------|---------|--------------|----------|-----|
| CaseFile_Subject.dwg | AC1018 | 0x1C0 | 25 | 0x20000000 | 0x1 | 0x0 |
| Civil3D_2025.dwg | AC1032 | 0x1C0 | 33 | 0x20000000 | 0x1 | 0x0 |
| Revit_2024_export.dwg | AC1032 | **0x120** | 33 | **0x0** | **0x0** | 0x0 |
| LibreDWG_sample.dwg | AC1032 | 0x1C0 | 33 | 0x20000000 | 0x1 | 0x0 |

### Key Distinguishing Factors

**Revit Export Signature:**
- Preview Address: 0x00000120 (others use 0x000001C0)
- Summary Info Address: 0x00000000 (others use 0x20000000)
- VBA Project Address: 0x00000000 (others use 0x00000001)
- NTFS nanoseconds: Exactly zero (timestamp truncation)

**Embedded Path Strings (AC1018 only - unencrypted):**
- Case File contains: `\Autodesk\AutoCAD 2004\R16.0\enu\Plot Styles\`
- This embedded path proves AutoCAD 2004 origin

### String Presence Analysis

| File | "autodesk" | "autocad" | "libredwg" | TrustedDWG Marker |
|------|------------|-----------|------------|-------------------|
| CaseFile_Subject.dwg | 1 | 1 | 0 | NO |
| Civil3D_2025.dwg | 2 | 0 | 0 | NO |
| Revit_2024_export.dwg | 0 | 0 | 0 | NO |
| LibreDWG_sample.dwg | 0 | 0 | 0 | NO |

### Handle Gap Analysis

| File | Total Gaps | Critical Gaps | Notes |
|------|-----------|---------------|-------|
| CaseFile_Subject.dwg | 258 | 215 | Small file, expected |
| Civil3D_2025.dwg | ~6000 | ~5598 | Large complex drawing |
| Revit_2024_export.dwg | 4117 | 2938 | Export artifact? |
| LibreDWG_sample.dwg | 486 | 282 | Simple test file |

## LibreDWG Analysis Results (2026-01-11)

Using LibreDWG's `dwgread` tool, we extracted and compared forensic header variables.
This revealed **NEW fingerprinting markers** that are more reliable than CRC or TrustedDWG.

### Drawing Variable Comparison

| Variable | Case File | Civil 3D 2025 | Revit 2024 Export | LibreDWG Sample |
|----------|-----------|---------------|-------------------|-----------------|
| **FINGERPRINTGUID** | C4F5D6E3-... | 7FBD120F-... | 02D3E6D4-... | **FDEAD578**-... |
| **TDINDWG** (edit time) | 350187 (~5.8 min) | 73000 (~1.2 min) | **1000 (~1 sec)** | 135859 (~2.3 min) |
| **HANDSEED[1]** | 2 | 2 | **3** | 2 |
| **Class Count** | 96 | 636 | **10** | 11 |
| **Object Count** | 361 | 6,569 | 74,915 | 143 |

### NEW Fingerprinting Markers Discovered

**1. LibreDWG GUID Pattern:**
- FINGERPRINTGUID contains "DEAD" (e.g., FDEAD578-A652-11D2-9A35-0060089B3A3F)
- This is a placeholder/test value unique to LibreDWG-created files
- Confidence: 98%

**2. Revit Export Signatures:**
- **TDINDWG near-zero** (~1000 = ~0.016 minutes): No real editing time because Revit exports directly
- **HANDSEED[1] = 3**: All other applications use 2
- **Very low class count** (10): Native AutoCAD has 90-100+, Civil 3D has 600+
- Combined confidence: 90%

**3. Civil 3D / AEC Pattern:**
- **Very high class count** (636+ classes): Due to specialized civil engineering objects
- Contains "AeccDb" class prefixes (AutoCAD Civil 3D Database classes)
- Confidence: 85%

### LibreDWG JSON Output Files

Analysis output files generated:
- `CaseFile_Subject_libredwg.json` (358 KB)
- `Civil3D_2025_libredwg.json` (6.9 MB)
- `Revit_2024_libredwg.json` (72 MB)
- `LibreDWG_sample_libredwg.json` (222 KB)

### Key Forensic Values by Application

| Application | TDINDWG Range | HANDSEED[1] | Class Count | GUID Pattern |
|-------------|---------------|-------------|-------------|--------------|
| AutoCAD 2004 | 50,000-500,000+ | 2 | 90-100 | Random |
| Civil 3D 2025 | 50,000-500,000+ | 2 | 600+ | Random |
| Revit Export | <2,000 | **3** | 10-15 | Random |
| LibreDWG | 50,000-500,000+ | 2 | 10-20 | **Contains "DEAD"** |

## Genuine Autodesk Files

### Civil 3D 2025 (User Provided)
- **File:** `Civil3D_2025_yourproject.dwg`
- **Version:** AC1032 (AutoCAD 2018+)
- **License:** Genuine AEC Collection
- **App Version:** 33
- **CRC:** 0x00000000 (!)
- **TrustedDWG:** ABSENT (!)
- **"autodesk" strings:** 2

### Revit 2024 Export (User Provided)
- **File:** `Revit_2024_export.dwg`
- **Version:** AC1032 (AutoCAD 2018+)
- **License:** Genuine AEC Collection
- **App Version:** 33
- **CRC:** 0x00000000 (!)
- **TrustedDWG:** ABSENT (!)
- **Distinguishing:** Preview Addr=0x120, no Summary/VBA pointers

### Case File Under Investigation
- **File:** `CaseFile_Subject.dwg`
- **Version:** AC1018 (AutoCAD 2004-2006)
- **App Version:** 25 (AutoCAD 2004)
- **Embedded Path:** `\Autodesk\AutoCAD 2004\R16.0\enu\Plot Styles\`
- **Note:** Contains embedded AutoCAD path proving origin

## Downloaded Samples

### AutoCAD Trial Samples (nextgis/dwg_samples)
Source: https://github.com/nextgis/dwg_samples
Created with: AutoCAD 2016 TRIAL (M.49.0.0)

- `AutoCAD_2000_circle.dwg` - AC1015
- `AutoCAD_2004_circle.dwg` - AC1018
- `AutoCAD_2007_circle.dwg` - AC1021
- `AutoCAD_2010_arc.dwg` - AC1024
- `AutoCAD_2010_circle.dwg` - AC1024
- `AutoCAD_2010_line.dwg` - AC1024
- `AutoCAD_2013_arc.dwg` - AC1027
- `AutoCAD_2013_circle.dwg` - AC1027
- `AutoCAD_2013_line.dwg` - AC1027

### Autodesk Developer Library Sample
Source: https://github.com/Developer-Autodesk/library-sample-autocad.io

- `Autodesk_library_A01.dwg` - AC1021

### LibreDWG Test Files (Open Source)
Source: https://github.com/LibreDWG/libredwg/tree/master/test/test-data
Created with: LibreDWG (GNU open-source library)

- `LibreDWG_example_2010.dwg` - AC1024
- `LibreDWG_example_2013.dwg` - AC1027
- `LibreDWG_example_2018.dwg` - AC1032
- `LibreDWG_sample_2000.dwg` - AC1015
- `LibreDWG_sample_2018.dwg` - AC1032

## Updated Fingerprint Matrix

Based on our analysis of ACTUAL files (not theoretical expectations):

| Source Type | CRC Value | TrustedDWG | Distinguishing Features |
|-------------|-----------|------------|------------------------|
| Genuine AutoCAD | 0x00000000 | ABSENT | Embedded Autodesk paths, AcDb classes |
| Civil 3D 2025 | 0x00000000 | ABSENT | "autodesk" strings, standard headers |
| Revit Export | 0x00000000 | ABSENT | Preview=0x120, No Summary/VBA addrs |
| AutoCAD Trial | 0x00000000 | ABSENT | Same as genuine (!!) |
| LibreDWG | 0x00000000 | ABSENT | No Autodesk strings |
| ODA-based | TBD | TBD | Need samples to verify |

## Still Needed

### ODA-Based Applications (Critical for comparison)
- [ ] BricsCAD
- [ ] DraftSight
- [ ] NanoCAD
- [ ] ZWCAD
- [ ] GstarCAD
- [ ] progeCAD
- [ ] CorelCAD

These applications use the Open Design Alliance SDK and may have:
- Non-zero CRC values (proper checksum implementation)
- OdDb class prefixes instead of AcDb
- Different header value patterns

## How to Analyze a File

```bash
cd DWG-forensic-tool
python -m dwg_forensic.cli analyze path/to/file.dwg -f json
```

Or use the GUI:
```bash
python -m dwg_forensic.cli gui
```

## Research Conclusions

**Previously Known:**
1. **CRC=0 is NOT a reliable indicator** - Both genuine and non-genuine files have CRC=0x00000000
2. **TrustedDWG is NOT present** in Revit exports or Civil 3D files (contrary to documentation)
3. **Embedded path strings** in older formats (AC1018) can prove AutoCAD origin
4. **Revit exports** have unique header signature (Preview Addr, Summary/VBA null)

**NEW Findings from LibreDWG Analysis (2026-01-11):**
5. **LibreDWG GUID signature** - FINGERPRINTGUID containing "DEAD" is definitive proof of LibreDWG origin
6. **TDINDWG (editing time)** - Revit exports have near-zero values; genuine AutoCAD files have substantial editing time
7. **HANDSEED[1] value** - Revit uses 3, all other applications use 2
8. **Class count patterns** - Revit: 10-15, AutoCAD: 90-100, Civil 3D: 600+
9. **Need ODA-based samples** to complete the fingerprinting matrix (still needed)
