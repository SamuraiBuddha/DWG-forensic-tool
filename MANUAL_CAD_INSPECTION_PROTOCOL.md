# MANUAL CAD INSPECTION PROTOCOL
## 6075 English Oaks Design Comparison

### Purpose
Due to DWG file structure corruption preventing automated layer/entity extraction, manual CAD inspection is REQUIRED to prove amenity differences between the contracted and delivered designs.

### Files to Inspect

**File 1: CONTRACTED DESIGN (Promised March 25, 2022)**
- Path: `Z:\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia\Caron - Produce to John Ehrig\Gansari\Naples\6075 English Oaks - Naples 2, 2022 Drawing Files\Cads from owner 2022 (old)\NEW 6075_032522.dwg`
- Size: 3.41 MB
- SHA-256: `9a991509c07c45da7bfaa5b3a4033cabf633c8c7b86c54035b289231ee967332`

**File 2: DELIVERED DESIGN (February 25, 2022)**
- Path: `Z:\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia\Caron - Produce to John Ehrig\Gansari\Naples\6075 English Oaks - Naples 2, 2022 Drawing Files\Cads from owner 2022 (old)\6075_02_25_2022.dwg`
- Size: 6.07 MB
- SHA-256: `e17080189ee0d0ed52b5f65de1ce1afffb0ad56611ce3e0a308e2efc98d080cc`

---

## Step 1: Layer Extraction

### In AutoCAD (or BricsCAD/DraftSight)

For EACH file, perform the following:

1. **Open File**
   - Use AutoCAD 2018 or later (AC1032 format)
   - If file won't open, try BricsCAD or LibreCAD
   - Note any error messages

2. **Extract Layer List**
   - Command: `LAYER`
   - Export layer list to CSV: `LAYTRANS` or manually screenshot
   - Save as: `[filename]_LAYERS.csv`
   - **Critical columns**: Layer Name, Color, Linetype, On/Off, Frozen/Thawed

3. **Search for Amenity Layers**
   Look for layers containing these keywords (case-insensitive):
   - `POOL`, `SWIMMING`, `SPA`, `JACUZZI`, `HOT_TUB`
   - `BBQ`, `GRILL`, `OUTDOOR_KITCHEN`, `COOKING`, `BARBECUE`
   - `FIREPLACE`, `FIRE_PIT`, `FIRE_FEATURE`
   - `FOUNTAIN`, `WATERFALL`, `WATER_FEATURE`, `POND`
   - `PATIO`, `DECK`, `TERRACE`, `PERGOLA`, `GAZEBO`
   - `FENCE`, `GATE`, `WALL`
   - `LANDSCAPE`, `HARDSCAPE`, `AMENITY`, `FEATURE`, `OUTDOOR`

4. **Count Entities**
   - Command: `LIST` (select all: `CTRL+A`)
   - Note total: Lines, Arcs, Circles, Polylines, Text, Blocks
   - Save output to: `[filename]_ENTITY_COUNT.txt`

5. **Export Block References**
   - Command: `BEDIT` or `BLOCK`
   - List all block definitions
   - Look for amenity-related blocks (POOL_EQUIPMENT, BBQ_ISLAND, etc.)
   - Save list to: `[filename]_BLOCKS.txt`

6. **Generate Full PDF Export**
   - Turn ON all layers (command: `LAYER` → Thaw All, On All)
   - Zoom to extents: `ZOOM E`
   - Plot to PDF with layer names visible
   - Save as: `[filename]_FULL_DESIGN.pdf`

7. **Generate Amenity-Only PDF** (if amenity layers exist)
   - Turn OFF all layers except amenity-related layers
   - Zoom to amenity area
   - Plot to PDF
   - Save as: `[filename]_AMENITIES_ONLY.pdf`

---

## Step 2: Comparison Analysis

### Layer Comparison

Create a spreadsheet comparing layers:

| Layer Name | In CONTRACTED? | In DELIVERED? | Status |
|------------|----------------|---------------|--------|
| POOL | YES | NO | REMOVED |
| BBQ | YES | NO | REMOVED |
| PATIO | YES | YES | PRESERVED |
| ... | ... | ... | ... |

**Count**:
- Layers in CONTRACTED only: ___
- Layers in DELIVERED only: ___
- Shared layers: ___

### Entity Count Comparison

| Entity Type | CONTRACTED | DELIVERED | Difference |
|-------------|------------|-----------|------------|
| Lines | ___ | ___ | ___ |
| Arcs | ___ | ___ | ___ |
| Circles | ___ | ___ | ___ |
| Polylines | ___ | ___ | ___ |
| Text | ___ | ___ | ___ |
| Blocks | ___ | ___ | ___ |
| **TOTAL** | ___ | ___ | ___ |

### Amenity-Specific Findings

For each amenity category:

#### POOL / SWIMMING POOL
- In CONTRACTED design? YES / NO
- In DELIVERED design? YES / NO
- Layer name(s): _______________
- Evidence: [screenshot/PDF reference]

#### BBQ / OUTDOOR KITCHEN
- In CONTRACTED design? YES / NO
- In DELIVERED design? YES / NO
- Layer name(s): _______________
- Evidence: [screenshot/PDF reference]

#### FIREPLACE / FIRE FEATURE
- In CONTRACTED design? YES / NO
- In DELIVERED design? YES / NO
- Layer name(s): _______________
- Evidence: [screenshot/PDF reference]

#### WATER FEATURE / FOUNTAIN
- In CONTRACTED design? YES / NO
- In DELIVERED design? YES / NO
- Layer name(s): _______________
- Evidence: [screenshot/PDF reference]

#### PATIO / DECK / TERRACE
- In CONTRACTED design? YES / NO
- In DELIVERED design? YES / NO
- Layer name(s): _______________
- Evidence: [screenshot/PDF reference]

#### LANDSCAPING / HARDSCAPING
- In CONTRACTED design? YES / NO
- In DELIVERED design? YES / NO
- Layer name(s): _______________
- Evidence: [screenshot/PDF reference]

---

## Step 3: Visual Comparison

### Side-by-Side PDF Comparison

Create a comparison document showing:
1. CONTRACTED design (full view)
2. DELIVERED design (full view)
3. CONTRACTED amenities (zoomed)
4. DELIVERED amenities (zoomed)

**Annotate with arrows/highlights:**
- "POOL - Present in CONTRACTED, ABSENT in DELIVERED"
- "BBQ - Present in CONTRACTED, ABSENT in DELIVERED"
- etc.

### Screenshot Evidence

For each missing amenity:
1. Screenshot from CONTRACTED design showing the feature
2. Screenshot from DELIVERED design showing its absence
3. Layer manager screenshot showing layer presence/absence
4. Side-by-side comparison with annotations

---

## Step 4: Documentation for Legal Team

### Summary Report Template

```
MANUAL CAD INSPECTION REPORT
Case: Kara Murphy vs Danny Garcia
Inspector: [Name]
Date: [Date]
Files Inspected: NEW 6075_032522.dwg, 6075_02_25_2022.dwg

EXECUTIVE SUMMARY:
- CONTRACTED design (March 25, 2022) contains [X] amenity layers
- DELIVERED design (February 25, 2022) contains [Y] amenity layers
- [Z] amenities were REMOVED in the delivered version
- Total entity count reduction: [X]%

AMENITIES REMOVED:
1. [Amenity name] - Layer: [layer name] - Evidence: [reference]
2. [Amenity name] - Layer: [layer name] - Evidence: [reference]
...

AMENITIES PRESERVED:
1. [Amenity name] - Layer: [layer name]
...

CONCLUSION:
The DELIVERED design (February 25, 2022) is missing the following features
that were present in the CONTRACTED design (March 25, 2022):
[List of removed amenities]

This supports the allegation that buyers were promised a design with amenities
that were not delivered in the final construction.

CONFIDENCE LEVEL: [High/Medium/Low]

ATTACHED EVIDENCE:
- Layer comparison spreadsheet
- Entity count comparison
- Full design PDFs (both files)
- Amenity-only PDFs
- Annotated comparison images
```

---

## Step 5: Expert Witness Preparation

### If hiring CAD expert, provide:

1. **File Provenance**
   - Email dated March 25, 2022 with Danny's promise
   - Forensic analysis reports (already generated)
   - File integrity reports
   - SHA-256 hashes

2. **Manual Inspection Results**
   - Layer lists (CSV)
   - Entity counts
   - Block references
   - PDF exports
   - Comparison spreadsheets

3. **Technical Context**
   - DWG version: AC1032 (AutoCAD 2018+)
   - File creation tool: Open Design Alliance SDK
   - File integrity issues (corruption/tampering)
   - Timestamp analysis

4. **Legal Context**
   - Contract terms (what amenities were promised?)
   - Construction photos (what was actually built?)
   - Other discovery materials

### Expert Witness Testimony Outline

The expert should be prepared to testify to:
1. Qualifications (CAD/DWG forensic experience)
2. Methodology (industry-standard CAD inspection techniques)
3. File authentication (SHA-256 hashes, timeline analysis)
4. Layer comparison findings (which amenities were removed)
5. Visual evidence (PDF comparisons, annotated screenshots)
6. Opinion: Did the delivered design match the promised design? YES/NO
7. Confidence level in findings (High/Medium/Low)

---

## Critical Success Factors

### MUST HAVES for Case Strength:
1. Layer lists showing amenity layers in CONTRACTED, absent in DELIVERED
2. Visual PDF evidence showing amenity presence/absence
3. Expert witness to authenticate and explain findings
4. Construction photos showing what was actually built (matches DELIVERED?)

### NICE TO HAVES:
1. Architect/designer deposition confirming design changes
2. Email chain showing design revision requests
3. County-submitted plans (which version was approved?)
4. Original email attachments (not copies) for clean forensic analysis

### DEAL BREAKERS:
1. Both files show identical layers/amenities → case fails
2. File corruption prevents opening in any CAD software → cannot prove
3. No expert witness → technical findings not admissible
4. Construction photos show all promised amenities were built → case fails

---

## Deliverables Checklist

- [ ] `NEW_6075_032522_LAYERS.csv` (layer list from CONTRACTED file)
- [ ] `6075_02_25_2022_LAYERS.csv` (layer list from DELIVERED file)
- [ ] `NEW_6075_032522_ENTITY_COUNT.txt` (entity counts from CONTRACTED)
- [ ] `6075_02_25_2022_ENTITY_COUNT.txt` (entity counts from DELIVERED)
- [ ] `NEW_6075_032522_BLOCKS.txt` (block references from CONTRACTED)
- [ ] `6075_02_25_2022_BLOCKS.txt` (block references from DELIVERED)
- [ ] `NEW_6075_032522_FULL_DESIGN.pdf` (full PDF export from CONTRACTED)
- [ ] `6075_02_25_2022_FULL_DESIGN.pdf` (full PDF export from DELIVERED)
- [ ] `NEW_6075_032522_AMENITIES_ONLY.pdf` (amenities-only PDF from CONTRACTED)
- [ ] `6075_02_25_2022_AMENITIES_ONLY.pdf` (amenities-only PDF from DELIVERED)
- [ ] `LAYER_COMPARISON.xlsx` (side-by-side layer comparison spreadsheet)
- [ ] `ENTITY_COUNT_COMPARISON.xlsx` (side-by-side entity count comparison)
- [ ] `AMENITY_FINDINGS.pdf` (annotated comparison showing removed amenities)
- [ ] `MANUAL_CAD_INSPECTION_REPORT.docx` (final summary report)

---

## Timeline

- **Day 1**: Open files in CAD software, extract layer lists
- **Day 2**: Count entities, extract block references, generate PDFs
- **Day 3**: Create comparison spreadsheets and annotated evidence
- **Day 4**: Draft final inspection report
- **Day 5**: Review with legal team, prepare for expert witness

**CRITICAL**: This inspection must be completed BEFORE depositions or trial to allow time for expert witness preparation and potential settlement negotiations.
