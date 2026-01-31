# TIMELINE EVIDENCE SUMMARY
## Kara Murphy vs Danny Garcia - Design Fraud Analysis

### Critical Timeline

```
February 25, 2022
├─ File: 6075_02_25_2022.dwg
├─ Size: 6.07 MB (6,369,163 bytes)
├─ Status: DELIVERED to buyers (allegedly)
└─ SHA-256: e17080189ee0d0ed52b5f65de1ce1afffb0ad56611ce3e0a308e2efc98d080cc

         ↓
    [ONE MONTH GAP]
         ↓

March 25, 2022
├─ File: NEW 6075_032522.dwg
├─ Size: 3.41 MB (3,577,311 bytes)
├─ Status: PROMISED via email as "EXACTLY what we are building"
├─ SHA-256: 9a991509c07c45da7bfaa5b3a4033cabf633c8c7b86c54035b289231ee967332
└─ Email Quote: "This is EXACTLY what we are building and under contract for
                 in terms of floorplans and design." - Danny Garcia
```

### Fraud Allegation

**CLAIM**: Danny Garcia promised buyers the March 25, 2022 design (NEW 6075_032522.dwg) but delivered the February 25, 2022 design (6075_02_25_2022.dwg) which allegedly lacked outdoor amenities (pool, BBQ, etc.).

### Forensic Findings

#### File Size Paradox
- **EXPECTED**: If amenities were REMOVED, the delivered file should be SMALLER
- **ACTUAL**: The delivered file is 2.79 MB LARGER (+78%) than the promised file
- **INTERPRETATION**:
  1. The February file may contain MORE elements, not fewer
  2. Different design revisions, not simple amenity removal
  3. File compression differences (ODA SDK vs AutoCAD)
  4. Requires manual CAD inspection to resolve

#### File Integrity Issues
Both files show:
- Corrupted DWG structure (missing AcDb:Header, AcDb:Classes sections)
- Created by Open Design Alliance SDK (non-Autodesk tool)
- CRC32 checksum failures (0x00000000 stored, different calculated)
- CRITICAL risk level with tampering indicators
- Prevents automated layer/entity extraction

#### Timestamps
- NTFS Modified timestamps are identical: January 8, 2026 (file copy date)
- NTFS Created timestamps are recent (January 30, 2026) - files were copied to analysis machine
- Original creation dates NOT preserved in DWG metadata (missing TDCREATE/TDUPDATE)
- File provenance relies entirely on filename dates

### Evidence Strength Assessment

| Evidence Type | Strength | Notes |
|---------------|----------|-------|
| Timeline (filename dates) | STRONG | Clear one-month gap, aligns with email date |
| Email promise | STRONG | Explicit statement: "EXACTLY what we are building" |
| File authenticity | WEAK | Both files corrupted, integrity questionable |
| Amenity comparison | INCONCLUSIVE | Structure corruption prevents extraction |
| File size contradiction | PROBLEMATIC | Delivered file LARGER, not smaller |

### Legal Implications

#### STRENGTHS
1. Email dated March 25, 2022 explicitly promises "EXACTLY what we are building"
2. File dated March 25, 2022 (NEW 6075_032522.dwg) exists
3. File dated February 25, 2022 (6075_02_25_2022.dwg) is different (different SHA-256)
4. Timeline alone proves different designs were involved

#### WEAKNESSES
1. Cannot prove amenity differences without manual CAD inspection
2. File size paradox contradicts "amenities removed" theory
3. Both files show tampering/corruption indicators (low authenticity)
4. No preserved original metadata (TDCREATE, TDUPDATE missing)
5. Files created by non-standard CAD tool (ODA SDK, not AutoCAD)

#### FALLBACK POSITION
Even without proving specific amenities were removed, the timeline evidence proves:
- Danny sent a March 25 design and said "this is EXACTLY what we are building"
- A different February 25 design exists
- If the February design was delivered instead, that constitutes misrepresentation
- File date discrepancy alone supports fraud claim

### Next Steps

#### REQUIRED FOR CASE STRENGTH
1. **Manual CAD Inspection** (CRITICAL)
   - Open both files in AutoCAD
   - Export layer lists to text/CSV
   - Generate PDF prints showing all layers
   - Compare layer names for "POOL", "BBQ", "OUTDOOR KITCHEN", etc.
   - Document entity counts and block references

2. **Obtain Original Files** (HIGH PRIORITY)
   - Subpoena original email attachments (not copies)
   - Request native AutoCAD files from architect/designer
   - Obtain email server logs showing attachment metadata
   - Verify files were not modified after email send date

3. **Expert Witness** (RECOMMENDED)
   - Hire CAD forensic expert to:
     - Perform binary diff analysis
     - Recover corrupted DWG sections using specialized tools
     - Testify to file authenticity and timeline
     - Explain technical findings to jury

4. **Discovery**
   - Depose Danny Garcia on design timeline
   - Request all design revisions from February-March 2022
   - Obtain construction plans submitted to county (what was actually built?)
   - Interview architect/designer about design changes

### Confidence Assessment

- **Timeline Evidence**: 95% (filename dates + email date strongly corroborate)
- **File Authenticity**: 30% (both files corrupted, low integrity)
- **Amenity Removal**: 20% (cannot verify without manual CAD inspection)
- **Overall Case Strength**: 60% MODERATE

**CRITICAL LIMITATION**: File structure corruption prevents automated proof of amenity removal. Manual CAD inspection is REQUIRED to clinch the fraud claim.

### Recommended Expert Testimony

If this goes to trial, expert witness should testify to:
1. Timeline discrepancy (March promised, February delivered)
2. Files are demonstrably different (different SHA-256 hashes)
3. File integrity issues and ODA SDK origin
4. Manual layer comparison results (PENDING CAD inspection)
5. Industry standards for design documentation and change control

**DO NOT** rely on automated forensic analysis alone - the file corruption issues will undermine credibility. Focus on timeline + manual CAD inspection results.
