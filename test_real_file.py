"""Test script for real DWG files."""
from pathlib import Path
from dwg_forensic.core.analyzer import ForensicAnalyzer

# Create analyzer
analyzer = ForensicAnalyzer()

# Analyze your file
file_path = Path(r'C:\Users\JordanEhrig\Desktop\T-406B-2.dwg')
print(f'Analyzing: {file_path}')
print()

result = analyzer.analyze(file_path)

# Print results
print('=== STRUCTURE ANALYSIS ===')
if result.structure_analysis:
    sa = result.structure_analysis
    print(f"Structure Type: {sa.get('structure_type', 'N/A')}")
    print(f"Detected Tool: {sa.get('tool_detection', {}).get('detected_tool', 'N/A')}")
    sections = sa.get('sections', {})
    print(f"Has Header Section: {sections.get('header', False)}")
    print(f"Has Classes Section: {sections.get('classes', False)}")
    print(f"Has Handles Section: {sections.get('handles', False)}")
    if sa.get('forensic', {}).get('notes'):
        print('Forensic Notes:')
        for note in sa.get('forensic', {}).get('notes', []):
            print(f'  - {note[:100]}...' if len(note) > 100 else f'  - {note}')
else:
    print('No structure analysis available')

print()
print('=== TIMESTAMPS ===')
metadata = result.metadata
if metadata:
    print(f'TDCREATE: {metadata.created_date}')
    print(f'TDUPDATE: {metadata.modified_date}')
    print(f'TDINDWG: {metadata.total_editing_time_hours} hours')
else:
    print('No metadata available')

print()
print('=== CRC ===')
crc = result.crc_validation
stored = crc.header_crc_stored
computed = crc.header_crc_calculated
if isinstance(stored, int):
    print(f'Stored CRC: {hex(stored)}')
else:
    print(f'Stored CRC: {stored}')
if isinstance(computed, int):
    print(f'Computed CRC: {hex(computed)}')
else:
    print(f'Computed CRC: {computed}')
print(f'Valid: {crc.is_valid}')

print()
print('=== REVIT DETECTION ===')
if result.revit_detection:
    rd = result.revit_detection
    print(f"Is Revit Export: {rd.get('is_revit_export', False)}")
    print(f"Confidence: {rd.get('confidence_score', 0)}")
else:
    print('No Revit detection results')

print()
print('=== RISK ASSESSMENT ===')
risk = result.risk_assessment
print(f'Risk Level: {risk.overall_risk}')
print(f'Factors: {len(risk.factors)}')
for factor in risk.factors[:3]:
    print(f'  - {factor}')
print(f'Recommendation: {risk.recommendation[:100]}...')

print()
print('=== TAMPERING INDICATORS ===')
print(f'Total indicators: {len(result.tampering_indicators)}')
for ind in result.tampering_indicators[:5]:  # Show first 5
    desc = ind.description[:80] if ind.description else "N/A"
    print(f'  [{ind.confidence:.0%}] {ind.indicator_type.value}: {desc}...')

print()
print('=== SUMMARY ===')
print(f'This file was created by: {result.structure_analysis.get("tool_detection", {}).get("detected_tool", "Unknown")}')
print(f'Standard structure: {result.structure_analysis.get("structure_type") == "standard"}')
print(f'Timestamps available: {result.metadata.created_date is not None or result.metadata.modified_date is not None}')
