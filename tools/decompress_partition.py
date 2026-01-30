"""
Decompress and analyze Revit partition data
Handles gzip-compressed partition streams
"""

import gzip
import io
import re
import sys
from pathlib import Path

try:
    import olefile
except ImportError:
    print("[ERROR] olefile library required: pip install olefile")
    sys.exit(1)


def extract_and_decompress_partition(rvt_file: str, partition_id: str, output_dir: str):
    """Extract partition data, attempt decompression, and search for keywords."""

    rvt_path = Path(rvt_file)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"[INFO] Opening RVT file: {rvt_path.name}")

    with olefile.OleFileIO(str(rvt_path)) as ole:
        # Find partition
        target_stream = None
        stream_list = ole.listdir()

        for stream_path_list in stream_list:
            stream_path = "/".join(stream_path_list)
            match = re.search(r'Partition[s]?[/_\s]?(\d+)', stream_path, re.IGNORECASE)

            if match and match.group(1) == partition_id:
                target_stream = stream_path_list
                break

        if not target_stream:
            print(f"[ERROR] Partition {partition_id} not found")
            return

        print(f"[OK] Found partition: {'/'.join(target_stream)}")

        # Read raw data
        raw_data = ole.openstream(target_stream).read()
        print(f"[OK] Raw size: {len(raw_data):,} bytes ({len(raw_data) / 1024:.2f} KB)")

        # Check for gzip magic header (1f 8b)
        if raw_data[:2] == b'\x1f\x8b':
            print("[INFO] Detected gzip compression - decompressing...")

            try:
                # Skip the header (first 31 bytes appear to be metadata)
                gzip_start = raw_data.find(b'\x1f\x8b')

                if gzip_start != -1:
                    gzip_data = raw_data[gzip_start:]

                    # Decompress
                    decompressed = gzip.decompress(gzip_data)
                    print(f"[OK] Decompressed size: {len(decompressed):,} bytes ({len(decompressed) / 1024:.2f} KB)")

                    # Save decompressed data
                    decompressed_file = output_path / f"partition_{partition_id}_decompressed.bin"
                    with open(decompressed_file, 'wb') as f:
                        f.write(decompressed)
                    print(f"[OK] Saved decompressed binary to: {decompressed_file}")

                    # Analyze decompressed data
                    analyze_data(decompressed, partition_id, output_path)

            except Exception as e:
                print(f"[WARN] Decompression failed: {e}")
                print("[INFO] Analyzing raw data instead...")
                analyze_data(raw_data, partition_id, output_path)
        else:
            print("[INFO] No gzip compression detected - analyzing raw data...")
            analyze_data(raw_data, partition_id, output_path)


def analyze_data(data: bytes, partition_id: str, output_path: Path):
    """Analyze binary data for keywords and patterns."""

    # Keywords to search
    keywords = [
        # Amenity-related
        b'pool', b'Pool', b'POOL',
        b'cabana', b'Cabana', b'CABANA',
        b'kitchen', b'Kitchen', b'KITCHEN',
        b'spa', b'Spa', b'SPA',
        b'amenity', b'Amenity', b'AMENITY',
        b'outdoor', b'Outdoor', b'OUTDOOR',
        b'patio', b'Patio', b'PATIO',
        b'BBQ', b'bbq', b'Bbq',
        b'grill', b'Grill', b'GRILL',

        # Construction elements
        b'wall', b'Wall', b'WALL',
        b'ceiling', b'Ceiling', b'CEILING',
        b'floor', b'Floor', b'FLOOR',
        b'door', b'Door', b'DOOR',
        b'window', b'Window', b'WINDOW',
        b'roof', b'Roof', b'ROOF',

        # Family-related
        b'Family', b'family', b'FAMILY',
        b'Type', b'type', b'TYPE',
        b'Level', b'level', b'LEVEL',
    ]

    # Search for keywords
    findings = {}

    for keyword in keywords:
        offsets = []
        offset = 0

        while True:
            index = data.find(keyword, offset)
            if index == -1:
                break

            offsets.append(index)

            # Extract context (50 bytes before/after)
            context_start = max(0, index - 50)
            context_end = min(len(data), index + len(keyword) + 50)
            context = data[context_start:context_end]

            offset = index + 1

        if offsets:
            findings[keyword.decode('latin-1')] = offsets

    # Report findings
    print("\n" + "=" * 80)
    print(f"KEYWORD ANALYSIS - Partition {partition_id}")
    print("=" * 80)

    if findings:
        for keyword, offsets in sorted(findings.items()):
            print(f"  [{len(offsets)}] '{keyword}' found at {len(offsets)} location(s)")

            # Show first 3 occurrences with context
            for i, offset in enumerate(offsets[:3]):
                context_start = max(0, offset - 30)
                context_end = min(len(data), offset + len(keyword) + 30)
                context = data[context_start:context_end]

                # Try to decode as ASCII/Latin-1
                try:
                    context_str = context.decode('latin-1', errors='replace')
                    # Clean non-printable chars
                    context_str = ''.join(c if 32 <= ord(c) < 127 else '.' for c in context_str)
                    print(f"      [{i+1}] Offset 0x{offset:08x}: ...{context_str}...")
                except:
                    pass

        # Save detailed findings
        findings_file = output_path / f"partition_{partition_id}_keyword_findings.txt"
        with open(findings_file, 'w', encoding='utf-8') as f:
            f.write(f"Keyword Analysis - Partition {partition_id}\n")
            f.write("=" * 80 + "\n\n")

            for keyword, offsets in sorted(findings.items()):
                f.write(f"Keyword: '{keyword}'\n")
                f.write(f"Occurrences: {len(offsets)}\n")
                f.write("-" * 80 + "\n")

                for offset in offsets[:20]:  # First 20 occurrences
                    context_start = max(0, offset - 100)
                    context_end = min(len(data), offset + len(keyword) + 100)
                    context = data[context_start:context_end]

                    try:
                        context_str = context.decode('latin-1', errors='replace')
                        f.write(f"  Offset 0x{offset:08x}:\n")
                        f.write(f"    {context_str}\n\n")
                    except:
                        pass

                f.write("\n")

        print(f"\n[OK] Detailed findings saved to: {findings_file}")

    else:
        print("  [INFO] No keywords found")

    # Generate hex dump of first 100KB
    hex_file = output_path / f"partition_{partition_id}_decompressed_hex.txt"
    with open(hex_file, 'w', encoding='utf-8') as f:
        f.write(f"Hex Dump - Partition {partition_id} (Decompressed)\n")
        f.write(f"Total Size: {len(data):,} bytes\n")
        f.write("=" * 80 + "\n\n")

        for offset in range(0, min(len(data), 102400), 16):  # First 100KB
            hex_chunk = data[offset:offset+16].hex()
            hex_formatted = " ".join(hex_chunk[i:i+2] for i in range(0, len(hex_chunk), 2))

            ascii_repr = "".join(
                chr(b) if 32 <= b < 127 else "."
                for b in data[offset:offset+16]
            )

            f.write(f"{offset:08x}: {hex_formatted:<48}  {ascii_repr}\n")

    print(f"[OK] Hex dump saved to: {hex_file}")

    # Try to extract text strings (sequences of printable ASCII >= 4 chars)
    strings_file = output_path / f"partition_{partition_id}_strings.txt"

    min_string_len = 4
    strings = []
    current_string = []

    for byte in data:
        if 32 <= byte < 127:  # Printable ASCII
            current_string.append(chr(byte))
        else:
            if len(current_string) >= min_string_len:
                strings.append(''.join(current_string))
            current_string = []

    # Final string
    if len(current_string) >= min_string_len:
        strings.append(''.join(current_string))

    print(f"[INFO] Extracted {len(strings)} text strings (>={min_string_len} chars)")

    # Save unique strings
    unique_strings = sorted(set(strings), key=lambda s: len(s), reverse=True)

    with open(strings_file, 'w', encoding='utf-8') as f:
        f.write(f"Extracted Strings - Partition {partition_id}\n")
        f.write(f"Total: {len(unique_strings)} unique strings\n")
        f.write("=" * 80 + "\n\n")

        for string in unique_strings[:1000]:  # Top 1000
            f.write(f"{string}\n")

    print(f"[OK] Strings saved to: {strings_file}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Decompress and analyze Revit partition")
    parser.add_argument("rvt_file", help="Path to RVT file")
    parser.add_argument("partition_id", help="Partition ID to analyze (e.g., 2158)")
    parser.add_argument("--output", "-o", default="./partition_decompress", help="Output directory")

    args = parser.parse_args()

    extract_and_decompress_partition(args.rvt_file, args.partition_id, args.output)
