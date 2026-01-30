"""
Revit OLE2 Structure Inspector

Deep inspection of Revit RVT OLE2 compound document structure to identify
where metadata is stored.

Usage:
    python revit_ole2_inspector.py <path_to_rvt_file>
"""

import sys
from pathlib import Path

try:
    import olefile
except ImportError:
    print("[ERROR] olefile library not found. Install with: pip install olefile")
    sys.exit(1)


def inspect_rvt_file(file_path: str):
    """Inspect OLE2 structure of an RVT file."""
    file_path = Path(file_path).resolve()

    if not file_path.exists():
        print(f"[ERROR] File not found: {file_path}")
        return

    print(f"[INFO] Inspecting: {file_path.name}")
    print(f"[INFO] File size: {file_path.stat().st_size / (1024*1024):.2f} MB")
    print("=" * 80)

    try:
        if not olefile.isOleFile(str(file_path)):
            print("[ERROR] Not a valid OLE2 compound document")
            return

        with olefile.OleFileIO(str(file_path)) as ole:
            print("\n[OK] Valid OLE2 compound document")
            print("\nAvailable streams:")
            print("-" * 80)

            # List all streams
            stream_list = ole.listdir()

            for stream_path in sorted(stream_list):
                stream_name = "/".join(stream_path)

                try:
                    stream_size = ole.get_size(stream_path)
                    print(f"  - {stream_name} ({stream_size:,} bytes)")
                except Exception as e:
                    print(f"  - {stream_name} (error reading size: {e})")

            print("\n" + "=" * 80)

            # Inspect BasicFileInfo stream
            if ole.exists("BasicFileInfo"):
                print("\n[INFO] Inspecting BasicFileInfo stream:")
                print("-" * 80)

                stream_data = ole.openstream("BasicFileInfo").read()
                print(f"Size: {len(stream_data)} bytes")

                # Try UTF-16LE decoding
                print("\n[UTF-16LE decoded (first 2000 chars)]:")
                try:
                    text_utf16 = stream_data.decode('utf-16le', errors='ignore')
                    print(text_utf16[:2000])
                except Exception as e:
                    print(f"Error decoding: {e}")

                # Show hex dump of first 512 bytes
                print("\n[Hex dump (first 512 bytes)]:")
                hex_dump = stream_data[:512].hex()
                for i in range(0, min(len(hex_dump), 512), 64):
                    print(f"  {i//2:04x}: {hex_dump[i:i+64]}")

                # Search for version strings
                print("\n[Searching for version patterns]:")

                # Try both UTF-16LE and Latin-1
                for encoding in ['utf-16le', 'latin-1', 'utf-8']:
                    try:
                        decoded = stream_data.decode(encoding, errors='ignore')

                        # Search for Revit version
                        import re

                        revit_matches = re.findall(r'Revit\s+\d{4}', decoded, re.IGNORECASE)
                        if revit_matches:
                            print(f"  [{encoding}] Found Revit versions: {revit_matches[:5]}")

                        build_matches = re.findall(r'Build[:\s]+[\w_\.]+', decoded, re.IGNORECASE)
                        if build_matches:
                            print(f"  [{encoding}] Found build strings: {build_matches[:5]}")

                        # Search for timestamps
                        timestamp_matches = re.findall(
                            r'\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}',
                            decoded
                        )
                        if timestamp_matches:
                            print(f"  [{encoding}] Found timestamps: {timestamp_matches[:5]}")

                    except Exception as e:
                        print(f"  [{encoding}] Decoding error: {e}")

            else:
                print("\n[WARN] BasicFileInfo stream not found")

            # Check for other metadata streams
            print("\n" + "=" * 80)
            print("[INFO] Checking for other metadata streams:")
            print("-" * 80)

            metadata_streams = [
                "RevitFileList",
                "RevitPreview",
                "RevitMetaData",
                "FileInfo",
                "DocumentSummaryInformation",
                "SummaryInformation",
            ]

            for stream_name in metadata_streams:
                if ole.exists(stream_name):
                    try:
                        stream_data = ole.openstream(stream_name).read()
                        print(f"  [FOUND] {stream_name} ({len(stream_data)} bytes)")

                        # Try to decode first 500 bytes
                        for encoding in ['utf-16le', 'latin-1']:
                            try:
                                decoded = stream_data[:500].decode(encoding, errors='ignore')
                                if any(c.isprintable() for c in decoded[:100]):
                                    print(f"    [{encoding}] Sample: {decoded[:200]}")
                                    break
                            except:
                                pass
                    except Exception as e:
                        print(f"  [ERROR] {stream_name}: {e}")

    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python revit_ole2_inspector.py <path_to_rvt_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    inspect_rvt_file(file_path)


if __name__ == "__main__":
    main()
