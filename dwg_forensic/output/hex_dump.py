"""
DWG Forensic Tool - Hex Dump Formatter

Provides hex dump formatting for forensic evidence documentation.
Supports various output formats including plain text and formatted tables.
"""

from pathlib import Path
from typing import Optional, Union, List


class HexDumpFormatter:
    """
    Formats binary data as hex dumps for forensic documentation.

    Supports:
    - Standard hex dump with ASCII representation
    - Offset highlighting for specific bytes
    - Configurable bytes per line
    - Address offset display
    """

    def __init__(
        self,
        bytes_per_line: int = 16,
        show_ascii: bool = True,
        show_offset: bool = True,
        uppercase: bool = True,
    ):
        """
        Initialize the hex dump formatter.

        Args:
            bytes_per_line: Number of bytes per line (default: 16)
            show_ascii: Show ASCII representation (default: True)
            show_offset: Show byte offset (default: True)
            uppercase: Use uppercase hex (default: True)
        """
        self.bytes_per_line = bytes_per_line
        self.show_ascii = show_ascii
        self.show_offset = show_offset
        self.uppercase = uppercase

    def format_bytes(self, data: bytes, start_offset: int = 0) -> str:
        """
        Format bytes as a hex dump string.

        Args:
            data: Binary data to format
            start_offset: Starting offset for display (default: 0)

        Returns:
            Formatted hex dump string
        """
        if not data:
            return "(empty)"

        lines = []
        hex_format = "{:02X}" if self.uppercase else "{:02x}"

        for i in range(0, len(data), self.bytes_per_line):
            chunk = data[i:i + self.bytes_per_line]

            # Build the line
            parts = []

            # Offset
            if self.show_offset:
                offset = start_offset + i
                parts.append(f"{offset:08X}:")

            # Hex values
            hex_values = " ".join(hex_format.format(b) for b in chunk)
            # Pad to full line width
            padding = (self.bytes_per_line - len(chunk)) * 3
            hex_values += " " * padding
            parts.append(hex_values)

            # ASCII representation
            if self.show_ascii:
                ascii_repr = "".join(
                    chr(b) if 32 <= b < 127 else "."
                    for b in chunk
                )
                parts.append(f"|{ascii_repr}|")

            lines.append("  ".join(parts))

        return "\n".join(lines)

    def format_file_region(
        self,
        file_path: Union[str, Path],
        offset: int,
        length: int,
    ) -> str:
        """
        Format a region of a file as hex dump.

        Args:
            file_path: Path to the file
            offset: Byte offset to start reading
            length: Number of bytes to read

        Returns:
            Formatted hex dump string
        """
        file_path = Path(file_path)

        with open(file_path, "rb") as f:
            f.seek(offset)
            data = f.read(length)

        return self.format_bytes(data, start_offset=offset)

    def format_with_highlight(
        self,
        data: bytes,
        highlight_offsets: List[int],
        start_offset: int = 0,
    ) -> str:
        """
        Format hex dump with highlighted bytes marked.

        Args:
            data: Binary data to format
            highlight_offsets: List of offsets to highlight (relative to data)
            start_offset: Starting offset for display

        Returns:
            Formatted hex dump with markers for highlighted bytes
        """
        if not data:
            return "(empty)"

        lines = []
        hex_format = "{:02X}" if self.uppercase else "{:02x}"
        highlight_set = set(highlight_offsets)

        for i in range(0, len(data), self.bytes_per_line):
            chunk = data[i:i + self.bytes_per_line]

            parts = []

            # Offset
            if self.show_offset:
                offset = start_offset + i
                parts.append(f"{offset:08X}:")

            # Hex values with highlighting
            hex_parts = []
            for j, b in enumerate(chunk):
                if i + j in highlight_set:
                    hex_parts.append(f"[{hex_format.format(b)}]")
                else:
                    hex_parts.append(f" {hex_format.format(b)} ")
            hex_values = "".join(hex_parts)
            # Pad to full line width
            padding = (self.bytes_per_line - len(chunk)) * 4
            hex_values += " " * padding
            parts.append(hex_values)

            # ASCII representation
            if self.show_ascii:
                ascii_repr = "".join(
                    chr(b) if 32 <= b < 127 else "."
                    for b in chunk
                )
                parts.append(f"|{ascii_repr}|")

            lines.append(" ".join(parts))

        return "\n".join(lines)


def format_hex_dump(
    data: bytes,
    start_offset: int = 0,
    bytes_per_line: int = 16,
    show_ascii: bool = True,
) -> str:
    """
    Convenience function to format a hex dump.

    Args:
        data: Binary data to format
        start_offset: Starting offset for display
        bytes_per_line: Number of bytes per line
        show_ascii: Show ASCII representation

    Returns:
        Formatted hex dump string
    """
    formatter = HexDumpFormatter(bytes_per_line=bytes_per_line, show_ascii=show_ascii)
    return formatter.format_bytes(data, start_offset)


def extract_and_format(
    file_path: Union[str, Path],
    offset: int,
    length: int,
    context_bytes: int = 0,
) -> str:
    """
    Extract a region from a file and format as hex dump with optional context.

    Args:
        file_path: Path to the file
        offset: Byte offset of interest
        length: Number of bytes to highlight
        context_bytes: Additional context bytes before/after (default: 0)

    Returns:
        Formatted hex dump with the region of interest
    """
    file_path = Path(file_path)

    # Calculate actual read range with context
    actual_offset = max(0, offset - context_bytes)
    actual_length = length + (offset - actual_offset) + context_bytes

    formatter = HexDumpFormatter()
    result = formatter.format_file_region(file_path, actual_offset, actual_length)

    if context_bytes > 0:
        result = f"[Region at offset 0x{offset:X}, length {length} bytes]\n\n{result}"

    return result
