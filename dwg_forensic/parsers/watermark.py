"""TrustedDWG watermark detection for DWG files.

This module detects and analyzes Autodesk TrustedDWG watermarks embedded in DWG files.
TrustedDWG watermarks indicate that a file was created or last modified by genuine
Autodesk software (AutoCAD or Autodesk-licensed applications).
"""

from pathlib import Path
from typing import Optional

from dwg_forensic.models import TrustedDWGAnalysis
from dwg_forensic.utils.exceptions import ParseError


class WatermarkDetector:
    """Detector for Autodesk TrustedDWG watermarks in DWG files.

    TrustedDWG watermarks are embedded by Autodesk applications to verify
    file authenticity. The presence of a valid watermark indicates the file
    was created or modified by genuine Autodesk software.
    """

    # Watermark marker bytes that identify the start of a TrustedDWG watermark
    WATERMARK_MARKER = b"Autodesk DWG"

    # Full watermark prefix for verification
    FULL_WATERMARK_PREFIX = b"Autodesk DWG. This file is a Trusted DWG"

    # Known AutoCAD application identifiers and their versions
    KNOWN_APPLICATION_IDS = {
        "ACAD0001427": "AutoCAD 2024",
        "ACAD0002101": "AutoCAD 2023",
        "ACAD0002051": "AutoCAD 2022",
        "ACAD0002001": "AutoCAD 2021",
        "ACAD0001951": "AutoCAD 2020",
        "ACAD0001901": "AutoCAD 2019",
        "ACAD0001851": "AutoCAD 2018",
    }

    def detect(self, file_path: Path) -> TrustedDWGAnalysis:
        """Detect and analyze TrustedDWG watermark in a DWG file.

        Args:
            file_path: Path to the DWG file to analyze

        Returns:
            TrustedDWGAnalysis object containing watermark detection results

        Raises:
            ParseError: If the file cannot be read or parsed
        """
        file_path = Path(file_path)

        try:
            # Read entire file into memory
            # DWG files are typically under 50MB, making this approach feasible
            with open(file_path, "rb") as f:
                data = f.read()
        except IOError as e:
            raise ParseError(f"Failed to read file {file_path}: {e}")

        # Search for watermark marker
        watermark_offset = self._find_watermark(data)

        if watermark_offset is None:
            # No watermark found - file was likely created by third-party software
            return TrustedDWGAnalysis(
                watermark_present=False,
                watermark_text=None,
                watermark_valid=False,
                application_origin=None,
                watermark_offset=None,
            )

        # Extract full watermark text
        watermark_text = self._extract_watermark_text(data, watermark_offset)

        # Verify watermark validity
        is_valid = watermark_text is not None and watermark_text.startswith(
            self.FULL_WATERMARK_PREFIX.decode("latin-1", errors="ignore")
        )

        # Extract application ID
        app_id = self._extract_application_id(data)
        app_origin = self.KNOWN_APPLICATION_IDS.get(app_id) if app_id else None

        return TrustedDWGAnalysis(
            watermark_present=True,
            watermark_text=watermark_text,
            watermark_valid=is_valid,
            application_origin=app_origin,
            watermark_offset=watermark_offset,
        )

    def _find_watermark(self, data: bytes) -> Optional[int]:
        """Search for watermark marker in file data.

        Args:
            data: Complete file contents as bytes

        Returns:
            Byte offset of watermark marker, or None if not found
        """
        try:
            offset = data.find(self.WATERMARK_MARKER)
            return offset if offset != -1 else None
        except Exception:
            return None

    def _extract_watermark_text(self, data: bytes, offset: int) -> Optional[str]:
        """Extract full watermark text starting from marker offset.

        The watermark text is typically null-terminated or ends at the next
        binary section. We extract up to 200 bytes to capture the full message.

        Args:
            data: Complete file contents as bytes
            offset: Starting offset of watermark marker

        Returns:
            Decoded watermark text, or None if extraction fails
        """
        try:
            # Extract up to 200 bytes from the watermark location
            # This should be sufficient for the full watermark message
            end_offset = min(offset + 200, len(data))
            watermark_bytes = data[offset:end_offset]

            # Find null terminator if present
            null_pos = watermark_bytes.find(b"\x00")
            if null_pos != -1:
                watermark_bytes = watermark_bytes[:null_pos]

            # Decode using latin-1 to handle any byte values
            # TrustedDWG watermarks are ASCII but latin-1 is more forgiving
            watermark_text = watermark_bytes.decode("latin-1", errors="ignore")

            # Clean up any trailing whitespace or control characters
            watermark_text = watermark_text.rstrip("\x00\r\n\t ")

            return watermark_text if watermark_text else None

        except Exception:
            return None

    def _extract_application_id(self, data: bytes) -> Optional[str]:
        """Extract AutoCAD application identifier from DWG file.

        The application ID is typically stored in the DWG header section
        and follows a pattern like "ACAD0001427". We search for known
        patterns in the file.

        Args:
            data: Complete file contents as bytes

        Returns:
            Application ID string, or None if not found
        """
        try:
            # Search for ACAD application ID pattern
            # Format is typically "ACAD" followed by 7 digits
            acad_marker = b"ACAD"
            offset = 0

            while True:
                offset = data.find(acad_marker, offset)
                if offset == -1:
                    break

                # Check if followed by 7 digits
                candidate_end = offset + 11  # "ACAD" + 7 chars
                if candidate_end <= len(data):
                    candidate = data[offset:candidate_end]
                    try:
                        app_id = candidate.decode("ascii")
                        # Verify it matches expected pattern: ACAD + 7 digits
                        if len(app_id) == 11 and app_id[4:].isdigit():
                            return app_id
                    except UnicodeDecodeError:
                        pass

                offset += 1

            return None

        except Exception:
            return None
