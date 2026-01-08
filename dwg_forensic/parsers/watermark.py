"""TrustedDWG watermark detection for DWG files.

This module detects and analyzes Autodesk TrustedDWG watermarks embedded in DWG files.
TrustedDWG watermarks indicate that a file was created or last modified by genuine
Autodesk software (AutoCAD or Autodesk-licensed applications).

TrustedDWG was introduced in AutoCAD 2007 (AC1021). Earlier versions do not have
this watermark feature.
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

    Note: TrustedDWG was introduced in AutoCAD 2007 (AC1021). Earlier versions
    (AC1018 and before) do not support this feature.
    """

    # Watermark marker bytes that identify the start of a TrustedDWG watermark
    WATERMARK_MARKER = b"Autodesk DWG"

    # Full watermark prefix for verification
    FULL_WATERMARK_PREFIX = b"Autodesk DWG. This file is a Trusted DWG"

    # Versions that support TrustedDWG (AC1021/AutoCAD 2007 and later)
    WATERMARK_SUPPORTED_VERSIONS = ["AC1021", "AC1024", "AC1027", "AC1032"]

    # Versions that do NOT support TrustedDWG
    NO_WATERMARK_VERSIONS = ["AC1012", "AC1014", "AC1015", "AC1018"]

    # Known AutoCAD application identifiers and their versions
    KNOWN_APPLICATION_IDS = {
        "ACAD0001427": "AutoCAD 2024",
        "ACAD0002101": "AutoCAD 2023",
        "ACAD0002051": "AutoCAD 2022",
        "ACAD0002001": "AutoCAD 2021",
        "ACAD0001951": "AutoCAD 2020",
        "ACAD0001901": "AutoCAD 2019",
        "ACAD0001851": "AutoCAD 2018",
        "ACAD0001801": "AutoCAD 2017",
        "ACAD0001751": "AutoCAD 2016",
        "ACAD0001701": "AutoCAD 2015",
        "ACAD0001651": "AutoCAD 2014",
        "ACAD0001601": "AutoCAD 2013",
        "ACAD0001551": "AutoCAD 2012",
        "ACAD0001501": "AutoCAD 2011",
        "ACAD0001451": "AutoCAD 2010",
        "ACAD0001401": "AutoCAD 2009",
        "ACAD0001351": "AutoCAD 2008",
        "ACAD0001301": "AutoCAD 2007",
    }

    def has_watermark_support(self, version_string: str) -> bool:
        """Check if a version supports TrustedDWG watermarks.

        Args:
            version_string: DWG version string (e.g., 'AC1032').

        Returns:
            True if version supports TrustedDWG watermarks.
        """
        return version_string in self.WATERMARK_SUPPORTED_VERSIONS

    def detect(
        self, file_path: Path, version_string: Optional[str] = None
    ) -> TrustedDWGAnalysis:
        """Detect and analyze TrustedDWG watermark in a DWG file.

        Args:
            file_path: Path to the DWG file to analyze.
            version_string: DWG version string (e.g., 'AC1032'). If None,
                           will be detected from the file.

        Returns:
            TrustedDWGAnalysis object containing watermark detection results.
            For versions that don't support TrustedDWG (pre-2007), returns
            a result indicating the feature is not applicable.

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

        # Detect version if not provided
        if version_string is None:
            version_string = self._detect_version(data)

        # Check if version supports TrustedDWG watermarks
        if version_string and not self.has_watermark_support(version_string):
            # Return "not applicable" result for older versions
            return TrustedDWGAnalysis(
                watermark_present=False,
                watermark_text="N/A - TrustedDWG not available for this version",
                watermark_valid=True,  # Not a failure, just not applicable
                application_origin=None,
                watermark_offset=None,
            )

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

    def _detect_version(self, data: bytes) -> Optional[str]:
        """Detect DWG version from file data.

        Args:
            data: Complete file contents as bytes.

        Returns:
            Version string (e.g., 'AC1032'), or None if detection fails.
        """
        if len(data) < 6:
            return None

        try:
            version_bytes = data[0:6]
            version_string = version_bytes.decode("ascii").rstrip("\x00")
            if version_string.startswith("AC"):
                return version_string
            return None
        except UnicodeDecodeError:
            return None
