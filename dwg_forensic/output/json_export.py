"""JSON export functionality for forensic analysis results.

This module provides JSON serialization for forensic analysis results,
handling Pydantic models, datetime objects, paths, UUIDs, and enums.
"""

import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Union
from uuid import UUID

from dwg_forensic.models import ForensicAnalysis


class ForensicJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for forensic analysis data types.

    Handles serialization of:
    - datetime objects (ISO 8601 format)
    - UUID objects (string representation)
    - Path objects (string representation)
    - Enum values (value extraction)
    - Pydantic models (dict conversion)
    """

    def default(self, obj: Any) -> Any:
        """Convert non-standard objects to JSON-serializable types.

        Args:
            obj: Object to serialize

        Returns:
            JSON-serializable representation of the object
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, Path):
            return str(obj)
        if isinstance(obj, Enum):
            return obj.value
        if hasattr(obj, "model_dump"):
            # Pydantic v2 models
            return obj.model_dump()
        if hasattr(obj, "dict"):
            # Pydantic v1 models (fallback)
            return obj.dict()
        return super().default(obj)


class JSONExporter:
    """Exporter for forensic analysis results to JSON format.

    Provides methods to convert ForensicAnalysis models to JSON strings
    or save them directly to files.
    """

    def __init__(self, indent: int = 2, sort_keys: bool = False):
        """Initialize the JSON exporter.

        Args:
            indent: Number of spaces for indentation (default: 2)
            sort_keys: Whether to sort keys alphabetically (default: False)
        """
        self.indent = indent
        self.sort_keys = sort_keys

    def to_dict(self, analysis: ForensicAnalysis) -> dict:
        """Convert ForensicAnalysis to a dictionary.

        Args:
            analysis: ForensicAnalysis model to convert

        Returns:
            Dictionary representation of the analysis
        """
        return analysis.model_dump()

    def to_json(self, analysis: ForensicAnalysis) -> str:
        """Convert ForensicAnalysis to a JSON string.

        Args:
            analysis: ForensicAnalysis model to convert

        Returns:
            JSON string representation of the analysis
        """
        return json.dumps(
            self.to_dict(analysis),
            cls=ForensicJSONEncoder,
            indent=self.indent,
            sort_keys=self.sort_keys,
        )

    def to_file(
        self,
        analysis: ForensicAnalysis,
        file_path: Union[str, Path],
        encoding: str = "utf-8",
    ) -> None:
        """Save ForensicAnalysis to a JSON file.

        Args:
            analysis: ForensicAnalysis model to save
            file_path: Path to the output file
            encoding: File encoding (default: utf-8)
        """
        file_path = Path(file_path)

        # Create parent directories if they don't exist
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, "w", encoding=encoding) as f:
            f.write(self.to_json(analysis))


def export_to_json(
    analysis: ForensicAnalysis,
    output_path: Optional[Union[str, Path]] = None,
    indent: int = 2,
) -> str:
    """Convenience function to export forensic analysis to JSON.

    Args:
        analysis: ForensicAnalysis model to export
        output_path: Optional path to save JSON file
        indent: Number of spaces for indentation (default: 2)

    Returns:
        JSON string representation of the analysis
    """
    exporter = JSONExporter(indent=indent)
    json_str = exporter.to_json(analysis)

    if output_path:
        exporter.to_file(analysis, output_path)

    return json_str
