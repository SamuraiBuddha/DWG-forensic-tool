"""Tests for JSON export functionality."""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import BaseModel

from dwg_forensic.models import (
    CRCValidation,
    FileInfo,
    ForensicAnalysis,
    HeaderAnalysis,
    RiskAssessment,
    RiskLevel,
)
from dwg_forensic.output.json_export import (
    ForensicJSONEncoder,
    JSONExporter,
    export_to_json,
)


@pytest.fixture
def sample_analysis():
    """Create a sample ForensicAnalysis for testing."""
    return ForensicAnalysis(
        file_info=FileInfo(
            filename="test.dwg",
            sha256="a" * 64,
            file_size_bytes=1024,
            intake_timestamp=datetime(2025, 1, 6, 12, 0, 0),
        ),
        header_analysis=HeaderAnalysis(
            version_string="AC1032",
            version_name="AutoCAD 2018+",
            maintenance_version=3,
            preview_address=0x1000,
            codepage=30,
            is_supported=True,
        ),
        crc_validation=CRCValidation(
            header_crc_stored="0x12345678",
            header_crc_calculated="0x12345678",
            is_valid=True,
        ),
        risk_assessment=RiskAssessment(
            overall_risk=RiskLevel.LOW,
            factors=["CRC valid"],
            recommendation="File appears authentic",
        ),
        analyzer_version="0.1.0",
    )


class TestForensicJSONEncoder:
    """Tests for ForensicJSONEncoder."""

    def test_encode_datetime(self):
        """Test encoding datetime objects."""
        dt = datetime(2025, 1, 6, 12, 0, 0)
        result = json.dumps({"time": dt}, cls=ForensicJSONEncoder)
        assert "2025-01-06" in result

    def test_encode_path(self):
        """Test encoding Path objects."""
        path = Path("/some/path")
        result = json.dumps({"path": path}, cls=ForensicJSONEncoder)
        assert "some" in result
        assert "path" in result

    def test_encode_enum(self):
        """Test encoding Enum values."""
        result = json.dumps({"level": RiskLevel.HIGH}, cls=ForensicJSONEncoder)
        assert "HIGH" in result

    def test_encode_uuid(self):
        """Test encoding UUID objects."""
        test_uuid = UUID("12345678-1234-5678-1234-567812345678")
        result = json.dumps({"id": test_uuid}, cls=ForensicJSONEncoder)
        assert "12345678-1234-5678-1234-567812345678" in result

    def test_encode_pydantic_model(self):
        """Test encoding Pydantic models with model_dump."""
        class SimpleModel(BaseModel):
            name: str
            value: int

        model = SimpleModel(name="test", value=42)
        result = json.dumps({"model": model}, cls=ForensicJSONEncoder)
        parsed = json.loads(result)
        assert parsed["model"]["name"] == "test"
        assert parsed["model"]["value"] == 42

    def test_encode_unsupported_type_raises(self):
        """Test encoding unsupported type raises TypeError."""
        class CustomObject:
            pass

        with pytest.raises(TypeError):
            json.dumps({"obj": CustomObject()}, cls=ForensicJSONEncoder)


class TestJSONExporter:
    """Tests for JSONExporter class."""

    def test_to_dict(self, sample_analysis):
        """Test conversion to dictionary."""
        exporter = JSONExporter()
        result = exporter.to_dict(sample_analysis)

        assert isinstance(result, dict)
        assert "file_info" in result
        assert "header_analysis" in result
        assert "crc_validation" in result
        assert "risk_assessment" in result

    def test_to_json(self, sample_analysis):
        """Test conversion to JSON string."""
        exporter = JSONExporter()
        result = exporter.to_json(sample_analysis)

        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed["file_info"]["filename"] == "test.dwg"

    def test_to_json_indent(self, sample_analysis):
        """Test JSON indentation."""
        exporter = JSONExporter(indent=4)
        result = exporter.to_json(sample_analysis)
        # With indent, there should be newlines
        assert "\n" in result

    def test_to_file(self, sample_analysis):
        """Test saving to file."""
        exporter = JSONExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "output.json"
            exporter.to_file(sample_analysis, output_path)

            assert output_path.exists()
            content = output_path.read_text()
            parsed = json.loads(content)
            assert parsed["file_info"]["filename"] == "test.dwg"

    def test_to_file_creates_parent_dirs(self, sample_analysis):
        """Test that to_file creates parent directories."""
        exporter = JSONExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "subdir" / "output.json"
            exporter.to_file(sample_analysis, output_path)
            assert output_path.exists()


class TestExportToJson:
    """Tests for export_to_json convenience function."""

    def test_export_returns_string(self, sample_analysis):
        """Test that export returns JSON string."""
        result = export_to_json(sample_analysis)
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert "file_info" in parsed

    def test_export_with_output_path(self, sample_analysis):
        """Test export with output path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "export.json"
            result = export_to_json(sample_analysis, output_path)

            assert isinstance(result, str)
            assert output_path.exists()
