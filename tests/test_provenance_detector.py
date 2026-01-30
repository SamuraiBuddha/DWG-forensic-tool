"""
Tests for DWG file provenance detection.

This test suite validates the ProvenanceDetector module's ability to identify
file origin and creation context before tampering analysis, preventing false positives
for legitimate file characteristics.

Test Coverage:
- Revit export detection (FINGERPRINTGUID "30314341-", Preview=0x120)
- ODA SDK tool detection (BricsCAD, NanoCAD, DraftSight)
- File transfer detection (NTFS created > modified pattern)
- Native AutoCAD detection (default fallback)
- Confidence scoring accuracy
- rules_to_skip correctness for each provenance type
- Integration with analyzer.py workflow
- Rule engine skip_rules functionality
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

from dwg_forensic.analysis.provenance_detector import (
    ProvenanceDetector,
    FileProvenance,
    detect_provenance,
)
from dwg_forensic.parsers.revit_detection import RevitDetectionResult, RevitExportType, RevitSignature
from dwg_forensic.analysis.cad_fingerprinting import FingerprintResult, CADApplication


class TestFileProvenance:
    """Test FileProvenance dataclass."""

    def test_default_initialization(self):
        """Test FileProvenance with default values."""
        provenance = FileProvenance()

        assert provenance.source_application == "Unknown"
        assert provenance.is_export is False
        assert provenance.is_transferred is False
        assert provenance.confidence == 0.0
        assert provenance.rules_to_skip == []
        assert provenance.detection_notes == []
        assert provenance.is_revit_export is False
        assert provenance.is_oda_tool is False
        assert provenance.is_native_autocad is False

    def test_custom_initialization(self):
        """Test FileProvenance with custom values."""
        provenance = FileProvenance(
            source_application="Revit",
            is_export=True,
            confidence=0.95,
            rules_to_skip=["TAMPER-001", "TAMPER-002"],
            detection_notes=["Revit export detected"],
            is_revit_export=True,
        )

        assert provenance.source_application == "Revit"
        assert provenance.is_export is True
        assert provenance.confidence == 0.95
        assert provenance.rules_to_skip == ["TAMPER-001", "TAMPER-002"]
        assert provenance.detection_notes == ["Revit export detected"]
        assert provenance.is_revit_export is True


class TestProvenanceDetector:
    """Test ProvenanceDetector class."""

    @pytest.fixture
    def detector(self):
        """Create a ProvenanceDetector instance."""
        return ProvenanceDetector()

    @pytest.fixture
    def mock_revit_file(self, tmp_path):
        """Create a mock Revit DWG file."""
        file_path = tmp_path / "revit_export.dwg"
        # Create minimal DWG header with Revit signature
        header = b"AC1032" + b"\x00" * 7  # Version string
        header += b"\x20\x01\x00\x00"  # Preview Address = 0x120 (Revit signature)
        header += b"\x00" * 100
        header += b"30314341-1234-5678-90AB-CDEF01234567"  # Revit GUID pattern
        file_path.write_bytes(header)
        return file_path

    @pytest.fixture
    def mock_autocad_file(self, tmp_path):
        """Create a mock native AutoCAD DWG file."""
        file_path = tmp_path / "autocad_native.dwg"
        # Create minimal DWG header without Revit signatures
        header = b"AC1032" + b"\x00" * 7  # Version string
        header += b"\xC0\x01\x00\x00"  # Preview Address = 0x1C0 (AutoCAD signature)
        header += b"\x00" * 100
        file_path.write_bytes(header)
        return file_path

    def test_revit_export_detection(self, detector, mock_revit_file):
        """Test detection of Revit export."""
        with patch('dwg_forensic.analysis.provenance_detector.RevitDetector') as MockRevitDetector:
            # Mock Revit detection result
            mock_revit_result = Mock()
            mock_revit_result.is_revit_export = True
            mock_revit_result.confidence_score = 0.93
            mock_revit_result.revit_version = "Revit 2023"

            mock_detector_instance = MockRevitDetector.return_value
            mock_detector_instance.detect.return_value = mock_revit_result

            provenance = detector.detect(mock_revit_file)

            # Verify Revit detection
            assert provenance.source_application == "Revit"
            assert provenance.is_export is True
            assert provenance.is_revit_export is True
            assert provenance.revit_confidence == pytest.approx(0.93, abs=0.001)
            assert provenance.confidence >= 0.9

            # Verify skip rules for Revit
            assert "TAMPER-001" in provenance.rules_to_skip  # CRC Header Mismatch
            assert "TAMPER-002" in provenance.rules_to_skip  # CRC Section Mismatch
            assert "TAMPER-003" in provenance.rules_to_skip  # TrustedDWG Missing
            assert "TAMPER-004" in provenance.rules_to_skip  # Watermark Missing

            # Verify detection notes
            assert any("Revit export detected" in note for note in provenance.detection_notes)
            assert any("CRC=0" in note for note in provenance.detection_notes)

    def test_oda_tool_detection(self, detector, mock_autocad_file):
        """Test detection of ODA SDK-based tool."""
        with patch('dwg_forensic.analysis.provenance_detector.CADFingerprinter') as MockFingerprinter:
            # Mock ODA tool fingerprint
            mock_fingerprint = Mock()
            mock_fingerprint.detected_application = CADApplication.BRICSCAD
            mock_fingerprint.confidence = 0.85
            mock_fingerprint.is_oda_based = True

            mock_fingerprinter_instance = MockFingerprinter.return_value
            mock_fingerprinter_instance.fingerprint.return_value = mock_fingerprint

            # Mock Revit detector to return negative result
            with patch('dwg_forensic.analysis.provenance_detector.RevitDetector') as MockRevitDetector:
                mock_revit_result = Mock()
                mock_revit_result.is_revit_export = False
                mock_revit_result.confidence_score = 0.1

                mock_revit_instance = MockRevitDetector.return_value
                mock_revit_instance.detect.return_value = mock_revit_result

                provenance = detector.detect(mock_autocad_file)

                # Verify ODA tool detection
                assert provenance.source_application == "bricscad"
                assert provenance.is_export is True
                assert provenance.is_oda_tool is True
                assert provenance.fingerprint_confidence == pytest.approx(0.85, abs=0.001)

                # Verify skip rules for ODA tools
                assert "TAMPER-001" in provenance.rules_to_skip  # CRC may be 0
                assert "TAMPER-003" in provenance.rules_to_skip  # TrustedDWG not applicable

                # Verify detection notes
                assert any("ODA SDK-based tool" in note for note in provenance.detection_notes)

    def test_file_transfer_detection(self, detector, mock_autocad_file):
        """Test detection of file transfer patterns."""
        with patch('dwg_forensic.analysis.provenance_detector.NTFSTimestampParser') as MockNTFSParser:
            # Mock NTFS timestamps showing file transfer (created > modified)
            now = datetime.now()
            mock_ntfs_data = Mock()
            mock_ntfs_data.si_timestamps = {
                "created": now,  # Newer (file was copied)
                "modified": now - timedelta(hours=2),  # Older (original modification time)
            }
            mock_ntfs_data.fn_timestamps = {
                "created": now - timedelta(hours=2),
            }

            mock_parser_instance = MockNTFSParser.return_value
            mock_parser_instance.parse.return_value = mock_ntfs_data

            # Mock other detectors to return negative results
            with patch('dwg_forensic.analysis.provenance_detector.RevitDetector') as MockRevitDetector:
                mock_revit_result = Mock()
                mock_revit_result.is_revit_export = False
                mock_revit_result.confidence_score = 0.0
                MockRevitDetector.return_value.detect.return_value = mock_revit_result

                with patch('dwg_forensic.analysis.provenance_detector.CADFingerprinter') as MockFingerprinter:
                    mock_fingerprint = Mock()
                    mock_fingerprint.confidence = 0.2  # Below threshold
                    MockFingerprinter.return_value.fingerprint.return_value = mock_fingerprint

                    provenance = detector.detect(mock_autocad_file)

                    # Verify file transfer detection
                    assert provenance.is_transferred is True
                    assert len(provenance.transfer_indicators) > 0
                    assert any("file copy" in indicator.lower() for indicator in provenance.transfer_indicators)

                    # Verify skip rules for file transfers
                    assert "TAMPER-019" in provenance.rules_to_skip  # NTFS Creation After Modification
                    assert "TAMPER-020" in provenance.rules_to_skip  # DWG-NTFS Creation Contradiction

                    # Verify detection notes
                    assert any("File transfer detected" in note for note in provenance.detection_notes)

    def test_native_autocad_detection(self, detector, mock_autocad_file):
        """Test detection of native AutoCAD file (default fallback)."""
        # Mock all detectors to return negative results
        with patch('dwg_forensic.analysis.provenance_detector.RevitDetector') as MockRevitDetector:
            mock_revit_result = Mock()
            mock_revit_result.is_revit_export = False
            mock_revit_result.confidence_score = 0.0
            MockRevitDetector.return_value.detect.return_value = mock_revit_result

            with patch('dwg_forensic.analysis.provenance_detector.CADFingerprinter') as MockFingerprinter:
                mock_fingerprint = Mock()
                mock_fingerprint.confidence = 0.1  # Below threshold
                MockFingerprinter.return_value.fingerprint.return_value = mock_fingerprint

                with patch('dwg_forensic.analysis.provenance_detector.NTFSTimestampParser') as MockNTFSParser:
                    MockNTFSParser.return_value.parse.return_value = None  # No NTFS data

                    with patch.object(detector, '_detect_native_autocad', return_value=True):
                        provenance = detector.detect(mock_autocad_file)

                        # Verify native AutoCAD detection
                        assert provenance.source_application == "AutoCAD"
                        assert provenance.is_native_autocad is True
                        assert provenance.confidence > 0.0

                        # Verify detection notes
                        assert any("native AutoCAD" in note for note in provenance.detection_notes)

    def test_confidence_calculation_revit(self, detector, mock_revit_file):
        """Test confidence score calculation for Revit export."""
        with patch('dwg_forensic.analysis.provenance_detector.RevitDetector') as MockRevitDetector:
            mock_revit_result = Mock()
            mock_revit_result.is_revit_export = True
            mock_revit_result.confidence_score = 0.95
            MockRevitDetector.return_value.detect.return_value = mock_revit_result

            provenance = detector.detect(mock_revit_file)

            # Revit confidence should be used directly
            assert provenance.confidence == pytest.approx(0.95, abs=0.001)

    def test_confidence_calculation_oda_tool(self, detector, mock_autocad_file):
        """Test confidence score calculation for ODA tool."""
        with patch('dwg_forensic.analysis.provenance_detector.RevitDetector') as MockRevitDetector:
            mock_revit_result = Mock()
            mock_revit_result.is_revit_export = False
            mock_revit_result.confidence_score = 0.0
            MockRevitDetector.return_value.detect.return_value = mock_revit_result

            with patch('dwg_forensic.analysis.provenance_detector.CADFingerprinter') as MockFingerprinter:
                mock_fingerprint = Mock()
                mock_fingerprint.detected_application = CADApplication.BRICSCAD
                mock_fingerprint.confidence = 0.80
                mock_fingerprint.is_oda_based = True
                MockFingerprinter.return_value.fingerprint.return_value = mock_fingerprint

                provenance = detector.detect(mock_autocad_file)

                # Fingerprint confidence should be used
                assert provenance.confidence == pytest.approx(0.80, abs=0.001)

    def test_confidence_calculation_file_transfer(self, detector, mock_autocad_file):
        """Test confidence score calculation for file transfer."""
        with patch('dwg_forensic.analysis.provenance_detector.RevitDetector') as MockRevitDetector:
            mock_revit_result = Mock()
            mock_revit_result.is_revit_export = False
            mock_revit_result.confidence_score = 0.0
            MockRevitDetector.return_value.detect.return_value = mock_revit_result

            with patch('dwg_forensic.analysis.provenance_detector.CADFingerprinter') as MockFingerprinter:
                mock_fingerprint = Mock()
                mock_fingerprint.confidence = 0.2  # Below threshold
                MockFingerprinter.return_value.fingerprint.return_value = mock_fingerprint

                with patch('dwg_forensic.analysis.provenance_detector.NTFSTimestampParser') as MockNTFSParser:
                    now = datetime.now()
                    mock_ntfs_data = Mock()
                    mock_ntfs_data.si_timestamps = {
                        "created": now,
                        "modified": now - timedelta(hours=1),
                    }
                    MockNTFSParser.return_value.parse.return_value = mock_ntfs_data

                    provenance = detector.detect(mock_autocad_file)

                    # File transfer confidence should be 0.85
                    assert provenance.confidence == pytest.approx(0.85, abs=0.001)

    def test_file_not_found_error(self, detector):
        """Test error handling for non-existent file."""
        non_existent_file = Path("/non/existent/file.dwg")

        with pytest.raises(FileNotFoundError):
            detector.detect(non_existent_file)

    def test_convenience_function(self, mock_revit_file):
        """Test detect_provenance convenience function."""
        with patch('dwg_forensic.analysis.provenance_detector.RevitDetector') as MockRevitDetector:
            mock_revit_result = Mock()
            mock_revit_result.is_revit_export = True
            mock_revit_result.confidence_score = 0.90
            MockRevitDetector.return_value.detect.return_value = mock_revit_result

            provenance = detect_provenance(mock_revit_file)

            assert isinstance(provenance, FileProvenance)
            assert provenance.is_revit_export is True


class TestProvenanceIntegration:
    """Test integration of provenance detection with analyzer and rule engine."""

    def test_provenance_in_analyzer_workflow(self, tmp_path):
        """Test that provenance detection is integrated into analyzer.py."""
        from dwg_forensic.core.analyzer import ForensicAnalyzer

        # Create a mock DWG file
        file_path = tmp_path / "test.dwg"
        header = b"AC1032" + b"\x00" * 200
        file_path.write_bytes(header)

        analyzer = ForensicAnalyzer()

        # Mock provenance detector
        with patch('dwg_forensic.core.analyzer.ProvenanceDetector') as MockProvenanceDetector:
            mock_provenance = FileProvenance(
                source_application="Revit",
                is_revit_export=True,
                confidence=0.95,
                rules_to_skip=["TAMPER-001", "TAMPER-002"],
                detection_notes=["Revit export detected"],
            )
            MockProvenanceDetector.return_value.detect.return_value = mock_provenance

            # Mock other components to avoid full analysis
            with patch.object(analyzer, '_parse_header'):
                with patch.object(analyzer, '_validate_crc'):
                    with patch.object(analyzer, '_detect_anomalies'):
                        with patch.object(analyzer, 'rule_engine') as mock_rule_engine:
                            mock_rule_engine.evaluate_all.return_value = []

                            # Run analysis
                            result = analyzer.analyze(file_path)

                            # Verify provenance was included
                            assert result.file_provenance is not None
                            assert result.file_provenance["source_application"] == "Revit"
                            assert result.file_provenance["is_revit_export"] is True
                            assert "TAMPER-001" in result.file_provenance["rules_to_skip"]

    def test_skip_rules_passed_to_engine(self, tmp_path):
        """Test that skip_rules are passed to rule engine."""
        from dwg_forensic.core.analyzer import ForensicAnalyzer

        file_path = tmp_path / "test.dwg"
        header = b"AC1032" + b"\x00" * 200
        file_path.write_bytes(header)

        analyzer = ForensicAnalyzer()

        # Mock provenance with skip rules
        with patch('dwg_forensic.core.analyzer.ProvenanceDetector') as MockProvenanceDetector:
            mock_provenance = FileProvenance(
                source_application="Revit",
                rules_to_skip=["TAMPER-001", "TAMPER-002", "TAMPER-003"],
            )
            MockProvenanceDetector.return_value.detect.return_value = mock_provenance

            with patch.object(analyzer, '_parse_header'):
                with patch.object(analyzer, '_validate_crc'):
                    with patch.object(analyzer, '_detect_anomalies'):
                        with patch.object(analyzer, 'rule_engine') as mock_rule_engine:
                            mock_rule_engine.evaluate_all.return_value = []

                            analyzer.analyze(file_path)

                            # Verify skip_rules were passed
                            mock_rule_engine.evaluate_all.assert_called_once()
                            call_args = mock_rule_engine.evaluate_all.call_args
                            assert "skip_rules" in call_args.kwargs
                            assert call_args.kwargs["skip_rules"] == ["TAMPER-001", "TAMPER-002", "TAMPER-003"]

    def test_rule_engine_skip_functionality(self):
        """Test that rule engine correctly skips rules."""
        from dwg_forensic.analysis.rules.engine import TamperingRuleEngine, RuleStatus

        engine = TamperingRuleEngine()

        # Create test context
        context = {
            "crc_validation": Mock(is_valid=False),
            "metadata": {},
            "ntfs_analysis": None,
        }

        # Evaluate with skip rules
        skip_rules = ["TAMPER-001", "TAMPER-002"]
        results = engine.evaluate_all(context, skip_rules=skip_rules)

        # Find skipped rules
        skipped_results = [r for r in results if r.rule_id in skip_rules]

        # Verify skipped rules have INCONCLUSIVE status
        for result in skipped_results:
            assert result.status == RuleStatus.INCONCLUSIVE
            assert "skipped" in result.description.lower()
            assert "provenance" in result.description.lower()

    def test_error_handling_in_provenance_detection(self, tmp_path):
        """Test error handling when provenance detection fails."""
        from dwg_forensic.core.analyzer import ForensicAnalyzer

        file_path = tmp_path / "test.dwg"
        header = b"AC1032" + b"\x00" * 200
        file_path.write_bytes(header)

        analyzer = ForensicAnalyzer()

        # Mock provenance detector to raise exception
        with patch('dwg_forensic.core.analyzer.ProvenanceDetector') as MockProvenanceDetector:
            MockProvenanceDetector.return_value.detect.side_effect = Exception("Test error")

            with patch.object(analyzer, '_parse_header'):
                with patch.object(analyzer, '_validate_crc'):
                    with patch.object(analyzer, '_detect_anomalies'):
                        with patch.object(analyzer, 'rule_engine') as mock_rule_engine:
                            mock_rule_engine.evaluate_all.return_value = []

                            result = analyzer.analyze(file_path)

                            # Verify error was captured
                            assert len(analyzer._analysis_errors) > 0
                            error_entry = next(
                                (e for e in analyzer._analysis_errors if e.get("phase") == "provenance_detection"),
                                None
                            )
                            assert error_entry is not None
                            assert "Test error" in error_entry["error"]


class TestProvenanceDetectionOrder:
    """Test the detection order priority (Revit > Fingerprint > Transfer > AutoCAD)."""

    def test_revit_takes_priority_over_fingerprint(self, tmp_path):
        """Test that Revit detection overrides fingerprint detection."""
        detector = ProvenanceDetector()
        file_path = tmp_path / "test.dwg"
        file_path.write_bytes(b"AC1032" + b"\x00" * 200)

        with patch.object(detector, '_detect_revit') as mock_revit:
            with patch.object(detector, '_fingerprint_application') as mock_fingerprint:
                # Both return positive results
                mock_revit_result = Mock(is_revit_export=True, confidence_score=0.9, revit_version="Revit 2023")
                mock_revit.return_value = mock_revit_result

                mock_fingerprint_result = Mock(
                    detected_application=CADApplication.BRICSCAD,
                    confidence=0.85,
                    is_oda_based=True
                )
                mock_fingerprint.return_value = mock_fingerprint_result

                provenance = detector.detect(file_path)

                # Revit should win
                assert provenance.source_application == "Revit"
                assert provenance.is_revit_export is True
                # Fingerprint should not have been called (early return)
                mock_fingerprint.assert_not_called()

    def test_fingerprint_used_when_not_revit(self, tmp_path):
        """Test that fingerprint is used when Revit detection fails."""
        detector = ProvenanceDetector()
        file_path = tmp_path / "test.dwg"
        file_path.write_bytes(b"AC1032" + b"\x00" * 200)

        with patch.object(detector, '_detect_revit', return_value=None):
            with patch.object(detector, '_fingerprint_application') as mock_fingerprint:
                mock_fingerprint_result = Mock(
                    detected_application=CADApplication.BRICSCAD,
                    confidence=0.85,
                    is_oda_based=True
                )
                mock_fingerprint.return_value = mock_fingerprint_result

                with patch.object(detector, '_detect_file_transfer', return_value=None):
                    provenance = detector.detect(file_path)

                    # Fingerprint should be used
                    assert provenance.source_application == "bricscad"
                    assert provenance.is_oda_tool is True
