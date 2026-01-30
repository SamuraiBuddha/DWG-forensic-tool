#!/usr/bin/env python3
"""
Test script for forensic sweep - validates on small sample before full 153-file run.
"""

import logging
import sys
from pathlib import Path

from dwg_forensic.core.batch_processor import BatchProcessor
from forensic_specialized_reports import (
    generate_handle_gap_analysis,
    generate_application_fingerprint_report,
    generate_dwg_vs_revit_timeline
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Test configuration
CASE_ROOT = Path(r"\\adam\DataPool\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia")
TEST_OUTPUT = Path(__file__).parent / "test_forensic_output"

def test_file_access():
    """Test network access to case files."""
    logger.info("Testing file access...")

    if not CASE_ROOT.exists():
        logger.error(f"Cannot access case directory: {CASE_ROOT}")
        return False

    # Find primary DWG
    primary_dwg = CASE_ROOT / "6075 Enlgish Oaks AutoCAD 092021mls.dwg"
    if not primary_dwg.exists():
        logger.error(f"Cannot find primary DWG: {primary_dwg}")
        return False

    logger.info(f"[OK] Found primary DWG: {primary_dwg.name}")
    logger.info(f"[OK] Size: {primary_dwg.stat().st_size:,} bytes")

    return True


def test_batch_processor():
    """Test batch processor on 2022 Drawing Files folder (11 files)."""
    logger.info("\nTesting batch processor on small sample...")

    test_dir = CASE_ROOT / "6075 English Oaks - Naples 2, 2022 Drawing Files"
    if not test_dir.exists():
        logger.error(f"Test directory not found: {test_dir}")
        return None

    # Process just this folder (11 files)
    processor = BatchProcessor(num_workers=4)

    try:
        batch_result = processor.process_directory(
            directory=test_dir,
            recursive=True,
            pattern="*.dwg",
            with_llm=False,
        )

        logger.info(f"[OK] Batch processing successful")
        logger.info(f"     Files processed: {batch_result.successful}/{batch_result.total_files}")
        logger.info(f"     Processing time: {batch_result.processing_time_seconds:.2f}s")
        logger.info(f"     Risk distribution: {batch_result.risk_distribution}")

        return batch_result

    except Exception as e:
        logger.error(f"Batch processing failed: {e}", exc_info=True)
        return None


def test_specialized_reports(batch_result):
    """Test specialized report generation."""
    logger.info("\nTesting specialized report generation...")

    TEST_OUTPUT.mkdir(exist_ok=True)

    try:
        # Test handle gap analysis
        handle_gap_path = generate_handle_gap_analysis(batch_result, TEST_OUTPUT)
        logger.info(f"[OK] Handle gap analysis: {handle_gap_path.name}")

        # Test application fingerprint
        fingerprint_path = generate_application_fingerprint_report(batch_result, TEST_OUTPUT)
        logger.info(f"[OK] Application fingerprint: {fingerprint_path.name}")

        # Test timeline
        timeline_path = generate_dwg_vs_revit_timeline(batch_result, TEST_OUTPUT)
        logger.info(f"[OK] DWG vs Revit timeline: {timeline_path.name}")

        logger.info(f"\nTest outputs saved to: {TEST_OUTPUT}")
        return True

    except Exception as e:
        logger.error(f"Report generation failed: {e}", exc_info=True)
        return False


def main():
    """Run validation tests."""
    logger.info("=" * 80)
    logger.info("FORENSIC SWEEP VALIDATION TEST")
    logger.info("=" * 80)

    # Test 1: File access
    if not test_file_access():
        logger.error("File access test failed. Aborting.")
        sys.exit(1)

    # Test 2: Batch processor
    batch_result = test_batch_processor()
    if batch_result is None:
        logger.error("Batch processor test failed. Aborting.")
        sys.exit(1)

    # Test 3: Specialized reports
    if not test_specialized_reports(batch_result):
        logger.error("Report generation test failed. Aborting.")
        sys.exit(1)

    logger.info("\n" + "=" * 80)
    logger.info("ALL TESTS PASSED")
    logger.info("=" * 80)
    logger.info("Ready to execute full 153-file forensic sweep.")
    logger.info("Run: python forensic_sweep_153_dwg.py")


if __name__ == "__main__":
    main()
