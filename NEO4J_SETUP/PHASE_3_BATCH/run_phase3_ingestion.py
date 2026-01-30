#!/usr/bin/env python3
"""
Phase 3 Quick-Start Runner
Orchestrates the complete batch ingestion pipeline.

Usage:
    python run_phase3_ingestion.py --password <neo4j_password>

Author: CasparCode-002 Orchestrator
Generated: 2026-01-30
"""

import argparse
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path


# Default configuration
DEFAULT_NEO4J_URI = "bolt://localhost:7687"
DEFAULT_NEO4J_USER = "neo4j"
DEFAULT_CSV_PATH = (
    r"\\adam\DataPool\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia"
    r"\DOCUMENT_CATALOG\6075_ENGLISH_OAKS_DOCUMENTS.csv"
)

# Get script directory for output
SCRIPT_DIR = Path(__file__).parent.resolve()


def print_banner():
    """Print execution banner."""
    print("=" * 70)
    print("PHASE 3: NEO4J CSV BATCH INGESTION")
    print("Kara Murphy vs Danny Garcia Litigation Case")
    print("=" * 70)
    print(f"Started: {datetime.now().isoformat()}")
    print(f"Output Directory: {SCRIPT_DIR}")
    print("=" * 70)
    print()


def check_dependencies():
    """Check required Python packages."""
    print("[->] Checking dependencies...")
    missing = []

    try:
        import neo4j
        print("    [OK] neo4j")
    except ImportError:
        missing.append("neo4j")
        print("    [FAIL] neo4j - Run: pip install neo4j")

    try:
        import networkx
        print("    [OK] networkx (optional)")
    except ImportError:
        print("    [WARN] networkx not found - PNG visualization will be skipped")

    try:
        import matplotlib
        print("    [OK] matplotlib (optional)")
    except ImportError:
        print("    [WARN] matplotlib not found - PNG visualization will be skipped")

    if missing:
        print(f"\n[FAIL] Missing required packages: {missing}")
        print("Install with: pip install " + " ".join(missing))
        return False

    print()
    return True


def check_csv_access(csv_path: str) -> bool:
    """Check if CSV file is accessible."""
    print(f"[->] Checking CSV access: {csv_path}")

    # Try different path formats
    paths_to_try = [
        csv_path,
        csv_path.replace("\\", "/"),
    ]

    for path in paths_to_try:
        if os.path.exists(path):
            print(f"    [OK] CSV file accessible ({path})")
            return True

    print("    [FAIL] CSV file not accessible")
    print("    Network path may not be mounted or accessible")
    return False


def run_ingestion(
    csv_path: str,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    skip_validation: bool = False
):
    """Run the batch ingestion script."""
    print("[->] Starting batch ingestion...")

    ingestion_script = SCRIPT_DIR / "batch_document_ingestion.py"

    cmd = [
        sys.executable,
        str(ingestion_script),
        "--csv", csv_path,
        "--uri", neo4j_uri,
        "--user", neo4j_user,
        "--password", neo4j_password,
        "--output-dir", str(SCRIPT_DIR),
    ]

    if skip_validation:
        cmd.append("--skip-validation")

    try:
        result = subprocess.run(cmd, check=True)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"[FAIL] Ingestion failed with exit code {e.returncode}")
        return False


def run_visualization():
    """Run the visualization generator."""
    print("[->] Generating visualization...")

    viz_script = SCRIPT_DIR / "graph_visualization_generator.py"
    backup_file = SCRIPT_DIR / "neo4j_full_backup.json"

    if not backup_file.exists():
        print("    [SKIP] Backup file not found, skipping visualization")
        return False

    cmd = [
        sys.executable,
        str(viz_script),
        "--backup", str(backup_file),
        "--output-dir", str(SCRIPT_DIR),
    ]

    try:
        result = subprocess.run(cmd, check=True)
        return result.returncode == 0
    except subprocess.CalledProcessError:
        print("    [WARN] Visualization generation had issues")
        return False


def print_deliverables():
    """List generated deliverables."""
    print()
    print("=" * 70)
    print("PHASE 3 DELIVERABLES")
    print("=" * 70)

    expected_files = [
        "PHASE_3_BATCH_INGESTION_REPORT.txt",
        "neo4j_full_backup.json",
        "BATCH_INGESTION_VALIDATION_QUERIES.txt",
        "PHASE_3_EXECUTION_LOG.txt",
        "LITIGATION_GRAPH_FULL_VISUALIZATION.txt",
        "LITIGATION_GRAPH_FULL_VISUALIZATION.png",
    ]

    for filename in expected_files:
        filepath = SCRIPT_DIR / filename
        if filepath.exists():
            size_kb = filepath.stat().st_size / 1024
            print(f"  [OK] {filename} ({size_kb:.1f} KB)")
        else:
            print(f"  [--] {filename} (not generated)")

    print()
    print("=" * 70)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Phase 3 Quick-Start: Run complete batch ingestion pipeline"
    )
    parser.add_argument(
        "--password",
        required=True,
        help="Neo4j password"
    )
    parser.add_argument(
        "--uri",
        default=DEFAULT_NEO4J_URI,
        help=f"Neo4j URI (default: {DEFAULT_NEO4J_URI})"
    )
    parser.add_argument(
        "--user",
        default=DEFAULT_NEO4J_USER,
        help=f"Neo4j username (default: {DEFAULT_NEO4J_USER})"
    )
    parser.add_argument(
        "--csv",
        default=DEFAULT_CSV_PATH,
        help="Path to document catalog CSV"
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip schema validation"
    )
    parser.add_argument(
        "--skip-visualization",
        action="store_true",
        help="Skip visualization generation"
    )

    args = parser.parse_args()

    print_banner()

    # Check dependencies
    if not check_dependencies():
        sys.exit(1)

    # Check CSV access
    if not check_csv_access(args.csv):
        print()
        print("[INFO] Running in template mode - CSV not accessible")
        print("       The ingestion script will fail but templates are ready")
        print()

    # Run ingestion
    ingestion_success = run_ingestion(
        csv_path=args.csv,
        neo4j_uri=args.uri,
        neo4j_user=args.user,
        neo4j_password=args.password,
        skip_validation=args.skip_validation,
    )

    # Run visualization if ingestion succeeded
    if ingestion_success and not args.skip_visualization:
        run_visualization()

    # List deliverables
    print_deliverables()

    print(f"Completed: {datetime.now().isoformat()}")

    if ingestion_success:
        print("[OK] Phase 3 ingestion completed successfully")
        sys.exit(0)
    else:
        print("[FAIL] Phase 3 ingestion encountered errors")
        sys.exit(1)


if __name__ == "__main__":
    main()
