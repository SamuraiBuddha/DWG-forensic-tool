#!/usr/bin/env python3
"""
EMAIL PARSER SETUP VERIFICATION SCRIPT

Checks if environment is ready to run email_timeline_parser.py

USAGE:
    python verify_email_parser_setup.py
"""

import sys
from pathlib import Path

# Configuration
EMAIL_DIR = Path(r"\\adam\DataPool\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia\Gansari\Naples\emails")
EXPECTED_MSG_COUNT = 65


def check_python_version():
    """Verify Python version is 3.7+."""
    version = sys.version_info
    if version.major >= 3 and version.minor >= 7:
        print(f"[OK] Python version: {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"[FAIL] Python version: {version.major}.{version.minor}.{version.micro}")
        print("       Required: Python 3.7 or higher")
        return False


def check_extract_msg_library():
    """Verify extract-msg library is installed."""
    try:
        import extract_msg
        print(f"[OK] extract-msg library installed (version: {extract_msg.__version__})")
        return True
    except ImportError:
        print("[FAIL] extract-msg library not found")
        print("       Install with: pip install extract-msg")
        return False


def check_network_share_access():
    """Verify network share is accessible."""
    if EMAIL_DIR.exists():
        print(f"[OK] Network share accessible: {EMAIL_DIR}")
        return True
    else:
        print(f"[FAIL] Network share not accessible: {EMAIL_DIR}")
        print()
        print("TROUBLESHOOTING:")
        print("  1. Open Windows Explorer")
        print(f"  2. Navigate to: {EMAIL_DIR}")
        print("  3. Verify you can see .msg files")
        print("  4. If not, contact IT to mount network share")
        return False


def count_msg_files():
    """Count MSG files in email directory."""
    if not EMAIL_DIR.exists():
        print("[SKIP] Cannot count MSG files (network share not accessible)")
        return False

    msg_files = list(EMAIL_DIR.glob("*.msg"))
    count = len(msg_files)

    if count == EXPECTED_MSG_COUNT:
        print(f"[OK] Found {count} MSG files (expected: {EXPECTED_MSG_COUNT})")
        return True
    elif count > 0:
        print(f"[WARN] Found {count} MSG files (expected: {EXPECTED_MSG_COUNT})")
        print(f"       Email count discrepancy: {count - EXPECTED_MSG_COUNT:+d}")
        return True  # Still usable
    else:
        print(f"[FAIL] Found {count} MSG files (expected: {EXPECTED_MSG_COUNT})")
        print("       No MSG files found in directory")
        return False


def main():
    """Run all verification checks."""
    print("=" * 80)
    print("EMAIL PARSER SETUP VERIFICATION")
    print("=" * 80)
    print()

    checks = {
        'Python Version': check_python_version(),
        'extract-msg Library': check_extract_msg_library(),
        'Network Share Access': check_network_share_access(),
        'MSG File Count': count_msg_files(),
    }

    print()
    print("=" * 80)
    print("VERIFICATION SUMMARY")
    print("=" * 80)

    all_passed = all(checks.values())

    for check_name, passed in checks.items():
        status = "[OK]  " if passed else "[FAIL]"
        print(f"{status} {check_name}")

    print()

    if all_passed:
        print("[READY] Environment is ready to run email_timeline_parser.py")
        print()
        print("NEXT STEP:")
        print("  python email_timeline_parser.py")
    else:
        print("[NOT READY] Please resolve failed checks above")
        print()
        print("COMMON FIXES:")
        print("  - Install library: pip install extract-msg")
        print("  - Mount network share: net use Z: \\\\adam\\DataPool\\")
        print("  - Contact IT for network access")

    print()
    print("=" * 80)


if __name__ == "__main__":
    main()
