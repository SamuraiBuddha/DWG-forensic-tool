"""Version release date mapping for anachronism detection.

Maps DWG version codes to their official release dates for detecting
files claiming creation dates before the version existed.

This is a critical forensic check: a file saved in AC1024 format (AutoCAD 2010)
cannot legitimately claim a creation date of 2008, because AutoCAD 2010 was
not released until March 2009. Such anachronisms prove timestamp manipulation.

Version History:
- AC1006: AutoCAD R10 (October 1988)
- AC1009: AutoCAD R11/R12 (October 1990)
- AC1012: AutoCAD R13 (November 1994)
- AC1014: AutoCAD R14 (February 1997)
- AC1015: AutoCAD 2000/2000i/2002 (March 1999)
- AC1018: AutoCAD 2004/2005/2006 (March 2003)
- AC1021: AutoCAD 2007/2008/2009 (March 2006)
- AC1024: AutoCAD 2010/2011/2012 (March 2009)
- AC1027: AutoCAD 2013-2017 (March 2012)
- AC1032: AutoCAD 2018-2025+ (March 2017)
"""

from datetime import datetime, timezone
from typing import Dict, Optional, Tuple


# Official release dates for AutoCAD versions
# Dates are approximated to the first of the release month
VERSION_RELEASE_DATES: Dict[str, datetime] = {
    # Legacy versions (limited support)
    "AC1006": datetime(1988, 10, 1, tzinfo=timezone.utc),  # R10 - October 1988
    "AC1009": datetime(1990, 10, 1, tzinfo=timezone.utc),  # R11/R12 - October 1990
    "AC1012": datetime(1994, 11, 1, tzinfo=timezone.utc),  # R13 - November 1994
    "AC1014": datetime(1997, 2, 1, tzinfo=timezone.utc),   # R14 - February 1997
    "AC1015": datetime(1999, 3, 1, tzinfo=timezone.utc),   # 2000 - March 1999
    "AC1018": datetime(2003, 3, 1, tzinfo=timezone.utc),   # 2004 - March 2003
    "AC1021": datetime(2006, 3, 1, tzinfo=timezone.utc),   # 2007 - March 2006
    # Full support versions
    "AC1024": datetime(2009, 3, 1, tzinfo=timezone.utc),   # 2010 - March 2009
    "AC1027": datetime(2012, 3, 1, tzinfo=timezone.utc),   # 2013 - March 2012
    "AC1032": datetime(2017, 3, 1, tzinfo=timezone.utc),   # 2018 - March 2017
}

# Human-readable version names
VERSION_NAMES: Dict[str, str] = {
    "AC1006": "AutoCAD R10",
    "AC1009": "AutoCAD R11/R12",
    "AC1012": "AutoCAD R13",
    "AC1014": "AutoCAD R14",
    "AC1015": "AutoCAD 2000/2000i/2002",
    "AC1018": "AutoCAD 2004/2005/2006",
    "AC1021": "AutoCAD 2007/2008/2009",
    "AC1024": "AutoCAD 2010/2011/2012",
    "AC1027": "AutoCAD 2013-2017",
    "AC1032": "AutoCAD 2018-2025+",
}

# Version format spans - when each format was current
VERSION_SPANS: Dict[str, Tuple[datetime, datetime]] = {
    "AC1006": (
        datetime(1988, 10, 1, tzinfo=timezone.utc),
        datetime(1990, 10, 1, tzinfo=timezone.utc),
    ),
    "AC1009": (
        datetime(1990, 10, 1, tzinfo=timezone.utc),
        datetime(1994, 11, 1, tzinfo=timezone.utc),
    ),
    "AC1012": (
        datetime(1994, 11, 1, tzinfo=timezone.utc),
        datetime(1997, 2, 1, tzinfo=timezone.utc),
    ),
    "AC1014": (
        datetime(1997, 2, 1, tzinfo=timezone.utc),
        datetime(1999, 3, 1, tzinfo=timezone.utc),
    ),
    "AC1015": (
        datetime(1999, 3, 1, tzinfo=timezone.utc),
        datetime(2003, 3, 1, tzinfo=timezone.utc),
    ),
    "AC1018": (
        datetime(2003, 3, 1, tzinfo=timezone.utc),
        datetime(2006, 3, 1, tzinfo=timezone.utc),
    ),
    "AC1021": (
        datetime(2006, 3, 1, tzinfo=timezone.utc),
        datetime(2009, 3, 1, tzinfo=timezone.utc),
    ),
    "AC1024": (
        datetime(2009, 3, 1, tzinfo=timezone.utc),
        datetime(2012, 3, 1, tzinfo=timezone.utc),
    ),
    "AC1027": (
        datetime(2012, 3, 1, tzinfo=timezone.utc),
        datetime(2017, 3, 1, tzinfo=timezone.utc),
    ),
    "AC1032": (
        datetime(2017, 3, 1, tzinfo=timezone.utc),
        datetime(2099, 12, 31, tzinfo=timezone.utc),  # Current format
    ),
}


def get_version_release_date(version_string: str) -> Optional[datetime]:
    """Get the official release date for a DWG version.

    Args:
        version_string: DWG version code (e.g., 'AC1024')

    Returns:
        Release date as datetime in UTC, or None if unknown version
    """
    return VERSION_RELEASE_DATES.get(version_string)


def get_version_name(version_string: str) -> str:
    """Get human-readable version name.

    Args:
        version_string: DWG version code (e.g., 'AC1024')

    Returns:
        Human-readable name like 'AutoCAD 2010/2011/2012'
    """
    return VERSION_NAMES.get(version_string, f"Unknown ({version_string})")


def get_version_span(version_string: str) -> Optional[Tuple[datetime, datetime]]:
    """Get the time span when a version format was current.

    Args:
        version_string: DWG version code

    Returns:
        Tuple of (start_date, end_date) when format was current
    """
    return VERSION_SPANS.get(version_string)


def is_date_before_version_release(
    version_string: str,
    claimed_date: datetime,
) -> bool:
    """Check if a claimed creation date predates the version's release.

    This is a key anachronism detection - a file saved in AC1024 format
    cannot claim to have been created before March 2009 when the format
    was introduced.

    Args:
        version_string: DWG version code
        claimed_date: The date the file claims as creation date

    Returns:
        True if claimed_date is before the version's release (anachronism detected)
    """
    release_date = get_version_release_date(version_string)
    if release_date is None:
        return False

    # Ensure timezone awareness for comparison
    if claimed_date.tzinfo is None:
        claimed_date = claimed_date.replace(tzinfo=timezone.utc)

    return claimed_date < release_date


def get_anachronism_details(
    version_string: str,
    claimed_date: datetime,
) -> Optional[Dict[str, any]]:
    """Get detailed information about a version anachronism.

    Args:
        version_string: DWG version code
        claimed_date: The date the file claims as creation date

    Returns:
        Dict with anachronism details, or None if no anachronism
    """
    if not is_date_before_version_release(version_string, claimed_date):
        return None

    release_date = get_version_release_date(version_string)
    version_name = get_version_name(version_string)

    # Ensure timezone awareness
    if claimed_date.tzinfo is None:
        claimed_date = claimed_date.replace(tzinfo=timezone.utc)

    days_before = (release_date - claimed_date).days

    return {
        "version_string": version_string,
        "version_name": version_name,
        "version_release_date": release_date.isoformat(),
        "claimed_creation_date": claimed_date.isoformat(),
        "days_before_release": days_before,
        "description": (
            f"File claims creation on {claimed_date.strftime('%Y-%m-%d')} "
            f"but {version_name} ({version_string}) was not released until "
            f"{release_date.strftime('%Y-%m-%d')} ({days_before} days later)"
        ),
    }


def could_file_exist_at_date(
    version_string: str,
    claimed_date: datetime,
) -> Tuple[bool, str]:
    """Check if a file with given version could exist at claimed date.

    This performs the complete anachronism check and returns a
    human-readable explanation.

    Args:
        version_string: DWG version code
        claimed_date: The date being checked

    Returns:
        Tuple of (is_possible, explanation)
    """
    release_date = get_version_release_date(version_string)

    if release_date is None:
        return (True, f"Unknown version {version_string}, cannot verify")

    # Ensure timezone awareness
    if claimed_date.tzinfo is None:
        claimed_date = claimed_date.replace(tzinfo=timezone.utc)

    version_name = get_version_name(version_string)

    if claimed_date < release_date:
        days_before = (release_date - claimed_date).days
        return (
            False,
            f"[FAIL] Impossible: {version_name} was released {days_before} days "
            f"after the claimed creation date. File format did not exist yet.",
        )

    return (
        True,
        f"[OK] {version_name} existed on {claimed_date.strftime('%Y-%m-%d')}",
    )


def get_expected_version_for_date(claimed_date: datetime) -> Optional[str]:
    """Get the expected DWG version for a given date.

    Returns the version that was current at the claimed date.
    Useful for detecting version inconsistencies.

    Args:
        claimed_date: The date to check

    Returns:
        Version string that was current at that date, or None
    """
    # Ensure timezone awareness
    if claimed_date.tzinfo is None:
        claimed_date = claimed_date.replace(tzinfo=timezone.utc)

    for version, (start, end) in VERSION_SPANS.items():
        if start <= claimed_date < end:
            return version

    return None
