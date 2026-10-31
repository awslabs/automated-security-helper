import os
import re
from typing import Dict, Optional
from urllib.parse import unquote


def locations_match(loc1: Dict, loc2: Dict, scan_root: Optional[str] = None) -> bool:
    """
    Check if two locations match, allowing for path normalization and flexible matching.

    This function implements a flexible matching strategy where:
    - File paths must match if both are present
    - Line ranges can overlap or be exact matches
    - Missing fields are handled gracefully
    - Locations with no common fields can match

    A SARIF location whose ``physicalLocation``, ``artifactLocation`` or
    ``region`` is JSON null is read as one without that part; line numbers given
    as digit strings, or as floats of a whole value, are read as the integers they
    spell. Both forms reach this function from scanner reports and raised
    TypeError out of the whole aggregation check. A line that is stated and
    reads as no line (a fraction, text) makes the locations incompatible with one
    that states a readable line: read as an absent line it matched every line in
    the file. Two locations that both state such a line match when they spell
    their lines alike (a finding and its unchanged copy), and one beside a
    location with no line at all matches at file level, the lost line then being
    a lost field and not a lost finding.

    Args:
        loc1: First location (can be SARIF format or simple format)
        loc2: Second location (can be SARIF format or simple format)
        scan_root: The directory the scan was run on, when known: see
            :func:`file_paths_match`

    Returns:
        True if locations match or are compatible
    """
    # Handle empty locations
    if not loc1 or not loc2:
        return False

    # Extract file paths from different formats
    file1 = _extract_file_path(loc1)
    file2 = _extract_file_path(loc2)

    # Check if locations have any common fields
    has_common_fields = _has_common_fields(loc1, loc2)

    # If no common fields, they can match (no conflicting information)
    if not has_common_fields:
        return True

    # If both have file paths, they must name the same file. Aggregation rewrites
    # URIs (a file:// URI or an absolute path becomes a path relative to the scan
    # root), so the two spellings are compared as paths, not as text.
    if file1 and file2:
        if not file_paths_match(file1, file2, scan_root):
            return False
    # If one has a file path and the other doesn't, they don't match
    elif file1 or file2:
        return False

    # A line that is stated and reads as no line (``10.5``, ``"abc"``) is not an
    # absent one: absent matches at file level, and this would match any line.
    unreadable1 = _has_unreadable_line(loc1)
    unreadable2 = _has_unreadable_line(loc2)
    if unreadable1 and unreadable2:
        # Neither side names a line this module can place, so the two are the
        # same location only when they spell the same lines: a finding and its
        # unchanged copy both carrying ``startLine: "abc"`` are one finding.
        return _raw_line_range(loc1) == _raw_line_range(loc2)
    if (unreadable1 and _has_readable_line(loc2)) or (
        unreadable2 and _has_readable_line(loc1)
    ):
        # A line on one side is no line on the other: the unreadable one would
        # match it by being read as absent. A side with no line at all is not
        # refused: the finding is there and its lost line is a lost field.
        return False

    # Extract line ranges
    start1, end1 = _extract_line_range(loc1)
    start2, end2 = _extract_line_range(loc2)

    # Check line range compatibility
    return _line_ranges_compatible(start1, end1, start2, end2)


def _mapping(value) -> Dict:
    """*value* when it is a mapping, else an empty one: a SARIF sub-object given as
    JSON null has no fields."""
    return value if isinstance(value, dict) else {}


def _has_common_fields(loc1: Dict, loc2: Dict) -> bool:
    """Check if two locations have any common fields."""
    # Get all possible field names from both locations
    fields1: set[str] = set()
    fields2: set[str] = set()

    # SARIF format fields
    for location, fields in ((loc1, fields1), (loc2, fields2)):
        if "physicalLocation" not in location:
            continue
        fields.add("physicalLocation")
        phys_loc = _mapping(location["physicalLocation"])
        if "uri" in _mapping(phys_loc.get("artifactLocation")):
            fields.add("file_path")
        region = _mapping(phys_loc.get("region"))
        if "startLine" in region:
            fields.add("start_line")
        if "endLine" in region:
            fields.add("end_line")

    # Simple format fields
    for field in ["file_path", "start_line", "end_line"]:
        if field in loc1:
            fields1.add(field)
        if field in loc2:
            fields2.add(field)

    # Check for intersection
    return len(fields1.intersection(fields2)) > 0


def _line_ranges_compatible(start1, end1, start2, end2) -> bool:
    """
    Check if two line ranges are compatible using flexible matching rules.

    Args:
        start1, end1: Line range for first location
        start2, end2: Line range for second location

    Returns:
        True if ranges are compatible
    """
    # If neither location has line information, they're compatible
    if start1 is None and end1 is None and start2 is None and end2 is None:
        return True

    # If one or both locations have no line info, they match at file level
    if (start1 is None and end1 is None) or (start2 is None and end2 is None):
        return True  # File-level match

    # A side with an end line and no start line is read as that one line. It
    # was read as a wildcard that matched any range, so two ranges whose only
    # known lines were far apart were compatible.
    if start1 is None or start2 is None:
        point, low, high = (
            (end1, start2, end2) if start1 is None else (end2, start1, end1)
        )
        if low is None:
            # Both sides are a lone end line.
            return point == high or abs(point - high) <= 5
        if high is None:
            high = low
        return low <= point <= high or abs(point - low) <= 5

    if start1 != start2:
        # If both have start lines and they're different, check for overlap
        if end1 is not None and end2 is not None:
            # Check for overlapping ranges
            # Range 1: start1 to end1, Range 2: start2 to end2
            # They overlap if: start1 <= end2 and start2 <= end1
            overlap = start1 <= end2 and start2 <= end1
            if overlap:
                # Accept overlapping ranges only when start lines are close
                # (off-by-one through off-by-5 is common across scanners).
                # Reject large start-line gaps to avoid collapsing distinct findings.
                start_diff = abs(start1 - start2)
                return start_diff <= 5
            else:
                return False
        else:
            # If no end lines, start lines must match exactly for compatibility
            return False

    # Start lines match: the ranges overlap whatever their end lines are, so they
    # are compatible. Ranges whose start lines differ by up to 5 are accepted
    # above; two with the same start and different ends (one scanner reports the
    # statement, another the whole block) are closer than that, not further.
    return True


def _normalize_file_path(path: str) -> str:
    """*path* as aggregation would write it: a POSIX path without a ``file://``
    scheme, ``./`` prefix or trailing separator, percent-decoded exactly where
    aggregation decodes it.

    Aggregation (``sarif_utils._sanitize_uri``) turns a ``file://`` URI into a
    path and percent-decodes it there (``_file_uri_to_path_text``), so a
    scanner's ``file:///work/a%20b.py`` is written ``a b.py``; a relative URI it
    writes as spelled, escapes included. The same rule here keeps each side
    decoded as many times as aggregation decoded it: the original
    ``file:///work/a%20b.py`` meets the aggregate's ``a b.py``, a relative
    ``a%20b.py`` meets the aggregate's ``a%20b.py``, and a file whose name holds
    a literal escape (``file:///work/a%2520b.py``, written ``a%20b.py``) is not
    decoded a second time into ``a b.py`` and reported as lost."""
    text = str(path).replace("\\", "/")
    if text.startswith("file://"):
        text = text[len("file://") :]
        if "%" in text:
            text = unquote(text)
        # file:///C:/x -> C:/x. Only a drive letter: a POSIX path such as
        # /a:/file keeps its leading slash.
        if (
            len(text) > 2
            and text[0] == "/"
            and text[2] == ":"
            and text[1].isascii()
            and text[1].isalpha()
        ):
            text = text[1:]
    while text.startswith("./"):
        text = text[2:]
    return text.rstrip("/")


_DRIVE_PATH = re.compile(r"[A-Za-z]:[\\/]")


def resolve_scan_root(scan_root: Optional[str]) -> Optional[str]:
    """*scan_root* as an absolute path with its symbolic links resolved, or None
    when no root is given.

    The root is compared as text against the paths in the reports, so it is
    resolved once, here: a root reached through a link (``/var`` for
    ``/private/var``) is the directory it points at. A root that is not absolute
    names no directory (``.`` is whatever the process runs in) and is refused. A
    root of the other system's spelling is kept as it is, since nothing here could
    resolve it: a Windows drive path on a host that is not Windows, a path that
    starts with one ``/`` on Windows.

    Raises:
        ValueError: *scan_root* is given and is not an absolute path.
    """
    if scan_root is None:
        return None
    text = os.fspath(scan_root)
    if not text:
        return None
    if os.name != "nt" and _DRIVE_PATH.match(text):
        return text
    if os.name == "nt" and text.startswith("/") and not text.startswith("//"):
        return text
    if not os.path.isabs(text):
        raise ValueError(
            f"scan_root must be an absolute path, not {text!r}: a relative root "
            "names whatever directory the process happens to run in"
        )
    return os.path.realpath(text)


def _root_prefix(scan_root: str) -> Optional[str]:
    """*scan_root* as the prefix paths below it start with (normalized, no
    trailing separator): the empty string for the filesystem root, None when
    the root names no directory."""
    text = str(scan_root).replace("\\", "/")
    prefix = _normalize_file_path(text)
    if prefix:
        return prefix
    # ``/`` normalizes to nothing; so does ``./``, which is no directory.
    if text.startswith("/") and not text.strip("/"):
        return ""
    return None


def _below_root(path: str, root: str) -> str:
    """*path* (normalized) as a path relative to *root* (normalized) when it is
    below it, else unchanged. The drive letter of a Windows path is compared
    without regard to case, as the file system does."""
    if (
        _DRIVE_PATH.match(root + "/")
        and _DRIVE_PATH.match(path[:3])
        and path[0].lower() == root[0].lower()
    ):
        path = root[0] + path[1:]
    if path.startswith(root + "/"):
        return path[len(root) + 1 :]
    return path


def file_paths_match(file1: str, file2: str, scan_root: Optional[str] = None) -> bool:
    """Whether two location URIs name the same file.

    Equal once normalized, or one is absolute and the other, relative, is its
    tail at a component boundary: ``/work/app/src/a.py`` and ``src/a.py`` are one
    file. Two relative paths are compared whole, so ``src/a.py`` and
    ``other/src/a.py`` stay two files.

    The tail rule cannot tell which file an absolute path means when two files of
    the scan share their end (``src/main.py`` and ``services/api/src/main.py``),
    and it reads an aggregate that dropped a leading directory (``lib/a.py``
    written ``a.py``) as a file kept. With *scan_root*, the directory the scan was
    run on, a path below it is read as the path relative to it first, so the
    files of the scan are compared whole and no tail is matched for them. An
    absolute path outside the root is not a file of the scan the root can place,
    so it keeps the tail rule against a relative path and matches an identical
    path as before. The root is compared as it is given: see
    :func:`resolve_scan_root` for one reached through a link.
    """
    norm1 = _normalize_file_path(file1)
    norm2 = _normalize_file_path(file2)
    root = _root_prefix(scan_root) if scan_root else None
    if root is not None:
        norm1 = _below_root(norm1, root)
        norm2 = _below_root(norm2, root)
    if norm1 == norm2:
        return True
    for longer, shorter in ((norm1, norm2), (norm2, norm1)):
        if (
            shorter
            and _is_absolute(longer)
            and not _is_absolute(shorter)
            and longer.endswith("/" + shorter)
        ):
            return True
    return False


def _is_absolute(path: str) -> bool:
    return path.startswith("/") or (len(path) > 1 and path[1] == ":")


def _extract_file_path(location: Dict) -> str:
    """Extract file path from location object."""
    # SARIF format
    if "physicalLocation" in location:
        artifact = _mapping(
            _mapping(location["physicalLocation"]).get("artifactLocation")
        )
        if "uri" in artifact:
            return artifact["uri"]

    # Simple format
    if "file_path" in location:
        return location["file_path"]

    return None


def _line_number(value) -> Optional[int]:
    """*value* as a line number: an integer as given, a float of a whole value
    (``10.0``) and a string of decimal digits as the integer each spells, anything
    else (a bool, a fraction, text) as no line.

    A value that reads as no line is not the same as an absent one: see
    :func:`_has_unreadable_line`.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    if isinstance(value, str):
        text = value.strip()
        # isdecimal, not isdigit: a superscript digit passes isdigit and int()
        # refuses it.
        if text.isdecimal():
            try:
                return int(text)
            except ValueError:
                # More digits than the interpreter converts.
                return None
    return None


def _raw_line_range(location: Dict) -> tuple:
    """The start and end line of a location object as written, SARIF form first."""
    # SARIF format
    if "physicalLocation" in location:
        phys_loc = _mapping(location["physicalLocation"])
        if "region" in phys_loc:
            region = _mapping(phys_loc["region"])
            return region.get("startLine"), region.get("endLine")

    # Simple format
    return location.get("start_line"), location.get("end_line")


def _has_unreadable_line(location: Dict) -> bool:
    """Whether a line the location states reads as no line: a fraction, text, a
    boolean. Such a location names a line this module cannot place, which is not
    the same as naming none; read as none, it matched any line in its file."""
    return any(
        value is not None and _line_number(value) is None
        for value in _raw_line_range(location)
    )


def _has_readable_line(location: Dict) -> bool:
    """Whether the location states a line that reads as a line number."""
    return any(_line_number(value) is not None for value in _raw_line_range(location))


def lines_equal(first, second) -> bool:
    """Whether two stated lines are the same line: the same number once read, or,
    when neither reads as a number, the same spelling (absent equals absent).

    Two lines that both read as no line were equal whatever they said, so
    ``"abc"`` was the line ``"xyz"`` and the line that was not stated at all."""
    number_one, number_two = _line_number(first), _line_number(second)
    if number_one is None and number_two is None:
        return first == second
    return number_one == number_two


def _extract_line_range(location: Dict) -> tuple:
    """Extract start and end line from location object."""
    start, end = _raw_line_range(location)
    return _line_number(start), _line_number(end)
