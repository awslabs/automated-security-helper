# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Field paths, importance classification, comparison, and value helpers.

The field-path grammar
----------------------
A field path names one leaf of a JSON document: keys joined with ``.`` and list
elements as ``[N]`` (``runs[0].results[0].ruleId``). A consumer may write ``[]``
for "any element" (``runs[].results[].ruleId``, the form the reporter mappings
and ``ash inspect sarif-fields`` use). A key that holds a ``.``, ``[``, ``]``,
``"`` or ``\\``, or is empty, is written bracket-quoted as a JSON string with no
``.`` before it, ``properties["bandit/v1.0"]``, which is also how jq spells such a
key. Joining raw keys with ``.`` made ``a.b`` the key ``b`` under ``a``, so a
fingerprint key such as ``matchBasedId/v1.2`` could not be looked up and was
reported absent. :func:`parse_field_path` reads the grammar and :func:`join_path`
writes it, so every producer and consumer in this package agrees.
"""

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from automated_security_helper.utils.meta_analysis.locations_match import (
    file_paths_match,
)

# The leaf aggregation rewrites in every result it keeps: a location's file URI
# (a ``file://`` URI or an absolute path becomes a path relative to the scan
# root). The two spellings are compared as paths, as ``locations_match`` does
# when it pairs the results, never as text.
_LOCATION_URI_LEAF = ".artifactLocation.uri"

#: A key that can stand bare in a path: anything else is bracket-quoted.
_BARE_KEY = re.compile(r'^[^.\[\]"\\]+$')

#: A bracket-quoted key, ``["..."]``, with JSON string escapes inside.
_QUOTED_KEY = re.compile(r'\["((?:[^"\\]|\\.)*)"\]')

#: A key jq accepts after a bare ``.``: an identifier.
_JQ_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

#: One step of a parsed path: ``("key", name)``, ``("index", N)`` or ``("any", None)``.
PathStep = Tuple[str, Any]


# ---------------------------------------------------------------------------
# The field-path grammar
# ---------------------------------------------------------------------------


def format_key(key: Any) -> str:
    """*key* as a path writes it: bare, or bracket-quoted when it holds a
    character the grammar reads (``.``, ``[``, ``]``, ``"``, ``\\``) or is empty."""
    text = str(key)
    if _BARE_KEY.match(text):
        return text
    return f"[{json.dumps(text, ensure_ascii=False)}]"


def join_path(base: str, key: Any) -> str:
    """The path of *key* under *base* (``""`` for the root)."""
    written = format_key(key)
    if written.startswith("["):
        return f"{base}{written}"
    return f"{base}.{written}" if base else written


def index_path(base: str, index: int) -> str:
    """The path of element *index* of the list at *base*."""
    return f"{base}[{index}]"


def parse_field_path(path: str) -> Optional[List[PathStep]]:
    """The steps of *path*, or None when it is not a path in the grammar.

    ``runs[0].results[].a["b.c"]`` reads as the key ``runs``, index 0, the key
    ``results``, any element, the key ``a``, the key ``b.c``.
    """
    if not isinstance(path, str) or not path:
        return None
    steps: List[PathStep] = []
    position = 0
    length = len(path)
    expect_key = True
    while position < length:
        if expect_key:
            if path.startswith('["', position):
                matched = _QUOTED_KEY.match(path, position)
                if matched is None:
                    return None
                try:
                    steps.append(("key", json.loads(f'"{matched.group(1)}"')))
                except ValueError:
                    return None
                position = matched.end()
            elif path[position] == "[":
                # A top-level list: "[0]" names element 0 of the document itself.
                pass
            else:
                end = position
                while end < length and path[end] not in ".[":
                    end += 1
                if end == position:
                    return None
                steps.append(("key", path[position:end]))
                position = end
            expect_key = False
        while (
            position < length
            and path[position] == "["
            and not path.startswith('["', position)
        ):
            close = path.find("]", position)
            if close < 0:
                return None
            inner = path[position + 1 : close]
            if inner == "":
                steps.append(("any", None))
            elif inner.isascii() and inner.isdigit():
                # ASCII digits only: str.isdigit admits a superscript, which
                # int() refuses with a ValueError out of the whole check.
                try:
                    steps.append(("index", int(inner)))
                except ValueError:
                    # More digits than the interpreter converts.
                    return None
            else:
                return None
            position = close + 1
        if position >= length:
            break
        if path[position] == ".":
            position += 1
            if position >= length:
                return None
            expect_key = True
        elif path.startswith('["', position):
            expect_key = True
        else:
            return None
    return steps or None


def path_key_names(path: str) -> List[str]:
    """The key names along *path*, in order, without the indices."""
    steps = parse_field_path(path)
    if steps is None:
        return [part.split("[")[0] for part in str(path).split(".") if part]
    return [name for kind, name in steps if kind == "key"]


def jq_path(path: str) -> str:
    """*path* as a jq expression: ``.a.b[0]`` with a non-identifier key written
    ``["key"]``, so a key holding ``/`` or ``-`` does not fail to compile."""
    steps = parse_field_path(path)
    if steps is None:
        return "." + str(path)
    rendered = ""
    for kind, value in steps:
        if kind == "key" and _JQ_IDENTIFIER.match(value):
            rendered += f".{value}"
            continue
        if kind == "key":
            bracket = f"[{json.dumps(value, ensure_ascii=False)}]"
        elif kind == "index":
            bracket = f"[{value}]"
        else:
            bracket = "[]"
        # A bracket at the start is written ".[...]": a bare ["x"] is an array
        # literal to jq.
        rendered += bracket if rendered else f".{bracket}"
    return rendered


# ---------------------------------------------------------------------------
# extract_field_paths
# ---------------------------------------------------------------------------


def _record(paths: Dict[str, Dict[str, Set[str]]], path: str, value: Any) -> None:
    """Add *value*'s type to the entry of *path*, keeping what a caller's
    accumulator already holds for it."""
    entry = paths.setdefault(path, {"type": set(), "scanners": set()})
    entry["type"].add(type(value).__name__)


def extract_field_paths(
    obj: Any,
    path: str = "",
    paths: Dict[str, Dict[str, Set[str]]] = None,
    context_path: str = "",
) -> Dict[str, Dict[str, Set[str]]]:
    """
    Extract all field paths from a nested object by recursively walking its structure.

    Every key of every dict and every element of every list is recorded, lists
    nested in lists included, at the path the grammar above writes. A caller's
    *paths* accumulator keeps the types and scanners it already holds for a path
    seen again. *context_path* prefixes *path* when both are given.

    Args:
        obj: The object to extract paths from
        path: Current path in the object hierarchy
        paths: Dictionary to store paths, types, and scanners
        context_path: Additional context for the path (used for suppressions)

    Returns:
        Dictionary mapping field paths to their types and scanners
    """
    if paths is None:
        paths = {}

    # Handle None values
    if obj is None:
        return paths

    if context_path and path:
        current_base = f"{context_path}.{path}"
    else:
        current_base = path or context_path or ""

    if isinstance(obj, dict):
        for key, value in obj.items():
            child_path = join_path(current_base, key)
            _record(paths, child_path, value)
            if isinstance(value, (dict, list)):
                extract_field_paths(value, "", paths, child_path)
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            indexed_path = index_path(current_base, idx)
            if isinstance(item, (dict, list)):
                extract_field_paths(item, "", paths, indexed_path)
            elif item is not None:
                _record(paths, indexed_path, item)

    return paths


# ---------------------------------------------------------------------------
# merge_field_paths
# ---------------------------------------------------------------------------


def merge_field_paths(
    all_paths: List[Dict[str, Dict[str, Set[str]]]],
) -> Dict[str, Dict[str, Set[str]]]:
    """
    Merge multiple field path dictionaries.

    Args:
        all_paths: List of field path dictionaries

    Returns:
        Merged dictionary
    """
    merged: Dict[str, Dict[str, Set[str]]] = {}

    for paths in all_paths:
        for path, info in paths.items():
            if path not in merged:
                merged[path] = {"type": set(), "scanners": set()}

            # Merge types and scanners
            merged[path]["type"].update(info["type"])
            merged[path]["scanners"].update(info["scanners"])

    return merged


# ---------------------------------------------------------------------------
# categorize_field_importance
# ---------------------------------------------------------------------------

#: Result fields that directly affect how a finding is read.
_CRITICAL_FIELDS = frozenset(
    {
        "ruleId",
        "level",
        "message",
        "locations",
        "physicalLocation",
        "artifactLocation",
        "region",
        "startLine",
        "endLine",
    }
)

#: Result fields that give context. The containers among them (codeFlows,
#: relatedLocations, fixes) hold physicalLocation and region sub-fields of their
#: own, which are context too, so a container is tested before the critical
#: names its children carry.
_IMPORTANT_FIELDS = frozenset(
    {
        "kind",
        "rank",
        "baselineState",
        "codeFlows",
        "relatedLocations",
        "fixes",
    }
)


def categorize_field_importance(path: str) -> str:
    """
    Categorize the importance of a field based on its path.

    The path's key names are read whole: ``level`` is critical, a key that
    merely contains it (``levelOfDetail``) is not, and a field under
    ``relatedLocations``, ``codeFlows`` or ``fixes`` is important, as the
    container is, however its own name reads.

    Args:
        path: Field path

    Returns:
        Importance category: "critical", "important", or "informational"
    """
    names = path_key_names(path)

    if any(name in _IMPORTANT_FIELDS for name in names):
        return "important"

    if any(name in _CRITICAL_FIELDS for name in names):
        return "critical"

    # Default to informational
    return "informational"


# ---------------------------------------------------------------------------
# compare_result_fields
# ---------------------------------------------------------------------------

#: Result fields aggregation rewrites on purpose, so a difference in one of them
#: is not a loss. ``ruleIndex`` points into the run's rule array, which the
#: aggregated run rebuilds; ``analysisTarget`` is normalized.
EXPECTED_TRANSFORMATIONS: List[str] = ["ruleIndex", "analysisTarget"]

#: The importance vocabulary ``compare_result_fields`` writes and
#: ``validate_sarif_aggregation`` buckets by. One tuple for both, in rank order:
#: the validator keys its ``missing_fields`` and its counters on exactly these
#: names, so an importance outside them is a KeyError there.
IMPORTANCE_LEVELS = ("critical", "important", "informational")


def _leaf_paths(obj: Any, prefix: str = "") -> List[str]:
    """Every path to a scalar (or empty container) under *obj*.

    Array elements are written ``name[0]``, the form ``get_value_from_path``
    reads, so each path found here can be looked up on the other side.
    """
    paths: List[str] = []
    if isinstance(obj, dict):
        if not obj:
            return [prefix] if prefix else []
        for key, value in obj.items():
            paths.extend(_leaf_paths(value, join_path(prefix, key)))
        return paths
    if isinstance(obj, list):
        if not obj:
            return [prefix] if prefix else []
        for index, item in enumerate(obj):
            paths.extend(_leaf_paths(item, index_path(prefix, index)))
        return paths
    return [prefix] if prefix else []


def comparable_field_paths(result: Dict) -> List[str]:
    """The leaf paths of *result* that :func:`compare_result_fields` compares:
    every leaf outside :data:`EXPECTED_TRANSFORMATIONS`."""
    if not isinstance(result, dict):
        return []
    paths = []
    for path in _leaf_paths(result):
        names = path_key_names(path)
        if names and names[0] in EXPECTED_TRANSFORMATIONS:
            continue
        paths.append(path)
    return paths


def _leaf_values_equivalent(path: str, original: Any, aggregated: Any) -> bool:
    """Whether the aggregated leaf at *path* carries the original's value.

    A location's file URI is compared as a path (``file:///work/src/a.py`` and
    ``src/a.py`` name one file once aggregation has made the URI relative to
    the scan root). An empty container on the original side (``suppressions:
    []``) is carried by any container of the same type on the aggregated side:
    aggregation fills such lists, and the filled list read as a lost field.
    Every other leaf goes through ``are_values_equivalent``.
    """
    if isinstance(original, (dict, list)) and not original:
        return isinstance(aggregated, type(original))
    if (
        path.endswith(_LOCATION_URI_LEAF)
        and isinstance(original, str)
        and isinstance(aggregated, str)
    ):
        return file_paths_match(original, aggregated)
    return are_values_equivalent(original, aggregated)


def compare_result_fields(original_result: Dict, aggregated_result: Dict) -> List[Dict]:
    """
    Compare fields between original and aggregated results.

    Every field of the original result is looked up in the aggregated one. A
    field that is absent there, or holds a value ``are_values_equivalent`` does
    not accept, is reported with the importance ``categorize_field_importance``
    gives its path: one of :data:`IMPORTANCE_LEVELS`, the vocabulary
    ``validate_sarif_aggregation`` buckets by. Fields aggregation rewrites on
    purpose (:data:`EXPECTED_TRANSFORMATIONS`) are not compared, and a
    location's file URI is compared as a path, since aggregation rewrites it
    relative to the scan root.

    Args:
        original_result: Result from original scanner report
        aggregated_result: Matching result from aggregated report

    Returns:
        List of missing fields with their importance
    """
    missing_fields: List[Dict] = []
    if not isinstance(original_result, dict) or not isinstance(aggregated_result, dict):
        return missing_fields

    for path in comparable_field_paths(original_result):
        original = get_value_from_path(original_result, path)
        aggregated = get_value_from_path(aggregated_result, path)
        if aggregated["exists"] and _leaf_values_equivalent(
            path, original["value"], aggregated["value"]
        ):
            continue
        missing_fields.append(
            {
                "path": path,
                "original_value": original["value"],
                "importance": categorize_field_importance(path),
            }
        )

    return missing_fields


# ---------------------------------------------------------------------------
# should_include_field
# ---------------------------------------------------------------------------


def should_include_field(path: str) -> bool:
    """
    Determine if a field should be included in the comparison.
    Only include fields under runs[].results and exclude certain top-level metadata.

    Every element index reads as ``[]``: only ``[0]`` did, so a field of a
    second run (``runs[1].results[0].ruleId``) was excluded and the ruleIndex of
    a second result (``runs[0].results[1].ruleIndex``) was included.

    Args:
        path: Field path

    Returns:
        True if the field should be included, False otherwise
    """
    if not path:
        return False

    # Normalize path format for consistent comparison
    normalized_path = re.sub(r"\[\d+\]", "[]", str(path)).replace("runs.", "runs[].")

    # Include only fields under runs[].results
    if (
        "runs[].results" in normalized_path
        and "runs[].results[].ruleIndex" not in normalized_path
    ):
        return True

    # Exclude specific top-level metadata fields
    excluded_patterns = [
        "$schema",
        "properties",
        "runs[].tool",
        "tool.driver",  # Added to match test case
        "runs[].results[].ruleIndex",
        "runs[].invocations",
        "runs[].originalUriBaseIds",
        "runs[].artifacts",
        "runs[].taxonomies",
        "runs[].threadFlowLocations",
        "runs[].addresses",
        "runs[].conversion",
        "runs[].language",
        "runs[].versionControlProvenance",
        "version",  # Added to match test case
    ]

    for pattern in excluded_patterns:
        if normalized_path == pattern or normalized_path.startswith(f"{pattern}"):
            return False

    return (
        False  # Changed to match test expectations - only include runs[].results fields
    )


# ---------------------------------------------------------------------------
# get_value_from_path
# ---------------------------------------------------------------------------

_ABSENT: Dict[str, Any] = {"exists": False, "value": None}


def _walk(current: Any, steps: List[PathStep]) -> Dict[str, Any]:
    """The value at *steps* below *current*; ``[]`` is any element that has it."""
    for position, (kind, value) in enumerate(steps):
        if kind == "key":
            if not isinstance(current, dict) or value not in current:
                return dict(_ABSENT)
            current = current[value]
        elif kind == "index":
            if not isinstance(current, list) or not (0 <= value < len(current)):
                return dict(_ABSENT)
            current = current[value]
        else:
            if not isinstance(current, list):
                return dict(_ABSENT)
            for item in current:
                found = _walk(item, steps[position + 1 :])
                if found["exists"]:
                    return found
            return dict(_ABSENT)
        # A null value is the field itself only at the end of the path: a null
        # intermediate holds no deeper field.
        if current is None and position < len(steps) - 1:
            return dict(_ABSENT)
    return {"exists": True, "value": current}


def get_value_from_path(obj: Dict, path: str) -> Dict[str, Any]:
    """
    Get a value from a nested object using a dot-notation path.
    Handles cases where parent arrays or objects don't exist.

    Reads the grammar in the module docstring: bracket-quoted keys, several
    indices on one segment (``m[0][1]``), and ``[]`` for any element, which
    exists when some element holds the rest of the path. A null intermediate
    object holds no deeper field, and an index past the end, or a name that is
    not an array, is a field the object does not have: reporting either as
    present made check_field_presence_in_reports count a field an aggregate had
    dropped as preserved.

    Args:
        obj: The object to extract the value from
        path: Dot-notation path to the value

    Returns:
        Dictionary with 'exists' (bool) and 'value' (Any) keys
    """
    if not path or obj is None:
        return dict(_ABSENT)
    steps = parse_field_path(str(path))
    if steps is None:
        return dict(_ABSENT)
    return _walk(obj, steps)


# ---------------------------------------------------------------------------
# are_values_equivalent
# ---------------------------------------------------------------------------


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def are_values_equivalent(val1: Any, val2: Any) -> bool:
    """
    Check if two values are equivalent, with special handling for common transformations.

    Scalars of different types are different (``1`` and ``"1"``, ``1`` and
    ``True``), except that an integer and a float of one value are equal: the
    SARIF model types ``rank`` as a float, so ``50`` and ``50.0`` are one rank.
    Lists are compared as multisets of equivalent elements by this same rule, so
    ``[1]`` and ``[True]`` differ as ``1`` and ``True`` do; a hash-based Counter
    merged them, and sorting by repr read two equal dicts with different key
    orders as different. Strings are compared as written: a location URI is
    compared as a path by ``compare_result_fields``, and rewriting the
    backslashes of every string holding a slash read two messages or regular
    expressions that differ only there as one.

    Args:
        val1: First value
        val2: Second value

    Returns:
        True if values are equivalent
    """
    # Handle None values
    if val1 is None and val2 is None:
        return True
    if val1 is None or val2 is None:
        return False

    if _is_number(val1) and _is_number(val2):
        return val1 == val2

    # Handle different types -- do NOT stringify-compare across types
    if type(val1) is not type(val2):
        return False

    if isinstance(val1, str):
        return val1 == val2

    # Handle lists -- a multiset comparison of equivalent elements, so that
    # [1,1,2] is not considered equal to [1,2,2].
    if isinstance(val1, list):
        if len(val1) != len(val2):
            return False
        unmatched = list(val2)
        for item in val1:
            for position, candidate in enumerate(unmatched):
                if are_values_equivalent(item, candidate):
                    del unmatched[position]
                    break
            else:
                return False
        return True

    # Handle dictionaries -- compare keys AND values recursively
    if isinstance(val1, dict):
        if set(val1.keys()) != set(val2.keys()):
            return False
        return all(are_values_equivalent(val1[k], val2[k]) for k in val1)

    # Default comparison
    return val1 == val2


# ---------------------------------------------------------------------------
# normalize_path
# ---------------------------------------------------------------------------


def normalize_path(path: str) -> str:
    """
    Normalize a path by stripping array indices and normalizing separators.

    For file paths (containing / or \\), normalizes separators to /.
    For SARIF field paths, strips array indices but preserves the full
    dotted structure so that different files/fields remain distinguishable.

    For example:
    - 'runs[0].results[0].ruleId' -> 'runs.results.ruleId'
    - 'tool.driver.name' -> 'tool.driver.name'
    - 'src/foo.py' -> 'src/foo.py'
    - 'src\\bar.py' -> 'src/bar.py'

    Args:
        path: Field path or file path

    Returns:
        Normalized path preserving full relative structure
    """
    # File path: normalize separators
    if "/" in path or "\\" in path:
        return path.replace("\\", "/")

    # SARIF field path: strip array indices (both [0] and []) so that
    # paths using either notation normalize to the same string.
    normalized = re.sub(r"\[\d*\]", "", path)
    return normalized
