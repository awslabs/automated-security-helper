# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Field paths, importance classification, comparison, and value helpers."""

import re
from collections import Counter
from typing import Any, Dict, List, Set


# ---------------------------------------------------------------------------
# extract_field_paths
# ---------------------------------------------------------------------------


def extract_field_paths(
    obj: Any,
    path: str = "",
    paths: Dict[str, Dict[str, Set[str]]] = None,
    context_path: str = "",
) -> Dict[str, Dict[str, Set[str]]]:
    """
    Extract all field paths from a nested object by recursively walking its structure.

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

    prefix = f"{context_path}." if context_path and not path else ""
    current_base = f"{prefix}{path}" if path else (context_path or "")

    if isinstance(obj, dict):
        for key, value in obj.items():
            child_path = f"{current_base}.{key}" if current_base else key
            type_name = type(value).__name__
            paths[child_path] = {"type": {type_name}, "scanners": set()}
            # Recurse into nested dicts and lists
            if isinstance(value, dict):
                extract_field_paths(value, "", paths, child_path)
            elif isinstance(value, list) and value:
                for idx, item in enumerate(value):
                    indexed_path = f"{child_path}[{idx}]"
                    if isinstance(item, dict):
                        extract_field_paths(item, "", paths, indexed_path)
                    else:
                        item_type = type(item).__name__
                        paths[indexed_path] = {"type": {item_type}, "scanners": set()}
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            indexed_path = f"{current_base}[{idx}]" if current_base else f"[{idx}]"
            if isinstance(item, dict):
                extract_field_paths(item, "", paths, indexed_path)
            elif item is not None:
                item_type = type(item).__name__
                paths[indexed_path] = {"type": {item_type}, "scanners": set()}

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


def categorize_field_importance(path: str) -> str:
    """
    Categorize the importance of a field based on its path.

    Args:
        path: Field path

    Returns:
        Importance category: "critical", "important", or "informational"
    """
    # Critical fields that directly affect finding interpretation
    critical_patterns = [
        "ruleId",
        "level",
        "message",
        "locations",
        "physicalLocation",
        "artifactLocation",
        "region",
        "startLine",
        "endLine",
    ]

    # Important fields that provide context but aren't critical
    important_patterns = [
        "kind",
        "rank",
        "baselineState",
        "codeFlows",
        "relatedLocations",
        "fixes",
    ]

    # Check if path contains any critical patterns
    for pattern in critical_patterns:
        if pattern in path:
            return "critical"

    # Check if path contains any important patterns
    for pattern in important_patterns:
        if pattern in path:
            return "important"

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
    """Every dotted path to a scalar (or empty container) under *obj*.

    Array elements are written ``name[0]``, the form ``get_value_from_path``
    reads, so each path found here can be looked up on the other side.
    """
    paths: List[str] = []
    if isinstance(obj, dict):
        if not obj:
            return [prefix] if prefix else []
        for key, value in obj.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            paths.extend(_leaf_paths(value, child))
        return paths
    if isinstance(obj, list):
        if not obj:
            return [prefix] if prefix else []
        for index, item in enumerate(obj):
            paths.extend(_leaf_paths(item, f"{prefix}[{index}]"))
        return paths
    return [prefix] if prefix else []


def compare_result_fields(original_result: Dict, aggregated_result: Dict) -> List[Dict]:
    """
    Compare fields between original and aggregated results.

    Every field of the original result is looked up in the aggregated one. A
    field that is absent there, or holds a value ``are_values_equivalent`` does
    not accept, is reported with the importance ``categorize_field_importance``
    gives its path: one of :data:`IMPORTANCE_LEVELS`, the vocabulary
    ``validate_sarif_aggregation`` buckets by. Fields aggregation rewrites on
    purpose (:data:`EXPECTED_TRANSFORMATIONS`) are not compared.

    Args:
        original_result: Result from original scanner report
        aggregated_result: Matching result from aggregated report

    Returns:
        List of missing fields with their importance
    """
    missing_fields: List[Dict] = []
    if not isinstance(original_result, dict) or not isinstance(aggregated_result, dict):
        return missing_fields

    for path in _leaf_paths(original_result):
        top_level = path.split(".")[0].split("[")[0]
        if top_level in EXPECTED_TRANSFORMATIONS:
            continue
        original = get_value_from_path(original_result, path)
        aggregated = get_value_from_path(aggregated_result, path)
        if aggregated["exists"] and are_values_equivalent(
            original["value"], aggregated["value"]
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

    Args:
        path: Field path

    Returns:
        True if the field should be included, False otherwise
    """
    if not path:
        return False

    # Normalize path format for consistent comparison
    normalized_path = str(path).replace("[0]", "[]").replace("runs.", "runs[].")

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


def get_value_from_path(obj: Dict, path: str) -> Dict[str, Any]:
    """
    Get a value from a nested object using a dot-notation path.
    Handles cases where parent arrays or objects don't exist.

    Args:
        obj: The object to extract the value from
        path: Dot-notation path to the value

    Returns:
        Dictionary with 'exists' (bool) and 'value' (Any) keys
    """
    if not path or obj is None:
        return {"exists": False, "value": None}

    current = obj
    parts = path.split(".")

    for i, part in enumerate(parts):
        # Handle array indices
        if "[" in part and "]" in part:
            array_name = part.split("[")[0]
            index_str = part.split("[")[1].split("]")[0]

            # Check if the array exists
            if not isinstance(current, dict) or array_name not in current:
                # The array doesn't exist
                return {"exists": False, "value": None}

            # If the array is null, the field doesn't exist
            if current[array_name] is None:
                return {"exists": False, "value": None}

            try:
                index = int(index_str)
            except ValueError:
                return {"exists": False, "value": None}
            # An index past the end, or a name that is not an array, is a field
            # the object does not have: reporting it as present (with a null
            # value) made check_field_presence_in_reports count a field an
            # aggregate had dropped as preserved.
            if not isinstance(current[array_name], list) or not (
                0 <= index < len(current[array_name])
            ):
                return {"exists": False, "value": None}
            current = current[array_name][index]
        else:
            if not isinstance(current, dict) or part not in current:
                return {"exists": False, "value": None}

            # If the value is null, the field exists but has null value
            if current[part] is None:
                return {"exists": True, "value": None}

            current = current[part]

    # The field exists (even if its value is None)
    return {"exists": True, "value": current}


# ---------------------------------------------------------------------------
# are_values_equivalent
# ---------------------------------------------------------------------------


def are_values_equivalent(val1: Any, val2: Any) -> bool:
    """
    Check if two values are equivalent, with special handling for common transformations.

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

    # Handle different types -- do NOT stringify-compare across types
    if type(val1) is not type(val2):
        return False

    # Handle strings - normalize paths, etc.
    if isinstance(val1, str) and isinstance(val2, str):
        # Normalize file paths
        if "/" in val1 or "\\" in val1:
            return normalize_path(val1) == normalize_path(val2)
        return val1 == val2

    # Handle lists -- use Counter for proper multiset comparison so that
    # [1,1,2] is not considered equal to [1,2,2].
    if isinstance(val1, list) and isinstance(val2, list):
        if len(val1) != len(val2):
            return False
        try:
            return Counter(val1) == Counter(val2)
        except TypeError:
            # Unhashable elements: fall back to sorted comparison
            try:
                return sorted(val1, key=repr) == sorted(val2, key=repr)
            except TypeError:
                return val1 == val2

    # Handle dictionaries -- compare keys AND values recursively
    if isinstance(val1, dict) and isinstance(val2, dict):
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
