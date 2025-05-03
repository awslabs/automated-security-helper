from typing import Dict, List, Set


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
    merged = {}

    for paths in all_paths:
        for path, info in paths.items():
            if path not in merged:
                merged[path] = {"type": set(), "scanners": set()}

            # Merge types and scanners
            merged[path]["type"].update(info["type"])
            merged[path]["scanners"].update(info["scanners"])

    return merged
