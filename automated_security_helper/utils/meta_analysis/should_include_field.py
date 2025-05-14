def should_include_field(path: str) -> bool:
    """
    Determine if a field should be included in the comparison.
    Only include fields under runs[].results and exclude certain top-level metadata.

    Args:
        path: Field path

    Returns:
        True if the field should be included, False otherwise
    """
    # Include only fields under runs[].results
    if ".results[" in path and "runs[].results[].ruleIndex" not in path:
        return True

    # Exclude specific top-level metadata fields
    excluded_patterns = [
        "$schema",
        "properties",
        "runs[].tool",
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
    ]

    for pattern in excluded_patterns:
        if path == pattern or path.startswith(f"{pattern}"):
            return False

    return True
