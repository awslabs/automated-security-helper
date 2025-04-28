def should_include_field(path: str) -> bool:
    """
    Determine if a field should be included in the comparison.
    Only include fields under runs[0].results and exclude certain top-level metadata.

    Args:
        path: Field path

    Returns:
        True if the field should be included, False otherwise
    """
    # Include only fields under runs[0].results
    if ".results[" in path and "runs[0].results[0].ruleIndex" not in path:
        return True

    # Exclude specific top-level metadata fields
    excluded_patterns = [
        "runs[0].tool",
        "runs[0].results[0].ruleIndex",
        "properties",
        "$schema",
        "runs[0].invocations",
        "runs[0].originalUriBaseIds",
        "runs[0].artifacts",
        "runs[0].taxonomies",
        "runs[0].threadFlowLocations",
        "runs[0].addresses",
        "runs[0].conversion",
        "runs[0].language",
        "runs[0].versionControlProvenance",
    ]

    for pattern in excluded_patterns:
        if path == pattern or path.startswith(f"{pattern}"):
            return False

    return True
