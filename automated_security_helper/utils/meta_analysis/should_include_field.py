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
