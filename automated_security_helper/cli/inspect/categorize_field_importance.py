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
