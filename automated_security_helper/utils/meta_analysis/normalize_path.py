def normalize_path(path: str) -> str:
    """
    Normalize a field path by extracting the leaf field name.

    For example:
    - 'runs[0].results[0].ruleId' -> 'ruleId'
    - 'tool.driver.name' -> 'name'
    - 'runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri' -> 'uri'

    Args:
        path: Field path

    Returns:
        Normalized path (leaf field name)
    """
    # Extract the leaf field name (last part after the dot)
    if "." in path:
        # Handle array notation by removing array indices
        parts = path.split(".")
        return parts[-1].split("[")[0]

    # Handle case where there's no dot but might have array notation
    return path.split("[")[0]
