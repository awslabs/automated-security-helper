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
    import re

    # File path: normalize separators
    if "/" in path or "\\" in path:
        return path.replace("\\", "/")

    # SARIF field path: strip array indices (both [0] and []) so that
    # paths using either notation normalize to the same string.
    normalized = re.sub(r"\[\d*\]", "", path)
    return normalized
