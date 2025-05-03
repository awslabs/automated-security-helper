def normalize_path(path: str) -> str:
    """
    Normalize a file path for comparison.

    Args:
        path: File path

    Returns:
        Normalized path
    """
    # Remove file:// prefix
    if path.startswith("file://"):
        path = path[7:]

    # Convert backslashes to forward slashes
    path = path.replace("\\", "/")

    # Get just the filename if paths are very different
    if "/" in path:
        return path.split("/")[-1]

    return path
