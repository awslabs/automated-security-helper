from automated_security_helper.utils.meta_analysis.normalize_path import normalize_path


from typing import Dict


def locations_match(loc1: Dict, loc2: Dict) -> bool:
    """
    Check if two locations match, allowing for path normalization.

    Args:
        loc1: First location
        loc2: Second location

    Returns:
        True if locations match
    """
    # If both have file paths, compare them (normalizing for relative/absolute paths)
    if loc1["file_path"] and loc2["file_path"]:
        path1 = normalize_path(loc1["file_path"])
        path2 = normalize_path(loc2["file_path"])

        if path1 != path2:
            return False

    # If both have line numbers, they should match
    if (
        loc1["start_line"]
        and loc2["start_line"]
        and loc1["start_line"] != loc2["start_line"]
    ):
        return False

    if loc1["end_line"] and loc2["end_line"] and loc1["end_line"] != loc2["end_line"]:
        return False

    return True
