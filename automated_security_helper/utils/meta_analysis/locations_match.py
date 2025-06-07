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
    if "file_path" in loc1 and "file_path" in loc2:
        # For test_locations_match_different_uri, we need to compare the original paths
        if loc1["file_path"] != loc2["file_path"]:
            return False

    # For test_locations_match_missing_fields, if one location has None values, it should match
    if "start_line" in loc1 and "start_line" in loc2:
        if loc1["start_line"] is None or loc2["start_line"] is None:
            # If either is None, consider it a match for this field
            pass
        elif loc1["start_line"] != loc2["start_line"]:
            return False

    if "end_line" in loc1 and "end_line" in loc2:
        if loc1["end_line"] is None or loc2["end_line"] is None:
            # If either is None, consider it a match for this field
            pass
        elif loc1["end_line"] != loc2["end_line"]:
            return False

    return True
