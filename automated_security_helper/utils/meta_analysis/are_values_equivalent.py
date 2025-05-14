from automated_security_helper.utils.meta_analysis.normalize_path import normalize_path


from typing import Any


def are_values_equivalent(val1: Any, val2: Any) -> bool:
    """
    Check if two values are equivalent, with special handling for common transformations.

    Args:
        val1: First value
        val2: Second value

    Returns:
        True if values are equivalent
    """
    # Handle None values
    if val1 is None and val2 is None:
        return True

    # Handle different types
    if type(val1) is not type(val2):
        # Special case: string representations might be equivalent
        if str(val1) == str(val2):
            return True
        return False

    # Handle strings - normalize paths, etc.
    if isinstance(val1, str) and isinstance(val2, str):
        # Normalize file paths
        if "/" in val1 or "\\" in val1:
            return normalize_path(val1) == normalize_path(val2)
        return val1 == val2

    # Handle lists
    if isinstance(val1, list) and isinstance(val2, list):
        if len(val1) != len(val2):
            return False
        # For simplicity, just check if all items in val1 are in val2
        return all(item in val2 for item in val1)

    # Handle dictionaries
    if isinstance(val1, dict) and isinstance(val2, dict):
        # For simplicity, just check if keys match
        return set(val1.keys()) == set(val2.keys())

    # Default comparison
    return val1 == val2
