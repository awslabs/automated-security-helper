from collections import Counter

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

    # Handle lists -- use Counter for proper multiset comparison so that
    # [1,1,2] is not considered equal to [1,2,2].
    if isinstance(val1, list) and isinstance(val2, list):
        if len(val1) != len(val2):
            return False
        try:
            return Counter(val1) == Counter(val2)
        except TypeError:
            # Unhashable elements: fall back to sorted comparison
            try:
                return sorted(val1, key=repr) == sorted(val2, key=repr)
            except TypeError:
                return val1 == val2

    # Handle dictionaries -- compare keys AND values recursively
    if isinstance(val1, dict) and isinstance(val2, dict):
        if set(val1.keys()) != set(val2.keys()):
            return False
        return all(
            are_values_equivalent(val1[k], val2[k]) for k in val1
        )

    # Default comparison
    return val1 == val2
