from typing import Any, Dict


def get_value_from_path(obj: Dict, path: str) -> Dict[str, Any]:
    """
    Get a value from a nested object using a dot-notation path.
    Handles cases where parent arrays or objects don't exist.

    Args:
        obj: The object to extract the value from
        path: Dot-notation path to the value

    Returns:
        Dictionary with 'exists' (bool) and 'value' (Any) keys
    """
    if not path:
        return {"exists": False, "value": None}

    current = obj
    parts = path.split(".")

    for i, part in enumerate(parts):
        # Handle array indices
        if "[" in part and "]" in part:
            array_name = part.split("[")[0]
            index_str = part.split("[")[1].split("]")[0]

            # Check if the array exists
            if array_name not in current:
                # The array doesn't exist
                return {"exists": False, "value": None}

            # If the array is null, the field doesn't exist
            if current[array_name] is None:
                return {"exists": False, "value": None}

            try:
                index = int(index_str)
                if (
                    isinstance(current[array_name], list)
                    and len(current[array_name]) > index
                ):
                    current = current[array_name][index]
                else:
                    # Array exists but index is out of bounds
                    return {"exists": True, "value": None}
            except (ValueError, IndexError):
                return {"exists": False, "value": None}
        else:
            if part not in current:
                return {"exists": False, "value": None}

            # If the value is null, the field exists but has null value
            if current[part] is None:
                return {"exists": True, "value": None}

            current = current[part]

    # The field exists (even if its value is None)
    return {"exists": True, "value": current}
