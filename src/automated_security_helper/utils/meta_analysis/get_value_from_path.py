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

    # Check if this is an array field path
    if "[" in path and "]" in path:
        # For array fields, check if the field exists in any array element
        array_path = path.split("[")[0]
        array_result = get_value_from_path(obj, array_path)

        # If the array itself doesn't exist, the field doesn't exist
        if not array_result["exists"]:
            return {"exists": False, "value": None}

        # If the array exists but is empty or null, consider the field as existing but null
        if array_result["value"] is None or (
            isinstance(array_result["value"], list) and len(array_result["value"]) == 0
        ):
            return {"exists": True, "value": None}

    current = obj
    parts = path.split(".")

    for part in parts:
        # Handle array indices
        if "[" in part and "]" in part:
            array_name = part.split("[")[0]
            index_str = part.split("[")[1].split("]")[0]

            # Check if the array exists
            if array_name not in current:
                # The array doesn't exist, but we'll consider the field as existing with null value
                # if we're checking for its presence in the structure
                return {"exists": True, "value": None}

            # If the array is null, consider the field as existing but null
            if current[array_name] is None:
                return {"exists": True, "value": None}

            try:
                index = int(index_str)
                if (
                    isinstance(current[array_name], list)
                    and len(current[array_name]) > index
                ):
                    current = current[array_name][index]
                else:
                    # Array exists but index is out of bounds
                    # Consider the field as existing but null
                    return {"exists": True, "value": None}
            except (ValueError, IndexError):
                return {"exists": False, "value": None}
        else:
            if part not in current:
                # If this is a leaf node, consider it missing
                # Otherwise, consider it as existing but null
                if part == parts[-1]:
                    return {"exists": False, "value": None}
                else:
                    return {"exists": True, "value": None}

            # If the value is null, consider the field as existing but null
            if current[part] is None:
                return {"exists": True, "value": None}

            current = current[part]

    # The field exists (even if its value is None)
    return {"exists": True, "value": current}
