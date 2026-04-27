from typing import Any, Dict, Set


def extract_field_paths(
    obj: Any,
    path: str = "",
    paths: Dict[str, Dict[str, Set[str]]] = None,
    context_path: str = "",
) -> Dict[str, Dict[str, Set[str]]]:
    """
    Extract all field paths from a nested object by recursively walking its structure.

    Args:
        obj: The object to extract paths from
        path: Current path in the object hierarchy
        paths: Dictionary to store paths, types, and scanners
        context_path: Additional context for the path (used for suppressions)

    Returns:
        Dictionary mapping field paths to their types and scanners
    """
    if paths is None:
        paths = {}

    # Handle None values
    if obj is None:
        return paths

    prefix = f"{context_path}." if context_path and not path else ""
    current_base = f"{prefix}{path}" if path else (context_path or "")

    if isinstance(obj, dict):
        for key, value in obj.items():
            child_path = f"{current_base}.{key}" if current_base else key
            type_name = type(value).__name__
            paths[child_path] = {"type": {type_name}, "scanners": set()}
            # Recurse into nested dicts and lists
            if isinstance(value, dict):
                extract_field_paths(value, "", paths, child_path)
            elif isinstance(value, list) and value:
                for idx, item in enumerate(value):
                    indexed_path = f"{child_path}[{idx}]"
                    if isinstance(item, dict):
                        extract_field_paths(item, "", paths, indexed_path)
                    else:
                        item_type = type(item).__name__
                        paths[indexed_path] = {"type": {item_type}, "scanners": set()}
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            indexed_path = f"{current_base}[{idx}]" if current_base else f"[{idx}]"
            if isinstance(item, dict):
                extract_field_paths(item, "", paths, indexed_path)
            elif item is not None:
                item_type = type(item).__name__
                paths[indexed_path] = {"type": {item_type}, "scanners": set()}

    return paths
