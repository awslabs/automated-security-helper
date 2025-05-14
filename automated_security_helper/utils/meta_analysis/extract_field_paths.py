from automated_security_helper.utils.meta_analysis.should_include_field import (
    should_include_field,
)


from typing import Any, Dict, Set


def extract_field_paths(
    obj: Any,
    path: str = "",
    paths: Dict[str, Dict[str, Set[str]]] = None,
    context_path: str = "",
) -> Dict[str, Dict[str, Set[str]]]:
    """
    Extract all field paths from a nested object.

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

    # Apply context path if we're in a results context
    full_path = path
    if context_path and path and not path.startswith(context_path):
        full_path = f"{context_path}.{path}" if path else context_path

    # Check if this field should be included
    if not should_include_field(path=full_path):
        return paths

    # Special handling for PropertyBag objects - don't drill into them
    if full_path.endswith(".properties") or full_path == "properties":
        if full_path not in paths:
            paths[full_path] = {"type": {"dict"}, "scanners": set()}
        return paths

    # Special handling for suppressions - ensure they have the proper context
    if path == "suppressions" or path.startswith("suppressions["):
        if "runs[0].results[0]" in context_path:
            # We're already in a results context
            full_path = f"{context_path}.{path}"
        elif not context_path:
            # We're at the top level, assume we need to add the context
            full_path = f"runs[0].results[0].{path}"
            context_path = "runs[0].results[0]"

    # Handle different types
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_path = f"{path}.{key}" if path else key

            # Update context path if we're entering a results array
            new_context = context_path
            if key == "results" and path == "runs[0]":
                new_context = "runs[0]"
            elif key == "suppressions" and "runs[0].results[0]" not in context_path:
                new_context = "runs[0].results[0]"

            extract_field_paths(value, new_path, paths, new_context)
    elif isinstance(obj, list):
        if obj:  # Only process non-empty lists
            # Process the first item to get field structure
            # Use [0] in the path to indicate it's an array element
            new_path = f"{path}[0]"

            # Update context path if we're entering a results array
            new_context = context_path
            if path == "runs[0].results":
                new_context = "runs[0].results[0]"
            elif path == "suppressions" and "runs[0].results[0]" not in context_path:
                new_context = "runs[0].results[0]"

            extract_field_paths(obj[0], new_path, paths, new_context)
    else:
        # Leaf node - store the type
        if full_path not in paths:
            paths[full_path] = {"type": set(), "scanners": set()}

        # Add the type of this field
        type_name = type(obj).__name__
        paths[full_path]["type"].add(type_name)

    return paths
