def generate_jq_query(field_path: str) -> str:
    """
    Generate a JQ query to find results containing the specified field.

    Args:
        field_path: The field path to search for (e.g., 'runs[0].results[0].suppressions[0].kind')

    Returns:
        A JQ query string that will return findings containing the field
    """
    # Extract the field name without the runs[0].results[0] prefix
    if field_path.startswith("runs[0].results[0]."):
        field_name = field_path[len("runs[0].results[0].") :]
        base_query = ".runs[0].results[]"
    else:
        field_name = field_path
        base_query = "."

    # Parse the field path into components
    components = []
    current = ""
    i = 0
    while i < len(field_name):
        if field_name[i] == ".":
            if current:
                components.append(current)
                current = ""
        elif field_name[i] == "[":
            # Handle array index
            if current:
                components.append(current)
                current = ""
            # Find the closing bracket
            j = i + 1
            while j < len(field_name) and field_name[j] != "]":
                j += 1
            # Skip the array index part
            i = j
        else:
            current += field_name[i]
        i += 1

    if current:
        components.append(current)

    # Build the selection criteria
    conditions = []
    path_so_far = ""

    for component in components:
        if path_so_far:
            path_so_far += "."
        path_so_far += component

        # For array fields, check if the field exists in any array element
        if "[" in field_name and component in field_name.split("[")[0].split("."):
            conditions.append(f'has("{component}")')
            conditions.append(f'.{component} | type == "array"')
        else:
            conditions.append(f'has("{component}")')

    # Replace array indices with array iteration
    field_path_for_query = field_name.replace("[0]", "[]")

    # Build the final query
    if conditions:
        query = f"{base_query} | select({' and '.join(conditions)})"
        # Add a check for the specific field
        query += f" | select(.{field_path_for_query} != null)"
    else:
        query = f"{base_query} | select(.{field_path_for_query} != null)"

    return query
