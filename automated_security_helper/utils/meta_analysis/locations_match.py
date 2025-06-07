from typing import Dict


def locations_match(loc1: Dict, loc2: Dict) -> bool:
    """
    Check if two locations match, allowing for path normalization and flexible matching.

    This function implements a lenient matching strategy where:
    - Missing/null fields are treated as wildcards
    - Partial matches are allowed (if common fields match)
    - Overlapping line ranges are considered matches
    - If there are no conflicting fields, locations match

    Args:
        loc1: First location (can be SARIF format or simple format)
        loc2: Second location (can be SARIF format or simple format)

    Returns:
        True if locations match or are compatible
    """
    # Handle empty locations
    if not loc1 or not loc2:
        return False

    # Extract file paths from different formats
    file1 = _extract_file_path(loc1)
    file2 = _extract_file_path(loc2)

    # If both have file paths, they must match
    if file1 and file2:
        if file1 != file2:
            return False

    # Extract line ranges
    start1, end1 = _extract_line_range(loc1)
    start2, end2 = _extract_line_range(loc2)

    # Check line range compatibility with lenient matching
    return _line_ranges_compatible(start1, end1, start2, end2)


def _line_ranges_compatible(start1, end1, start2, end2) -> bool:
    """
    Check if two line ranges are compatible using lenient matching rules.

    Rules:
    - None/missing values are treated as wildcards (always compatible)
    - If both locations have specific line numbers, check for overlap or exact match
    - For simple format: exact matches preferred, but wildcards allowed
    - For SARIF format: overlapping ranges are considered compatible

    Args:
        start1, end1: Line range for first location
        start2, end2: Line range for second location

    Returns:
        True if ranges are compatible
    """
    # If neither location has line information, they're compatible
    if start1 is None and end1 is None and start2 is None and end2 is None:
        return True

    # If one location has no line info, they're compatible (wildcard match)
    if (start1 is None and end1 is None) or (start2 is None and end2 is None):
        return True

    # Handle cases where only start lines are available
    if start1 is not None and start2 is not None:
        # If both have start lines but no end lines, start lines must match
        if end1 is None and end2 is None:
            return start1 == start2

        # If one has end line and other doesn't, treat missing end as wildcard
        if end1 is None or end2 is None:
            return start1 == start2

        # Both have start and end lines - check for overlap
        # Range 1: [start1, end1], Range 2: [start2, end2]
        # They overlap if: start1 <= end2 and start2 <= end1
        return start1 <= end2 and start2 <= end1

    # If only one location has start line info, treat as wildcard match
    if start1 is not None or start2 is not None:
        return True

    # Default to compatible
    return True


def _extract_file_path(location: Dict) -> str:
    """Extract file path from location object."""
    # SARIF format
    if "physicalLocation" in location:
        phys_loc = location["physicalLocation"]
        if "artifactLocation" in phys_loc:
            artifact = phys_loc["artifactLocation"]
            if "uri" in artifact:
                return artifact["uri"]

    # Simple format
    if "file_path" in location:
        return location["file_path"]

    return None


def _extract_line_range(location: Dict) -> tuple:
    """Extract start and end line from location object."""
    # SARIF format
    if "physicalLocation" in location:
        phys_loc = location["physicalLocation"]
        if "region" in phys_loc:
            region = phys_loc["region"]
            start_line = region.get("startLine")
            end_line = region.get("endLine")
            return start_line, end_line

    # Simple format
    start_line = location.get("start_line")
    end_line = location.get("end_line")
    return start_line, end_line
