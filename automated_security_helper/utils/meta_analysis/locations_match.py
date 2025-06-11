from typing import Dict


def locations_match(loc1: Dict, loc2: Dict) -> bool:
    """
    Check if two locations match, allowing for path normalization and flexible matching.

    This function implements a flexible matching strategy where:
    - File paths must match if both are present
    - Line ranges can overlap or be exact matches
    - Missing fields are handled gracefully
    - Locations with no common fields can match

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

    # Check if locations have any common fields
    has_common_fields = _has_common_fields(loc1, loc2)

    # If no common fields, they can match (no conflicting information)
    if not has_common_fields:
        return True

    # If both have file paths, they must match
    if file1 and file2:
        if file1 != file2:
            return False
    # If one has a file path and the other doesn't, they don't match
    elif file1 or file2:
        return False

    # Extract line ranges
    start1, end1 = _extract_line_range(loc1)
    start2, end2 = _extract_line_range(loc2)

    # Check line range compatibility
    return _line_ranges_compatible(start1, end1, start2, end2)


def _has_common_fields(loc1: Dict, loc2: Dict) -> bool:
    """Check if two locations have any common fields."""
    # Get all possible field names from both locations
    fields1 = set()
    fields2 = set()

    # SARIF format fields
    if "physicalLocation" in loc1:
        fields1.add("physicalLocation")
        phys_loc = loc1["physicalLocation"]
        if "artifactLocation" in phys_loc and "uri" in phys_loc["artifactLocation"]:
            fields1.add("file_path")
        if "region" in phys_loc:
            region = phys_loc["region"]
            if "startLine" in region:
                fields1.add("start_line")
            if "endLine" in region:
                fields1.add("end_line")

    if "physicalLocation" in loc2:
        fields2.add("physicalLocation")
        phys_loc = loc2["physicalLocation"]
        if "artifactLocation" in phys_loc and "uri" in phys_loc["artifactLocation"]:
            fields2.add("file_path")
        if "region" in phys_loc:
            region = phys_loc["region"]
            if "startLine" in region:
                fields2.add("start_line")
            if "endLine" in region:
                fields2.add("end_line")

    # Simple format fields
    for field in ["file_path", "start_line", "end_line"]:
        if field in loc1:
            fields1.add(field)
        if field in loc2:
            fields2.add(field)

    # Check for intersection
    return len(fields1.intersection(fields2)) > 0


def _line_ranges_compatible(start1, end1, start2, end2) -> bool:
    """
    Check if two line ranges are compatible using flexible matching rules.

    Args:
        start1, end1: Line range for first location
        start2, end2: Line range for second location

    Returns:
        True if ranges are compatible
    """
    # If neither location has line information, they're compatible
    if start1 is None and end1 is None and start2 is None and end2 is None:
        return True

    # If one or both locations have no line info, they match at file level
    if (start1 is None and end1 is None) or (start2 is None and end2 is None):
        return True  # File-level match

    # Handle null values - treat None as a wildcard that matches anything
    if start1 is None or start2 is None:
        # If one start line is None, they can still match
        return True
    elif start1 != start2:
        # If both have start lines and they're different, check for overlap
        if end1 is not None and end2 is not None:
            # Check for overlapping ranges
            # Range 1: start1 to end1, Range 2: start2 to end2
            # They overlap if: start1 <= end2 and start2 <= end1
            overlap = start1 <= end2 and start2 <= end1
            if overlap:
                # Check if this is a "close" match vs a true significant overlap
                # For close matches (small difference in start lines), require exact matching
                start_diff = abs(start1 - start2)

                # If start lines are very close (1 line apart), require exact matching
                # This handles cases like (10-15) vs (11-15) which should not match
                # But allows (10-15) vs (12-18) which should match (2+ lines apart)
                if start_diff == 1:
                    return False
                else:
                    # Significant overlap, allow it (like 10-15 vs 12-18)
                    return True
            else:
                return False
        else:
            # If no end lines, start lines must match exactly for compatibility
            return False

    # Start lines match, now check end lines
    if end1 is None and end2 is None:
        # Both have no end line, that's fine if start lines match
        return True
    elif end1 is None or end2 is None:
        # One has end line, other doesn't - this is compatible (partial match)
        return True
    elif end1 != end2:
        # Both have end lines but they're different - not compatible for exact matching
        return False

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
