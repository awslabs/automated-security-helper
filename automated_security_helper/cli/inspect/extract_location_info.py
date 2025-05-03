from typing import Dict


def extract_location_info(result: Dict) -> Dict:
    """
    Extract location information from a result.

    Args:
        result: SARIF result object

    Returns:
        Dictionary with location information
    """
    location = {"file_path": None, "start_line": None, "end_line": None}

    # Extract from locations array
    if result.get("locations") and len(result["locations"]) > 0:
        loc = result["locations"][0]
        if loc.get("physicalLocation"):
            phys_loc = loc["physicalLocation"]

            # Handle different SARIF structures
            if phys_loc.get("artifactLocation") and phys_loc["artifactLocation"].get(
                "uri"
            ):
                location["file_path"] = phys_loc["artifactLocation"]["uri"]
            elif (
                phys_loc.get("root")
                and phys_loc["root"].get("artifactLocation")
                and phys_loc["root"]["artifactLocation"].get("uri")
            ):
                location["file_path"] = phys_loc["root"]["artifactLocation"]["uri"]

            # Extract line information
            if phys_loc.get("region"):
                location["start_line"] = phys_loc["region"].get("startLine")
                location["end_line"] = phys_loc["region"].get("endLine")
            elif phys_loc.get("root") and phys_loc["root"].get("region"):
                location["start_line"] = phys_loc["root"]["region"].get("startLine")
                location["end_line"] = phys_loc["root"]["region"].get("endLine")

    return location
