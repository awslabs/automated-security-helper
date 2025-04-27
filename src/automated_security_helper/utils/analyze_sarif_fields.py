"""
Utility functions for analyzing SARIF fields across different scanners.

This module provides functions to:
1. Extract field paths from SARIF reports
2. Identify field types and group them by scanner
3. Compare fields between original and aggregated reports
4. Validate that fields from original scanner reports are preserved in aggregated reports
5. Track field presence in aggregate and flat reports
6. Support reporter field mappings
"""

import json
import os
from typing import Any, Dict, List, Set, Tuple, Optional

from automated_security_helper.utils.log import ASH_LOGGER

# Mapping of scanner names in SARIF reports to their ASH configuration names
SCANNER_NAME_MAP = {
    "Semgrep OSS": "semgrep",
    "Bandit": "bandit",
    "cfn_nag": "cfn-nag",
    "Checkov": "checkov",
    "Grype": "grype",
    "Syft": "syft",
    "detect-secrets": "detect-secrets",
    "npm-audit": "npm-audit",
    "cdk-nag": "cdk-nag",
}

# List of fields expected to change during aggregation
EXPECTED_TRANSFORMATIONS = [
    "ruleIndex",  # Rule array changes during aggregation
    "tool.driver",  # Tool driver information is consolidated
    "invocations",  # Invocation details may change
    "properties.scanner_details",  # Scanner details may be reformatted
    "properties.tags",  # Tags may be consolidated
    "run.tool",  # Tool information is consolidated
    "run.invocations",  # Invocation details may change
    "analysisTarget",  # Analysis target may be normalized
]


def extract_field_paths(
    obj: Any, path: str = "", paths: Dict[str, Dict[str, Set[str]]] = None
) -> Dict[str, Dict[str, Set[str]]]:
    """
    Extract all field paths from a nested object.

    Args:
        obj: The object to extract paths from
        path: Current path in the object hierarchy
        paths: Dictionary to store paths, types, and scanners

    Returns:
        Dictionary mapping field paths to their types and scanners
    """
    if paths is None:
        paths = {}

    # Handle None values
    if obj is None:
        return paths

    # Special handling for PropertyBag objects - don't drill into them
    if path.endswith(".properties") or path == "properties":
        if path not in paths:
            paths[path] = {"type": {"dict"}, "scanners": set()}
        return paths

    # Handle different types
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_path = f"{path}.{key}" if path else key
            extract_field_paths(value, new_path, paths)
    elif isinstance(obj, list):
        if obj:  # Only process non-empty lists
            # Process the first item to get field structure
            # Use [0] in the path to indicate it's an array element
            extract_field_paths(obj[0], f"{path}[0]", paths)
    else:
        # Leaf node - store the type
        if path not in paths:
            paths[path] = {"type": set(), "scanners": set()}

        # Add the type of this field
        type_name = type(obj).__name__
        paths[path]["type"].add(type_name)

    return paths


def analyze_sarif_file(file_path: str) -> Tuple[Dict[str, Dict[str, Set[str]]], str]:
    """
    Analyze a SARIF file and extract field paths.

    Args:
        file_path: Path to the SARIF file

    Returns:
        Tuple of (field paths dict, scanner name)
    """
    try:
        with open(file_path, "r") as f:
            sarif_data = json.load(f)

        # Extract scanner name from the file
        scanner_name = "unknown"
        if (
            sarif_data.get("runs")
            and sarif_data["runs"][0].get("tool")
            and sarif_data["runs"][0]["tool"].get("driver")
        ):
            scanner_name = sarif_data["runs"][0]["tool"]["driver"].get(
                "name", "unknown"
            )
            # Map scanner name to ASH configuration name if available
            scanner_name = SCANNER_NAME_MAP.get(scanner_name, scanner_name)
        else:
            # Try to infer from filename
            base_name = os.path.basename(file_path)
            if "_" in base_name:
                scanner_name = base_name.split("_")[0]
                # Map scanner name to ASH configuration name if available
                scanner_name = SCANNER_NAME_MAP.get(scanner_name, scanner_name)

        # Extract field paths
        field_paths = extract_field_paths(sarif_data)

        # Add scanner name to each field
        for path_info in field_paths.values():
            path_info["scanners"].add(scanner_name)

        return field_paths, scanner_name

    except Exception as e:
        ASH_LOGGER.error(f"Error processing {file_path}: {e}")
        return {}, "error"


def merge_field_paths(
    all_paths: List[Dict[str, Dict[str, Set[str]]]],
) -> Dict[str, Dict[str, Set[str]]]:
    """
    Merge multiple field path dictionaries.

    Args:
        all_paths: List of field path dictionaries

    Returns:
        Merged dictionary
    """
    merged = {}

    for paths in all_paths:
        for path, info in paths.items():
            if path not in merged:
                merged[path] = {"type": set(), "scanners": set()}

            # Merge types and scanners
            merged[path]["type"].update(info["type"])
            merged[path]["scanners"].update(info["scanners"])

    return merged


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


def normalize_path(path: str) -> str:
    """
    Normalize a file path for comparison.

    Args:
        path: File path

    Returns:
        Normalized path
    """
    # Remove file:// prefix
    if path.startswith("file://"):
        path = path[7:]

    # Convert backslashes to forward slashes
    path = path.replace("\\", "/")

    # Get just the filename if paths are very different
    if "/" in path:
        return path.split("/")[-1]

    return path


def get_message_text(result: Dict) -> str:
    """
    Extract message text from a result.

    Args:
        result: SARIF result object

    Returns:
        Message text
    """
    if result.get("message"):
        if isinstance(result["message"], str):
            return result["message"]
        elif isinstance(result["message"], dict):
            if result["message"].get("text"):
                return result["message"]["text"]
            elif result["message"].get("root") and result["message"]["root"].get(
                "text"
            ):
                return result["message"]["root"]["text"]

    return ""


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


def locations_match(loc1: Dict, loc2: Dict) -> bool:
    """
    Check if two locations match, allowing for path normalization.

    Args:
        loc1: First location
        loc2: Second location

    Returns:
        True if locations match
    """
    # If both have file paths, compare them (normalizing for relative/absolute paths)
    if loc1["file_path"] and loc2["file_path"]:
        path1 = normalize_path(loc1["file_path"])
        path2 = normalize_path(loc2["file_path"])

        if path1 != path2:
            return False

    # If both have line numbers, they should match
    if (
        loc1["start_line"]
        and loc2["start_line"]
        and loc1["start_line"] != loc2["start_line"]
    ):
        return False

    if loc1["end_line"] and loc2["end_line"] and loc1["end_line"] != loc2["end_line"]:
        return False

    return True


def find_matching_result(original_result: Dict, aggregated_results: List[Dict]) -> Dict:
    """
    Find a matching result in the aggregated report.

    Args:
        original_result: Result from original scanner report
        aggregated_results: List of results from aggregated report

    Returns:
        Matching result or None
    """
    # Extract matching criteria
    rule_id = original_result.get("ruleId")

    # Extract location info
    location_info = extract_location_info(original_result)

    # Try to find a match
    for agg_result in aggregated_results:
        # Match by rule ID first
        if agg_result.get("ruleId") == rule_id:
            # Then check location
            agg_location = extract_location_info(agg_result)

            # Compare locations, allowing for path normalization
            if locations_match(location_info, agg_location):
                return agg_result

            # If locations don't match but messages do, consider it a match
            if (
                original_result.get("message")
                and agg_result.get("message")
                and get_message_text(original_result) == get_message_text(agg_result)
            ):
                return agg_result

    return None


def get_value_from_path(obj: Dict, path: str) -> Any:
    """
    Get a value from a nested object using a dot-notation path.

    Args:
        obj: The object to extract the value from
        path: Dot-notation path to the value

    Returns:
        The value at the specified path, or None if not found
    """
    if not path:
        return None

    current = obj
    parts = path.split(".")

    for part in parts:
        # Handle array indices
        if "[" in part and "]" in part:
            array_name = part.split("[")[0]
            index_str = part.split("[")[1].split("]")[0]

            if array_name not in current:
                return None

            try:
                index = int(index_str)
                if (
                    isinstance(current[array_name], list)
                    and len(current[array_name]) > index
                ):
                    current = current[array_name][index]
                else:
                    return None
            except (ValueError, IndexError):
                return None
        else:
            if part not in current:
                return None
            current = current[part]

    return current


def categorize_field_importance(path: str) -> str:
    """
    Categorize the importance of a field based on its path.

    Args:
        path: Field path

    Returns:
        Importance category: "critical", "important", or "informational"
    """
    # Critical fields that directly affect finding interpretation
    critical_patterns = [
        "ruleId",
        "level",
        "message",
        "locations",
        "physicalLocation",
        "artifactLocation",
        "region",
        "startLine",
        "endLine",
    ]

    # Important fields that provide context but aren't critical
    important_patterns = [
        "kind",
        "rank",
        "baselineState",
        "codeFlows",
        "relatedLocations",
        "fixes",
    ]

    # Check if path contains any critical patterns
    for pattern in critical_patterns:
        if pattern in path:
            return "critical"

    # Check if path contains any important patterns
    for pattern in important_patterns:
        if pattern in path:
            return "important"

    # Default to informational
    return "informational"


def compare_result_fields(original_result: Dict, aggregated_result: Dict) -> List[Dict]:
    """
    Compare fields between original and aggregated results.

    Args:
        original_result: Result from original scanner report
        aggregated_result: Matching result from aggregated report

    Returns:
        List of missing fields with their importance
    """
    missing_fields = []

    # Extract all field paths from both results
    orig_paths = extract_field_paths(original_result)
    agg_paths = extract_field_paths(aggregated_result)

    # Find fields in original that are missing in aggregated
    for path in orig_paths:
        # Skip known fields that might be intentionally different
        if path in ["properties", ".properties"]:
            continue

        # Check if this is an expected transformation
        is_expected_transformation = False
        for transform_path in EXPECTED_TRANSFORMATIONS:
            if path == transform_path or path.startswith(f"{transform_path}."):
                is_expected_transformation = True
                break

        if path not in agg_paths and not is_expected_transformation:
            # Get the value from the original result
            orig_value = get_value_from_path(original_result, path)

            missing_fields.append(
                {
                    "path": path,
                    "original_value": orig_value,
                    "importance": categorize_field_importance(path),
                }
            )

    return missing_fields


def extract_result_summary(result: Dict) -> Dict:
    """
    Extract a summary of a result for reporting.

    Args:
        result: SARIF result object

    Returns:
        Summary dictionary
    """
    summary = {
        "ruleId": result.get("ruleId", "unknown"),
        "message": get_message_text(result),
        "location": extract_location_info(result),
    }

    return summary


def validate_sarif_aggregation(
    original_reports: Dict[str, Dict], aggregated_report: Dict
) -> Dict:
    """
    Validate that all important fields from original scanner reports
    are preserved in the aggregated report.

    Args:
        original_reports: Dict mapping scanner names to their SARIF reports
        aggregated_report: The combined ASH SARIF report

    Returns:
        Dict with validation results and statistics
    """
    validation_results = {
        "missing_fields": {},
        "match_statistics": {},
        "unmatched_results": {},
        "summary": {
            "total_findings": 0,
            "matched_findings": 0,
            "critical_missing_fields": 0,
            "important_missing_fields": 0,
            "informational_missing_fields": 0,
        },
    }

    # Extract results from aggregated report
    agg_results = []
    if (
        aggregated_report.get("runs")
        and len(aggregated_report["runs"]) > 0
        and aggregated_report["runs"][0].get("results")
    ):
        agg_results = aggregated_report["runs"][0]["results"]

    # For each scanner's report
    for scanner_name, original_report in original_reports.items():
        # Map scanner name to ASH configuration name if available
        normalized_scanner_name = SCANNER_NAME_MAP.get(scanner_name, scanner_name)

        validation_results["missing_fields"][normalized_scanner_name] = {
            "critical": [],
            "important": [],
            "informational": [],
        }
        validation_results["match_statistics"][normalized_scanner_name] = {
            "total_results": 0,
            "matched_results": 0,
            "field_preservation_rate": 0,
            "critical_fields_missing": 0,
            "important_fields_missing": 0,
            "informational_fields_missing": 0,
        }

        # Get original results
        orig_results = []
        if (
            original_report.get("runs")
            and len(original_report["runs"]) > 0
            and original_report["runs"][0].get("results")
        ):
            orig_results = original_report["runs"][0]["results"]

        # Process each result in the original report
        for orig_result in orig_results:
            validation_results["match_statistics"][normalized_scanner_name][
                "total_results"
            ] += 1
            validation_results["summary"]["total_findings"] += 1

            # Find matching result in aggregated report
            matched_result = find_matching_result(orig_result, agg_results)

            if matched_result:
                validation_results["match_statistics"][normalized_scanner_name][
                    "matched_results"
                ] += 1
                validation_results["summary"]["matched_findings"] += 1

                # Compare fields between original and matched result
                missing_fields = compare_result_fields(orig_result, matched_result)

                # Categorize missing fields by importance
                for field_info in missing_fields:
                    importance = field_info["importance"]
                    validation_results["missing_fields"][normalized_scanner_name][
                        importance
                    ].append(field_info)
                    validation_results["match_statistics"][normalized_scanner_name][
                        f"{importance}_fields_missing"
                    ] += 1
                    validation_results["summary"][f"{importance}_missing_fields"] += 1
            else:
                # Track unmatched results
                if (
                    normalized_scanner_name
                    not in validation_results["unmatched_results"]
                ):
                    validation_results["unmatched_results"][
                        normalized_scanner_name
                    ] = []
                validation_results["unmatched_results"][normalized_scanner_name].append(
                    extract_result_summary(orig_result)
                )

    # Calculate field preservation rates
    for scanner_name in validation_results["match_statistics"]:
        stats = validation_results["match_statistics"][scanner_name]
        if stats["total_results"] > 0:
            stats["field_preservation_rate"] = (
                stats["matched_results"] / stats["total_results"]
            )

    return validation_results


def check_field_presence_in_reports(
    field_paths: Dict[str, Dict[str, Set[str]]],
    aggregate_report: Dict,
    flat_reports: Optional[Dict[str, Dict]] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Check if fields are present in aggregate and flat reports.

    Args:
        field_paths: Dictionary of field paths from original reports
        aggregate_report: The aggregated SARIF report
        flat_reports: Optional dictionary of flat report formats (CSV, JSON)

    Returns:
        Dictionary mapping field paths to presence information
    """
    presence_info = {}

    for path, info in field_paths.items():
        presence_info[path] = {
            "type": list(info["type"]),
            "scanners": list(info["scanners"]),
            "in_aggregate": False,
            "in_flat": {},
            "reporter_mappings": {},
        }

        # Check presence in aggregate report
        if aggregate_report:
            # Use get_value_from_path to check if field exists in aggregate
            value = get_value_from_path(aggregate_report, path)
            presence_info[path]["in_aggregate"] = value is not None

        # Check presence in flat reports
        if flat_reports:
            for report_type, report_data in flat_reports.items():
                # This is a simplified check - in a real implementation,
                # you would need to map SARIF fields to flat report fields
                presence_info[path]["in_flat"][report_type] = False

                # For demonstration, we'll just check if any field in the flat report
                # contains the last part of the SARIF path
                if path.split(".")[-1] in str(report_data):
                    presence_info[path]["in_flat"][report_type] = True

    # Add reporter mappings if available
    reporter_mappings = get_reporter_mappings()
    for path in presence_info:
        for reporter_name, mappings in reporter_mappings.items():
            if path in mappings:
                presence_info[path]["reporter_mappings"][reporter_name] = mappings[path]

    return presence_info


def get_reporter_mappings() -> Dict[str, Dict[str, str]]:
    """
    Get field mappings from registered reporters.

    Returns:
        Dictionary mapping reporter names to their field mappings
    """
    mappings = {}

    # This would be implemented to collect mappings from reporter plugins
    # For now, return a sample mapping for demonstration
    mappings["ocsf"] = {
        "runs[0].tool.driver.rules[0].id": "vulnerabilities[0].cve.uid",
        "runs[0].results[0].message.text": "vulnerabilities[0].desc",
    }

    mappings["asff"] = {
        "runs[0].results[0].ruleId": "Findings[0].Types[0]",
        "runs[0].results[0].message.text": "Findings[0].Description",
    }

    return mappings


# This function is no longer used - we've replaced it with the more comprehensive generate_html_report function
# Keeping the function signature for backward compatibility
def generate_enhanced_html_report(
    validation_results: Dict,
    field_presence: Dict[str, Dict[str, Any]],
    output_path: str,
) -> None:
    """
    Generate an enhanced HTML report with field presence information.

    This function is deprecated and now just calls generate_html_report.

    Args:
        validation_results: Validation results dictionary
        field_presence: Field presence information
        output_path: Path to write the HTML report
    """
    # Just call the main generate_html_report function
    generate_html_report(validation_results, output_path)


def generate_html_report(validation_results: Dict, output_path: str) -> None:
    """
    Generate a comprehensive HTML report showing SARIF field analysis and validation results.

    Args:
        validation_results: Validation results dictionary
        output_path: Path to write the HTML report
    """
    html = []
    html.append("<!DOCTYPE html>")
    html.append("<html>")
    html.append("<head>")
    html.append("  <title>SARIF Field Analysis Report</title>")
    html.append("  <style>")
    html.append("    body { font-family: Arial, sans-serif; margin: 20px; }")
    html.append("    h1, h2, h3 { color: #333; }")
    html.append(
        "    .summary { background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }"
    )
    html.append(
        "    .scanner { margin-bottom: 30px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }"
    )
    html.append(
        "    .scanner-header { display: flex; justify-content: space-between; align-items: center; }"
    )
    html.append("    .stats { display: flex; gap: 20px; margin: 10px 0; }")
    html.append(
        "    .stat { background-color: #eee; padding: 10px; border-radius: 3px; }"
    )
    html.append("    .critical { color: #d32f2f; }")
    html.append("    .important { color: #f57c00; }")
    html.append("    .informational { color: #388e3c; }")
    html.append("    .present { color: #388e3c; }")
    html.append("    .missing { color: #d32f2f; }")
    html.append(
        "    .field-table { width: 100%; border-collapse: collapse; margin: 15px 0; }"
    )
    html.append(
        "    .field-table th, .field-table td { padding: 8px; text-align: left; border: 1px solid #ddd; }"
    )
    html.append("    .field-table th { background-color: #f2f2f2; }")
    html.append("    .field-table tr:nth-child(even) { background-color: #f9f9f9; }")
    html.append("    .field-path { font-family: monospace; font-weight: bold; }")
    html.append(
        "    .field-value { font-family: monospace; color: #666; white-space: pre-wrap; }"
    )
    html.append(
        "    .collapsible { cursor: pointer; padding: 10px; background-color: #f1f1f1; }"
    )
    html.append("    .content { display: none; padding: 10px; overflow: hidden; }")
    html.append("    .active { display: block; }")
    html.append(
        "    .tab { overflow: hidden; border: 1px solid #ccc; background-color: #f1f1f1; }"
    )
    html.append(
        "    .tab button { background-color: inherit; float: left; border: none; outline: none; cursor: pointer; padding: 14px 16px; transition: 0.3s; }"
    )
    html.append("    .tab button:hover { background-color: #ddd; }")
    html.append("    .tab button.active { background-color: #ccc; }")
    html.append(
        "    .tabcontent { display: none; padding: 6px 12px; border: 1px solid #ccc; border-top: none; }"
    )
    html.append("    .search-container { margin: 10px 0; }")
    html.append("    #fieldSearch { width: 300px; padding: 8px; margin-right: 10px; }")
    html.append("    .reporter-mapping { margin-top: 5px; color: #0066cc; }")
    html.append("  </style>")
    html.append("</head>")
    html.append("<body>")

    # Add title and tabs
    html.append("  <h1>SARIF Field Analysis Report</h1>")

    html.append("  <div class='tab'>")
    html.append(
        "    <button class='tablinks active' onclick='openTab(event, \"FieldAnalysis\")'>Field Analysis</button>"
    )
    html.append(
        "    <button class='tablinks' onclick='openTab(event, \"ValidationResults\")'>Validation Results</button>"
    )
    html.append(
        "    <button class='tablinks' onclick='openTab(event, \"SarifFieldTable\")'>SARIF Field Table</button>"
    )
    html.append("  </div>")

    # Field Analysis Tab
    html.append("  <div id='FieldAnalysis' class='tabcontent' style='display: block;'>")
    html.append("    <h2>Field Analysis by Scanner</h2>")

    # Extract all scanners and fields from validation results
    all_scanners = set()
    all_fields = {}

    for scanner, importance_categories in validation_results["missing_fields"].items():
        all_scanners.add(scanner)
        for importance, fields in importance_categories.items():
            for field_info in fields:
                path = field_info["path"]
                if path not in all_fields:
                    all_fields[path] = {
                        "type": set(),
                        "scanners": set([scanner]),
                        "in_aggregate": False,  # It's missing, so it's not in aggregate
                    }
                else:
                    all_fields[path]["scanners"].add(scanner)

    # Add scanner sections
    for scanner, stats in validation_results["match_statistics"].items():
        html.append("    <div class='scanner'>")
        html.append("      <div class='scanner-header'>")
        html.append(f"        <h3>{scanner}</h3>")
        html.append(
            f"        <div>Match Rate: {stats['matched_results']}/{stats['total_results']} ({stats['field_preservation_rate']:.2%})</div>"
        )
        html.append("      </div>")

        # Add missing fields sections
        for importance in ["critical", "important", "informational"]:
            missing_fields = validation_results["missing_fields"][scanner][importance]
            if missing_fields:
                html.append(
                    f"      <div class='collapsible {importance}'>{importance.capitalize()} Missing Fields ({len(missing_fields)})</div>"
                )
                html.append("      <div class='content'>")
                html.append("        <table class='field-table'>")
                html.append(
                    "          <tr><th>Field Path</th><th>Original Value</th></tr>"
                )

                for field in missing_fields:
                    html.append("          <tr>")
                    html.append(
                        f"            <td class='field-path'>{field['path']}</td>"
                    )
                    html.append(
                        f"            <td class='field-value'>{json.dumps(field['original_value'], indent=2)}</td>"
                    )
                    html.append("          </tr>")

                html.append("        </table>")
                html.append("      </div>")

        html.append("    </div>")

    html.append("  </div>")

    # Validation Results Tab
    html.append("  <div id='ValidationResults' class='tabcontent'>")

    # Add validation summary section
    html.append("    <div class='summary'>")
    html.append("      <h2>Validation Summary</h2>")
    html.append("      <div class='stats'>")
    html.append(
        f"        <div class='stat'>Total Findings: {validation_results['summary']['total_findings']}</div>"
    )
    html.append(
        f"        <div class='stat'>Matched Findings: {validation_results['summary']['matched_findings']} ({validation_results['summary']['matched_findings'] / validation_results['summary']['total_findings']:.2%})</div>"
    )
    html.append("      </div>")
    html.append("      <div class='stats'>")
    html.append(
        f"        <div class='stat critical'>Critical Missing Fields: {validation_results['summary']['critical_missing_fields']}</div>"
    )
    html.append(
        f"        <div class='stat important'>Important Missing Fields: {validation_results['summary']['important_missing_fields']}</div>"
    )
    html.append(
        f"        <div class='stat informational'>Informational Missing Fields: {validation_results['summary']['informational_missing_fields']}</div>"
    )
    html.append("      </div>")
    html.append("    </div>")

    # Add scanner results table
    html.append("    <h2>Scanner Results</h2>")
    html.append("    <table class='field-table'>")
    html.append("      <tr>")
    html.append("        <th>Scanner</th>")
    html.append("        <th>Matched/Total</th>")
    html.append("        <th>Match Rate</th>")
    html.append("        <th>Critical Missing</th>")
    html.append("        <th>Important Missing</th>")
    html.append("        <th>Informational Missing</th>")
    html.append("      </tr>")

    for scanner, stats in validation_results["match_statistics"].items():
        match_rate = stats["field_preservation_rate"] * 100
        html.append("      <tr>")
        html.append(f"        <td>{scanner}</td>")
        html.append(
            f"        <td>{stats['matched_results']}/{stats['total_results']}</td>"
        )
        html.append(f"        <td>{match_rate:.2f}%</td>")
        html.append(
            f"        <td class='critical'>{stats.get('critical_fields_missing', 0)}</td>"
        )
        html.append(
            f"        <td class='important'>{stats.get('important_fields_missing', 0)}</td>"
        )
        html.append(
            f"        <td class='informational'>{stats.get('informational_fields_missing', 0)}</td>"
        )
        html.append("      </tr>")

    html.append("    </table>")
    html.append("  </div>")

    # SARIF Field Table Tab
    html.append("  <div id='SarifFieldTable' class='tabcontent'>")
    html.append("    <h2>SARIF Field Analysis Table</h2>")
    html.append("    <div class='search-container'>")
    html.append(
        "      <input type='text' id='fieldSearch' placeholder='Search for fields...' onkeyup='searchFields()'>"
    )
    html.append("    </div>")
    html.append("    <table class='field-table' id='sarifFieldTable'>")
    html.append("      <tr>")
    html.append("        <th>SARIF Field</th>")
    html.append("        <th>Supporting Scanners</th>")
    html.append("        <th>Field Type</th>")
    html.append("        <th>In Aggregate</th>")
    html.append("        <th>Reporter Mappings</th>")
    html.append("      </tr>")

    # Get reporter mappings
    reporter_mappings = get_reporter_mappings()

    # Collect all fields from all scanners
    all_fields_by_path = {}
    for scanner, importance_categories in validation_results["missing_fields"].items():
        for importance, fields in importance_categories.items():
            for field_info in fields:
                path = field_info["path"]
                if path not in all_fields_by_path:
                    all_fields_by_path[path] = {
                        "scanners": set([scanner]),
                        "type": set(),
                        "in_aggregate": False,  # It's missing from aggregate
                    }
                else:
                    all_fields_by_path[path]["scanners"].add(scanner)

    # Sort fields by path for better readability
    for path in sorted(all_fields_by_path.keys()):
        info = all_fields_by_path[path]
        scanners_list = ", ".join(sorted(info["scanners"]))

        # Determine field type - use a default if not available
        field_type = "unknown"
        if info["type"]:
            field_type = ", ".join(sorted(info["type"]))

        # Check for reporter mappings
        mappings_html = ""
        for reporter, mappings in reporter_mappings.items():
            if path in mappings:
                mappings_html += (
                    f"<div class='reporter-mapping'>{reporter}: {mappings[path]}</div>"
                )

        # Add row to table
        html.append("      <tr>")
        html.append(f"        <td class='field-path'>{path}</td>")
        html.append(f"        <td>{scanners_list}</td>")
        html.append(f"        <td>{field_type}</td>")
        html.append(
            f"        <td class='{'present' if info['in_aggregate'] else 'missing'}'>{info['in_aggregate']}</td>"
        )
        html.append(f"        <td>{mappings_html}</td>")
        html.append("      </tr>")

    html.append("    </table>")
    html.append("  </div>")

    # Add JavaScript for collapsible sections, tabs, and search
    html.append("  <script>")
    html.append("    // Collapsible sections")
    html.append("    var coll = document.getElementsByClassName('collapsible');")
    html.append("    for (var i = 0; i < coll.length; i++) {")
    html.append("      coll[i].addEventListener('click', function() {")
    html.append("        this.classList.toggle('active');")
    html.append("        var content = this.nextElementSibling;")
    html.append("        if (content.style.display === 'block') {")
    html.append("          content.style.display = 'none';")
    html.append("        } else {")
    html.append("          content.style.display = 'block';")
    html.append("        }")
    html.append("      });")
    html.append("    }")

    html.append("    // Tab functionality")
    html.append("    function openTab(evt, tabName) {")
    html.append("      var i, tabcontent, tablinks;")
    html.append("      tabcontent = document.getElementsByClassName('tabcontent');")
    html.append("      for (i = 0; i < tabcontent.length; i++) {")
    html.append("        tabcontent[i].style.display = 'none';")
    html.append("      }")
    html.append("      tablinks = document.getElementsByClassName('tablinks');")
    html.append("      for (i = 0; i < tablinks.length; i++) {")
    html.append(
        "        tablinks[i].className = tablinks[i].className.replace(' active', '');"
    )
    html.append("      }")
    html.append("      document.getElementById(tabName).style.display = 'block';")
    html.append("      evt.currentTarget.className += ' active';")
    html.append("    }")

    html.append("    // Search functionality")
    html.append("    function searchFields() {")
    html.append("      var input, filter, table, tr, td, i, txtValue;")
    html.append("      input = document.getElementById('fieldSearch');")
    html.append("      filter = input.value.toUpperCase();")
    html.append("      table = document.getElementById('sarifFieldTable');")
    html.append("      tr = table.getElementsByTagName('tr');")
    html.append(
        "      for (i = 1; i < tr.length; i++) {"
    )  # Start at 1 to skip header row
    html.append(
        "        td = tr[i].getElementsByTagName('td')[0];"
    )  # Field path column
    html.append("        if (td) {")
    html.append("          txtValue = td.textContent || td.innerText;")
    html.append("          if (txtValue.toUpperCase().indexOf(filter) > -1) {")
    html.append("            tr[i].style.display = '';")
    html.append("          } else {")
    html.append("            tr[i].style.display = 'none';")
    html.append("          }")
    html.append("        }")
    html.append("      }")
    html.append("    }")
    html.append("  </script>")

    html.append("</body>")
    html.append("</html>")

    # Write the HTML file
    with open(output_path, "w") as f:
        f.write("\n".join(html))
