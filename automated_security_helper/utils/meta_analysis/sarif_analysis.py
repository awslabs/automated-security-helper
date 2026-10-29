# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""SARIF parsing, field extraction, and validation functions."""

import json
import os
from typing import Dict, List, Optional, Set, Tuple

from automated_security_helper.utils.meta_analysis import SCANNER_NAME_MAP
from automated_security_helper.utils.terminal_text import shown_not_obeyed


# ---------------------------------------------------------------------------
# analyze_sarif_file
# ---------------------------------------------------------------------------


def analyze_sarif_file(
    file_path: str, scanner_name: str = None
) -> Tuple[Dict[str, Dict[str, Set[str]]], str]:
    """
    Analyze a SARIF file and extract field paths.

    The field paths are ``field_mapping.extract_field_paths`` over the parsed
    report, each tagged with the scanner name, so a report with results yields
    its ``runs[0].results[0].ruleId`` and the rest. The scanner name is the one
    given, else the run's ``tool.driver.name`` mapped through
    ``SCANNER_NAME_MAP``, else the part of the file name before its first ``_``.

    Args:
        file_path: Path to the SARIF file
        scanner_name: Optional scanner name to use (overrides auto-detection)

    Returns:
        Tuple of (field paths dict, scanner name)
    """
    from automated_security_helper.utils.meta_analysis.field_mapping import (
        extract_field_paths,
    )

    try:
        with open(file_path, mode="r", encoding="utf-8") as f:
            sarif_data = json.load(f)

        # Extract scanner name from the file if not provided
        detected_scanner = "unknown"
        if (
            sarif_data.get("runs")
            and sarif_data["runs"][0].get("tool")
            and sarif_data["runs"][0]["tool"].get("driver")
        ):
            detected_scanner = sarif_data["runs"][0]["tool"]["driver"].get(
                "name", "unknown"
            )
            # Map scanner name to ASH configuration name if available
            detected_scanner = SCANNER_NAME_MAP.get(detected_scanner, detected_scanner)
        else:
            # Try to infer from filename
            base_name = os.path.basename(file_path)
            if "_" in base_name:
                detected_scanner = base_name.split("_")[0]
                # Map scanner name to ASH configuration name if available
                detected_scanner = SCANNER_NAME_MAP.get(
                    detected_scanner, detected_scanner
                )

        # Use provided scanner name if available, otherwise use detected name
        final_scanner_name = scanner_name or detected_scanner

        # Extract field paths
        field_paths = extract_field_paths(sarif_data)
        # Add scanner name to each field
        for path_info in field_paths.values():
            path_info["scanners"].add(final_scanner_name)

        return field_paths, final_scanner_name

    except Exception as e:
        print(shown_not_obeyed(f"Error processing {file_path}: {e}"))
        return {}, "error"


# ---------------------------------------------------------------------------
# extract_result_summary
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# validate_sarif_aggregation
# ---------------------------------------------------------------------------


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
    from automated_security_helper.utils.meta_analysis.field_mapping import (
        compare_result_fields,
    )

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

    # Extract results from every run of the aggregated report: a workspace scan
    # writes one run per project, and reading runs[0] alone left every other
    # run's findings unmatched.
    agg_results = _all_results(aggregated_report)
    # Each aggregated result stands for one original: once it has matched, it is
    # not offered again, so an original whose aggregated copy was dropped is not
    # counted as matched against a sibling's copy.
    taken_ids: Set[int] = set()

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

        # Process each result of every run in the original report
        for orig_result in _all_results(original_report):
            validation_results["match_statistics"][normalized_scanner_name][
                "total_results"
            ] += 1
            validation_results["summary"]["total_findings"] += 1

            # Find matching result in aggregated report
            matched_result = find_matching_result(
                orig_result, agg_results, exclude_ids=taken_ids
            )

            if matched_result:
                taken_ids.add(id(matched_result))
                validation_results["match_statistics"][normalized_scanner_name][
                    "matched_results"
                ] += 1
                validation_results["summary"]["matched_findings"] += 1

                # Compare fields between original and matched result
                missing_fields = compare_result_fields(orig_result, matched_result)

                # Categorize missing fields by importance. compare_result_fields
                # writes IMPORTANCE_LEVELS, the names these buckets carry; a name
                # outside them is a defect in that function, not a field to drop.
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


# ---------------------------------------------------------------------------
# find_matching_result
# ---------------------------------------------------------------------------


def _all_results(report: Dict) -> List[Dict]:
    """The results of every run of *report*, in run order."""
    results: List[Dict] = []
    for run in (report or {}).get("runs") or []:
        if isinstance(run, dict) and run.get("results"):
            results.extend(run["results"])
    return results


def _has_location(location_info: Dict) -> bool:
    """Whether ``extract_location_info`` found anything: it always returns the
    three keys, so the dict itself is never empty."""
    return any(value is not None for value in location_info.values())


def find_matching_result(
    original_result: Dict,
    aggregated_results: List[Dict],
    exclude_ids: Optional[Set[int]] = None,
) -> Optional[Dict]:
    """
    Find a matching result in the aggregated report using rule ID and location.

    Two results of one rule match when both carry a location and the locations
    match, or when neither carries one and their message texts, or failing those
    their ``analysisTarget`` URIs, are equal. A result with a location never
    matches one whose location differs, whatever else they share.

    Args:
        original_result: Result from original scanner report
        aggregated_results: List of results from aggregated report
        exclude_ids: ``id()`` of aggregated results already matched to another
            original, which are not offered again

    Returns:
        Matching result or None
    """
    from automated_security_helper.utils.meta_analysis.locations_match import (
        locations_match,
    )

    # Extract matching criteria
    rule_id = original_result.get("ruleId")

    # Extract location info
    location_info = extract_location_info(original_result)
    original_located = _has_location(location_info)

    # Try to find a match
    for agg_result in aggregated_results:
        if exclude_ids and id(agg_result) in exclude_ids:
            continue
        # Match by rule ID first
        if agg_result.get("ruleId") != rule_id:
            continue
        agg_location = extract_location_info(agg_result)
        agg_located = _has_location(agg_location)

        if original_located or agg_located:
            # A location on either side decides: it must be on both, and match.
            if (
                original_located
                and agg_located
                and locations_match(location_info, agg_location)
            ):
                return agg_result
            continue

        # No location on either side; fall back to the message text
        if (
            original_result.get("message")
            and agg_result.get("message")
            and get_message_text(original_result) == get_message_text(agg_result)
        ):
            return agg_result

        # Then to analysisTarget, when both name one
        original_target = (original_result.get("analysisTarget") or {}).get("uri")
        agg_target = (agg_result.get("analysisTarget") or {}).get("uri")
        if original_target and original_target == agg_target:
            return agg_result

    return None


# ---------------------------------------------------------------------------
# get_message_text
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# extract_location_info
# ---------------------------------------------------------------------------


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
