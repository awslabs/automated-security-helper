# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""SARIF parsing, field extraction, and validation functions."""

import json
import os
from typing import Any, Dict, List, Optional, Set, Tuple

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
    original_reports: Dict[str, Dict],
    aggregated_report: Dict,
    scan_root: Optional[str] = None,
) -> Dict:
    """
    Validate that all important fields from original scanner reports
    are preserved in the aggregated report.

    Per scanner, ``match_statistics`` carries ``match_rate`` (matched results
    over results) and ``field_preservation_rate`` (the share of the compared
    fields of the matched results that the aggregate preserved, from
    ``fields_compared`` and ``fields_missing``). The latter used to be the match
    rate under the other name, so a scanner whose every matched result had lost
    critical fields still read 1.0. It is None, not 0, for a scanner with no
    matched result: nothing was compared, so no share of it was preserved.
    (``ash inspect sarif-fields`` writes the same key from its own counts, where
    each "result" is a field path, so there the match rate is the share of a
    scanner's fields that reach the aggregate.) Two scanner names that normalize to one
    (``SCANNER_NAME_MAP``) share one entry and their counts add up; each used to
    reset the other's statistics while the summary totals kept both.

    Args:
        original_reports: Dict mapping scanner names to their SARIF reports
        aggregated_report: The combined ASH SARIF report
        scan_root: The directory the scan was run on, when known. With it a
            result's file is compared whole relative to that root: a file the
            aggregate wrote without a leading directory (``lib/a.py`` as
            ``a.py``) is no longer read as the same file by the end of its
            path. Without it, a relative path matches an absolute one that ends
            with it. The root is resolved once (``os.path.realpath``), so one
            reached through a link names the directory it points at; a root
            that is not an absolute path is refused. An absolute path outside
            the root keeps the end-of-path rule against a relative one.

    Returns:
        Dict with validation results and statistics

    Raises:
        ValueError: *scan_root* is given and is not an absolute path.
    """
    from automated_security_helper.utils.meta_analysis.field_mapping import (
        comparable_field_paths,
        compare_result_fields,
    )
    from automated_security_helper.utils.meta_analysis.locations_match import (
        resolve_scan_root,
    )

    scan_root = resolve_scan_root(scan_root)

    validation_results: Dict[str, Any] = {
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

    # Every original of every scanner report, in report order. Matching needs the
    # whole list before it starts: see _match_originals.
    originals: List[Tuple[str, Dict]] = []

    # For each scanner's report
    for scanner_name, original_report in original_reports.items():
        # Map scanner name to ASH configuration name if available
        normalized_scanner_name = SCANNER_NAME_MAP.get(scanner_name, scanner_name)

        validation_results["missing_fields"].setdefault(
            normalized_scanner_name,
            {"critical": [], "important": [], "informational": []},
        )
        validation_results["match_statistics"].setdefault(
            normalized_scanner_name,
            {
                "total_results": 0,
                "matched_results": 0,
                "match_rate": 0,
                "fields_compared": 0,
                "fields_missing": 0,
                "field_preservation_rate": None,
                "critical_fields_missing": 0,
                "important_fields_missing": 0,
                "informational_fields_missing": 0,
            },
        )

        # Every result of every run in the original report
        originals.extend(
            (normalized_scanner_name, orig_result)
            for orig_result in _all_results(original_report)
        )

    matches = _match_originals(originals, agg_results, scan_root)

    for (normalized_scanner_name, orig_result), matched_result in zip(
        originals, matches
    ):
        stats = validation_results["match_statistics"][normalized_scanner_name]
        stats["total_results"] += 1
        validation_results["summary"]["total_findings"] += 1

        if matched_result:
            stats["matched_results"] += 1
            validation_results["summary"]["matched_findings"] += 1

            # Compare fields between original and matched result
            missing_fields = compare_result_fields(
                orig_result, matched_result, scan_root
            )
            stats["fields_compared"] += len(comparable_field_paths(orig_result))
            stats["fields_missing"] += len(missing_fields)

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
            validation_results["unmatched_results"].setdefault(
                normalized_scanner_name, []
            ).append(extract_result_summary(orig_result))

    # Calculate the match and field preservation rates
    for scanner_name in validation_results["match_statistics"]:
        stats = validation_results["match_statistics"][scanner_name]
        if stats["total_results"] > 0:
            stats["match_rate"] = stats["matched_results"] / stats["total_results"]
        if stats["fields_compared"] > 0:
            stats["field_preservation_rate"] = (
                stats["fields_compared"] - stats["fields_missing"]
            ) / stats["fields_compared"]

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


def _match_originals(
    originals: List[Tuple[str, Dict]],
    aggregated_results: List[Dict],
    scan_root: Optional[str] = None,
) -> List[Optional[Dict]]:
    """The aggregated result each original stands for, or None, in order.

    *originals* are ``(normalized scanner name, result)`` pairs. Each aggregated
    result stands for one original: once taken it is not offered again, so an
    original whose aggregated copy was dropped is not counted as matched against
    a sibling's copy. Taking in report order was not enough: an original whose
    copy was dropped took the sibling's copy as the nearest overlapping result,
    and when the sibling came next its own copy was gone, so the sibling was
    reported unmatched and the fields the dropped original lacked in the copy
    were reported as lost. Every original's exact match is therefore taken
    first, and an overlapping result is offered only to what is left.

    Two findings of one rule on the same lines have the same exact match, so the
    exact tier has a tier before it: a result at the original's own lines that
    also carries its message (and start column, when both state one). Taken in
    report order, the first of two such findings took the copy of the second
    when only the second's copy was kept, and the second then read as lost.
    """
    taken_ids: Set[int] = set()
    matches: List[Optional[Dict]] = [None] * len(originals)
    # (same finding only, exact only): the same finding at its own lines, then
    # any result at its own lines, then any overlapping result.
    for same_finding_only, exact_only in ((True, True), (False, True), (False, False)):
        for index, (scanner_name, original) in enumerate(originals):
            if matches[index]:
                continue
            found = find_matching_result(
                original,
                aggregated_results,
                exclude_ids=taken_ids,
                scanner_name=scanner_name,
                exact_only=exact_only,
                scan_root=scan_root,
                same_finding_only=same_finding_only,
            )
            if found:
                taken_ids.add(id(found))
                matches[index] = found
    return matches


def _has_location(location_info: Dict) -> bool:
    """Whether ``extract_location_info`` found anything: it always returns the
    three keys, so the dict itself is never empty."""
    return any(value is not None for value in location_info.values())


def _rule_identity(result: Dict) -> Optional[str]:
    """The rule a result names: ``ruleId``, else ``rule.id`` (SARIF 3.27.5 lets a
    result name its rule through the ``rule`` reference alone)."""
    rule_id = result.get("ruleId")
    if rule_id:
        return rule_id
    rule = result.get("rule")
    if isinstance(rule, dict):
        return rule.get("id") or None
    return None


def _result_scanner(result: Dict) -> Optional[str]:
    """The scanner an aggregated result records (``properties.scanner_name``,
    which aggregation attaches to every result), normalized, or None."""
    properties = result.get("properties")
    if not isinstance(properties, dict):
        return None
    name = properties.get("scanner_name")
    if not isinstance(name, str) or not name:
        return None
    return SCANNER_NAME_MAP.get(name, name)


def find_matching_result(
    original_result: Dict,
    aggregated_results: List[Dict],
    exclude_ids: Optional[Set[int]] = None,
    scanner_name: Optional[str] = None,
    exact_only: bool = False,
    scan_root: Optional[str] = None,
    same_finding_only: bool = False,
) -> Optional[Dict]:
    """
    Find a matching result in the aggregated report using rule ID and location.

    Two results of one rule match when both carry a location and the locations
    match, or when neither carries one and their message texts, or failing those
    their ``analysisTarget`` URIs, are equal. A result with a location never
    matches one whose location differs, whatever else they share. A rule is
    named by ``ruleId`` or by ``rule.id``; two results that name no rule at all
    are the same finding only when their locations match and their messages,
    when both carry one, are equal, since a location alone is not a rule. With
    *scanner_name*, an aggregated result that records another scanner
    (``properties.scanner_name``) is not a match: one scanner's finding was
    paired with another scanner's result of the same rule id at the same place.
    Among the located results that match, one at the original's own file and
    lines is preferred over one whose range merely overlaps: the first
    overlapping result in file order used to win, so a second finding of the
    same rule a few lines away took the first original's place and left the
    exact copy to be reported as unmatched.

    Args:
        original_result: Result from original scanner report
        aggregated_results: List of results from aggregated report
        exclude_ids: ``id()`` of aggregated results already matched to another
            original, which are not offered again
        scanner_name: The normalized name of the scanner that reported
            *original_result*, when known
        exact_only: Offer no overlapping result: only one at the original's own
            file and lines (or, for results with no location, with an equal
            message or ``analysisTarget``). ``validate_sarif_aggregation`` takes
            every original's exact match this way before it offers overlaps.
        scan_root: The directory the scan was run on, when known: files are
            then compared whole relative to it (see ``file_paths_match``)
        same_finding_only: Offer only a result at the original's own file and
            lines that also carries its message text and, when both state one,
            its start column. Implies *exact_only*: of two findings of one rule
            on the same lines this finds the copy that is each one's own.

    Returns:
        Matching result or None
    """
    from automated_security_helper.utils.meta_analysis.locations_match import (
        locations_match,
    )

    exact_only = exact_only or same_finding_only

    # Extract matching criteria
    rule_id = _rule_identity(original_result)
    wanted_scanner = (
        SCANNER_NAME_MAP.get(scanner_name, scanner_name) if scanner_name else None
    )

    # Extract location info
    location_info = extract_location_info(original_result)
    original_located = _has_location(location_info)

    # The first result whose location overlaps the original's without being at
    # its exact file and lines; returned only when no exact one follows.
    overlapping_match: Optional[Dict] = None

    # Try to find a match
    for agg_result in aggregated_results:
        if exclude_ids and id(agg_result) in exclude_ids:
            continue
        # Match by rule ID first
        if _rule_identity(agg_result) != rule_id:
            continue
        if wanted_scanner is not None:
            recorded = _result_scanner(agg_result)
            if recorded is not None and recorded.lower() != wanted_scanner.lower():
                continue
        agg_location = extract_location_info(agg_result)
        agg_located = _has_location(agg_location)

        if original_located or agg_located:
            # A location on either side decides: it must be on both, and match.
            if (
                original_located
                and agg_located
                and locations_match(location_info, agg_location, scan_root)
            ):
                if rule_id is None and not _messages_agree(original_result, agg_result):
                    continue
                if _locations_equal(location_info, agg_location, scan_root):
                    if same_finding_only and not _same_finding(
                        original_result, agg_result
                    ):
                        continue
                    return agg_result
                if overlapping_match is None:
                    overlapping_match = agg_result
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

    return None if exact_only else overlapping_match


def _locations_equal(
    location_info: Dict, other: Dict, scan_root: Optional[str] = None
) -> bool:
    """Whether two ``extract_location_info`` dicts name one file and one line
    range: the same file once the URIs are read as paths, and equal start and
    end lines once digit strings are read as the integers they spell. Lines that
    read as no line are equal only when they are spelled alike."""
    from automated_security_helper.utils.meta_analysis.locations_match import (
        file_paths_match,
        lines_equal,
    )

    file_one, file_two = location_info.get("file_path"), other.get("file_path")
    if (file_one is None) != (file_two is None):
        return False
    if (
        file_one is not None
        and file_two is not None
        and not file_paths_match(file_one, file_two, scan_root)
    ):
        return False
    return all(
        lines_equal(location_info.get(key), other.get(key))
        for key in ("start_line", "end_line")
    )


def _messages_agree(original_result: Dict, agg_result: Dict) -> bool:
    """Whether two results' message texts are equal, when both carry a message."""
    if not (original_result.get("message") and agg_result.get("message")):
        return True
    return get_message_text(original_result) == get_message_text(agg_result)


def _start_column(result: Dict):
    """The ``startColumn`` of a result's first location, else None."""
    locations = result.get("locations")
    if not (isinstance(locations, list) and locations):
        return None
    first = locations[0]
    physical = first.get("physicalLocation") if isinstance(first, dict) else None
    if not isinstance(physical, dict):
        return None
    region = physical.get("region")
    if not region:
        root = physical.get("root")
        region = root.get("region") if isinstance(root, dict) else None
    return region.get("startColumn") if isinstance(region, dict) else None


def _same_finding(original_result: Dict, agg_result: Dict) -> bool:
    """Whether two results at one place also carry one message text and, when
    both state a start column, one start column."""
    from automated_security_helper.utils.meta_analysis.locations_match import (
        lines_equal,
    )

    if not _messages_agree(original_result, agg_result):
        return False
    column, agg_column = _start_column(original_result), _start_column(agg_result)
    return column is None or agg_column is None or lines_equal(column, agg_column)


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

    # Extract from locations array. A first location, or a physicalLocation,
    # that is JSON null or not an object carries no location; it raised
    # AttributeError out of the whole aggregation check.
    locations = result.get("locations")
    if isinstance(locations, list) and locations:
        loc = locations[0]
        if isinstance(loc, dict) and isinstance(loc.get("physicalLocation"), dict):
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
