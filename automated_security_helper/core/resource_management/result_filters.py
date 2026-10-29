# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Result filtering utilities for MCP scan results.

These functions filter and reshape the raw scan-result dict returned by
mcp_get_scan_results into smaller, purpose-specific views.
"""

import copy
from typing import Any, Dict, List, Optional
from automated_security_helper.utils.severity_ladder import result_severity

#: The per-severity buckets a summary carries, in the order the summary lists
#: them. ``suppressed`` is a bucket of its own, as it is in SummaryStats.
_SEVERITY_KEYS = ("critical", "high", "medium", "low", "info", "suppressed")

#: ``scanner_results[*].status`` -> the SummaryStats outcome counter it lands in.
_OUTCOME_COUNTERS = {
    "PASSED": "passed",
    "FAILED": "failed",
    "MISSING": "missing",
    "SKIPPED": "skipped",
    "ERROR": "error",
}


def _count(value: Any) -> int:
    """*value* as a count: an int that is not a bool, else 0."""
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _stats_of_scanners(scanner_results: Dict[str, Any]) -> Dict[str, Any]:
    """The SummaryStats fields recomputed from the per-scanner entries.

    What a results document's ``summary_stats`` would say for exactly these
    scanners: per-severity counts and ``total``, ``actionable`` and
    ``suppressed`` summed over them, and the outcome counters from their
    statuses. The summary of a filtered view is derived from this rather than
    copied from the whole scan's stats.
    """
    counts = dict.fromkeys(_SEVERITY_KEYS, 0)
    stats: Dict[str, Any] = {
        "total": 0,
        "actionable": 0,
        **dict.fromkeys(_OUTCOME_COUNTERS.values(), 0),
    }
    for data in scanner_results.values():
        if not isinstance(data, dict):
            continue
        for severity, value in (data.get("severity_counts") or {}).items():
            bucket = str(severity).lower()
            if bucket in counts:
                counts[bucket] += _count(value)
        stats["total"] += _count(data.get("finding_count"))
        stats["actionable"] += _count(data.get("actionable_finding_count"))
        counter = _OUTCOME_COUNTERS.get(str(data.get("status") or "").upper())
        if counter is not None:
            stats[counter] += 1
    stats["severity_counts"] = counts
    return stats


def filter_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """Filter results to return only summary information."""
    summary: Dict[str, Any] = {
        "success": True,
        "scan_id": results.get("scan_id"),
        "status": results.get("status"),
        "is_complete": results.get("is_complete"),
        "completion_time": results.get("completion_time"),
        "metadata": {},
        "findings_summary": {},
        "scanner_summary": {},
        "_filter": "summary",
    }

    raw_results = results.get("raw_results", {})
    metadata = raw_results.get("metadata", {})

    summary["metadata"] = {
        "generated_at": metadata.get("generated_at"),
        "ash_version": metadata.get("tool_version"),
        "scan_duration_seconds": metadata.get("summary_stats", {}).get("duration"),
        # Whether the repository's ignore files shrank the scan set, and by how
        # much. A summary that leaves it out reads the same for a scan that skipped
        # files as for one that read them all. None for results that carry no
        # record (no scan set was built, or an older ASH wrote them).
        "ignore_file_exclusions": metadata.get("ignore_file_exclusions"),
    }

    summary_stats = results.get("summary_stats") or {}
    scanner_results = raw_results.get("scanner_results", {})
    if not summary_stats and scanner_results:
        # A results document with no summary_stats (the workspace unified
        # results file) still carries every scanner's own counts, so the
        # summary is derived from them. Defaulting each count to 0 instead
        # reported such a scan as clean, indistinguishable from one that found
        # nothing.
        summary_stats = _stats_of_scanners(scanner_results)
    # SummaryStats serializes its per-severity tallies under "severity_counts"
    # (a ScannerSeverityCount), not at the top level. Reading the top level only
    # made every severity count zero for every real scan. The flat keys are
    # still honored as a fallback for a caller that hands in a flattened dict.
    severity_counts = summary_stats.get("severity_counts") or {}

    def _stat(name: str) -> Optional[int]:
        # None, not 0, when the document records nothing at all: a count the
        # results do not carry is unknown, and a zero here reads as "none found".
        return summary_stats.get(name, 0) if summary_stats else None

    def _severity(name: str) -> Optional[int]:
        if not summary_stats:
            return None
        return severity_counts.get(name, summary_stats.get(name, 0))

    summary["findings_summary"] = {
        "by_severity": {
            "critical": _severity("critical"),
            "high": _severity("high"),
            "medium": _severity("medium"),
            "low": _severity("low"),
            "info": _severity("info"),
            "suppressed": _severity("suppressed"),
            "total": _stat("total"),
            "actionable": _stat("actionable"),
        },
        "scan_stats": {
            "passed": _stat("passed"),
            "failed": _stat("failed"),
            "missing": _stat("missing"),
            "skipped": _stat("skipped"),
            # SummaryStats has five outcome counters; without this one the four
            # above did not sum to the scanner count when scanners ERRORed.
            "error": _stat("error"),
        },
    }
    summary["scanner_summary"] = {
        "by_scanner": {},
        "total_scanners": len(scanner_results),
        "completed_scanners": 0,
    }

    for scanner_name, scanner_data in scanner_results.items():
        status = scanner_data.get("status", "UNKNOWN")
        severity_counts = scanner_data.get("severity_counts", {})

        scanner_info = {
            "status": status,
            "findings_count": scanner_data.get("finding_count", 0),
            "actionable_findings": scanner_data.get("actionable_finding_count", 0),
            "suppressed_findings": scanner_data.get("suppressed_finding_count", 0),
            "duration": scanner_data.get("duration", 0),
            "by_severity": {
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
                "info": severity_counts.get("info", 0),
                "suppressed": severity_counts.get("suppressed", 0),
            },
        }

        summary["scanner_summary"]["by_scanner"][scanner_name] = scanner_info

        if status in ["PASSED", "FAILED"]:
            summary["scanner_summary"]["completed_scanners"] += 1

    return summary


def filter_minimal(results: Dict[str, Any]) -> Dict[str, Any]:
    """Filter results to return only minimal status information."""
    return {
        "success": True,
        "scan_id": results.get("scan_id"),
        "status": results.get("status"),
        "is_complete": results.get("is_complete"),
        "completion_time": results.get("completion_time"),
        "summary_stats": results.get("summary_stats", {}),
        "_filter": "minimal",
    }


def filter_actionable_only(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Filter results to the actionable findings, the ones that make a scan exit 2.

    A finding is actionable when it is not suppressed and is at or above the
    severity threshold the scan was judged by: its scanner's own threshold when
    the scan's config sets one, else the global one. That is the set
    ``run_ash_scan._compute_exit_code`` counts. Dropping only the suppressed
    findings would keep findings below the threshold, which the scan reports but
    does not fail on, so a client gating on them would fail a scan that exited 0.

    Returns a deep copy of *results* with the SARIF entries that are not
    actionable removed, and the suppressed counts zeroed. ``summary_stats.total``
    becomes ``summary_stats.actionable``, which the scan counted by the same
    thresholds.

    ``--min-severity``, a whole-scan switch of the CLI, is not applied: the
    results do not record it, and an MCP scan runs at its default ``low``, which
    every finding meets.

    Raises:
        ValueError: The results carry SARIF without the thresholds its findings
            were judged by (``raw_results["severity_thresholds"]``, written by
            ``scan_tracking.get_scan_results(include_sarif=True)``). Without them
            the actionable set cannot be told apart, and keeping either too much
            or nothing would read as an answer. Also when the SARIF was asked
            for and the document has none (``raw_results["sarif"]`` is None)
            while ``summary_stats.actionable`` is nonzero: the scan counted
            actionable findings that cannot be listed, and an empty list beside
            that count would read as "none".
    """
    filtered_results = copy.deepcopy(results)
    kept_counts: Optional[Dict[str, int]] = None

    raw = filtered_results.get("raw_results")
    if isinstance(raw, dict) and "sarif" in raw and raw["sarif"] is None:
        stats = filtered_results.get("summary_stats") or {}
        if _count(stats.get("actionable")) > 0:
            raise ValueError(
                "The scan's results carry no SARIF, so its "
                f"{stats.get('actionable')} actionable finding(s) cannot be listed"
            )

    if isinstance(raw, dict) and "sarif" in raw and isinstance(raw["sarif"], dict):
        sarif = filtered_results["raw_results"]["sarif"]
        thresholds = filtered_results["raw_results"].get("severity_thresholds")
        if "runs" in sarif:
            if not isinstance(thresholds, dict):
                raise ValueError(
                    "The scan's SARIF came without raw_results.severity_thresholds, "
                    "so which of its findings are actionable cannot be decided"
                )
            # The per-severity buckets of the kept findings. Left at the whole
            # scan's values, the buckets counted findings below the threshold
            # beside a total that counted only the actionable ones.
            kept_counts = dict.fromkeys(_SEVERITY_KEYS, 0)
            for run in sarif["runs"]:
                if "results" in run and run["results"]:
                    run["results"] = [
                        r
                        for r in run["results"]
                        if _counts_toward_exit_2(r, _threshold_for(r, thresholds))
                    ]
                    for r in run["results"]:
                        bucket = _get_finding_severity(r).lower()
                        if bucket in kept_counts:
                            kept_counts[bucket] += 1

    if "summary_stats" in filtered_results:
        summary_stats = filtered_results["summary_stats"]
        summary_stats["suppressed"] = 0
        # The real count lives under severity_counts; see filter_summary.
        if isinstance(summary_stats.get("severity_counts"), dict):
            summary_stats["severity_counts"]["suppressed"] = 0
        summary_stats["total"] = summary_stats.get("actionable", 0)
        # With the SARIF at hand the buckets follow the kept findings; without
        # it (the summary and minimal levels never load it) the document has no
        # per-severity split of the actionable count and the buckets stay.
        if kept_counts is not None:
            if isinstance(summary_stats.get("severity_counts"), dict):
                summary_stats["severity_counts"] = {
                    **summary_stats["severity_counts"],
                    **kept_counts,
                }
            for bucket, value in kept_counts.items():
                if bucket in summary_stats:
                    summary_stats[bucket] = value

    if (
        "raw_results" in filtered_results
        and "scanner_results" in filtered_results["raw_results"]
    ):
        for scanner_data in filtered_results["raw_results"]["scanner_results"].values():
            if "suppressed_finding_count" in scanner_data:
                scanner_data["suppressed_finding_count"] = 0
            if (
                "severity_counts" in scanner_data
                and "suppressed" in scanner_data["severity_counts"]
            ):
                scanner_data["severity_counts"]["suppressed"] = 0

    if "_content_filters" not in filtered_results:
        filtered_results["_content_filters"] = {}
    filtered_results["_content_filters"]["actionable_only"] = True

    return filtered_results


def _threshold_for(
    result: Dict[str, Any], thresholds: Dict[str, Optional[str]]
) -> Optional[str]:
    """The threshold *result* was judged by, from ``severity_thresholds``.

    Keyed by scanner name, ``""`` for a result that names none, which is the
    global threshold. A name missing from the map is judged by that too, as
    ``_compute_exit_code`` judges a scanner with no threshold of its own.
    """
    props = result.get("properties")
    name = props.get("scanner_name") if isinstance(props, dict) else None
    key = name if isinstance(name, str) else ""
    return thresholds[key] if key in thresholds else thresholds.get("")


def _counts_toward_exit_2(result: Dict[str, Any], threshold: Optional[str]) -> bool:
    """Whether ``_compute_exit_code`` counts *result* toward exit 2 at *threshold*.

    Its per-result test, step for step: a suppressed result never counts;
    ``properties.issue_severity`` decides when it names an ASH severity;
    otherwise the SARIF ``level`` does. Both comparisons are
    ``utils.severity_ladder``'s, so a falsy threshold counts nothing here too.
    """
    from automated_security_helper.utils.severity_ladder import (
        SEVERITIES,
        sarif_level_fails_threshold,
        severity_fails_threshold,
    )

    if result.get("suppressions"):
        return False
    props = result.get("properties")
    issue_severity = (
        str(props.get("issue_severity") or "").upper()
        if isinstance(props, dict)
        else ""
    )
    if issue_severity in SEVERITIES:
        return severity_fails_threshold(issue_severity, threshold)
    return sarif_level_fails_threshold(result.get("level"), threshold)


def apply_content_filters(
    results: Dict[str, Any],
    scanners: Optional[str] = None,
    severities: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Filter results by scanner names and/or severity levels.

    Args:
        results: The full scan results.
        scanners: Comma-separated scanner names (e.g., "bandit,semgrep").
        severities: Comma-separated severity levels (e.g., "critical,high").

    Returns:
        Filtered results with only matching scanners and severities.
    """
    scanner_list = (
        [s.strip().lower() for s in scanners.split(",")] if scanners else None
    )
    severity_list = (
        [s.strip().lower() for s in severities.split(",")] if severities else None
    )

    filtered_results = copy.deepcopy(results)

    if "scanner_reports" in filtered_results and scanner_list:
        filtered_results["scanner_reports"] = {
            name: data
            for name, data in filtered_results["scanner_reports"].items()
            if name.lower() in scanner_list
        }

    if (
        "raw_results" in filtered_results
        and "scanner_results" in filtered_results["raw_results"]
    ):
        orig = filtered_results["raw_results"]["scanner_results"]
        if scanner_list:
            new_scanner_results = {}
            for name, data in orig.items():
                if name.lower() in scanner_list:
                    if severity_list and "severity_counts" in data:
                        data = data.copy()
                        data["severity_counts"] = {
                            k: v
                            for k, v in data["severity_counts"].items()
                            if k.lower() in severity_list
                        }
                    new_scanner_results[name] = data
            filtered_results["raw_results"]["scanner_results"] = new_scanner_results
        elif severity_list:
            new_scanner_results = {}
            for name, data in orig.items():
                if "severity_counts" in data:
                    data = data.copy()
                    data["severity_counts"] = {
                        k: v
                        for k, v in data["severity_counts"].items()
                        if k.lower() in severity_list
                    }
                new_scanner_results[name] = data
            filtered_results["raw_results"]["scanner_results"] = new_scanner_results

    # The findings themselves, which add_findings_list reads. Narrowing only the
    # counts above left a findings list with every scanner and every severity in
    # it, so `severities="critical"` listed low findings too.
    sarif = filtered_results.get("raw_results", {}).get("sarif")
    if isinstance(sarif, dict) and (scanner_list or severity_list):
        for run in sarif.get("runs") or []:
            if run.get("results"):
                run["results"] = [
                    r
                    for r in run["results"]
                    if _sarif_result_selected(r, scanner_list, severity_list)
                ]

    if (
        "raw_results" in filtered_results
        and "additional_reports" in filtered_results["raw_results"]
        and scanner_list
    ):
        filtered_results["raw_results"]["additional_reports"] = {
            name: data
            for name, data in filtered_results["raw_results"][
                "additional_reports"
            ].items()
            if name.lower() in scanner_list
        }

    _severity_keys = set(_SEVERITY_KEYS)

    def _zero_unselected(counts: Dict[str, Any], selected: List[str]) -> Dict[str, Any]:
        return {
            key: (value if key not in _severity_keys or key.lower() in selected else 0)
            for key, value in counts.items()
        }

    # The summary follows the scanners kept. summary_stats, actionable_findings
    # and total_scanners are whole-scan values in the producer's output; left as
    # they were under a scanners filter, the summary reported other scanners'
    # findings beside a scanner_results map that no longer held them.
    if scanner_list and isinstance(filtered_results.get("summary_stats"), dict):
        kept = (filtered_results.get("raw_results") or {}).get("scanner_results")
        if isinstance(kept, dict):
            recount = _stats_of_scanners(kept)
            summary_stats = dict(filtered_results["summary_stats"])
            for key, value in recount.items():
                if key == "severity_counts":
                    continue
                if key in summary_stats:
                    summary_stats[key] = value
            if isinstance(summary_stats.get("severity_counts"), dict):
                summary_stats["severity_counts"] = {
                    **summary_stats["severity_counts"],
                    **recount["severity_counts"],
                }
            for bucket, value in recount["severity_counts"].items():
                if bucket in summary_stats:
                    summary_stats[bucket] = value
            filtered_results["summary_stats"] = summary_stats
            if "actionable_findings" in filtered_results:
                filtered_results["actionable_findings"] = recount["actionable"]
            if "total_scanners" in filtered_results:
                filtered_results["total_scanners"] = (
                    recount["passed"] + recount["failed"]
                )

    if severity_list and "summary_stats" in filtered_results:
        summary_stats = _zero_unselected(
            filtered_results["summary_stats"], severity_list
        )
        # The real per-severity counts are nested; see filter_summary. Filtering
        # only the top level left every count in place.
        if isinstance(summary_stats.get("severity_counts"), dict):
            summary_stats["severity_counts"] = _zero_unselected(
                summary_stats["severity_counts"], severity_list
            )
        # The total is the findings in the selected buckets, not the whole
        # scan's: a view that lists only critical and high findings and says
        # "total 17" reports findings it does not show.
        buckets = (
            summary_stats["severity_counts"]
            if isinstance(summary_stats.get("severity_counts"), dict)
            else summary_stats
        )
        if "total" in summary_stats:
            summary_stats["total"] = sum(
                _count(buckets.get(bucket)) for bucket in _SEVERITY_KEYS
            )
        # actionable is recounted when the findings it counts are at hand: the
        # SARIF results kept above, judged by the thresholds the scan recorded.
        # Without the SARIF (the summary and minimal levels never load it) the
        # per-severity split of the actionable count is not in the document,
        # and the whole-scan value stays.
        if "actionable" in summary_stats and isinstance(sarif, dict):
            thresholds = (filtered_results.get("raw_results") or {}).get(
                "severity_thresholds"
            )
            if isinstance(thresholds, dict):
                summary_stats["actionable"] = sum(
                    1
                    for run in sarif.get("runs") or []
                    for result in run.get("results") or []
                    if _counts_toward_exit_2(result, _threshold_for(result, thresholds))
                )
                if "actionable_findings" in filtered_results:
                    filtered_results["actionable_findings"] = summary_stats[
                        "actionable"
                    ]
        filtered_results["summary_stats"] = summary_stats

    filter_metadata: Dict[str, Any] = {}
    if scanner_list:
        filter_metadata["scanners"] = scanner_list
    if severity_list:
        filter_metadata["severities"] = severity_list
    filtered_results["_content_filters"] = filter_metadata

    return filtered_results


def _sarif_result_selected(
    result: Dict[str, Any],
    scanner_list: Optional[List[str]],
    severity_list: Optional[List[str]],
) -> bool:
    """Whether a SARIF result passes the scanner and severity filters.

    A suppressed result is in the ``suppressed`` bucket rather than its own
    severity's, as it is in the severity counts, so ``severities="high"`` does
    not select a suppressed high finding and ``severities="suppressed"`` does.
    A result that names no scanner matches no scanner filter.
    """
    if scanner_list:
        props = result.get("properties") or {}
        scanner = props.get("scanner_name") if isinstance(props, dict) else None
        if not isinstance(scanner, str) or scanner.lower() not in scanner_list:
            return False
    if severity_list:
        if result.get("suppressions"):
            return "suppressed" in severity_list
        return _get_finding_severity(result).lower() in severity_list
    return True


def _get_finding_severity(result: Dict[str, Any]) -> str:
    """
    Determine the severity of a SARIF finding.

    Checks explicit issue_severity in properties first, then falls back to
    mapping the SARIF level to a severity string.

    Args:
        result: A single SARIF result dict

    Returns:
        Uppercase severity string (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    """
    # The gate's rule, shared with every report: utils.severity_ladder.
    return result_severity(result)


def add_findings_list(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract a flat list of actionable findings from SARIF results and add it
    to the top level of the response for easy consumption.

    This provides a clear, focused list of findings that require attention,
    rather than requiring consumers to navigate the nested SARIF structure.

    Args:
        results: The filtered scan results (after actionable_only and severity filters)

    Returns:
        Results with an added top-level 'findings' list
    """
    findings_list = []

    # Extract findings from SARIF runs. ``sarif`` is None for a document that
    # was asked for its SARIF and has none (scan_tracking.get_scan_results).
    sarif = results.get("raw_results", {}).get("sarif") or {}
    if "runs" in sarif:
        for run in sarif["runs"]:
            for result in run.get("results", []):
                props = result.get("properties", {}) or {}
                locations = result.get("locations", [])

                # Extract location info
                file_path = None
                line_start = None
                line_end = None
                if locations:
                    phys_loc = (
                        locations[0].get("physicalLocation", {}) if locations else {}
                    )
                    artifact_loc = phys_loc.get("artifactLocation", {})
                    file_path = artifact_loc.get("uri")
                    region = phys_loc.get("region", {})
                    line_start = region.get("startLine")
                    line_end = region.get("endLine")

                finding = {
                    "rule_id": result.get("ruleId"),
                    "severity": _get_finding_severity(result),
                    "message": (
                        result.get("message", {}).get("text")
                        or result.get("message", {}).get("markdown")
                    ),
                    "scanner": props.get("scanner_name"),
                    "file_path": file_path,
                    "line_start": line_start,
                    "line_end": line_end,
                }

                # Only include non-None values
                finding = {k: v for k, v in finding.items() if v is not None}
                findings_list.append(finding)

    results["findings"] = findings_list
    results["findings_count"] = len(findings_list)

    return results
