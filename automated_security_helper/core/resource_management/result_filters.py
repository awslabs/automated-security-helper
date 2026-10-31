# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Result filtering utilities for MCP scan results.

These functions filter and reshape the raw scan-result dict returned by
mcp_get_scan_results into smaller, purpose-specific views.
"""

import copy
from typing import Any, Dict, List, Optional, TypeGuard
from automated_security_helper.utils.severity_ladder import (
    SEVERITY_THRESHOLDS,
    result_severity,
)

#: The result property the workspace aggregator sets when it writes a rebased
#: location's ``uri`` percent-encoded: the path that ``uri`` names, as plain
#: text. Spelled as ``flat_vulnerability.ARTIFACT_PATH_PROPERTY`` spells it (a
#: test compares them), because that module is not imported here.
ARTIFACT_PATH_PROPERTY = "workspace_artifact_path"

#: The per-severity buckets a summary carries, in the order the summary lists
#: them. ``suppressed`` is a bucket of its own, as it is in SummaryStats.
_SEVERITY_KEYS = ("critical", "high", "medium", "low", "info", "suppressed")

#: The buckets ``total`` counts. SummaryStats.total is "the sum of all
#: non-suppressed severity counts" (models/asharp_model.py), and the per-scanner
#: ``finding_count`` the aggregated file carries is ScannerMetrics.total, the same
#: rule (core/unified_metrics.py). ``suppressed`` is a count beside the total, not
#: part of it. Two recounts here used to define total differently: one summed
#: ``finding_count``, the other every bucket including suppressed, so the same
#: scanner read as 5 findings under a scanners filter and 6 under a severities
#: filter that selected all six buckets.
_COUNTED_SEVERITY_KEYS = ("critical", "high", "medium", "low", "info")

#: ``scanner_results[*].status`` -> the SummaryStats outcome counter it lands in.
_OUTCOME_COUNTERS = {
    "PASSED": "passed",
    "FAILED": "failed",
    "MISSING": "missing",
    "SKIPPED": "skipped",
    "ERROR": "error",
}


#: The coverage fields a results document carries beside ``status``: whether the
#: scan covered everything, and the gap lists that say what it did not
#: (``ScanIncompleteness.to_payload()``). A summary that keeps ``status``
#: "incomplete" and drops these names an incomplete scan without saying what is
#: missing.
_COVERAGE_KEYS = (
    "coverage_complete",
    "incomplete_scanners",
    "no_scanner_ran",
    "incomplete_converters",
    "unevaluated_rules",
    "stale_content_databases",
    "could_not_stop",
)


class ResultFilterInputError(ValueError):
    """A filter argument the results cannot honor: an unknown scanner or severity name.

    Still a ValueError, so a caller that catches that catches this. The
    ``error_category`` is what the server's response should carry for it
    (``ErrorCategory.INVALID_PARAMETER``): a client's typo is the client's input
    error, and it used to leave through the server's unexpected-error handler,
    logged as a server fault with no category a client could branch on.
    """

    error_category = "invalid_parameter"


def _count(value: Any) -> int:
    """*value* as a count: an int that is not a bool, else 0."""
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _coverage_fields(results: Dict[str, Any]) -> Dict[str, Any]:
    """The coverage fields *results* carries, for a view that keeps ``status``."""
    return {key: results[key] for key in _COVERAGE_KEYS if key in results}


def _outcome_counter(data: Dict[str, Any]) -> Optional[str]:
    """The SummaryStats outcome counter a ``scanner_results`` entry feeds, or None.

    An entry with no ``status`` key is read as PASSED, as the results model
    reads it (and as ``scan_tracking`` reads the same entry); counted as no
    outcome, it left ``passed`` and the scanner total short, and the actionable
    count a lower bound shown as exact. A status that is not a string, or a
    word the model does not have, feeds no counter.
    """
    status = data.get("status", "PASSED")
    if not isinstance(status, str):
        return None
    return _OUTCOME_COUNTERS.get(status.upper())


def _records_a_breakdown(severity_counts: Any) -> TypeGuard[Dict[Any, Any]]:
    """Whether *severity_counts* names at least one bucket with a usable count.

    An object that is empty, or holds only keys the summary has no bucket for
    and values that are not counts, records no breakdown: the row's
    ``finding_count`` is then the only record of what the scanner found, as it
    is for a row with no ``severity_counts`` at all.
    """
    return isinstance(severity_counts, dict) and any(
        str(severity).lower() in _SEVERITY_KEYS
        and isinstance(value, int)
        and not isinstance(value, bool)
        for severity, value in severity_counts.items()
    )


def _total_of(counts: Dict[str, Any]) -> int:
    """``total`` by the one rule: the non-suppressed buckets of *counts*."""
    return sum(_count(counts.get(bucket)) for bucket in _COUNTED_SEVERITY_KEYS)


def _total_of_known(counts: Dict[str, Any]) -> Optional[int]:
    """``_total_of``, or None when a counted bucket of *counts* is unknown.

    A bucket present with the value None is a count the document records as
    unknown (``_stats_of_scanners`` writes it for a row that counts findings and
    records no breakdown). Reading it as 0 would put an exact-looking total
    beside a bucket the same view reports as unknown. A bucket that is absent
    reads 0, as in a recorded summary, which writes all six.
    """
    if any(
        bucket in counts and counts[bucket] is None
        for bucket in _COUNTED_SEVERITY_KEYS
    ):
        return None
    return _total_of(counts)


def _stats_of_scanners(scanner_results: Dict[str, Any]) -> Dict[str, Any]:
    """The SummaryStats fields recomputed from the per-scanner entries.

    What a results document's ``summary_stats`` would say for exactly these
    scanners: per-severity counts and ``total``, ``actionable`` and
    ``suppressed`` summed over them, and the outcome counters from their
    statuses. The summary of a filtered view is derived from this rather than
    copied from the whole scan's stats.

    A scanner's ``total`` is its non-suppressed buckets when it records a
    breakdown, a ``severity_counts`` object naming at least one usable bucket
    (the rule SummaryStats.total follows), else its ``finding_count``: a
    per-target file written before the metrics pass can carry a finding_count
    that counted suppressed findings too, and an empty ``severity_counts``
    object records nothing beside a count of 4.

    ``actionable`` is None, not 0, when a scanner that ran (PASSED or FAILED)
    records no ``actionable_finding_count``: a count the entries do not carry is
    unknown, and a zero here read as "nothing actionable" for a workspace file
    whose scanner entries never had the field. It used to be summed over the
    entries that carried it, so with a mix the sum was a lower bound shown as an
    exact number. A scanner that did not run (MISSING, SKIPPED, ERROR) has no
    actionable findings to count and may lack the field without making the sum
    unknown: a set made only of such scanners has 0 actionable findings, which
    is known. Starting the sum at None made that set read as unknown.

    When a row counts findings but records no breakdown (see
    :func:`_rows_without_a_breakdown`), no per-severity bucket of the set is
    known: each is None, beside a ``total`` that is exact. Left at the sum of
    the other rows' buckets, they read as exact numbers beside a total that
    counted findings they do not hold.
    """
    counts = dict.fromkeys(_SEVERITY_KEYS, 0)
    stats: Dict[str, Any] = {
        "total": 0,
        "actionable": 0,
        **dict.fromkeys(_OUTCOME_COUNTERS.values(), 0),
    }
    actionable_unknown = False
    for data in scanner_results.values():
        if not isinstance(data, dict):
            continue
        severity_counts = data.get("severity_counts")
        own_counts: Dict[str, int] = {}
        if _records_a_breakdown(severity_counts):
            for severity, value in severity_counts.items():
                bucket = str(severity).lower()
                if bucket in counts:
                    counts[bucket] += _count(value)
                    own_counts[bucket] = own_counts.get(bucket, 0) + _count(value)
            stats["total"] += _total_of(own_counts)
        else:
            stats["total"] += _count(data.get("finding_count"))
        counter = _outcome_counter(data)
        if counter is not None:
            stats[counter] += 1
        actionable = data.get("actionable_finding_count")
        if isinstance(actionable, int) and not isinstance(actionable, bool):
            stats["actionable"] = (stats["actionable"] or 0) + actionable
        elif counter in ("passed", "failed"):
            actionable_unknown = True
    if actionable_unknown:
        stats["actionable"] = None
    stats["severity_counts"] = (
        dict.fromkeys(_SEVERITY_KEYS)
        if _rows_without_a_breakdown(scanner_results)
        else counts
    )
    return stats


def _rows_without_a_breakdown(scanner_results: Dict[str, Any]) -> bool:
    """Whether a scanner row counts findings but records no severity breakdown.

    ``_stats_of_scanners`` adds such a row's ``finding_count`` to the total and
    nothing to any bucket (it has none to add), so the buckets of the derived
    stats are a lower bound beside an exact total: 0 per severity next to a
    total of 4. The summary reports them as unknown instead.
    """
    return any(
        isinstance(data, dict)
        and not _records_a_breakdown(data.get("severity_counts"))
        and _count(data.get("finding_count")) > 0
        for data in scanner_results.values()
    )


def _seed_scanners_the_sarif_never_named(
    raw_results: Dict[str, Any], kept_per_scanner: Dict[str, Dict[str, int]]
) -> None:
    """Give every PASSED or FAILED scanner row the SARIF never named zero kept buckets.

    Called by ``filter_actionable_only`` once the SARIF's results have been
    read, and only when the SARIF can attribute its results (see the call).
    A scanner that ran and has no result in the SARIF has nothing kept, so its
    row recounts to zero and its actionable count is known. Scanners that did
    not run (MISSING, SKIPPED, ERROR) are left as they are: ``_stats_of_scanners``
    already reads them as nothing actionable.
    """
    rows = raw_results.get("scanner_results")
    if not isinstance(rows, dict):
        return
    for name, data in rows.items():
        if not isinstance(data, dict):
            continue
        counter = _outcome_counter(data)
        if counter in ("passed", "failed"):
            kept_per_scanner.setdefault(name, dict.fromkeys(_SEVERITY_KEYS, 0))


def filter_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """Filter results to return only summary information.

    The coverage fields (``coverage_complete`` and the gap lists) travel with
    ``status``: a summary that said "incomplete" and dropped them left the
    client no way to see which scanners did not run.

    Every count under ``findings_summary.by_severity`` and ``scan_stats`` is an
    int or None. None means the document records no such count (a results file
    with no ``summary_stats`` and no scanner entries to derive one from, a
    ``summary_stats`` without the counter, as one written before the ``error``
    counter existed, or scanner entries that carry no
    ``actionable_finding_count``); it is never a stand-in for 0, and a client
    that compares or adds these reads None first. The per-severity buckets of a
    recorded summary are the one exception: SummaryStats writes all six, so a
    bucket missing from one reads 0.
    """
    summary: Dict[str, Any] = {
        "success": True,
        "scan_id": results.get("scan_id"),
        "status": results.get("status"),
        "is_complete": results.get("is_complete"),
        "completion_time": results.get("completion_time"),
        **_coverage_fields(results),
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
    # Whether the derived total counts findings that no severity bucket does.
    buckets_unknown = False
    if not summary_stats and scanner_results:
        buckets_unknown = _rows_without_a_breakdown(scanner_results)
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
        # None, not 0, when the document records no such count: a count the
        # results do not carry is unknown, and a zero here reads as "none found".
        # That held for an absent summary and not for a counter absent from a
        # recorded one, so a summary written before the `error` counter existed
        # reported `error: 0`.
        return summary_stats.get(name) if summary_stats else None

    def _severity(name: str) -> Optional[int]:
        # A derived total that counts findings of a scanner with no breakdown
        # has no per-severity answer: the buckets read 0 beside a total of 4.
        if not summary_stats or buckets_unknown:
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
        # Every scanner in the results, whatever its status. The top-level
        # total_scanners of the same results counts only the scanners that ran
        # to an end (PASSED or FAILED); see ScanProgress.total_scanners.
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
    """Filter results to return only minimal status information.

    The coverage fields travel with ``status``, as in :func:`filter_summary`.
    """
    return {
        "success": True,
        "scan_id": results.get("scan_id"),
        "status": results.get("status"),
        "is_complete": results.get("is_complete"),
        "completion_time": results.get("completion_time"),
        **_coverage_fields(results),
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

    When the SARIF was asked for and the document has none (``raw_results["sarif"]``
    is None) while ``summary_stats.actionable`` is nonzero, the scan counted
    actionable findings that cannot be listed. The response says so instead of
    being refused whole: ``findings_available`` is False (the key
    ``add_findings_list`` sets, so an empty list beside it reads as "could not
    be listed", not "none") and a warning names the count. The refusal threw
    away the status, coverage fields and counts the document still carried.

    A document whose ``summary_stats`` is empty (the workspace unified results
    file carries none, and the producer puts ``{}`` in its place) gets its
    summary derived from the per-scanner rows as this filter leaves them. Writing
    ``suppressed`` and ``total`` into that empty dict made it non-empty, so
    :func:`filter_summary` never derived one and the view read every bucket 0, a
    workspace scan reported as clean. ``total`` is None, not 0, for a recorded
    summary that carries no ``actionable`` count: unknown, not "nothing".

    Raises:
        ValueError: The results carry SARIF without the thresholds its findings
            were judged by (``raw_results["severity_thresholds"]``, written by
            ``scan_tracking.get_scan_results(include_sarif=True)``). Without them
            the actionable set cannot be told apart, and keeping either too much
            or nothing would read as an answer.
    """
    filtered_results = copy.deepcopy(results)
    kept_counts: Optional[Dict[str, int]] = None
    # Per scanner named in the SARIF: the kept findings' severity buckets. The
    # per-scanner entries used to keep their whole-scan finding_count and
    # severity_counts under this filter, with only their suppressed counts
    # zeroed, so a scanner's row counted findings the view no longer listed.
    kept_per_scanner: Dict[str, Dict[str, int]] = {}
    # Whether the SARIF held any result before the filter: with results it
    # attributes them only when they name their scanner; with none, every
    # scanner that ran has nothing kept.
    saw_a_result = False

    raw = filtered_results.get("raw_results")
    if isinstance(raw, dict) and "sarif" in raw and raw["sarif"] is None:
        stats = filtered_results.get("summary_stats")
        actionable = stats.get("actionable") if isinstance(stats, dict) else None
        if _count(actionable) > 0:
            filtered_results["findings_available"] = False
            warnings = filtered_results.get("warnings")
            if not isinstance(warnings, list):
                warnings = filtered_results["warnings"] = []
            warnings.append(
                "The scan's results carry no SARIF, so its "
                f"{actionable} actionable finding(s) cannot be listed"
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
            # A workspace document's per-project gates; empty for a single scan.
            projects = _workspace_project_gates(filtered_results["raw_results"])
            for run in sarif["runs"]:
                if "results" in run and run["results"]:
                    saw_a_result = True
                    for r in run["results"]:
                        name = _sarif_scanner_name(r)
                        if name is not None:
                            kept_per_scanner.setdefault(
                                name, dict.fromkeys(_SEVERITY_KEYS, 0)
                            )
                    run["results"] = [
                        r
                        for r in run["results"]
                        if _actionable_in_view(r, thresholds, projects)
                    ]
                    for r in run["results"]:
                        bucket = _get_finding_severity(r).lower()
                        if bucket in kept_counts:
                            kept_counts[bucket] += 1
                        name = _sarif_scanner_name(r)
                        if name is not None and bucket in kept_per_scanner[name]:
                            kept_per_scanner[name][bucket] += 1
            # The SARIF is the one document that holds every finding, so a
            # scanner that ran (PASSED or FAILED) and that it never names has
            # none: nothing kept, actionable 0, which is known. Left unnamed,
            # such a row kept its shape, and a workspace row has no
            # actionable_finding_count, so the derived summary read the whole
            # document's actionable and total as None beside findings the SARIF
            # had decided. Only when the SARIF can attribute: its results carry
            # scanner names (some scanner was named), or it has no results at
            # all. A SARIF whose results name no scanner attributes nothing and
            # seeds nothing.
            if kept_per_scanner or not saw_a_result:
                _seed_scanners_the_sarif_never_named(
                    filtered_results["raw_results"], kept_per_scanner
                )

    # The per-scanner rows first: the summary below may be derived from them.
    scanner_rows = None
    if (
        "raw_results" in filtered_results
        and "scanner_results" in filtered_results["raw_results"]
    ):
        scanner_rows = filtered_results["raw_results"]["scanner_results"]
        for name, scanner_data in scanner_rows.items():
            if not isinstance(scanner_data, dict):
                continue
            if "suppressed_finding_count" in scanner_data:
                scanner_data["suppressed_finding_count"] = 0
            if (
                "severity_counts" in scanner_data
                and "suppressed" in scanner_data["severity_counts"]
            ):
                scanner_data["severity_counts"]["suppressed"] = 0
            # A scanner the SARIF names follows its kept findings: the count,
            # the actionable count (every kept finding is actionable) and the
            # buckets. A scanner the SARIF never named has no findings to
            # recount from and keeps its row.
            kept = kept_per_scanner.get(name)
            if kept is None:
                continue
            kept_total = sum(kept.values())
            if "finding_count" in scanner_data:
                scanner_data["finding_count"] = kept_total
            # Set whether or not the row carried the field: every kept finding
            # is actionable, so the count is known. Written only when the key
            # was there, a later scanners filter recounted actionable, and so
            # total, as None for a row that never had it.
            scanner_data["actionable_finding_count"] = kept_total
            if isinstance(scanner_data.get("severity_counts"), dict):
                scanner_data["severity_counts"] = {
                    **scanner_data["severity_counts"],
                    **kept,
                }

    if "summary_stats" in filtered_results:
        summary_stats = filtered_results["summary_stats"]
        if not isinstance(summary_stats, dict) or not summary_stats:
            # The workspace unified results file carries no summary_stats and
            # the producer puts {} in its place. Writing suppressed 0 and total
            # 0 into that dict made it non-empty, so filter_summary's derivation
            # from the scanner rows never ran and the view read every bucket 0:
            # a workspace scan reported as clean. Derived here from the rows as
            # this filter just left them; with nothing to derive from, the
            # summary stays as it was and filter_summary reports None.
            if isinstance(scanner_rows, dict) and scanner_rows:
                summary_stats = _stats_of_scanners(scanner_rows)
                filtered_results["summary_stats"] = summary_stats
            else:
                summary_stats = None
        if summary_stats:
            summary_stats["suppressed"] = 0
            # The real count lives under severity_counts; see filter_summary.
            if isinstance(summary_stats.get("severity_counts"), dict):
                summary_stats["severity_counts"]["suppressed"] = 0
            # None, not 0, for a summary that records no actionable count: the
            # view's total is then unknown, and 0 read as "nothing actionable".
            summary_stats["total"] = summary_stats.get("actionable")
            # With the SARIF at hand the buckets follow the kept findings;
            # without it (the summary and minimal levels never load it) the
            # document has no per-severity split of the actionable count and
            # the buckets stay.
            if kept_counts is not None:
                if isinstance(summary_stats.get("severity_counts"), dict):
                    summary_stats["severity_counts"] = {
                        **summary_stats["severity_counts"],
                        **kept_counts,
                    }
                for bucket, value in kept_counts.items():
                    if bucket in summary_stats:
                        summary_stats[bucket] = value

    if "_content_filters" not in filtered_results:
        filtered_results["_content_filters"] = {}
    filtered_results["_content_filters"]["actionable_only"] = True

    return filtered_results


#: The ``properties.origin`` value the workspace executor writes on a finding from
#: a scanner only the workspace policy added (``workspace.aggregation.POLICY_ORIGIN``,
#: spelled here so this module does not import the workspace; a test pins the two
#: equal).
_POLICY_ORIGIN = "workspace-policy"


def _workspace_project_gates(raw_results: Any) -> Dict[str, Dict[str, Any]]:
    """Per workspace project key, the gates its verdict graded its findings by.

    Read off ``raw_results["workspace"]["projects"]``, which a workspace results
    document carries (``get_scan_results`` dumps the whole model but the config
    and the reports) and a single scan's does not. Each entry holds the project's
    gate threshold (``severity_threshold``), its recorded per-scanner thresholds
    (``scanner_thresholds``) and whether a policy scanner's findings decided its
    verdict (``policy_scanners_gate``: True, False, or None for a file written
    before the field existed, whose verdict applied the gate), as
    ``WorkspaceProjectResult`` records them. Empty for a single scan, so every
    reader of it falls through to the scanner-keyed ``severity_thresholds`` map.

    A scanner named in the entry's ``withheld_scanner_thresholds`` was graded
    by a threshold the scan read from an environment variable, and the value is
    not published. Grading its findings by the project gate would call a
    finding non-actionable that the project's own count included whenever the
    withheld value is the stricter one, so such a scanner is graded by the
    strictest threshold (``ALL``): the view lists every unsuppressed finding of
    it, the side that cannot hide an actionable finding.

    Why this is needed: ``severity_thresholds`` is resolved from the results'
    ``ash_config``, which a workspace's unified file does not carry, so for that
    file every entry reads ASH's default and every project's findings were judged
    by one threshold while each project's verdict used its own.
    """
    if not isinstance(raw_results, dict):
        return {}
    workspace = raw_results.get("workspace")
    if not isinstance(workspace, dict):
        return {}
    gates: Dict[str, Dict[str, Any]] = {}
    for entry in workspace.get("projects") or []:
        if not isinstance(entry, dict):
            continue
        key = entry.get("project")
        if not isinstance(key, str) or not key:
            continue
        threshold = entry.get("severity_threshold")
        scanners = entry.get("scanner_thresholds")
        withheld = entry.get("withheld_scanner_thresholds")
        own_gates = {
            str(name): value
            for name, value in (scanners.items() if isinstance(scanners, dict) else ())
            if isinstance(value, str) and value
        }
        for name in withheld if isinstance(withheld, list) else ():
            if isinstance(name, str) and name:
                own_gates.setdefault(name, SEVERITY_THRESHOLDS[0])
        gates[key] = {
            "threshold": threshold
            if isinstance(threshold, str) and threshold
            else None,
            "scanners": own_gates,
            "policy_gate": (
                entry["policy_scanners_gate"]
                if isinstance(entry.get("policy_scanners_gate"), bool)
                else None
            ),
        }
    return gates


def _project_of(result: Dict[str, Any]) -> Optional[str]:
    """The workspace project *result* is attributed to, or None."""
    props = result.get("properties")
    project = props.get("workspace_project") if isinstance(props, dict) else None
    return project if isinstance(project, str) and project else None


def _sarif_scanner_name(result: Dict[str, Any]) -> Optional[str]:
    """The scanner a SARIF result names in ``properties.scanner_name``, or None."""
    props = result.get("properties")
    name = props.get("scanner_name") if isinstance(props, dict) else None
    return name if isinstance(name, str) and name else None


def _threshold_for(
    result: Dict[str, Any],
    thresholds: Dict[str, Optional[str]],
    projects: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Optional[str]:
    """The threshold *result* was judged by, from ``severity_thresholds``.

    Keyed by scanner name, ``""`` for a result that names none, which is the
    global threshold. A name missing from the map is judged by that too, as
    ``_compute_exit_code`` judges a scanner with no threshold of its own.

    *projects* is :func:`_workspace_project_gates`. A result attributed to one
    of its projects is judged as that project's verdict judged it: by the
    scanner's recorded own threshold when the project recorded one, else by the
    project's gate; the scanner-keyed map is read only for a result no project
    claims, or a project whose entry recorded no gate.
    """
    props = result.get("properties")
    name = props.get("scanner_name") if isinstance(props, dict) else None
    key = name if isinstance(name, str) else ""
    if projects:
        project = _project_of(result)
        gate = projects.get(project) if project is not None else None
        if gate is not None:
            own = gate["scanners"].get(key) if key else None
            if own:
                return own
            if gate["threshold"]:
                return gate["threshold"]
    return thresholds[key] if key in thresholds else thresholds.get("")


def _excluded_by_policy(
    result: Dict[str, Any], projects: Optional[Dict[str, Dict[str, Any]]]
) -> bool:
    """Whether *result*'s project excluded it from its verdict as a policy finding.

    A finding from a scanner only the workspace policy added carries
    ``properties.origin: workspace-policy``; with the project's
    ``policy_scanners_gate`` explicitly off, the verdict reported it and left it
    out of ``actionable_finding_count`` (``execution.py``'s gating results). The
    actionable view follows the verdict, so such a finding is not kept. Only an
    explicit False excludes: a project whose entry carries no gate (a file
    written before the field existed, whose verdict applied the gate) and a
    project the workspace block does not list are both judged by the threshold,
    the fail-closed side.
    """
    if not projects:
        return False
    props = result.get("properties")
    if not isinstance(props, dict) or props.get("origin") != _POLICY_ORIGIN:
        return False
    project = _project_of(result)
    gate = projects.get(project) if project is not None else None
    return gate is not None and gate["policy_gate"] is False


def _actionable_in_view(
    result: Dict[str, Any],
    thresholds: Dict[str, Optional[str]],
    projects: Optional[Dict[str, Dict[str, Any]]],
) -> bool:
    """Whether the actionable view keeps *result*: exit 2's test, by its own gates."""
    if _excluded_by_policy(result, projects):
        return False
    return _counts_toward_exit_2(result, _threshold_for(result, thresholds, projects))


def _counts_toward_exit_2(result: Dict[str, Any], threshold: Optional[str]) -> bool:
    """Whether ``_compute_exit_code`` counts *result* toward exit 2 at *threshold*.

    Its per-result test, step for step: a suppressed result never counts, where
    suppressed means a suppression in effect (``sarif_utils.is_result_suppressed``:
    a ``rejected`` or ``underReview`` one hides nothing, SARIF 3.35.4);
    ``properties.issue_severity`` decides when it names an ASH severity;
    otherwise the SARIF ``level`` does. Both comparisons are
    ``utils.severity_ladder``'s, so a falsy threshold counts nothing here too.
    """
    from automated_security_helper.utils.sarif_utils import is_result_suppressed
    from automated_security_helper.utils.severity_ladder import (
        SEVERITIES,
        sarif_level_fails_threshold,
        severity_fails_threshold,
    )

    if is_result_suppressed(result):
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

    Raises:
        ResultFilterInputError: A severity name that is not one of the summary's
            buckets, or a scanner name the results do not know (none of
            ``scanner_results``, ``scanner_reports``, ``additional_reports`` or
            the SARIF names it). An unrecognized name used to match nothing, so
            a typo returned a success response with every count zeroed and no
            findings, which reads as a clean scan. A ValueError subclass whose
            ``error_category`` names the client's input as the cause.

    A name that is only whitespace, or a list of separators, is no filter: it
    used to become a list of empty names that matched nothing and removed every
    finding and count.

    Applied after ``filter_actionable_only`` (the server's order), the recounts
    below keep its contract: ``summary_stats.total`` stays the actionable count,
    and ``_content_filters`` keeps its ``actionable_only`` flag beside the
    scanner and severity lists. The recounts used to overwrite the total with a
    count of every finding the kept scanners or buckets held, so an
    "actionable only" view reported findings it did not list, and the metadata
    was replaced outright, so the flag was lost.

    Under a ``severities`` filter without the SARIF at hand, ``actionable`` is
    None (unknown) unless the selection decides it: every counted bucket
    selected keeps the whole scan's count, none of them selected makes it 0.
    The whole-scan count used to stay under a partial selection, so a view of
    the low findings alone reported the scan's critical findings as actionable.

    Under a ``scanners`` filter that keeps a scanner only the SARIF names (no
    row of its own in ``scanner_results``), the summary is derived from the
    kept SARIF results. Derived from the empty row set, it read every count 0
    beside a findings list that was not empty.
    """
    scanner_list = _filter_names(scanners)
    severity_list = _filter_names(severities)

    if severity_list:
        unknown = sorted(set(severity_list) - set(_SEVERITY_KEYS))
        if unknown:
            raise ResultFilterInputError(
                f"Unknown severity name(s) {', '.join(unknown)}; the severities "
                f"are {', '.join(_SEVERITY_KEYS)}"
            )
    if scanner_list:
        known = _scanner_names_in(results)
        if known is not None:
            unknown = sorted(set(scanner_list) - known)
            if unknown:
                raise ResultFilterInputError(
                    f"Unknown scanner name(s) {', '.join(unknown)}; the scan's "
                    f"scanners are {', '.join(sorted(known)) or 'none'}"
                )

    already_applied = results.get("_content_filters")
    if not isinstance(already_applied, dict):
        already_applied = {}
    actionable_only = bool(already_applied.get("actionable_only"))

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
                        data = _scanner_row_at_severities(data, severity_list)
                    new_scanner_results[name] = data
            filtered_results["raw_results"]["scanner_results"] = new_scanner_results
        elif severity_list:
            new_scanner_results = {}
            for name, data in orig.items():
                if "severity_counts" in data:
                    data = _scanner_row_at_severities(data, severity_list)
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
            if not kept and isinstance(sarif, dict):
                # The kept scanner has no row of its own (the SARIF alone names
                # it), so its counts come from the SARIF results kept above.
                # The outcome counters stay 0: no row says whether it passed.
                thresholds = (filtered_results.get("raw_results") or {}).get(
                    "severity_thresholds"
                )
                projects = _workspace_project_gates(filtered_results.get("raw_results"))
                recount.update(_stats_of_sarif(sarif, thresholds, projects))
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
                    if kept or not isinstance(sarif, dict)
                    else len(_sarif_scanner_names(sarif))
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
        # "total 17" reports findings it does not show. By the one rule, the
        # suppressed bucket is not part of it: selecting "suppressed" lists the
        # suppressed findings under their own count with a total of 0, as
        # SummaryStats reports them. A selected bucket the view reports as
        # unknown makes the total unknown too, not a count with that bucket read
        # as 0.
        buckets = (
            summary_stats["severity_counts"]
            if isinstance(summary_stats.get("severity_counts"), dict)
            else summary_stats
        )
        if "total" in summary_stats:
            summary_stats["total"] = _total_of_known(buckets)
        # actionable is recounted when the findings it counts are at hand: the
        # SARIF results kept above, judged by the thresholds the scan recorded.
        # Without the SARIF (the summary and minimal levels never load it) the
        # per-severity split of the actionable count is not in the document:
        # the count is known only when the selection decides it (every counted
        # bucket kept, or none of them), else unknown. The whole-scan value
        # used to stay, so a view of the low findings alone reported the scan's
        # critical findings as actionable.
        if "actionable" in summary_stats:
            thresholds = (filtered_results.get("raw_results") or {}).get(
                "severity_thresholds"
            )
            if isinstance(sarif, dict) and isinstance(thresholds, dict):
                projects = _workspace_project_gates(filtered_results.get("raw_results"))
                summary_stats["actionable"] = sum(
                    1
                    for run in sarif.get("runs") or []
                    for result in run.get("results") or []
                    if _actionable_in_view(result, thresholds, projects)
                )
            else:
                selected = set(_COUNTED_SEVERITY_KEYS) & set(severity_list)
                if not selected:
                    summary_stats["actionable"] = 0
                elif selected != set(_COUNTED_SEVERITY_KEYS):
                    summary_stats["actionable"] = None
            if "actionable_findings" in filtered_results:
                filtered_results["actionable_findings"] = summary_stats["actionable"]
        filtered_results["summary_stats"] = summary_stats

    # filter_actionable_only's contract, restated over the recounted stats: an
    # actionable-only view's total is its actionable count (None when that is
    # unknown), never a count of findings the view does not list.
    if actionable_only and isinstance(filtered_results.get("summary_stats"), dict):
        summary_stats = dict(filtered_results["summary_stats"])
        if "total" in summary_stats:
            summary_stats["total"] = summary_stats.get("actionable")
        filtered_results["summary_stats"] = summary_stats

    # The producer's payload carries the same summary twice: at the top level
    # and under raw_results.metadata. The recount above replaced the top-level
    # dict with a new one, so the copy under metadata kept the whole scan's
    # figures in a response whose every other part described the filtered
    # view. After the restatement above, so the copy carries the same total.
    metadata = (filtered_results.get("raw_results") or {}).get("metadata")
    if (
        isinstance(metadata, dict)
        and "summary_stats" in metadata
        and isinstance(filtered_results.get("summary_stats"), dict)
    ):
        metadata["summary_stats"] = filtered_results["summary_stats"]

    # Recorded beside whatever filter ran before this one (the server applies
    # actionable_only first): assigned wholesale, this dropped that marker.
    filter_metadata: Dict[str, Any] = dict(already_applied)
    if scanner_list:
        filter_metadata["scanners"] = scanner_list
    if severity_list:
        filter_metadata["severities"] = severity_list
    filtered_results["_content_filters"] = filter_metadata

    return filtered_results


def _filter_names(names: Optional[str]) -> Optional[List[str]]:
    """The lowercased names in a comma-separated filter, or None for no filter."""
    if not names:
        return None
    parsed = [name.strip().lower() for name in names.split(",")]
    parsed = [name for name in parsed if name]
    return parsed or None


def _scanner_row_at_severities(
    data: Dict[str, Any], severity_list: List[str]
) -> Dict[str, Any]:
    """A scanner's row narrowed to *severity_list*: the buckets, and the count.

    The count follows the buckets kept, by the one rule (the non-suppressed
    buckets, as SummaryStats.total and the scanner's own finding_count count
    them). Left as it was, a row under a ``severities`` filter said "7 findings"
    beside buckets that summed to 2; summed over every kept bucket, a row under
    ``severities="suppressed"`` counted its suppressed findings as findings.
    """
    data = data.copy()
    data["severity_counts"] = {
        k: v for k, v in data["severity_counts"].items() if k.lower() in severity_list
    }
    if "finding_count" in data:
        data["finding_count"] = _total_of(
            {str(k).lower(): v for k, v in data["severity_counts"].items()}
        )
    return data


def _sarif_scanner_names(sarif: Dict[str, Any]) -> set[str]:
    """The lowercased ``properties.scanner_name`` values of *sarif*'s results."""
    names: set[str] = set()
    for run in sarif.get("runs") or []:
        for result in (run.get("results") or []) if isinstance(run, dict) else []:
            name = _sarif_scanner_name(result)
            if name is not None:
                names.add(name.lower())
    return names


def _stats_of_sarif(
    sarif: Dict[str, Any],
    thresholds: Any,
    projects: Optional[Dict[str, Dict[str, Any]]],
) -> Dict[str, Any]:
    """The severity buckets, ``total`` and ``actionable`` of *sarif*'s results.

    The counts a scanner row would carry, read from the findings themselves:
    a result with a suppression in effect is in the ``suppressed`` bucket, every
    other one in its severity's, ``total`` is every non-suppressed result, and
    ``actionable`` is exit 2's test at the scan's thresholds, or None when the
    document records no thresholds to judge it by. Every non-suppressed result
    is in exactly one named bucket: ``result_severity`` returns a declared
    severity only when it names one of the ladder's five, and reads any other
    declared value from the SARIF level, so ``total`` equals the sum of the
    five buckets and ``actionable`` never exceeds it. ``total`` is counted
    directly rather than summed back from the buckets, so it stays the plain
    "non-suppressed results" figure whatever the bucket set becomes.
    """
    from automated_security_helper.utils.sarif_utils import is_result_suppressed

    counts = dict.fromkeys(_SEVERITY_KEYS, 0)
    total = 0
    actionable: Optional[int] = 0 if isinstance(thresholds, dict) else None
    for run in sarif.get("runs") or []:
        for result in (run.get("results") or []) if isinstance(run, dict) else []:
            if is_result_suppressed(result):
                counts["suppressed"] += 1
                continue
            total += 1
            bucket = _get_finding_severity(result).lower()
            if bucket in counts:
                counts[bucket] += 1
            if actionable is not None and _actionable_in_view(
                result, thresholds, projects
            ):
                actionable += 1
    return {
        "severity_counts": counts,
        "total": total,
        "actionable": actionable,
    }


def _scanner_names_in(results: Dict[str, Any]) -> Optional[set[str]]:
    """The lowercased scanner names *results* knows, or None when it names none.

    Read from ``scanner_results``, ``scanner_reports``, ``additional_reports``
    and the SARIF results' ``properties.scanner_name``. None, not an empty set,
    when the document has none of those: a filter against a document that
    cannot name its scanners is not checked.
    """
    names: set[str] = set()
    found_any = False
    raw = results.get("raw_results")
    raw = raw if isinstance(raw, dict) else {}
    for mapping in (
        raw.get("scanner_results"),
        results.get("scanner_reports"),
        raw.get("additional_reports"),
    ):
        if isinstance(mapping, dict):
            found_any = True
            names.update(str(name).lower() for name in mapping)
    sarif = raw.get("sarif")
    if isinstance(sarif, dict):
        for run in sarif.get("runs") or []:
            for result in (run.get("results") or []) if isinstance(run, dict) else []:
                name = _sarif_scanner_name(result)
                if name is not None:
                    found_any = True
                    names.add(name.lower())
    return names if found_any else None


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
        from automated_security_helper.utils.sarif_utils import is_result_suppressed

        # The same reading as the counts: a suppression in effect puts the
        # result in the suppressed bucket; a rejected or underReview one leaves
        # it in its own severity's.
        if is_result_suppressed(result):
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
        Results with an added top-level 'findings' list, and
        ``findings_available``: whether the document carried the SARIF the list
        is built from. An empty list beside False means the findings could not
        be listed; beside True it means there are none. The two used to read
        the same.
    """
    findings_list = []

    # Extract findings from SARIF runs. ``sarif`` is None for a document that
    # was asked for its SARIF and has none (scan_tracking.get_scan_results).
    sarif = results.get("raw_results", {}).get("sarif") or {}
    results["findings_available"] = isinstance(sarif, dict) and "runs" in sarif
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
                    # The workspace aggregator writes a rebased uri percent-
                    # encoded and records the path it names; the encoded text
                    # names no file. The flattened finding reads it the same way.
                    recorded_path = props.get(ARTIFACT_PATH_PROPERTY)
                    if (
                        isinstance(recorded_path, str)
                        and recorded_path.strip()
                        and not (
                            isinstance(file_path, str)
                            and file_path.startswith("file://")
                        )
                    ):
                        file_path = recorded_path
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
