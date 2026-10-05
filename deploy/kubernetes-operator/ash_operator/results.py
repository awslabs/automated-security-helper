"""Turn the collector's summary into the AshScan ``.status`` block.

Per-scanner completeness survives the shard boundary, so the operator can and must
report it. ``_adopt_owning_shard_results`` keeps only the *owning* shard's entry for
each scanner, keyed on ``assigned_scanners``, and every other shard's skip marker is
discarded -- which is what lets the merged report distinguish "not in my shard"
from "ran and failed". Unioning the two dictionaries instead is the single mistake
that turns a working merge into a report claiming nothing ran.

``fail_on_incomplete_scanners`` defaults to **True** in ASH, so a scan whose
scanners did not all run exits 1 with its partial results written, and this
operator reports that as ``phase: Incomplete`` -- a third answer beside ``Clean``
(exit 0) and ``Findings`` (exit 2), not a kind of failure and not a refusal. The
per-scanner completeness and ``coverageComplete`` are surfaced unconditionally,
including when an adopter turned the gate off: they have accepted the gap, not
asked to be told there was none, and ``.status`` is the only place they can see
which scanner it was.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ash_operator.constants import (
    COMPLETE_SCANNER_STATUSES,
    KNOWN_SCANNER_STATUSES,
    PHASE_REFUSED,
)
from ash_operator.entrypoints.collect import verdict_phase


def classify_status(status: str | None) -> str:
    """Return ``Complete``, ``Incomplete`` or ``Unknown`` for a scanner status.

    Tests membership of the complete set rather than absence from the incomplete
    one, and that direction is the whole point. The pods in a fan-out can be
    mid-upgrade, so this can be handed a status string neither set knows. "Is it
    one of the two bad ones" answers *no* for such a string and reports the shard
    complete -- reading an unrecognised status as success. ``ash merge`` makes the
    same choice for the same reason and has a test class named after it.

    SKIPPED counts as complete because it means "not selected", which is a
    decision rather than a gap.
    """
    if status is None:
        return "Unknown"
    if status in COMPLETE_SCANNER_STATUSES:
        return "Complete"
    if status in KNOWN_SCANNER_STATUSES:
        return "Incomplete"
    return "Unknown"


@dataclass
class CollectorSummary:
    """The collector's termination message, parsed."""

    phase: str = "Unknown"
    shard_count: int | None = None
    consumed_shard_indices: list[int] = field(default_factory=list)
    selected_attempts: list[dict[str, Any]] = field(default_factory=list)
    discarded_attempts: list[dict[str, Any]] = field(default_factory=list)
    merge_exit_code: int | None = None
    refusal: str | None = None
    scanners: list[dict[str, Any]] = field(default_factory=list)
    findings: dict[str, Any] = field(default_factory=dict)
    merged_shard_count: int | None = None
    merged_shard_indices: list[int] = field(default_factory=list)
    candidate_roster_agreed: bool | None = None
    coverage_complete: bool | None = None
    coverage_source: str | None = None
    coverage_gaps: list[str] = field(default_factory=list)
    omitted: list[str] = field(default_factory=list)
    parse_error: str | None = None


def parse_collector_summary(message: str | None) -> CollectorSummary:
    """Parse the collector's termination message.

    A message the kubelet truncated is not valid JSON, and that has to read as
    "the operator does not know" rather than as a clean run. The collector sheds
    detail to stay inside the 4 KiB cap for exactly this reason, but an operator
    that silently swallowed a parse failure would report a clean run for a run whose
    outcome it never saw.
    """
    if not message:
        return CollectorSummary(
            parse_error=(
                "the collector pod produced no termination message. Its outcome is "
                "unknown to the operator; the merged report on the results volume "
                "is authoritative."
            )
        )
    try:
        raw = json.loads(message)
    except ValueError as err:
        return CollectorSummary(
            parse_error=(
                f"the collector's termination message is not valid JSON "
                f"({err}). The kubelet caps it at 4 KiB, so this is most likely "
                f"truncation; treat the run's outcome as unknown rather than clean."
            )
        )
    if not isinstance(raw, dict):
        return CollectorSummary(parse_error=f"expected a JSON object, got {type(raw).__name__}")
    return CollectorSummary(
        phase=str(raw.get("phase", "Unknown")),
        shard_count=raw.get("shardCount"),
        consumed_shard_indices=list(raw.get("consumedShardIndices") or []),
        selected_attempts=list(raw.get("selectedAttempts") or []),
        discarded_attempts=list(raw.get("discardedAttempts") or []),
        merge_exit_code=raw.get("mergeExitCode"),
        refusal=raw.get("refusal"),
        scanners=list(raw.get("scanners") or []),
        findings=dict(raw.get("findings") or {}),
        merged_shard_count=raw.get("mergedShardCount"),
        merged_shard_indices=list(raw.get("mergedShardIndices") or []),
        candidate_roster_agreed=raw.get("candidateRosterAgreed"),
        coverage_complete=raw.get("coverageComplete"),
        coverage_source=raw.get("coverageSource"),
        coverage_gaps=list(raw.get("coverageGaps") or []),
        omitted=list(raw.get("omittedFromStatus") or []),
    )


def status_from_summary(summary: CollectorSummary, *, expected_shard_count: int) -> dict[str, Any]:
    """Return the ``.status`` fields the collector's summary supports."""
    scanners = []
    for entry in summary.scanners:
        status = entry.get("s")
        scanners.append(
            {
                "name": entry.get("n"),
                "status": status,
                "completeness": classify_status(status),
                "owningShardIndex": entry.get("o", -1),
                "dependenciesSatisfied": bool(entry.get("d", True)),
                "findingCount": int(entry.get("f") or 0),
                "actionableFindingCount": int(entry.get("a") or 0),
            }
        )
    incomplete = [s["name"] for s in scanners if s["completeness"] != "Complete"]

    consumed = sorted(summary.consumed_shard_indices)
    merge_block: dict[str, Any] = {
        "exitCode": summary.merge_exit_code,
        "consumedShardIndices": consumed,
        "expectedShardCount": expected_shard_count,
        # Not the same question as "did every index resolve". The merged report
        # records what `ash merge` itself believed it consumed, from the provenance
        # inside the result files. Reporting both means a disagreement between the
        # collector's walk and the merge's own accounting is visible instead of
        # averaged away.
        "mergeReportedShardCount": summary.merged_shard_count,
        "mergeReportedShardIndices": sorted(summary.merged_shard_indices),
    }
    if summary.refusal:
        merge_block["refusalReason"] = summary.refusal
    if summary.discarded_attempts:
        merge_block["discardedAttempts"] = summary.discarded_attempts
    if summary.selected_attempts:
        merge_block["selectedAttempts"] = summary.selected_attempts
    # Always reported, including when it is None. `ash merge` refuses a roster
    # disagreement only when every shard recorded candidate_scanners; a set where
    # none did is accepted with a coverage hole intact, so "we would have been told"
    # is not a safe assumption and this field says which case happened. derive_phase
    # refuses on anything but True -- see its docstring.
    merge_block["candidateRosterAgreed"] = summary.candidate_roster_agreed
    if summary.candidate_roster_agreed is not True:
        merge_block.setdefault(
            "refusalReason",
            "no shard recorded candidate_scanners, or the shards did not agree on it. "
            "That field is the only check that can see a coverage hole where two "
            "executors partitioned different scanner sets without overlapping, and "
            "`ash merge` does not refuse when it is absent from every shard -- it "
            "skips the union check and merges. So a scanner may have run nowhere and "
            "the report would read as a complete scan. Most likely cause: spec.image "
            "is an ASH build that predates ShardAssignment stamping.",
        )

    complete_walk = consumed == list(range(expected_shard_count))
    if not complete_walk and not summary.refusal:
        merge_block["refusalReason"] = (
            f"the collector reported consuming {consumed} but the run has "
            f"{expected_shard_count} shards. A merge over a subset exits 0 and "
            f"reports a clean scan, so this is treated as a failure."
        )

    status: dict[str, Any] = {
        # ash merge's own exit code, unreinterpreted: 0 clean, 2 findings, 1
        # incomplete or an error. The phase below is what it means.
        "exitCode": summary.merge_exit_code,
        # From the merged report, assessed the way ASH answers coverage_complete
        # for an MCP scan. None means the collector could not assess it.
        "coverageComplete": summary.coverage_complete,
        "coverageSource": summary.coverage_source,
        "coverageGaps": summary.coverage_gaps,
        "scannerCompleteness": scanners,
        "incompleteScanners": incomplete,
        "merge": merge_block,
        "findings": {
            "total": summary.findings.get("total"),
            "actionable": summary.findings.get("actionable"),
            "suppressed": summary.findings.get("suppressed"),
        },
    }
    if summary.omitted:
        status["statusTruncated"] = summary.omitted
    if summary.parse_error:
        status["collectorSummaryError"] = summary.parse_error
    status["phase"] = derive_phase(summary, complete_walk=complete_walk)
    return status


def derive_phase(summary: CollectorSummary, *, complete_walk: bool) -> str:
    """Return the terminal phase: ``Clean``, ``Findings``, ``Incomplete`` or ``Refused``.

    The first three are ``ash merge``'s three answers -- exit 0, exit 2, and exit 1
    over a merged report that names a coverage gap -- mapped by
    :func:`ash_operator.entrypoints.collect.verdict_phase`, the same function the
    collector used, so the two cannot disagree. ``Incomplete`` carries partial
    results: the findings in ``.status.findings`` are real, but the set is known
    to be short, so clearing them does not clear the scan.

    ``Refused`` means the operator does not have an answer and is declining to
    synthesise one, which is a different thing for a human to act on and a
    different thing for a pipeline to alert on.

    ``candidate_roster_agreed`` is one of those. The collector detects the case it
    names -- no shard recorded ``candidate_scanners``, or only some did, or the
    recorded sets disagree -- but for the all-absent case ``ash merge`` does **not**
    refuse: the union check is skipped, and a mid-rollout coverage hole merges into a
    report that reads as a complete scan. For a while this function read that field
    not at all, so a scan with no provenance whatsoever reported success with
    ``candidateRosterAgreed: false`` sitting in its own status. The path is reachable
    without anyone doing anything odd: an adopter's ``spec.image`` is an ASH build
    predating ``ShardAssignment`` stamping, which this operator explicitly supports.
    Detecting a coverage hole and then reporting success is worse than not detecting
    it, so this refuses.

    ``None`` refuses too, and that is deliberate rather than cautious. The collector
    always sets the field, and it is shipped from the operator's own package in the
    run's immutable ConfigMap, so ``None`` means the summary did not survive -- the
    operator does not know whether the coverage check was possible, which is exactly
    what ``Refused`` is for. ``write_termination_message`` must therefore never shed
    this key; :mod:`ash_operator.entrypoints.collect` says so at the shed list.
    """
    if summary.parse_error:
        return PHASE_REFUSED
    if summary.refusal or not complete_walk:
        return PHASE_REFUSED
    if summary.merge_exit_code is None:
        return PHASE_REFUSED
    if summary.candidate_roster_agreed is not True:
        return PHASE_REFUSED
    return verdict_phase(
        exit_code=summary.merge_exit_code, coverage_complete=summary.coverage_complete
    )
