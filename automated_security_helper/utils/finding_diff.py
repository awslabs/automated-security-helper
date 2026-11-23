# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.utils.finding_identity import canonical

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.models.flat_vulnerability import FlatVulnerability


class ComparabilityRefusal(ValueError):
    """Two scans, or one of them, cannot be compared; the text says why."""


def check_comparable(results: AshAggregatedResults) -> None:
    """Refuse one scan's results that no comparison can use.

    The CLI runs this as each file loads (it names the file); the MCP tool runs it
    through :func:`comparable_findings`.
    """
    if results.workspace is not None:
        raise ComparabilityRefusal(
            "use the per-project results instead of a workspace aggregate"
        )
    if results.metadata.shard is not None:
        raise ComparabilityRefusal("use ash merge before comparing sharded results")
    changed_files_only = getattr(results.metadata, "changed_files_only", None)
    if changed_files_only is True:
        raise ComparabilityRefusal(
            "cannot compare results filtered by --changed-files-only"
        )
    if changed_files_only is not None and changed_files_only is not False:
        raise ComparabilityRefusal("invalid changed-files-only marker")
    project = getattr(results.metadata, "workspace_project", None)
    if project is not None and (not isinstance(project, str) or not project.strip()):
        raise ComparabilityRefusal("invalid workspace project marker")


def check_same_project(
    baseline: AshAggregatedResults, current: AshAggregatedResults
) -> None:
    """Refuse two scans of different projects, or a standalone and a workspace one."""
    baseline_workspace = getattr(baseline.metadata, "workspace_project", None)
    current_workspace = getattr(current.metadata, "workspace_project", None)
    if (baseline_workspace is None) != (current_workspace is None):
        raise ComparabilityRefusal(
            "cannot mix standalone and workspace project results"
        )
    if baseline_workspace != current_workspace or (
        baseline.metadata.project_name
        and current.metadata.project_name
        and baseline.metadata.project_name != current.metadata.project_name
    ):
        raise ComparabilityRefusal("the results name different projects")


def unique_findings(
    results: AshAggregatedResults, label: str
) -> list[FlatVulnerability]:
    """*results*' findings, refusing a scan in which two share an ID."""
    findings = results.to_flat_vulnerabilities()
    if len({finding.id for finding in findings}) != len(findings):
        raise ComparabilityRefusal(f"{label} scan contains duplicate finding IDs")
    return findings


def comparable_findings(
    baseline: AshAggregatedResults, current: AshAggregatedResults
) -> tuple[list[FlatVulnerability], list[FlatVulnerability]]:
    """Both scans' findings, once the pair has passed every comparability check."""
    check_comparable(baseline)
    check_comparable(current)
    check_same_project(baseline, current)
    return unique_findings(baseline, "Baseline"), unique_findings(current, "Current")


def _evaluated_scanners(results: AshAggregatedResults) -> set[str]:
    return {
        name
        for name, row in results.scanner_results.items()
        if not row.excluded
        and row.status in {ScannerStatus.PASSED, ScannerStatus.FAILED}
    }


def coverage_warnings(
    baseline: AshAggregatedResults, current: AshAggregatedResults
) -> list[str]:
    """What makes a comparison of the two scans less than like for like."""
    from automated_security_helper.interactions.run_ash_scan import (
        scan_incompleteness,
    )

    warnings = []
    if set(baseline.metadata.expected_scanners) != set(
        current.metadata.expected_scanners
    ) or _evaluated_scanners(baseline) != _evaluated_scanners(current):
        warnings.append("Scanner coverage differs between scans.")
    if (
        baseline.metadata.ignore_file_exclusions
        != current.metadata.ignore_file_exclusions
    ):
        warnings.append("Recorded ignore-file exclusions differ between scans.")
    for label, result in (("Baseline", baseline), ("Current", current)):
        missing = set(result.metadata.expected_scanners) - result.scanner_results.keys()
        if missing or scan_incompleteness(result, gate=True):
            warnings.append(f"{label} scan has incomplete scanner coverage.")
        elif not result.metadata.expected_scanners or not result.scanner_results:
            warnings.append(
                f"{label} scan does not record enough scanner coverage to establish comparability."
            )
        if result.metadata.inputs_not_scanned:
            warnings.append(f"{label} scan records inputs that were not scanned.")
    return warnings


@dataclass(frozen=True)
class FindingMatch:
    exact: list[tuple[FlatVulnerability, FlatVulnerability]]
    moved: list[tuple[FlatVulnerability, FlatVulnerability]]
    new: list[FlatVulnerability]
    absent: list[FlatVulnerability]


@dataclass(frozen=True)
class FindingDiff:
    new: list[FlatVulnerability]
    absent_after: list[FlatVulnerability]
    moved: list[tuple[FlatVulnerability, FlatVulnerability]]
    severity_changed: list[tuple[FlatVulnerability, FlatVulnerability]]
    suppression_changed: list[tuple[FlatVulnerability, FlatVulnerability]]


def fallback_key(finding: FlatVulnerability) -> tuple[Any, ...] | None:
    base = finding.identity_base
    if base is None or finding.source_report is not None:
        return None
    if finding.has_fingerprint_identity:
        return None
    return (
        canonical(base),
        finding.identity_message or "",
        (finding.severity or "").upper(),
    )


def _order(finding: FlatVulnerability) -> tuple[Any, ...]:
    return (
        finding.line_start if finding.line_start is not None else -1,
        finding.line_end if finding.line_end is not None else -1,
        finding.id,
    )


def match_findings(
    before: Iterable[FlatVulnerability], after: Iterable[FlatVulnerability]
) -> FindingMatch:
    before = list(before)
    after = list(after)
    before_ids = defaultdict(list)
    after_ids = defaultdict(list)
    for index, finding in enumerate(before):
        before_ids[finding.id].append(index)
    for index, finding in enumerate(after):
        after_ids[finding.id].append(index)
    matched_before = set()
    matched_after = set()
    exact = []
    exact_indices = []
    for finding_id in sorted(before_ids.keys() & after_ids.keys()):
        if len(before_ids[finding_id]) != 1 or len(after_ids[finding_id]) != 1:
            continue
        i, j = before_ids[finding_id][0], after_ids[finding_id][0]
        previous, current = before[i], after[j]
        if previous.identity is not None and current.identity is not None:
            fingerprinted = all(
                finding.has_fingerprint_identity for finding in (previous, current)
            )
            if (
                not fingerprinted
                and previous.identity_message != current.identity_message
            ):
                continue
        exact.append((previous, current))
        exact_indices.append((i, j))
        matched_before.add(i)
        matched_after.add(j)

    def loose_key(finding: FlatVulnerability) -> tuple[Any, ...] | None:
        key = fallback_key(finding)
        return None if key is None else key[:2]

    partner = {j: i for i, j in exact_indices}
    whole_before = defaultdict(list)
    whole_after = defaultdict(list)
    for index, finding in enumerate(before):
        key = loose_key(finding)
        if key is not None:
            whole_before[key].append(index)
    for index, finding in enumerate(after):
        key = loose_key(finding)
        if key is not None:
            whole_after[key].append(index)
    ambiguous = {
        key
        for key in whole_before.keys() & whole_after.keys()
        if len({before[i].is_suppressed for i in whole_before[key]}) > 1
        and not (
            len(whole_before[key]) == len(whole_after[key])
            and all(
                j in partner and loose_key(before[partner[j]]) == key
                for j in whole_after[key]
            )
        )
    }
    if ambiguous:
        kept = []
        for i, j in exact_indices:
            if loose_key(before[i]) in ambiguous or loose_key(after[j]) in ambiguous:
                matched_before.discard(i)
                matched_after.discard(j)
            else:
                kept.append((before[i], after[j]))
        exact = kept
    groups_before = defaultdict(list)
    groups_after = defaultdict(list)
    for index, finding in enumerate(before):
        key = fallback_key(finding)
        if index not in matched_before and key is not None:
            groups_before[key].append(index)
    for index, finding in enumerate(after):
        key = fallback_key(finding)
        if index not in matched_after and key is not None:
            groups_after[key].append(index)
    moved = []
    for key in sorted(groups_before.keys() & groups_after.keys()):
        if key[:2] in ambiguous:
            continue
        old, new = groups_before[key], groups_after[key]
        if len(new) > len(old) or len({before[i].is_suppressed for i in old}) > 1:
            continue
        for i, j in zip(
            sorted(old, key=lambda n: _order(before[n])),
            sorted(new, key=lambda n: _order(after[n])),
        ):
            moved.append((before[i], after[j]))
            matched_before.add(i)
            matched_after.add(j)
    return FindingMatch(
        exact,
        moved,
        sorted(
            (f for i, f in enumerate(after) if i not in matched_after),
            key=lambda f: (f.id, _order(f)),
        ),
        sorted(
            (f for i, f in enumerate(before) if i not in matched_before),
            key=lambda f: (f.id, _order(f)),
        ),
    )


def compare_findings(
    before: Iterable[FlatVulnerability], after: Iterable[FlatVulnerability]
) -> FindingDiff:
    match = match_findings(before, after)
    pairs = match.exact + match.moved
    return FindingDiff(
        new=match.new,
        absent_after=match.absent,
        moved=match.moved,
        severity_changed=[
            (a, b)
            for a, b in pairs
            if (a.severity or "").upper() != (b.severity or "").upper()
        ],
        suppression_changed=[
            (a, b) for a, b in pairs if a.is_suppressed != b.is_suppressed
        ],
    )
