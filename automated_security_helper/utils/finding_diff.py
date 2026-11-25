# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import polars as pl

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.utils.finding_identity import canonical
from automated_security_helper.utils.frame_text import ranks, wire

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
    if results.baseline_filtered:
        raise ComparabilityRefusal("cannot use results filtered by --baseline")
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
        missing = set(result.metadata.expected_scanners) - _evaluated_scanners(result)
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


#: One scan's side of the match, a column per name. Where a column is not the
#: bare model field of the same name, it says so in its name, so a reader of a
#: join key is not misled:
#:
#: - ``identity_message`` is ``FlatVulnerability.identity_message``, not ``message``.
#: - ``severity_upper`` is the severity upper-cased (``None`` read as ``""``), the
#:   form :func:`fallback_key` keys on, not ``FlatVulnerability.severity``.
#: - ``is_suppressed`` is ``FlatVulnerability.is_suppressed``, the name
#:   ``flat_frame`` gives it.
#: - ``line_start`` and ``line_end`` are dense ranks of the lines (see
#:   :func:`_side`), not the lines.
#: - ``i`` is the finding's position in the list given.
#: - ``base`` and ``key_message`` are the parts of :func:`fallback_key` that are
#:   text; they are null for a finding it does not key.
_SIDE_SCHEMA = {
    "i": pl.Int64,
    "id": pl.String,
    "has_identity": pl.Boolean,
    "fingerprinted": pl.Boolean,
    "identity_message": pl.String,
    "base": pl.String,
    "key_message": pl.String,
    "severity_upper": pl.String,
    "is_suppressed": pl.Boolean,
    "line_start": pl.Int64,
    "line_end": pl.Int64,
}
_LOOSE = ["base", "key_message"]
_FULL = [*_LOOSE, "severity_upper"]
#: How findings of one place are put in order: lines (-1 for none), then id, then
#: where the scan listed them (the stable tie-break the old ``sorted`` gave).
_PLACE = [
    pl.col("line_start").fill_null(-1),
    pl.col("line_end").fill_null(-1),
    pl.col("id"),
    pl.col("i"),
]


def _side(findings: list[FlatVulnerability]) -> pl.DataFrame:
    """One scan's findings as a frame, one row per finding, ``i`` its position.

    The identity attributes are properties of the finding objects, so reading
    them is a Python pass; everything after it is frame operations. ``base`` is
    null for a finding :func:`fallback_key` does not key.
    """
    columns: dict[str, list[Any]] = {name: [] for name in _SIDE_SCHEMA}
    # Lines are unbounded ints and the frame column is 64-bit. This frame holds
    # each line's DENSE RANK (no line is -1, as the old sort key had it), because
    # only the order of lines is ever used here and every line has a rank. That
    # differs from ``models.flat_frame``, which holds the line itself and a null
    # with ``line_overflow`` set for one that does not fit, because its consumers
    # need the value. A column from one frame is not a column of the other.
    line_rank = ranks(
        -1 if line is None else line
        for finding in findings
        for line in (finding.line_start, finding.line_end)
    )
    for index, finding in enumerate(findings):
        key = fallback_key(finding)
        row = {
            "i": index,
            "id": wire(finding.id),
            "has_identity": finding.identity is not None,
            "fingerprinted": finding.has_fingerprint_identity,
            "identity_message": wire(finding.identity_message),
            "base": wire(key[0]) if key else None,
            "key_message": wire(key[1]) if key else None,
            "severity_upper": wire(key[2]) if key else None,
            "is_suppressed": finding.is_suppressed,
            "line_start": line_rank[
                -1 if finding.line_start is None else finding.line_start
            ],
            "line_end": line_rank[-1 if finding.line_end is None else finding.line_end],
        }
        # Named, not positional: a column added to the schema without its value
        # here is a KeyError, not every later value in the wrong column.
        for name in columns:
            columns[name].append(row[name])
    return pl.DataFrame(columns, schema=_SIDE_SCHEMA)


def match_findings(
    before: Iterable[FlatVulnerability], after: Iterable[FlatVulnerability]
) -> FindingMatch:
    """Pair findings from ``before`` with findings from ``after``.

    ``moved`` pairs differ only in their lines. This matcher is for display as
    well as gating, and the two deliberately differ on secrets: ``ash diff``
    reports a moved secret as moved, while ``apply_baseline`` refuses to drop
    one. The refusal is not applied here. A gating consumer must apply
    ``FlatVulnerability.requires_exact_identity_match`` and
    ``has_fingerprint_identity`` to each pair, as ``apply_baseline`` does.
    """
    before = list(before)
    after = list(after)
    old, new = _side(before), _side(after)

    # Exact: an id carried once on each side, unless both sides have an identity,
    # are not both fingerprinted, and say different things.
    exact = (
        old.filter(pl.col("id").is_unique())
        .join(new.filter(pl.col("id").is_unique()), on="id", suffix="_a")
        .filter(
            ~(
                pl.col("has_identity")
                & pl.col("has_identity_a")
                & ~(pl.col("fingerprinted") & pl.col("fingerprinted_a"))
                & pl.col("identity_message").ne_missing(pl.col("identity_message_a"))
            )
        )
    )

    # A place (rule, file, message) is ambiguous when its before findings differ
    # in suppression and the after findings are not simply their exact partners.
    # Every after finding of the place must have an exact partner of the same place.
    before_places = (
        old.filter(pl.col("base").is_not_null())
        .group_by(_LOOSE)
        .agg(
            pl.len().alias("n"), (pl.col("is_suppressed").n_unique() > 1).alias("mixed")
        )
    )
    after_places = (
        new.filter(pl.col("base").is_not_null())
        .join(
            exact.select(
                "i_a", pl.col("base").alias("pb"), pl.col("key_message").alias("pm")
            ),
            left_on="i",
            right_on="i_a",
            how="left",
        )
        .group_by(_LOOSE)
        .agg(
            pl.len().alias("n_a"),
            ((pl.col("pb") == pl.col("base")) & (pl.col("pm") == pl.col("key_message")))
            .fill_null(False)
            .all()
            .alias("partnered"),
        )
    )
    ambiguous = (
        before_places.join(after_places, on=_LOOSE)
        .filter(
            pl.col("mixed") & ~((pl.col("n") == pl.col("n_a")) & pl.col("partnered"))
        )
        .select(_LOOSE)
    )
    exact = (
        exact.join(ambiguous, on=_LOOSE, how="anti")
        .join(
            ambiguous,
            left_on=["base_a", "key_message_a"],
            right_on=_LOOSE,
            how="anti",
        )
        .sort("id")
    )

    # Moved: what is left, grouped by the full key. A group moves when it has no
    # more after than before findings and its before findings agree on
    # suppression; they pair off in line order, in order of key.
    def unmatched(side: pl.DataFrame, matched: pl.Series) -> pl.DataFrame:
        return side.filter(
            ~pl.col("i").is_in(matched.implode()) & pl.col("base").is_not_null()
        )

    left_old = unmatched(old, exact["i"])
    left_new = unmatched(new, exact["i_a"])
    moving = (
        left_old.group_by(_FULL)
        .agg(
            pl.len().alias("n"), (pl.col("is_suppressed").n_unique() > 1).alias("mixed")
        )
        .join(left_new.group_by(_FULL).agg(pl.len().alias("n_a")), on=_FULL)
        .join(ambiguous, on=_LOOSE, how="anti")
        .filter(~pl.col("mixed") & (pl.col("n_a") <= pl.col("n")))
        .select(_FULL)
    )

    def lined_up(side: pl.DataFrame) -> pl.DataFrame:
        return (
            side.join(moving, on=_FULL)
            .sort(_PLACE)
            .with_columns(pl.int_range(pl.len()).over(_FULL).alias("rank"))
        )

    moved = (
        lined_up(left_old)
        .join(lined_up(left_new), on=[*_FULL, "rank"], suffix="_a")
        .sort([*_FULL, "rank"])
    )

    def leftover(side: pl.DataFrame, matched: list[pl.Series]) -> pl.Series:
        taken = pl.concat(matched)
        return side.filter(~pl.col("i").is_in(taken.implode())).sort(
            [pl.col("id"), *_PLACE]
        )["i"]

    return FindingMatch(
        [(before[i], after[j]) for i, j in exact.select("i", "i_a").iter_rows()],
        [(before[i], after[j]) for i, j in moved.select("i", "i_a").iter_rows()],
        [after[i] for i in leftover(new, [exact["i_a"], moved["i_a"]])],
        [before[i] for i in leftover(old, [exact["i"], moved["i"]])],
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
