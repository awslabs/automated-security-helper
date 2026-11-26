# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable

import polars as pl

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.models.frame_model import (
    Computed,
    FrameSpec,
    Position,
    Ranked,
    to_frame,
)
from automated_security_helper.utils.finding_identity import canonical

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults


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


def _severity_upper(finding: FlatVulnerability) -> str:
    """The finding's severity upper-cased, ``None`` read as ``""``."""
    return (finding.severity or "").upper()


def fallback_key(finding: FlatVulnerability) -> tuple[Any, ...] | None:
    base = finding.identity_base
    if base is None or finding.source_report is not None:
        return None
    if finding.has_fingerprint_identity:
        return None
    return (
        canonical(base),
        finding.identity_message or "",
        _severity_upper(finding),
    )


def _key_member(place: int) -> Callable[[FlatVulnerability], Any]:
    """A reader of one member of :func:`fallback_key`; null for an unkeyed finding."""

    def read(finding: FlatVulnerability) -> Any:
        key = fallback_key(finding)
        return None if key is None else key[place]

    return read


#: Everything :func:`fallback_key` reads, for the drift gate's accounting.
_FALLBACK_READS = (
    "identity_base",
    "source_report",
    "has_fingerprint_identity",
    "identity_message",
    "severity",
)

_OFF_KEY = "joined through the identity base and the fallback key, never a column"

# One scan's side of the diff. The canonical column vocabulary: a column that
# projects a model field bears the field's pydantic name (is_suppressed,
# line_start, line_end), and a transformed value never bears a field's bare name
# -- severity_uc is the uppercased severity of the fallback key, identity_message
# the identity's message, not the model's description. The line columns are the
# per-site Ranked override of the fields' flat-frame overflow policy: only their
# order is ever used here, a null line is a null rank, and _PLACE's fill_null(-1)
# puts it before every real line, as the old -1 sentinel did.
SIDE_SPEC = FrameSpec(
    FlatVulnerability,
    columns=(
        Position("i"),
        "id",
        Computed(
            "has_identity",
            "Boolean",
            lambda finding: finding.identity is not None,
            reads=("identity",),
            nullable=False,
        ),
        Computed(
            "fingerprinted",
            "Boolean",
            lambda finding: finding.has_fingerprint_identity,
            reads=("has_fingerprint_identity",),
            nullable=False,
        ),
        Computed(
            "identity_message",
            "String",
            lambda finding: finding.identity_message,
            reads=("identity_message",),
        ),
        Computed(
            "base",
            "String",
            _key_member(0),
            reads=_FALLBACK_READS,
            note="canonical identity base; null for a finding fallback_key "
            "does not key",
        ),
        Computed("key_message", "String", _key_member(1), reads=_FALLBACK_READS),
        Computed(
            "severity_uc",
            "String",
            _key_member(2),
            reads=_FALLBACK_READS,
            note="the fallback key's uppercased severity, never the field's bare name",
        ),
        "is_suppressed",
        Ranked("line_start", "lines"),
        Ranked("line_end", "lines"),
    ),
    waived={
        "severity": "carried as severity_uc, a member of the fallback key",
        "scanner": _OFF_KEY,
        "scanner_type": _OFF_KEY,
        "rule_id": _OFF_KEY,
        "file_path": _OFF_KEY,
        "_identity": "read through the identity and identity_base properties",
        "_assigned_identity_key": "read through has_fingerprint_identity and "
        "identity_base",
        "_identity_message": "read through the identity_message property",
        "_secret_detection": "a baseline-gate policy flag the pair consumer "
        "applies on the host",
        "_source_report": "read through the source_report property",
        "location_display": "display text over fields the diff never joins on",
        "correlation_id": "a cross-scanner grouping id assigned at flatten time; "
        "the diff pairs findings by identity and never joins on it",
        "is_secret_detection": "a rule-classification flag the correlation "
        "registry reads on the host; the diff never joins on it",
        "requires_exact_identity_match": "a gating policy flag the pair "
        "consumer applies on the host (see match_findings' docstring)",
    },
)

_LOOSE = ["base", "key_message"]
_FULL = [*_LOOSE, "severity_uc"]
#: How findings of one place are put in order: lines (-1 for none), then id, then
#: where the scan listed them (the stable tie-break the old ``sorted`` gave).
_PLACE = [
    pl.col("line_start").fill_null(-1),
    pl.col("line_end").fill_null(-1),
    pl.col("id"),
    pl.col("i"),
]


def _side(findings: list[FlatVulnerability]) -> pl.DataFrame:
    """One scan's findings as a frame of :data:`SIDE_SPEC`, ``i`` the position.

    The identity attributes are properties of the finding objects, so reading
    them is a Python pass; everything after it is frame operations. ``base`` is
    null for a finding :func:`fallback_key` does not key. Lines are unbounded
    ints and the frame column is 64-bit, so the line columns hold each line's
    rank; only the order of lines is ever used.
    """
    return to_frame(findings, SIDE_SPEC)


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
            (a, b) for a, b in pairs if _severity_upper(a) != _severity_upper(b)
        ],
        suppression_changed=[
            (a, b) for a, b in pairs if a.is_suppressed != b.is_suppressed
        ],
    )
