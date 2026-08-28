# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Split one scan across N executors, and check afterwards that N came back.

Why this exists
---------------
Workspace mode parallelises *projects* across an in-process thread pool
(``workspace/execution.py``), which is one machine. A single large repository on a
CI fleet had no way to spread one scan over several jobs. This module supplies the
assignment half of that: each executor is told ``--shard-index k --shard-count n``
and works out its own slice with no coordination, no lock and no shared state. The
recombination half is ``ash merge``.

Why the split is by scanner and not by file
-------------------------------------------
The obvious design is to partition the file list, and it does not work here.
Scanners receive a *directory* (``ScannerPluginBase.scan(target: Path, ...)``), and
only a handful of plugins consult ``utils.get_scan_set.scan_set`` at all --
``orchestrator.source_scan_set`` is assigned once for reporting and never read
back. bandit, semgrep, checkov, grype and syft all walk the tree they are pointed
at.

So a file-level split would be honoured by roughly a third of the scanners and
ignored by the rest. Every shard's semgrep would scan the whole repository, and
because merging deliberately does not deduplicate findings (see
``SarifReport.merge_sarif_report``), an n-shard run would report every semgrep
finding n times. That is a wrong report, not merely a slow one, and it is wrong in
the direction that wastes a reviewer's time on n-1 phantom copies of every real
issue.

Partitioning the scanner set instead is honoured by every scanner without any
scanner knowing sharding exists, and it maps onto the actual cost distribution:
semgrep and checkov dominate ASH's runtime, so putting them on separate executors
is where the wall-clock win comes from.

Why an exclusion list rather than a new filter
----------------------------------------------
A shard is applied by adding every *unassigned* scanner to ``excluded_scanners``,
the mechanism ``--exclude-scanners`` already uses. This is deliberate reuse:
``ScanPhase`` carries three separate validators (``_validate_scanner_tasks``,
``_validate_execution_completion``, ``_validate_result_completeness``) whose whole
job is to notice scanners that were registered but produced no result. A bespoke
"skip these" path would trip all three on every shard. The excluded-scanner path
already records a scanner as deliberately excluded rather than missing, so shards
inherit correct, already-tested bookkeeping.

Determinism, and the failure it is guarding against
---------------------------------------------------
Executors never talk to each other, so the partition must be a pure function of
(the set of scanner names, index, count). It is: names are deduplicated, sorted,
then dealt round-robin. Input order cannot matter, which is what makes it safe to
feed this the output of ``ash_plugin_manager.plugin_modules("scanner")`` whose
order depends on module load sequence.

Round-robin over a sorted list rather than a hash of the name. With around ten
scanners a hash gives no better balance and can easily produce an empty shard
alongside a triple-loaded one; dealing guarantees sizes within one of each other
and is predictable enough for an operator to check by eye.

The residual risk is that two executors resolve *different scanner sets* -- one
missing a plugin module, or with ``--python-only`` set on only some jobs. Then both
partitions are internally valid and the union has a hole. Nothing at assignment
time can detect that, so it is caught at merge time instead:
:func:`verify_shard_coverage` refuses a set of shards that does not reconstruct
exactly one whole scan.

Catching it needs each shard to record the set it partitioned, and for a while
this claim was false because nothing did. ``ShardAssignment`` held only the index,
the count and the assignment, so at ``shard_count=2`` executor 0 resolving
``{a,b,c,d}`` and taking ``[a,c]`` merged cleanly with executor 1 resolving
``{a,b,c}`` and taking ``[b]``: counts agree, indices complete, no duplicates, no
overlap, and ``d`` never scanned. ``candidate_scanners`` is what the union is
compared against. It happened to be caught in practice by
``merge._verify_scanner_union``, but only incidentally -- that check works from
the SKIPPED markers a shard writes for scanners it did not own, and
``verify_shard_coverage`` is exported in ``__all__``, so any caller using it alone
got no hole detection at all.

Known limitations
-----------------
Balance is by scanner *count*, not by scanner *cost*. A shard holding semgrep
finishes long after a shard holding syft, so wall clock is bounded by the slowest
single scanner and shard counts above about four buy very little. There is no
attempt to model or measure per-scanner cost; doing so would need history the CLI
does not have.

A shard count above the number of scanners leaves the surplus shards empty. They
run, produce a valid empty report, and merge correctly -- so this is wasteful
rather than wrong, and it is allowed so that a pipeline can parameterise shard
count without knowing the scanner count.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from pydantic import BaseModel, ConfigDict, Field

from automated_security_helper.core.exceptions import (
    ShardCoverageError,
    ShardSelectionError,
)

__all__ = [
    "ShardAssignment",
    "ShardCoverageError",
    "ShardSelectionError",
    "partition_scanners",
    "scanners_to_exclude",
    "validate_shard_selection",
    "verify_shard_coverage",
]


class ShardAssignment(BaseModel):
    """What one shard was actually asked to run.

    Recorded on each shard's results so ``ash merge`` can verify coverage from the
    result files alone, without being told out of band how many shards to expect.
    Taking the expected count as a merge argument would mean an operator who
    changed their matrix in one place and not the other gets a silently short
    merge.

    ``assigned_scanners`` is the assignment, not the outcome. A scanner listed
    here that failed or was disabled by config still appears; the scanner's own
    status in the results says what became of it. Conflating the two would make a
    legitimately-disabled scanner look like a coverage gap.

    ``candidate_scanners`` is what makes coverage verifiable at all. Recording
    only the assignment lets every shard be internally consistent while the union
    has a hole: at ``shard_count=2``, executor 0 resolving ``{a,b,c,d}`` and
    taking ``[a,c]`` alongside executor 1 resolving ``{a,b,c}`` and taking ``[b]``
    agrees on the count, has complete indices, no duplicates and no overlap. Every
    check in :func:`verify_shard_coverage` passed and ``d`` was never scanned,
    because nothing recorded what the partition was taken *from*.
    """

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    shard_index: int = Field(
        ge=0, description="Zero-based index of this shard within the run."
    )
    shard_count: int = Field(
        ge=1, description="Total number of shards the scan was split across."
    )
    assigned_scanners: list[str] = Field(
        default_factory=list,
        description="Scanner names this shard was responsible for running.",
    )
    candidate_scanners: list[str] | None = Field(
        default=None,
        description=(
            "Every scanner this executor resolved before partitioning -- the set "
            "assigned_scanners was taken from. None on results written before "
            "this field existed, in which case the union check is skipped."
        ),
    )


def validate_shard_selection(shard_index: int | None, shard_count: int | None) -> None:
    """Check a shard selection, raising :class:`ShardSelectionError` if unusable.

    Both unset means no sharding, which is the normal case and always fine.

    Args:
        shard_index: Zero-based shard index, or None.
        shard_count: Total shard count, or None.

    Raises:
        ShardSelectionError: If exactly one of the pair is set, if the count is
            not positive, or if the index falls outside ``0 <= index < count``.
    """
    if shard_index is None and shard_count is None:
        return

    if shard_index is None or shard_count is None:
        given, missing = (
            ("--shard-count", "--shard-index")
            if shard_index is None
            else ("--shard-index", "--shard-count")
        )
        raise ShardSelectionError(
            f"{given} requires {missing} as well. Sharding splits one scan across "
            f"several executors, so a shard is only meaningful as 'index of count'; "
            f"acting on {given} alone would scan part of the repository and report "
            f"it as a whole scan."
        )

    if shard_count < 1:
        raise ShardSelectionError(
            f"--shard-count must be at least 1, got {shard_count}."
        )

    if not 0 <= shard_index < shard_count:
        raise ShardSelectionError(
            f"--shard-index must satisfy 0 <= index < --shard-count, got "
            f"index={shard_index} with count={shard_count}. Indices are zero-based, "
            f"so a {shard_count}-way split uses 0 through {shard_count - 1}."
        )


def _normalized(scanner_names: Iterable[str]) -> list[str]:
    """Deduplicate, drop blanks, and sort -- the canonical order every shard sees.

    Lower-cased because the rest of the CLI compares scanner names case
    insensitively (``ScanPhase`` lowercases both sides), so treating "Bandit" and
    "bandit" as two scanners here would put the same scanner on two shards.
    """
    seen = {name.strip().lower() for name in scanner_names if name and name.strip()}
    return sorted(seen)


def partition_scanners(
    scanner_names: Sequence[str], shard_index: int, shard_count: int
) -> list[str]:
    """Return the scanners belonging to *shard_index* of *shard_count*.

    Pure function of the deduplicated, sorted name set and the two integers, so
    every executor computes the same partition without coordinating. See the
    module docstring for why the partition is round-robin over a sorted list.

    Args:
        scanner_names: Candidate scanner names, in any order, possibly with
            duplicates or differing case.
        shard_index: Zero-based index of the shard to compute.
        shard_count: Total number of shards.

    Returns:
        The sorted subset of scanner names assigned to this shard. Possibly empty,
        when there are fewer scanners than shards.

    Raises:
        ShardSelectionError: If the index and count are not a usable pair.
    """
    validate_shard_selection(shard_index, shard_count)
    ordered = _normalized(scanner_names)
    return [
        name
        for position, name in enumerate(ordered)
        if position % shard_count == shard_index
    ]


def scanners_to_exclude(
    all_scanner_names: Sequence[str],
    assigned: Sequence[str],
    already_excluded: Sequence[str] | None = None,
) -> list[str]:
    """Turn a shard assignment into the exclusion list that implements it.

    ``already_excluded`` is carried through rather than replaced. An operator who
    passed ``--exclude-scanners semgrep`` means it on every shard; dropping their
    exclusions here would quietly run a scanner they had turned off, on whichever
    shard it happened to land.

    Args:
        all_scanner_names: Every candidate scanner name for this run.
        assigned: The names this shard is responsible for.
        already_excluded: Exclusions the operator asked for, if any.

    Returns:
        Sorted, deduplicated, lower-cased exclusion list.
    """
    assigned_set = set(_normalized(assigned))
    excluded = {
        name for name in _normalized(all_scanner_names) if name not in assigned_set
    }
    excluded.update(_normalized(already_excluded or []))
    return sorted(excluded)


def verify_shard_coverage(assignments: Sequence[ShardAssignment]) -> None:
    """Check that *assignments* reconstruct exactly one whole scan.

    Called by ``ash merge`` before merging anything. Every condition checked here
    would otherwise yield a well-formed report that is quietly missing whole
    scanners, or that counts some findings twice.

    Args:
        assignments: One entry per shard result being merged.

    Raises:
        ShardCoverageError: If no shards were supplied, if the shards disagree
            about the total count, if any index is missing or repeated, if two
            shards claim the same scanner, if the shards disagree about the
            candidate set, or if the assignments do not union to it.
    """
    if not assignments:
        raise ShardCoverageError(
            "No shard results were supplied to merge. Refusing to write an empty "
            "unified report, because an empty report is indistinguishable from a "
            "clean scan."
        )

    counts = {assignment.shard_count for assignment in assignments}
    if len(counts) > 1:
        raise ShardCoverageError(
            f"Shard results disagree about the total shard count: saw "
            f"{sorted(counts)}. These results come from different runs, or the "
            f"shard count changed while the pipeline was in flight; merging them "
            f"would produce a report missing whole scanners."
        )

    expected_count = counts.pop()
    seen_indices = [assignment.shard_index for assignment in assignments]

    duplicates = sorted({i for i in seen_indices if seen_indices.count(i) > 1})
    if duplicates:
        raise ShardCoverageError(
            f"Shard indices {duplicates} appear more than once. Merging a shard "
            f"twice would double-count every finding it reported, because merging "
            f"does not deduplicate."
        )

    missing = sorted(set(range(expected_count)) - set(seen_indices))
    if missing:
        raise ShardCoverageError(
            f"Missing shard results for indices {missing} of {expected_count}. "
            f"Those scanners did not run, or their results were never collected -- "
            f"check whether the matching CI jobs succeeded and uploaded their "
            f"artifacts. Refusing to merge a partial scan into a report that would "
            f"read as complete."
        )

    unexpected = sorted(i for i in set(seen_indices) if i >= expected_count)
    if unexpected:
        raise ShardCoverageError(
            f"Shard indices {unexpected} are outside the declared count of "
            f"{expected_count}."
        )

    claimed: dict[str, int] = {}
    overlaps: list[str] = []
    for assignment in assignments:
        for scanner in _normalized(assignment.assigned_scanners):
            if scanner in claimed:
                overlaps.append(
                    f"{scanner} (shards {claimed[scanner]} and {assignment.shard_index})"
                )
            else:
                claimed[scanner] = assignment.shard_index
    if overlaps:
        raise ShardCoverageError(
            "The same scanner was assigned to more than one shard: "
            f"{'; '.join(sorted(overlaps))}. Its findings would be counted once "
            "per shard."
        )

    _verify_candidate_agreement(assignments, claimed)


def _verify_candidate_agreement(
    assignments: Sequence[ShardAssignment], claimed: dict[str, int]
) -> None:
    """Check the shards agree on what they partitioned, and that they cover it.

    This is the check that closes the residual risk named in the module docstring:
    two executors resolving *different* scanner sets, so that both partitions are
    internally valid and the union has a hole. Every other check here reads only
    indices and assignments, and a hole of that kind disturbs neither.

    Skipped when no shard records a candidate set, which is how results written
    before ``candidate_scanners`` existed keep merging. A mixed set -- some shards
    carrying it, some not -- is refused rather than checked on the subset: the
    shards that predate the field are exactly the ones that could be hiding the
    hole, so verifying only the ones that do carry it would report a pass that
    means less than it appears to.

    Args:
        assignments: One entry per shard result being merged.
        claimed: Normalized scanner name to the index of the shard that owns it,
            built by the caller while checking for overlaps. Reused rather than
            recomputed so the two checks cannot disagree about normalization.

    Raises:
        ShardCoverageError: If only some shards record a candidate set, if the
            shards disagree about it, or if the assignments do not union to it.
    """
    with_candidates = [a for a in assignments if a.candidate_scanners is not None]
    if not with_candidates:
        return

    if len(with_candidates) != len(assignments):
        missing = sorted(
            a.shard_index for a in assignments if a.candidate_scanners is None
        )
        raise ShardCoverageError(
            f"Shards {missing} record no candidate scanner set while the others "
            f"do. These results were produced by different versions of ASH, so "
            f"they are not known to have partitioned the same scanner set -- and "
            f"the shards without the record are the ones that could be hiding a "
            f"gap. Re-run the whole matrix on one version."
        )

    candidate_sets = {tuple(_normalized(a.candidate_scanners)) for a in with_candidates}
    if len(candidate_sets) > 1:
        detail = "; ".join(
            f"shard {a.shard_index}: {', '.join(_normalized(a.candidate_scanners))}"
            for a in sorted(with_candidates, key=lambda a: a.shard_index)
        )
        raise ShardCoverageError(
            f"The shards partitioned different scanner sets: {detail}. Each "
            f"partition is internally valid, so nothing else here can see this: "
            f"one executor was missing a plugin module, or --python-only or a "
            f"config override was applied to some jobs and not others. Merging "
            f"would report a scan that never covered the scanners the smaller set "
            f"omitted."
        )

    candidates = set(candidate_sets.pop())
    uncovered = sorted(candidates - set(claimed))
    if uncovered:
        raise ShardCoverageError(
            f"These scanners were candidates on every shard but assigned to none: "
            f"{', '.join(uncovered)}. The partition did not cover the set it was "
            f"taken from, so no shard ran them and the merged report would not "
            f"say so."
        )

    unexpected = sorted(set(claimed) - candidates)
    if unexpected:
        raise ShardCoverageError(
            f"These scanners were assigned to a shard but are not in the candidate "
            f"set: {', '.join(unexpected)}. An assignment that names a scanner the "
            f"executor did not resolve cannot have been produced by partitioning "
            f"that set, so the provenance does not describe this run."
        )
