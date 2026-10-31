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
missing a plugin module, say. Then both partitions are internally valid and the
union has a hole. Nothing at assignment time can detect that, so it is caught at
merge time instead: :func:`verify_shard_coverage` refuses a set of shards that
does not reconstruct exactly one whole scan. ``--python-only`` set on only some
jobs is a different shape: every executor records its candidates before the
selection filters apply, so the candidate sets agree and nothing here can see the
flag; the merge's contribution check reads it from the shards' records and warns,
naming the scanners the flagged shards left unrun and which shards ran with the
flag (``cli.merge``).

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

import difflib
import hashlib
from collections.abc import Iterable, Sequence
from itertools import islice

from typing import Any

from pydantic import ConfigDict, Field, model_validator

from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.undecodable_text import StrippedRecordModel

from automated_security_helper.core.exceptions import (
    ShardCoverageError,
    ShardSelectionError,
)
from automated_security_helper.utils.terminal_text import (
    NAMED_HASH_COMMAND,
    controls_shown,
    hash_command_broken,
    shown_on_one_line,
)

__all__ = [
    "ShardAssignment",
    "ShardCoverageError",
    "ShardSelectionError",
    "partition_scanners",
    "scanners_to_exclude",
    "shown_shard_text",
    "validate_shard_selection",
    "verify_shard_coverage",
]

#: How many missing shard indices a coverage refusal names before "and N more".
#: The count of missing indices is always exact; only the listing is bounded, so a
#: shard_count read from a corrupt results file cannot make the refusal itself
#: unbounded.
MISSING_SHARD_INDICES_SHOWN = 20


def shown_shard_text(value: object) -> str:
    """*value* as a refusal or a warning about shard results shows it.

    For what a shard or the operator chose: scanner names, statuses, paths. Any job
    in the matrix wrote the shard results, so a name can hold an ESC sequence the
    terminal would act on, or a newline followed by a line GitHub Actions reads as
    a workflow command. Each character utils/terminal_text.py shows rather than
    prints (controls, format characters, the line and paragraph separators, a lone
    surrogate, and the private-use and unassigned code points) is written as its
    escape there, ``\\xNN``, ``\\uNNNN`` or ``\\UNNNNNNNN``, newline, tab and
    carriage return included, so the value cannot
    start a line of its own; a backslash run that would read as an escape is
    doubled, one to one. The first "#" of a "##name[" command is written as
    ``\\x23``. A "::" in the value is left alone: GitHub reads one only at the start
    of a line, which the value no longer reaches.
    """
    text = controls_shown(str(value), keep_layout=False)
    return NAMED_HASH_COMMAND.sub(hash_command_broken, text)


#: How many ignored provenance keys the warning names before "and N more", and
#: how much of one key or of the shard index it quotes. The count is exact; only
#: the listing is bounded, so a results file with 100,000 unknown keys, or a list
#: for the index, cannot make the warning line that size.
_DROPPED_KEYS_SHOWN = 20
_DROPPED_TEXT_SHOWN = 80


def _cut_text(text: str, limit: int) -> str:
    """*text* as it stands, or its first *limit* characters and "..."."""
    return text if len(text) <= limit else f"{text[:limit]}..."


#: The (shard index, digest of the ignored fields) pairs ShardAssignment has
#: warned about in this process; see ShardAssignment._name_the_dropped_keys.
_WARNED_PROVENANCE_KEYS: set[tuple[str, str]] = set()


class ShardAssignment(StrippedRecordModel):
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

    ``selected_scanners`` closes the remaining gap, and it is a third field rather
    than a narrowing of ``assigned_scanners`` for a reason that is easy to get
    backwards. The partition is taken over every registered scanner, before the
    selection filters, so ``assigned_scanners`` names scanners the shard never
    intended to run -- ``--scanners bandit`` leaves grype assigned and SKIPPED. That
    breadth reads like the defect, and narrowing it looks like the fix, but two
    readers depend on it. ``verify_shard_coverage``'s ``uncovered`` check compares
    the union of the assignments against the candidate set, so a narrowed assignment
    would leave every config-disabled and platform-declined scanner uncovered and
    refuse merges with nothing wrong with them. ``cli.merge._verify_shard_contributions``
    reads it as ownership, and would stop holding a shard to the scanners it was
    given. Recording intent alongside the assignment keeps both readers correct and
    makes the over-claim recoverable: a scanner assigned, not selected here, and not
    selected on any other shard ran nowhere, and before this field there was nothing
    in the provenance that said so.
    """

    # Read from a results file, whose values an error does not quote. Unknown
    # keys are dropped, not refused: a results file written by a newer ASH can
    # carry a provenance field this version does not know, and refusing it made
    # ``ash merge`` report the shard as having no provenance at all, which
    # named the wrong cause. Every field this version reads is still validated,
    # and the dropped keys are named at WARNING (below): the rest of this module
    # fails closed on a version mismatch, so a silent drop would be the one
    # place a mismatch left no trace.
    model_config = ConfigDict(
        str_strip_whitespace=True, extra="ignore", hide_input_in_errors=True
    )

    @classmethod
    def _near_misses(cls, dropped: Sequence[str], data: dict) -> str:
        """The sentence that says a dropped key looks like a misspelled field.

        Dropping a key is right for a field a newer ASH added, and wrong for a
        known field spelled differently: ``candidate_scaner`` is read as no
        candidate set at all, which skips the one coverage check that needs it.
        A hand-edited record is the only way to get there, and the line above
        does not say what the dropped key cost, so a name close to a field this
        version reads (and not already supplied under its own name) is called
        out with the field it resembles.
        """
        wanted = [name for name in cls.model_fields if name not in data]
        found = []
        for key in dropped:
            close = difflib.get_close_matches(key, wanted, n=1, cutoff=0.8)
            if close:
                found.append(f"{_cut_text(key, _DROPPED_TEXT_SHOWN)} (for {close[0]})")
        if not found:
            return ""
        return (
            " Read as absent, because the name does not match: "
            + ", ".join(found)
            + ". A shard with no candidate_scanners is not checked for coverage "
            "of the set it was partitioned from."
        )

    @model_validator(mode="before")
    @classmethod
    def _name_the_dropped_keys(cls, data: Any) -> Any:
        """Log the keys of a provenance record this version ignores, by name.

        Once per record per process: one merge reads the same shard's record
        several times (collecting the assignments, ordering the shards, naming a
        shard in a message), and a line repeated five or six times for one
        shard reads as five or six shards.
        """
        if isinstance(data, dict):
            known = set(cls.model_fields)
            dropped = sorted(str(key) for key in data if key not in known)
            if dropped:
                shard = data.get("shard_index")
                # A results file can carry any value here and any number of
                # unknown keys: a list for the index, 100,000 keys. The line names
                # a text or numeric index, cut, and the first few keys, cut, with
                # the count of the rest; the memo holds a digest, not the keys.
                shard_text = (
                    _cut_text(str(shard), _DROPPED_TEXT_SHOWN)
                    if isinstance(shard, (str, int)) and not isinstance(shard, bool)
                    else None
                )
                memo_key = (
                    shard_text if shard_text is not None else type(shard).__name__,
                    hashlib.sha256(
                        "\0".join(dropped).encode("utf-8", "surrogatepass")
                    ).hexdigest(),
                )
                if memo_key in _WARNED_PROVENANCE_KEYS:
                    return data
                _WARNED_PROVENANCE_KEYS.add(memo_key)
                # The values are put in raw and the whole message is shown once,
                # by shown_on_one_line, which the log sink writes as it is. A value
                # shown here and the message shown again at the sink doubled the
                # backslash of every escape (``\\x1b`` for one ESC).
                where = f"shard {shard_text}" if shard_text is not None else "a shard"
                names = ", ".join(
                    _cut_text(name, _DROPPED_TEXT_SHOWN)
                    for name in dropped[:_DROPPED_KEYS_SHOWN]
                )
                if len(dropped) > _DROPPED_KEYS_SHOWN:
                    names += f", and {len(dropped) - _DROPPED_KEYS_SHOWN} more"
                ASH_LOGGER.warning(
                    shown_on_one_line(
                        f"The provenance of {where} carries {len(dropped)} field(s) "
                        f"this ASH does not know and ignores: {names}. The results "
                        "file was written by another ASH version; the fields this "
                        "version knows are read as usual."
                        + cls._near_misses(dropped, data)
                    ),
                    extra=NO_MARKUP,
                )
        return data

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
    selected_scanners: list[str] | None = Field(
        default=None,
        description=(
            "The subset of assigned_scanners this shard actually intended to run, "
            "after the --scanners allowlist, --exclude-scanners, --python-only and "
            "each scanner's own enabled flag. A third field rather than a narrowing of "
            "assigned_scanners, because that field's breadth is load-bearing for "
            "two existing readers -- see the class docstring. Intent and not "
            "outcome: a scanner whose tool is absent stays here, because 'nobody "
            "asked for it' and 'nobody could run it' route to different people. "
            "None on results written before this field existed."
        ),
    )
    intended_scanners: list[str] | None = Field(
        default=None,
        description=(
            "Every candidate scanner this executor's selection asks for, whichever "
            "shard owns it: candidate_scanners after the --scanners allowlist, "
            "--exclude-scanners, --python-only and each scanner's own enabled "
            "flag. Unlike selected_scanners, which covers assigned_scanners only, "
            "it covers every candidate. It lets ash merge tell a scanner no job "
            "asked for, which is the operator's choice, from one some job asked "
            "for and its owner did not, which is a coverage hole. None on results "
            "written before this field existed."
        ),
    )
    python_only: bool | None = Field(
        default=None,
        description=(
            "Whether this shard ran with --python-only. ash merge reads it to tell "
            "a sharded --python-only scan, where every shard leaves the non-Python "
            "scanners out, from a matrix whose jobs disagree on the flag, where a "
            "scanner one shard left out ran nowhere. None on results written before "
            "this field existed."
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
        ShardSelectionError: If the index and count are not a usable pair, or if
            neither is given. An unsharded scan has nothing to partition, so a
            caller that reaches this with no selection has a defect, and it is
            named here rather than surfacing as a TypeError from the arithmetic.
    """
    if shard_index is None and shard_count is None:
        raise ShardSelectionError(
            "partition_scanners needs both --shard-index and --shard-count; an "
            "unsharded scan has no partition to compute."
        )
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

    What this does NOT check, and where that check lives
    ----------------------------------------------------
    This function answers "did every shard report", not "did every shard report
    something". It takes ``ShardAssignment`` objects, which by design hold the
    assignment and not the outcome, so it cannot see a scanner's status at all: a
    shard that is present, index-correct and carrying a valid assignment passes
    every check below while having run nothing.

    That gap is real and is covered by ``cli.merge._verify_shard_contributions``,
    which refuses a shard that owned scanners and completed none of them. It lives
    there rather than here for two reasons. It needs the shard *results*, not just
    their assignments, and every other results-reading check
    (``_collect_assignments``, ``_verify_scanner_union``) is already in that
    module. And it is gated behind ``--fail-on-incomplete-scanners`` rather than
    unconditional, because four of the ten default scanners report MISSING on a
    machine without their tools installed -- whereas every condition below is
    wrong in any environment. A function whose six checks are unconditional and
    whose seventh depends on a flag would be harder to reason about than one that
    consistently answers a narrower question.

    Args:
        assignments: One entry per shard result being merged.

    Raises:
        ShardCoverageError: If no shards were supplied, if the shards disagree
            about the total count, if any index is missing or repeated, if two
            shards claim the same scanner, if the shards disagree about the
            candidate set, if the assignments do not union to it, or if a shard
            selected a scanner assigned to another shard or to no shard.
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

    # Counted, never materialized. shard_count is read from a results file and has
    # no upper bound, so set(range(expected_count)) could exhaust memory on a
    # corrupt or hostile count, and a refusal that listed every missing index
    # could run to megabytes. The count is exact; the listing stops at
    # MISSING_SHARD_INDICES_SHOWN.
    seen_set = set(seen_indices)
    missing_count = expected_count - len({i for i in seen_set if i < expected_count})
    if missing_count:
        shown = list(
            islice(
                (i for i in range(expected_count) if i not in seen_set),
                MISSING_SHARD_INDICES_SHOWN,
            )
        )
        more = missing_count - len(shown)
        listed = ", ".join(map(str, shown)) + (f" and {more} more" if more else "")
        raise ShardCoverageError(
            f"Missing shard results for {missing_count} of {expected_count} "
            f"indices ({listed}). Those scanners did not run, or their results "
            f"were never collected -- check whether the matching CI jobs "
            f"succeeded and uploaded their artifacts. Refusing to merge a partial "
            f"scan into a report that would read as complete."
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
                    f"{shown_shard_text(scanner)} "
                    f"(shards {claimed[scanner]} and {assignment.shard_index})"
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
    _verify_selection_within_assignment(assignments)


def _verify_selection_within_assignment(
    assignments: Sequence[ShardAssignment],
) -> None:
    """Check no shard intended to run a scanner another shard owns, or no shard owns.

    Two conditions ``selected_scanners`` supports refusing on, and it is worth
    being precise about why the others are not here. A scanner assigned to some
    shard and selected by none ran nowhere, which sounds like the refusal to make;
    but that is also exactly what a config-disabled or platform-declined scanner
    looks like, and the provenance cannot tell those apart. Refusing would break
    merges that have nothing wrong with them, which is the same trap narrowing
    ``assigned_scanners`` would have walked into.

    This one has no such reading. A shard reporting that it selected a scanner it
    does not own means the shard exclusion did not take effect on that executor, so
    two shards ran it and every finding it reported is counted twice. The overlap
    check above cannot see it: the overlap is between one shard's selection and
    another's assignment, and the assignments themselves are still disjoint.

    The second is a shard reporting that it selected a scanner no shard owns. The
    selection is taken from the assignment, so a scanner outside every assignment
    was selected by a run whose exclusion did not take effect either; it ran on
    every shard that selected it, outside the split, and the shard's provenance
    does not describe its run. The refusal names that case in its own words, since
    no other shard ran the scanner.

    A shard carrying no selection record is skipped rather than refused, unlike the
    candidate set. The distinction is which absence can hide something: a shard with
    no candidate set could be concealing the union hole, while a shard with no
    selection record only says less. Refusing the latter would stop a fan-out whose
    runners are mid-upgrade from merging at all.

    Args:
        assignments: One entry per shard result being merged.

    Raises:
        ShardCoverageError: If any shard selected a scanner assigned to another
            shard, or one assigned to no shard.
    """
    owner: dict[str, int] = {}
    for assignment in assignments:
        for scanner in _normalized(assignment.assigned_scanners):
            owner[scanner] = assignment.shard_index

    trespasses: list[str] = []
    for assignment in assignments:
        if assignment.selected_scanners is None:
            continue
        for scanner in _normalized(assignment.selected_scanners):
            holder = owner.get(scanner)
            if holder is None:
                # Selected by this shard and assigned to none. The selection is
                # taken from the assignment, so a scanner outside every assignment
                # was selected by a run whose exclusion did not take effect either,
                # and two shards selecting it would count its findings twice while
                # the overlap check, which reads assignments only, sees nothing.
                trespasses.append(
                    f"{shown_shard_text(scanner)} (selected by shard "
                    f"{assignment.shard_index}, assigned to no shard)"
                )
            elif holder != assignment.shard_index:
                trespasses.append(
                    f"{shown_shard_text(scanner)} (selected by shard "
                    f"{assignment.shard_index}, assigned to shard {holder})"
                )

    if trespasses:
        unowned = [
            item for item in trespasses if item.endswith("assigned to no shard)")
        ]
        listed = "; ".join(sorted(trespasses))
        if len(unowned) < len(trespasses):
            # At least one scanner another shard owns: the two-shard wording,
            # which tests/snapshot/errors pins, with a sentence for any scanner
            # no shard owns beside it.
            message = (
                "These shards intended to run a scanner assigned to another shard: "
                f"{listed}. A shard only runs what it was "
                "assigned, so the exclusion that implements the split did not take "
                "effect on that executor -- the scanner ran on both shards and its "
                "findings would be counted once per shard. The assignments themselves "
                "are disjoint, so no other check here can see this."
            )
            if unowned:
                # The header above speaks of two shards; a scanner outside every
                # assignment ran on whichever shards selected it.
                message += (
                    " A scanner assigned to no shard was selected by a run whose "
                    "exclusion did not take effect either: it ran on every shard that "
                    "selected it, outside the split, and its findings would be counted "
                    "once per such shard."
                )
        else:
            # Every selection names a scanner no shard owns: no other shard ran
            # it, so the two-shard wording would describe a run that did not
            # happen.
            message = (
                "These shards recorded selecting a scanner that is in no shard's "
                f"assignment: {listed}. A shard only runs what it was assigned, so "
                "its provenance does not describe its run: the exclusion that "
                "implements the split did not take effect on that executor, the "
                "scanner ran on every shard that selected it, outside the split, and "
                "its findings would be counted once per such shard. The assignments "
                "themselves are disjoint, so no other check here can see this."
            )
        raise ShardCoverageError(message)


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
            f"shard {a.shard_index}: "
            f"{', '.join(map(shown_shard_text, _normalized(a.candidate_scanners)))}"
            for a in sorted(with_candidates, key=lambda a: a.shard_index)
        )
        raise ShardCoverageError(
            f"The shards partitioned different scanner sets: {detail}. Each "
            f"partition is internally valid, so nothing else here can see this: "
            f"one executor was missing a plugin module, or a config override "
            f"was applied to some jobs and not others. Merging "
            f"would report a scan that never covered the scanners the smaller set "
            f"omitted."
        )

    candidates = set(candidate_sets.pop())
    uncovered = sorted(candidates - set(claimed))
    if uncovered:
        raise ShardCoverageError(
            f"These scanners were candidates on every shard but assigned to none: "
            f"{', '.join(map(shown_shard_text, uncovered))}. The partition did not "
            f"cover the set it was taken from, so no shard ran them and the merged "
            f"report would not say so."
        )

    unexpected = sorted(set(claimed) - candidates)
    if unexpected:
        raise ShardCoverageError(
            f"These scanners were assigned to a shard but are not in the candidate "
            f"set: {', '.join(map(shown_shard_text, unexpected))}. An assignment that "
            f"names a scanner the executor did not resolve cannot have been produced "
            f"by partitioning that set, so the provenance does not describe this run."
        )
