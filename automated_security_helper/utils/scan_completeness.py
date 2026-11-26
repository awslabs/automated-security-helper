# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan-completeness predicates: which scanners and converters did not finish.

``incomplete_scanners`` and ``scan_incompleteness`` answer "did every selected scanner
complete, and what did the scan lose" from an aggregated results model. They and the
helpers they reach used to live in ``interactions/run_ash_scan.py``, so any ``utils``
or ``core`` module that wanted the answer (a results-file reader, a baseline gate, a
diff) had to import upward into the ~8k-line CLI-interaction module, and anything that
imported such a module transitively loaded ``run_ash_scan``. They live here so the
dependency runs one way: ``interactions`` imports this module, never the reverse.

``interactions/run_ash_scan.py`` re-exports every name below, so existing callers and
the tests that patch ``run_ash_scan.<name>`` keep working. One edge needs more than a
re-export: the three readers of ``get_unified_scanner_metrics`` here
(:func:`scanner_statuses`, :func:`incomplete_scanners`, :func:`scan_incompleteness`)
read it through :func:`bind_scanner_metrics_reader`'s seam. A function that was moved
looks the name up in *this* module's namespace, so a patch of
``run_ash_scan.get_unified_scanner_metrics`` would no longer reach it; ``run_ash_scan``
binds a reader that looks the name up in its own namespace at call time, which keeps
that patch effective. Unbound, the seam is ``get_unified_scanner_metrics`` itself.
"""

from dataclasses import dataclass
from typing import (
    Any,
    Callable,
    Collection,
    Dict,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.unified_metrics import (
    NO_MISSING_REASON_RECORDED,
    UNUSABLE_COUNTERS,
    get_unified_scanner_metrics,
    recorded_reason,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    known_failed_input_kind,
    waives_gate,
)
from automated_security_helper.utils.content_db_staleness import (
    ContentDbAgeRecord,
    scanners_in_error_for_a_stale_database,
    stale_content_databases,
)
from automated_security_helper.utils.sarif_utils import is_result_suppressed
from automated_security_helper.utils.terminal_text import shown_on_one_line

_scanner_metrics: Callable[..., Any] = get_unified_scanner_metrics


def bind_scanner_metrics_reader(reader: Callable[..., Any]) -> None:
    """Make the predicates here read scanner metrics through *reader*.

    ``interactions/run_ash_scan.py`` binds a reader that resolves
    ``get_unified_scanner_metrics`` in its own namespace on every call, so a test that
    patches that name there still intercepts the reads these functions make. Nothing
    else needs to call this.
    """
    global _scanner_metrics
    _scanner_metrics = reader


# ---------------------------------------------------------------------------
# Scanner completeness
#
# The statuses whose outcome is known. This is the allowlist, and the incomplete set
# below is its complement, so the default for anything not named here is "incomplete"
# rather than "complete".
#
# That direction is the point. The classification used to be a two-member denylist,
# which meant every status it did not name -- including one this version has never
# heard of -- counted as complete. Reachable rather than hypothetical: `ashx merge`
# reads results files written by whatever ASH produced each shard, so a fan-out whose
# runners are mid-upgrade can hand this code a status string that is not in this
# enum, and a denylist reports that shard as a scanner that ran. An allowlist fails
# loudly on it instead.
#
# It also makes the derivation real. The comment here used to claim that a member
# added to ScannerStatus "surfaces here as a decision to make", which was not true of
# a hand-listed pair -- adding a member changed nothing and the new status defaulted
# to complete. As a complement it is true by construction: a new member is incomplete
# until someone deliberately adds it below.
#
# PASSED and FAILED both mean the scanner ran; FAILED already carries its verdict
# through the finding count.
#
# SKIPPED is the one entry here that is a decision rather than a definition, and it is
# load-bearing. SKIPPED means the scanner was not selected, and that is the mechanism
# sharding uses to divide work: core.sharding.exclusions_for_shard excludes every
# scanner the other shards own, so each shard of an n-way split records n-1 scanner
# sets as SKIPPED. Treating SKIPPED as incomplete would fail every shard of a
# perfectly healthy sharded scan. Operator-level --exclude-scanners lands in the same
# place, and an excluded scanner is one the operator said not to run.
#
# What SKIPPED cannot do is speak for a whole run. Every scanner being SKIPPED means
# the run selected nothing, which is caught where the selection is made -- see
# ScanPhase's allowlist resolution and .github/scripts/assert_scanners_completed.py --
# because a shard legitimately owns nothing when it is handed a count above the
# scanner count, and that merge still has to succeed.
_COMPLETE_SCANNER_STATUSES = frozenset(
    {
        ScannerStatus.PASSED.value,
        ScannerStatus.FAILED.value,
        ScannerStatus.SKIPPED.value,
    }
)

#: The parenthetical ``incomplete_scanners`` gives a FAILED scanner that found its
#: dependencies unavailable on one of its trees, and that ``scan_incompleteness``
#: reads to give the row's missing_reason under it.
_MISSING_ON_SOME_FILES = "MISSING on some files"

#: Every remaining ScannerStatus member: today ERROR (ran and failed) and MISSING
#: (selected, dependencies unavailable, never ran).
_INCOMPLETE_SCANNER_STATUSES = (
    frozenset({member.value for member in ScannerStatus}) - _COMPLETE_SCANNER_STATUSES
)

# The statuses that mean "this scanner executed and reached a verdict".
#
# Not the complement of anything. It is deliberately narrower than
# _COMPLETE_SCANNER_STATUSES, which tolerates SKIPPED one entry at a time because
# SKIPPED means "not selected" -- and a per-entry tolerance cannot answer whether the
# *set* measured anything. Every entry being SKIPPED passes the per-scanner pass while
# the run has shown the target to be neither clean nor dirty.
#
# Spelled identically to RAN_STATUSES in .github/scripts/assert_scanners_completed.py,
# so the two answer the status question the same way. Until this set existed here the
# script asserted the set-level condition and _compute_exit_code did not.
#
# ERROR is excluded even though an ERROR scanner did technically run, which is where
# this differs from ScannerState.ran in scripts/verify_external_target_scan.py. An
# ERROR scanner reached no verdict from its status alone.
#
# CANONICAL EXPLANATION of how the set-level answer differs from the CI script's.
# The other places that touch it (the docstring and RAN_STATUSES comment in
# .github/scripts/assert_scanners_completed.py, and the comment on the script quoted
# in _compute_exit_code) only point here.
#
# The set-level answer is not exactly the script's, and that is deliberate.
# no_scanner_ran also counts two kinds of ERROR scanner as having run:
#
# * one whose recorded target counts show a partial audit (audited_some_targets): it
#   evaluated some targets and lost the rest;
# * one in ERROR only because its content database is stale
#   (ran_against_a_stale_database): it ran, and the database is the failure.
#
# The script reads statuses only, so for results whose sole non-SKIPPED row is such an
# ERROR scanner it still finds that nothing ran, and ASH's no_scanner_ran field is
# False. The difference is harmless to the exit code, because both exit 1 on that file,
# but the cause differs by kind:
#
# * Partial audit: the ERROR row is listed by incomplete_scanners, so the per-scanner
#   arm of _compute_exit_code fails it. The script fails it too, because ERROR is not
#   in COMPLETE_STATUSES.
# * Stale database: scan_incompleteness DROPS that scanner's row from `scanners`
#   (_listed_only_for_a_stale_database), so the per-scanner arm finds nothing. The
#   exit 1 comes from the stale_content_databases arm, which does not depend on the
#   completeness gate. The script has no such arm and fails the ERROR row on its
#   status alone.
#
# Do not "restore" field-level agreement by dropping the two arms of no_scanner_ran:
# that brings back a no_scanner_ran of True beside an "ERROR (4 of 10 targets
# unevaluated)" row. Do not make the script read counts either: it runs without an
# importable ASH, and the exit codes already agree.
_RAN_SCANNER_STATUSES = frozenset(
    {
        ScannerStatus.PASSED.value,
        ScannerStatus.FAILED.value,
    }
)


def scanner_statuses(
    results: Optional[AshAggregatedResults],
) -> List[tuple[str, str]]:
    """(name, status) for every scanner in *results*, in scanner-name order.

    What :func:`no_scanner_ran` reads, and read through
    ``get_unified_scanner_metrics`` for the same reason
    :func:`incomplete_scanners` does: that function is what every reporter and the
    metrics table already use, so the set-level gate answers from the statuses the
    operator was shown rather than from a second, independently-derived read of
    ``results.scanner_results``.

    Deliberately just the pairs. An earlier form of this shared one pass with
    ``incomplete_scanners`` by filtering these pairs, which stopped being possible
    when that function grew a second arm reading the per-metric target counters --
    a shortfall is not visible in a (name, status) pair. Keeping this narrow is
    what makes the two gates independently correct; the cost is one extra pass over
    the metrics, which ``_compute_exit_code`` already takes for the findings count.
    """
    if results is None:
        return []
    return [
        (metric.scanner_name, metric.status)
        for metric in _scanner_metrics(asharp_model=results)
    ]


def no_scanner_ran(
    observed: List[tuple[str, str]],
    expected: Optional[List[str]] = None,
    ran_against_a_stale_database: Collection[str] = (),
    audited_some_targets: Collection[str] = (),
) -> bool:
    """True when this run reached no verdict about the target.

    Two conditions, and the second exists because the first could not express it.

    1. *observed* is non-empty and none of its scanners reached a verdict. SKIPPED
       has to be tolerated one entry at a time -- it is how sharding and
       ``--exclude-scanners`` record work a run was never meant to do -- so a file
       in which every entry is SKIPPED clears the per-scanner pass while having
       measured nothing.

    2. *observed* is empty AND *expected* is not. An empty scanner set used to be
       exempt unconditionally, on the reasoning that it is reachable from a
       legitimate ``--phases convert`` run. That reasoning is sound but covers two
       different states, and a boolean over ``observed`` alone cannot separate
       them: "the scan phase was not requested", which is benign, and "the scan
       phase ran and had nothing to run", which is the silent-zero case this gate
       exists for.

    *expected* is what separates them, and it needs no new state to do it.
    ``ScanPhase`` is what records ``metadata.expected_scanners``, so a recorded
    roster means the scan phase ran; no roster and no scanners means it never did.

    Defaults to None so a results file written by a version that recorded no roster
    -- which ``ashx merge`` reads, from whatever ASH produced each shard -- keeps the
    old benign reading rather than becoming a failure on upgrade.

    *ran_against_a_stale_database* names scanners recorded ERROR because their clean
    result came from a database the policy rejects
    (``scanners_in_error_for_a_stale_database``). They reached a verdict, so they
    count as having run, as they did when that result was recorded PASSED; the stale
    database fails the scan through its own arm.

    *audited_some_targets* names ERROR scanners whose recorded counts show a partial
    audit (``0 < failed < attempted``, :func:`_partial_coverage`). A scanner that
    evaluated some of its targets and lost the rest ran: when its survivors are clean
    the loss grades it ERROR, and "no scanner reached a verdict" would contradict the
    "4 of 10 targets unevaluated" line printed beside it. The loss itself still
    fails the scan through the incomplete-scanner arm.
    """
    if not observed:
        return bool(expected)
    return not any(
        status in _RAN_SCANNER_STATUSES
        or name in ran_against_a_stale_database
        or (status == ScannerStatus.ERROR.value and name in audited_some_targets)
        for name, status in observed
    )


def _partial_coverage(metric: Any) -> tuple[int, int] | None:
    """``(attempted, failed)`` when *metric* lost some of its input, else None.

    The tri-state on ``targets_attempted`` is the whole content of this function.
    ``None`` means the scanner does not track per-target outcomes and is making no
    claim -- bandit, checkov, grype, syft, detect-secrets and opengrep
    are all in that state (cdk-nag, cfn-nag and npm-audit track targets). Reading
    absence as "attempted 0,
    therefore lost everything" would fail every scan on every repository the
    moment the flag was turned on, which is the inverse of the defect being fixed
    here.

    Both counters are type-checked rather than trusted, matching what
    ``unified_metrics.target_counts`` already does to the serialized counters it
    reads. Two reasons, one of them load-bearing:

    * ``bool`` is an ``int`` subclass, so ``True`` would otherwise read as one
      attempted target and invent coverage that was never claimed.
    * This function is reached through whatever ``get_unified_scanner_metrics``
      returns, and the sibling test module patches that with MagicMocks whose
      every attribute is present and truthy. Without the check, a PASSED bandit
      built as a MagicMock would start reporting as a coverage failure and
      ``test_helper_lists_only_incomplete_scanners_with_statuses`` would break --
      a test asserting the correct thing, broken by the gate reading a mock's
      auto-attribute as a count.

    A failure count with no attempt count is a producer bug, not a third state:
    there is no honest denominator to print, so it is not reported rather than
    rendered as "3 of None" (``unified_metrics.target_counts`` classifies that
    report as untrustworthy before it ever reaches a metric here).

    A NEGATIVE count in either position is an untrustworthy claim, not the
    absence of one: ``target_counts`` answers the pair ``(-1, -1)`` for a
    report whose counters cannot be trusted, and a negative that arrives any
    other way is the same accounting defect. The pair is returned so the
    caller lists the scanner; reading it as None here would complete a scan
    off counters that are known to be wrong.
    """
    # A row whose stored counters were unusable carries None counts and this flag
    # (``unified_metrics.counters_unusable``); the pair is returned for it too, so the
    # caller lists the scanner. `is True`: the sibling tests hand this MagicMocks.
    if getattr(metric, "counters_unusable", False) is True:
        return UNUSABLE_COUNTERS
    attempted = getattr(metric, "targets_attempted", None)
    failed = getattr(metric, "targets_failed", None)
    if isinstance(attempted, bool) or not isinstance(attempted, int):
        return None
    if isinstance(failed, bool) or not isinstance(failed, int):
        return None
    if attempted < 0 or failed < 0:
        return attempted, failed
    if failed == 0:
        return None
    return attempted, failed


def incomplete_scanners(
    results: Optional[AshAggregatedResults],
) -> List[tuple[str, str]]:
    """(name, status) for every scanner that was selected and did not complete.

    "Did not complete" covers two distinct failures, and it did not always cover
    the second:

    1. The scanner never produced a result -- status ERROR or MISSING.
    2. The scanner ran, reported a status, and could not evaluate some of the
       targets it was given.

    A third shape is listed with (1): a scanner FAILED on its findings that found
    its dependencies unavailable on one of its trees. Findings outrank MISSING in
    its status, and the tree it could not scan is still a gap, so it is listed as
    ``FAILED (MISSING on some files)`` and its row's missing_reason names the tree.

    Originally only (1) was selected on, because (2) did not move a target's
    status: ``ScanResultsContainer.determine_status`` returned ERROR only once
    ``targets_failed >= targets_attempted`` (measured then on this repository:
    cdk-nag attempted 10 targets, failed 4, its per-target container reported
    PASSED, and the gate exited 0). The rule is now gate-first: on a partial
    loss the severity gate runs before the status settles, so such a run
    arrives here as FAILED when its surviving findings fail the gate and as
    ERROR otherwise -- an all-failed run, or one whose counters are
    inconsistent, stays ERROR unconditionally -- and the counts arm below is
    what prints the denominator an operator needs in either case.

    A sibling commit ORs ``any_target_errored`` into the ``error`` flag, so a
    target tree that lost ALL of its targets -- which ``determine_status``
    reports as ERROR -- reaches the rolled-up status where previously only the
    ``"source"`` report was consulted, and even that only when the scanner was
    absent from ``scanner_results``. That is a status change, it is not opted
    in, and it is the thing the CHANGELOG's "Behavior changes" entry
    describes. Under the gate-first rule a partial loss still moves the
    status -- to FAILED or ERROR as the gate decides -- and this list names
    the run in either case.

    No ``ScannerStatus`` member was added for case (2), and
    ``_INCOMPLETE_SCANNER_STATUSES`` was not widened; partial coverage reaches
    FAILED or ERROR through ``determine_status``'s gate-first rule instead.
    ``cli.merge._completed`` keys on status against that same set to answer a
    different question -- whether a shard's scanner ran at all -- so an ERROR
    entry reads not-completed there. Shard verification does not stop at that
    read: ``cli.merge._ran_partially`` consults the recorded counts for an
    ERROR entry, and one whose scanner audited some of its targets
    (``0 < failed < attempted``) counts as having run, so the shard merges with
    its real findings and this gate is what names the shortfall on the merged
    product. ``_verify_shard_contributions`` still refuses a merge where a
    shard's owned scanners show no sign of having run -- no counts, or every
    attempted target failed.

    Worth being precise about the residual risk, because two earlier versions of
    this comment got it wrong in opposite directions. One said ``_completed``
    inspects a ``ScannerTargetStatusInfo``, which declares no target counters, so
    the protection is structural rather than conventional. That is false, and
    measurably so: the model sets ``extra="allow"``, so counters written into
    ``scanner_results`` land in ``model_extra`` and a ``getattr`` for them
    succeeds. Nothing structural stops ``_completed`` reading coverage; what stops
    it is that it does not, which is a behavior and therefore something a test can
    hold. ``tests/unit/interactions/test_fail_on_partial_target_coverage.py``
    holds it, and mutating ``_completed`` to consult the counters reddens it.

    The other claimed no reporter and no summary table sees anything new, and this
    change is the reason both do. ``ScannerMetrics`` gained ``targets_attempted``
    and ``targets_failed``; the console table, the markdown report and
    ``ash.flat.json`` all carry them, and the first two grew an "Incomplete
    coverage" section. Measured on this repository, ``ash.summary.md`` gained
    ``### Incomplete coverage`` and ``ash.flat.json`` gained the two keys. What is
    genuinely untouched is narrower and worth naming exactly: ``_completed``, and
    the DEFAULT exit code, which reaches this function only once
    ``_resolve_fail_on_incomplete_scanners`` returns true.
    ``tests/unit/cli/test_merge.py`` pins the boundary from the merge side.

    Precedence between the two arms is on TOTALITY, not on status. Total loss
    satisfies the coverage condition too -- ``failed >= attempted`` implies
    ``failed > 0`` -- and appending counts there would give an ERROR row a
    parenthetical it never had while saying nothing the status does not already
    say, so total loss reports the bare status.

    A PARTIAL shortfall reports its counts whatever the status is, and that is a
    correction rather than a preference. Selecting the bare-status arm on status
    alone made this function unable to deliver what it exists for in the case it
    was written for: an ERROR scanner that is only partly incomplete took the bare
    arm and printed ``cdk-nag: ERROR``, never ``cdk-nag: ERROR (4 of 10 targets
    unevaluated)``, so the counts the operator needs to tell "the tool is absent"
    from "the tool ran and skipped four templates" were dropped by the routing.
    An ERROR with no counters available still falls to the bare form, because there
    is no honest denominator to print.

    Read through ``get_unified_scanner_metrics`` rather than off
    ``results.scanner_results`` directly, so the gate and the report cannot
    disagree: that function is what every reporter and the metrics table already
    use, and it is where excluded-versus-missing precedence is decided. The target
    counters are read from the same rows for the same reason -- ``ScannerMetrics``
    is what the summary table prints, so the gate fails on exactly the numbers the
    operator was shown rather than on a second, independently-derived count.

    An allowlist narrowing -- ``--scanners bandit`` -- does not trip this, because
    the scanners it leaves out are recorded SKIPPED. That was not always true: the
    scan phase used to validate a scanner's dependencies before checking whether it
    had been selected, so on a host without cfn-nag, grype and syft a
    ``--scanners bandit`` run reported those three MISSING while the six
    tool-present scanners it left out reported SKIPPED. Which status an unselected
    scanner got therefore depended on whether its tool happened to be installed.
    See ``core/phases/scan_phase.py`` for the ordering that fixed it.

    Filtering here against ``opts.scanners`` was the alternative and is rejected:
    it would make the exit code disagree with the status the report prints for the
    same scanner, and it has no counterpart in ``ashx merge``, which has no scanner
    selection to consult. Fixing the recorded status instead makes both agree.

    Tested against ``_COMPLETE_SCANNER_STATUSES`` and not against
    ``_INCOMPLETE_SCANNER_STATUSES``, though the two are complements over the enum.
    ``metric.status`` is a plain string that may have come from a results file this
    version did not write, and only the allowlist form treats a status outside the
    enum entirely as incomplete rather than as a scanner that ran.

    Args:
        results: The aggregated results, or None when the scan produced none.

    Returns:
        Pairs in scanner-name order, empty when every selected scanner completed.
        The second element is the scanner's own status for a status-based
        incompleteness, and that status followed by the unevaluated-target counts
        for a coverage-based one. It is a display string, not a status token:
        both callers interpolate it into a message and neither parses it.
    """
    if results is None:
        return []

    # A scanner that ran against a content database past its declared bound, under the
    # default `content_db_staleness: fail`, is incomplete in the sense this function
    # means: its findings are real, and its silence about anything published since the
    # database was built is not. Listed here so the callers that read only this list --
    # the workspace layer and `ashx merge` -- name it. Under `warn` the record is not
    # enforced and is not listed.
    #
    # The exit code does NOT come from this arm. A stale database fails the scan
    # whether or not `fail_on_incomplete_scanners` is on, so `scan_incompleteness`
    # carries it in its own field, which `_compute_exit_code` reads, and drops a row
    # listed here only for its stale database so the one condition is not reported
    # twice. That includes the ERROR a clean result from such a database is recorded
    # as. See `_listed_only_for_a_stale_database`.
    stale_by_scanner: dict[str, list[str]] = {}
    for record in stale_content_databases(results, enforced_only=True):
        stale_by_scanner.setdefault(record.scanner, []).append(record.name)

    def _with_stale(name: str, status: str) -> tuple[str, str]:
        names = stale_by_scanner.pop(name, None)
        if names:
            status = f"{status} (stale content database: {', '.join(names)})"
        return (name, status)

    listed: list[tuple[str, str]] = []
    for metric in _scanner_metrics(asharp_model=results):
        # Against the allowlist, not against _INCOMPLETE_SCANNER_STATUSES, and the
        # two are not interchangeable here even though they partition the enum.
        # `metric.status` is a plain string that may have come from a results file
        # this version did not write -- `ashx merge` reads shard results from
        # whatever ASH produced each one -- and only the allowlist form treats a
        # status outside the enum entirely as incomplete rather than as a scanner
        # that ran. This arm arrived from one side of a merge spelled as
        # `in _INCOMPLETE_SCANNER_STATUSES`, which is the denylist that inversion
        # replaced; `TestStatusClassificationFailsClosed` is what catches it.
        status_is_incomplete = metric.status not in _COMPLETE_SCANNER_STATUSES
        shortfall = _partial_coverage(metric)
        # The third shape in the docstring. `is True`, not truthiness: the sibling
        # tests hand this MagicMock metrics whose every attribute is truthy.
        missing_a_tree = (
            metric.status == ScannerStatus.FAILED.value
            and metric.dependencies_missing is True
        )
        shown = (
            f"{metric.status} ({_MISSING_ON_SOME_FILES})"
            if missing_a_tree
            else metric.status
        )

        # No usable counters. The status is the only thing there is to report, so
        # this is the arm an ERROR or MISSING with no denominator falls to.
        if shortfall is None:
            if status_is_incomplete or missing_a_tree:
                listed.append(_with_stale(metric.scanner_name, shown))
            elif metric.scanner_name in stale_by_scanner:
                listed.append(_with_stale(metric.scanner_name, shown))
            continue

        attempted, failed = shortfall
        # An untrustworthy claim: a counter that was present but not a genuine
        # non-negative int. There is no honest denominator to print, but the
        # scanner made a coverage claim that cannot be read, which is a gap in
        # its own right -- dropping the row would complete the scan on the
        # writer's behalf.
        if attempted < 0 or failed < 0:
            listed.append(
                _with_stale(
                    metric.scanner_name,
                    f"{shown} (unreadable target counters, coverage unknown)",
                )
            )
            continue

        # Total loss, and a status that already says so. The counts would add a
        # parenthetical that repeats the status.
        if status_is_incomplete and failed >= attempted:
            listed.append(_with_stale(metric.scanner_name, shown))
            continue

        # A partial shortfall against a known denominator, whatever the status.
        # Selecting on status ahead of this is what dropped the counts from the
        # measured case.
        listed.append(
            _with_stale(
                metric.scanner_name,
                f"{shown} ({failed} of {attempted} targets unevaluated)",
            )
        )
    return listed


def _failed_inputs_reason(failed_inputs: Sequence[Any], shown: int = 5) -> str:
    """``could not convert 2 inputs: a.ipynb, b.ipynb``, naming at most ``shown``.

    The names are the scanned tree's, and this reason is printed and logged:
    ``incomplete_converters`` shows the whole reason once, so each name is left
    as it is here.
    """
    paths = [
        str(
            getattr(item, "path", None)
            or (item.get("path") if isinstance(item, dict) else None)
            or "?"
        )
        for item in failed_inputs
    ]
    named = ", ".join(paths[:shown])
    if len(paths) > shown:
        named += f" and {len(paths) - shown} more"
    noun = "input" if len(paths) == 1 else "inputs"
    return f"could not convert {len(paths)} {noun}: {named}"


def _limit_refusals_reason(refused_inputs: Sequence[Any], shown: int = 5) -> str:
    """``refused 1 input over an extraction limit: a.zip (max_total_bytes)``.

    Each archive's name is left as it is, as in _failed_inputs_reason.
    """
    named = [
        f"{getattr(item, 'path', '?')} ({getattr(item, 'limit', '?')})"
        for item in refused_inputs
    ]
    listed = ", ".join(named[:shown])
    if len(named) > shown:
        listed += f" and {len(named) - shown} more"
    noun = "input" if len(named) == 1 else "inputs"
    return f"refused {len(named)} {noun} over an extraction limit: {listed}"


class IncompleteConverter(NamedTuple):
    """One ``incomplete_converters`` row: the converter, why, and what failed.

    ``kinds`` is the distinct ``kind`` of the non-accepted failed-input records
    behind the reason, sorted, plus the marker ``"limit"`` for a row whose
    ``refused_inputs`` name an extraction limit; empty for a converter that did
    not run (a crash, or dependencies unsatisfied). Carried as data rather than
    as the reason's type, so a string operation or a JSON round trip keeps it
    and the MCP payload can pass it to clients; the console chooses its advice
    from it. Indexes like the (name, reason) pair it grew from, so a hand-built
    pair still reads as a row with no kinds.
    """

    name: str
    reason: str
    kinds: Tuple[str, ...] = ()


def incomplete_converters(
    results: Optional[AshAggregatedResults],
) -> List["IncompleteConverter"]:
    """A row for every converter that was meant to run and did not.

    Conversion produces the second set of targets the scanners are given: notebooks
    become Python, archives become their contents. A converter that crashed or whose
    tool was absent therefore costs scan coverage, and it did so with no effect on
    any verdict -- the scanners that ran reported PASSED on the targets they were
    handed, and nothing asked whether the targets that should have existed did.

    Four conditions, read off the recorded row rather than re-derived:

    1. ``failure`` is set -- the converter raised, or was dropped by the plugin
       filter for a reason its own dependency check did not explain. ConvertPhase
       records both.
    2. ``failed_inputs`` has a record that is not accepted -- the converter ran,
       and some of its inputs could not be converted: nbconvert exited non-zero
       on a notebook, could not be run, or an archive could not be extracted.
       Each one is a file the scanners never saw in converted form, which is the
       same loss as condition 1 at a smaller scale. A record whose ``accepted``
       is True together with kind "input" (an input error a suppression with
       rule_id "ash-unconverted-input" accepts) stays in the row and is left out
       here: the loss was reviewed. An accepted record of any other kind still
       counts, because only the writer promises a tool failure is never
       accepted, and a shard file can come from any producer.
    3. A ``refused_inputs`` entry names a ``limit`` -- an archive over one of the
       archive converter's extraction limits, refused whole, so none of its
       contents reached the scanners. A refusal without one (a symlinked input, a
       link or ``..`` member, a nested archive, a Git LFS pointer) does not count:
       those refuse one input or member that is not to be read at all, and the
       scan reports them without failing on them.
    4. ``dependencies_satisfied`` is False -- its external tool was not available.
       Read as "it never ran" is an inference of this function, not a promise of
       the writer, so the one exemption (``candidate_inputs`` an explicit 0) is
       taken only for a row that shows no sign of a run: no converted paths, no
       failed-input records of any kind and no refused inputs. The reason listed
       is the row's own ``dependency_unavailable_reason`` when it carries one.

    ``excluded`` is checked first and wins over all of them. It is the converter-side
    counterpart of a SKIPPED scanner: work the run was never meant to do, which is
    what a config-disabled converter and one dropped by
    ``--python-based-plugins-only`` are. A gate that failed on those would fail every
    run that turns conversion off, which is a supported configuration.

    Read with ``getattr`` because a results file written by an older version carries
    rows without ``failure`` or ``failed_inputs``, and ``ashx merge`` reads shard
    results from whatever ASH produced each one.

    Args:
        results: The aggregated results, or None when the scan produced none.

    Returns:
        ``IncompleteConverter`` rows in the order they were recorded, empty when
        every converter either ran or was excluded. The reason is a display
        string, not a token; the caller interpolates it into a message and does
        not parse it. For condition 2 the row's ``kinds`` names what failed.
    """
    if results is None:
        return []

    listed: list[IncompleteConverter] = []
    for name, row in (getattr(results, "converter_results", None) or {}).items():
        if getattr(row, "excluded", False):
            continue
        failure = getattr(row, "failure", None)
        failed_inputs = [
            record
            for record in (getattr(row, "failed_inputs", None) or [])
            if not waives_gate(record)
        ]
        over_limit = [
            item
            for item in getattr(row, "refused_inputs", None) or []
            if getattr(item, "limit", None)
        ]
        lost = [
            reason
            for reason in (
                _failed_inputs_reason(failed_inputs) if failed_inputs else "",
                _limit_refusals_reason(over_limit) if over_limit else "",
            )
            if reason
        ]
        # Both reasons reach the terminal, the log and the MCP payload, and both
        # can quote the scanned tree's file names: an exception's text as well as
        # the failed and refused inputs. So each is shown once here, as
        # utils/terminal_text.py shows a value (a ShownText, which every sink
        # leaves as it is); a caller that shows a whole message holding the
        # reason reads it back with as_written first (see _compute_exit_code).
        if failure:
            listed.append(IncompleteConverter(name, shown_on_one_line(str(failure))))
        elif lost:
            listed.append(
                IncompleteConverter(
                    name,
                    shown_on_one_line("; ".join(lost)),
                    # Read as the validator reads it: a record that skipped
                    # validation can hold any kind. An over-limit refusal is
                    # carried as the marker kind "limit", so the console's
                    # advice can name the limit remedy.
                    tuple(
                        sorted(
                            {
                                known_failed_input_kind(
                                    getattr(record, "kind", None)
                                ).value
                                for record in failed_inputs
                            }
                            | ({"limit"} if over_limit else set())
                        )
                    ),
                )
            )
        elif getattr(row, "dependencies_satisfied", True) is False:
            # An unavailable converter costs coverage only if it had inputs. The count
            # is established without its tool, which is what makes it answerable for a
            # converter that never ran -- see
            # ``ConverterPluginBase.candidate_input_count``.
            #
            # ONLY an explicit 0 exempts the row. None means the converter reports no
            # count, and that is treated exactly as this function treated every row
            # before the field existed: still incomplete. So a converter that has not
            # opted in, one whose count raised, and a results file written by a version
            # predating the field all keep the strict answer, and nothing is exempted by
            # missing information. ``is 0`` rather than ``== 0`` to keep False out:
            # ``bool`` is an ``int`` subclass and ``False == 0``, so a row carrying a
            # boolean would otherwise silence the gate.
            #
            # And the count exempts only a row that shows no sign of a run. "Never
            # ran" is this function's inference from ``dependencies_satisfied``, not
            # a promise of the writer: ConvertPhase asks the dependency check more
            # than once, so a converter whose first answer was False can still run,
            # and a shard row can come from any producer. A row with converted
            # paths, with failed-input records of any kind (an accepted one too), or
            # with refused inputs describes a converter that ran, and for such a row
            # a count of 0 answers a question that was not asked; it keeps the
            # strict answer every row had before the field existed.
            candidates = getattr(row, "candidate_inputs", None)
            ran = bool(
                (getattr(row, "converted_paths", None) or [])
                or (getattr(row, "failed_inputs", None) or [])
                or (getattr(row, "refused_inputs", None) or [])
            )
            if candidates is not None and not isinstance(candidates, bool):
                if candidates == 0 and not ran:
                    continue
            # The row's own reason when it carries one (the dependency check's
            # words, which the phase redacts and writes with the home directory
            # as ~), shown as a failure's text is; the fixed line otherwise, for a
            # row written before the field existed or assembled without it.
            reason = getattr(row, "dependency_unavailable_reason", None)
            listed.append(
                IncompleteConverter(
                    name,
                    shown_on_one_line(str(reason))
                    if isinstance(reason, str) and reason
                    else "dependencies unavailable, so it never ran",
                )
            )
    return listed


def _result_rule_id(result: Any) -> str:
    """The rule a SARIF result names: ``ruleId``, else ``rule.id``.

    SARIF lets a result name its rule either way (3.27.5 ``ruleId`` and 3.27.6
    ``rule``, a reference whose ``id`` is the rule's), and a tool that writes only
    the reference is as valid as one that writes the id. A gate that read ``ruleId``
    alone could not pair such a result with its notification, so a suppression of
    its not-evaluated results did not reach the gate. Empty when neither is set.
    """
    rule_id = getattr(result, "ruleId", None)
    if rule_id:
        return str(rule_id)
    reference = getattr(result, "rule", None)
    referenced = getattr(getattr(reference, "root", None), "id", None)
    return str(referenced) if referenced else ""


def unevaluated_rules(results: Optional[AshAggregatedResults]) -> List[str]:
    """Every rule a scanner reported, at run level, that it could not evaluate.

    WHY THIS IS A SECOND FUNCTION RATHER THAN PART OF ``incomplete_scanners``
    -----------------------------------------------------------------------
    ``incomplete_scanners`` answers "which scanners lost whole targets", and it
    answers it from the target counters. A rule that raised mid-evaluation loses
    neither a scanner nor a target: the scanner ran, the target was read, most of
    the rules reached a verdict, and one did not. Counting it as a lost target
    would overstate in a way that is measurable rather than theoretical --
    ``ScanResultsContainer.determine_status`` moves the whole run's grade once
    any attempted target failed (FAILED when the surviving findings fail the
    severity gate, ERROR otherwise), so a rule that raises on even one template
    would regrade the scanner's whole run, and one that raises on every template (which is
    the normal case for one that cannot resolve an intrinsic) would report the
    scanner as having evaluated nothing -- the cdk-nag scanner's own log line
    would read "No rules were evaluated" about a run that evaluated all but one
    of its rules.

    So the granularity is the rule, and the fact is read from where SARIF already
    puts it.

    WHAT IT READS, AND WHY THAT IS THE RIGHT CHANNEL
    -----------------------------------------------
    ``invocation.toolExecutionNotifications`` is, in the schema's own words, "A
    list of runtime conditions detected by the tool during the analysis", and
    ``notification.associatedRule`` is "A reference used to locate the rule
    descriptor associated with this notification". A rule raising instead of
    returning a verdict is a runtime condition, and the rule it happened to is
    what to associate it with. The cdk-nag scanner already writes exactly that.

    Reading it here rather than inventing a counter is what makes this gate
    scanner-agnostic: any scanner -- or any externally-produced SARIF that ASH
    ingests -- which reports an error-level runtime condition is reporting that
    part of its analysis did not run, and that is the thing being gated on.

    ONLY ``level == "error"``. ``warning`` is the field's default and a tool may
    use it for conditions that cost no coverage, so gating on it would fail scans
    for notes. The cdk-nag scanner sets ``error`` deliberately and says so.

    ``.value`` RATHER THAN ``str()`` ON THE LEVEL. ``Level`` is a str-mixin enum,
    so ``Enum.__str__`` still wins and ``str(Level.error)`` renders
    ``"Level.error"``, which matches nothing. Comparing the raw member against
    ``"error"`` works because of the str mixin, but only for a model built
    in-process; a model round-tripped through JSON carries a plain string. Both
    shapes are handled by taking ``.value`` when it is there.

    Read from the in-memory model rather than re-reading ``reports/ash.sarif``.
    Verified end to end against a real cdk-nag run: the notifications survive
    ``sanitize_sarif_paths``, ``apply_suppressions_to_sarif``,
    ``attach_scanner_details``, ``merge_sarif_report``, and a second scanner
    merging into the same aggregate. Nothing in that chain rewrites them, which
    is why no disk read is needed to see them.

    SUPPRESSIONS ARE HONORED, AND THAT IS NOT A CONVENIENCE
    ------------------------------------------------------
    A notification carries no suppression of its own -- SARIF puts suppressions on
    results -- so read naively this gate would be unsuppressable, and an operator
    who has already reviewed a rule's failure and accepted not knowing its verdict
    would have no way to say so. That is not hypothetical: this repository's own
    ``.ash.yaml`` carries fifteen such entries under the heading "rules that
    threw and never ran", each with a reviewed reason, and its own note calls
    naming them "the only way to keep the exit code honest". A gate that ignored
    them would fail ASH's own default scan with no escape hatch, which is a worse
    defect than the one being fixed.

    So a rule is reported only when at least one of its not-evaluated results is
    unsuppressed. The results are what suppression applies to, and consulting them
    is what lets the existing mechanism reach a fact recorded somewhere it cannot
    be attached. Unsuppressed is read as every other consumer reads it
    (``utils.sarif_utils.is_result_suppressed``): a suppression whose state is
    ``rejected`` or ``underReview`` has not taken effect (SARIF 3.35.4) and does
    not quiet the rule.

    ``kind`` is the filter rather than the cdk-nag property bag, so this stays
    generic to SARIF. Restricting to not-evaluated rows matters: one rule can throw
    on one resource while reaching a verdict on another, and counting an ordinary
    unsuppressed finding as evidence would report a rule whose only failure was
    suppressed.

    A rule with an error-level notification and NO matching result is reported.
    Absence of a result is not evidence of suppression, and defaulting to silence
    there would reintroduce the silent pass through the one shape nothing checks.

    Returns:
        Rule ids in sorted order, deduplicated, with the notification's message
        substituted for a notification that names no rule so a condition is never
        silently dropped for lacking an id. Empty when every rule was evaluated,
        which is the case for every scanner that reports no such condition at all.
    """
    sarif = getattr(results, "sarif", None)
    if sarif is None:
        return []

    reported: set[str] = set()
    for run in getattr(sarif, "runs", None) or []:
        # Per run, because a rule id is only unique within the tool that reported
        # it and the aggregate holds one run per merged scanner.
        unsuppressed: set[str] = set()
        has_result: set[str] = set()
        for result in getattr(run, "results", None) or []:
            kind = getattr(result, "kind", None)
            if getattr(kind, "value", kind) != "notApplicable":
                continue
            rule_id = _result_rule_id(result)
            has_result.add(rule_id)
            # Suppressed means a suppression IN EFFECT, the one reading every
            # consumer makes: a suppression whose state is rejected or
            # underReview (SARIF 3.35.4) was never an approval, so the throw it
            # sits on still reports the rule, the fail-closed side.
            if not is_result_suppressed(result):
                unsuppressed.add(rule_id)

        for invocation in getattr(run, "invocations", None) or []:
            for notification in (
                getattr(invocation, "toolExecutionNotifications", None) or []
            ):
                level = getattr(notification, "level", None)
                if getattr(level, "value", level) != "error":
                    continue
                associated = getattr(notification, "associatedRule", None)
                named_rule = getattr(getattr(associated, "root", None), "id", None)
                if named_rule:
                    notified_id = str(named_rule)
                    if notified_id in has_result and notified_id not in unsuppressed:
                        continue
                    reported.add(notified_id)
                    continue
                message = getattr(getattr(notification, "message", None), "root", None)
                text = str(getattr(message, "text", "") or "").strip()
                reported.add(text or "an unnamed rule")
    return sorted(reported)


#: How an incomplete scanner's recorded status reads as a reason in a structured
#: payload. ``missing_dependencies`` is the token ``skipped_scanners`` already uses
#: for the same status, so a client sees one spelling for one cause.
_INCOMPLETE_SCANNER_REASONS = {
    ScannerStatus.MISSING.value: "missing_dependencies",
    ScannerStatus.ERROR.value: "error",
}


def missing_on_some_files(display_status: str) -> bool:
    """Whether an ``incomplete_scanners`` display status is a ``FAILED (MISSING on
    some files)`` row.

    The one test behind the payload's ``missing_dependencies`` reason, shared by
    :func:`scan_incompleteness` and the workspace surface's coverage (which has only
    the display status the outcome stored), so the two cannot read it differently.
    """
    return f"({_MISSING_ON_SOME_FILES})" in display_status


def _row_is_missing(status: str) -> bool:
    """Whether an ``incomplete_scanners`` display status is a MISSING row: the
    scanner could not run for lack of a dependency, on every file (``MISSING``) or
    on one tree (``FAILED (MISSING on some files)``)."""
    return status.split(" (", 1)[
        0
    ] == ScannerStatus.MISSING.value or missing_on_some_files(status)


def incomplete_scanner_reason(
    status: str, partial: bool = False, missing_dependencies: bool = False
) -> str:
    """The reason token for a scanner ``incomplete_scanners`` listed, from its status.

    A scanner listed with a status the per-scanner pass accepts (PASSED, FAILED,
    SKIPPED) is there for the targets it lost, not for its status.

    ``partial`` says the scanner's recorded counts show a partial audit
    (``0 < failed < attempted``). That is the reason the row exists whatever
    status the writer graded -- FAILED or ERROR under the gate-first status
    rule, PASSED in a results file written before it -- so it outranks the
    status token:
    telling "the tool never ran" apart from "the tool ran and lost some
    targets" is this token's whole job, and keying it on the status alone made
    every current scan's partial loss read ``error``.

    ``missing_dependencies`` says the row is a ``FAILED (MISSING on some files)``
    one: the scanner could not run on one tree for lack of its dependencies, which
    is not a scanner that ran and lost targets, so it outranks ``partial``.
    """
    if missing_dependencies:
        return "missing_dependencies"
    if partial:
        return "partial_coverage"
    if status in _INCOMPLETE_SCANNER_REASONS:
        return _INCOMPLETE_SCANNER_REASONS[status]
    if status in _COMPLETE_SCANNER_STATUSES:
        return "partial_coverage"
    return "unrecognized_status"


@dataclass(frozen=True)
class ScanIncompleteness:
    """Every reason a finished scan exits 1 for coverage rather than for a crash.

    One field per arm of the exit-1 half of ``_compute_exit_code``, which reads its
    verdict from this object rather than from its own calls to the primitives. That
    is what makes it safe for anything else to act on: the MCP runner reports a scan
    ``incomplete`` instead of ``failed`` from this object, and if the two read the
    question separately, the status a client sees and the exit code the CLI returns
    could disagree on the same results.

    Truthy when any field is set. Empty for ``results is None``, which also exits
    1 but means no results exist. That is a crash, and it does not belong in here.
    """

    #: ``incomplete_scanners`` rows: (name, display status).
    scanners: Tuple[Tuple[str, str], ...] = ()
    #: Names from ``scanners`` whose recorded counts show a partial audit
    #: (``0 < failed < attempted``), whatever status the writer graded. The
    #: payload's reason token reads ``partial_coverage`` for these; see
    #: :func:`incomplete_scanner_reason`.
    partial_coverage: Tuple[str, ...] = ()
    #: Names from ``scanners`` listed as ``FAILED (MISSING on some files)``: the
    #: payload's reason token reads ``missing_dependencies`` for these.
    missing_dependencies: Tuple[str, ...] = ()
    #: Every scanner's recorded status, the raw token rather than the display
    #: string, so a payload can say MISSING or ERROR without parsing prose.
    observed: Tuple[Tuple[str, str], ...] = ()
    #: The set-level arm: scanners were expected or recorded, and none reached a
    #: verdict.
    no_scanner_ran: bool = False
    #: ``incomplete_converters`` rows.
    converters: Tuple["IncompleteConverter", ...] = ()
    #: ``unevaluated_rules``. Not behind the completeness gate.
    unevaluated_rules: Tuple[str, ...] = ()
    #: Content databases past their declared bound under ``content_db_staleness:
    #: fail``. Not behind the completeness gate either; its opt-out is
    #: ``--allow-stale-content-db`` or ``content_db_staleness: warn``, under which
    #: nothing is recorded here.
    stale_content_databases: Tuple[ContentDbAgeRecord, ...] = ()
    #: (name, missing_reason) for each MISSING scanner in ``scanners`` that recorded
    #: one, so the console can say why it did not run. Not a cause of exit 1 on its
    #: own and not in the payload, which carries the rows.
    missing_reasons: Tuple[Tuple[str, str], ...] = ()
    #: (name, reason) for each scanner whose run ended with a tool ASH could not
    #: stop; the reason names the process id. Not behind the completeness gate:
    #: the tool may still write into the output directory after the gate has read
    #: it, so this one fails the run whatever the gate says.
    could_not_stop: Tuple[Tuple[str, str], ...] = ()

    def __bool__(self) -> bool:
        return bool(
            self.scanners
            or self.no_scanner_ran
            or self.converters
            or self.unevaluated_rules
            or self.stale_content_databases
            or self.could_not_stop
        )

    def to_payload(self) -> Dict[str, object]:
        """The structured form an MCP client reads. JSON-serializable."""
        raw_status = dict(self.observed)
        scanners = []
        for name, detail in self.scanners:
            status = raw_status.get(name, "")
            scanners.append(
                {
                    "scanner": name,
                    "status": status,
                    "reason": incomplete_scanner_reason(
                        status,
                        partial=name in self.partial_coverage,
                        missing_dependencies=name in self.missing_dependencies,
                    ),
                    "detail": detail,
                }
            )
        return {
            "incomplete_scanners": scanners,
            "no_scanner_ran": self.no_scanner_ran,
            "incomplete_converters": [
                {
                    "converter": row[0],
                    "reason": row[1],
                    "failed_input_kinds": list(getattr(row, "kinds", ()) or ()),
                }
                for row in self.converters
            ],
            "unevaluated_rules": list(self.unevaluated_rules),
            "stale_content_databases": [
                record.to_dict() for record in self.stale_content_databases
            ],
            "could_not_stop": [
                {"scanner": name, "reason": reason}
                for name, reason in self.could_not_stop
            ],
        }


def scanners_that_could_not_stop(
    results: Optional[AshAggregatedResults],
) -> List[Tuple[str, str]]:
    """(scanner, reason) for each scanner whose run ended with a tool ASH could
    not stop.

    Read from the per-target reports' recorded ``could_not_stop`` key, which the
    executor copies from the state the run itself recorded, with the reason
    naming the process id. The reports' error lines are never searched: they also
    carry the tool's own output, and a tool that prints the same words is data,
    not a stop that failed. One reason per scanner: they all name the same
    ending, and the exit-code arm prints each row once.
    """
    rows: List[Tuple[str, str]] = []
    if results is None:
        return rows
    # Read like every carrier read: tolerant of a results object that does not
    # carry the field, which answers no rows rather than raising.
    reports_by_scanner = getattr(results, "additional_reports", None) or {}
    if not isinstance(reports_by_scanner, dict):
        return rows
    for scanner, reports in reports_by_scanner.items():
        if not isinstance(reports, dict):
            continue
        reason = None
        for report in reports.values():
            if not isinstance(report, dict):
                continue
            recorded = report.get("could_not_stop")
            if isinstance(recorded, str) and recorded:
                reason = recorded
                break
        if reason is not None:
            rows.append((scanner, reason))
    return rows


def scan_incompleteness(
    results: Optional[AshAggregatedResults],
    *,
    gate: bool,
    one_shard_of_a_split: bool = False,
) -> ScanIncompleteness:
    """Ask the exit-1 coverage questions of *results*, under the gate as resolved.

    ``gate`` is ``_resolve_fail_on_incomplete_scanners``'s answer. When it is off,
    only the unevaluated-rule arm is asked, because that arm is the only one
    ``_compute_exit_code`` asks with the gate off. Pass ``gate=True`` to get the
    facts whatever the gate says, which is what a report that states coverage
    needs.

    ``one_shard_of_a_split`` exempts the set-level arm for the reason
    ``_compute_exit_code`` gives at that arm.

    A stale content database is reported in ``stale_content_databases`` whatever the
    gate says, and ONLY there. ``incomplete_scanners`` also lists its scanner, with
    the database named in the status, so that the workspace layer and ``ashx merge``
    see it; a row that is there for nothing else is dropped from ``scanners`` here.
    Otherwise the one condition would be reported twice with the gate on -- once as
    an incomplete scanner whose advice is to install a tool that ran, and once as a
    stale database -- and once with it off, so the MCP payload and the console
    message would change shape with a gate the staleness check does not consult.

    "Nothing else" covers the ERROR a clean result from such a database is recorded
    as (``scanners_in_error_for_a_stale_database``): that ERROR is the stale
    database, so its row is dropped too, and the scanner counts as having run for
    the set-level arm. A scanner that is stale AND lost targets, failed to run, or
    is MISSING keeps its row: that part is a coverage gap in its own right.
    """
    if results is None:
        return ScanIncompleteness()
    unevaluated = tuple(unevaluated_rules(results))
    stale = tuple(stale_content_databases(results, enforced_only=True))
    could_not_stop = tuple(scanners_that_could_not_stop(results))
    if not gate:
        return ScanIncompleteness(
            unevaluated_rules=unevaluated,
            stale_content_databases=stale,
            could_not_stop=could_not_stop,
        )
    observed = scanner_statuses(results)
    expected_roster = list(
        getattr(getattr(results, "metadata", None), "expected_scanners", None) or []
    )
    stale_scanners = {record.scanner for record in stale}
    in_error_for_staleness = scanners_in_error_for_a_stale_database(results)
    rows = tuple(
        (name, status)
        for name, status in incomplete_scanners(results)
        if not _listed_only_for_a_stale_database(
            name, status, stale_scanners, in_error_for_staleness
        )
    )
    missing_reasons = []
    for name, status in rows:
        if not _row_is_missing(status):
            continue
        reason = recorded_reason(results, name, "missing_reason")
        if reason and reason != NO_MISSING_REASON_RECORDED:
            missing_reasons.append((name, reason))
    # The counts behind each row, read off the same metrics the gate reads, so
    # the reason token and the gate's message cannot disagree about the same
    # scanner.
    row_names = {name for name, _ in rows}
    # Through _partial_coverage, the reader incomplete_scanners prints its counts
    # with, so a bool counter (an int subclass) is no partial claim here either
    # and a metrics row that does not model counts raises nothing. Total loss
    # (failed >= attempted) is a partial claim for neither reader.
    # A negative count in either position is _partial_coverage's "untrustworthy
    # counters" answer, which incomplete_scanners lists as such; it is no partial
    # audit, so it is not also claimed as one here.
    partial_audits = {
        metric.scanner_name: metric
        for metric in _scanner_metrics(results)
        if (counts := _partial_coverage(metric)) is not None
        and 0 <= counts[1] < counts[0]
    }
    partial_coverage = tuple(name for name in partial_audits if name in row_names)
    # An ERROR scanner that audited some targets ran, whether or not it is listed
    # above: see no_scanner_ran's audited_some_targets.
    audited_some_targets = {
        name
        for name, metric in partial_audits.items()
        if metric.status == ScannerStatus.ERROR.value
    }
    missing_dependencies = tuple(
        name for name, status in rows if missing_on_some_files(status)
    )
    return ScanIncompleteness(
        scanners=rows,
        partial_coverage=partial_coverage,
        missing_dependencies=missing_dependencies,
        missing_reasons=tuple(missing_reasons),
        observed=tuple(observed),
        no_scanner_ran=(
            not one_shard_of_a_split
            and no_scanner_ran(
                observed,
                expected_roster,
                ran_against_a_stale_database=in_error_for_staleness,
                audited_some_targets=audited_some_targets,
            )
        ),
        converters=tuple(incomplete_converters(results)),
        unevaluated_rules=unevaluated,
        stale_content_databases=stale,
        could_not_stop=could_not_stop,
    )


def _listed_only_for_a_stale_database(
    name: str,
    status: str,
    stale_scanners: Set[str],
    in_error_for_staleness: Collection[str] = (),
) -> bool:
    """Whether an ``incomplete_scanners`` row is there for its stale database alone.

    The status is followed by exactly the stale-database annotation
    ``incomplete_scanners`` appends, and nothing else (no target counts), and the
    status itself says nothing more: a complete one, or the ERROR a clean result
    from a rejected database is recorded as, which *in_error_for_staleness* names
    (``scanners_in_error_for_a_stale_database``). Any other ERROR, and MISSING, keep
    the row. The test is the one ``run_ash_scan`` applied to its console message
    when the staleness check landed, moved here so the exit code, the message and
    the MCP payload share it.
    """
    if not (
        name in stale_scanners
        and status.count(" (") == 1
        and "(stale content database:" in status
    ):
        return False
    base = status.split(" (", 1)[0]
    return base in _COMPLETE_SCANNER_STATUSES or (
        base == ScannerStatus.ERROR.value and name in in_error_for_staleness
    )
