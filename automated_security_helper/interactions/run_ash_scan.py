# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import os
import platform
import shutil
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, cast

import typer
from pydantic import BaseModel, ConfigDict, Field, field_validator

# `print` shadows the builtin on purpose: this is rich's documented import
# idiom, so every print() below renders markup and respects the console. The
# fix A004 wants is an alias, which would mean rewriting every call in this
# module for no behavior change -- and tests/unit/cli/mcp/test_stdout_jsonrpc_safety.py
# reasons about this exact import form.
from rich import print  # noqa: A004

from automated_security_helper.core.constants import (
    ASH_CONFIG_FILE_NAMES,
    ASH_EXIT_CODES,
    ASH_WORK_DIR_NAME,
    is_offline_mode,
)
from automated_security_helper.core.enums import (
    AshLogLevel,
    BuildTarget,
    ExecutionPhase,
    ExecutionStrategy,
    ExportFormat,
    RunMode,
    ScannerStatus,
)
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    ScannerSelectionError,
    WorkspaceDefinitionError,
)
from automated_security_helper.core.progress import ExecutionPhaseType
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.core.unified_metrics import (
    format_duration,
    get_unified_scanner_metrics,
)
from automated_security_helper.interactions.run_ash_container import run_ash_container
from automated_security_helper.interactions.run_ash_nix import run_ash_nix
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import WorkspaceExitCode
from automated_security_helper.utils.log import NO_MARKUP, escape_markup
from automated_security_helper.utils.sarif_utils import _resolve_result_severity
from automated_security_helper.utils.severity_ladder import (
    SEVERITIES,
    sarif_level_fails_threshold,
    severity_fails_threshold,
)
from automated_security_helper.workspace.plan import WorkspacePlan

if TYPE_CHECKING:
    # Imported for annotations only. A runtime import here would pull the
    # workspace executor -- and through it core.orchestrator -- into every
    # single-directory scan's import graph.
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        WorkspaceRunResult,
    )


# ---------------------------------------------------------------------------
# ScanOptions — bundles all 40+ parameters; eliminates 7 None-rebinding stanzas
# ---------------------------------------------------------------------------


class ScanOptions(BaseModel):
    """All parameters for a single run_ash_scan invocation."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Core paths
    source_dir: Path
    output_dir: Path

    # Workspace mode. When set, source_dir is the workspace ROOT and each project
    # is scanned with its own source_dir inside it. None means single-directory
    # mode, which is the only shape the rest of this module handles.
    workspace_plan: Optional[WorkspacePlan] = None
    allow_missing_projects: bool = False

    # General scan options
    config: Optional[str] = None
    config_overrides: Optional[List[str]] = Field(default_factory=list)
    offline: bool = False
    strategy: ExecutionStrategy = ExecutionStrategy.PARALLEL
    scanners: Optional[List[str]] = Field(default_factory=list)
    excluded_scanners: Optional[List[str]] = Field(default_factory=list)
    progress: bool = True
    output_formats: Optional[List[ExportFormat]] = Field(default_factory=list)
    cleanup: bool = False
    phases: Optional[List[ExecutionPhase]] = Field(
        default_factory=lambda: [
            ExecutionPhase.CONVERT,
            ExecutionPhase.SCAN,
            ExecutionPhase.REPORT,
        ]
    )
    inspect: bool = False
    existing_results: Optional[str] = None
    python_based_plugins_only: bool = False
    quiet: bool = False
    simple: bool = False
    verbose: bool = False
    debug: bool = False
    color: bool = True
    fail_on_findings: Optional[bool] = None
    # Fail when a selected scanner did not complete. None means "not set on the
    # command line", which defers to the config file and then to off. Kept
    # separate from fail_on_findings rather than folded into it because the two
    # answer different questions: whether anything was found, and whether the
    # scanners that were supposed to look actually ran.
    fail_on_incomplete_scanners: Optional[bool] = None
    ignore_suppressions: bool = False
    min_severity: str = "low"
    changed_files_only: bool = False
    base_ref: str = "origin/main"
    # One shard of a split scan, or both None for an ordinary whole scan. Left
    # unvalidated here on purpose: ScanPhase._execute_phase is the single place
    # that refuses an unusable pair, so a second rule in this model could drift
    # from it and start rejecting a selection the scan phase would have accepted
    # (or the reverse). The CLI validates early for the operator's benefit; that
    # is presentation, not the contract.
    shard_index: Optional[int] = None
    shard_count: Optional[int] = None
    mode: RunMode = RunMode.local
    show_summary: bool = True
    log_level: AshLogLevel = AshLogLevel.INFO

    # Container-specific
    build: bool = True
    run: bool = True
    force: bool = False
    oci_runner: Optional[str] = None
    build_target: Optional[BuildTarget] = None
    offline_semgrep_rulesets: str = "p/ci"
    container_uid: Optional[str] = None
    container_gid: Optional[str] = None
    ash_revision_to_install: Optional[str] = None
    custom_containerfile: Optional[str] = None
    custom_build_arg: Optional[List[str]] = Field(default_factory=list)
    ash_plugin_modules: Optional[List[str]] = Field(default_factory=list)
    container_network: str = "bridge"

    @field_validator("source_dir", "output_dir", mode="before")
    @classmethod
    def _coerce_absolute_path(cls, v):
        return Path(v).absolute()

    @field_validator(
        "scanners",
        "excluded_scanners",
        "output_formats",
        "config_overrides",
        "custom_build_arg",
        "ash_plugin_modules",
        mode="before",
    )
    @classmethod
    def _none_to_empty_list(cls, v):
        return v if v is not None else []

    @field_validator("phases", mode="before")
    @classmethod
    def _phases_default(cls, v):
        if v is None:
            return [ExecutionPhase.CONVERT, ExecutionPhase.SCAN, ExecutionPhase.REPORT]
        return v


# ---------------------------------------------------------------------------
# Severity helpers (module-level so _compute_exit_code can be patched cleanly)
# ---------------------------------------------------------------------------

# The --min-severity scale, which is not the severity ladder's: it has no `info`,
# and `critical` and `high` share a rank because SARIF's `error` covers both.
# `workspace.aggregation._MIN_SEVERITY_RANK` mirrors this table for the same gate
# on the workspace path.
#
# There is no `_SARIF_LEVEL_TO_SEVERITY` beside it any more. That table spelled
# `error -> high` where `utils.sarif_utils` spells `error -> critical`, and
# `_severity_filters_finding` was the only severity resolver in ASH that read a
# result's SARIF level while ignoring `properties.issue_severity` -- the field
# every other resolver treats as authoritative. Both are now routed through
# `utils.sarif_utils._resolve_result_severity`.
_SEVERITY_RANK = {"critical": 3, "high": 3, "medium": 2, "low": 1, "none": 0}

# ---------------------------------------------------------------------------
# Scanner completeness
#
# The statuses whose outcome is known. This is the allowlist, and the incomplete set
# below is its complement, so the default for anything not named here is "incomplete"
# rather than "complete".
#
# That direction is the point. The classification used to be a two-member denylist,
# which meant every status it did not name -- including one this version has never
# heard of -- counted as complete. Reachable rather than hypothetical: `ash merge`
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
# which is the whole point: that script's docstring claims it and ASH's exit code read
# the same field and so cannot disagree, and until this set existed here they could --
# the script asserted the set-level condition and _compute_exit_code did not.
#
# ERROR is excluded even though an ERROR scanner did technically run, which is where
# this differs from ScannerState.ran in scripts/verify_external_target_scan.py. An
# ERROR scanner reached no verdict, and excluding it is what keeps this in step with
# the CI script: there, any ERROR entry already fails the per-scanner pass, so
# counting it as "ran" here would make ASH exit 0 on a results file the script exits 1
# on -- exactly the disagreement this set exists to remove.
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
        for metric in get_unified_scanner_metrics(asharp_model=results)
    ]


def no_scanner_ran(
    observed: List[tuple[str, str]],
    expected: Optional[List[str]] = None,
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
    -- which ``ash merge`` reads, from whatever ASH produced each shard -- keeps the
    old benign reading rather than becoming a failure on upgrade.
    """
    if not observed:
        return bool(expected)
    return not any(status in _RAN_SCANNER_STATUSES for _, status in observed)


def _partial_coverage(metric) -> tuple[int, int] | None:
    """``(attempted, failed)`` when *metric* lost some of its input, else None.

    The tri-state on ``targets_attempted`` is the whole content of this function.
    ``None`` means the scanner does not track per-target outcomes and is making no
    claim -- bandit, checkov, semgrep, grype, syft, detect-secrets, opengrep,
    cfn-nag and npm-audit are all in that state. Reading absence as "attempted 0,
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
    rendered as "3 of None".
    """
    attempted = getattr(metric, "targets_attempted", None)
    failed = getattr(metric, "targets_failed", None)
    if isinstance(attempted, bool) or not isinstance(attempted, int):
        return None
    if isinstance(failed, bool) or not isinstance(failed, int):
        return None
    if failed <= 0:
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

    Only (1) was selected on, because that is a status test and (2) does not move
    a target's status. ``ScanResultsContainer.determine_status`` returns ERROR only
    once ``targets_failed >= targets_attempted``, so a scanner that lost some of
    its input keeps whatever the severity gate gave it and the gate could not see
    it. Measured on this repository under its own config: cdk-nag attempts 10
    targets and fails 4, its per-target container still reports PASSED, and the
    gate exited 0. Two of those four are real CloudFormation templates that went
    unscanned.

    Do not read "(2) does not change the status" as "nothing in this change
    touches a status". A sibling commit ORs ``any_target_errored`` into the
    ``error`` flag, so a target tree that lost ALL of its targets -- which
    ``determine_status`` does report as ERROR -- now reaches the rolled-up status
    where previously only the ``"source"`` report was consulted, and even that only
    when the scanner was absent from ``scanner_results``. That is a status change,
    it is not opted in, and it is the thing the CHANGELOG's "Behavior changes"
    entry describes. The two arms are separable: partial loss stays out of the
    status and is expressed here; total loss on any tree is a status.

    Case (2) is expressed HERE and not as a status, and not by widening
    ``_INCOMPLETE_SCANNER_STATUSES``. The reason is a caller rather than taste.
    ``cli.merge._completed`` keys on status against that same set to answer a
    different question -- whether a shard's scanner ran at all -- and
    ``_verify_shard_contributions`` refuses a merge outright where a shard
    completed none of the scanners it owned. A scanner that lost one target of ten
    ran, so any status-shaped expression of partial coverage would propagate into
    shard refusal and start rejecting healthy shards, failing the merge far from
    the code that caused it. That is the concrete cost of adding a
    ``ScannerStatus`` member for this, and the reason none was added.

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
    same scanner, and it has no counterpart in ``ash merge``, which has no scanner
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

    listed: list[tuple[str, str]] = []
    for metric in get_unified_scanner_metrics(asharp_model=results):
        # Against the allowlist, not against _INCOMPLETE_SCANNER_STATUSES, and the
        # two are not interchangeable here even though they partition the enum.
        # `metric.status` is a plain string that may have come from a results file
        # this version did not write -- `ash merge` reads shard results from
        # whatever ASH produced each one -- and only the allowlist form treats a
        # status outside the enum entirely as incomplete rather than as a scanner
        # that ran. This arm arrived from one side of a merge spelled as
        # `in _INCOMPLETE_SCANNER_STATUSES`, which is the denylist that inversion
        # replaced; `TestStatusClassificationFailsClosed` is what catches it.
        status_is_incomplete = metric.status not in _COMPLETE_SCANNER_STATUSES
        shortfall = _partial_coverage(metric)

        # No usable counters. The status is the only thing there is to report, so
        # this is the arm an ERROR or MISSING with no denominator falls to.
        if shortfall is None:
            if status_is_incomplete:
                listed.append((metric.scanner_name, metric.status))
            continue

        attempted, failed = shortfall
        # Total loss, and a status that already says so. The counts would add a
        # parenthetical that repeats the status.
        if status_is_incomplete and failed >= attempted:
            listed.append((metric.scanner_name, metric.status))
            continue

        # A partial shortfall against a known denominator, whatever the status.
        # Selecting on status ahead of this is what dropped the counts from the
        # measured case.
        listed.append(
            (
                metric.scanner_name,
                f"{metric.status} ({failed} of {attempted} targets unevaluated)",
            )
        )
    return listed


def unevaluated_rules(results: Optional[AshAggregatedResults]) -> List[str]:
    """Every rule a scanner reported, at run level, that it could not evaluate.

    WHY THIS IS A SECOND FUNCTION RATHER THAN PART OF ``incomplete_scanners``
    -----------------------------------------------------------------------
    ``incomplete_scanners`` answers "which scanners lost whole targets", and it
    answers it from the target counters. A rule that raised mid-evaluation loses
    neither a scanner nor a target: the scanner ran, the target was read, most of
    the rules reached a verdict, and one did not. Counting it as a lost target
    would overstate in a way that is measurable rather than theoretical --
    ``ScanResultsContainer.determine_status`` returns ERROR once
    ``targets_failed >= targets_attempted``, so a rule that raises on every
    template (which is the normal case for one that cannot resolve an intrinsic)
    would report the scanner as having evaluated nothing, and the cdk-nag
    scanner's own log line would read "No rules were evaluated" about a run that
    evaluated all but one of them.

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
    ``.ash/.ash.yaml`` carries fifteen such entries under the heading "rules that
    threw and never ran", each with a reviewed reason, and its own note calls
    naming them "the only way to keep the exit code honest". A gate that ignored
    them would fail ASH's own default scan with no escape hatch, which is a worse
    defect than the one being fixed.

    So a rule is reported only when at least one of its not-evaluated results is
    unsuppressed. The results are what suppression applies to, and consulting them
    is what lets the existing mechanism reach a fact recorded somewhere it cannot
    be attached.

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
            rule_id = str(getattr(result, "ruleId", "") or "")
            has_result.add(rule_id)
            if not getattr(result, "suppressions", None):
                unsuppressed.add(rule_id)

        for invocation in getattr(run, "invocations", None) or []:
            for notification in (
                getattr(invocation, "toolExecutionNotifications", None) or []
            ):
                level = getattr(notification, "level", None)
                if getattr(level, "value", level) != "error":
                    continue
                associated = getattr(notification, "associatedRule", None)
                rule_id = getattr(getattr(associated, "root", None), "id", None)
                if rule_id:
                    rule_id = str(rule_id)
                    if rule_id in has_result and rule_id not in unsuppressed:
                        continue
                    reported.add(rule_id)
                    continue
                message = getattr(getattr(notification, "message", None), "root", None)
                text = str(getattr(message, "text", "") or "").strip()
                reported.add(text or "an unnamed rule")
    return sorted(reported)


def _resolve_fail_on_incomplete_scanners(
    results: Optional[AshAggregatedResults],
    opts: ScanOptions,
    config_value: Optional[bool],
) -> bool:
    """Whether the completeness gate is on, highest-precedence source first.

    1. The command line, when the operator passed either form of the flag.
    2. ``results.ash_config`` -- the config the scan actually ran under, so a
       ``--config-overrides`` change to the field is honoured. Accepted only when
       it is genuinely a ``bool``: this attribute is reached by ``getattr`` on
       whatever object the caller supplied, and a partially-built model or a test
       double would otherwise contribute a truthy non-answer.
    3. *config_value* -- read from the config file before the scan, which is what
       container mode has to fall back on and what ``ash merge`` passes from the
       config carried in the shard results.
    4. Off, matching ``AshConfig.fail_on_incomplete_scanners``.

    Step 4 is reached only when no config model was available at all -- a results
    object built by hand, or a scan whose config failed to load. It agrees with the
    model default deliberately: the two are the same question answered twice, and
    when they disagreed the answer you got depended on how far the scan had got
    before it was asked, which is not a property anyone wants an exit code to have.

    OFF rather than on, and this was on by default for part of this branch's life.
    The gate is correct and this repository does not currently pass it: cdk-nag
    evaluates 6 of its 10 targets here, so `incomplete_scanners` reports
    ``PASSED (4 of 10 targets unevaluated)`` and every scan leg in CI exits 1 --
    measured on x86 Linux, arm64 and Windows alike, so it is not a platform
    artifact. Turning a completeness gate on before the tree it gates is complete
    makes the gate's first act a false alarm, and the two unscanned CloudFormation
    templates behind that count are a real coverage gap that wants fixing rather
    than defaulting past. Enabling it is therefore blocked on that fix, not on
    anyone's appetite; until then the honest default is the one an operator opts
    out of nothing to get.
    """
    if opts.fail_on_incomplete_scanners is not None:
        return opts.fail_on_incomplete_scanners

    resolved_config = getattr(results, "ash_config", None)
    from_results = getattr(resolved_config, "fail_on_incomplete_scanners", None)
    if isinstance(from_results, bool):
        return from_results

    if config_value is not None:
        return config_value
    return False


def _severity_filters_finding(result, min_sev_rank: int) -> bool:
    """Return True when *result* meets the minimum severity threshold.

    Severity is resolved by ``utils.sarif_utils._resolve_result_severity``, the
    resolver the rest of ASH uses, rather than from ``result.level`` alone. Reading
    the level alone ignored ``properties.issue_severity``, which is the field
    scanners use to state a severity SARIF cannot express -- grype reports a
    CRITICAL vulnerability at ``level: warning`` -- so ``--min-severity high``
    zeroed the whole actionable count and the scan exited 0 over it. The same
    substitution removes the ``error -> high`` spelling here that disagreed with
    ``error -> critical`` there.

    ``info`` is deliberately absent from ``_SEVERITY_RANK``, so a result the
    resolver grades ``info`` falls back to the ``low`` rank. That preserves the
    outcome for a missing or ``none`` level, which the deleted level table also
    graded ``low`` through its own default -- adding an ``info`` rank of 0 would
    change what ``--min-severity low`` accepts and would have to be mirrored in
    ``workspace.aggregation`` to keep the two paths answering alike.
    """
    if result.suppressions:
        return False
    return _SEVERITY_RANK.get(_resolve_result_severity(result), 1) >= min_sev_rank


# ---------------------------------------------------------------------------
# Helper: resolve final AshLogLevel
# ---------------------------------------------------------------------------


def _load_config_file(opts: ScanOptions):
    """Load the config file a scan of *opts* would use, or None.

    Extracted so the two exit-code fields read from one place. Duplicating the
    candidate search was the alternative, and it would let the two fields be read
    from different files the moment the search changed in one copy.

    Returns None when no config file is found or when it cannot be parsed --
    parsing failures surface later through the orchestrator's own validation with
    a message that names the problem, so swallowing them here loses nothing.
    """
    from automated_security_helper.config.ash_config import AshConfig

    config_path_str = opts.config
    if config_path_str is None:
        for config_file in ASH_CONFIG_FILE_NAMES:
            for candidate in (
                opts.source_dir / config_file,
                opts.source_dir / ".ash" / config_file,
            ):
                if candidate.exists():
                    config_path_str = candidate.as_posix()
                    break
            if config_path_str is not None:
                break

    if config_path_str is None:
        return None

    try:
        return AshConfig.from_file(Path(config_path_str))
    except Exception:
        return None


def _resolve_config_fail_on_findings(opts: ScanOptions) -> Optional[bool]:
    """Read fail_on_findings from the YAML config file, without loading the full orchestrator.

    Returns None when no config file is found or when the field is absent.
    Used by both container and local mode so that YAML overrides are honoured
    regardless of execution path.
    """
    return getattr(_load_config_file(opts), "fail_on_findings", None)


def _resolve_config_fail_on_incomplete_scanners(opts: ScanOptions) -> Optional[bool]:
    """Read fail_on_incomplete_scanners from the YAML config file.

    The sibling of :func:`_resolve_config_fail_on_findings`, and needed for the
    same reason: container mode has to know the value before it builds the
    container's command line, so it cannot wait for the orchestrator to resolve
    the config. Returns None when there is no config file to read, which the
    caller distinguishes from a file that sets the field to False.
    """
    return getattr(_load_config_file(opts), "fail_on_incomplete_scanners", None)


def _resolve_log_level(opts: ScanOptions) -> AshLogLevel:
    if opts.verbose:
        return AshLogLevel.VERBOSE
    if opts.debug:
        return AshLogLevel.DEBUG
    if (
        opts.quiet
        or opts.simple
        or opts.log_level in [AshLogLevel.QUIET, AshLogLevel.ERROR, AshLogLevel.SIMPLE]
    ):
        return AshLogLevel.ERROR
    return opts.log_level


# ---------------------------------------------------------------------------
# _setup_logger
# ---------------------------------------------------------------------------


def _setup_logger(opts: ScanOptions):
    from automated_security_helper.utils.log import get_logger

    final_log_level = _resolve_log_level(opts)
    final_logging_level = logging._nameToLevel.get(final_log_level.value, logging.INFO)
    simple_logging = opts.simple or opts.log_level == AshLogLevel.SIMPLE

    return get_logger(
        level=final_logging_level,
        output_dir=opts.output_dir,
        show_progress=(
            opts.progress
            and not opts.quiet
            and not opts.simple
            and os.environ.get("ASH_IN_CONTAINER", "NO").upper()
            not in ["YES", "1", "TRUE"]
        ),
        use_color=opts.color,
        simple_format=simple_logging,
        truncate_log=opts.existing_results is None,
    )


# ---------------------------------------------------------------------------
# _run_container_mode
# ---------------------------------------------------------------------------


def _workspace_relative_file(opts: ScanOptions) -> Optional[str]:
    """The workspace definition's path relative to the root, for container mode.

    Container mode has exactly one bind mount, so the workspace root goes to
    ``/src`` and the definition has to be named relative to it. Resolution has
    already established that every project sits below the root, which is what
    makes one mount sufficient.
    """
    plan = opts.workspace_plan
    if plan is None:
        return None
    return (
        Path(plan.workspace_file)
        .resolve()
        .relative_to(Path(plan.workspace_root).resolve())
        .as_posix()
    )


# The output-directory entries a local scan clears before it starts, copied from the two
# places the orchestrator clears them: ``ensure_directories`` rmtrees these four working
# directories (core/orchestrator.py:418-425) and ``initialize`` unlinks these three files
# (core/orchestrator.py:280-293). Both are gated there on ``existing_results_path is
# None``, which is the exemption in ``_discard_prior_run_artifacts`` below.
#
# Named here rather than inlined because the point of the list is that it matches that
# other list; a reader checking the claim needs to see the whole of both.
_PRIOR_RUN_OUTPUT_DIRECTORIES = ("analysis", "reports", "scanners", "converted")
_PRIOR_RUN_OUTPUT_FILES = (
    "ash_aggregated_results.json",
    "ash-ignore-report.txt",
    "ash-scan-set-files-list.txt",
)


def _discard_prior_run_artifacts(opts: ScanOptions, logger) -> None:
    """Clear the output directory the way a local scan does, before an outer mode starts.

    Container mode and Nix mode both re-execute ASH somewhere else and then read
    ``ash_aggregated_results.json`` back out of the output directory, so the file's mere
    presence is what stands in for "the scan ran". On its own it does not mean that. Every
    pre-run refusal in ``run_ash_container`` -- a non-numeric ``--container-uid``, a
    rejected revision, an OCI runner that cannot be resolved, an image build that failed --
    reports the same status the in-container CLI uses for an error during execution, and
    leaves whatever an earlier run wrote: possibly of a different repository, possibly with
    a different scanner set. Removing it beforehand is what makes ``exists()`` afterwards
    mean "this invocation produced this".

    The exit code is not the only thing a stale tree corrupts, and it is not the worst.
    ``reports/`` is what gets published: a caller that runs its publish steps on failure as
    well as success -- which is the usual shape, so that a failed scan still explains
    itself -- will post a previous run's ``ash.summary.md`` as its comment, upload a
    previous ``ash.junit.xml`` as check results and a previous ``ash.ghas.sarif`` to code
    scanning. An honest exit code beside a stale clean report is the same false negative
    this function exists to prevent, just moved somewhere a reviewer trusts more.

    So this clears what a local scan clears, in full: the four working directories
    ``ensure_directories`` rmtrees and the three files ``initialize`` unlinks
    (``_PRIOR_RUN_OUTPUT_DIRECTORIES`` and ``_PRIOR_RUN_OUTPUT_FILES``). Two entries earn a
    note:

    - ``reports/ash.sarif`` is not redundant with the results file. ``_compute_exit_code``
      re-reads that SARIF and lets its count REPLACE the one taken from the model, so a
      stale report decides the exit code by itself.
    - ``projects/`` is deliberately NOT in either list. Workspace mode writes a complete
      single-project tree per project under ``projects/<key>/`` and only the unified
      top-level files are rewritten by the outer run, so a workspace scan that removed
      ``projects/`` would delete the per-project reports it is about to summarize.
    """
    if opts.existing_results:
        # The one shape that legitimately consumes a file from before this invocation.
        # --use-existing resolves to a path in this directory and the inner scan is asked
        # to read it, so removing it would delete the run's only input. --phases report
        # and --phases inspect do NOT need this exemption: with existing_results unset the
        # orchestrator unlinks the results file itself, so the inner run discards it
        # whether or not the host did.
        #
        # Truthiness, not `is not None`, and the empty string is why: run_ash_container
        # appends --use-existing under `if existing_results:`, so an empty value asks the
        # inner scan to read nothing. Exempting it here on `is not None` would keep the
        # stale file AND leave it unread by the container -- the read-back then answers
        # from it, which is the exact failure this function closes.
        return

    stale_paths = [
        opts.output_dir / name
        for name in (*_PRIOR_RUN_OUTPUT_DIRECTORIES, *_PRIOR_RUN_OUTPUT_FILES)
    ]
    for stale in stale_paths:
        try:
            if stale.is_dir():
                shutil.rmtree(stale)
            else:
                # Also the branch a non-directory `reports` takes: removing it as a file
                # is what lets the inner run create the directory it expects.
                stale.unlink(missing_ok=True)
        except OSError as e:
            if not stale.exists():
                # The call failed but the artifact is gone -- another process removed it,
                # or a partial rmtree finished the job. Refusing here would fail on the
                # condition "the call raised" when the property that matters is "the
                # artifact is still there". On Windows that distinction is the difference
                # between refusing a scan and running one.
                logger.debug(
                    f"{stale.as_posix()} is already gone despite {type(e).__name__}: {e}"
                )
                continue
            # Fail closed. Continuing here would leave the read-back unable to tell a run
            # that never started from one that finished clean, which is the whole failure
            # this function exists to prevent -- and a false clean report is worse than a
            # refusal an operator can see and fix.
            logger.error(
                f"Could not remove {stale.as_posix()} from a previous run: {e}. ASH "
                "cannot tell that output apart from output this scan produced, so it "
                "will not read it back or publish it. Remove it, or point --output-dir "
                "somewhere ASH can write."
            )
            sys.exit(1)


# The statuses the in-container CLI reaches from a results file, and therefore the only
# ones the host can re-derive its own verdict from. Deliberately narrower than
# ASH_EXIT_CODES -- see the guard in _run_container_mode for which two are excluded and why.
_CONTAINER_VERDICT_EXIT_CODES = frozenset({0, 1, 2})


def _run_container_mode(
    opts: ScanOptions,
    logger,
    resolved_fail_on_findings: Optional[bool] = None,
    resolved_fail_on_incomplete_scanners: Optional[bool] = None,
) -> AshAggregatedResults:
    """Run the scan inside the ASH container image and read its results back.

    Sharding is forwarded into the container rather than warned about and dropped,
    which is how ``--changed-files-only`` immediately above is handled. The two
    look alike and are not. Dropping ``--changed-files-only`` widens the scan: the
    operator asked for less and got more, which is wasteful but never reports a
    finding that is not there and never hides one that is. Dropping a shard
    selection widens it the same way, but every shard would then scan the whole
    repository, and because merging deliberately does not deduplicate (see
    ``SarifReport.merge_sarif_report``) an n-shard matrix would report every
    finding n times. That is a wrong report, and the n-1 phantom copies of each
    real issue land on a reviewer.

    Forwarding is also cheap and complete: the container entrypoint is this same
    CLI, so ``--shard-index``/``--shard-count`` mean exactly what they mean on the
    host, and the provenance stamp survives the read-back below because
    ``metadata.shard`` is a declared field of ``ReportMetadata``.
    """
    if opts.changed_files_only:
        logger.warning(
            "--changed-files-only is not supported in container mode; performing full scan"
        )

    # Use the CLI-supplied value when present; fall back to the value already read from
    # the config file on the host.  Passing the resolved value avoids a race where the
    # user mutates the config file between the host read and the container's own read.
    effective_fail_on_findings = (
        opts.fail_on_findings
        if opts.fail_on_findings is not None
        else resolved_fail_on_findings
    )
    effective_fail_on_incomplete_scanners = (
        opts.fail_on_incomplete_scanners
        if opts.fail_on_incomplete_scanners is not None
        else resolved_fail_on_incomplete_scanners
    )

    if opts.run:
        # Only when a scan is actually being asked for. --no-run builds an image and
        # stops; it never claims to have scanned anything, so it has no business
        # discarding a report from a run that did.
        _discard_prior_run_artifacts(opts, logger)

    container_result = run_ash_container(
        source_dir=opts.source_dir,
        output_dir=opts.output_dir,
        offline=opts.offline,
        log_level=opts.log_level,
        verbose=opts.verbose,
        debug=opts.debug,
        color=opts.color,
        simple=opts.simple,
        quiet=opts.quiet,
        build=opts.build,
        run=opts.run,
        force=opts.force,
        oci_runner=opts.oci_runner,
        build_target=opts.build_target,
        offline_semgrep_rulesets=opts.offline_semgrep_rulesets,
        container_uid=opts.container_uid,
        container_gid=opts.container_gid,
        config=opts.config,
        config_overrides=opts.config_overrides,
        strategy=opts.strategy,
        scanners=opts.scanners,
        exclude_scanners=opts.excluded_scanners,
        progress=opts.progress,
        output_formats=opts.output_formats,
        cleanup=opts.cleanup,
        phases=opts.phases,
        inspect=opts.inspect,
        existing_results=opts.existing_results,
        python_based_plugins_only=opts.python_based_plugins_only,
        fail_on_findings=effective_fail_on_findings,
        fail_on_incomplete_scanners=effective_fail_on_incomplete_scanners,
        ash_revision_to_install=opts.ash_revision_to_install,
        custom_containerfile=opts.custom_containerfile,
        custom_build_arg=opts.custom_build_arg,
        ash_plugin_modules=opts.ash_plugin_modules,
        container_network=opts.container_network,
        workspace_relative_file=_workspace_relative_file(opts),
        allow_missing_projects=opts.allow_missing_projects,
        shard_index=opts.shard_index,
        shard_count=opts.shard_count,
    )

    if opts.debug:
        print("\n[bold blue]Debug: Container Command[/bold blue]")
        if hasattr(container_result, "args"):
            print(f"Command: {' '.join(str(arg) for arg in container_result.args)}")
        print(f"Return code: {container_result.returncode}")
        print(
            f"Stdout length: {len(container_result.stdout) if hasattr(container_result, 'stdout') else 'N/A'}"
        )
        print(
            f"Stderr length: {len(container_result.stderr) if hasattr(container_result, 'stderr') else 'N/A'}"
        )

    if hasattr(container_result, "returncode") and container_result.returncode != 0:
        logger.error(
            f"Container execution failed with code {container_result.returncode}"
        )
        if hasattr(container_result, "stderr") and container_result.stderr:
            # The container runner's own output is data, not markup. podman
            # writes lines like `msg="SHELL is not supported ... [/bin/bash -c]
            # will be ignored"`, which Rich reads as a closing tag and rejects --
            # destroying the report that explains the failed build. The logger
            # takes NO_MARKUP so the message string is not rewritten; the print
            # below styles its own heading, so there only the value is escaped.
            logger.error(
                f"Container stderr:\n{container_result.stderr}", extra=NO_MARKUP
            )
            print(
                f"\n[bold red]Container Error Output:[/bold red]\n"
                f"{escape_markup(container_result.stderr)}"
            )
        if hasattr(container_result, "stdout") and container_result.stdout:
            logger.debug(
                f"Container stdout:\n{container_result.stdout}", extra=NO_MARKUP
            )
            if opts.debug:
                print(
                    f"\n[bold blue]Container Standard Output:[/bold blue]\n"
                    f"{escape_markup(container_result.stdout)}"
                )

    if not opts.run:
        if hasattr(container_result, "returncode") and container_result.returncode != 0:
            sys.exit(container_result.returncode)
        sys.exit(0)

    # A status that is not a verdict did not come from a results file, so there is no
    # verdict for the host to re-derive and nothing below should try.
    #
    # NOT "any non-zero status", and the difference matters: the container entrypoint is
    # this same CLI, so 0, 1 and 2 are verdicts that _compute_exit_code reached from a
    # results file, and the host deliberately recomputes them, because it applies
    # --min-severity and --ignore-suppressions, neither of which is forwarded inward.
    # Exiting on 2 here would report findings the operator asked to filter out.
    #
    # NOT ASH_EXIT_CODES either, which is the wider table of every status the CLI can
    # return and includes two that assert the opposite of a verdict. 3 is an invalid
    # config, raised by _run_local_mode before it writes the results file, and 4 is a
    # workspace definition or policy error, which models/workspace.py defines precisely so
    # that "nothing was scanned" is distinguishable from 2's "a scan completed and found
    # something". Falling through on either sends the caller to the read-back, which finds
    # no file and reports 1 with a message about a missing report rather than about the
    # config -- losing the code that said which of the two it was.
    #
    # Everything outside the set is either one of those two or the runner's own
    # vocabulary: 125 for a `docker run` that failed before the entrypoint, 126 and 127 for
    # an entrypoint that could not be executed, 137 for a container the kernel killed. Each
    # of the latter can leave a partially written report behind, which the pre-run cleanup
    # cannot catch because the file is then genuinely this invocation's -- just not a
    # complete account of it.
    #
    # Default 1, not 0, for a result object without the attribute: this guard exists to
    # fail closed and "assume success" is the wrong posture inside it.
    container_returncode = getattr(container_result, "returncode", 1)
    if container_returncode not in _CONTAINER_VERDICT_EXIT_CODES:
        verdict_codes = ", ".join(
            str(code) for code in sorted(_CONTAINER_VERDICT_EXIT_CODES)
        )
        ash_meaning = ASH_EXIT_CODES.get(container_returncode)
        if ash_meaning is not None:
            # One of ASH's own non-verdict codes. Name what it means, because the status
            # is the whole diagnostic -- there is no report to point the operator at.
            logger.error(
                f"The container exited with {container_returncode} ({ash_meaning}), which "
                "means nothing was scanned. Only "
                f"{verdict_codes} are verdicts ASH reaches from a results file, so there "
                "is nothing in the output directory to read back."
            )
        else:
            logger.error(
                f"The container exited with {container_returncode}, which is not a status "
                f"an ASH scan can return ({verdict_codes} are the verdicts it reaches "
                "from a results file). The scan did not run to completion, so any report "
                "in the output directory is incomplete and is not being read back."
            )
        sys.exit(container_returncode)

    output_file = opts.output_dir / "ash_aggregated_results.json"
    if output_file.exists():
        with open(output_file, mode="r", encoding="utf-8") as f:
            content = f.read()
        try:
            return AshAggregatedResults.model_validate_json(content)
        except Exception as e:
            logger.error(f"Failed to parse results file: {e}")
            sys.exit(1)
    else:
        logger.error(f"Results file not found at {output_file}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# _run_nix_mode
# ---------------------------------------------------------------------------


def _run_nix_mode(opts: ScanOptions, logger) -> AshAggregatedResults:
    """Run the scan inside a Nix shell that supplies the pinned scanner toolchain.

    An outer wrapper like container mode: ASH re-executes itself inside `nix develop` and
    the inner run is an ordinary local scan. Simpler than container mode in one respect,
    since a development shell changes PATH but not the filesystem, so there is no mount
    translation and none of that path-mapping logic belongs here.
    """
    # The shell writes into the output directory this process was given, so a report left
    # by an earlier run sits exactly where a successful one would. run_ash_nix returns a
    # bare status and requests no capture -- stdout and stderr are both None -- so a `nix`
    # that exists on PATH and fails is otherwise indistinguishable from a scan that ran.
    _discard_prior_run_artifacts(opts, logger)

    nix_result = run_ash_nix(debug=opts.debug)

    if nix_result.returncode != 0:
        # Reported rather than fatal. A scan that finds something exits non-zero by design,
        # so treating any non-zero status as a failure here would turn a working scan into
        # an error. Whether findings should fail the run is decided from the loaded
        # results, exactly as in container mode.
        #
        # At warning rather than debug because this is the only diagnostic the path has
        # for a shell that never opened, and the console handler plus both file handlers
        # sit at INFO -- a debug record is emitted nowhere, neither to the terminal nor to
        # ash.log.
        logger.warning(f"Nix shell exited with code {nix_result.returncode}")

    # The inner scan wrote to the same output directory this process was given, so unlike
    # container mode there is no path to translate back.
    output_file = opts.output_dir / "ash_aggregated_results.json"
    if output_file.exists():
        with open(output_file, mode="r", encoding="utf-8") as f:
            content = f.read()
        try:
            return AshAggregatedResults.model_validate_json(content)
        except Exception as e:
            logger.error(f"Failed to parse results file: {e}")
            sys.exit(1)
    else:
        # No results file means the inner scan never got far enough to write one, so the
        # shell's own exit code is the only diagnostic available. Reporting it here is the
        # difference between an actionable error and a bare "file not found".
        logger.error(
            f"Results file not found at {output_file}. The Nix shell exited with "
            f"code {nix_result.returncode}."
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# _run_local_mode
# ---------------------------------------------------------------------------


def _run_local_mode(
    opts: ScanOptions, logger
) -> tuple[AshAggregatedResults, Optional[bool]]:
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    _offline_was_set = False
    if opts.offline:
        os.environ["ASH_OFFLINE"] = "YES"
        _offline_was_set = True

    _changed_file_set = None
    if opts.changed_files_only:
        from automated_security_helper.utils.get_scan_set import get_changed_files

        changed_paths = get_changed_files(base_ref=opts.base_ref, cwd=opts.source_dir)
        if changed_paths is not None:
            _changed_file_set = {
                opts.source_dir.joinpath(p).resolve() for p in changed_paths
            }

    try:
        if not opts.quiet and not opts.simple:
            logger.verbose(f"Source directory: {opts.source_dir.as_posix()}")
            logger.verbose(f"Output directory: {opts.output_dir.as_posix()}")
            logger.verbose(f"Scanners specified: {opts.scanners}")
            logger.verbose(f"Scanners excluded: {opts.excluded_scanners}")

        config = opts.config
        if config is None:
            for config_file in ASH_CONFIG_FILE_NAMES:
                def_paths = [
                    opts.source_dir / config_file,
                    opts.source_dir / ".ash" / config_file,
                ]
                for def_path in def_paths:
                    if def_path.exists():
                        logger.info(
                            f"Using config file found at: {def_path.as_posix()}"
                        )
                        config = def_path.as_posix()
                        break
                if config is not None:
                    break
        else:
            logger.info(f"Using config file specified at: {config}")

        if opts.config_overrides:
            logger.info(
                f"Applying {len(opts.config_overrides or [])} configuration overrides"
            )

        final_log_level = _resolve_log_level(opts)
        final_scanners = list(opts.scanners or [])
        if opts.mode == RunMode.precommit:
            fast_scanners = [
                "bandit",
                "detect-secrets",
                "checkov",
                "cdk-nag",
                "npm-audit",
            ]
            final_scanners = list(set(final_scanners + fast_scanners))

        final_show_progress = (
            opts.progress
            and final_log_level
            not in [
                AshLogLevel.QUIET,
                AshLogLevel.SIMPLE,
                AshLogLevel.VERBOSE,
                AshLogLevel.DEBUG,
            ]
            and os.environ.get("CI") is None
            and os.environ.get("ASH_IN_CONTAINER", "NO").upper()
            not in ["YES", "1", "TRUE"]
        )

        orchestrator = ASHScanOrchestrator.create(
            source_dir=opts.source_dir,
            output_dir=opts.output_dir,
            work_dir=opts.output_dir / ASH_WORK_DIR_NAME,
            enabled_scanners=final_scanners,
            excluded_scanners=list(opts.excluded_scanners or []),
            config_path=config,
            config_overrides=opts.config_overrides or [],
            verbose=opts.verbose or opts.debug,
            debug=opts.debug,
            strategy=(
                ExecutionStrategy.PARALLEL
                if opts.strategy == ExecutionStrategy.PARALLEL
                else ExecutionStrategy.SEQUENTIAL
            ),
            no_cleanup=not opts.cleanup,
            output_formats=opts.output_formats or [],
            show_progress=final_show_progress,
            simple_mode=opts.simple,
            show_summary=opts.show_summary,
            color_system=(
                "windows"
                if platform.system() == "Windows"
                else "auto"
                if opts.color
                else None
            ),
            offline=(opts.offline if opts.offline is not None else is_offline_mode()),
            existing_results_path=(
                Path(opts.existing_results) if opts.existing_results else None
            ),
            python_based_plugins_only=opts.python_based_plugins_only,
            ignore_suppressions=opts.ignore_suppressions,
            ash_plugin_modules=opts.ash_plugin_modules or [],
            shard_index=opts.shard_index,
            shard_count=opts.shard_count,
            metadata=None,
        )
        _config_fail_on_findings: Optional[bool] = getattr(
            getattr(orchestrator, "config", None), "fail_on_findings", None
        )

        _phases = opts.phases or []
        phases_to_run = []
        if ExecutionPhase.CONVERT in _phases:
            phases_to_run.append("convert")
        if ExecutionPhase.SCAN in _phases:
            phases_to_run.append("scan")
        if ExecutionPhase.REPORT in _phases:
            phases_to_run.append("report")
        if ExecutionPhase.INSPECT in _phases or opts.inspect:
            phases_to_run.append("inspect")
        if not phases_to_run:
            phases_to_run = ["convert", "scan", "report"]

        if not opts.quiet and not opts.simple:
            logger.debug(f"Running phases: {phases_to_run}")

        results = orchestrator.execute_scan(
            phases=cast(List[ExecutionPhaseType], phases_to_run)
        )

        if opts.simple and not opts.quiet:
            typer.echo("\nASH scan completed.")

        if _changed_file_set and results is not None:
            results = _filter_results_to_changed_files(
                results, _changed_file_set, opts.source_dir
            )
            sarif_path = opts.output_dir / "reports" / "ash.sarif"
            if sarif_path.exists() and results.sarif:
                sarif_path.write_text(
                    results.sarif.model_dump_json(indent=2, by_alias=True),
                    encoding="utf-8",
                )

        if isinstance(results, BaseModel):
            content = results.model_dump_json(indent=2, by_alias=True)
        else:
            content = json.dumps(results, indent=2, default=str)

        output_file = opts.output_dir / "ash_aggregated_results.json"
        with open(output_file, mode="w", encoding="utf-8") as f:
            f.write(content)

        return results, _config_fail_on_findings

    except ASHConfigValidationError as e:
        print(f"[bold red]ERROR (3) Invalid configuration: {e}[/bold red]")
        sys.exit(3)
    except ScannerSelectionError as e:
        # Ahead of the generic handler, and without logger.exception, because this is
        # a mistyped argument rather than a fault: a traceback would bury the one
        # line that says which name did not resolve and what the valid names are.
        # Exit 1 rather than 3 -- exit 3 means the config file is invalid, and this
        # operator's config is fine.
        print(f"[bold red]ERROR (1) {e}[/bold red]")
        sys.exit(1)
    except Exception as e:
        logger.exception(e)
        print(
            f"[bold red]ERROR (1) Exiting due to exception during ASH scan: {e}[/bold red]"
        )
        sys.exit(1)
    finally:
        if _offline_was_set:
            os.environ.pop("ASH_OFFLINE", None)


# ---------------------------------------------------------------------------
# Workspace mode
# ---------------------------------------------------------------------------


def _resolve_workspace_execution_config(opts: ScanOptions):
    """Read the workspace execution knobs from the workspace root's ASH config.

    The workspace root's config, not a project's: how many projects run at once
    is not a project's decision, and a project that set it would be overriding a
    sibling. Falls back to the defaults when there is no config file or it cannot
    be read -- these are scheduling knobs, so refusing to scan over an unreadable
    one would be a poor trade.
    """
    from automated_security_helper.config.ash_config import (
        AshConfig,
        WorkspaceExecutionConfig,
    )

    config_path_str = opts.config
    if config_path_str is None:
        for config_file in ASH_CONFIG_FILE_NAMES:
            for candidate in (
                opts.source_dir / config_file,
                opts.source_dir / ".ash" / config_file,
            ):
                if candidate.exists():
                    config_path_str = candidate.as_posix()
                    break
            if config_path_str is not None:
                break

    if config_path_str is None:
        return WorkspaceExecutionConfig()

    try:
        return AshConfig.from_file(Path(config_path_str)).workspace
    except Exception as exc:  # noqa: BLE001 -- scheduling knobs, not policy
        logging.getLogger(__name__).warning(
            f"Could not read workspace execution settings from "
            f"'{config_path_str}' ({exc}); using defaults."
        )
        return WorkspaceExecutionConfig()


def build_project_scan_settings(opts: ScanOptions) -> "ProjectScanSettings":
    """Build the per-project settings record a workspace run scans from.

    Module-level and public because there are two callers, not one: the CLI's
    ``_run_workspace_mode`` and the MCP surface in
    ``automated_security_helper.cli.mcp.workspace``. They assemble their
    ``ScanOptions`` differently -- one from typer arguments, one from MCP tool
    parameters -- but the record handed to ``execute_workspace`` has to come from
    one construction.

    Why it is extracted rather than written twice
    ---------------------------------------------
    ``ProjectScanSettings`` has 24 fields and every one of them is optional with a
    plausible default, so a second construction that omits a field produces a
    valid record and a scan that runs to completion with a setting the caller
    never chose. Nothing raises. The two worst omissions are ``config_overrides``,
    where dropping it silently scans with different configuration, and
    ``ignore_suppressions``, where the default is the lenient direction.

    What it owns, and why the boundary is here
    ------------------------------------------
    Both derived inputs are computed inside: the workspace execution config, via
    :func:`_resolve_workspace_execution_config`, which supplies
    ``max_parallel_projects`` and ``project_timeout``; and the ``phases`` list,
    which is the only field with branching behind it. A builder that took either
    as an argument would push part of the construction back out to its callers,
    which is where the duplication started.

    Note what it does *not* own. Setting ``ASH_OFFLINE`` stays with the caller:
    it mutates process state and has to be unset in a ``finally``, which a
    builder returning a value cannot do.

    Failure modes
    -------------
    An unreadable ASH config at the workspace root does not raise here.
    ``_resolve_workspace_execution_config`` warns and falls back to the defaults,
    because these are scheduling knobs -- refusing the whole scan over a typo in
    one would be a poor trade, and on the MCP path it would surface as an
    internal error for what is really an operator's config file.
    """
    from automated_security_helper.workspace.execution import ProjectScanSettings

    if opts.shard_index is not None or opts.shard_count is not None:
        # Same reasoning as the missing-plan check above: the CLI refuses this
        # combination with an operator-facing message (see
        # cli.scan._validate_shard_options), so reaching here means a programmatic
        # caller passed both. Raised rather than ignored because ProjectScanSettings
        # has no shard fields, so ignoring is not a degraded mode -- it is every
        # shard scanning every project with every scanner, and a merge multiplying
        # each finding by the shard count. RuntimeError rather than
        # ShardSelectionError, which would report a caller bug as though the
        # operator's shard arguments were at fault; theirs are fine, the
        # combination is not.
        raise RuntimeError(
            "Sharding is not supported in workspace mode, and workspace mode "
            "cannot silently ignore it: every shard would scan every project in "
            "full and the merged report would count each finding once per shard. "
            "Scan the workspace whole, or scan one project per job with "
            "source_dir and shard that."
        )

    workspace_config = _resolve_workspace_execution_config(opts)

    phases: List[str] = []
    for phase, name in (
        (ExecutionPhase.CONVERT, "convert"),
        (ExecutionPhase.SCAN, "scan"),
        (ExecutionPhase.REPORT, "report"),
    ):
        if phase in (opts.phases or []):
            phases.append(name)
    if ExecutionPhase.INSPECT in (opts.phases or []) or opts.inspect:
        phases.append("inspect")
    if not phases:
        phases = ["convert", "scan", "report"]

    return ProjectScanSettings(
        output_dir=opts.output_dir,
        phases=tuple(phases),
        enabled_scanners=tuple(opts.scanners or []),
        excluded_scanners=tuple(opts.excluded_scanners or []),
        output_formats=tuple(
            getattr(fmt, "value", str(fmt)) for fmt in (opts.output_formats or [])
        ),
        config_overrides=tuple(opts.config_overrides or []),
        ash_plugin_modules=tuple(opts.ash_plugin_modules or []),
        strategy=getattr(opts.strategy, "value", str(opts.strategy)),
        offline=opts.offline,
        python_based_plugins_only=opts.python_based_plugins_only,
        ignore_suppressions=opts.ignore_suppressions,
        min_severity=opts.min_severity,
        fail_on_findings=opts.fail_on_findings,
        fail_on_incomplete_scanners=opts.fail_on_incomplete_scanners,
        changed_files_only=opts.changed_files_only,
        base_ref=opts.base_ref,
        precommit=opts.mode == RunMode.precommit,
        cleanup=opts.cleanup,
        verbose=opts.verbose,
        debug=opts.debug,
        simple=opts.simple,
        color_system=(
            "windows"
            if platform.system() == "Windows"
            else "auto"
            if opts.color
            else None
        ),
        max_parallel_projects=workspace_config.resolved_max_parallel_projects(),
        project_timeout=workspace_config.project_timeout,
        allow_missing_projects=opts.allow_missing_projects,
    )


def _run_workspace_mode(opts: ScanOptions, logger) -> "WorkspaceRunResult":
    """Scan every project in the plan and write the unified workspace results.

    Returns the run result rather than an ``AshAggregatedResults``, because a
    workspace run's verdict is per project and is already computed -- handing back
    a merged model for ``_compute_exit_code`` to re-derive would give two answers
    to the same question and no rule for which wins.
    """
    from automated_security_helper.workspace.execution import execute_workspace

    if opts.workspace_plan is None:
        # The sole caller checks this before dispatching here, so reaching this
        # branch means a new call site skipped the check. Raised rather than
        # asserted because `python -O` strips assert, and a missing plan would then
        # surface much deeper as an unrelated AttributeError inside
        # execute_workspace. RuntimeError rather than a Workspace*Error, which
        # would report a caller bug as though the operator's workspace file were
        # at fault.
        raise RuntimeError(
            "_run_workspace_mode requires a resolved workspace plan; "
            "opts.workspace_plan is None"
        )

    # Built before ASH_OFFLINE is set, preserving the order the inline
    # construction had: the builder reads a config file off disk, and doing that
    # with the offline flag already in the environment is a different read.
    settings = build_project_scan_settings(opts)

    _offline_was_set = False
    if opts.offline:
        os.environ["ASH_OFFLINE"] = "YES"
        _offline_was_set = True

    try:
        return execute_workspace(opts.workspace_plan, settings)
    except WorkspaceDefinitionError as exc:
        # A refusal, not a project failure: nothing was scanned, so there is no
        # results file and the exit-2 collision is unambiguous. See
        # models.workspace for the discriminator.
        typer.echo(str(exc), err=True)
        sys.exit(int(WorkspaceExitCode.WORKSPACE_ERROR))
    except ASHConfigValidationError as exc:
        print(f"[bold red]ERROR (3) Invalid configuration: {exc}[/bold red]")
        sys.exit(int(WorkspaceExitCode.INVALID_PROJECT_CONFIG))
    except Exception as exc:
        logger.exception(exc)
        print(
            f"[bold red]ERROR (1) Exiting due to exception during ASH workspace "
            f"scan: {exc}[/bold red]"
        )
        sys.exit(int(WorkspaceExitCode.INTERNAL_ERROR))
    finally:
        if _offline_was_set:
            os.environ.pop("ASH_OFFLINE", None)


def _print_workspace_summary(
    result: "WorkspaceRunResult", opts: ScanOptions, scan_start_time: float
) -> None:
    """Per-project outcomes, in workspace-file order.

    A per-project table rather than the single-scan "next steps" block, because
    the first question about a workspace scan is which project failed, and a
    merged count cannot answer it.
    """
    if opts.quiet:
        return

    duration_str = format_duration(time.time() - scan_start_time)
    print(f"\n[cyan]=== ASH Workspace Scan Completed in {duration_str} ===[/cyan]")
    print(f"  workspace: {result.payload.workspace_file}")
    print(f"  output:    {opts.output_dir.as_posix()}")
    print("")

    for entry in result.payload.projects:
        if entry.status.value == "skipped":
            reason = entry.skip_reason.value if entry.skip_reason else "unspecified"
            print(f"  [yellow]skipped[/yellow]  {entry.display_label} ({reason})")
            continue
        if entry.status.value == "failed":
            print(
                f"  [bold red]failed[/bold red]   {entry.display_label}: {entry.error}"
            )
            continue
        colour = "bold red" if entry.exceeds_threshold else "green"
        verdict = "FAIL" if entry.exceeds_threshold else "pass"
        print(
            f"  [{colour}]{verdict}[/{colour}]     {entry.display_label} -- "
            f"{entry.actionable_finding_count} actionable of "
            f"{entry.finding_count} at threshold "
            f"{entry.severity_threshold or 'none'} "
            f"({entry.duration_seconds:.1f}s)"
        )

    print("")
    print(f"  Aggregated results: {result.results_path.as_posix()}")
    print(f"  Per-project output: {opts.output_dir.joinpath('projects').as_posix()}")
    if result.payload.unconvertible_finding_paths:
        print(
            f"  [yellow]{result.payload.unconvertible_finding_paths} finding "
            f"path(s) could not be expressed relative to the workspace root and "
            f"carry no workspace_uri; they are still reported.[/yellow]"
        )


# ---------------------------------------------------------------------------
# _compute_exit_code
#
# This comment used to open "pure function from in-memory results; no disk reads"
# and go on to say the ash.sarif re-read had been deleted as a workaround for a
# Pydantic suppression-state concern that root-cause investigation had disproved.
# The re-read was still there, below, overwriting the in-memory actionable count
# exactly as described -- so the file argued against its own code, and a reader who
# trusted the comment would conclude the exit code and the summary table could not
# disagree. They could, and about more than suppressions: the re-read applied
# global_settings.severity_threshold to every result, while
# get_unified_scanner_metrics resolves a per-scanner options.severity_threshold and
# records threshold_source "config". A scanner configured away from the global
# setting had its findings counted one way in the report and the other way in the
# exit code, which is the whole contract for a CI gate.
#
# The re-read now resolves the threshold per result's owning scanner, through the
# same ScannerStatisticsCalculator.get_scanner_threshold_info the metrics use, so
# both counts answer from one threshold model. Deleting the re-read outright was
# the other option and is what the original comment claimed had happened; it was
# not taken here because the re-read counts every result in the file whereas the
# metrics only count results whose scanner name resolves, so deleting it would drop
# an unattributable finding from the verdict -- a false negative, which is the worse
# failure for a gate. Whether that superset is real on any shipped scanner is
# unmeasured; the conservative change does not depend on the answer.
#
# Two independent questions, in this order:
#
#   1. Did the scanners that were supposed to run actually run? Gated by
#      fail_on_incomplete_scanners, default OFF, exit 1. Off by default because this
#      repository cannot pass the gate until cfn-nag, grype and syft are provisioned
#      on every leg, so CI relies on .github/scripts/assert_scanners_completed.py,
#      which has no such flag, for the same assertion.
#   2. Did they find anything actionable? Gated by fail_on_findings, default on,
#      exit 2.
#
# Deriving the verdict from finding counts alone -- which is what this function
# did -- cannot tell "nothing was wrong" from "nothing was checked", because both
# produce zero findings. Measured on this tree: a scan with four of ten scanners
# MISSING exits 0, and a deployed run with five MISSING or ERROR reported a clean
# scan of a repository a working scan flags at HIGH.
# ---------------------------------------------------------------------------


def _compute_exit_code(
    results: Optional[AshAggregatedResults],
    opts: ScanOptions,
    config_fail_on_findings: Optional[bool] = None,
    config_fail_on_incomplete_scanners: Optional[bool] = None,
) -> int:
    if results is None:
        logging.getLogger(__name__).error(
            "ASH scan produced no results — scan may have crashed"
        )
        return 1

    # Checked before the fail_on_findings resolution below, and deliberately so.
    # An operator who runs with findings-gating off has said "do not fail me for
    # what you find"; they have not said "do not tell me the scanners never ran".
    # Placing this after the `not final_fail_on_findings` early return would make
    # the gate dead for exactly the people who turned findings-gating off.
    #
    # 1 rather than 2, and 1 in preference to 2 when both hold. 1 is ASH's "error
    # during execution" code, and an incomplete scan is that: the findings that
    # were reported are real but the set is known to be partial. Reporting 2 would
    # tell a reviewer that clearing the listed findings clears the scan, when some
    # scanners contributed nothing. `ash merge` already uses 1 for its coverage
    # refusals on the same reasoning -- the findings are unknown, which is not the
    # same as "no findings".
    if _resolve_fail_on_incomplete_scanners(
        results, opts, config_fail_on_incomplete_scanners
    ):
        # Two reads of the metrics rather than one, and the second is not a
        # duplicate of the first. `incomplete_scanners` no longer answers from status
        # alone -- it also reports a scanner that ran and lost some of its targets,
        # which needs the per-metric target counters -- so its result cannot be
        # derived from a list of (name, status) pairs. An earlier form of this merge
        # did exactly that, and it dropped the partial-coverage arm out of the exit
        # code entirely while the file looked clean.
        observed = scanner_statuses(results)
        incomplete = incomplete_scanners(results)
        if incomplete:
            logging.getLogger(__name__).error(
                "Scan incomplete: %s",
                ", ".join(f"{name} ({status})" for name, status in incomplete),
            )
            return 1

        # Then the same question asked of the set rather than of each entry, and
        # it is not implied by the pass above. SKIPPED has to be tolerated one
        # entry at a time -- it is how sharding and --exclude-scanners record work
        # a run was never meant to do -- so a results file in which *every* entry
        # is SKIPPED clears the loop above having measured nothing.
        #
        # Reachable without any sharding and without any operator error beyond a
        # single word. Measured on this tree with the repository's own
        # .ash/.ash.yaml, which sets `semgrep: enabled: true`:
        # `ash scan --scanners semgrep` on Windows resolves semgrep against the
        # registered names, so ScannerSelectionError does not fire; semgrep then
        # declares the platform unsupported and is recorded SKIPPED; the other nine
        # are not selected and are SKIPPED too; findings are 0; exit 0. A scan that
        # ran no scanner reported the tree clean.
        #
        # .github/scripts/assert_scanners_completed.py already asserted this and
        # caught that case in CI, which is the reason it has to be here as well:
        # its docstring states that reading the JSON status means "the guard and
        # ASH's own exit code answer from the same field, so they cannot disagree",
        # and on this exact input they did. An operator running `ash scan` got 0
        # from the same results file the CI gate exits 1 on.
        #
        # Inside the fail_on_incomplete_scanners gate rather than beside it. The
        # committed contract for --no-fail-on-incomplete-scanners is that a scan
        # whose scanners did not run still exits 0 -- that is what
        # test_cli_false_overrides_config_true pins, for a run whose only scanner
        # is MISSING, which measured nothing just as thoroughly as an all-SKIPPED
        # one. Making this one check unconditional would answer that same question
        # two different ways depending on which status the non-running scanners
        # happened to land on. The flag defaults OFF, so the case above exits 0
        # unless a config or an operator opts in -- which is precisely why
        # .github/scripts/assert_scanners_completed.py asserts it unconditionally,
        # and why that script rather than this function is what holds the line in
        # CI. An operator who leaves the gate off, or turns it off, has said they
        # accept a scan that did not run.
        #
        # Skipped for one shard of a split scan, because a shard genuinely can own
        # nothing: core.sharding documents that a shard count above the scanner
        # count "leaves the surplus shards empty. They run, produce a valid empty
        # report, and merge correctly", and a shard that owns one platform-declined
        # scanner is the same shape. A shard also cannot see whether the union
        # measured anything -- only the merge can, and it does: cli.merge's
        # _verify_shard_contributions refuses a shard that owned scanners and
        # completed none of them, and _merged_exit_code runs this same function
        # over the merged model with no shard fields set, so the union is held to
        # the assertion the individual shards are excused from.
        one_shard_of_a_split = (
            opts.shard_index is not None or opts.shard_count is not None
        )
        expected_roster = list(
            getattr(getattr(results, "metadata", None), "expected_scanners", None) or []
        )
        if not one_shard_of_a_split and no_scanner_ran(observed, expected_roster):
            logging.getLogger(__name__).error(
                "Scan ran no scanners: %s. Every scanner was skipped, so this run "
                "has shown the target to be neither clean nor dirty -- most often a "
                "--scanners name that matches no scanner on this platform, or an "
                "allowlist wholly cancelled by --exclude-scanners.",
                ", ".join(f"{name} ({status})" for name, status in observed),
            )
            return 1

    # A rule that raised instead of reaching a verdict, which no other gate can see.
    #
    # NOT behind fail_on_incomplete_scanners, and that is the whole point of it being
    # here. This condition has no honest reading under which the scan was clean: the
    # tool was asked to evaluate a rule, it tried, and it failed. That is different
    # from the case the flag exists to keep quiet, which is an environment
    # legitimately lacking a scanner's tool -- there the operator's setup explains the
    # gap, so defaulting to silence is defensible. Nothing explains this one.
    #
    # It also has to sit ahead of the fail_on_findings early return, for the reason
    # the block above states: an operator who turned findings-gating off said "do not
    # fail me for what you find", not "do not tell me part of the scan never ran".
    #
    # 1 rather than 2, matching the gate above and `ash merge`'s coverage refusals.
    # 2 means "clearing the listed findings clears the scan", which is exactly what
    # is not true here -- the reported set is known to be missing whatever these rules
    # would have said.
    #
    # WHY THIS IS NOT EXPRESSED AS A FINDING INSTEAD. It was the obvious alternative:
    # give the result a gating severity and let the existing findings count carry it,
    # which is also how this behaved before the not-evaluated work. SARIF forbids it.
    # Section 3.27.10 defines `level` "none" as required whenever `kind` (3.27.9) is
    # anything other than "fail", and "fail" asserts the rule WAS evaluated and the
    # target did not satisfy it. So a severity-bearing result would have to claim a
    # verdict that was never reached -- the report lying in the opposite direction.
    # SARIF's channel for this is the run-level notification, which is what
    # `unevaluated_rules` reads, so the gate reads the fact where the format puts it
    # instead of restating it somewhere it can gate more conveniently.
    #
    # A rule that genuinely does not apply to a target is untouched, and not by a
    # carve-out here. Such a rule produces no row in cdk-nag's validation report at
    # all, so it reaches neither a result nor a notification; the only producer of
    # the not-evaluated state is a rule that threw.
    #
    # THE ESCAPE HATCH IS THE EXISTING ONE. Suppressing the rule's not-evaluated
    # results suppresses this gate too -- see `unevaluated_rules`, which will not
    # report a rule whose every such result is suppressed. That is what makes the
    # gate defaults-on without being unavoidable, and it is already how this
    # repository's own config accepts the fifteen rules that throw on its
    # deliberately parameterized templates.
    unevaluated = unevaluated_rules(results)
    if unevaluated:
        logging.getLogger(__name__).error(
            "Scan incomplete: %d rule(s) could not be evaluated, so this scan "
            "reports nothing about compliance with them: %s",
            len(unevaluated),
            ", ".join(unevaluated),
        )
        return 1

    final_fail_on_findings: bool
    if opts.fail_on_findings is not None:
        final_fail_on_findings = opts.fail_on_findings
    elif config_fail_on_findings is not None:
        final_fail_on_findings = config_fail_on_findings
    else:
        final_fail_on_findings = True

    if not final_fail_on_findings:
        return 0

    scanner_metrics = get_unified_scanner_metrics(asharp_model=results)
    actionable_findings = sum(item.actionable for item in scanner_metrics)

    # Count actionable findings from the persisted SARIF report file, honouring the
    # threshold that governs each result's own scanner (#329). The SARIF reporter
    # serializes all suppressions, including the final pass, while in-memory model
    # access has a Pydantic mutation bug where result.suppressions is not reliably
    # set.
    #
    # The threshold is resolved per result rather than once for the whole file. It
    # used to be read once from global_settings.severity_threshold, which silently
    # discarded every per-scanner options.severity_threshold -- so a scanner the
    # operator had tightened or relaxed was judged by the global setting here and by
    # its own setting in the report and the summary table.
    #
    # The comparison is utils.severity_ladder's, replacing the two tables that used
    # to be inlined here. They agreed with the ladder on all five real thresholds
    # and diverged off-table, reading an unrecognised threshold as MEDIUM where
    # every other consumer reads it as CRITICAL. One consequence is worth naming:
    # the ladder treats a falsy threshold as "no gate at all" rather than as
    # MEDIUM, which is how the operator turns the gate off and how
    # calculate_actionable_count already reads it, so the two counts agree on that
    # input too. No validated config route produces one -- global_settings is a
    # Literal and ScannerOptionsBase.severity_threshold is Literal | None whose None
    # means "defer to global" -- so this is parity rather than a new behaviour.
    sarif_file = Path(opts.output_dir).joinpath("reports", "ash.sarif")
    if sarif_file.exists():
        try:
            with open(sarif_file, encoding="utf-8") as f:
                sarif_json = json.load(f)  # nosec

            # Memoised because get_scanner_threshold_info dumps the whole scanners
            # config on every call, and a large ash.sarif carries one result per
            # finding.
            _threshold_cache: Dict[str, str] = {}

            def _threshold_for(scanner_name: object) -> str:
                """The threshold governing *scanner_name*, global when it has none.

                An empty name is passed through to the same resolver rather than
                short-circuited: it matches no scanner config key, so the resolver
                answers with the global threshold. That keeps one threshold
                resolution site for both cases, and it means a result whose scanner
                cannot be identified is judged exactly as every result was judged
                before this change instead of being skipped -- dropping it would
                remove a finding from the verdict.
                """
                key = scanner_name if isinstance(scanner_name, str) else ""
                if key not in _threshold_cache:
                    _threshold_cache[key] = (
                        ScannerStatisticsCalculator.get_scanner_threshold_info(
                            results, key
                        )[0]
                    )
                return _threshold_cache[key]

            sarif_active = 0
            for sarif_run in sarif_json.get("runs", []):
                for r in sarif_run.get("results", []):
                    if r.get("suppressions"):
                        continue
                    props = r.get("properties", {}) or {}
                    threshold = _threshold_for(
                        props.get("scanner_name") if isinstance(props, dict) else None
                    )
                    issue_severity = (
                        (props.get("issue_severity") or "").upper()
                        if isinstance(props, dict)
                        else ""
                    )
                    if issue_severity in SEVERITIES:
                        if severity_fails_threshold(issue_severity, threshold):
                            sarif_active += 1
                    elif sarif_level_fails_threshold(r.get("level"), threshold):
                        sarif_active += 1
            actionable_findings = sarif_active
        except Exception:  # nosec B110
            pass  # Fall through to the unified-metrics count

    min_sev_rank = _SEVERITY_RANK.get(opts.min_severity.lower(), 1)
    if min_sev_rank > 0 and actionable_findings > 0:
        has_qualifying = False
        try:
            sarif = getattr(results, "sarif", None)
            if sarif is None or not getattr(sarif, "runs", None):
                has_qualifying = True
            for run in getattr(sarif, "runs", []) if not has_qualifying else []:
                for result in getattr(run, "results", []):
                    if _severity_filters_finding(result, min_sev_rank):
                        has_qualifying = True
                        break
                if has_qualifying:
                    break
        except Exception:
            has_qualifying = True
        if not has_qualifying:
            actionable_findings = 0

    if actionable_findings > 0:
        return 2
    return 0


# ---------------------------------------------------------------------------
# _print_summary
# ---------------------------------------------------------------------------


def _print_summary(
    results: Optional[AshAggregatedResults],
    opts: ScanOptions,
    scan_start_time: float,
    actionable_findings: int,
) -> None:
    scan_duration = time.time() - scan_start_time
    duration_str = format_duration(scan_duration)

    output_file = opts.output_dir / "ash_aggregated_results.json"
    relative_out_dir = (
        opts.output_dir.relative_to(opts.source_dir)
        if opts.output_dir.is_relative_to(opts.source_dir)
        else opts.output_dir
    )
    out_dir_alias = os.environ.get("ASH_ACTUAL_OUTPUT_DIR", relative_out_dir.as_posix())

    if not opts.quiet:
        if results and hasattr(results, "validation_checkpoints"):
            config_warnings = [
                cp
                for cp in results.validation_checkpoints
                if cp.get("type") == "config_warning"
            ]
            if config_warnings:
                print("\n[bold yellow]⚠️  CONFIGURATION WARNING ⚠️[/bold yellow]")
                for cw in config_warnings:
                    print(f"[yellow]  {cw['message']}[/yellow]")
                print("")

        print(
            f"\n[cyan]=== ASH Scan Completed in {duration_str}: Next Steps ===[/cyan]"
        )
        print("View detailed findings...")
        print(f"  - SARIF: '{out_dir_alias}/reports/ash.sarif'")
        print(f"  - JUnit: '{out_dir_alias}/reports/ash.junit.xml'")
        print(
            f"  - ASH aggregated results JSON available at: "
            f"'{out_dir_alias}/{output_file.relative_to(opts.output_dir).as_posix()}'"
        )

    if actionable_findings > 0:
        print("\n[magenta]=== Actionable findings detected! ===[/magenta]")
        print("To investigate...")
        print(
            "  1. Open one of the summary reports for a user-friendly table of the findings:"
        )
        print(f"    - HTML report of all findings: '{out_dir_alias}/reports/ash.html'")
        print(f"    - Markdown summary: '{out_dir_alias}/reports/ash.summary.md'")
        print(f"    - Text summary: '{out_dir_alias}/reports/ash.summary.txt'")
        print(
            "  2. Use [magenta]ash report[/magenta] to view a short text summary of the scan in your terminal"
        )
        print(
            "  3. Use [magenta]ash inspect findings[/magenta] to explore the findings interactively"
        )
        print(
            f"  4. Review scanner-specific reports and outputs in the '{out_dir_alias}/scanners' directory"
        )


# ---------------------------------------------------------------------------
# _filter_results_to_changed_files (unchanged helper)
# ---------------------------------------------------------------------------


def _filter_results_to_changed_files(
    results: "AshAggregatedResults",
    changed_files: set,
    source_dir: Path,
) -> "AshAggregatedResults":
    """Remove SARIF results whose primary location is not in *changed_files*."""
    if not results or not results.sarif or not results.sarif.runs:
        return results
    for run in results.sarif.runs:
        if not run.results:
            continue
        filtered = []
        for result in run.results:
            if not result.locations:
                filtered.append(result)
                continue
            loc = result.locations[0]
            if (
                not loc.physicalLocation
                or not loc.physicalLocation.root.artifactLocation
            ):
                filtered.append(result)
                continue
            uri = loc.physicalLocation.root.artifactLocation.uri or ""
            if uri.startswith("file://"):
                uri = uri[7:]
                if uri.startswith("///"):
                    uri = uri[2:]
            resolved = Path(source_dir).joinpath(uri).resolve()
            if resolved in changed_files:
                filtered.append(result)
        run.results = filtered
    return results


# ---------------------------------------------------------------------------
# run_ash_scan — top-level entry point (~50 lines)
# ---------------------------------------------------------------------------


def run_ash_scan(
    source_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
    config: str | None = None,
    config_overrides: List[str] | None = None,
    offline: bool = False,
    strategy: ExecutionStrategy = ExecutionStrategy.PARALLEL,
    scanners: List[str] | None = None,
    exclude_scanners: List[str] | None = None,
    progress: bool = True,
    output_formats: List[ExportFormat] | None = None,
    cleanup: bool = False,
    phases: List[ExecutionPhase] | None = None,
    inspect: bool = False,
    existing_results: str | None = None,
    python_based_plugins_only: bool = False,
    quiet: bool = False,
    simple: bool = False,
    verbose: bool = False,
    debug: bool = False,
    color: bool = True,
    fail_on_findings: bool | None = None,
    fail_on_incomplete_scanners: bool | None = None,
    ignore_suppressions: bool = False,
    min_severity: str = "low",
    changed_files_only: bool = False,
    base_ref: str = "origin/main",
    shard_index: int | None = None,
    shard_count: int | None = None,
    mode: RunMode = RunMode.local,
    show_summary: bool = True,
    log_level: AshLogLevel = AshLogLevel.INFO,
    # Container-specific args
    build: bool = True,
    run: bool = True,
    force: bool = False,
    oci_runner: str | None = None,
    build_target: BuildTarget | None = None,
    offline_semgrep_rulesets: str = "p/ci",
    container_uid: str | None = None,
    container_gid: str | None = None,
    ash_revision_to_install: str | None = None,
    custom_containerfile: str | None = None,
    custom_build_arg: List[str] | None = None,
    ash_plugin_modules: List[str] | None = None,
    container_network: str = "bridge",
    workspace_plan: "WorkspacePlan | None" = None,
    allow_missing_projects: bool = False,
    *args,
    **kwargs,
):
    """Run an ASH scan against source_dir, outputting results to output_dir.

    When *workspace_plan* is given, *source_dir* is the workspace root and each
    project in the plan is scanned in its own scope. See
    :mod:`automated_security_helper.workspace.execution`.
    """
    scan_start_time = time.time()

    # Resolve cwd-based defaults at call time (not import time).
    _source_dir: Path = (
        Path(source_dir).absolute() if source_dir is not None else Path.cwd()
    )
    _output_dir: Path = (
        Path(output_dir).absolute()
        if output_dir is not None
        else Path.cwd().joinpath(".ash", "ash_output")
    )

    opts = ScanOptions(
        source_dir=_source_dir,
        output_dir=_output_dir,
        config=config,
        config_overrides=config_overrides,
        offline=offline,
        strategy=strategy,
        scanners=scanners,
        excluded_scanners=exclude_scanners,
        progress=progress,
        output_formats=output_formats,
        cleanup=cleanup,
        phases=phases,
        inspect=inspect,
        existing_results=existing_results,
        python_based_plugins_only=python_based_plugins_only,
        quiet=quiet,
        simple=simple,
        verbose=verbose,
        debug=debug,
        color=color,
        fail_on_findings=fail_on_findings,
        fail_on_incomplete_scanners=fail_on_incomplete_scanners,
        ignore_suppressions=ignore_suppressions,
        min_severity=min_severity,
        changed_files_only=changed_files_only,
        base_ref=base_ref,
        shard_index=shard_index,
        shard_count=shard_count,
        mode=mode,
        show_summary=show_summary,
        log_level=log_level,
        build=build,
        run=run,
        force=force,
        oci_runner=oci_runner,
        build_target=build_target,
        offline_semgrep_rulesets=offline_semgrep_rulesets,
        container_uid=container_uid,
        container_gid=container_gid,
        ash_revision_to_install=ash_revision_to_install,
        custom_containerfile=custom_containerfile,
        custom_build_arg=custom_build_arg,
        ash_plugin_modules=ash_plugin_modules,
        container_network=container_network,
        workspace_plan=workspace_plan,
        allow_missing_projects=allow_missing_projects,
    )

    logger = _setup_logger(opts)

    if opts.workspace_plan is not None and opts.mode != RunMode.container:
        # Workspace mode owns its own verdict and its own summary. It does not go
        # through _compute_exit_code, which answers for one directory against one
        # threshold and has no way to express "project A failed, project B did
        # not".
        workspace_result = _run_workspace_mode(opts, logger)
        if opts.show_summary:
            _print_workspace_summary(workspace_result, opts, scan_start_time)
        if workspace_result.exit_code != 0:
            sys.exit(workspace_result.exit_code)
        return workspace_result

    config_fail_on_findings: Optional[bool] = _resolve_config_fail_on_findings(opts)
    config_fail_on_incomplete_scanners: Optional[bool] = (
        _resolve_config_fail_on_incomplete_scanners(opts)
    )
    results: Optional[AshAggregatedResults]
    if opts.mode == RunMode.container:
        results = _run_container_mode(
            opts,
            logger,
            resolved_fail_on_findings=config_fail_on_findings,
            resolved_fail_on_incomplete_scanners=config_fail_on_incomplete_scanners,
        )
    elif opts.mode == RunMode.nix:
        # No resolved-flag arguments here, unlike container mode, and that asymmetry is
        # deliberate rather than an oversight in the merge that brought these two together.
        # Container mode forwards the flags into the CLI invocation it runs inside the
        # container, because that inner process computes its own verdict. Nix mode returns
        # the parsed results and the verdict is computed once, below, by
        # _compute_exit_code -- which already receives config_fail_on_incomplete_scanners,
        # so nix runs honour it through the shared path.
        results = _run_nix_mode(opts, logger)
    else:
        results, _local_config_fof = _run_local_mode(opts, logger)
        # _run_local_mode resolves config via the live orchestrator; prefer that
        # value over the file-based pre-read when it differs (e.g. config_overrides
        # applied by the orchestrator may alter fail_on_findings).
        if _local_config_fof is not None:
            config_fail_on_findings = _local_config_fof

    if opts.workspace_plan is not None:
        # Container mode ran `ash --workspace` inside the container, so the
        # verdict was already computed there by the same code. Re-deriving it on
        # the host from a merged model would answer a different question.
        workspace_payload = getattr(results, "workspace", None)
        exit_code = (
            int(workspace_payload.exit_code)
            if workspace_payload is not None
            else int(WorkspaceExitCode.INTERNAL_ERROR)
        )
        if workspace_payload is None:
            logger.error(
                "The container produced no workspace payload, so no per-project "
                "verdict is available."
            )
        if exit_code != 0:
            sys.exit(exit_code)
        return results

    exit_code = _compute_exit_code(
        results,
        opts,
        config_fail_on_findings,
        config_fail_on_incomplete_scanners,
    )

    if opts.show_summary:
        scanner_metrics = (
            get_unified_scanner_metrics(asharp_model=results) if results else []
        )
        actionable_findings = sum(item.actionable for item in scanner_metrics)
        _print_summary(results, opts, scan_start_time, actionable_findings)

        if exit_code == 2 and not opts.quiet:
            actionable_count = sum(
                item.actionable
                for item in (
                    get_unified_scanner_metrics(asharp_model=results) if results else []
                )
            )
            print("\n[yellow]=== ASH Exit Codes ===[/yellow]")
            print(
                "  0: Success - No actionable findings or not configured to fail on findings"
            )
            print("  1: Error during execution")
            print(
                f"  2: Actionable findings detected when configured with `fail_on_findings: true`."
                f" Default is True. Current value: {opts.fail_on_findings if opts.fail_on_findings is not None else True}"
            )
            print(
                f"[bold red]ERROR (2) Exiting due to {actionable_count} actionable findings found in ASH scan[/bold red]"
            )

    if exit_code == 1:
        # An incomplete scan and a crash share exit 1, so the message has to be
        # chosen from the cause rather than the code. Printing "an exception
        # occurred" for a run whose scanners simply were not installed sends the
        # operator looking for a traceback that does not exist.
        _incomplete = (
            incomplete_scanners(results)
            if _resolve_fail_on_incomplete_scanners(
                results, opts, config_fail_on_incomplete_scanners
            )
            else []
        )
        if _incomplete:
            # "did not run" would be false for the coverage case: that scanner ran,
            # reported a status, and could not read some of its targets. Sending an
            # operator to install a tool that is already installed is the specific
            # wrong turn this wording avoids.
            print(
                "\n[bold red]ERROR (1) Exiting because the scan was incomplete: "
                f"{len(_incomplete)} selected scanner(s) did not evaluate "
                "everything they were given[/bold red]"
            )
            for _name, _status in _incomplete:
                print(f"  [red]{_name}: {_status}[/red]")
            print(
                "[yellow]ERROR means the scanner ran and failed; MISSING means its "
                "dependencies were unavailable; a target count means the scanner ran "
                "but could not read that many of its inputs. Install the missing "
                "tools, fix or exclude the unreadable targets, exclude the scanners "
                "with --exclude-scanners, or drop --fail-on-incomplete-scanners to "
                "accept a partial scan.[/yellow]"
            )
        else:
            print(
                "[bold red]ERROR (1) Exiting due to exception during ASH scan[/bold red]"
            )

    if exit_code != 0:
        sys.exit(exit_code)

    return results
