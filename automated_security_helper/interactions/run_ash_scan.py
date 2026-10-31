# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import functools
import inspect
import json
import logging
import os
import platform
import shutil
import stat
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Collection,
    Dict,
    List,
    NamedTuple,
    NoReturn,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
    cast,
)

import typer
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from rich.text import Text

# `print` shadows the builtin on purpose: this is rich's documented import
# idiom, so every print() below renders markup and respects the console. The
# fix A004 wants is an alias, which would mean rewriting every call in this
# module for no behavior change -- and tests/unit/cli/mcp/test_stdout_jsonrpc_safety.py
# reasons about this exact import form. It is utils/console.py's print, not rich's:
# its console checks each line it writes off a terminal, so none reads as a CI command.
from automated_security_helper.utils.console import echo, global_console, secho
from automated_security_helper.utils.console import print  # noqa: A004
from automated_security_helper.utils.terminal_text import (
    as_written,
    shown_not_obeyed,
    shown_on_one_line,
)

from automated_security_helper.core.cancellation import raise_if_cancelled
from automated_security_helper.core.previous_results import (
    HELD_DIR_NAME,
    RESTORED_MARKER_NAME,
    RESTORING_DIR_NAME,
    PreviousResults,
    holds_restored_results,
)
from automated_security_helper.core.constants import (
    ASH_EXIT_CODES,
    ASH_EXIT_USAGE_ERROR,
    ASH_WORK_DIR_NAME,
    is_offline_mode,
)
from automated_security_helper.core.scanner_selection import SelectionOrigin
from automated_security_helper.core.enums import (
    AshLogLevel,
    BuildTarget,
    ExecutionPhase,
    ExecutionStrategy,
    ExportFormat,
    MinSeverity,
    RunMode,
    SandboxMode,
    ScannerStatus,
)
from automated_security_helper.core.committed_output import (
    COMMITTED_OUTPUT_REFUSED_EXIT_CODE,
    LOG_FILE_NAMES,
    PREVIOUS_RUN_FILE_NAMES,
    WORKSPACE_ROOT_FILES,
    committed_entries_in_a_workspace_output,
    committed_entries_in_the_way,
    committed_output_files_error,
    refusal_label,
    report_over_existing_results_writes,
)
from automated_security_helper.core.exceptions import (
    ASHConfigFieldDeniedError,
    ASHConfigPolicyUnreadableError,
    ASHConfigValidationError,
    CommittedOutputFilesError,
    ScannerSelectionError,
    WorkspaceDefinitionError,
    WorkspacePathNotUtf8Error,
)
from automated_security_helper.core.progress import ExecutionPhaseType
from automated_security_helper.core.sharding import shown_shard_text
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.core.unified_metrics import (
    NO_MISSING_REASON_RECORDED,
    UNUSABLE_COUNTERS,
    format_duration,
    get_unified_scanner_metrics,
    recorded_reason,
)
from automated_security_helper.interactions.container_leftovers import sweep_env_dirs
from automated_security_helper.interactions.run_ash_container import (
    ASH_CONFIG_FROM_HOST_FLAG,
    CONFIG_FILE_FROM_ANOTHER_CHECKOUT_FLAG,
    CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG,
    CONFIG_FROM_SCANNED_REPOSITORY_FLAG,
    ContainerInputError,
    OperatorConfigReads,
    _require_mountable_directories,
    container_build_refusal,
    container_input_refusal,
    container_output_dir_refusal,
    container_was_started,
    run_ash_container,
    sweep_leftovers_before_run,
)
from automated_security_helper.interactions.run_ash_nix import (
    ASH_IN_NIX_ENV_VAR,
    NixModeRefused,
    nix_executable_for_this_run,
    run_ash_nix,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    known_failed_input_kind,
    waives_gate,
)
from automated_security_helper.models.workspace import WorkspaceExitCode
from automated_security_helper.utils.atomic_write import write_text_atomically
from automated_security_helper.utils.content_db_staleness import (
    ContentDbAgeRecord,
    scanners_in_error_for_a_stale_database,
    stale_content_databases,
)
from automated_security_helper.utils.converter_refusals import inert_text
from automated_security_helper.utils.directory_refusals import output_dir_unmakeable
from automated_security_helper.utils.error_text import error_text, log_unexpected_error
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP, escape_markup
from automated_security_helper.utils.output_dir_links import (
    OUTPUT_RESULT_FILES,
    OUTPUT_WORKING_DIRS,
)
from automated_security_helper.utils.process_env import (
    hold_environ,
    release_environ,
    snapshot_environ,
)
from automated_security_helper.utils.report_path_links import (
    ReportPathLinkRefused,
    ReportPathRefused,
    linked_report_path,
    refuse_a_linked_reports_dir,
)
from automated_security_helper.utils.inner_run_outcome import (
    INNER_RUN_OUTCOME_FILE,
    ExistingResultsRefused,
    as_seen_from_the_host,
    completion_marker,
    mark_run_completed,
    new_outer_run_id,
    not_a_regular_file,
    take_outer_run_id,
    read_back_outcome,
    read_refusal_outcome,
    record_refusal_outcome,
    record_reports_written,
    records_reports_written,
    release_records_completion,
    report_file_written_as,
)
from automated_security_helper.utils.sarif_utils import (
    _resolve_result_severity,
    is_result_suppressed,
)
from automated_security_helper.utils.scan_output_dirs import WORKING_DIR_NAMES
from automated_security_helper.utils.severity_ladder import severity_fails_threshold
from automated_security_helper.workspace.plan import WorkspacePlan

if TYPE_CHECKING:
    # Imported for annotations only. A runtime import here would pull the
    # workspace executor -- and through it core.orchestrator -- into every
    # single-directory scan's import graph.
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.client_config_policy import (
        ClientConfigRules,
    )
    from automated_security_helper.config.config_sources import (
        ResolvedConfigDocument,
    )
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
    # The --workspace-config value as the operator spelled it, when one was
    # given. The plan holds the resolved policy path (the file read); container
    # mode hands the policy over by this name instead, so a policy named inside
    # the workspace's tree that links out of it is refused as an in-tree
    # --config that links out is.
    workspace_config_as_named: Optional[str] = None

    # General scan options
    config: Optional[str] = None
    config_overrides: Optional[List[str]] = Field(default_factory=list)
    # A check every `extends` base of the config must also pass, applied by every
    # config read below. The MCP server passes the calling session's allowed
    # config roots (cli/mcp/sandbox.config_base_gate); None keeps the CLI rule.
    config_base_gate: Optional[Callable[[Path], bool]] = Field(
        default=None, exclude=True
    )
    # The config was written by the caller (an MCP client's upload), so its sandbox
    # settings are restrict-only; trusted_config_path is the operator's config the
    # grants come from instead. Both go to resolve_config, in local mode only.
    untrusted_config: bool = False
    trusted_config_path: Optional[str] = None
    # config_overrides came from an MCP client (a workspace tool's), so a tool
    # config path they name is not the operator's (config/path_trust.py).
    client_overrides: bool = False
    # The scan was started by a remote MCP client (cli/mcp/sandbox.caller_is_remote),
    # so every config file the operator did not set aside resolves no !ENV; see
    # "Environment variables" in config/config_sources.py. Applied by every config
    # read below, and carried to each project in workspace mode.
    remote_client: bool = False
    # The session's ClientConfigRules, which a config file an MCP client
    # delivered is checked against. Goes to
    # resolve_config, in local mode only. Typed Any to keep config imports out of
    # this module's import time, as the other config inputs here are.
    client_config_policy: Optional[Any] = Field(default=None, exclude=True)
    # A threshold the scan must be at least as strict as: it runs at the stricter
    # of this and the config's global severity_threshold. The MCP server passes a
    # client's severity_threshold here, which may tighten the configured one and
    # never loosen it. Local mode only.
    severity_threshold_restriction: Optional[str] = None
    # Keep the previous scan's results until this scan has its own, instead of
    # deleting them when it starts (core/previous_results.py). For the MCP server,
    # which settles them itself: a scan that returns leaves them set aside, and
    # the caller drops them once it has decided the scan has results, or puts
    # them back. A scan that fails inside the orchestrator has them put back
    # there. In workspace mode it reaches each project's orchestrator, which then
    # drops them itself once the project's phases finish. Local and workspace mode
    # only; the CLI never sets it.
    keep_previous_results: bool = False
    offline: bool = False
    strategy: ExecutionStrategy = ExecutionStrategy.PARALLEL
    scanners: Optional[List[str]] = Field(default_factory=list)
    excluded_scanners: Optional[List[str]] = Field(default_factory=list)
    # Who gave the two lists above: "mcp" only from the MCP workspace tool, whose
    # SKIPPED rows and selection refusals then name its scanners and
    # excluded_scanners parameters instead of the CLI's flags.
    selection_origin: SelectionOrigin = "cli"
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

    @field_validator("min_severity", mode="before")
    @classmethod
    def _known_min_severity(cls, v):
        # The library and MCP entry point reaches here without the CLI's choice
        # check, so this is where an unknown value is refused for every caller.
        value = v.value if isinstance(v, MinSeverity) else v
        accepted = [member.value for member in MinSeverity]
        if not isinstance(value, str) or value.lower() not in accepted:
            raise ValueError(
                f"min_severity must be one of {', '.join(accepted)} (any case), "
                f"not {v!r}"
            )
        return value

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
#
# Keyed by exactly the MinSeverity values, which are what the CLI offers and what
# ScanOptions accepts, so the lookup in _compute_exit_code never meets a value it does
# not rank. tests/unit/cli/test_min_severity_is_validated.py holds the two together.
_SEVERITY_RANK = {"critical": 3, "high": 3, "medium": 2, "low": 1, "none": 0}

# The scanners `--mode precommit` always adds to the selection. A module constant
# so that .pre-commit-hooks.yaml can be checked against it: the `ash` hook's
# environment has to install whatever these need from Python (cdk-nag needs the
# `cdk` extra), or every hook run ends with a MISSING scanner and exit 1.
# tests/unit/test_pre_commit_hooks_manifest.py holds the two together.
PRECOMMIT_MODE_SCANNERS: Tuple[str, ...] = (
    "bandit",
    "detect-secrets",
    "checkov",
    "cdk-nag",
    "npm-audit",
)

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
        for metric in get_unified_scanner_metrics(asharp_model=results)
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
    -- which ``ash merge`` reads, from whatever ASH produced each shard -- keeps the
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


def scanners_with_nothing_to_scan(
    results: Optional[AshAggregatedResults],
) -> List[str]:
    """The scanners that were SKIPPED because they had no file to scan.

    A scanner that counts its targets says so with ``targets_attempted`` 0, which is
    graded SKIPPED: bandit with no Python file it was not told to exclude,
    detect-secrets with every file of its scan set ignored. A scanner that was not
    selected, or that declined this platform, is SKIPPED too but carries no count,
    so it is not listed: it made no claim about the files.
    """
    if results is None:
        return []
    names = []
    for metric in get_unified_scanner_metrics(asharp_model=results):
        attempted = getattr(metric, "targets_attempted", None)
        if (
            metric.status == ScannerStatus.SKIPPED.value
            and isinstance(attempted, int)
            and not isinstance(attempted, bool)
            and attempted == 0
        ):
            names.append(metric.scanner_name)
    return names


#: How many ignore_paths patterns the nothing-to-scan message shows.
_IGNORE_PATTERNS_SHOWN = 3


#: The gate's way out of the nothing-to-scan exit, appended to the message when
#: the gate is what clears it.
_NOTHING_TO_SCAN_ACCEPT_REMEDY = (
    " To accept a run that scanned nothing, set fail_on_incomplete_scanners: "
    "false or pass --no-fail-on-incomplete-scanners."
)


def nothing_to_scan_message(
    results: Optional[AshAggregatedResults],
    names: List[str],
    *,
    accept_remedy: bool = True,
) -> str:
    """Why a run whose scanners all had nothing to scan exits 1, and the remedy.

    Names global_settings.ignore_paths when the recorded config sets it, since
    ignored paths are left out of what each scanner reads and so can leave it
    nothing. The patterns may come from a config in the scanned tree, so each is
    shown with its control characters escaped. The one text serves the log line
    and the console, so the two cannot disagree; *accept_remedy* False leaves the
    gate's way out off, for a console arm that adds it only when the gate is what
    clears the exit (:func:`print_incompleteness_message`).
    """
    message = (
        f"No selected scanner had a file to scan: {', '.join(names)} "
        f"{'was' if len(names) == 1 else 'were'} SKIPPED with nothing to scan, so "
        "this run has shown the target to be neither clean nor dirty."
    )
    config = getattr(results, "ash_config", None)
    settings = getattr(config, "global_settings", None)
    patterns = [
        str(getattr(entry, "path", entry))
        for entry in (getattr(settings, "ignore_paths", None) or [])
    ]
    if patterns:
        shown = ", ".join(
            repr(inert_text(pattern)) for pattern in patterns[:_IGNORE_PATTERNS_SHOWN]
        )
        if len(patterns) > _IGNORE_PATTERNS_SHOWN:
            shown += f" and {len(patterns) - _IGNORE_PATTERNS_SHOWN} more"
        message += (
            f" The config's global_settings.ignore_paths ({shown}) leaves every "
            "path it matches out of what the scanners read, which can leave them "
            "nothing to scan; narrow it to have those files scanned."
        )
    return message + (_NOTHING_TO_SCAN_ACCEPT_REMEDY if accept_remedy else "")


def _partial_coverage(metric) -> tuple[int, int] | None:
    """``(attempted, failed)`` when *metric* lost some of its input, else None.

    The tri-state on ``targets_attempted`` is the whole content of this function.
    ``None`` means the scanner does not track per-target outcomes and is making no
    claim -- bandit, checkov, semgrep, grype, syft, detect-secrets and opengrep
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

    # A scanner that ran against a content database past its declared bound, under the
    # default `content_db_staleness: fail`, is incomplete in the sense this function
    # means: its findings are real, and its silence about anything published since the
    # database was built is not. Listed here so the callers that read only this list --
    # the workspace layer and `ash merge` -- name it. Under `warn` the record is not
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
    rows without ``failure`` or ``failed_inputs``, and ``ash merge`` reads shard
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
                                known_failed_input_kind(getattr(record, "kind", None))
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


def print_incompleteness_message(
    incomplete_scanner_rows: List[tuple[str, str]],
    incomplete_converter_rows: Sequence[Union["IncompleteConverter", tuple[str, str]]],
    stale_database_records: Sequence[ContentDbAgeRecord] = (),
    *,
    no_scanner_ran: bool = False,
    observed: Sequence[tuple[str, str]] = (),
    nothing_to_scan: Optional[str] = None,
    unevaluated_rules: Sequence[str] = (),
    missing_reasons: Optional[Dict[str, str]] = None,
    could_not_stop: Sequence[tuple[str, str]] = (),
) -> None:
    """Explain an exit code of 1 in terms of what actually caused it.

    *nothing_to_scan* is the log line's own text for scanners SKIPPED with no
    file to scan (``nothing_to_scan_message`` with ``accept_remedy=False``), or
    None. When every scanner was skipped and that text is given, the
    no-scanner-ran arm prints it, with the gate's way out when the gate clears
    the exit, instead of the selection-mistake advice, which would contradict
    the log.

    WHY THIS IS A FUNCTION RATHER THAN THREE BRANCHES INLINE
    ------------------------------------------------------
    It was inline, and the converter arm had no branch of its own, so it fell through to
    "Exiting due to exception during ASH scan" -- which is false. Nothing raises on that
    path: ``_compute_exit_code`` returns 1 from the converter gate after a
    ``logger.error``. Both Nix CI legs exited that way, and the wording sent a reader
    through 1572 log lines hunting a traceback that was never written, with the real
    cause recorded only in a log line seventy lines earlier.

    Inline it also could not be tested. The enclosing function runs a whole scan, so no
    unit test could assert on the wording, which is how a message this wrong survived.
    Extracted, the arm selection is a pure function of two lists and
    ``tests/unit/interactions/test_fail_on_incomplete_converters.py`` asserts it
    directly.

    THE SCANNER ARM WINS WHEN BOTH ARE NON-EMPTY, deliberately. A scanner that did not
    run is the more specific and more serious finding, and conversion shortfalls often
    follow from the same absent environment. The converter arm is still reachable on its
    own, which is the case Nix mode produces.

    STALE CONTENT DATABASES ARE PRINTED FIRST AND ALONGSIDE, not as a third arm of
    the precedence above. Their advice is different (refresh the database, or opt out
    with ``--allow-stale-content-db``), and that arm is not behind the completeness
    gate, so a run can trip it together with either of the others. A scanner listed
    only for its stale database never reaches ``incomplete_scanner_rows``, and that
    includes one recorded ERROR because its clean result came from that database:
    ``scan_incompleteness`` carries it in the stale records instead, so it is listed
    once, with the refresh advice in the record's message, and the install-the-tool
    advice below is not given for a tool that ran.

    EVERY OTHER CAUSE OF EXIT 1 HAS AN ARM TOO. ``no_scanner_ran`` (every scanner
    SKIPPED, ``observed`` naming them) sits with the gate arms, after the scanner arm
    and before the converter arm, the order ``_compute_exit_code`` tests them in.
    ``unevaluated_rules`` and ``could_not_stop`` are printed alongside, like the
    stale databases, because those arms are not behind the gate. ``could_not_stop``
    in particular must never hide behind the scanner arm: the same run usually
    trips both (the stop that failed left an ERROR row), and the scanner arm's
    advice -- install the tool, or decline the gate -- does not apply to a cause
    no setting silences. So an ``--exclude-scanners`` that
    leaves nothing to run, a rule that raised, and a tool ASH could not stop are
    each named by their arm,
    not by the exception line of a scan that did not finish, which is printed
    only when nothing at all was recorded: exit 1 with no results.

    A MISSING row is followed by its recorded reason when *missing_reasons* has one
    (``ScanIncompleteness.missing_reasons``). When every MISSING row has one, the
    advice points at them instead of saying "Install the missing tools": npm-audit
    offline is MISSING with npm installed, and the reason is the offline mode.
    """
    # The gated arms advise declining the gate only when that clears the exit.
    # A tool ASH could not stop, a rule that could not be evaluated and a stale
    # content database each fail the run whatever the gate says
    # (_compute_exit_code; their own arms below name what clears them), so
    # beside any of them the gated advice ends without the flag.
    gate_clears_the_exit = not (
        could_not_stop or unevaluated_rules or stale_database_records
    )

    def ways_out(*ways: str) -> str:
        # The ways out of a gated exit as one list: commas between them, and
        # "or" before the last, whether or not the gate's own way is among them.
        return ", ".join(ways[:-1]) + ", or " + ways[-1] if len(ways) > 1 else ways[0]

    # The gate's own way out, the last in each gated arm's list.
    accept_partial = (
        ("pass --no-fail-on-incomplete-scanners to accept a partial scan",)
        if gate_clears_the_exit
        else ()
    )
    if could_not_stop:
        print(
            "\n[bold red]ERROR (1) Exiting because "
            f"{len(could_not_stop)} scanner tool(s) could not be stopped and may "
            "still be running[/bold red]"
        )
        for _name, _reason in could_not_stop:
            print(f"  [red]{escape_markup(_name)}: {escape_markup(_reason)}[/red]")
        print(
            "[yellow]A tool still running can write into the output directory "
            "after the scan has read it, so the report is not final. This exit is "
            "not behind --fail-on-incomplete-scanners; end the listed process(es) "
            "and run the scan again.[/yellow]"
        )
    if unevaluated_rules:
        print(
            "\n[bold red]ERROR (1) Exiting because "
            f"{len(unevaluated_rules)} rule(s) could not be evaluated, so this scan "
            "reports nothing about compliance with them[/bold red]"
        )
        for _rule in unevaluated_rules:
            print(f"  [red]{escape_markup(str(_rule))}[/red]")
        print(
            "[yellow]The scanner ran and the rule raised instead of reaching a "
            "verdict. Fix the template the rule cannot read, or suppress the rule's "
            "not-evaluated results to accept that it was not evaluated.[/yellow]"
        )
    if stale_database_records:
        print(
            "\n[bold red]ERROR (1) Exiting because "
            f"{len(stale_database_records)} content database(s) are past their "
            "declared age bound[/bold red]"
        )
        for _record in stale_database_records:
            print(f"  [red]{escape_markup(_record.message())}[/red]")
    if incomplete_scanner_rows:
        # "did not run" would be false for the coverage case: that scanner ran,
        # reported a status, and could not read some of its targets. Sending an
        # operator to install a tool that is already installed is the specific
        # wrong turn this wording avoids.
        print(
            "\n[bold red]ERROR (1) Exiting because the scan was incomplete: "
            f"{len(incomplete_scanner_rows)} selected scanner(s) did not evaluate "
            "everything they were given[/bold red]"
        )
        reasons = dict(missing_reasons or {})
        for _name, _status in incomplete_scanner_rows:
            print(f"  [red]{escape_markup(_name)}: {escape_markup(_status)}[/red]")
            if _name in reasons:
                print(f"    [red]{escape_markup(reasons[_name])}[/red]")
        missing_rows = [
            _name
            for _name, _status in incomplete_scanner_rows
            if _status.split(" (", 1)[0] == ScannerStatus.MISSING.value
        ]
        # The warning that a relative ASH_BIN_PATH was skipped goes to ash.log,
        # which a reader of this advice may never open.
        from automated_security_helper.utils.subprocess_utils import (
            ignored_relative_bin_path,
        )

        relative_bin_path = ignored_relative_bin_path()
        if relative_bin_path is not None and missing_rows:
            # On one line, unwrapped: wrapped at the console width, a long value
            # could start a line with text it chose, such as a GitHub Actions
            # "::error" workflow command.
            global_console().print(
                "[yellow]Tools in ASH_BIN_PATH "
                f"{escape_markup(repr(relative_bin_path))} were not looked for: it "
                "is a relative path. If the missing tools are there, set "
                "ASH_BIN_PATH to an absolute path.[/yellow]",
                soft_wrap=True,
                highlight=False,
            )
        if missing_rows and all(_name in reasons for _name in missing_rows):
            print(
                "[yellow]ERROR means the scanner ran and failed; MISSING means it "
                "could not run, for the reason under it; a target count means the "
                "scanner ran but could not read that many of its inputs. "
                + ways_out(
                    "Act on each MISSING scanner's reason",
                    "fix or exclude the unreadable targets",
                    "exclude the scanners with --exclude-scanners",
                    *accept_partial,
                )
                + ".[/yellow]"
            )
        else:
            print(
                "[yellow]ERROR means the scanner ran and failed; MISSING means its "
                "dependencies were unavailable; a target count means the scanner ran "
                "but could not read that many of its inputs. "
                + ways_out(
                    "Install the missing tools",
                    "fix or exclude the unreadable targets",
                    "exclude the scanners with --exclude-scanners",
                    *accept_partial,
                )
                + ".[/yellow]"
            )
        _print_in_tree_refusals()
    elif no_scanner_ran:
        # Every scanner was SKIPPED, so the scan finished having checked nothing.
        print(
            "\n[bold red]ERROR (1) Exiting because no scanner ran: every scanner "
            "was skipped, so this scan has shown the target to be neither clean "
            "nor dirty[/bold red]"
        )
        for _name, _status in observed:
            print(f"  [red]{escape_markup(_name)}: {escape_markup(_status)}[/red]")
        if nothing_to_scan:
            # The selected scanners had no file to scan: the cause is what they
            # were given, not which were selected. The text is the log line's
            # (nothing_to_scan_message: the config's ignore_paths named only when
            # it sets them, each pattern shown inert), so console and log agree;
            # the gate's way out follows only when the gate is what clears the
            # exit, as the scanner arm offers it.
            remedy = _NOTHING_TO_SCAN_ACCEPT_REMEDY if gate_clears_the_exit else ""
            print(f"[yellow]{escape_markup(nothing_to_scan + remedy)}[/yellow]")
        else:
            print(
                "[yellow]Each scanner's skipped_reason in ash_aggregated_results.json "
                "says why. The usual cause is --scanners naming no scanner this "
                "platform supports, or --exclude-scanners leaving nothing to "
                "run.[/yellow]"
            )
        _print_in_tree_refusals()
    elif incomplete_converter_rows:
        # Names the converter, because that is the actionable part -- the fix is
        # per kind, printed below, and none of it is discoverable from "an
        # exception occurred".
        print(
            "\n[bold red]ERROR (1) Exiting because conversion was incomplete: "
            f"{len(incomplete_converter_rows)} converter(s) did not process the "
            "files they were given[/bold red]"
        )
        for row in incomplete_converter_rows:
            # The reason is the converter's exception text, which can name a file.
            print(f"  [red]{escape_markup(row[0])}: {escape_markup(row[1])}[/red]")
        # The advice is chosen per record kind, read from the rows' data (a
        # hand-built (name, reason) pair reads as a converter that did not
        # run). Telling the operator to install the tool for a converter that
        # ran is the wrong turn the scanner arm's wording avoids too, and
        # telling one to fix the inputs when the tool failed on them is the
        # same turn the other way.
        kinds_present: set[str] = set()
        for row in incomplete_converter_rows:
            kinds_present.update(getattr(row, "kinds", ()) or ())
        if "input" in kinds_present:
            print(
                "[yellow]A converter listed with inputs it could not convert ran, "
                "and the scanners did not see those inputs in converted form: "
                + ways_out(
                    "fix the listed inputs or add them to ignore_paths",
                    "accept a reviewed one with a global_settings.suppressions "
                    "entry with rule_id ash-unconverted-input",
                    *accept_partial,
                )
                + ".[/yellow]"
            )
        if "tool" in kinds_present:
            print(
                "[yellow]A converter's tool failed on the listed inputs, or could "
                "not be run on them; each line's reason says which. When the tool "
                "itself could not run, make the converter's tool able to run (its "
                "runtime, network or installation). When it ran and failed on an "
                "input, fix that input or add it to ignore_paths."
                + (
                    " Either way --no-fail-on-incomplete-scanners accepts a "
                    "partial scan."
                    if gate_clears_the_exit
                    else ""
                )
                + "[/yellow]"
            )
        if "limit" in kinds_present:
            print(
                "[yellow]An archive over an extraction limit was refused whole, so "
                "none of its contents reached the scanners. It is extracted once "
                "the limit named is raised, with --config-overrides "
                "converters.archive.options.<limit>=<value> or a config file "
                "outside every git checkout."
                + (
                    " --no-fail-on-incomplete-scanners accepts a partial scan."
                    if gate_clears_the_exit
                    else ""
                )
                + "[/yellow]"
            )
        if any(
            not (getattr(row, "kinds", ()) or ()) for row in incomplete_converter_rows
        ):
            print(
                "[yellow]A converter that did not run leaves its inputs unscanned, "
                "so the scanners saw fewer files than this repository holds. "
                + ways_out(
                    "Install the converter's tool",
                    "disable the converter if its inputs are not wanted",
                    *accept_partial,
                )
                + ". A converter with nothing to convert never reports here.[/yellow]"
            )
    elif not stale_database_records and not unevaluated_rules and not could_not_stop:
        print("[bold red]ERROR (1) Exiting due to exception during ASH scan[/bold red]")


def _print_in_tree_refusals() -> None:
    """Name the tools this scan found only inside its tree, which are MISSING rows.

    "Install the missing tools" is the wrong advice for one that is installed, in
    the repository's own .venv/bin or node_modules/.bin.
    """
    from automated_security_helper.utils.subprocess_utils import (
        in_tree_refusals,
        in_tree_remedy,
    )

    refused = in_tree_refusals()
    if not refused:
        return
    named = ", ".join(
        f"{command} ({path})" for command, path in sorted(refused.items())
    )
    message = (
        f"Found only inside the scanned tree, so not run: {named}. To use them, "
        f"{in_tree_remedy()}."
    )
    print(f"[yellow]{escape_markup(message)}[/yellow]")


def _result_rule_id(result) -> str:
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
    ``.ash/.ash.yaml`` carries fifteen such entries under the heading "rules that
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
    4. On, matching ``AshConfig.fail_on_incomplete_scanners``.

    Step 4 is reached only when no config model was available at all -- a results
    object built by hand, or a scan whose config failed to load. It agrees with the
    model default deliberately: the two are the same question answered twice, and
    when they disagreed the answer you got depended on how far the scan had got
    before it was asked, which is not a property anyone wants an exit code to have.
    ``cli.merge._resolve_require_scanner_completion`` is a third copy and has to
    move with these two.

    ON rather than off, and this was off by default for part of this branch's life.
    A scanner recorded ERROR or MISSING produces no findings, so deriving the exit
    code from findings alone gives that scan the code of a clean one -- and step 4 in
    particular is the least-attributable input there is, a results object whose
    configuration could not be established. Defaulting the least trustworthy case to
    the most trusting answer is backwards. The environment that genuinely cannot
    provide a scanner's tool says so once, with
    ``--no-fail-on-incomplete-scanners`` or ``fail_on_incomplete_scanners: false``,
    and keeps its old exit codes; what it no longer gets is that outcome by saying
    nothing.

    This gate selects on status, so it sees a tool's hard failure only because the
    failure reaches the status: a tool that exits with a code outside its scanner's
    ``success_exit_codes`` is recorded ERROR whatever its results file holds
    (``ScannerPluginBase._refuse_rejected_exit_code``). With the gate off, that ERROR
    row still leaves the exit code to the findings, so a scan whose only problem is a
    failed scanner exits 0. Pinned by ``TestAHardFailureReachesTheGate`` in
    ``tests/unit/interactions/test_fail_on_incomplete_scanners.py``, in all three
    positions of this flag.
    """
    if opts.fail_on_incomplete_scanners is not None:
        return opts.fail_on_incomplete_scanners

    resolved_config = getattr(results, "ash_config", None)
    from_results = getattr(resolved_config, "fail_on_incomplete_scanners", None)
    if isinstance(from_results, bool):
        return from_results

    if config_value is not None:
        return config_value
    return True


#: How an incomplete scanner's recorded status reads as a reason in a structured
#: payload. ``missing_dependencies`` is the token ``skipped_scanners`` already uses
#: for the same status, so a client sees one spelling for one cause.
_INCOMPLETE_SCANNER_REASONS = {
    ScannerStatus.MISSING.value: "missing_dependencies",
    ScannerStatus.ERROR.value: "error",
}


def incomplete_scanner_reason(status: str, partial: bool = False) -> str:
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
    """
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
                        status, partial=name in self.partial_coverage
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
    the database named in the status, so that the workspace layer and ``ash merge``
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
        if (
            status.split(" (", 1)[0] != ScannerStatus.MISSING.value
            and f"({_MISSING_ON_SOME_FILES})" not in status
        ):
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
        for metric in get_unified_scanner_metrics(results)
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
    return ScanIncompleteness(
        scanners=rows,
        partial_coverage=partial_coverage,
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


class ScanIncompleteExit(SystemExit):
    """``sys.exit(1)`` for a scan that finished with partial coverage.

    A ``SystemExit`` with code 1, so the CLI's exit code and every caller that
    catches ``SystemExit`` see what they saw before. It adds the structured reason.
    Exit 1 also means a crash, and an in-process caller that has only the code
    cannot tell the two apart. Its other choices are parsing the log or re-reading
    a results file that a crash after the SCAN phase leaves behind looking just
    like a finished scan's.

    Raised only where ``_compute_exit_code`` returned 1 with results in hand. That
    function returns 1 with results only from the coverage arms, so the
    exception's presence is the signal and ``incompleteness`` is what it was.
    """

    def __init__(
        self, incompleteness: ScanIncompleteness, results: AshAggregatedResults
    ):
        super().__init__(1)
        self.incompleteness = incompleteness
        self.results = results


class ReportPathRefusedExit(SystemExit):
    """``sys.exit(1)`` for a run whose reports were refused, with the reason.

    Raised when a report path is a link, when a file name a reporter would write is
    not a file in the reports directory, and in container and nix mode when the
    inner run recorded either refusal in its results file. A ``SystemExit`` with
    code 1, so the CLI's exit code is that of any other error. ``reason`` is the
    message printed to the console, which names the link or the file name; an
    in-process caller (the MCP scan runner) reports it rather than a bare "exited
    with code 1". See utils/report_path_links.py.
    """

    def __init__(self, reason: str):
        super().__init__(1)
        self.reason = reason


def _refuse_report_path_link(refusal: ReportPathRefused) -> NoReturn:
    print(f"[bold red]ERROR (1) {escape_markup(str(refusal))}[/bold red]")
    raise ReportPathRefusedExit(str(refusal)) from refusal


def _record_inner_refusal(
    opts: ScanOptions, refusal: ReportPathRefused, run_id: Optional[str], logger
) -> None:
    """As the inner run of a container or nix scan, record ``refusal`` for the outer process.

    Beside the results file (``record_refusal_outcome``), whether or not the run
    wrote one: a local or workspace run refused before it wrote results has none,
    and a results file that held only the refusal would read as a scan to a later
    ``--use-existing``. The results file, when there is one, is left as written.
    """
    if run_id is None:
        return
    if not record_refusal_outcome(opts.output_dir, str(refusal), run_id):
        logger.warning(
            f"Could not record the refusal in {opts.output_dir / INNER_RUN_OUTCOME_FILE}; "
            "the outer process will report that this run did not complete."
        )


def _refuse_an_inner_file_that_is_not_regular(path: Path, what: str) -> None:
    """Exit 1, without reading it, when a file the inner run left is not a regular file.

    The inner run, a container's included, can leave a link at a path this
    process reads, naming any file on the host. ``what`` names the file's content
    in the message.
    """
    problem = not_a_regular_file(path)
    if problem is None:
        return
    reason = (
        f"{path.as_posix()} {problem}, so {what} is not read. ASH writes that file "
        "as a regular file; remove it and run ASH again."
    )
    print(f"[bold red]ERROR (1) {escape_markup(reason)}[/bold red]")
    raise ReportPathRefusedExit(reason)


def _read_back_inner_results(
    output_file: Path, logger
) -> Optional[AshAggregatedResults]:
    """The inner run's results file, parsed; None when there is none.

    Exits 1 when it is not a regular file, is not UTF-8, or does not parse. The
    reason is describe_results_error's, as ``ash report`` gives it for the same
    file: a location names only the results schema's own names (a key the file
    chose is ``<key>``), no value the file held is repeated, and control
    characters are written as ``\\xNN``.
    """
    from automated_security_helper.config.config_validator import (
        describe_results_error,
    )

    _refuse_an_inner_file_that_is_not_regular(output_file, "the inner run's results")
    if not output_file.exists():
        return None
    try:
        with open(output_file, mode="r", encoding="utf-8") as f:
            content = f.read()
        return AshAggregatedResults.model_validate_json(content)
    except (ValidationError, ValueError) as e:
        # UnicodeDecodeError is a ValueError, so the read is inside the handler.
        logger.error(
            f"Failed to parse results file {output_file}: {describe_results_error(e)}"
        )
    except OSError as e:
        # A file that exists but cannot be opened or read (a permission the inner
        # run set, a device that fails the read) is the same exit, worded, not a
        # traceback.
        logger.error(f"Could not read results file {output_file}: {error_text(e)}")
    sys.exit(1)


def _refuse_an_inner_run_that_was_refused(opts: ScanOptions, run_id: str) -> None:
    """Exit 1 with the refusal the inner run recorded, given as this process sees the paths.

    Read before the results file, which a run refused before its scan phase never
    wrote. A record that is a link, or not a regular file, refuses the read-back
    without being read; one with another run's ID is ignored.
    """
    _refuse_an_inner_file_that_is_not_regular(
        opts.output_dir / INNER_RUN_OUTCOME_FILE, "the inner run's outcome"
    )
    refusal = read_refusal_outcome(opts.output_dir, run_id)
    if refusal is not None:
        reason = as_seen_from_the_host(
            refusal.message, refusal.inner_output_dir, opts.output_dir.as_posix()
        )
        print(f"[bold red]ERROR (1) {escape_markup(reason)}[/bold red]")
        raise ReportPathRefusedExit(reason)


def _image_rebuild_hint() -> str:
    """How to replace a container image whose ASH records no completion.

    A rebuild from this ASH always works, so it comes first. A release is offered
    by version only when that release records completion (v3.7.1 and earlier do
    not, so naming one would build an image that fails the same way); otherwise
    the hint names the revision a rebuild installs.
    """
    from automated_security_helper.interactions.run_ash_container import (
        get_ash_revision,
    )
    from automated_security_helper.utils.get_ash_version import get_ash_version

    rebuild = (
        "rebuild the image from this ASH (run without --no-build, with --force if "
        "the image is cached)"
    )
    version = get_ash_version()
    if release_records_completion(version):
        return (
            f"{rebuild}, or pass --ash-revision-to-install v{version} to install "
            f"ASH {version} in it."
        )
    revision = get_ash_revision(quiet=True)
    if revision == "LOCAL":
        source = "this ASH's own source tree"
    elif revision:
        source = f"ASH revision {revision}"
    else:
        source = "the revision this ASH was installed from"
    return f"{rebuild}. Without --ash-revision-to-install, the build installs {source}."


def _refuse_an_inner_run_that_did_not_complete(
    results: AshAggregatedResults,
    opts: ScanOptions,
    run_id: str,
    mode: str,
    output_file: Path,
    logger,
) -> None:
    """Refuse the read-back of an inner run that did not record its completion.

    The inner run's status is a verdict this process re-derives, and 1 is also what
    a refused or failed inner run exits with, so the results file has to say that
    the run with this ID completed (utils/inner_run_outcome.py). A refusal the inner
    run recorded was reported before this, by
    ``_refuse_an_inner_run_that_was_refused``.
    """
    outcome = read_back_outcome(results, run_id)
    if outcome.completed:
        return
    if outcome.written_by_an_older_ash:
        found = (
            "holds a record without a run ID, which an ASH older than this one "
            "writes, and no record that this run completed"
        )
    elif outcome.marked_by_another_run:
        found = "holds only records an earlier run wrote"
    else:
        found = "holds no record that the run completed"
    # In container mode the inner ASH is the image's, which can be older than this
    # one. In nix mode it is started with this ASH's own interpreter
    # (run_ash_nix._this_ash), so the message names that instead.
    if mode == "container":
        older = (
            " An ASH older than this one does not write that record: "
            f"{_image_rebuild_hint()}"
        )
    else:
        older = (
            f" The inner run was started with this ASH's interpreter, {sys.executable}."
        )
    logger.error(
        f"The {mode} run did not complete, so its results are not read back: "
        f"{output_file} {found}. The run's own output above says what stopped it."
        f"{older}"
    )
    sys.exit(1)


def _refuse_links_left_in_reports(opts: ScanOptions) -> None:
    """Refuse the read-back of a container or nix run when ``reports/`` holds a link.

    The inner run's report phase refuses a link at a file its reporters write, and
    exits 1. That status alone does not reach the operator: 1 is a verdict this
    process re-derives from the results file. This process does not know the inner
    run's reporters (an image can carry plugins this host lacks), but no reporter
    creates a link, and _discard_prior_run_artifacts removed ``reports/`` unless
    ``--use-existing`` kept it. So a link directly in ``reports/`` after the inner
    run is one the inner run refused or one no reporter wrote, and either way the
    run is refused here rather than answered from the files beside it.
    """
    reports = opts.output_dir / "reports"
    try:
        listed = [entry.name for entry in reports.iterdir()]
    except OSError:
        listed = []
    # ash.sarif always, since _compute_exit_code reads it back. That also has the
    # directory itself examined when it lists nothing, as a dangling link does.
    found = linked_report_path(reports, ["ash.sarif", *listed])
    if found is not None:
        _refuse_report_path_link(ReportPathLinkRefused(found))


class ScanRefusedExit(SystemExit):
    """``sys.exit(code)`` for a run ASH refused or gave up, with the reason it showed.

    A ``SystemExit`` with the same code, so the CLI's exit code and every caller
    that catches ``SystemExit`` see a plain ``sys.exit(code)``. ``message`` is the text
    the CLI printed or logged for it, as plain text: not escaped, not shown. A
    caller that only had the code could say that the run failed, not why; the MCP
    runner shows ``message`` to its client (cli/mcp_tools.py), which may be on
    another host, so an error caught here is quoted in it only as
    ``utils.error_text.error_text`` gives it: a pydantic error's own text quotes
    the refused input, which can be a secret read from the environment.

    Container and Nix mode's other host-side exits, which hand on the inner run's
    status or refuse the outer run before it starts, stay plain ``sys.exit``: the
    MCP server never runs those modes, and the CLI prints their reasons already.
    """

    def __init__(self, code: int, message: str):
        super().__init__(code)
        self.message = message


def _printed_refusal(code: int, message: str, one_line: bool = False) -> NoReturn:
    """Print *message* as the CLI's ``ERROR (code)`` line, then exit with *code*.

    *message* is plain text; it is escaped for Rich here, so text a repository or
    an operator wrote prints as what it says. With *one_line* its newlines are
    written as escapes too (escape_markup's ``one_line``), for a message that
    names a path.

    Raised ``from None``, as the two helpers below are: a failure handler calls
    these inside its ``except`` block, and the exit would otherwise chain the
    error being handled, whose unredacted text anything formatting the exit
    prints.
    """
    print(
        f"[bold red]ERROR ({code}) {escape_markup(message, one_line=one_line)}"
        "[/bold red]"
    )
    raise ScanRefusedExit(code, message) from None


def _printed_config_refusal(code: int, error: ASHConfigValidationError) -> NoReturn:
    """_printed_refusal for a config file the run cannot use.

    The refusal names the file, whose path is the caller's text, so each of its
    lines is shown on one line: a newline in the path started a line of the
    path's choosing. Which lines there are is parser_text.refusal_own_lines'
    one rule, shared with the workspace plan's refusal
    (cli/scan._fail_workspace_config): a parser's message that names its file
    keeps the parser's lines, and anything else is one line.
    """
    from automated_security_helper.utils.parser_text import refusal_own_lines

    message = _config_refusal_text(error)
    for line in refusal_own_lines(error, f"ERROR ({code}) {message}"):
        print(f"[bold red]{escape_markup(line, one_line=True)}[/bold red]")
    raise ScanRefusedExit(code, message) from None


def _logged_refusal(logger, code: int, message: str) -> NoReturn:
    """Log *message* as an error, then exit with *code* (``from None``, as
    _printed_refusal)."""
    logger.error(message)
    raise ScanRefusedExit(code, message) from None


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

    A suppressed result is one with a suppression IN EFFECT
    (``utils.sarif_utils.is_result_suppressed``): a suppression whose state is
    ``rejected`` or ``underReview`` has not taken effect (SARIF 3.35.4) and hides
    nothing, so the finding it sits on keeps the count standing, as it does for
    the per-scanner counts, the flat finding and the workspace verdict.
    """
    if is_result_suppressed(result):
        return False
    return _SEVERITY_RANK.get(_resolve_result_severity(result), 1) >= min_sev_rank


def _scanner_threshold_lookup(results) -> Callable[[object], str]:
    """The threshold governing a scanner, by name, memoised for one exit-code read.

    The scanner's own ``options.severity_threshold`` when it has one, else
    ``global_settings.severity_threshold``
    (``ScannerStatisticsCalculator.get_scanner_threshold_info``, which dumps the
    whole scanners config on every call, so one read of a large report asks it
    once per scanner, not once per result). An empty or missing name is passed
    through to the same resolver rather than short-circuited: it matches no
    scanner config key, so the resolver answers with the global threshold, and a
    result whose scanner cannot be identified is judged as every result was
    judged before per-scanner thresholds reached this gate instead of being
    skipped, which would remove a finding from the exit code.
    """
    cache: Dict[str, str] = {}

    def threshold_for(scanner_name: object) -> str:
        key = scanner_name if isinstance(scanner_name, str) else ""
        if key not in cache:
            cache[key] = ScannerStatisticsCalculator.get_scanner_threshold_info(
                results, key
            )[0]
        return cache[key]

    return threshold_for


def _run_tool_name(run) -> Optional[str]:
    """The tool a SARIF run names as its driver, model or JSON form."""
    tool = run.get("tool") if isinstance(run, dict) else getattr(run, "tool", None)
    driver = (
        tool.get("driver") if isinstance(tool, dict) else getattr(tool, "driver", None)
    )
    name = (
        driver.get("name")
        if isinstance(driver, dict)
        else getattr(driver, "name", None)
    )
    return name if isinstance(name, str) and name else None


def _result_scanner_name(result, run=None) -> Optional[str]:
    """The scanner a SARIF result belongs to, model or JSON form.

    ``properties.scanner_name`` when the result carries one, else the tool of
    the *run* that holds it (``utils.sarif_utils`` reads a result's scanner the
    same way for the client exclusions). A result named only by its run fell
    to the global threshold, so a scanner the operator relaxed had its findings
    counted as actionable by the scanner metrics and then judged non-actionable
    here, and the run exited 0 over them.
    """
    props = (
        result.get("properties")
        if isinstance(result, dict)
        else getattr(result, "properties", None)
    )
    name = None
    if props is not None:
        name = (
            props.get("scanner_name")
            if isinstance(props, dict)
            else getattr(props, "scanner_name", None)
        )
    if isinstance(name, str) and name:
        return name
    return _run_tool_name(run) if run is not None else None


def _result_fails_its_scanner_threshold(result, threshold_for, run=None) -> bool:
    """Whether *result* (a SARIF ``Result`` or its JSON form) fails the gate of
    the scanner that reported it: the ONE actionability rule of the exit code.

    The count over the written report and the ``--min-severity`` filter over the
    model's results both read it, with the same *threshold_for* (from
    ``_scanner_threshold_lookup``) and the same severity reading, the ladder's
    ``result_severity`` through ``_resolve_result_severity``:
    ``properties.issue_severity`` when it names a severity, else the SARIF level.
    Two readings (one upper-casing ``issue_severity`` against ``SEVERITIES`` and
    falling back to the level, one resolving the result) could disagree on a
    result with only a level or a non-standard ``issue_severity``.

    *run* is the SARIF run that holds the result: it names the scanner of a
    result that carries no ``scanner_name`` of its own.
    """
    return severity_fails_threshold(
        _resolve_result_severity(result),
        threshold_for(_result_scanner_name(result, run)),
    )


def _actionable_under_its_scanner_threshold(
    result,
    results,
    threshold_for: Optional[Callable[[object], str]] = None,
    run=None,
) -> bool:
    """Whether *result* fails the gate of the scanner that reported it.

    A result the scanner's threshold made non-actionable was not counted, so
    the ``--min-severity`` filter must not read it as the finding that keeps the
    count standing. *threshold_for* is the exit-code read's shared lookup; a
    caller without one gets a fresh lookup over *results*. *run* is the SARIF
    run that holds the result.
    """
    if threshold_for is None:
        threshold_for = _scanner_threshold_lookup(results)
    return _result_fails_its_scanner_threshold(result, threshold_for, run)


# ---------------------------------------------------------------------------
# Helper: resolve final AshLogLevel
# ---------------------------------------------------------------------------


def _discovered_config_path(
    source_dir: Path,
    log_selection: bool = False,
    permit: Optional[Callable[[Path], bool]] = None,
) -> Optional[str]:
    """The config source a scan of *source_dir* uses, by the one discovery rule.

    Every reader in this module goes through here and through
    ``config_sources.discover_config_source``, so the exit-code fields, the
    workspace knobs and the orchestrator all read the same file -- including a
    pyproject.toml [tool.ash] table or an ashrc file. Discovery errors are left
    to the caller, and so is the refusal of a file that resolves to one
    ``permit`` does not permit (``config_sources.check_discovered_source``), so
    that no reader here opens it.

    Nothing is logged here, ``log_selection`` or not: the caller logs the file it
    uses, and the sources discovery ignored become resolution warnings when the
    orchestrator resolves this file, which logs each one once and records it with
    the results. Logging them here as well printed each one twice.

    ``permit`` is the scan's ``config_base_gate``: every source discovery finds
    is checked against it before anything opens it. Every caller passes it, so
    no reader here opens a source the scan's resolution would refuse.
    """
    from automated_security_helper.config.config_sources import (
        check_discovered_source,
        discover_config_source,
    )

    discovery = discover_config_source(source_dir, permit=permit)
    if discovery.selected is None:
        return None
    check_discovered_source(discovery.selected.path, permit)
    return discovery.selected.path.as_posix()


def _ash_config_fallback(
    source_dir: Path, permit: Optional[Callable[[Path], bool]] = None
) -> Optional[str]:
    """``ASH_CONFIG``, when a local scan of *source_dir* with no config named uses it.

    A local scan falls back to ``ASH_CONFIG``'s file when it finds no config in the
    source directory (config/default_config.py). The scan inside a container sees
    neither the host's environment nor that file, so a one-directory container
    scan names it explicitly as ``--config``, in that same case and no other.
    A workspace scan does not ask this function: its caller names ``ASH_CONFIG``
    as ``--config`` whenever it is set, as the CLI hands it over, where the
    variable is ``--config``'s environment variable. In every case the file is
    also handed over as the scan's base, which a local scan reads whatever names
    the config (``run_ash_container._host_ash_config``). The rule lives in
    ``run_ash_container._env_config_is_the_scans_config``, shared with the
    launcher's own carry. A discovery error is left to the scan, which reports
    it. ``permit`` is the scan's ``config_base_gate``, forwarded to the shared
    rule's discovery so no source the scan's resolution would refuse is opened.
    """
    from automated_security_helper.interactions.run_ash_container import (
        _env_config_is_the_scans_config,
    )

    env_config = os.environ.get("ASH_CONFIG")
    if not env_config:
        return None
    if _env_config_is_the_scans_config(env_config, source_dir, permit=permit):
        return env_config
    return None


def _load_with_confinement(
    config_path_str: str,
    source_dir: Path,
    permit_base: Optional[Callable[[Path], bool]] = None,
    log_failure: bool = True,
    remote_client: bool = False,
    session_id: Optional[str] = None,
    confine: Optional[Callable[[Path, Path, Any], Any]] = None,
    repository_file: Optional[Callable[[Path, Path], bool]] = None,
):
    """Load a config file with its `extends` bases confined as a scan would.

    A file that is missing or does not load raises ``ASHConfigValidationError``,
    as it does when the scan resolves it; see ``resolve_config.load_config_file``.
    ``session_id`` is the MCP session the scan runs for
    (``ClientConfigRules.session_id``), whose ``config/`` directory holds the
    files set aside for a remote caller. ``confine`` and ``repository_file`` are
    load_config_file's. ``log_failure`` is accepted for the callers that pass
    it and not forwarded: the run-protocol load logs a refused file once
    itself.
    """
    del log_failure
    from automated_security_helper.config.config_sources import (
        default_confinement_root,
        env_refused_for,
    )
    from automated_security_helper.config.resolve_config import load_config_file

    config_path = Path(config_path_str)
    return load_config_file(
        config_path,
        confine_to=default_confinement_root(config_path, source_dir),
        permit_base=permit_base,
        refuse_env=env_refused_for(remote_client, session_id),
        confine=confine,
        repository_file=repository_file,
    )[1]


def _load_for_run_with_confinement(
    config_path_str: str,
    source_dir: Path,
    permit_base: Optional[Callable[[Path], bool]] = None,
    confine: Optional[Callable[[Path, Path, Any], Any]] = None,
    repository_file: Optional[Callable[[Path, Path], bool]] = None,
    remote_client: bool = False,
    session_id: Optional[str] = None,
):
    """_load_with_confinement for a configuration this process acts on and
    records: through load_config_file_for_run, so it knows the values its files
    read from the environment and the reference each was written as.
    ``remote_client`` and ``session_id`` are _load_with_confinement's: the same
    ``!ENV`` rule for the files of the chain, so a file a remote client's scan
    loads that reads from the environment is refused here as it is there."""
    from automated_security_helper.config.config_sources import (
        default_confinement_root,
        env_refused_for,
    )
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    config_path = Path(config_path_str)
    return load_config_file_for_run(
        config_path,
        confine_to=default_confinement_root(config_path, source_dir),
        permit_base=permit_base,
        refuse_env=env_refused_for(remote_client, session_id),
        confine=confine,
        repository_file=repository_file,
    )[1]


def _take_own_values_for_record(
    results: AshAggregatedResults,
    opts: ScanOptions,
    *,
    image_may_differ: Optional[bool] = None,
) -> None:
    """For results the inner scan of a container or Nix run wrote: each field
    their record holds as an environment reference it cannot hold, such as
    severity_threshold, takes this process's own resolved value, which the exit
    code is computed with (config/recorded_config.py).

    This process loads the operator's own configuration, as the inner scan did,
    so it uses that value rather than refuse; read with the field's default, the
    exit code could differ from a local scan's. It loads it as a run does
    (load_config_file_for_run), so a value its file read from the environment is
    recorded as the reference, as ``ash merge`` and ``--use-existing`` record
    theirs.

    When the selected file's model refuses to load here and the image's ASH may
    hold another schema, the values come from the operator's base configuration
    instead, and a warning says so.

    *image_may_differ* is the answer the pre-run gate already holds
    (:func:`_image_schema_may_differ`); None asks for itself. Asking names the
    image's source in the log, and this runs after the run's own output, so a
    caller that has the answer hands it over by keyword.
    """
    from automated_security_helper.config.recorded_config import (
        take_own_values,
        unreadable_references,
    )
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    record = getattr(results, "ash_config", None)
    if record is None or not unreadable_references(record):
        return
    own = _load_config_file(opts, for_run=True)
    if not own:
        try:
            selected = _selected_config_path(opts) is not None
        except Exception:
            selected = False
        if image_may_differ is None:
            image_may_differ = selected and _image_schema_may_differ(opts)
        if selected and image_may_differ:
            ASH_LOGGER.warning(
                "The record's environment-read fields were repaired from the "
                "operator's base configuration, because the selected config "
                "file loads only under the image's own revision."
            )
        own = _operator_default_config(opts)
    overrides = list(getattr(opts, "config_overrides", None) or [])
    if overrides:
        try:
            own = apply_config_overrides(own, overrides)
        except ASHConfigValidationError:
            # This apply only feeds the record-value repair below; an override
            # that does not apply to the operator's own file (it can refuse
            # here even when the scan's own apply accepted it, when a section
            # exists only in this file) fails the whole apply, so the repair
            # reads the file's values without every override. The scan's
            # behavior took the overrides through its own apply, which raises.
            pass
    take_own_values(record, own)


def _operator_default_config(opts: ScanOptions):
    """get_default_config() loaded as a scan of *opts* loads it: with ASH_CONFIG's
    files inside the scanned tree tolerated the way the scan's own load
    tolerates them (default_config_for_tree), so the record repair above does
    not refuse a file the scan itself reads past."""
    from automated_security_helper.config.default_config import (
        default_config_for_tree,
    )

    return default_config_for_tree(Path(opts.source_dir))


def _selected_config_path(opts: ScanOptions) -> Optional[str]:
    """The config file a scan of *opts* selects, as a path: ``--config``, or
    discovery's find under the scan's ``config_base_gate``, or None. A discovery
    error is left to the scan, which reports it with its own message (the rule
    :func:`_loaded_config_file` already follows; extracted so the
    parse-and-confine judgment selects the same file the load would). Each
    call discovers again when ``--config`` is not given, so the pre-run gate
    asks once and hands the answer to its loads and refusals."""
    if opts.config is not None:
        return opts.config
    try:
        return _discovered_config_path(opts.source_dir, permit=opts.config_base_gate)
    except Exception:
        return None


def _host_resolved_config(opts: ScanOptions) -> Tuple["AshConfig", bool]:
    """The config a scan of *opts* resolves, read on the host, and whether a file gave it.

    The one read behind the host's config refusal in container and nix mode and
    the exit-code fields every mode reads before the scan, so they all see the
    config the scan resolves, by a local scan's rule: ``--config`` (in container
    mode, also the file ``ASH_CONFIG`` names when run_ash_scan passes it on),
    else the file discovery selects under ``config_base_gate``, else the file
    ``ASH_CONFIG`` names, else the defaults. Each file is loaded by
    ``resolve_config.load_config_file`` (against the confinement root resolution
    would use, for the first two), and ``--config-overrides`` are applied as
    resolution applies them (``resolve_config.apply_config_overrides``). Not
    logged: the resolution that refuses a file logs it once.

    The file ``ASH_CONFIG`` names is loaded first, whichever file supplies the
    config, as a local scan loads it (``default_config.get_default_config``,
    before ``resolve_config`` reads the named file): it is the base the settings
    a repository-written config may not choose come from, so a file there that
    does not load is refused with a valid ``--config`` as well, with its own
    error.

    Returns:
        The config, and False when no config file supplied it (the defaults).

    Raises:
        ASHConfigValidationError: The file, or discovery, or an override is one
            resolution refuses (exit 3), or the scanned directory cannot be
            searched for the checkouts that confine a file.
    """
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.default_config import _ash_config_file
    from automated_security_helper.config.operator_only_options import (
        repository_settings_for_root,
    )
    from automated_security_helper.config.operator_paths import (
        not_delivered_by_a_client,
    )
    from automated_security_helper.config.resolve_config import (
        _load_single_config_file,
        apply_config_overrides,
    )

    env_config_path = _ash_config_file()
    # As default_config.get_default_config loads it.
    env_config = (
        _load_single_config_file(
            env_config_path,
            log_failure=False,
            anchor_relative_paths=not_delivered_by_a_client,
        )
        if env_config_path is not None
        else None
    )
    config_path = _scan_config_path(opts)
    if config_path is not None:
        # As the scan loads the file: what a file inside the scanned tree, or
        # inside any other checkout, writes for an option only the operator sets
        # is left out first (_loaded_config_file), so a value the option refuses,
        # which the scan ignores, does not hide the file's exit-code fields. The
        # checkout walk is part of the load, so a walk that fails is a load that
        # failed, and the readers answer None. The host's config refusal catches
        # only the refusals a load raises, so the walk's failure is raised as one.
        try:
            settings = repository_settings_for_root(Path(opts.source_dir))
        except OSError as exc:
            raise ASHConfigValidationError(
                f"The directory {opts.source_dir} could not be searched for the "
                f"git checkouts that decide whose config files these are: {exc}"
            ) from None
        config = _load_with_confinement(
            config_path,
            opts.source_dir,
            opts.config_base_gate,
            log_failure=False,
            remote_client=opts.remote_client,
            session_id=getattr(opts.client_config_policy, "session_id", None),
            confine=settings.confine,
            repository_file=settings.is_repository_file,
        )
        from_file = True
    elif env_config is not None:
        config = env_config
        from_file = True
    else:
        config = AshConfig()
        from_file = False
    return apply_config_overrides(config, list(opts.config_overrides or [])), from_file


def _load_config_file(opts: ScanOptions, for_run: bool = False):
    """The config file a scan of *opts* would use, overrides applied, or None.

    None when no config file supplies the config (the defaults), and also when it
    cannot be resolved. That is not a fallback: such a config is refused with exit
    3 before any scanner runs -- by the orchestrator's resolve_config in local
    mode, and in container and nix mode by run_ash_scan on the host before
    anything starts (:func:`_outer_mode_config_load`) -- so a value read here
    is never used for a scan. Refusing here as well would only duplicate that
    message.

    With *for_run*, the selected file is loaded as a run's configuration is
    (:func:`_load_for_run_with_confinement`, through :func:`_loaded_config_file`),
    knowing the references its files wrote; overrides are not applied on that
    path, which feeds the record repair alone.
    """
    if for_run:
        try:
            return _loaded_config_file(opts, for_run=True)
        except Exception:
            return None
    try:
        config, from_file = _host_resolved_config(opts)
    except Exception:
        return None
    return config if from_file else None


def _host_config_value(opts: ScanOptions, name: str) -> Any:
    """Top-level field *name* of the config a scan of *opts* resolves, or None if unset.

    Set means a config file supplies the config, or a ``--config-overrides``
    entry names the field; with neither, the field is the default, and None lets
    the caller tell that from a value someone chose.
    """
    try:
        config, from_file = _host_resolved_config(opts)
    except Exception:
        return None
    overridden = {
        override.partition("=")[0].removesuffix("+").strip().replace("-", "_")
        for override in opts.config_overrides or []
    }
    if from_file or name in overridden:
        return getattr(config, name, None)
    return None


def _print_invalid_config(error: Exception) -> None:
    """The message a scan prints for a config it refuses with exit 3, in every run mode.

    The text is ``error_text``'s, as :func:`_printed_config_refusal` prints the
    same class of error: a pydantic ValidationError in the chain is described
    without its input, so a value the file held is not repeated on the console.
    """
    print(
        f"[bold red]ERROR (3) Invalid configuration: "
        f"{escape_markup(error_text(error))}[/bold red]"
    )


def _outer_mode_config_refusal(
    opts: ScanOptions,
) -> Optional[ASHConfigValidationError]:
    """Why the scan inside the image or Nix shell would refuse its config, or None.

    Container and nix mode hand the config to a second ASH, which refuses a file
    that does not load with exit 3, but only once the image is built and started,
    or the shell entered, and the previous run's output cleared. So the host
    resolves it first, as a local scan of the same directory would
    (:func:`_host_resolved_config`): a file that is missing, not a regular file,
    unreadable, not UTF-8, not valid YAML, JSON or TOML (YAML aliases included),
    or not a valid config, a discovered name that is a link to nothing, and an
    override that does not parse or leaves a value the config model refuses are
    refused with the error a local scan reports. That holds for the file
    ``ASH_CONFIG`` names too, with a ``--config`` or without one. Options of a plugin are not
    judged here: they are validated against the plugin, which may be installed
    only in the image.
    """
    try:
        _host_resolved_config(opts)
    except ASHConfigValidationError as exc:
        return exc
    return None


def _parse_and_confine_config(
    config_path_str: str, opts: ScanOptions
) -> "ResolvedConfigDocument":
    """Judge of *config_path_str* only what holds for every ASH revision: that
    it parses, and that its ``extends`` chain stays confined to its root.

    The caller builds the model from the resolved document and words its
    refusal itself, unless the image is built with an ASH from another
    revision (:func:`_image_ash_revision_differs`); here the document is
    resolved without building the model, so only in that skewed build is a
    field this revision does not declare left to the scan inside, whose own
    apply refuses what its model refuses.
    A chain or confinement error raises ``ASHConfigSourceError`` (an
    ``ASHConfigValidationError``) as the scan's own load would; a file that
    does not parse raises the same refusal a local scan words for it. Returns
    the resolved document.
    """
    from automated_security_helper.config.config_sources import (
        default_confinement_root,
        is_config_parse_error,
        resolve_config_document,
        unparsed_config_reason,
    )
    from automated_security_helper.config.operator_only_options import (
        repository_settings_for_root,
    )

    config_path = Path(config_path_str)
    settings = repository_settings_for_root(Path(opts.source_dir))
    try:
        return resolve_config_document(
            config_path,
            confine_to=default_confinement_root(config_path, Path(opts.source_dir)),
            permit_base=opts.config_base_gate,
            confine=settings.confine,
            repository_file=settings.is_repository_file,
        )
    except ASHConfigValidationError:
        raise
    except Exception as e:  # noqa: BLE001 - only a parse error is reworded
        if not is_config_parse_error(e):
            raise
        refused = ASHConfigValidationError(unparsed_config_reason(config_path, e))
        refused.ash_config_file = config_path
        raise refused from None


#: Marks "select the file here" for :func:`_loaded_config_file`'s
#: *selected_path*, as None is a real answer there (the caller selected no file).
_SELECT_HERE: Any = object()


def _loaded_config_file(
    opts: ScanOptions, for_run: bool = False, *, selected_path: Any = _SELECT_HERE
):
    """The config file a scan of *opts* selects, loaded as the scan loads it, or
    None when there is none.

    The raising half of :func:`_load_config_file`: a file that does not load as
    the scan would load it raises, an ``ASHConfigValidationError`` for
    everything the scan refuses with exit 3 (:func:`_outer_mode_config_load`
    turns that into the host's own refusal). A discovery error is still left to
    the scan, which reports it with its own message.

    *selected_path* is what a caller has already selected
    (:func:`_selected_config_path`); with it the file is not discovered again,
    so the load reads the file the caller judged, which a second discovery
    could answer differently if the directory changed between the two. None
    is an answer: the caller selected no file, so nothing is loaded and
    nothing is discovered. Left out, this selects here.

    Read as resolve_config reads the scan's config file: what a file inside the
    scanned tree or inside any other checkout writes for an option only the
    operator sets is left out first
    (``operator_only_options.scan_repository_settings``), so a value there the
    option refuses, which the scan ignores, does not hide the file's other
    fields.
    """
    from automated_security_helper.config.operator_only_options import (
        repository_settings_for_root,
    )

    config_path_str: Optional[str] = (
        _selected_config_path(opts) if selected_path is _SELECT_HERE else selected_path
    )
    if config_path_str is None:
        return None

    # With the load: the checkout walk is part of loading the file as a scan
    # loads it, so a walk that fails is a load that failed -- and with no
    # config file to read, no walk runs at all.
    settings = repository_settings_for_root(Path(opts.source_dir))
    if for_run:
        return _load_for_run_with_confinement(
            config_path_str,
            opts.source_dir,
            opts.config_base_gate,
            settings.confine,
            settings.is_repository_file,
            remote_client=opts.remote_client,
            session_id=getattr(opts.client_config_policy, "session_id", None),
        )
    return _load_with_confinement(
        config_path_str,
        opts.source_dir,
        opts.config_base_gate,
        remote_client=opts.remote_client,
        session_id=getattr(opts.client_config_policy, "session_id", None),
        confine=settings.confine,
        repository_file=settings.is_repository_file,
    )


def _model_of_resolved_document(document):
    """The ``AshConfig`` a scan builds from *document*, or None when the model
    refuses it.

    The model half of ``resolve_config.load_config_file`` (``build_config``
    with no overrides, which is what :func:`_load_config_file` reaches through
    the load), run on a document already resolved, so a caller
    that parsed the file builds its model from that read and does not read the
    file again. Refusals are swallowed as :func:`_load_config_file` swallows
    them: the scan inside words them.
    """
    from automated_security_helper.config.resolve_config import build_config

    try:
        return build_config(document.data)
    except Exception:
        return None


def _model_or_refusal_of_resolved_document(
    document: Any, config_path_str: str, opts: ScanOptions
) -> "Tuple[Any, Optional[ASHConfigValidationError]]":
    """(model, refusal): the ``AshConfig`` a scan builds from *document*, or
    the worded model refusal when the model refuses it.

    The raising twin of :func:`_model_of_resolved_document`, for the pre-run
    gate, which has to tell a model refusal from any other failure: the model
    is built from the already-resolved document (``resolve_config.
    build_config``, the model half of ``load_config_file``), and a refusal is
    worded as that load words it (``ConfigFileRefused``, the same message
    shape), without reading the file or its chain again. A failure that is
    not the model refusing the document is swallowed as
    :func:`_model_of_resolved_document` swallows it: (None, None), the scan
    inside words it.
    """
    from pydantic import ValidationError

    from automated_security_helper.config.config_sources import describe_config_path
    from automated_security_helper.config.config_validator import (
        describe_validation_error,
    )
    from automated_security_helper.config.resolve_config import (
        ConfigFileRefused,
        build_config,
        lint_hint,
    )

    try:
        return build_config(document.data), None
    except ValidationError as e:
        # The wording of resolve_config.load_config_file's file refusal, from
        # the same pieces, so the gate's refusal and a local scan's read alike.
        described = describe_validation_error(e, document.environment_values)
        return None, ConfigFileRefused(
            f"Configuration validation failed for "
            f"'{describe_config_path(Path(config_path_str))}': "
            f"{described.rstrip('.')}. "
            f"{lint_hint(config_path_str, opts.source_dir)}",
            document=document,
            validation_error=e,
            after_overrides=False,
        )
    except Exception:
        return None, None


#: Marks "no config was handed in" for the two exit-code readers below, as None
#: is a real answer (the scan selects no file).
_NOT_LOADED: Any = object()


_EXIT_FIELDS = ("fail_on_findings", "fail_on_incomplete_scanners")


def _exit_field_as_the_model_reads_it(name: str, value: Any) -> Optional[bool]:
    """*value* as ``AshConfig`` reads its field *name* from a config file, or
    None when the model refuses it.

    A config file is validated strictly (``resolve_config.build_config``), so
    the text ``"no"`` and the number ``0`` are not a False there: the model
    refuses the file. Reading the value through the field's own annotation
    with the constraints pydantic moved into the field's metadata, strictly,
    keeps this fallback and the model agreeing about what a value means,
    whatever type the field comes to hold. A lax read would take ``"no"`` as
    False and turn off an exit code the image's own ASH refuses the file over.
    The model's field validators are not applied here; a cell fails when one
    is added to either field.

    A *name* the model does not declare (a field renamed or removed while
    ``_EXIT_FIELDS`` still lists it) is refused as well, and reads as None
    like any other refused value. None means the file sets nothing for the
    field, so the run falls back on the model's own default, which is True
    for both exit fields (``AshConfig.fail_on_findings`` and
    ``AshConfig.fail_on_incomplete_scanners``): the run is still gated on
    findings and on incomplete scanners, as a run with no such setting is.
    """
    from pydantic import TypeAdapter, ValidationError

    from automated_security_helper.config.ash_config import AshConfig

    field = AshConfig.model_fields.get(name)
    if field is None:
        return None
    # rebuild_annotation puts the metadata back as Annotated[annotation, ...].
    annotation = field.rebuild_annotation()
    try:
        return TypeAdapter(annotation).validate_python(value, strict=True)
    except ValidationError:
        return None


def _load_config_file_or_its_exit_fields(
    opts: ScanOptions,
    *,
    document: Any = _NOT_LOADED,
    image_may_differ: Optional[bool] = None,
    model: Any = _NOT_LOADED,
):
    """:func:`_load_config_file`'s config; when this tree's model does not load
    the selected file and the image's ASH may hold another schema
    (:func:`_image_schema_may_differ`), an object holding the exit-code
    fields the file's resolved document writes as booleans.

    Each field is read the way the model reads a config file's
    (:func:`_exit_field_as_the_model_reads_it`), so a value the model refuses
    is unset here too. With no config file selected there is nothing to read,
    and the image-schema question is not asked at all. Only a container scan
    has an image whose schema can differ, so any other mode answers None
    before the file is selected again.

    The pre-run gate has already resolved the selected file's document, tried
    to load it as this tree's model, and asked about the image; a caller that
    holds those answers hands them in as *document* (None when the scan
    selects no file), *model* (None when the model did not load the file) and
    *image_may_differ*, and none of them is repeated here, so the document the
    gate judged and the model this returns come from the same read. A caller
    that hands in the *document* alone gets the model built from it, so the
    file and its ``extends`` chain are not read a second time and the
    exit-code fields come from a document and a model that are one version of
    the file. Without them this reads for itself.
    """
    if model is not _NOT_LOADED:
        loaded = model
    elif document is _NOT_LOADED:
        loaded = _load_config_file(opts)
    elif document is None:
        loaded = None
    else:
        loaded = _model_of_resolved_document(document)
    if loaded is not None:
        return loaded
    if opts.mode != RunMode.container:
        return None
    path: Optional[str] = None
    if document is _NOT_LOADED:
        try:
            path = _selected_config_path(opts)
        except Exception:
            return None
        if path is None:
            return None
    elif document is None:
        return None
    # The image's revision is asked about only for a run that has a selected
    # file this tree's model did not load (it refused it, or the load failed
    # some other way): asking it logs which source the image is built from,
    # which a run with no config has no reason to say.
    if image_may_differ is None:
        image_may_differ = _image_schema_may_differ(opts)
    if not image_may_differ:
        return None
    from collections.abc import Mapping
    from types import SimpleNamespace

    if path is not None:
        # No document was handed in: this read resolves the file itself.
        try:
            document = _parse_and_confine_config(path, opts)
        except Exception:
            return None
    data = document.data
    if not isinstance(data, Mapping):
        return None
    fields = {}
    for name in _EXIT_FIELDS:
        if name in data:
            value = _exit_field_as_the_model_reads_it(name, data[name])
            if value is not None:
                fields[name] = value
    return SimpleNamespace(**fields)


def _resolve_config_fail_on_findings(
    opts: ScanOptions, *, loaded: Any = _NOT_LOADED
) -> Optional[bool]:
    """fail_on_findings of the config the scan resolves, without the orchestrator.

    Read as :func:`_host_config_value` reads it, so container mode forwards, and
    nix mode decides the exit code from, the value the scan's own config and
    ``--config-overrides`` give. None when neither sets it. *loaded* is the file
    the caller already loaded for these *opts* (the pre-run gate's own load, or
    one load serving both exit-code fields); with it, the field is read off that
    object instead of loading again. *loaded* is keyword-only: ``None`` is a
    loaded answer (the scan selects no file), so a caller handing some other
    second argument positionally must fail loudly instead of reading it as
    "loaded, nothing" and silently ignoring the YAML override.
    """
    if loaded is not _NOT_LOADED:
        return getattr(loaded, "fail_on_findings", None)
    return _host_config_value(opts, "fail_on_findings")


def _resolve_config_fail_on_incomplete_scanners(
    opts: ScanOptions, *, loaded: Any = _NOT_LOADED
) -> Optional[bool]:
    """Read fail_on_incomplete_scanners from the YAML config file.

    The sibling of :func:`_resolve_config_fail_on_findings`, and needed for the
    same reason: container mode has to know the value before it builds the
    container's command line, so it cannot wait for the orchestrator to resolve
    the config. Returns None when no config file or override sets it, which the
    caller distinguishes from a value of False. *loaded* is as for
    :func:`_resolve_config_fail_on_findings`.
    """
    if loaded is not _NOT_LOADED:
        return getattr(loaded, "fail_on_incomplete_scanners", None)
    return _host_config_value(opts, "fail_on_incomplete_scanners")


def _image_schema_may_differ(opts: ScanOptions) -> bool:
    """Whether the run's container image can hold an ASH whose config schema
    differs from this one's.

    False only when the image is built from this source tree: a build (not
    ``--no-build``, no custom Containerfile) whose revision is ``LOCAL`` --
    given as ``--ash-revision-to-install LOCAL``, as the repository's CI
    container legs give it, or derived by
    ``run_ash_container.get_ash_revision`` for an ASH running from a checkout,
    an editable install or a local file install. Every other revision is a
    clone of the repository: a pinned commit, a branch, or the latest-revision
    fallback a PyPI install without ``vcs_info`` resolves to, none of which
    this process verifies against its own code. Never true outside container
    mode: nix mode re-executes this checkout's own ASH.
    """
    if opts.mode != RunMode.container:
        return False
    if not opts.build or opts.custom_containerfile:
        # "Unverifiable", not "known to differ": an image already present or
        # built from a Containerfile this process did not write says nothing
        # about its ASH until it is inspected, and no revision is read for it
        # (there is none to name). What the answer changes at the gate is what
        # is left to the scan inside: the overrides, and the base's model. A
        # selected file's model refusal stays the host's in these two states
        # (_outer_mode_config_load, ``skewed``), because this process still
        # reads that file for its own decisions.
        return True
    return _image_ash_revision_differs(opts)


def _image_ash_revision_differs(opts: ScanOptions) -> bool:
    """Whether the run builds its image with an ASH from another revision.

    The narrow cause of :func:`_image_schema_may_differ`: a build (not
    ``--no-build``, no custom Containerfile) whose revision is not ``LOCAL``
    installs a clone of the repository -- a pinned commit, a branch, or the
    latest-revision fallback a PyPI install without ``vcs_info`` resolves to
    -- whose config schema this process cannot check against its own code. An
    image this process does not build (``--no-build``, a custom
    Containerfile) is just as unverifiable, but choosing not to build changes
    nothing about what this process itself reads the config for, so it is not
    this predicate. Reads the revision the same way the broad predicate's
    tail did: the named ``--ash-revision-to-install``, or
    ``run_ash_container.get_ash_revision`` for an ASH running from a
    checkout, an editable install or a local file install.
    """
    if opts.mode != RunMode.container:
        return False
    if not opts.build or opts.custom_containerfile:
        return False
    from automated_security_helper.interactions.run_ash_container import (
        get_ash_revision,
    )

    revision = (
        opts.ash_revision_to_install
        if opts.ash_revision_to_install is not None
        else get_ash_revision()
    )
    return revision != "LOCAL"


def _gate_has_a_schema_to_judge(
    opts: ScanOptions, selected_path: Optional[str]
) -> bool:
    """Whether the pre-run gate reads anything it would judge against this
    tree's config schema, so that the image's revision has to be asked about.

    Three inputs reach this tree's model at the gate: the config file the scan
    selects (*selected_path*), the file ``ASH_CONFIG`` names as the base, and
    ``--config-overrides``, whose apply refuses a key this tree's model does
    not declare. With none of them the gate judges only the defaults, so no
    schema's skew can matter and the question, which reads the image's
    revision and logs where the image's ASH comes from, is not asked. With any
    of them it is asked: when the image may hold another schema the base and
    the overrides' keys this tree does not declare are left to the scan inside,
    as a selected file's model refusal is for an image built from another
    revision.
    """
    return (
        selected_path is not None
        or bool(opts.config_overrides)
        or bool(os.environ.get("ASH_CONFIG"))
    )


class _OuterModeConfigLoad(NamedTuple):
    """What :func:`_outer_mode_config_load` read: the refusal, if any, and the
    file the scan selects.

    ``selected`` is meaningful only when ``loaded`` is true: the load ran to the
    end, so ``selected`` is the exit-code fields of the file, or None when the
    scan selects no file. They are read as soon as the load returns and again
    from the model the overrides produce when the apply succeeds, so a
    ``--config-overrides`` value for either field decides the exit code in
    container and nix mode as in a local scan. A failed apply leaves the file's
    own values. A load that failed some other way leaves ``loaded`` false, and
    a reader then loads for itself, as it did before this was shared.

    The image-schema branch parses the file and builds this tree's model from
    that same parsed document, judging only the parse and the overrides. What it
    learned there rides along so the exit-code read repeats none of it:
    ``document`` is the
    resolved document of the selected file (None when the scan selects none;
    ``_NOT_LOADED`` when the gate did not get that far), ``model`` is what
    loading the selected file as this tree's model gave (None when the model
    did not load it; ``_NOT_LOADED`` when the gate did not get that far), and
    ``image_may_differ`` is the answer to :func:`_image_schema_may_differ`
    (False when the gate has no schema to judge, which it does not ask the
    question for: no config file selected, no ``ASH_CONFIG`` and no
    ``--config-overrides``; None when the gate never got that far, a question
    that raised included: no answer is not "same schema"). Then a key only
    the image's schema may declare is the image's to judge, and the readers
    report the file's values: the model's when it loaded, the document's
    otherwise. When the model loaded the file and the overrides applied to it,
    ``selected`` holds the applied model's exit-code fields and ``loaded`` is
    true, so the readers take those and the overrides decide the exit code.
    """

    refusal: Optional[ASHConfigValidationError]
    selected: Any
    loaded: bool
    document: Any = _NOT_LOADED
    image_may_differ: Optional[bool] = None
    model: Any = _NOT_LOADED


def _refuse_a_named_config_that_is_not_a_file(config: str) -> None:
    """Raise the refusal for a ``--config`` path that is not a regular file.

    The one place that words it, for the local scan and for the nix gate
    (:func:`_unusable_nix_config`): a name that does not exist, a symbolic link
    loop, a path whose stat is denied, and one that exists and is not a file (a
    directory, a FIFO) are each named for what they are, and in ASH_CONFIG's
    words when ASH_CONFIG gave ``--config`` its value.

    One stat, which both answers whether the named path is a file and
    classifies it when it is not (utils/path_stat.py): before Python 3.14
    ``is_file()`` raises what stat raises for a path it cannot classify (EACCES
    under an unsearchable directory), and a second stat could answer
    differently from the first. Returns when the path is a regular file.
    """
    from automated_security_helper.utils.path_stat import (
        LOOP,
        UNREADABLE,
        StatProblem,
        is_regular_file,
        stat_named_path,
    )

    named_config = stat_named_path(config)
    if is_regular_file(named_config):
        return
    ash_config = os.environ.get("ASH_CONFIG")
    if ash_config is not None and config == ash_config:
        # ASH_CONFIG gave --config its value: refused in the words for
        # ASH_CONFIG, for a name that does not exist and for one that exists
        # and is not a file (a directory, a FIFO), which "not found" below
        # misnamed. Classified by this pre-check's own stat:
        # get_default_config stats the path again, and that second answer named
        # a denied or looping path, or a directory, as missing.
        from automated_security_helper.config.default_config import (
            refuse_unless_ash_config_names_a_file,
        )

        refuse_unless_ash_config_names_a_file(ash_config, named_config)
    # The same classification the loader gives a named path: a symbolic link
    # loop or a denied stat is not a missing file, and "not found" misnamed it.
    # Keys only: the errno's code and the caller's own path text.
    if isinstance(named_config, StatProblem):
        if named_config.kind == LOOP:
            raise ASHConfigValidationError(
                f"Config file is a symbolic link loop: {Path(config).as_posix()}"
            ) from named_config.cause()
        if named_config.kind == UNREADABLE:
            raise ASHConfigValidationError(
                f"Config file cannot be read ({named_config.code}): "
                f"{Path(config).as_posix()}"
            ) from named_config.cause()
        # MISSING, the one kind left.
        raise ASHConfigValidationError(
            f"Configuration file not found: {Path(config).as_posix()}"
        )
    # The path exists and is not a regular file (a directory, a FIFO, a
    # device): named for what it is, in the words every other reader of a
    # config path uses, and not called missing.
    from automated_security_helper.config.config_sources import (
        not_a_regular_file_refusal,
    )

    raise not_a_regular_file_refusal(Path(config))


def _names_the_same_file(first: str, second: str) -> bool:
    """Whether two paths name one file, however each is spelled.

    By identity (``os.path.samefile``) when both can be read, so a link, a
    ``..`` segment or a relative spelling of the file ``ASH_CONFIG`` names still
    counts as that file; by text when either cannot be, which is what the
    comparison was before and all that is left to compare.
    """
    try:
        return os.path.samefile(first, second)
    except OSError:
        return Path(first) == Path(second)


def _selected_config_is_a_link_loop(selected: Optional[str]) -> bool:
    """Whether the config file a scan selects (*selected*, as
    :func:`_selected_config_path` answered) is a symbolic link loop, by one
    stat (utils/path_stat.py), the classification
    :func:`_refuse_a_named_config_that_is_not_a_file` words."""
    from automated_security_helper.utils.path_stat import (
        LOOP,
        StatProblem,
        stat_named_path,
    )

    if selected is None:
        return False
    answer = stat_named_path(selected)
    return isinstance(answer, StatProblem) and answer.kind == LOOP


def _discovered_config_refusal(
    selected: str, error: OSError
) -> ASHConfigValidationError:
    """The refusal for a DISCOVERED config file whose read raised *error*.

    The pre-run gate defers the OSError of a named file to the checks that own
    ``--config`` (container mode's handover check, nix mode's
    :func:`_unusable_nix_config`). Neither judges a file discovery selected, so
    a discovered ``.ash.yaml`` that cannot be read passed the gate: the previous
    run's output was cleared and the shell or container started before the scan
    inside refused it, and the scan inside a container, running as root, read
    it. Worded as a local scan words the same read of the same file
    (``resolve_config``'s handler for an OSError the load raises): the file as
    the scan named it, then the error without its own copy of that name.
    """
    from automated_security_helper.config.config_sources import describe_config_path
    from automated_security_helper.utils.error_text import os_error_without_named_file

    path = Path(selected)
    refusal = ASHConfigValidationError(
        f"could not read {describe_config_path(path)}: "
        f"{os_error_without_named_file(error, path)}"
    )
    refusal.ash_config_file = path
    return refusal


def _names_the_failed_file(error: OSError, selected: str) -> bool:
    """Whether *error*'s own filename is *selected*, the config file the gate's
    load was reading: the OSError the open of that file raised names it, while
    one the checkout walk or another read raised names some other path or none,
    and is not the config file's to word. The two are compared as
    :func:`_names_the_same_file` compares them, so a relative spelling, a link
    or another prefix of the same file still counts as that file."""
    filename = error.filename
    if not isinstance(filename, (str, bytes, os.PathLike)):
        return False
    try:
        return _names_the_same_file(os.fsdecode(filename), selected)
    except TypeError:
        return False


def _unusable_nix_config(opts: ScanOptions) -> Optional[ASHConfigValidationError]:
    """The refusal for a ``--config`` that names no file the shell's ASH can read.

    Container mode has its own owner for this shape (``container_input_refusal``,
    run by the caller for container only), so nothing here changes what it
    does. Nix mode had none: the load raises the OSError a missing file raises,
    which the gate defers, and ``_run_nix_mode`` then cleared the previous
    run's output before the scan inside refused the file. The path is
    classified as a local scan classifies it
    (:func:`_refuse_a_named_config_that_is_not_a_file`), by one stat that does
    not raise, so no error comes out of the handler that calls this.
    """
    if opts.mode != RunMode.nix or opts.config is None:
        return None
    try:
        _refuse_a_named_config_that_is_not_a_file(opts.config)
    except ASHConfigValidationError as refused:
        return refused
    if not os.access(opts.config, os.R_OK):
        return ASHConfigValidationError(
            f"Config file cannot be read: {opts.config}. The scan inside the "
            "shell reads it with this process's rights."
        )
    return None


def _exit_fields_of(selected: Any) -> Any:
    """The exit-code fields of a loaded config, as a plain object the later
    apply of ``config_overrides`` cannot change, or None when there is none.

    The readers take any object that holds the fields (the image-schema
    fallback already hands them a namespace), so a snapshot stands in for the
    model they would otherwise share.
    """
    from types import SimpleNamespace

    if selected is None:
        return None
    return SimpleNamespace(
        **{name: getattr(selected, name, None) for name in _EXIT_FIELDS}
    )


def _refuse_overrides_that_every_revision_refuses(
    opts: ScanOptions,
    model: Any,
    *,
    another_revision: bool = False,
    file_refused: bool = False,
) -> Any:
    """Raise the refusal a local scan gives the ``--config-overrides`` of *opts*
    when no ASH revision would apply them, and stay silent about what only
    another schema can judge. Returns the model the overrides produce, or None
    when there is none to use.

    For an image that may hold another schema
    (:func:`_image_schema_may_differ`) the overrides are the scan inside's to
    judge, which refuses them only after the image is built and started and the
    previous output is cleared. What every revision refuses is the host's, and
    is judged here against *model*, this tree's model of the selected file (the
    defaults when no file is selected or the file only another schema loads):
    an override that does not parse (no ``=``, an empty or spaced part of the
    key) and one the apply cannot make. Refused in a local scan's words, with
    exit 3. Both leave an error with no ``validation_error``, which no schema
    would judge differently.

    What the model's validation refuses after the apply (``validation_error``)
    is a judgment of this tree's schema, and whose answer it is depends on the
    image:

    - A refusal whose every error names a key this tree's model does not
      declare (:func:`error_names_an_undeclared_key`) is waived in every case:
      an image from another revision may declare the key.
    - Any other validation error is a value this tree's model refuses
      (``fail_on_findings=maybe``, ``global_settings=7``). It is refused for a
      run that builds no image or builds from a custom Containerfile, as the
      selected file's own refusal is, and waived when *another_revision* is
      true: the image installs an ASH whose schema this process cannot read,
      and may accept the value. The same split the gate makes for the selected
      file.
    - When *file_refused* is true this tree's model refused the selected file,
      so *model* is None and the overrides were applied to the defaults while
      the image applies them to the file. A validation error then says nothing
      about the file (an append to a list only the file holds, a cross-field
      check the file satisfies), so it is waived too.

    Where values are refused, one refusal that holds an unknown key and a wrong
    value stands whole only when the two sit in different sections. A section
    validates its keys before its fields (``mode="before"`` validators), so a
    wrong value beside an unknown key in the same section does not appear in the
    refusal: only the unknown-key error does, and the waiver applies to it. The
    scan inside then refuses the value if its schema does not accept it.

    The apply is given a copy of *model*: the gate hands that model on to the
    exit-code readers, which must not see anything an apply did to it. The
    returned model is the copy with the overrides applied, for the exit-code
    fields; it is None when there are no overrides and when a validation error
    was waived, so the file's own values stay the answer then.
    """
    overrides = list(opts.config_overrides or [])
    if not overrides:
        return None
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )
    from automated_security_helper.utils.unknown_keys import (
        error_names_an_undeclared_key,
    )

    base = model.model_copy(deep=True) if model is not None else AshConfig()
    try:
        return apply_config_overrides(base, overrides)
    except ASHConfigValidationError as refused:
        described = getattr(refused, "validation_error", None)
        if described is not None:
            try:
                errors = described.errors()
            except Exception:  # noqa: BLE001 - not a pydantic error: it stands
                errors = []
            if errors and (
                another_revision
                or file_refused
                or all(error_names_an_undeclared_key(e) for e in errors)
            ):
                return None
        raise


def _outer_mode_config_load(opts: ScanOptions) -> _OuterModeConfigLoad:
    """Why the scan inside the image or Nix shell would refuse its config, or
    None, and the exit-code fields of the file it loaded.

    Container and nix mode hand the config to a second ASH, which refuses a
    file that does not load with exit 3, but only once the image is built and
    started, or the shell entered, and the previous run's output cleared. So
    the host judges it first, as a local scan of the same directory would, and
    which refusals are this gate's depends on the image. An ``extends`` chain
    whose confinement a local scan refuses (a base outside the chain's root,
    reached plainly or through a link) is refused here on both branches. So
    is a file that is not UTF-8, is not valid YAML, JSON or TOML, or is
    nested past the interpreter's recursion limit: exit 3 in the words a
    local scan uses for it (``unparsed_config_reason``), naming the file that
    was being read, in every mode and before anything is built, started or
    cleared. The parse step (:func:`_parse_and_confine_config`) words the
    refusal when the image's schema may differ
    (:func:`_image_schema_may_differ`); when the image is built from this
    tree the load raises the parser's own error and this gate words it
    from the same reason. A file this tree's MODEL refuses is refused here
    too, unless the image is built with an ASH from another revision
    (:func:`_image_ash_revision_differs`): only that build installs a config
    schema this process cannot check against its own code, so there the model
    is the image's own ASH's to judge, which refuses what its model refuses
    with the same exit code. A run that does not build its image, or builds
    from a custom Containerfile, keeps the full refusal: the image is just as
    unverifiable, but this process still reads the config for its own
    decisions -- the sandbox floor and its reporting among them -- and an
    unverifiable image does not make those reads any sounder. The two
    predicates split there: :func:`_image_schema_may_differ` (the broad one)
    decides what the host can judge at all, and
    :func:`_image_ash_revision_differs` (its narrow cause) decides whose
    answer a model refusal is. A file given as ``--config`` that
    is MISSING or UNREADABLE raises an ``OSError`` the gate does not word
    itself (a file DISCOVERY selected is the one exception: no owner of that
    shape judges it, so the gate words it as a local scan does,
    :func:`_discovered_config_refusal`). It returns
    :func:`_unusable_nix_config`'s answer: in nix mode a
    refusal with exit 3 before the previous run's output is cleared, and in
    container mode none, because the handover check owns that shape and
    refuses a config it cannot hand over, with exit 3. The file ``ASH_CONFIG``
    names is judged with the scan's own tolerance for its in-tree files:
    ``default_config_for_tree`` when the image is built from this tree, its
    document-only form ``default_config_document_for_tree`` when the image's
    schema may differ. That document-only judgment holds when the same file
    is also the config the scan selects (a run with no config of its own
    names ASH_CONFIG's file as ``--config`` for the handover,
    :func:`_ash_config_fallback`): its model skew stays the scan inside's in
    every may-differ state. ``run_ash_container._host_ash_config`` only answers
    whether ``ASH_CONFIG`` names a file; the document is read by
    ``default_config_document_for_tree`` from the same variable.
    A set ``ASH_CONFIG`` naming a missing file is refused when the image is
    built from this tree; when the image's schema may differ, that read's
    refusal is left to the handover check, which refuses it with the same
    exit code. A file ``ASH_CONFIG`` names that exists but cannot be read is
    refused at this gate on both branches, because the environment's config
    is read here, not handed over unread.
    Only the LOAD is judged, never the scan's wider resolution: what a
    repository-written or marked file may not choose is settled or dropped by
    that same read, as the scan inside settles it, not refused here, and
    options of a plugin are validated against the plugin, which may be
    installed only in the image. When the image's ASH can hold a config schema
    this one does not declare (:func:`_image_schema_may_differ`),
    ``--config-overrides`` are judged only as far as every revision judges
    them (:func:`_refuse_overrides_that_every_revision_refuses`): an override
    that does not parse, or that the apply cannot make, is refused here. So is
    one that gives a field this tree declares a value of the wrong kind, unless
    the image is built with an ASH from another revision, which may accept the
    value: the file's model refusal is split the same way. This tree's apply
    also refuses a key its own model does not declare, which an inner ASH from
    another revision may declare, so that part is left to the scan inside,
    whose own apply refuses it with exit 3, as is any validation failure of an
    apply made to the defaults because this tree's model refused the selected
    file. That holds for a run that selects no config file as well.
    The question is asked whenever something is judged
    against this tree's schema (:func:`_gate_has_a_schema_to_judge`): the
    selected file, the base ``ASH_CONFIG`` names, or ``--config-overrides``.
    A run with none of the three judges only the defaults, and does not read
    the image's revision.

    What this thread logs while it loads is dropped, as the sandbox report
    drops it (``_DropThisThreadsRecords``): the loads log what they read as a
    local scan would, and that scan does not run here. The refusal itself is
    returned, for the caller to print once.

    The exit-code field readers load the same file with the same arguments, so
    the caller hands them ``selected`` instead of having each read the chain
    again. When the image's schema may differ the model is still built once,
    next to the parse; a refusal it raises is this gate's to word except in
    the another-revision build, and the result is returned as ``model``
    (None when the model refused) for the readers to take instead of loading
    the file a second time. ``selected`` carries the exit-code fields (see
    :func:`_exit_fields_of`), read from the file first, and from the model
    ``apply_config_overrides`` returns once the apply succeeds, so a
    ``--config-overrides`` value for either field is the one the exit code
    follows, as in a local scan. In the branch for an image that may differ
    this holds when this tree's model loaded the file; when it refused the
    file, or the overrides were left to the image, the file's own values stay
    the answer and an override of an exit-code field does not reach them. The
    input of the apply is never read after it: an apply that changed its input,
    or failed half way, must not change what the readers report.
    """
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    silence = _DropThisThreadsRecords()
    ASH_LOGGER.addFilter(silence)
    selected: Any = None
    loaded = False
    document: Any = _NOT_LOADED
    image_may_differ: Optional[bool] = None
    own_model: Any = _NOT_LOADED
    # Whose file the load under way reads: "base" is the file ASH_CONFIG
    # names, "selected" the config the scan selects. A parser's failure on
    # either is refused naming that file, and the two are different files.
    reading: Optional[str] = None
    # The config file the scan selects, discovered once: every read below, and
    # the words of a refusal about it, take this answer, not a second
    # discovery that the directory's changes could answer differently.
    selected_path: Optional[str] = None
    try:
        # The base first, as a local scan loads it (default_config.
        # get_default_config, before the named file is read): the file
        # ASH_CONFIG names is the source of the settings a repository-written
        # config may not choose, so one that does not load is refused with a
        # valid --config as well, with its own error.
        # The image question reads the image's revision and logs where its ASH
        # comes from, so it is asked only when something is judged against this
        # tree's schema (_gate_has_a_schema_to_judge): the selected file, the
        # base ASH_CONFIG names, or --config-overrides. A run with none of
        # them has no schema whose skew could matter. A run with any of them
        # asks, so overrides and a base this tree's model cannot check are
        # left to the scan inside when the image may hold another schema.
        # One assignment, so a question that raises leaves the answer None
        # ("no answer": the readers after the gate ask for themselves), not
        # False ("same schema", which they would trust).
        selected_path = _selected_config_path(opts)
        image_may_differ = (
            _image_schema_may_differ(opts)
            if _gate_has_a_schema_to_judge(opts, selected_path)
            else False
        )
        if image_may_differ:
            # Parse and confinement hold for every revision: which files the
            # chain names, and whether it stays in its root, is about what is
            # mounted, not about the model. The model is the image's to judge
            # only for an image built with an ASH from another revision, whose
            # schema may declare a field this revision does not; in every
            # other may-differ state the selected file's model refusal is
            # raised below.
            from automated_security_helper.config.default_config import (
                default_config_document_for_tree,
            )
            from automated_security_helper.interactions.run_ash_container import (
                _host_ash_config,
            )

            try:
                env_config = _host_ash_config()
            except ContainerInputError:
                env_config = None
            if env_config is not None:
                reading = "base"
                # Refuses an ASH_CONFIG file that does not load; its document
                # is not read further, and the exit fields come from the
                # selected file's document below.
                default_config_document_for_tree(Path(opts.source_dir))
            reading = "selected"
            # Kept, not dropped: the exit-code read takes this document.
            document = (
                None
                if selected_path is None
                else _parse_and_confine_config(selected_path, opts)
            )
            # The model is built from the document just parsed, so the
            # judgment above and the model come from one read of the file,
            # and the exit-code read takes the answer (None when the model
            # refuses the document) in place of loading the file again. A
            # model refusal of the selected file rides to the scan inside
            # only when the image is built with an ASH from another revision
            # (_image_ash_revision_differs); a run that does not build its
            # image, or builds from a custom Containerfile, keeps the full
            # refusal, because this process still reads the config for its
            # own decisions -- the sandbox floor and its reporting among
            # them -- and an unverifiable image does not make those reads
            # any sounder.
            own_model = None
            # The narrow predicate, without a second revision read: in this
            # branch the broad answer is already True, so
            # _image_ash_revision_differs reduces to the build test alone, and
            # the image's source stays named once per scan (calling the
            # predicate would ask get_ash_revision again). It decides whose
            # answer a refusal of this tree's model is, for the file below and
            # for the overrides after it.
            another_revision = bool(opts.build) and not opts.custom_containerfile
            if selected_path is not None and document is not None:
                own_model, refused = _model_or_refusal_of_resolved_document(
                    document, selected_path, opts
                )
                # The file ASH_CONFIG names keeps the base's document-only
                # judgment even when it is also the config the scan selects:
                # a scan with no config of its own names that file as
                # --config for the handover (_ash_config_fallback), and its
                # model skew is the scan inside's to judge in every
                # may-differ state, as it is when the same file is read as
                # the base alone.
                selected_is_the_env_config = (
                    env_config is not None
                    and _names_the_same_file(selected_path, env_config)
                )
                if refused is not None and not selected_is_the_env_config:
                    if not another_revision:
                        raise refused
            # The overrides last, as the other branch applies them after the
            # file: what every revision refuses (a part that does not parse, an
            # apply that cannot be made) is refused here, and so is a value
            # this tree's model refuses unless the image holds another
            # revision's ASH, as for the file above. A key only another schema
            # declares is left to the scan inside, and so is any failure of an
            # apply made to the defaults in place of a file this tree's model
            # refused: the image applies the overrides to that file.
            reading = None
            applied = _refuse_overrides_that_every_revision_refuses(
                opts,
                own_model,
                another_revision=another_revision,
                file_refused=selected_path is not None and own_model is None,
            )
            if applied is not None and own_model is not None:
                # The overrides decide the exit code as they do in a local
                # scan, and as the other branch takes them: the fields are the
                # applied model's, and the readers take them instead of the
                # file's. The host forwards what they read as a flag the scan
                # inside ranks above its own overrides, so the file's value
                # would win there. With no model of the file, or overrides left
                # to the image, the file's own values stay the answer.
                selected = _exit_fields_of(applied)
                loaded = True
        else:
            reading = "base"
            base = _operator_default_config(opts)
            reading = "selected"
            # The selection made above, None included: a gate that selected no
            # file loads none and does not discover a second time.
            model = _loaded_config_file(opts, selected_path=selected_path)
            reading = None
            # The file's own values; a successful apply replaces them below.
            selected = _exit_fields_of(model)
            # This branch judges the model, so the exit-code read takes
            # ``selected``; the image-schema branch above carries its own
            # parse and model load instead.
            loaded = True
            applied = apply_config_overrides(
                model if model is not None else base,
                list(opts.config_overrides or []),
            )
            if model is not None:
                # The overrides decide the exit code as they do in a local
                # scan (which reads the orchestrator's config, overrides
                # applied), so the fields are the applied model's. The file's
                # own values, read above, stay the answer when the apply
                # raises, and when no file was selected there is no file value
                # to override (the scan inside reports its own).
                selected = _exit_fields_of(applied)
    except ASHConfigValidationError as exc:
        refusal: Optional[ASHConfigValidationError] = exc
        if (
            reading == "selected"
            and opts.config is not None
            and _selected_config_is_a_link_loop(selected_path)
        ):
            # Before Python 3.13 resolve() raises RuntimeError for a path that
            # is a symbolic link loop, and the load words that as its own
            # refusal; from 3.13 resolve() answers, the open raises the ELOOP
            # OSError, and the handler below defers to _unusable_nix_config.
            # The file that was being read is the loop, so both interpreters
            # take that deferral and the words are a local scan's. Only for a
            # NAMED file: the deferral's owners (container mode's handover check,
            # nix mode's _unusable_nix_config) judge --config alone, so a loop
            # discovery selected keeps the load's own refusal, or the run would
            # clear the previous output before the scan inside refused it.
            refusal = _unusable_nix_config(opts)
        return _OuterModeConfigLoad(
            refusal, selected, loaded, document, image_may_differ, own_model
        )
    except Exception as exc:  # noqa: BLE001 - re-raised unless handled
        # Two kinds of failure are this gate's. A parser's refusal of a file's
        # text (is_config_parse_error) is refused here with exit 3 in a local
        # scan's words, naming the file that was being read. The load of this
        # tree's own model does not word it, and neither a started runtime
        # nor a run that has cleared the previous output should be the first
        # to say it. A file nested past the recursion limit is not decided
        # here: parse_config_text refuses it as an unparsed config naming the
        # file it parsed, so it arrives as the ASHConfigValidationError
        # above, and a RecursionError that reaches this clause came from
        # somewhere other than a parse and propagates.
        # The OSError a missing or unreadable named file raises is deferred
        # to the checks that own that shape: container_input_refusal exits 3
        # for a config it cannot hand over, and nix mode, which has no such
        # check, is refused by _unusable_nix_config (None outside nix mode).
        # A failure that is neither (MemoryError, a bug) is not this gate's
        # to hide and propagates.
        from automated_security_helper.config.config_sources import (
            config_file_being_read,
            is_config_parse_error,
            unparsed_config_reason,
        )

        unparsable = is_config_parse_error(exc)
        if not isinstance(exc, OSError) and not unparsable:
            raise
        unparsed_file: Optional[str] = None
        if unparsable:
            # The file the chain walk was reading when the failure was raised.
            # The walk notes it where the read failed, so a root file's parse
            # error is named by the note; without one, the file this load was
            # reading is named.
            being_read = config_file_being_read(exc)
            if being_read is not None:
                unparsed_file = str(being_read)
            elif reading == "base":
                # The text the variable holds, which is what the load reads.
                unparsed_file = os.environ.get("ASH_CONFIG") or None
            elif reading == "selected":
                unparsed_file = selected_path
        if unparsed_file is not None:
            refusal = ASHConfigValidationError(
                unparsed_config_reason(Path(unparsed_file), exc)
            )
            refusal.ash_config_file = Path(unparsed_file)
            return _OuterModeConfigLoad(
                refusal, selected, loaded, document, image_may_differ, own_model
            )
        if (
            isinstance(exc, OSError)
            and reading == "selected"
            and opts.config is None
            and selected_path is not None
            and _names_the_failed_file(exc, selected_path)
        ):
            # A DISCOVERED file the load could not open. The deferral below
            # judges --config alone, so this file passed the gate and the run
            # cleared the previous output before the scan inside refused it.
            # Refused here, in a local scan's words (_discovered_config_refusal).
            # Only when the error names the selected file: an OSError the
            # checkout walk or another read raised keeps the deferral.
            return _OuterModeConfigLoad(
                _discovered_config_refusal(selected_path, exc),
                selected,
                loaded,
                document,
                image_may_differ,
                own_model,
            )
        return _OuterModeConfigLoad(
            _unusable_nix_config(opts),
            selected,
            loaded,
            document,
            image_may_differ,
            own_model,
        )
    finally:
        ASH_LOGGER.removeFilter(silence)
    return _OuterModeConfigLoad(
        None, selected, loaded, document, image_may_differ, own_model
    )


# The values click's boolean type (typer's vendored copy included) reads as true. `ash scan` declares ASH_DEBUG and
# ASH_VERBOSE as envvars of --debug/--verbose, so click parses them first and
# rejects anything outside its set; this has to agree with click about what turns
# them on, or `ASH_DEBUG=on` would pass the CLI and then do nothing. It is a
# superset of the "true"/"1"/"yes" core/execution_engine.py accepts.
_TRUE_ENV_VALUES = ("1", "true", "t", "yes", "y", "on")


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUE_ENV_VALUES


def resolved_console_log_level(
    log_level: AshLogLevel,
    verbose: bool,
    debug: bool,
    quiet: bool,
    simple: bool,
) -> AshLogLevel:
    """The console log level: CLI flags, then ASH_DEBUG/ASH_VERBOSE, then INFO.

    The environment used to be read only by the execution engine, for the Rich
    live panel, so ``ASH_DEBUG=true`` with no flag left the console at INFO --
    and the live panel is disabled in CI and in the container, where the env
    var is the natural way to ask (#628). It is read here now, below every CLI
    flag: a flag is the more specific request.

    ``--log-level INFO`` cannot be told from the default, so it does not
    override the environment; every other ``--log-level`` does.
    """
    if verbose:
        return AshLogLevel.VERBOSE
    if debug:
        return AshLogLevel.DEBUG
    if (
        quiet
        or simple
        or log_level in [AshLogLevel.QUIET, AshLogLevel.ERROR, AshLogLevel.SIMPLE]
    ):
        return AshLogLevel.ERROR
    if log_level != AshLogLevel.INFO:
        return log_level
    if _env_flag("ASH_DEBUG"):
        return AshLogLevel.DEBUG
    if _env_flag("ASH_VERBOSE"):
        return AshLogLevel.VERBOSE
    return log_level


def _resolve_log_level(opts: ScanOptions) -> AshLogLevel:
    """:func:`resolved_console_log_level` over the flags *opts* carries."""
    return resolved_console_log_level(
        log_level=opts.log_level,
        verbose=opts.verbose,
        debug=opts.debug,
        quiet=opts.quiet,
        simple=opts.simple,
    )


def _apply_log_level_env(opts: ScanOptions) -> None:
    """Record an env-requested level on *opts* as the matching flag.

    Done once, before anything reads the flags, because more than the console
    reads them: container mode forwards ``--debug``/``--verbose`` into the
    container, nix mode passes ``debug``, and the orchestrator is built with
    ``verbose``/``debug``. Each of those reading the env itself would be four
    copies of the precedence rule.
    """
    level = _resolve_log_level(opts)
    if level == AshLogLevel.DEBUG and not opts.debug:
        opts.debug = True
    elif level == AshLogLevel.VERBOSE and not opts.verbose:
        opts.verbose = True


def _live_progress_enabled(opts: ScanOptions) -> bool:
    """Whether the Rich live panel will run, and so own the console's log output.

    One answer for both consumers. ``_setup_logger`` leaves the console handler
    off when the panel is on, because the panel renders the log itself; the
    orchestrator decides whether to start the panel. They used to compute this
    separately and disagree: the orchestrator also refused the panel under CI and
    for VERBOSE/DEBUG, ``_setup_logger`` did not, so ``ash --debug`` in a
    terminal -- or any scan under ``CI`` that reached here with progress on --
    had neither sink, and every log line was dropped.
    """
    return (
        opts.progress
        and not opts.quiet
        and not opts.simple
        and _resolve_log_level(opts)
        not in [
            AshLogLevel.QUIET,
            AshLogLevel.SIMPLE,
            AshLogLevel.VERBOSE,
            AshLogLevel.DEBUG,
        ]
        and os.environ.get("CI") is None
        and os.environ.get("ASH_IN_CONTAINER", "NO").upper() not in ["YES", "1", "TRUE"]
    )


# ---------------------------------------------------------------------------
# _refuse_a_source_dir_that_is_not_utf8
# ---------------------------------------------------------------------------


def _refuse_a_source_dir_that_is_not_utf8(opts: ScanOptions) -> None:
    """Exit 1 before a scan run on this host starts on a directory whose path is not UTF-8.

    The scan writes the directory's absolute path into the results file and the
    SARIF (the run's working directory, a scanner's ``--target`` argument,
    ``additional_reports``), and both are UTF-8. A path that is not arrives as a
    str with surrogate escapes, which neither can hold: such a scan would run its
    scanners and write its working files, then exit 1 with "Error serializing
    to JSON" and write no results and no reports. Refused here, before the
    logger opens ash.log and before anything clears the previous run's output,
    so nothing is written and the previous results stay.

    Local, precommit and Nix mode scan the path as given; Nix mode's shell runs
    a local scan of it. A report over existing results (``--use-existing``) is
    left alone, since it writes its reports from the stored results. Container
    mode is refused by _refuse_a_container_mount_that_is_not_utf8 instead, so the
    message does not offer it.

    The path is shown as the exit-1 reasons show a name, through
    shown_shard_text: a surrogate is written as ``\\udcNN``, as the console's text
    rule writes it, and a newline as ``\\x0a``, so the message stays one line.
    Printed as a Text, not markup, so a ``[`` in the name is shown too.
    """
    if opts.mode == RunMode.container or opts.existing_results:
        return
    source = str(opts.source_dir)
    if _is_utf8_text(source):
        return
    print(
        Text(
            f"ERROR (1) The directory to scan, '{shown_shard_text(source)}', has a "
            "path that is not UTF-8. A scan run on this host writes that path into "
            "its results and SARIF, which hold UTF-8 only, so the scan would fail "
            "after its scanners ran. Rename the directory whose name is not UTF-8. "
            "Container mode cannot mount such a directory either.",
            style="bold red",
        )
    )
    sys.exit(1)


def _is_utf8_text(text: str) -> bool:
    """Whether *text* is UTF-8: a path that is not arrives with surrogate escapes."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _refuse_a_container_mount_that_is_not_utf8(opts: ScanOptions) -> None:
    """Exit 3 before container mode mounts a directory whose path is not UTF-8.

    3, as for every other path the container runtime cannot take (a comma, a
    quote, a line break) and as ``./ash`` refuses it. The host-mode refusal of
    such a directory, ``_refuse_a_source_dir_that_is_not_utf8``, stays 1: host
    mode mounts nothing, and there it is the directory's state.

    Container mode bind-mounts the directory to scan at ``/src`` and the output
    directory at ``/out`` (run_ash_container's ``--mount type=bind,source=...``).
    The runtime takes the mount's source as UTF-8 text. Measured with docker 25:
    the daemon receives the byte that is not UTF-8 as U+FFFD and refuses the
    mount ("bind source path does not exist"), which would end the scan with
    exit 125; and where a directory of that other name exists, it mounts that
    one, so the container would read a directory the operator did not name. No
    other runtime was measured; the refusal covers every runtime, since none
    takes the bytes on trust here.

    Checked as the mount gets it, made absolute, in every container run, a
    report over existing results included, since that run mounts both too. Not
    for ``--no-run``, which builds an image and mounts nothing. The source is
    named first: with no ``--output-dir`` the output directory is below it.
    """
    if opts.mode != RunMode.container or not opts.run:
        return
    for described, path, way_out in (
        (
            "The directory to scan",
            opts.source_dir,
            "Rename the directory whose name is not UTF-8.",
        ),
        (
            "The output directory",
            opts.output_dir,
            "Choose an --output-dir whose path is UTF-8.",
        ),
    ):
        absolute = os.path.abspath(str(path))
        if _is_utf8_text(absolute):
            continue
        print(
            Text(
                f"ERROR (3) {described}, '{shown_shard_text(absolute)}', has a path "
                "that is not UTF-8. Container mode bind-mounts it, and the container "
                "runtime takes a mount's path as UTF-8 text: it would refuse the "
                "mount, or mount a different directory whose name it reads the same "
                f"way. {way_out}",
                style="bold red",
            )
        )
        sys.exit(3)


def _refuse_a_container_mount_the_runner_cannot_carry(opts: ScanOptions) -> None:
    """Exit 3 before container mode mounts a directory ``--mount`` cannot carry.

    A path holding a comma, a double quote, a newline or a carriage return
    (run_ash_container._require_mountable): ``--mount`` reads its value as
    comma-separated fields. Checked as the mount gets it, resolved, before
    anything is created, so a refused scan writes no output directory or log;
    run_ash_container checks again for a caller that reaches it directly. Not for
    ``--no-run``, which builds an image and mounts nothing.
    """
    if opts.mode != RunMode.container or not opts.run:
        return
    try:
        _require_mountable_directories(opts.source_dir, opts.output_dir)
    except ContainerInputError as error:
        print(Text(str(error), style="bold red"))
        sys.exit(3)


# ---------------------------------------------------------------------------
# _refuse_symlinked_output_dir
# ---------------------------------------------------------------------------


def _scan_config_path(opts: ScanOptions, log_selection: bool = False) -> Optional[str]:
    """The config file a single-directory scan resolves: ``--config``, else the
    one discovery finds in the source directory under the scan's
    ``config_base_gate``, else None (the defaults)."""
    if opts.config is not None:
        return opts.config
    return _discovered_config_path(
        opts.source_dir, log_selection=log_selection, permit=opts.config_base_gate
    )


#: The exit code for an output directory ASH will not use because it, or something
#: ASH writes below it, is reached through a link: 3, as for container mode's other
#: unusable inputs, and the same whichever check refuses it (container mode's own
#: rule, the general check, or the log file's open).
OUTPUT_DIR_REFUSED_EXIT_CODE = 3


class OutputDirRefusedExit(SystemExit):
    """``sys.exit(3)`` for an output directory ASH will not use, with the reason.

    A ``SystemExit`` with OUTPUT_DIR_REFUSED_EXIT_CODE. ``found`` names the link and
    ``reason`` adds the command-line remedy; an in-process caller (the MCP scan
    runner) reports ``found`` with a remedy of its own instead of a bare "exited
    with code 3".
    """

    def __init__(self, found: str, reason: str):
        super().__init__(OUTPUT_DIR_REFUSED_EXIT_CODE)
        self.found = found
        self.reason = reason


def _refuse_symlinked_output_dir(opts: ScanOptions) -> None:
    """Exit before ASH writes, clears or mounts its output through a link.

    The logger opens ash.log in the output directory, the orchestrator and the
    container and nix modes clear its working directories, and a sandbox mounts it,
    so this runs before any of them, in every run mode and whatever the sandbox
    mode. Refused, with the link named and --output-dir as the remedy: a component
    below the scanned directory on the way to the output directory, the output
    directory itself, each of ``analysis``, ``reports``, ``scanners`` and
    ``converted`` under it, and the files ASH writes there by a fixed name. See
    utils/output_dir_links.py, and
    ASHScanOrchestrator._refuse_linked_output_dir, which makes the same refusal for
    callers that do not come through here. A workspace project's own output tree is
    checked by workspace/execution.py before it is created; here a workspace run's
    ``projects`` and spool directories are checked with the rest.

    Container mode first applies its own link rule: the output directory is mounted
    read-write at ``/out``, so the scan inside the container would write wherever a
    link leads (``container_output_dir_refusal``). The general check then runs as
    in every other mode, for the paths that rule does not name. Either refusal
    exits OUTPUT_DIR_REFUSED_EXIT_CODE (3).
    """
    if opts.mode == RunMode.container:
        refusal = container_output_dir_refusal(opts.source_dir, opts.output_dir)
        if refusal is not None:
            secho(str(refusal), fg=typer.colors.RED)
            raise OutputDirRefusedExit(refusal.found, str(refusal)) from refusal
    from automated_security_helper.utils.output_dir_links import (
        OutputDirLinkRefused,
        refuse_linked_output_dir,
    )

    try:
        refuse_linked_output_dir(
            opts.source_dir,
            opts.output_dir,
            workspace=opts.workspace_plan is not None,
        )
    except OutputDirLinkRefused as refusal:
        # The reason names the output directory, whose path is the caller's
        # text: shown on one line.
        print(
            f"[bold red]ERROR ({OUTPUT_DIR_REFUSED_EXIT_CODE}) "
            f"{escape_markup(str(refusal), one_line=True)}[/bold red]"
        )
        raise OutputDirRefusedExit(refusal.found, str(refusal)) from refusal


# ---------------------------------------------------------------------------
# _refuse_committed_output
# ---------------------------------------------------------------------------


def _config_refusal_text(error: ASHConfigValidationError) -> str:
    """The exit-3 refusal for *error*, as plain text for :func:`_printed_refusal`.

    A refusal over committed files is labeled as one, not as an invalid
    configuration (``committed_output.refusal_label``, which a workspace's refused
    project carries too); both exit 3. _printed_refusal escapes the text: a
    committed file's name is the repository's, and Rich reads ``[...]`` in it as
    markup, so unescaped, a name like ``reports/[/x].sarif`` would raise
    ``MarkupError`` out of the handler printing it. The text is ``error_text``'s,
    which describes a pydantic error instead of quoting its input.
    """
    return f"{refusal_label(error)}: {error_text(error)}"


def _workspace_project_outputs(opts: ScanOptions) -> List[Path]:
    """Each active project's own output directory, ``projects/<key>/``."""
    plan = opts.workspace_plan
    if plan is None:
        return []
    # Imported here, as in _run_workspace_mode: only a workspace run needs it.
    from automated_security_helper.workspace.execution import PROJECTS_DIR_NAME

    return [
        opts.output_dir / PROJECTS_DIR_NAME / project.key
        for project in plan.active_projects
    ]


def _log_files_the_nix_host_opened() -> Tuple[str, ...]:
    """The log files not to count on disk when git cannot answer: those of the host.

    Inside Nix mode (``ASH_IN_NIX``) this run is the inner scan, in the output
    directory the host CLI checked in full before its own logger opened the log
    files there, so on disk they are that logger's and not a previous run's.
    Committed log files are still refused whenever git answers.
    """
    if os.environ.get(ASH_IN_NIX_ENV_VAR, "NO").upper() in ("YES", "1", "TRUE"):
        return LOG_FILE_NAMES
    return ()


def _committed_entries_this_run_writes(opts: ScanOptions) -> List[Path]:
    """The entries git tracks where this run deletes or writes in its output dir.

    The CLI's logger writes the log files in every mode. Beyond them:

    * container mode with ``--no-run`` builds the image and writes nothing else;
    * a report over existing results (``--use-existing``), in any mode, writes
      what ``report_over_existing_results_writes`` lists;
    * a workspace scan run here writes the unified results file and ``reports/``
      at the root, spools under ``.workspace-spool/`` there, and scans each
      project into ``projects/<key>/``;
    * container mode, for a workspace too, clears the output directory on the
      host before the container starts (``_discard_prior_run_artifacts``), and
      the scan inside it cannot ask the host's git, so everything it writes is
      checked here;
    * any other scan starts fresh and writes every results path.

    See core/committed_output.py.
    """
    if opts.mode == RunMode.container and not opts.run:
        return committed_entries_in_the_way(
            opts.output_dir, files=LOG_FILE_NAMES, directories=()
        )
    if opts.workspace_plan is None:
        not_on_disk = _log_files_the_nix_host_opened()
        if opts.existing_results:
            # Truthiness, as in _discard_prior_run_artifacts and _run_local_mode:
            # an empty value reads nothing, and the run starts fresh.
            files, directories = report_over_existing_results_writes(
                inspect=opts.inspect or ExecutionPhase.INSPECT in (opts.phases or []),
                cleanup=opts.cleanup,
            )
            return committed_entries_in_the_way(
                opts.output_dir,
                files=files,
                directories=directories,
                not_on_disk=not_on_disk,
            )
        return committed_entries_in_the_way(opts.output_dir, not_on_disk=not_on_disk)
    return committed_entries_in_a_workspace_output(
        opts.output_dir,
        _workspace_project_outputs(opts),
        root_files=(*WORKSPACE_ROOT_FILES, *LOG_FILE_NAMES),
        every_results_path_at_the_root=opts.mode == RunMode.container,
    )


def _refuse_committed_output(opts: ScanOptions) -> None:
    """Exit 3 before this run deletes or writes a file git tracks in its output.

    Before the logger, which truncates ``ash.log``, and before the mode dispatch:
    container and Nix mode clear the output directory on the host, and the scan
    they start would then find nothing committed there. The orchestrator refuses
    the same files, but only once it runs, after those writes.

    When git cannot list the repository's index, whatever is on disk where this
    run writes, the log files included, is refused the same way
    (``committed_output.UnverifiedOutputFilesError``, raised by the check).
    """
    # Each refusal names the output directory, whose path is the caller's text:
    # one line.
    try:
        committed = _committed_entries_this_run_writes(opts)
    except CommittedOutputFilesError as unverified:
        _printed_refusal(
            COMMITTED_OUTPUT_REFUSED_EXIT_CODE,
            _config_refusal_text(unverified),
            one_line=True,
        )
    if not committed:
        return
    _printed_refusal(
        COMMITTED_OUTPUT_REFUSED_EXIT_CODE,
        _config_refusal_text(committed_output_files_error(opts.output_dir, committed)),
        one_line=True,
    )


# ---------------------------------------------------------------------------
# _setup_logger
# ---------------------------------------------------------------------------


def _setup_logger(opts: ScanOptions):
    """Configure ASH's logger, with ``ash.log`` in the output directory.

    The log file is opened as ASH's other writes below the output directory are,
    so a symlink at ``ash.log``, or a file another name refers to, stops the scan
    here with exit 3 (OutputDirRefusedExit) rather than being written through.

    The logger is also what first makes the output directory. Exit 5 when it
    cannot make it (a file on the way to it, or a parent that cannot be
    written), not a NotADirectoryError or PermissionError traceback and exit 1.
    Refused in the words every surface uses (utils/directory_refusals.py),
    with the error's own reason. An error once the directory is there is not
    about the directory, and is raised as it was.
    """
    from automated_security_helper.utils.log import get_logger
    from automated_security_helper.utils.output_dir_links import OutputDirLinkRefused

    final_log_level = _resolve_log_level(opts)
    final_logging_level = logging._nameToLevel.get(final_log_level.value, logging.INFO)
    simple_logging = opts.simple or opts.log_level == AshLogLevel.SIMPLE

    try:
        return get_logger(
            level=final_logging_level,
            output_dir=opts.output_dir,
            show_progress=_live_progress_enabled(opts),
            use_color=opts.color,
            simple_format=simple_logging,
            # Truthiness, as every other reader of existing_results: an empty
            # string asks for no existing results (run_ash_container appends
            # --use-existing under `if existing_results:`), so a fresh scan
            # starts a fresh ash.log.
            truncate_log=not opts.existing_results,
        )
    except OutputDirLinkRefused as refused:
        # The family's base: a symlink or a file another name refers to.
        reason = (
            f"{refused}. Remove it, or choose an output directory outside the "
            "scanned tree."
        )
        print(
            f"[bold red]ERROR ({OUTPUT_DIR_REFUSED_EXIT_CODE}) "
            f"{escape_markup(reason)}[/bold red]"
        )
        raise OutputDirRefusedExit(refused.found, reason) from refused
    except OSError as error:
        if Path(opts.output_dir).is_dir():
            raise
        message = output_dir_unmakeable(
            opts.output_dir, error.strerror or type(error).__name__
        )
        echo(shown_on_one_line(message), err=True)
        raise ScanRefusedExit(ASH_EXIT_USAGE_ERROR, message) from None


def _ignore_output_dir_in_git(opts: ScanOptions) -> None:
    """Write the output directory's ``.gitignore`` when it is inside the source tree.

    Here, once the logger has created the directory and before any mode starts, so
    that it covers every run mode. In container mode only the host can: the scan
    inside writes to ``/out``, which is not below ``/src``, though the same
    directory is visible below ``/src`` too, and a scanner reading the tree there
    reads it. See utils/output_dir_links.ignore_output_dir_in_git. A link at the
    name stops the scan with exit 3, as one at ``ash.log`` does.
    """
    from automated_security_helper.utils.output_dir_links import (
        OutputDirLinkRefused,
        ignore_output_dir_in_git,
    )

    try:
        ignore_output_dir_in_git(opts.source_dir, opts.output_dir)
    except OutputDirLinkRefused as refused:
        reason = (
            f"{refused}. Remove it, or choose an output directory outside the "
            "scanned tree."
        )
        print(
            f"[bold red]ERROR ({OUTPUT_DIR_REFUSED_EXIT_CODE}) "
            f"{escape_markup(reason)}[/bold red]"
        )
        raise OutputDirRefusedExit(refused.found, reason) from refused


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


# The output-directory entries a local scan clears before it starts: the working
# directories the orchestrator's ``ensure_directories`` rmtrees and the files its
# ``initialize`` unlinks, read from the shared constants both sides keep (one list
# in utils/output_dir_links.py, which also refuses a link at any of them, and one
# in utils/scan_output_dirs.py and core/committed_output.py, the same two constants
# the orchestrator clears from, so the lists cannot drift apart; a hand copy here
# once lacked the scan-set run record, ``ash-scan-set-run.json``). The union of the
# two spellings is cleared, plus an earlier inner run's refusal record
# (utils/inner_run_outcome.py). Both clears are gated there on
# ``existing_results_path is None``, which is the exemption in
# ``_discard_prior_run_artifacts`` below.
_PRIOR_RUN_OUTPUT_DIRECTORIES = tuple(
    dict.fromkeys((*OUTPUT_WORKING_DIRS, *WORKING_DIR_NAMES))
)
_PRIOR_RUN_OUTPUT_FILES = tuple(
    dict.fromkeys(
        (*OUTPUT_RESULT_FILES, *PREVIOUS_RUN_FILE_NAMES, INNER_RUN_OUTCOME_FILE)
    )
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

    So this clears what a local scan clears, in full: the working directories
    ``ensure_directories`` rmtrees and the files ``initialize`` unlinks
    (``_PRIOR_RUN_OUTPUT_DIRECTORIES`` and ``_PRIOR_RUN_OUTPUT_FILES``). A file git tracks
    at one of those paths stopped the run before this (``_refuse_committed_output``). Two
    entries earn a note:

    - ``reports/ash.sarif`` is not redundant with the results file. ``_compute_exit_code``
      re-reads that SARIF and lets its count REPLACE the one taken from the model. It
      reads it only when this run wrote it (``report_sarif_identity``), and removing it
      here keeps a stale one from being mistaken for this run's.
    - ``projects/`` is deliberately NOT in either list. Workspace mode writes a complete
      single-project tree per project under ``projects/<key>/`` and only the unified
      top-level files are rewritten by the outer run, so a workspace scan that removed
      ``projects/`` would delete the per-project reports it is about to summarize.

    The output directory is checked for links first, here beside the removals it
    protects, although run_ash_scan has already checked it: an rmtree through a
    linked ``reports`` deletes inside wherever it points. A ``reports/`` that is
    itself a link, to a directory or dangling, refuses the run first, as a local
    scan refuses it: rmtree fails on a link to a directory, and removing a dangling
    one would hide that the operator put a link there.

    It also removes what an MCP scan that kept the previous results left
    (core/previous_results.py): the held set, its staging directory and the marker a
    restore leaves. A held set is a complete earlier run; an inner scan that kept and
    then restored it would leave it where the read-back looks, so it goes before the
    inner run, without following links.
    """
    _refuse_symlinked_output_dir(opts)
    try:
        refuse_a_linked_reports_dir(opts.output_dir / "reports")
    except ReportPathRefused as refusal:
        _refuse_report_path_link(refusal)
    # Never an input, so removed even when --use-existing keeps the rest: the inner
    # run this process starts records its own refusal there, if any.
    try:
        (opts.output_dir / INNER_RUN_OUTCOME_FILE).unlink(missing_ok=True)
    except OSError as error:
        logger.debug(f"Could not remove {INNER_RUN_OUTCOME_FILE}: {error}")
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
        #
        # The restore marker stays with them for now. It says the results here
        # were put back by a scan that ended without its own; this scan reads
        # them on purpose, so _refuse_restored_results stands aside for it, and
        # the marker is dropped only once the read-back has accepted the inner
        # run's own results (_drop_restore_marker_after_a_completed_run). Dropped
        # here, before the image build and the container start, a build that
        # fails or a container that never starts would leave the put-back set
        # looking like the last scan's to every reader of the marker.
        return

    # Every entry core/previous_results.py keeps or stages beside the results
    # while a scan runs: the held set, its staging directory, the directory a
    # resumed restore moves entries back from, and the marker.
    kept_entries = [
        opts.output_dir / name
        for name in (
            HELD_DIR_NAME,
            HELD_DIR_NAME + ".partial",
            RESTORING_DIR_NAME,
            RESTORED_MARKER_NAME,
        )
    ]
    try:
        PreviousResults(opts.output_dir).discard()
    except OSError as e:
        # Refused on what is still there, not on the call having raised, and fail
        # closed when something is, for the reasons given below for the other
        # entries.
        if not any(os.path.lexists(p) for p in kept_entries):
            logger.debug(
                f"The kept previous results in {opts.output_dir.as_posix()} are "
                f"already gone despite {type(e).__name__}: {e}"
            )
        else:
            _logged_refusal(
                logger,
                1,
                f"Could not remove the previous results an earlier scan kept in "
                f"{opts.output_dir.as_posix()}: {error_text(e)}. ASH cannot tell them "
                "apart from "
                "output this scan produced, so it will not run. Remove "
                f"{HELD_DIR_NAME} there, or point --output-dir somewhere ASH can "
                "write.",
            )

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
            _logged_refusal(
                logger,
                1,
                f"Could not remove {stale.as_posix()} from a previous run: "
                f"{error_text(e)}. ASH "
                "cannot tell that output apart from output this scan produced, so it "
                "will not read it back or publish it. Remove it, or point --output-dir "
                "somewhere ASH can write.",
            )


class _DropThisThreadsRecords(logging.Filter):
    """Drops what the thread that made it logs; every other thread's records pass.

    For a logger filter that is only in place while one call runs. Records are
    filtered synchronously in the thread that logs them, so comparing that thread to
    the creator is enough, and it does not depend on ``logging.logThreads``.
    """

    def __init__(self) -> None:
        super().__init__()
        self._thread = threading.get_ident()

    def filter(self, record: logging.LogRecord) -> bool:
        return threading.get_ident() != self._thread


def _sandbox_overrides(config_overrides: Optional[List[str]]) -> List[str]:
    """The overrides that can change the sandbox section, in order.

    Selected the way ``resolve_config`` selects the ones it replays onto the trusted
    base: the key's first component is ``sandbox``, so ``sandbox.mode=``,
    ``sandbox.extra_read_paths+=`` and a whole ``sandbox=`` section all count. Kept
    equal to that expression by
    tests/unit/interactions/test_container_mode_reports_sandbox_not_applied.py.
    """
    return [
        override
        for override in config_overrides or []
        if override.partition("=")[0].removesuffix("+").split(".")[0] == "sandbox"
    ]


def _sandbox_mode_without_the_config(opts: ScanOptions) -> List[str]:
    """The sandbox mode a local run of *opts* has whatever its config file says.

    Used when the host cannot resolve the config. A config file can raise the mode
    but not take away the operator's floor, and nothing in a file can take back what
    ``--sandbox`` and ``--config-overrides`` set, so this is the trusted base
    ``resolve_config`` confines an in-tree config with (``trusted_base_config``,
    shared with it) -- from the operator's config (``trusted_config_path``, or in
    workspace mode the ``--config`` every project falls back to) and ASH_CONFIG's,
    over the tree resolve_config scans -- with the sandbox overrides replayed onto
    it, so ``--sandbox off`` still turns it off.

    A single-element list holding the mode, ``off`` included; the caller drops
    ``off``. Empty when the overrides do not apply, because then the scan in the
    container fails on them rather than running unsandboxed. An operator config
    that does not load counts as none, as an ASH_CONFIG that does not load counts
    as setting no floor; the scan in the container reports either.
    """
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.config.operator_only_options import (
        scan_repository_settings,
    )
    from automated_security_helper.config.operator_paths import the_operators_files
    from automated_security_helper.config.resolve_config import (
        _load_operator_config,
        apply_config_overrides,
        trusted_base_config,
    )
    from automated_security_helper.config.sandbox_grants import (
        files_inside,
        scanned_trees,
    )

    if opts.workspace_plan is not None:
        trusted_config_path = opts.config
        scanned_root = Path(opts.workspace_plan.workspace_root)
    else:
        trusted_config_path = opts.trusted_config_path
        scanned_root = Path(opts.source_dir)
    try:
        # The operator's file: its relative paths are taken from its own
        # directory (config/operator_paths.py), as resolve_config reads it.
        operator = _load_operator_config(
            trusted_config_path,
            opts.source_dir,
            opts.config_base_gate,
            the_operators_files(scanned_trees(scanned_root)),
        )
    except Exception:
        operator = None
    try:
        trees = scanned_trees(scanned_root)
        # ONE load of the ASH_CONFIG chain, under the settings the real load
        # uses (scan_repository_settings: the scanned trees and any other
        # checkout), is the single source here: the membership views ride out
        # of it, and the loaded config is carried into the trusted base, which
        # then reads nothing again. Separate reads could describe different
        # files if the variable or a link changed in between, and a read that
        # judged a file in another checkout differently from the real load
        # would let the floor and the scan disagree about what the file sets.
        settings = scan_repository_settings(trees)
        views: List[tuple] = []
        reads: dict = {}
        carried = get_default_config(
            settings.confine,
            views=views,
            repository_file=settings.is_repository_file,
            reads=reads,
        )
        env_chain, env_named, _ = views[0] if views else ([], [], frozenset())
        default_in_tree = bool(files_inside(env_chain, trees, env_named))
        floor = trusted_base_config(
            operator,
            trees,
            default_in_tree,
            default_config=carried,
            # The same read's views and per-file documents, for the floor's
            # owned-mode walk: the floor then reads the mode from the files
            # the operator's own chain wrote, never the merged chain.
            default_views=(views[0] if views else None),
            default_reads=reads,
            # The floor's semantics: with no operator-owned write, a merged
            # mode is repository-written and grants nothing, so the base's
            # own off stands. The scan's resolution passes True.
            merged_fallback=False,
        )
    except Exception:
        # ASH_CONFIG does not load, so it sets no floor here. The operator's
        # own files still do: the same owned walk the loaded path uses reads
        # the mode from the files the operator's chain wrote, under the same
        # membership, never from the merged chain -- a base in the scanned
        # tree later in the operator root's extends list could otherwise
        # turn off the mode the operator's own base set, on exactly the path
        # that reports what the container run drops. With no owned write, or
        # when the membership itself cannot be read, the floor stays off.
        from automated_security_helper.config.resolve_config import (
            _owned_sandbox_mode,
            _repository_members,
        )

        floor = AshConfig()
        if operator is not None:
            try:
                walk_trees = scanned_trees(scanned_root)
                owned = _owned_sandbox_mode(
                    operator.chain,
                    _repository_members(
                        operator.chain, operator.named, walk_trees, False
                    ),
                    operator.reads,
                    operator.environment_paths,
                )
            except Exception:
                owned = None
            if owned is not None:
                floor.sandbox.mode = owned
    selected = _sandbox_overrides(opts.config_overrides)
    if selected:
        try:
            floor = apply_config_overrides(floor, selected)
        except Exception:
            # An override that does not apply fails the scan in the container instead.
            return []
    return [floor.sandbox.mode]


def _config_as_the_scan_resolves_it(opts: ScanOptions):
    """The config a local single-directory scan of *opts* resolves.

    One call for a reader that needs a scan's config before the scan runs (the
    sandbox modes reported as dropped). It resolves through
    ``core.orchestrator.resolve_scan_config``, the function the orchestrator
    resolves with, so the arguments handed on to ``resolve_config`` and any
    step the scan's resolution takes are the scan's own and not a copy that
    can fall behind it. Every input the scan resolves with is handed over: the
    selected file (an explicit ``--config``, ``""`` included, is a selection
    to the load, never a fall-through to discovery), ``--config-overrides``,
    the base gate, the trusted base and whether the config is the scanned
    repository's, the client's overrides and policy, and whether the caller
    is a remote MCP client. A reader that passed fewer inputs would read a mode
    the scan does not run with.

    Imported here, not at the top of the module: the orchestrator would join
    every single-directory scan's import graph, as the ``TYPE_CHECKING``
    imports above explain for the workspace executor.
    """
    from automated_security_helper.core.orchestrator import resolve_scan_config

    return resolve_scan_config(
        config_path=_selected_config_path(opts),
        source_dir=opts.source_dir,
        # As the local scan hands them to the orchestrator (``or []``,
        # _run_local_mode): a scan that left the overrides at None resolves
        # with none, and the probe gets a list of its own, so a resolution
        # that changed its argument could not change the overrides the
        # container command line is built from.
        config_overrides=list(opts.config_overrides or []),
        config_base_gate=opts.config_base_gate,
        trusted_config_path=opts.trusted_config_path,
        untrusted_config=opts.untrusted_config,
        client_overrides=opts.client_overrides,
        client_config_policy=opts.client_config_policy,
        remote_client=opts.remote_client,
    )


def _sandbox_modes_requested(opts: ScanOptions) -> List[str]:
    """The scanner sandbox modes, other than ``off``, that a local run of *opts* applies.

    Container mode does not apply the sandbox (see ``_run_container_mode``), and this
    is what it reports as dropped. Resolved by the functions a local scan resolves its
    config with, given the same inputs, so every way of asking counts the way the scan
    counts it: ``--sandbox`` and any ``--config-overrides`` (``sandbox.mode=`` or a
    whole ``sandbox`` section), the config file, and the trusted base whose mode is a
    floor under a config the scanned repository wrote -- an operator ``--config`` over
    a workspace project's own, or ``ASH_CONFIG`` under an in-tree ``--config``.

    A single-directory scan resolves as ``_run_local_mode`` has the orchestrator
    resolve it; in workspace mode each active project resolves as
    ``workspace.execution`` resolves it. When the host cannot resolve the config --
    a base the container finds under ``/src``, an ASH_CONFIG that does not
    validate -- the scan in the container reports that itself, and the mode no
    config file can take away is still reported here: the operator's floor with
    ``--sandbox`` and ``--config-overrides`` over it
    (``_sandbox_mode_without_the_config``).

    What this thread logs while it resolves is dropped. Resolution logs what it reads
    and what it ignores, as a local scan would, and in container mode none of that
    happens: the scan inside resolves its own config and logs for itself. Only this
    thread's records are dropped, by a filter removed afterwards, so another thread
    logging meanwhile, or a second probe overlapping this one, is unaffected.
    """
    silence = _DropThisThreadsRecords()
    ASH_LOGGER.addFilter(silence)
    try:
        if opts.workspace_plan is not None:
            from automated_security_helper.workspace.execution import (
                _project_config_with_policy,
            )

            settings = build_project_scan_settings(opts)
            modes = [
                _project_config_with_policy(project, settings).sandbox.mode
                for project in opts.workspace_plan.active_projects
            ]
        else:
            # The selected file's mode, not a discovered neighbor's: the
            # helper resolves with the scan's own inputs.
            config = _config_as_the_scan_resolves_it(opts)
            modes = [config.sandbox.mode]
    except Exception:
        # Why the config does not resolve is the container's to report, with its own
        # exit code. The floor and the command line do not depend on the file.
        modes = _sandbox_mode_without_the_config(opts)
    finally:
        ASH_LOGGER.removeFilter(silence)
    return sorted(
        {
            SandboxMode(mode).value
            for mode in modes
            if SandboxMode(mode) != SandboxMode.off
        }
    )


def _names_the_output_directorys_own_results(opts: ScanOptions) -> bool:
    """Whether ``existing_results`` is the file a ``--use-existing`` run reads.

    The scan inside a container or a shell reads one file, the output
    directory's own ``ash_aggregated_results.json``, whatever path the caller
    named, so only that path is a request for the file the inner run read. The
    two are compared resolved, so the file spelled through a link or a relative
    path counts.
    """
    if not opts.existing_results:
        return False
    named = Path(opts.existing_results).resolve()
    own = (Path(opts.output_dir) / "ash_aggregated_results.json").resolve()
    return named == own


def _refuse_restored_results(
    output_dir: Path, where: str, logger, *, kept_on_purpose: bool = False
) -> None:
    """Exit 1 when the output directory says its results were put back.

    A scan that kept the previous results and ended without its own puts them back
    with a marker beside them (core/previous_results.py). The results file is then
    a complete, parseable earlier run, and reading it back would report that run as
    this one.

    *kept_on_purpose* is a ``--use-existing`` run: it asked for that file and the
    inner run read it, so the marker refuses nothing here; it is dropped once the
    read-back accepts the inner run's results as this run's
    (:func:`_drop_restore_marker_after_a_completed_run`), as a local
    ``--use-existing`` run accepts them.
    """
    if kept_on_purpose:
        return
    if holds_restored_results(output_dir):
        _logged_refusal(
            logger,
            1,
            f"The scan in {where} ended without results: {output_dir.as_posix()} holds "
            "the results of an earlier scan, which ASH put back, so they are not "
            "being read back as this scan's.",
        )


def _drop_restore_marker_after_a_completed_run(opts: ScanOptions, logger) -> None:
    """Remove the restore marker once a ``--use-existing`` run's read-back is accepted.

    The marker kept through the run (see :func:`_discard_prior_run_artifacts`)
    said the results were an earlier scan's put back; the inner run has now
    completed over them and the file is this run's, so the marker is no longer
    true. Only under ``--use-existing``: without it the marker was removed with
    the previous output before the run.
    """
    if not opts.existing_results:
        return
    try:
        (opts.output_dir / RESTORED_MARKER_NAME).unlink(missing_ok=True)
    except OSError as error:
        logger.debug(f"Could not remove {RESTORED_MARKER_NAME}: {error}")


# The statuses the in-container CLI reaches from a results file, and therefore the only
# ones the host can re-derive its own verdict from. Deliberately narrower than
# ASH_EXIT_CODES -- see the guard in _run_container_mode for which three are excluded and
# why. Nix mode, which runs the same CLI in a shell, reads it the same way.
_CONTAINER_VERDICT_EXIT_CODES = frozenset({0, 1, 2})


def _container_config_to_parse(opts: ScanOptions) -> Optional[Path]:
    """The config file the scan inside the container would load: the ``--config``
    file, else the one discovery finds in the source directory. On the CLI
    path ``opts.config`` carries the file ASH_CONFIG names too (typer reads
    the variable into the option), so that file is parsed here and mounted
    read-only for the scan inside (run_ash_container's
    _host_file_in_container). An API caller that sets ASH_CONFIG in the
    environment and leaves ``opts.config`` None has that file carried in the
    same way (_ash_config_fallback when nothing is discovered, and the
    --ash-config-from-host mount in every case), and its chain is checked by
    container_input_refusal; the parse check here reads the file the inner
    scan loads as its config. The discovery here and the one that decides
    whether ASH_CONFIG is the scan's config
    (run_ash_container._env_config_is_the_scans_config) are the same call,
    find_config_file of the source directory. None when there is nothing to
    check, or when the named path is not a regular file: what to say about a
    missing or non-file path is the run's own refusal, not the parse check's."""
    from automated_security_helper.config.resolve_config import find_config_file

    if opts.config:
        path = Path(opts.config)
        try:
            is_file = path.is_file()
        except OSError:
            # Before Python 3.14 is_file raises for a path under a directory this
            # user cannot search. What to say about it is the run's own refusal,
            # as for a missing path, so the parse check stands aside here too.
            is_file = False
        return path if is_file else None
    return find_config_file(search_dir=Path(opts.source_dir))


def _refuse_a_container_config_that_does_not_parse(opts: ScanOptions) -> None:
    """Refuse a config file that does not parse before the runner is resolved.

    A local scan refuses one with exit 3, naming the file. Container mode reads
    the file only inside the container, so without this check the host would
    start the runner (an image build, minutes of work) and end the run with its
    exit code, never naming the file. For a workspace plan this is the one
    layer that reads the config before the runner at all: the pre-run gate
    (``_outer_mode_config_load``) does not run there, because the plan was
    resolved on the host and each project resolves its own config. The check is
    syntax only (yaml.compose builds the
    node graph without constructing values, so an ``!ENV`` tag passes), and
    full validation stays with the scan inside the container.

    The refusal is the shared formatter's (unparsed_config_reason):
    the error's type and place, never the parser's own problem text, which can
    quote a token of the file (an alias, a tag).
    """
    # tomllib is stdlib only from Python 3.11; requires-python starts at 3.10.
    # There it is tomli, the parser tomllib was taken from, which
    # pyproject.toml declares for Python below 3.11 (config/config_sources.py).
    if sys.version_info >= (3, 11):  # pragma: no cover - depends on interpreter version
        import tomllib
    else:  # pragma: no cover - Python 3.10
        import tomli as tomllib

    import yaml

    from automated_security_helper.config.config_sources import (
        _read_toml_text,
        describe_config_path,
        is_json_file,
        is_toml_file,
        unparsed_config_reason,
    )

    if not opts.run:
        # With --no-run the container never starts and the inner scan never
        # loads the config, so there is nothing to refuse for, as
        # every other container pre-check gates.
        return
    path = _container_config_to_parse(opts)
    if path is None:
        return
    try:
        if is_json_file(path):
            # utf-8-sig, as the scan's own JSON reader decodes the file: a
            # leading byte order mark is dropped, which json.loads rejects, so
            # a marked file the scan loads is not refused here.
            json.loads(path.read_text(encoding="utf-8-sig"))
        elif is_toml_file(path):
            # The text the scan's own reader hands the parser: _read_toml_text
            # drops a leading UTF-8 byte order mark, which tomllib rejects, so
            # a marked file the scan loads is not refused here.
            tomllib.loads(_read_toml_text(path))
        else:
            yaml.compose(path.read_text(encoding="utf-8"))
        return
    except OSError as error:
        # A read failure says read, not parsed: the file's syntax was never
        # seen, and it has no place.
        reason = (
            f"{describe_config_path(path)} could not be read ({type(error).__name__})"
        )
    except (yaml.YAMLError, ValueError, RecursionError) as error:
        # The shared refusal's words: UnicodeDecodeError, a ValueError, gives
        # the byte's offset and never its value. RecursionError is a file
        # nested past the interpreter's limit, which the repository's own
        # config can be (the pre-run gate's rule); the try holds only the read
        # and one parser call, so every RecursionError here is that file's.
        reason = unparsed_config_reason(path, error)
    refused = ASHConfigValidationError(reason)
    refused.ash_config_file = path
    _printed_config_refusal(3, refused)


def _refuse_container_inputs(
    opts: ScanOptions,
    workspace_config: str | None,
    reads: OperatorConfigReads | None = None,
) -> None:
    """Exit 3, before the runtime is called, when container mode cannot be given its
    inputs as they are (run_ash_container.container_input_refusal): a config it
    cannot hand over, or a path the runner cannot be handed, one that is not UTF-8
    included. The code run_ash_container gives.
    """
    refusal = container_input_refusal(
        opts.source_dir,
        opts.output_dir,
        opts.config,
        workspace_config,
        _workspace_relative_file(opts),
        reads,
    )
    if refusal is not None:
        # It can name a path inside the scanned tree: the whole raw message is
        # shown once, on one line.
        echo(shown_on_one_line(refusal), err=True)
        sys.exit(3)


def _workspace_policy_for_the_container(opts: ScanOptions) -> Optional[str]:
    """The workspace policy path handed to container mode, or None.

    The container resolves the workspace again, and on its own it would find
    only a policy inside the root, so one named with ``--workspace-config``
    elsewhere would not apply. It is handed over by the name it was given or
    found under (``named_workspace_policy_path``), not the resolved path the
    plan holds, so a policy named inside the workspace's tree that links out
    of it is refused as an in-tree ``--config`` that links out is; the mount
    itself is of the real file. The name is used only when it resolves to the
    file the plan read: a plan built without the as-named spelling (an API
    caller's) can hold an explicit policy outside the root while the root
    carries an ``ash-workspace.yaml`` of its own, which the plan's resolution
    skipped -- handing discovery's find over then replaced the operator's
    policy with a file the repository wrote.
    """
    plan = opts.workspace_plan
    if plan is None or plan.workspace_config_source is None:
        return None
    from automated_security_helper.workspace.policy import (
        named_workspace_policy_path,
    )

    named = named_workspace_policy_path(
        plan.workspace_root, opts.workspace_config_as_named
    )
    if named is None or os.path.realpath(named) != os.path.realpath(
        plan.workspace_config_source
    ):
        return plan.workspace_config_source
    return named.as_posix()


def _shown_container_command(container_result) -> str:
    """The container command, as the debug dump may print it.

    The run attaches the command as it may be shown (``shown_command``: each
    override value replaced by its key, the spawn's recorded values hidden),
    and that text wins verbatim. A result that never reached the run carries
    no such text, and its raw arguments are the fallback; today every such
    result also carries empty arguments, but the fallback does not rely on
    that staying true, so it is redacted the same way the run's own text is
    before anything prints it.
    """
    from automated_security_helper.utils import subprocess_utils
    from automated_security_helper.utils.error_text import text_without_values

    shown = getattr(container_result, "shown_command", None)
    if shown is not None:
        return shown
    joined = " ".join(
        str(arg)
        for arg in subprocess_utils.shown_arguments(
            list(getattr(container_result, "args", None) or [])
        )
    )
    return text_without_values(joined, subprocess_utils._SPAWN_VALUES.get())


def _run_container_mode(
    opts: ScanOptions,
    logger,
    resolved_fail_on_findings: Optional[bool] = None,
    resolved_fail_on_incomplete_scanners: Optional[bool] = None,
    reads: OperatorConfigReads | None = None,
    *,
    image_may_differ: Optional[bool] = None,
) -> AshAggregatedResults:
    """Run the scan inside the ASH container image and read its results back.

    *reads* is the scan's one record of the operator's config chain
    (:class:`OperatorConfigReads`), handed on to every check and to
    ``run_ash_container``; a caller that has none gets one for this call.
    *image_may_differ* is the pre-run gate's answer for the record repair
    (:func:`_take_own_values_for_record`); None asks for itself.

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
    # Before anything starts, the runner's resolution included: a config file
    # that does not parse refuses the run as a local scan refuses it, instead
    # of building an image and exiting with the runner's code.
    if reads is None:
        reads = OperatorConfigReads()
    _refuse_a_container_config_that_does_not_parse(opts)
    # The same gate's second half: a config the container cannot be given as it
    # is on the host -- a missing file, a path the runner cannot mount, a
    # variable the configuration reads that is not passed inside -- is refused
    # before the runner is resolved and before the previous run's output is
    # cleared. run_ash_container checks again, for a caller that reaches it
    # directly. In workspace mode the policy the host resolved into the plan is
    # a mount of its own, so it is checked, and below handed over, with the
    # config, by the name the operator gave it. Gated on ``opts.run`` like the
    # parse check above: --no-run builds an image, mounts nothing and reads no
    # config, so there is no scan input to refuse an image build over.
    workspace_config = _workspace_policy_for_the_container(opts)
    if opts.run:
        _refuse_container_inputs(opts, workspace_config, reads)
    if opts.changed_files_only:
        logger.warning(
            "--changed-files-only is not supported in container mode; performing full scan"
        )
    # The sandbox is turned off for the scan inside (sandbox.mode=off, below). That
    # is by design, and dropping a sandbox the operator asked for is announced. On
    # stderr directly rather than logged, so --quiet and --log-level ERROR, which
    # hide log records, cannot hide it either.
    requested_sandbox = _sandbox_modes_requested(opts) if opts.run else []
    if requested_sandbox:
        echo(
            f"WARNING: The scanner sandbox ({', '.join(requested_sandbox)}, from "
            "sandbox.mode in a config file, --config-overrides or the operator's "
            "config) is not applied in container mode: the scanners run "
            "unsandboxed inside the container, and the container is the boundary. "
            "Run with --mode local to sandbox each scanner.",
            err=True,
        )

    # Use the CLI-supplied value when present; fall back to the value already read from
    # the config file on the host.  Passing the resolved value avoids a race where the
    # user mutates the config file between the host read and the container's own read.
    #
    # Not in workspace mode. The in-container run layers the operator's --config over
    # each project's own config and judges each project itself; a value the host read
    # here (from --config, or from a config at the workspace root, which the workspace
    # wrote) would reach it as a command-line flag and beat every project's own value.
    # Only what the operator gave on the command line is forwarded there.
    in_workspace = opts.workspace_plan is not None
    if opts.workspace_plan is not None and opts.config:
        # The in-container run is given the operator's file at
        # /ash-operator-config, outside /src, so it cannot tell where the file
        # sat on the host. Judged here, against the workspace root on the host,
        # as workspace resolution judged it (resolve_workspace), so a plan built
        # without that check is refused the same way before a container starts.
        from automated_security_helper.config.resolve_config import (
            check_operator_config,
        )

        try:
            check_operator_config(opts.config, opts.workspace_plan.workspace_root)
        except ASHConfigValidationError as exc:
            # The shared printer escapes the error's text, which names a path:
            # printed raw, a bracket sequence in it raised MarkupError out of
            # this handler instead of exiting 3.
            _print_invalid_config(exc)
            sys.exit(int(WorkspaceExitCode.INVALID_PROJECT_CONFIG))
    effective_fail_on_findings = (
        opts.fail_on_findings
        if opts.fail_on_findings is not None or in_workspace
        else resolved_fail_on_findings
    )
    effective_fail_on_incomplete_scanners = (
        opts.fail_on_incomplete_scanners
        if opts.fail_on_incomplete_scanners is not None or in_workspace
        else resolved_fail_on_incomplete_scanners
    )

    # The policy handed to the container is the one _workspace_policy_for_the_container
    # computed above, checked against the file the plan read. It is not computed
    # again here: a second computation without that check handed discovery's find
    # over for a plan built without the as-named spelling, so an ash-workspace.yaml
    # the repository wrote replaced the operator's policy in the container.

    if opts.run:
        # The scan inputs were checked once, above, before anything else of this
        # function ran; nothing between there and here changes them. The build
        # inputs too: IDs that are not numbers, a revision the build cannot take,
        # and a non-root build as UID or GID 0, which is the default outcome on a
        # root host that does not pass --build-target ci. With the host IDs
        # unreadable, run_ash_container reports that itself.
        from automated_security_helper.utils import subprocess_utils

        try:
            host_ids = (
                subprocess_utils.get_host_uid(),
                subprocess_utils.get_host_gid(),
            )
        except Exception:
            host_ids = None
        if host_ids is not None:
            build_refusal = container_build_refusal(
                build=opts.build,
                build_target=opts.build_target,
                custom_containerfile=opts.custom_containerfile,
                container_uid=opts.container_uid,
                container_gid=opts.container_gid,
                ash_revision_to_install=opts.ash_revision_to_install,
                host_uid=host_ids[0],
                host_gid=host_ids[1],
            )
            if build_refusal is not None:
                secho(build_refusal[1], fg=typer.colors.RED)
                sys.exit(build_refusal[0])
        # Only when a scan is actually being asked for. --no-run builds an image and
        # stops; it never claims to have scanned anything, so it has no business
        # discarding a report from a run that did.
        #
        # A container an earlier run left behind is removed first. It may still be
        # writing declared outputs, and one written after the clear below and before
        # the read would be vouched for as this run's.
        sweep_leftovers_before_run(opts.oci_runner)
        # The private directories a SIGKILLed run stranded go too, ahead of the clear.
        sweep_env_dirs()
        _discard_prior_run_artifacts(opts, logger)

    # Written into the results file by the in-container run when it completes, so a
    # file it did not finish is not read back as a verdict. See
    # utils/inner_run_outcome.py.
    outer_run_id = new_outer_run_id()
    container_result = run_ash_container(
        outer_run_id=outer_run_id,
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
        # The host path: run_ash_container mounts the file read-only and hands
        # the scan inside the path it has there (_host_file_in_container).
        config=str(opts.config) if opts.config else None,
        # The container is the boundary, and the image does not ship bubblewrap: an
        # inner run that read sandbox.mode from the config file or --sandbox would
        # record every scanner MISSING. Appended last so it wins.
        config_overrides=[*(opts.config_overrides or []), "sandbox.mode=off"],
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
        ignore_suppressions=opts.ignore_suppressions,
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
        # Applied inside only in workspace mode, whose exit code the host
        # returns as the container computed it (below); a one-directory scan's
        # exit code is recomputed on the host, where --min-severity is applied.
        min_severity=opts.min_severity,
        # The policy the host resolved into the plan, mounted for the workspace
        # scan inside as --config is (_host_file_in_container).
        workspace_config=workspace_config,
        reads=reads,
    )

    if opts.debug:
        print("\n[bold blue]Debug: Container Command[/bold blue]")
        if hasattr(container_result, "args"):
            # The arguments name the operator's paths, which markup would read.
            # The run attaches the command as it may be shown (each
            # --config-overrides value as its key, the run's environment
            # values hidden); the raw arguments carry both, so they are only
            # the fallback for a result no container run built, and the
            # fallback is redacted the same way the run's own text is.
            command = _shown_container_command(container_result)
            print(f"Command: {escape_markup(command)}")
        print(f"Return code: {container_result.returncode}")
        print(
            f"Stdout length: {len(container_result.stdout) if hasattr(container_result, 'stdout') else 'N/A'}"
        )
        print(
            f"Stderr length: {len(container_result.stderr) if hasattr(container_result, 'stderr') else 'N/A'}"
        )

    if not container_was_started(container_result):
        # A refusal before any container ran: no runner, a non-numeric UID or GID, a
        # runner marker the wrapper's command line cannot take, an unsafe revision, a
        # missing Dockerfile, a failed build, an unusable source or output directory.
        # run_ash_container has already printed why (a failed build's
        # own output streams to the terminal as it runs), and there is nothing more to
        # report. Going on would log "Container execution failed" for a container that
        # never started and then look for a results file nothing could have written,
        # ending in a "Results file not found" that names the wrong problem. The status
        # is the refusal's own; a failed build keeps the runner's code.
        sys.exit(getattr(container_result, "returncode", 1) or 1)

    container_returncode_now = getattr(container_result, "returncode", 0)
    if container_returncode_now in (0, 2):
        if container_returncode_now == 2:
            # 2 is the scan inside saying it found something, a status it reaches
            # only after writing its results file, which this process re-derives
            # below; its output already streamed to the terminal as it ran, so it
            # is neither a failure to report nor stderr to print again. 1 is NOT
            # quieted: an incomplete scan and a crash share it, and a crash that
            # exits 1 before writing the results file has only this error and the
            # captured stderr to explain itself.
            logger.debug(
                f"The container exited with {container_returncode_now}, a status "
                "re-derived from the results file below"
            )
    else:
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
    # --min-severity, which is not forwarded inward. Exiting on 2 here would report
    # findings the operator asked to filter out. (--ignore-suppressions is forwarded:
    # suppressions are applied by the scan inside, and reach the host in its ash.sarif.)
    #
    # NOT ASH_EXIT_CODES either, which is the wider table of every status the CLI can
    # return and includes three that assert the opposite of a verdict. 3 is an invalid
    # config, raised by _run_local_mode before it writes the results file; 4 is a
    # workspace definition or policy error, which models/workspace.py defines precisely so
    # that "nothing was scanned" is distinguishable from 2's "a scan completed and found
    # something"; and 5 is a usage error, the inner CLI refusing its own command line.
    # Falling through on any of them sends the caller to the read-back, which finds no
    # file and reports 1 with a message about a missing report rather than about the
    # config or the arguments -- losing the code that said which it was.
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

    _refuse_links_left_in_reports(opts)
    _refuse_an_inner_run_that_was_refused(opts, outer_run_id)
    # Kept on purpose only when the caller named the file the inner run reads. A
    # path outside the output directory is not read by the container (it reads
    # the directory's own file), so a restore marker beside that file still
    # means the results are an earlier scan's put back.
    _refuse_restored_results(
        opts.output_dir,
        "the container",
        logger,
        kept_on_purpose=_names_the_output_directorys_own_results(opts),
    )

    output_file = opts.output_dir / "ash_aggregated_results.json"
    if container_returncode == 2 and not output_file.exists():
        # The scan inside exits 2 for findings only after writing the results file,
        # and for a usage error without one: an image built from an older ASH
        # rejects an option this ASH passes it, such as the repository mark.
        passed = [str(arg) for arg in (getattr(container_result, "args", None) or [])]
        marks = [
            flag
            for flag in (
                CONFIG_FROM_SCANNED_REPOSITORY_FLAG,
                CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG,
                CONFIG_FILE_FROM_ANOTHER_CHECKOUT_FLAG,
                ASH_CONFIG_FROM_HOST_FLAG,
            )
            if flag in passed
        ]
        cause = (
            f"the image was built from an older ASH that does not accept "
            f"{' or '.join(marks)}, which this ASH passes it"
            if marks
            else "the image may be from an older ASH that does not accept an option "
            "this ASH passes it"
        )
        logger.error(
            "The scan inside the container exited 2 without writing a results file, "
            f"which is how the ASH command line rejects its arguments: {cause}. "
            "Rebuild the image from this ASH (run without --no-build, or rebuild the "
            "image ASH_IMAGE_NAME names)."
        )
        sys.exit(3)
    results = _read_back_inner_results(output_file, logger)
    if results is not None:
        _refuse_an_inner_run_that_did_not_complete(
            results, opts, outer_run_id, "container", output_file, logger
        )
        _drop_restore_marker_after_a_completed_run(opts, logger)
        _take_own_values_for_record(results, opts, image_may_differ=image_may_differ)
        return results
    else:
        # The container's own status beside the missing file, as nix mode names the
        # shell's: with nothing to read back it is the only diagnostic left.
        logger.error(
            f"Results file not found at {output_file}. The container exited with "
            f"code {container_returncode}."
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# _run_nix_mode
# ---------------------------------------------------------------------------


def _no_workspace_payload_message(mode: RunMode) -> str:
    """The error for an outer mode whose inner run returned no workspace payload,
    naming the thing that ran: the container, or the Nix shell. One text named
    the container for a Nix run too."""
    ran = "Nix shell" if mode == RunMode.nix else "container"
    return (
        f"The {ran} produced no workspace payload, so no per-project exit code "
        "is available."
    )


def _refuse_a_results_file_the_shell_cannot_be_handed(
    opts: ScanOptions, logger
) -> None:
    """Refuse a Nix run whose ``existing_results`` is not the output directory's own.

    The scan CLI has no option that names a results file: ``--use-existing``
    reads ``<output-dir>/ash_aggregated_results.json``, and that is all the
    inner command line can say. A library caller naming another file
    (``existing_results="/elsewhere/results.json"``) was handed that flag, so the
    scan inside the shell read the output directory's file from an earlier run,
    or refused for want of one, and the caller's file was never read. Exit 3,
    before the preflight and before the previous run's output is cleared
    (``_discard_prior_run_artifacts`` keeps that file when ``existing_results``
    is set, so nothing of the caller's is lost). The two paths are compared
    resolved, so the output directory's own file spelled through a link or a
    relative path is accepted.
    """
    if not opts.existing_results:
        return
    named = Path(opts.existing_results).resolve()
    own = (Path(opts.output_dir) / "ash_aggregated_results.json").resolve()
    if named == own:
        return
    _logged_refusal(
        logger,
        3,
        "Scan refused: --mode nix reads existing results from the output "
        f"directory's own file, {shown_on_one_line(str(own))}, which is all the "
        "scan inside the shell can be told; the results file named, "
        f"{shown_on_one_line(str(named))}, is another file. Pass the output "
        "directory that holds the file, or run the report phase with --mode local.",
    )


def _nix_inner_argv(opts: ScanOptions) -> List[str]:
    """The command line of the scan inside the Nix shell, built from this call.

    From the options, not from this process's ``sys.argv``. A library caller's
    ``run_ash_scan(mode=RunMode.nix, ...)`` has no command line of its own, and
    forwarding the host program's arguments ran the inner scan on whatever that
    program was started with (another directory, another scanner set, another
    output directory) and read that run's results back as this call's.

    Every ScanOptions field is one of three things here, and
    tests/unit/interactions/test_run_ash_scan_nix_inner_arguments.py lists the
    fields by name so a field added later has to be placed:

    * FORWARDED, as the flag the scan CLI reads it by (the body below).
      ``--mode`` is left to ``rewrite_mode_args``, which appends ``--mode local``.
      ``--cli-json-input`` never reaches the inner scan: its document was read
      into these options already, and the shell's standard input is empty.
      ``--config`` is forwarded unless it is the file ``ASH_CONFIG`` names: the
      scan CLI reads the option from that variable when none is typed, and the
      shell keeps the variable, so the inner CLI reads it the same way.
    * REFUSED before this point, in ``run_ash_scan``, because the scan CLI has
      no flag for them and the scan inside the shell cannot be given them:
      ``config_base_gate``, ``untrusted_config``, ``client_config_policy``,
      ``remote_client``, ``severity_threshold_restriction``,
      ``keep_previous_results`` and ``trusted_config_path``.
    * NOT FORWARDED on purpose: ``mode`` (rewritten), ``workspace_plan`` (its
      definition and policy are forwarded as ``--workspace`` and
      ``--workspace-config``), ``workspace_config_as_named`` (container mode's
      hand-over spelling; the shell shares this filesystem and gets the
      resolved path), ``client_overrides`` and ``selection_origin`` (who gave
      the options on this side; the inner scan's own are the CLI's), and the
      container-only fields (``build``, ``run``, ``force``, ``oci_runner``,
      ``build_target``, ``container_uid``, ``container_gid``,
      ``container_network``, ``ash_revision_to_install``,
      ``custom_containerfile``, ``custom_build_arg``), which no shell reads.

    The host's own environment is kept out of the inner scan's option reading
    by ``run_ash_nix`` (``INNER_SCAN_OPTION_VARIABLES``), so what this function
    leaves off the command line is the default, not the host's setting.
    """

    def value_of(member: Any) -> str:
        return str(member.value if hasattr(member, "value") else member)

    argv: List[str] = ["scan"]
    plan = opts.workspace_plan
    if plan is not None:
        # The workspace scan runs inside the shell, as it runs inside the
        # container: the definition and the policy the plan applied are named to
        # it, on this same filesystem. --source-dir is mutually exclusive with
        # --workspace; the workspace root is the plan's.
        argv.extend(["--workspace", str(plan.workspace_file)])
        if plan.workspace_config_source is not None:
            argv.extend(["--workspace-config", str(plan.workspace_config_source)])
        if opts.allow_missing_projects:
            argv.append("--allow-missing-projects")
    else:
        argv.extend(["--source-dir", str(opts.source_dir)])
    argv.extend(["--output-dir", str(opts.output_dir)])
    # The scan CLI fills --config from ASH_CONFIG when none is typed (the
    # option's envvar), and run_ash_nix keeps that variable for the shell, so
    # the inner CLI reads it the same way. The command names a config only when
    # the caller named one: forwarded, the file ASH_CONFIG names reached the
    # inner scan as if the operator had typed it, against what install.md says
    # of a scan with no --config.
    if opts.config and str(opts.config) != os.environ.get("ASH_CONFIG"):
        argv.extend(["--config", str(opts.config)])
    for override in opts.config_overrides or []:
        argv.extend(["--config-overrides", override])
    for scanner in opts.scanners or []:
        argv.extend(["--scanners", scanner])
    for scanner in opts.excluded_scanners or []:
        argv.extend(["--exclude-scanners", scanner])
    for module in opts.ash_plugin_modules or []:
        argv.extend(["--ash-plugin-modules", module])
    for fmt in opts.output_formats or []:
        argv.extend(["--output-formats", value_of(fmt)])
    for phase in opts.phases or []:
        argv.extend(["--phases", value_of(phase)])
    argv.extend(["--strategy", value_of(opts.strategy)])
    if opts.offline:
        argv.append("--offline")
    if opts.offline_semgrep_rulesets != "p/ci":
        argv.extend(["--offline-semgrep-rulesets", opts.offline_semgrep_rulesets])
    if not opts.progress:
        argv.append("--no-progress")
    if not opts.color:
        argv.append("--no-color")
    if not opts.show_summary:
        argv.append("--no-show-summary")
    for flag, given in (
        ("--quiet", opts.quiet),
        ("--verbose", opts.verbose),
        ("--debug", opts.debug),
        ("--simple", opts.simple),
        ("--cleanup", opts.cleanup),
        ("--inspect", opts.inspect),
        ("--python-based-plugins-only", opts.python_based_plugins_only),
        ("--ignore-suppressions", opts.ignore_suppressions),
    ):
        if given:
            argv.append(flag)
    log_level = value_of(opts.log_level)
    if log_level != AshLogLevel.INFO.value:
        argv.extend(["--log-level", log_level])
    if opts.fail_on_findings is not None:
        argv.append(
            "--fail-on-findings" if opts.fail_on_findings else "--no-fail-on-findings"
        )
    if opts.fail_on_incomplete_scanners is not None:
        argv.append(
            "--fail-on-incomplete-scanners"
            if opts.fail_on_incomplete_scanners
            else "--no-fail-on-incomplete-scanners"
        )
    if opts.min_severity.lower() != "low":
        argv.extend(["--min-severity", opts.min_severity])
    if opts.changed_files_only:
        argv.extend(["--changed-files-only", "--base-ref", opts.base_ref])
    if opts.existing_results:
        # The CLI resolves --use-existing to the output directory's own results
        # file. _refuse_a_results_file_the_shell_cannot_be_handed, run before
        # this, has checked that the file this option names IS that file; the
        # shell shares this filesystem, so the inner scan resolves the same one.
        argv.append("--use-existing")
    # Each value on its own: ScanPhase is the one place that refuses an unusable
    # pair (see the ScanOptions comment on shard_index), and it can refuse only
    # what reaches it. Forwarding the pair only when both were set turned a
    # caller's half pair into an unsharded whole scan that came back as a
    # normal result.
    if opts.shard_index is not None:
        argv.extend(["--shard-index", str(opts.shard_index)])
    if opts.shard_count is not None:
        argv.extend(["--shard-count", str(opts.shard_count)])
    return argv


# The two refusals of Nix mode (`nix` missing, the recursion guard), asked by
# _run_nix_mode before it clears the previous run's output: a refused run starts no
# shell, so it must not delete the reports of one that did. A module-level name of
# its own, asked whatever stands in for run_ash_nix: a test or caller that replaces
# the runner with something that starts no shell replaces this too, on purpose
# (monkeypatch.setattr(run_ash_scan, "nix_preflight", lambda: None)), so the refusal
# is never lifted by a stand-in that merely lacks a check of its own.
nix_preflight = nix_executable_for_this_run


def _run_nix_mode(
    opts: ScanOptions, logger, *, image_may_differ: Optional[bool] = None
) -> AshAggregatedResults:
    """Run the scan inside a Nix shell that supplies the pinned scanner toolchain.

    *image_may_differ* is the pre-run gate's answer for the record repair
    (:func:`_take_own_values_for_record`); None asks for itself.

    An outer wrapper like container mode: ASH re-executes itself inside `nix develop` and
    the inner run is an ordinary local scan. Simpler than container mode in one respect,
    since a development shell changes PATH but not the filesystem, so there is no mount
    translation and none of that path-mapping logic belongs here.

    Two module-level names are read at call time and are the seams a test replaces:
    ``run_ash_nix``, the runner, and ``nix_preflight``, the refusals asked before the
    clear. A stand-in runner that starts no shell sets ``nix_preflight`` to a no-op as
    well; left alone, the preflight refuses on a host without `nix` whatever the runner
    is, and the stand-in is never reached.
    """
    # The shell writes into the output directory this process was given, so a report left
    # by an earlier run sits exactly where a successful one would. run_ash_nix returns a
    # bare status and requests no capture -- stdout and stderr are both None -- so a `nix`
    # that exists on PATH and fails is otherwise indistinguishable from a scan that ran.
    #
    # A container an earlier container-mode run left behind may still be writing into
    # this output directory, so it is removed before the clear, as container mode does.
    # A host with no container runtime has nothing to remove and its records stay.
    #
    # Before the preflight and the clear: a refused run deletes nothing.
    _refuse_a_results_file_the_shell_cannot_be_handed(opts, logger)

    try:
        # The two refusals of Nix mode (`nix` missing, the recursion guard), asked
        # first: a refused run starts no shell, so it must not delete the reports of a
        # run that did. run_ash_nix asks them again for a caller that reaches it directly.
        nix_preflight()
        sweep_leftovers_before_run(opts.oci_runner)
        sweep_env_dirs()
        _discard_prior_run_artifacts(opts, logger)

        # Written into the results file by the inner run when it completes, so a file it
        # did not finish is not read back as a verdict. See utils/inner_run_outcome.py.
        outer_run_id = new_outer_run_id()
        nix_result = run_ash_nix(
            argv=_nix_inner_argv(opts), debug=opts.debug, outer_run_id=outer_run_id
        )
    except NixModeRefused as e:
        # `nix` missing, or the recursion guard. A message and exit 1, not a traceback.
        # 1 rather than the usage-error code: the command line is valid, and what is
        # missing is a tool on this host, which is what 1 reports for a MISSING scanner.
        # stderr via echo, shown not obeyed: the message names a URL and flags,
        # not Rich markup.
        echo(str(e), err=True)
        sys.exit(1)

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

    # One of ASH's own codes outside the three a results file decides (3 for an
    # input or config the scan inside refused, 4 for a workspace error, 5 for a
    # usage error) is the inner ASH's answer: it refused before scanning and its
    # own output says what. Carried as the host's exit code, as in container mode,
    # BEFORE any read-back: a results file left in the directory (one
    # --use-existing kept, say) is an earlier run's, and reading it back would
    # re-word the refusal as "did not complete" with exit 1. 0, 1 and 2 are
    # re-derived from the results file below, and any other status is nix's own
    # (it exits 1 for most failures and 100 and up for build failures), a shell
    # that never ran ASH.
    shell_code = nix_result.returncode
    ash_meaning = (
        None
        if shell_code in _CONTAINER_VERDICT_EXIT_CODES
        else ASH_EXIT_CODES.get(shell_code)
    )
    if ash_meaning is not None:
        logger.error(
            f"The scan inside the Nix shell exited with {shell_code} ({ash_meaning}), "
            "which means nothing was scanned; its own output above says what it "
            "refused, and no results file is read back as this run's."
        )
        sys.exit(shell_code)

    _refuse_links_left_in_reports(opts)
    _refuse_an_inner_run_that_was_refused(opts, outer_run_id)

    # The inner scan wrote to the same output directory this process was given, so unlike
    # container mode there is no path to translate back.
    _refuse_restored_results(
        opts.output_dir,
        "the Nix shell",
        logger,
        kept_on_purpose=bool(opts.existing_results),
    )
    output_file = opts.output_dir / "ash_aggregated_results.json"
    results = _read_back_inner_results(output_file, logger)
    if results is not None:
        _refuse_an_inner_run_that_did_not_complete(
            results, opts, outer_run_id, "nix", output_file, logger
        )
        _drop_restore_marker_after_a_completed_run(opts, logger)
        _take_own_values_for_record(results, opts, image_may_differ=image_may_differ)
        return results
    else:
        # No results file means the inner scan never got far enough to write one, so the
        # shell's own exit code is the only diagnostic available. Reporting it here is the
        # difference between an actionable error and a bare "file not found". One of
        # ASH's own refusal codes was carried above, before the read-back; what
        # reaches here is a results-file code with no file, or nix's own status (it
        # exits 1 for most failures and 100 and up for build failures), reported as
        # 1, a scan that did not run.
        logger.error(
            f"Results file not found at {output_file}. The Nix shell exited with "
            f"code {shell_code}."
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# _run_local_mode
# ---------------------------------------------------------------------------


def _changed_file_set_for(
    opts: ScanOptions, logger, values: Tuple[str, ...] = ()
) -> Optional[Set[Path]]:
    """The --changed-files-only set for a local scan, or None for no filter.

    None when the flag was not given, and when it falls back to a full scan
    (no repository root, or git could not produce the diff). Starts git, so
    _run_local_mode calls it only once ASHScanOrchestrator.create has accepted
    the command line. ``values`` are the run's environment-read values, for
    the git stderr line a root-problem clause can quote.
    """
    if not opts.changed_files_only:
        return None
    from automated_security_helper.utils.get_scan_set import (
        get_changed_files,
        git_repository_root,
        git_repository_root_problem,
    )
    from automated_security_helper.utils.undecodable_text import resolve_uri_reading

    # The diff is anchored on the repository root, never on source_dir.
    # get_changed_files wraps `git diff --name-only`, which prints
    # repository-root-relative paths whatever directory it ran in, so joining
    # them onto source_dir is only correct when the two coincide. Under
    # `--source-dir services/api` inside a larger repository joining would give
    # <source_dir>/services/api/app.py, while the filter (utils.changed_files)
    # resolves the SARIF side's source-relative URIs (made so by
    # sanitize_sarif_paths) to <source_dir>/app.py -- two sets that cannot
    # intersect, so the filter would discard every finding.
    # workspace/execution.py:changed_file_set anchors on the root too; this is
    # the same resolution.
    repository_root = git_repository_root(opts.source_dir, values=values)
    if repository_root is None:
        # The root is the only anchor, so there is nothing to resolve against.
        # Report every finding, the fallback get_changed_files already
        # documents for its own unanswerable cases, rather than guess a root.
        # The cause, not a guess at it: a missing git is named as missing, not
        # as "not inside a git repository" for a directory that is one.
        # NO_MARKUP: the problem carries a path and git's own text, and a "[/"
        # in either is a closing Rich tag that raises instead of printing.
        logger.warning(
            f"--changed-files-only was requested but "
            f"{git_repository_root_problem(opts.source_dir, values=values)}; "
            f"reporting every "
            f"finding in {opts.source_dir.as_posix()}.",
            extra=NO_MARKUP,
        )
        return None
    changed_paths = get_changed_files(base_ref=opts.base_ref, cwd=opts.source_dir)
    if changed_paths is None:
        return None
    # Entries outside source_dir are dropped because --source-dir and
    # --changed-files-only are two scopings and the operator asked for
    # both, so what gets reported is their intersection. Only one input
    # notices: a scanner that escapes the scan root with a `../` URI
    # sanitize_sarif_paths did not make source-relative is not revived
    # by its file being in the diff. An empty result here is a filter
    # that matches nothing, which is the honest answer when nothing in
    # the diff is in scope -- see utils.changed_files, which
    # distinguishes that from None.
    # Through resolve_uri_reading, the one guard for resolving a name that may
    # not be a file's (utils.undecodable_text): an entry that cannot be resolved
    # names no file inside the source directory, so it is skipped rather than
    # raising out of the set construction -- a committed symlink loop
    # (`loop -> loop`) in the diff raises RuntimeError from a bare resolve on
    # CPython 3.10-3.12 (check_eloop; 3.13 stopped that). Workspace mode's
    # changed_file_set reads such a name the same way: the entry does not join
    # the set, and the other entries still scope the report.
    resolved_source = opts.source_dir.resolve()
    return {
        candidate
        for candidate in (
            resolve_uri_reading(str(p), base=repository_root) for p in changed_paths
        )
        if candidate is not None and candidate.is_relative_to(resolved_source)
    }


def _refuse_an_unknown_severity_restriction(restriction: Optional[str]) -> None:
    """Refuse a severity restriction that names no threshold, with exit 3.

    The restriction is an option the caller hands the scan (an MCP client's
    ``severity_threshold``). The orchestrator refuses an unknown one with an
    ``ASHValidationError``, which this module's generic handler reads as a
    crash and exits 1 for; it is an input ASH cannot use, as an invalid
    configuration is, so it is refused here, before anything is built, as the
    configuration refusal (exit 3). A blank value means no restriction.
    """
    from automated_security_helper.utils.severity_ladder import normalize_threshold

    if restriction is None or not restriction.strip():
        return
    if normalize_threshold(restriction) is None:
        raise ASHConfigValidationError(
            f"The severity threshold {restriction!r} is not one of ALL, LOW, "
            "MEDIUM, HIGH or CRITICAL."
        )


def _run_local_mode(
    opts: ScanOptions, logger
) -> tuple[AshAggregatedResults, Optional[bool]]:
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    # Before this run starts any process, so none of them inherits it. See
    # utils/inner_run_outcome.py.
    outer_run_id = take_outer_run_id()

    # Through utils/process_env.py rather than os.environ directly: an MCP server
    # runs this in an executor thread while other scans may be spawning, and the
    # helper's lock is what keeps their environment copies consistent. Held rather
    # than set and restored: with two offline scans overlapping in one process, the
    # first to end would put back "unset" while the other still runs, and the last
    # would put back the first one's "YES". The last release restores what the
    # process started with, so an ASH_OFFLINE=YES it was started with survives.
    #
    # The imports sit above the hold: one that raised between the hold and its try
    # would leave ASH_OFFLINE held with no release. Nothing but the flag assignment
    # sits between the hold and its try, as in _run_workspace_mode.
    from automated_security_helper.utils.get_scan_set import git_repository_root
    from automated_security_helper.utils.scan_source import recorded_scan_source

    _offline_held = False
    if opts.offline:
        hold_environ("ASH_OFFLINE", "YES")
        _offline_held = True

    try:
        if not opts.quiet and not opts.simple:
            logger.verbose(f"Source directory: {opts.source_dir.as_posix()}")
            logger.verbose(f"Output directory: {opts.output_dir.as_posix()}")
            logger.verbose(f"Scanners specified: {opts.scanners}")
            logger.verbose(f"Scanners excluded: {opts.excluded_scanners}")

        # The configuration is resolved once, by the orchestrator below, which also
        # discovers a file when --config names none and announces it once it has
        # loaded. Nothing here discovers or announces one, so the log never says
        # "Using config file found at" for a file the run has not read, or
        # "specified at" for a --config that does not exist.
        config = opts.config
        if config is not None:
            _refuse_a_named_config_that_is_not_a_file(config)
        _refuse_an_unknown_severity_restriction(opts.severity_threshold_restriction)

        if opts.config_overrides:
            logger.info(
                f"Applying {len(opts.config_overrides or [])} configuration overrides"
            )

        final_scanners = list(opts.scanners or [])
        if opts.mode == RunMode.precommit:
            final_scanners = list(set(final_scanners + list(PRECOMMIT_MODE_SCANNERS)))

        final_show_progress = _live_progress_enabled(opts)

        orchestrator = ASHScanOrchestrator.create(
            source_dir=opts.source_dir,
            output_dir=opts.output_dir,
            work_dir=opts.output_dir / ASH_WORK_DIR_NAME,
            enabled_scanners=final_scanners,
            excluded_scanners=list(opts.excluded_scanners or []),
            config_path=config,
            config_overrides=opts.config_overrides or [],
            config_base_gate=opts.config_base_gate,
            untrusted_config=opts.untrusted_config,
            remote_client=opts.remote_client,
            trusted_config_path=opts.trusted_config_path,
            client_overrides=opts.client_overrides,
            client_config_policy=opts.client_config_policy,
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
            severity_threshold_restriction=opts.severity_threshold_restriction,
            keep_previous_results=opts.keep_previous_results,
        )
        # A discovered file was announced by the resolution that loaded it; a named
        # one is announced here, from that same resolution's record, so neither is
        # named unless it actually loaded.
        loaded_from = getattr(
            getattr(orchestrator, "config", None), "_loaded_from", None
        )
        if config is not None and loaded_from is not None:
            from automated_security_helper.config.config_sources import (
                describe_config_path,
            )

            # One line: the path is the caller's text.
            logger.info(
                shown_on_one_line(
                    f"Using ASH configuration from {describe_config_path(loaded_from)}"
                )
            )
        # Only now, after create(): it is where an invalid configuration or plugin
        # option and an unusable scanner selection stop the command, and a command
        # line ASH refuses starts no process. Both of these start git.
        #
        # The engine drops findings outside the changed files before the summary
        # counts and every report are written. None: no filter (the flag was not
        # given, or it fell back to a full scan). Empty: matches nothing.
        from automated_security_helper.utils.error_text import (
            config_environment_values,
        )

        # The values to hide in the git-root problem clause are the LOADED
        # config's environment reads (the orchestrator's model), not the --config
        # path string ``config`` holds, which has none to give.
        _changed_file_set = _changed_file_set_for(
            opts,
            logger,
            values=config_environment_values(getattr(orchestrator, "config", None)),
        )
        if _changed_file_set is not None:
            orchestrator.restrict_to_changed_files(_changed_file_set)
        orchestrator.add_metadata(
            # Recorded on every result set, so a reporter that reads "not
            # reported" as "fixed" (aws-security-hub can archive such findings)
            # knows whether the changed-files filter removed findings that are not
            # fixed. True when a changed-file set was computed; False otherwise,
            # also when the flag fell back to a full scan. Always explicit, so
            # results that predate the marker are told apart from a full scan.
            changed_files_only=_changed_file_set is not None,
            # Beside the marker, for the same reporter: the directory the scan
            # looked at, recorded at scan time while it exists
            # (utils/scan_source.py; a report made on another host cannot work it
            # out, and inside the container the launcher's label is used).
            scan_source=recorded_scan_source(
                opts.source_dir, git_repository_root, snapshot_environ()
            ),
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

        # With keep_previous_results the caller settles the previous results, after
        # this function's last cancellation check below and after its own. Without
        # it nothing was set aside, and the call is the one the CLI always made.
        settle: Dict[str, bool] = (
            {"settle_on_success": False} if opts.keep_previous_results else {}
        )
        results = orchestrator.execute_scan(
            phases=cast(List[ExecutionPhaseType], phases_to_run), **settle
        )

        if opts.simple and not opts.quiet:
            echo("\nASH scan completed.")

        # A run whose report phase did not run (--phases without report) wrote no
        # report file, and says so: a reports/ash.sarif something else wrote is not
        # its report.
        if isinstance(results, BaseModel) and not records_reports_written(results):
            record_reports_written(results, [])
        # The run completed: as the inner run of a container or nix scan, say so for
        # the outer process, replacing any record an earlier run left in a results
        # file read back with --use-existing. See utils/inner_run_outcome.py.
        mark_run_completed(results, outer_run_id)
        if isinstance(results, BaseModel):
            content = results.model_dump_json(indent=2, by_alias=True)
        else:
            content = json.dumps(results, indent=2, default=str)

        # A scan cancelled after its last phase began must not leave a results
        # file behind: a client polling a cancelled scan reads that file as
        # finished results. A no-op outside a cancellable scan.
        raise_if_cancelled()

        # This rewrite lands after the REPORT phase, while an MCP client that has seen
        # the reports appear may already be re-reading this file for progress. A
        # truncating open() hands that reader an empty file, so replace it atomically.
        output_file = opts.output_dir / "ash_aggregated_results.json"
        write_text_atomically(output_file, content)

        return results, _config_fail_on_findings

    # Each message below quotes text the operator or the scanned repository wrote --
    # a scanner name from --scanners, a config value, an exception's text -- so
    # _printed_refusal escapes it: rich.print reads every string as markup.
    except (ASHConfigFieldDeniedError, ASHConfigPolicyUnreadableError) as e:
        # An MCP caller passed the rules, and it records the error it is handed
        # as the scan's; an exit code would leave the client with "exited with
        # code 3" and the fields named only in the server log.
        if opts.client_config_policy is not None:
            raise
        # The shared printer escapes the text, which names fields and a path.
        _print_invalid_config(e)
        sys.exit(3)
    except ASHConfigValidationError as e:
        _printed_config_refusal(3, e)
    except ScannerSelectionError as e:
        # Ahead of the generic handler, and without logger.exception, because this is
        # a mistyped argument rather than a fault: a traceback would bury the one
        # line that says which name did not resolve and what the valid names are.
        # The usage-error code, the one every other refused argument exits with:
        # not 3, which means the config file is invalid when this operator's config
        # is fine, and not 1, which means a scan failed when none was attempted.
        # One line: the names are the caller's text, as typed.
        _printed_refusal(ASH_EXIT_USAGE_ERROR, error_text(e), one_line=True)
    except ExistingResultsRefused as e:
        # --use-existing named results that hold no scan: reported on, they would
        # read as a clean one. An input ASH cannot use, as an invalid config is, so
        # exit 3; not a fault, so no traceback. The message names the file and
        # quotes nothing from it.
        print(f"[bold red]ERROR (3) {escape_markup(str(e))}[/bold red]")
        sys.exit(3)
    except ReportPathRefused as e:
        # A report path was refused: by the report phase before any reporter wrote
        # (a link at the reports directory or at a report file, a report file name
        # that is not a file in the reports directory, or two reporters writing one
        # file). Not a fault, so no traceback. As the
        # inner run of a container or nix scan, recorded beside the results file
        # for the outer process; if that fails, the outer process finds no record
        # of this run's completion and exits 1 all the same.
        _record_inner_refusal(opts, e, outer_run_id, logger)
        _refuse_report_path_link(e)
    except Exception as e:
        # Redacted with the values the run's config read from the environment,
        # which the orchestrator records on an error raised while it was built:
        # error_text and log_unexpected_error read them off the error. (A
        # plugin module that crashes at import does not land here; it is
        # the exit-3 refusal above.) One
        # line: the error's text can name a path, and error_text names an
        # OSError's files as given.
        log_unexpected_error(logger, e)
        _printed_refusal(
            1,
            f"Exiting due to exception during ASH scan: {error_text(e)}",
            one_line=True,
        )
    finally:
        if _offline_held:
            release_environ("ASH_OFFLINE")


# ---------------------------------------------------------------------------
# Workspace mode
# ---------------------------------------------------------------------------


def _resolve_workspace_execution_config(opts: ScanOptions):
    """Read the workspace execution knobs from the workspace root's ASH config.

    The workspace root's config, not a project's: how many projects run at once
    is not a project's decision, and a project that set it would be overriding a
    sibling. The defaults apply when there is no config file. A config file that
    is named (``--config``, an MCP profile) or discovered and cannot be loaded
    raises ``ASHConfigValidationError`` (exit 3), the way the same file refuses a
    single-directory scan: the file was meant to configure this run, and running
    without it is not the run the operator asked for.
    """
    return resolve_workspace_execution_config(
        opts.source_dir,
        opts.config,
        opts.config_base_gate,
        remote_client=opts.remote_client,
        session_id=getattr(opts.client_config_policy, "session_id", None),
    )


def resolve_workspace_execution_config(
    workspace_root: Path,
    config: Optional[str] = None,
    permit: Optional[Callable[[Path], bool]] = None,
    remote_client: bool = False,
    session_id: Optional[str] = None,
):
    """``_resolve_workspace_execution_config`` from its inputs.

    Public so workspace planning (``ash scan --workspace ... --dry-run`` and MCP
    ``resolve_workspace``) refuses the workspace root's config exactly as the
    run does: a plan reported as fine for a config the run refuses with exit 3
    would answer the question a dry run exists to ask the wrong way. A discovery
    that refuses a source raises as it does for a scan. ``remote_client`` and
    ``session_id`` are as for ``_load_with_confinement``.
    """
    import yaml

    from automated_security_helper.config.ash_config import (
        WorkspaceExecutionConfig,
    )
    from automated_security_helper.config.config_sources import (
        describe_config_path,
        is_config_parse_error,
        unparsed_config_reason,
    )
    from automated_security_helper.config.operator_only_options import (
        repository_settings_for_root,
    )
    from automated_security_helper.core.exceptions import (
        ASHConfigSourceError,
        ASHConfigValidationError,
    )

    config_path_str = config
    if config_path_str is None:
        config_path_str = _discovered_config_path(workspace_root, permit=permit)

    if config_path_str is None:
        return WorkspaceExecutionConfig()

    path = Path(config_path_str)
    unparsed: Optional[str] = None
    # Under the scan's own confinement and ownership: without them this load
    # refused, with exit 3, a chain the scan itself takes -- a repository
    # file's write for an operator-only option, which the confine strips as
    # the file is read, or an operator pointer the ownership fold lands on
    # the operator's own key. Neither knob this loader answers is a confined
    # row, so the confine changes nothing it returns.
    settings = repository_settings_for_root(workspace_root)
    try:
        return _load_with_confinement(
            config_path_str,
            workspace_root,
            permit,
            remote_client=remote_client,
            session_id=session_id,
            confine=settings.confine,
            repository_file=settings.is_repository_file,
        ).workspace
    except ASHConfigValidationError:
        raise
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError) as exc:
        # json.JSONDecodeError and UnicodeDecodeError are ValueErrors. A model
        # refusal arrives above, as an ASHConfigValidationError.
        if not is_config_parse_error(exc):
            verb = "read" if isinstance(exc, OSError) else "parse"
            raise ASHConfigSourceError(
                f"could not {verb} {describe_config_path(path)}: {error_text(exc)}"
            ) from exc
        # The parser's own words can quote the file (unparsed_config_reason).
        unparsed = unparsed_config_reason(path, exc)
    if unparsed is None:
        # Reached only through the handler above; a future path that falls
        # through without binding fails here, not with a "None" refusal.
        raise AssertionError("the load neither returned nor raised")
    # Outside the handler, so the parser's error is not its context.
    raise ASHConfigSourceError(unparsed)


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
    An ASH config at the workspace root (or named by ``opts.config``) that cannot
    be loaded raises ``ASHConfigValidationError`` from
    ``_resolve_workspace_execution_config``, as the same file does for a
    single-directory scan. ``_run_workspace_mode`` exits 3 on it, and the MCP
    path maps it to exit code 3 (``cli/mcp/workspace._EXIT_CODE_BY_EXCEPTION``),
    so it is reported as an invalid configuration, not an internal error.
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
        selection_origin=opts.selection_origin,
        output_formats=tuple(
            getattr(fmt, "value", str(fmt)) for fmt in (opts.output_formats or [])
        ),
        config_overrides=tuple(opts.config_overrides or []),
        client_overrides=opts.client_overrides,
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
        # The MCP session's gate, the same one the plan was resolved with.
        config_base_gate=opts.config_base_gate,
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
        keep_previous_results=opts.keep_previous_results,
        # ``opts.config`` in workspace mode is the operator's config: a project
        # with no config of its own uses it, and the plan records it as the
        # ``operator_config`` layered over a project's own ``.ash.yaml``, whose
        # fields it does not set stay the project's (resolver
        # ``_resolve_project_config``).
        #
        # The caller has to pass the same value as ``resolve_workspace``'s
        # ``default_config``, because the plan's reported threshold comes from
        # resolution and the scan's config from execution. Dropping it here -- which
        # this builder did -- made an MCP client's `profile` argument accepted,
        # threaded through two layers, and silently ignored, which is the same
        # shape of defect as the ``ASH_OFFLINE`` one recorded in cli/mcp/workspace.
        default_config_path=opts.config,
        # The registered profile ``opts.config`` is resolved against when an MCP
        # client patched the session's copy; None takes ``opts.config``.
        trusted_config_path=opts.trusted_config_path,
        # The rules a project config an MCP client delivered is checked against.
        # The same value the plan was resolved with, for the reason above.
        client_config_rules=opts.client_config_policy,
        # Which project configs resolve no !ENV. Also the plan's, for that reason.
        remote_client=opts.remote_client,
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

    # Before this run starts any process, so none of them inherits it. See
    # utils/inner_run_outcome.py.
    outer_run_id = take_outer_run_id()

    # Built before ASH_OFFLINE is set, preserving the order the inline
    # construction had: the builder reads a config file off disk, and doing that
    # with the offline flag already in the environment is a different read.
    try:
        settings = build_project_scan_settings(opts)
    except ASHConfigValidationError as exc:
        # The shared printer escapes the error's text, which names a path:
        # printed raw, a bracket sequence in it raised MarkupError out of this
        # handler instead of exiting 3.
        _print_invalid_config(exc)
        sys.exit(int(WorkspaceExitCode.INVALID_PROJECT_CONFIG))

    # Held and released through utils/process_env.py; see _run_local_mode.
    _offline_held = False
    if opts.offline:
        hold_environ("ASH_OFFLINE", "YES")
        _offline_held = True

    try:
        result = execute_workspace(opts.workspace_plan, settings)
        if outer_run_id is not None:
            # The inner run of a container scan: say it completed, for the outer
            # process, after the report step. Stamped into the file the aggregator
            # streamed rather than by loading it. See utils/inner_run_outcome.py.
            from automated_security_helper.workspace.aggregation import (
                stamp_run_record,
            )

            if not stamp_run_record(
                result.results_path, completion_marker(outer_run_id)
            ):
                logger.warning(
                    f"Could not record in {result.results_path} that this run "
                    "completed; the outer process will report that it did not."
                )
        return result
    except WorkspacePathNotUtf8Error as exc:
        # Its paths are as they are, and the message is one line: shown once, as
        # a whole, so a newline in a name is written \x0a.
        echo(shown_on_one_line(str(exc)), err=True)
        sys.exit(int(WorkspaceExitCode.WORKSPACE_ERROR))
    except WorkspaceDefinitionError as exc:
        # A refusal, not a project failure: nothing was scanned, so there is no
        # results file and the exit-2 collision is unambiguous. See
        # models.workspace for the discriminator. Shown, not obeyed: the message
        # names the workspace file's projects and paths.
        echo(error_text(exc), err=True)
        # from None: formatting the exit would otherwise print the handled
        # error's own text where only the described form was shown.
        raise ScanRefusedExit(
            int(WorkspaceExitCode.WORKSPACE_ERROR), error_text(exc)
        ) from None
    # Escaped for the same reason as in _run_local_mode.
    except ASHConfigValidationError as exc:
        _printed_config_refusal(int(WorkspaceExitCode.INVALID_PROJECT_CONFIG), exc)
    except ScannerSelectionError as exc:
        # The same mistyped argument _run_local_mode refuses, raised here by
        # execute_workspace before any project starts, on one line as there.
        _printed_refusal(
            int(WorkspaceExitCode.USAGE_ERROR), error_text(exc), one_line=True
        )
    except ReportPathRefused as exc:
        # Exit 1, as in a single-directory scan: a link at a report path, or a file
        # name outside the reports directory, is not a workspace definition error.
        # Recorded beside the unified results, which keep what the projects wrote.
        _record_inner_refusal(opts, exc, outer_run_id, logger)
        _refuse_report_path_link(exc)
    except Exception as exc:
        # Redacted with the values the workspace's configs read from the
        # environment, which the prewarm records on an error raised while it
        # imported the plugin modules, and on one line (cf. _run_local_mode).
        log_unexpected_error(logger, exc)
        _printed_refusal(
            int(WorkspaceExitCode.INTERNAL_ERROR),
            f"Exiting due to exception during ASH workspace scan: {error_text(exc)}",
            one_line=True,
        )
    finally:
        if _offline_held:
            release_environ("ASH_OFFLINE")


def _print_text(*parts: Union[str, Tuple[str, str]]) -> None:
    """Print one line built from *parts*, reading no Rich markup in them.

    A part is a string, or a ``(string, style)`` pair for the words this module
    styles. Paths, project labels and error text go in as strings, so a bracket in
    them prints as given: through markup, ``[/x]`` raised MarkupError and
    ``[bold]`` vanished. Escaping them instead is not exact either:
    ``rich.markup.escape`` doubles a trailing backslash wherever no tag follows,
    so an escaped ``C:\\out\\`` joined to ``/reports`` printed
    ``C:\\out\\\\/reports``. Emoji codes are left alone for the same reason. The
    console's highlighter still runs on every part, styled or not, as it does for
    a printed string.

    Each part is shown, not obeyed (utils/terminal_text.py): a path's controls are
    written as escapes, so an OSC 52 in one does not set the clipboard, and an
    output directory read from a byte that is not UTF-8 (a lone surrogate) neither
    raises on a strict stdout nor writes the byte on a lenient one.
    """
    console = global_console()
    rendered = []
    for part in parts:
        text, style = part if isinstance(part, tuple) else (part, "")
        line = console.render_str(shown_not_obeyed(text), markup=False, emoji=False)
        # Over the highlighter's spans, as "[yellow]...[/yellow]" printed: its color
        # wins and the highlighting adds only bold. As the base style it sat under
        # them, so quoted words came out green. render_str applies its own style=
        # only when it reads markup.
        if style:
            line.stylize(style)
        rendered.append(line)
    console.print(Text.assemble(*rendered))


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
    # The single-scan summary's rule (display_path): relative to the working
    # directory, else absolute, and the host's path inside the container image.
    out_dir_alias = os.environ.get(
        "ASH_ACTUAL_OUTPUT_DIR", display_path(opts.output_dir)
    )

    def _under_output(path: Path) -> str:
        path = Path(path)
        if path.is_relative_to(opts.output_dir):
            relative = path.relative_to(opts.output_dir).as_posix()
            return out_dir_alias if relative == "." else f"{out_dir_alias}/{relative}"
        return display_path(path)

    # Paths, project labels and error text go through _print_text, so a bracket in
    # them prints as given rather than as markup.
    _print_text(f"  workspace: {display_path(result.payload.workspace_file)}")
    _print_text(f"  output:    {out_dir_alias}")
    print("")

    for entry in result.payload.projects:
        if entry.status.value == "skipped":
            reason = entry.skip_reason.value if entry.skip_reason else "unspecified"
            _print_text(
                "  ", ("skipped", "yellow"), f"  {entry.display_label} ({reason})"
            )
            continue
        if entry.status.value == "failed":
            _print_text(
                "  ",
                ("failed", "bold red"),
                f"   {entry.display_label}: {entry.error}",
            )
            continue
        # An incomplete project fails like one over its threshold: it exits 1, and
        # "pass" beside it contradicted the run's own status.
        failing = entry.exceeds_threshold or entry.scan_incomplete
        colour = "bold red" if failing else "green"
        verdict = "FAIL" if failing else "pass"
        incomplete = ""
        if entry.incomplete_scanners:
            incomplete = "; incomplete: " + ", ".join(entry.incomplete_scanners)
        elif entry.scan_incomplete:
            incomplete = "; incomplete"
        _print_text(
            "  ",
            (verdict, colour),
            f"     {entry.display_label} -- "
            f"{entry.actionable_finding_count} actionable of "
            f"{entry.finding_count} at threshold "
            f"{entry.severity_threshold or 'none'} "
            f"({entry.duration_seconds:.1f}s){incomplete}",
        )

    # Each project's inputs a scanner did not scan, as a single-directory scan lists
    # its own beside the table (metrics_table.print_inputs_not_scanned).
    not_scanned = [
        item for entry in result.payload.projects for item in entry.inputs_not_scanned
    ]
    if not_scanned:
        # Imported here: metrics_table loads ash_config, which importing this
        # module must not (test_forward_ref_resolves_in_any_import_order.py).
        from automated_security_helper.core.metrics_table import not_scanned_line

        print("")
        for item in not_scanned:
            print(f"  {not_scanned_line(item.scanner, item.path, item.reason)}")

    print("")
    _print_text(f"  Aggregated results: {_under_output(result.results_path)}")
    _print_text(f"  Per-project output: {_under_output(opts.output_dir / 'projects')}")
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
#      fail_on_incomplete_scanners, default ON, exit 1. CI additionally runs
#      .github/scripts/assert_scanners_completed.py, which asserts the same thing
#      with no flag of its own, so a leg whose ASH invocation was edited to pass
#      --no-fail-on-incomplete-scanners still fails rather than going quiet.
#   2. Did they find anything actionable? Gated by fail_on_findings, default on,
#      exit 2.
#
# Deriving the verdict from finding counts alone -- which is what this function
# did -- cannot tell "nothing was wrong" from "nothing was checked", because both
# produce zero findings. Measured on this tree: a scan with four of ten scanners
# MISSING exits 0, and a deployed run with five MISSING or ERROR reported a clean
# scan of a repository a working scan flags at HIGH.
# ---------------------------------------------------------------------------


def report_sarif_identity(output_dir: Path) -> Optional[Tuple[int, int, int, int]]:
    """Identify the ``reports/ash.sarif`` under *output_dir* as it is now.

    ``(st_dev, st_ino, st_mtime_ns, st_size)``, or None when there is no such file.
    Taken before and after a run, it tells whether the run wrote the file: the
    report phase replaces it atomically (a new inode), so a file the run did not
    write keeps its identity. See ``_compute_exit_code``'s
    ``report_sarif_written_this_run``.

    Only a regular file has one, read with lstat: stat follows a symlink, so
    through it a link at ash.sarif to another report this run rewrites (one that
    survives into the run under --use-existing, or in ``ash merge`` into a
    reused directory) would read as written this run, and the gate would count
    that file.
    """
    try:
        status = os.lstat(Path(output_dir).joinpath("reports", "ash.sarif"))
    except OSError:
        return None
    if not stat.S_ISREG(status.st_mode):
        return None
    return (status.st_dev, status.st_ino, status.st_mtime_ns, status.st_size)


def _compute_exit_code(
    results: Optional[AshAggregatedResults],
    opts: ScanOptions,
    config_fail_on_findings: Optional[bool] = None,
    config_fail_on_incomplete_scanners: Optional[bool] = None,
    report_sarif_written_this_run: Optional[bool] = None,
    actionable_count: Optional[int] = None,
) -> int:
    """The exit code for *results*.

    *actionable_count* is :func:`_gating_actionable_count`'s answer when the
    caller has read it already (``run_ash_scan`` reads it once for the exit code,
    the summary and the legend together); None reads it here, as ``ash merge``
    has it read.

    *report_sarif_written_this_run* says whether ``reports/ash.sarif`` is this
    run's (see ``report_sarif_identity``). False keeps the gate off the file, so
    an ash.sarif an earlier run left there (``--use-existing``, a report phase
    without the sarif format, ``ash merge`` into a reused directory) is not read
    and cannot decide the exit code against what every report of this run says.
    None, for a caller that cannot tell, reads the file when it exists.
    ``run_ash_scan`` and ``ash merge`` always say.
    """
    # Each reason below goes to ASH's logger, so it reaches ash.log and the console
    # as every other message does: this module's own logger is not under "ash",
    # and logging's last resort wrote to stderr only. Each quotes names a shard
    # chose under `ash merge`, so the whole message is shown on one line here and
    # logged as text, which the sinks pass on as it is.
    if results is None:
        ASH_LOGGER.error(
            shown_on_one_line("ASH scan produced no results — scan may have crashed")
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
    #
    # Every coverage arm below, and the unevaluated-rule arm after the gate, reads
    # its answer from this one object. The MCP runner acts on the same object (see
    # ScanIncompleteness), so the status a client is shown and the exit code here
    # come from the same reads. The arms stay separate for their order and their
    # messages.
    gate_on = _resolve_fail_on_incomplete_scanners(
        results, opts, config_fail_on_incomplete_scanners
    )
    incompleteness = scan_incompleteness(
        results,
        gate=gate_on,
        # The exemption is explained at the set-level arm below.
        one_shard_of_a_split=(
            getattr(opts, "shard_index", None) is not None
            or getattr(opts, "shard_count", None) is not None
        ),
    )

    # Every exit-1 arm below logs its cause and sets this flag instead of
    # returning, with one return after the last arm. A run usually trips several
    # arms at once (a stop that failed also left an ERROR row), and an arm that
    # returned hid every later cause: an operator working from ash.log fixed and
    # re-ran once per cause. The log is complete, not ordered -- the arms' order
    # decides which cause is named first, never which causes are named at all.
    failing = False

    # A tool ASH could not stop may still be running, and it can write into the
    # output directory after this code has read it, so the report is not final.
    # That ending fails the run whatever `fail_on_incomplete_scanners` says: the
    # gate is the operator accepting partial coverage, not an unfinished write.
    # Ahead of the gate arms, which the same run usually also trips, so the one
    # cause no setting can silence is the first one named. Read from
    # `incompleteness`, like every arm below, so the exit code and the MCP
    # payload answer from the same object.
    could_not_stop = list(incompleteness.could_not_stop)
    if could_not_stop:
        ASH_LOGGER.error(
            shown_on_one_line(
                f"Scan failed: {len(could_not_stop)} scanner tool(s) could not "
                "be stopped and may still be running: "
                + ", ".join(name for name, _ in could_not_stop)
            ),
            extra=NO_MARKUP,
        )
        for _name, reason in could_not_stop:
            ASH_LOGGER.error(shown_on_one_line(reason), extra=NO_MARKUP)
        failing = True

    if gate_on:
        # Two reads of the metrics rather than one, and the second is not a
        # duplicate of the first. `incomplete_scanners` no longer answers from status
        # alone -- it also reports a scanner that ran and lost some of its targets,
        # which needs the per-metric target counters -- so its result cannot be
        # derived from a list of (name, status) pairs. An earlier form of this merge
        # did exactly that, and it dropped the partial-coverage arm out of the exit
        # code entirely while the file looked clean.
        observed = list(incompleteness.observed)
        incomplete = list(incompleteness.scanners)
        if incomplete:
            # Shown, and logged as text rather than markup: under `ash merge` the
            # names are the shards', and one holding a newline put a line
            # "::error ..." on stdout.
            ASH_LOGGER.error(
                shown_on_one_line(
                    "Scan incomplete: "
                    + ", ".join(f"{name} ({status})" for name, status in incomplete)
                ),
                extra=NO_MARKUP,
            )
            failing = True

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
        # its docstring says that reading the JSON status rather than the rendered
        # report means the guard and ASH's own exit code "read the same field", and
        # on this exact input they did not agree. An operator running `ash scan` got
        # 0 from the same results file the CI gate exits 1 on.
        #
        # Inside the fail_on_incomplete_scanners gate rather than beside it. The
        # committed contract for --no-fail-on-incomplete-scanners is that a scan
        # whose scanners did not run still exits 0 -- that is what
        # test_cli_false_overrides_config_true pins, for a run whose only scanner
        # is MISSING, which measured nothing just as thoroughly as an all-SKIPPED
        # one. Making this one check unconditional would answer that same question
        # two different ways depending on which status the non-running scanners
        # happened to land on. The flag defaults ON, so the case above now exits 1
        # unless a config or an operator turns the gate off -- but it can still be
        # turned off, which is why .github/scripts/assert_scanners_completed.py
        # asserts it unconditionally and why that script rather than this function
        # is what holds the line in CI. An operator who turns the gate off has said
        # they accept a scan that did not run.
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
        # the assertion the individual shards are excused from. scan_incompleteness
        # applies that exemption, from the shard fields passed to it above.
        #
        # Gated on the per-entry arm having found nothing, because this arm is
        # that arm's residual rather than an independent cause: its message
        # states that every scanner was skipped, which is false whenever the
        # arm above has already named a MISSING or ERROR scanner, and a
        # diagnosis of "nothing ran" would misdirect from the named one.
        if not incomplete and incompleteness.no_scanner_ran:
            # The selected scanners all had nothing to scan (each SKIPPED with a
            # count of 0): say that, rather than suggest a selection mistake.
            nothing_to_scan = scanners_with_nothing_to_scan(results)
            # Shown and logged as text, as the arm above: `ash merge` reaches this
            # one too, since a shard set whose every scanner was SKIPPED merges.
            ran = ", ".join(f"{name} ({status})" for name, status in observed)
            ASH_LOGGER.error(
                shown_on_one_line(
                    nothing_to_scan_message(results, nothing_to_scan)
                    if nothing_to_scan
                    else f"Scan ran no scanners: {ran}. Every scanner was skipped, "
                    "so this run has shown the target to be neither clean nor dirty "
                    "-- most often a --scanners name that matches no scanner on "
                    "this platform, or an allowlist wholly cancelled by "
                    "--exclude-scanners."
                ),
                extra=NO_MARKUP,
            )
            failing = True

        # The same question asked of the convert phase, which produces the targets
        # the scanners above were given. A converter that crashed or whose tool was
        # absent leaves its inputs unscanned, and every scanner that did run still
        # reports PASSED on the targets it was handed, so no scanner-side signal can
        # see it.
        #
        # Behind fail_on_incomplete_scanners rather than behind a flag of its own,
        # and that placement is the decision worth recording. It is the same question
        # the two arms above ask -- did what I asked for actually run -- so it belongs
        # on the same switch. An operator who has settled how much an incomplete run
        # matters to them has settled it once, and gets one escape hatch covering
        # both halves instead of a second flag to discover.
        #
        # The consequence they will actually meet is that converters are more likely
        # than scanners to be legitimately absent on a given host, so this is the arm
        # that fires on a setup nobody thinks is broken. That is stated as a
        # consequence rather than as a reason to soften the gate: a converter that did
        # not run leaves its inputs unscanned whether or not anything is watching, and
        # the recorded converter_results row is what names which one it was.
        #
        # The argument above deliberately does not turn on which way
        # fail_on_incomplete_scanners defaults. That polarity is a separate decision,
        # made at the field and the flag rather than here, and a rationale leaning on
        # it would need rewriting every time it moves.
        #
        # 1 rather than 2, matching the two arms above: the reported findings are
        # real but the set is known to be partial, so clearing them does not clear
        # the scan.
        incomplete_conversions = list(incompleteness.converters)
        if incomplete_conversions:
            # The reason is the converter's own failure text, which `ash merge`
            # carries over from the shards. incomplete_converters showed it once;
            # shown here as part of the whole message, its escapes would be shown
            # again, so the text it was made from is read back first.
            ASH_LOGGER.error(
                shown_on_one_line(
                    "Conversion incomplete, so the scanners were given fewer targets "
                    "than this repository has: "
                    + ", ".join(
                        f"{row[0]} ({as_written(row[1])})"
                        for row in incomplete_conversions
                    )
                ),
                extra=NO_MARKUP,
            )
            failing = True

    # A rule that raised instead of reaching a verdict, which no other gate can see.
    #
    # NOT behind fail_on_incomplete_scanners, and that is the whole point of it being
    # here. This condition has no honest reading under which the scan was clean: the
    # tool was asked to evaluate a rule, it tried, and it failed. That is different
    # from the case the flag can be told to keep quiet, which is an environment
    # legitimately lacking a scanner's tool -- there the operator's setup explains the
    # gap, so letting them silence it is defensible. Nothing explains this one, so it
    # is not silenceable at all. The flag now defaults on, which narrows the practical
    # difference but not the reason: a gate that can be turned off and one that cannot
    # are different guarantees whatever the default is.
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
    unevaluated = list(incompleteness.unevaluated_rules)
    if unevaluated:
        # Rule ids and notification text from the SARIF, which a shard wrote under
        # `ash merge`.
        ASH_LOGGER.error(
            shown_on_one_line(
                f"Scan incomplete: {len(unevaluated)} rule(s) could not be evaluated, "
                "so this scan reports nothing about compliance with them: "
                + ", ".join(unevaluated)
            ),
            extra=NO_MARKUP,
        )
        failing = True

    # A scanner's content database past its declared bound, under the default
    # `content_db_staleness: fail`. Same placement and the same 1 as the gate above, for
    # the same reasons: not behind fail_on_incomplete_scanners, because nothing about an
    # operator's environment makes a stale vulnerability database a clean result, and
    # ahead of the fail_on_findings early return, because turning findings-gating off is
    # not asking to be told nothing about the database the findings came from.
    #
    # Read from the SARIF notification's level, which the scan set from the policy it ran
    # under, rather than re-resolving the policy here. That keeps the decision with the
    # results: container mode's host and `ash merge` both arrive here with a results
    # model and no reliable view of the config the inner scan used. The opt-out is
    # `--allow-stale-content-db` or `content_db_staleness: warn`, which writes the same
    # notification at level warning so it reaches the reports without failing the scan.
    #
    # Read from `incompleteness`, like every arm above, so that a stale database is one
    # condition with one exit code, one message and one MCP status (`incomplete`)
    # whether the completeness gate is on or off. With the gate on it is not ALSO
    # reported by the incomplete-scanner arm: `scan_incompleteness` drops a row that is
    # listed only for its stale database, and leaves it to this arm.
    stale = list(incompleteness.stale_content_databases)
    if stale:
        # Each record is read back from a SARIF notification, which a shard wrote
        # under `ash merge`.
        ASH_LOGGER.error(
            shown_on_one_line(
                f"Scan failed: {len(stale)} content database(s) are past their "
                "declared age bound: " + ", ".join(record.name for record in stale)
            ),
            extra=NO_MARKUP,
        )
        for record in stale:
            ASH_LOGGER.error(shown_on_one_line(record.message()), extra=NO_MARKUP)
        failing = True

    # One return for every arm above, after all of them have logged.
    if failing:
        return 1

    final_fail_on_findings: bool
    if opts.fail_on_findings is not None:
        final_fail_on_findings = opts.fail_on_findings
    elif config_fail_on_findings is not None:
        final_fail_on_findings = config_fail_on_findings
    elif results.ash_config is not None:
        # The configuration the run recorded: the one read the scan acted on.
        # ``config_fail_on_findings`` is a separate pre-read of the same file
        # (made before the run for the container command line), and a file
        # unreadable during the pre-read alone answers None there while the
        # run's own load succeeds, so a run with fail_on_findings false was
        # still gated by the default below and exited 2 (measured with the
        # read denied for the pre-read and allowed after). The default gates
        # only when neither read answered.
        final_fail_on_findings = results.ash_config.fail_on_findings
    else:
        final_fail_on_findings = True

    # The SARIF report this run's SARIF reporter wrote, under the name its extension
    # gave it. Not reports/ash.sarif as such: --use-existing keeps reports/, so with
    # no SARIF reporter selected the file there is an earlier run's, and another
    # reporter's extension can name it. Without such a report the model's own
    # findings are counted. See utils/inner_run_outcome.py.
    reports_dir = Path(opts.output_dir).joinpath("reports")
    sarif_name = report_file_written_as(results, "sarif")

    # Not read through a link, which would let the file it points to decide the exit
    # code. The report phase refuses one where the SARIF reporter writes; this covers
    # a run in which that reporter did not write it. Ahead of the fail_on_findings
    # return below, so a link left in reports/ refuses the run either way.
    found = linked_report_path(
        reports_dir, ["ash.sarif", *([sarif_name] if sarif_name else [])]
    )
    if found is not None:
        _refuse_report_path_link(ReportPathLinkRefused(found))

    if not final_fail_on_findings:
        return 0

    if actionable_count is None:
        actionable_count = _gating_actionable_count(
            results, opts, report_sarif_written_this_run
        )
    if actionable_count > 0:
        return 2
    return 0


def _is_a_regular_report_file(path: Path) -> bool:
    """Whether *path* is itself a regular file, read with lstat.

    stat, which ``Path.exists`` uses, follows a link, so a link to a file that
    exists answered True and a link to a pipe could be opened, and a pipe
    without a writer blocks the open.
    """
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def _gating_actionable_count(
    results: AshAggregatedResults,
    opts: ScanOptions,
    report_sarif_written_this_run: Optional[bool] = None,
) -> int:
    """The actionable-finding count the exit code is derived from.

    One function, so the summary and the exit-code legend name the number that
    gated: read from the persisted SARIF report when this run wrote it, each
    result judged under its own scanner's threshold, and zeroed when nothing at
    or above ``--min-severity`` is actionable. Printed from the in-memory metrics
    instead, "Exiting due to N actionable findings" could name a different N than
    the one that decided the exit.
    """
    reports_dir = Path(opts.output_dir).joinpath("reports")
    sarif_name = report_file_written_as(results, "sarif")
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
    # Only the SARIF report this run's SARIF reporter wrote (sarif_name above), and
    # only as a file in reports/: the name comes from the results file, which in
    # container and nix mode another process wrote.
    from automated_security_helper.base.reporter_plugin import confined_report_path

    # Indexed, not .get() with a default: ScanOptions only holds a ranked value.
    min_sev_rank = _SEVERITY_RANK[opts.min_severity.lower()]
    # One threshold lookup for this read, shared by the count over the written
    # report and the --min-severity filter over the model: one resolver call per
    # scanner, and one actionability rule (_result_fails_its_scanner_threshold).
    threshold_for = _scanner_threshold_lookup(results)
    # Set when the count below is taken from the written report: whether that
    # report holds a counted result at or above --min-severity. None when the
    # count comes from the model's own results, which are then judged instead.
    counted_in_file: Optional[bool] = None

    sarif_file = confined_report_path(reports_dir, sarif_name) if sarif_name else None
    # A file in reports/ and not a link to one: the name is the results file's, and
    # a link at it (to a report beside it, or to a pipe, which blocks the open) is
    # refused by _compute_exit_code's link check, which runs after this count is
    # read. Opening it here would read the file it points to first.
    if (
        sarif_file is not None
        and _is_a_regular_report_file(sarif_file)
        and report_sarif_written_this_run is not False
    ):
        try:
            with open(sarif_file, encoding="utf-8") as f:
                sarif_json = json.load(f)  # nosec

            sarif_active = 0
            # The --min-severity question is answered on the file the count is
            # taken from. The model's own results can hold other findings: a
            # report phase over saved results writes this run's report from
            # them, and in container and Nix mode the inner run wrote the file.
            # Judging the model's results against a count made from the file
            # read a run whose only finding sat in the file as having none.
            file_has_qualifying = False
            for sarif_run in sarif_json.get("runs", []):
                for r in sarif_run.get("results", []):
                    # A suppression hides the result only when it is in effect:
                    # one whose state is rejected or underReview (SARIF 3.35.4)
                    # was never an approval, so the finding counts and the scan
                    # exits non-zero, as the per-scanner counts, the flat finding
                    # and the workspace verdict already read it.
                    if is_result_suppressed(r):
                        continue
                    # The one actionability rule, with the shared lookup: the
                    # same threshold and the same severity reading the
                    # --min-severity filter below applies to the model's results.
                    if not _result_fails_its_scanner_threshold(
                        r, threshold_for, sarif_run
                    ):
                        continue
                    sarif_active += 1
                    # Rank as _severity_filters_finding ranks a model result:
                    # the one severity rule (utils.severity_ladder.result_severity)
                    # reads a result's JSON form too.
                    if (
                        _SEVERITY_RANK.get(_resolve_result_severity(r), 1)
                        >= min_sev_rank
                    ):
                        file_has_qualifying = True
            actionable_findings = sarif_active
            counted_in_file = file_has_qualifying
        except Exception:  # nosec B110
            pass  # Fall through to the unified-metrics count

    if min_sev_rank > 0 and actionable_findings > 0:
        if counted_in_file is not None:
            # The count came from the written report, and so does the answer:
            # every counted result there passed its own scanner's threshold,
            # so a counted one at or above the minimum is a qualifying one.
            has_qualifying = counted_in_file
        else:
            has_qualifying = False
            try:
                sarif = getattr(results, "sarif", None)
                if sarif is None or not getattr(sarif, "runs", None):
                    has_qualifying = True
                for run in getattr(sarif, "runs", []) if not has_qualifying else []:
                    for result in getattr(run, "results", []):
                        # A qualifying result is an ACTIONABLE one at or above
                        # the minimum: one its own scanner's threshold made
                        # non-actionable is not counted above, so it cannot be
                        # the reason the count stands, and reading it as
                        # qualifying kept exit 2 for actionable findings below
                        # --min-severity.
                        if _severity_filters_finding(
                            result, min_sev_rank
                        ) and _actionable_under_its_scanner_threshold(
                            result, results, threshold_for, run
                        ):
                            has_qualifying = True
                            break
                    if has_qualifying:
                        break
            except Exception:
                has_qualifying = True
        if not has_qualifying:
            actionable_findings = 0

    return actionable_findings


# ---------------------------------------------------------------------------
# _print_summary
# ---------------------------------------------------------------------------


def print_exit_code_legend(opts: ScanOptions, actionable_count: int) -> None:
    """The exit codes a scan can return, printed after a scan that exits 2.

    Read from ASH_EXIT_CODES, so it lists every code and cannot drift from them.
    """
    fail_on_findings = (
        opts.fail_on_findings if opts.fail_on_findings is not None else True
    )
    print("\n[yellow]=== ASH Exit Codes ===[/yellow]")
    for code, meaning in ASH_EXIT_CODES.items():
        note = (
            f" (fail_on_findings is {str(fail_on_findings).lower()}; default true)"
            if code == 2
            else ""
        )
        print(f"  {code}: {meaning}{note}")
    print(
        f"[bold red]ERROR (2) Exiting due to {actionable_count} actionable findings found in ASH scan[/bold red]"
    )


def display_path(path: Path | str) -> str:
    """*path* as the console shows it: relative to the working directory, else absolute.

    The rule the metrics table's caption uses (core/metrics_table.py), so the report
    paths printed under it name the same directory the same way.
    """
    path = Path(path)
    cwd = Path.cwd()
    return (path.relative_to(cwd) if path.is_relative_to(cwd) else path).as_posix()


def _print_summary(
    results: Optional[AshAggregatedResults],
    opts: ScanOptions,
    scan_start_time: float,
    actionable_findings: int,
) -> None:
    scan_duration = time.time() - scan_start_time
    duration_str = format_duration(scan_duration)

    output_file = opts.output_dir / "ash_aggregated_results.json"
    # Relative to the working directory, as the metrics table above it is, not to the
    # source directory; inside the container image, the host's path. The lines that
    # carry it, and the configuration warnings, go through _print_text, since a
    # directory name can contain brackets.
    out_dir_alias = os.environ.get(
        "ASH_ACTUAL_OUTPUT_DIR", display_path(opts.output_dir)
    )

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
                    # A checkpoint read back from a results file another process
                    # or version wrote may carry no message; the summary runs
                    # after the exit code is computed and must not raise there.
                    _print_text(
                        (
                            f"  {cw.get('message') or '(no message recorded)'}",
                            "yellow",
                        )
                    )
                print("")

        print(
            f"\n[cyan]=== ASH Scan Completed in {duration_str}: Next Steps ===[/cyan]"
        )
        print("View detailed findings...")
        _print_text(f"  - SARIF: '{out_dir_alias}/reports/ash.sarif'")
        _print_text(f"  - JUnit: '{out_dir_alias}/reports/ash.junit.xml'")
        _print_text(
            f"  - ASH aggregated results JSON available at: "
            f"'{out_dir_alias}/{output_file.relative_to(opts.output_dir).as_posix()}'"
        )

    if actionable_findings > 0:
        print("\n[magenta]=== Actionable findings detected! ===[/magenta]")
        print("To investigate...")
        print(
            "  1. Open one of the summary reports for a user-friendly table of the findings:"
        )
        _print_text(
            f"    - HTML report of all findings: '{out_dir_alias}/reports/ash.html'"
        )
        _print_text(f"    - Markdown summary: '{out_dir_alias}/reports/ash.summary.md'")
        _print_text(f"    - Text summary: '{out_dir_alias}/reports/ash.summary.txt'")
        print(
            "  2. Use [magenta]ash report[/magenta] to view a short text summary of the scan in your terminal"
        )
        print(
            "  3. Use [magenta]ash inspect findings[/magenta] to explore the findings interactively"
        )
        _print_text(
            f"  4. Review scanner-specific reports and outputs in the '{out_dir_alias}/scanners' directory"
        )


# ---------------------------------------------------------------------------
# run_ash_scan — top-level entry point (~50 lines)
# ---------------------------------------------------------------------------


def _in_scanned_tree_from_arguments(run):
    """Run ``run_ash_scan`` with its target registered as the scanned tree.

    Before mode dispatch, so container mode's runtime lookup, nix mode's ``nix``
    and workspace mode's projects are covered too: the source directory, or the
    workspace root when a workspace plan is given.
    """

    signature = inspect.signature(run)

    @functools.wraps(run)
    def wrapper(*args, **kwargs):
        from automated_security_helper.utils.subprocess_utils import scanning_tree

        # Bound against the signature, so a target given positionally
        # (``run_ash_scan(source_dir)``) is read as well as one given by name;
        # read from kwargs alone, a positional call registered the working
        # directory instead of the scanned tree.
        arguments = signature.bind_partial(*args, **kwargs).arguments
        plan = arguments.get("workspace_plan")
        source_dir = arguments.get("source_dir")
        if plan is not None:
            root = Path(plan.workspace_root)
        elif source_dir is not None:
            root = Path(source_dir)
        else:
            root = Path.cwd()
        with scanning_tree(root):
            return run(*args, **kwargs)

    return wrapper


def _in_a_run_log_scope(scan):
    """*scan* inside a run log scope (utils/log.py), joined or its own.

    Everything the run logs goes only to the ash.log its own _setup_logger
    opened, which takes no other run's lines, and the handlers come off the
    logger when the run ends. The MCP server opens the scope around its runner
    so the runner's own lines belong to the scan, and this joins it; a CLI run
    is the opener, so the scope ends when the scan returns.
    """
    import functools

    @functools.wraps(scan)
    def scoped(*args, **kwargs):
        from automated_security_helper.utils.log import run_log_scope

        with run_log_scope():
            return scan(*args, **kwargs)

    return scoped


@_in_a_run_log_scope
@_in_scanned_tree_from_arguments
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
    workspace_config_as_named: str | None = None,
    config_base_gate: Optional[Callable[[Path], bool]] = None,
    untrusted_config: bool = False,
    trusted_config_path: Optional[str] = None,
    client_config_policy: "Optional[ClientConfigRules]" = None,
    remote_client: bool = False,
    severity_threshold_restriction: Optional[str] = None,
    keep_previous_results: bool = False,
):
    """Run an ASH scan against source_dir, outputting results to output_dir.

    Takes only the parameters above: an unknown keyword argument, such as a
    misspelled ``fail_on_finding``, is a TypeError naming it, so a scan never runs
    without an option the caller believed was set.

    When *workspace_plan* is given, *source_dir* is the workspace root and each
    project in the plan is scanned in its own scope. See
    :mod:`automated_security_helper.workspace.execution`.
    """
    scan_start_time = time.time()

    # A new scan gets its own once-per-entry window for the unverifiable-.git
    # boundary warning; without this, a long-lived process (the MCP server)
    # warns only on its first scan.
    from automated_security_helper.config.sandbox_grants import (
        forget_unverifiable_warnings,
    )

    forget_unverifiable_warnings()

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
        workspace_config_as_named=workspace_config_as_named,
        config_base_gate=config_base_gate,
        untrusted_config=untrusted_config,
        trusted_config_path=trusted_config_path,
        client_config_policy=client_config_policy,
        remote_client=remote_client,
        severity_threshold_restriction=severity_threshold_restriction,
        keep_previous_results=keep_previous_results,
    )

    # Only the local orchestrator resolves with these. Container and nix mode run
    # a separate ASH that is handed the config path alone, and workspace mode
    # resolves each project's own config, so in any of them the restriction would
    # be dropped without a word.
    if opts.config_base_gate is not None and opts.mode in (
        RunMode.container,
        RunMode.nix,
    ):
        raise ValueError(
            "config_base_gate is applied only to a scan in local mode, not to "
            f"mode={opts.mode.value!r}: the ASH that mode runs reads the config "
            "without it"
        )
    for name, value, workspace_ok in (
        ("untrusted_config", opts.untrusted_config, False),
        # Workspace mode carries these to every project through the settings
        # builder.
        ("client_config_policy", opts.client_config_policy, True),
        ("remote_client", opts.remote_client, True),
        # The MCP server's two: the threshold it tightens the scan to, which only
        # the local orchestrator applies, and the kept previous results, which the
        # local orchestrator and each workspace project's orchestrator settle.
        # Container and nix mode hand neither to the ASH they run, so a caller
        # that sets one there is told, as for the three above, instead of
        # scanning with it dropped: the scan CLI has no flag for either, a
        # restriction dropped on the way is a gate loosened without a word, and a
        # kept-results request dropped deletes what the caller asked to keep.
        ("severity_threshold_restriction", opts.severity_threshold_restriction, False),
        ("keep_previous_results", opts.keep_previous_results, True),
        # The operator's trusted config path has no scan CLI flag either, so the
        # scan a container or a shell runs cannot be given it, and the grants it
        # names would go unread. Refused for the two modes that re-execute ASH;
        # what workspace mode on the host does with it is that mode's own and is
        # not changed by this line.
        ("trusted_config_path", opts.trusted_config_path, True),
    ):
        if value and (
            opts.mode in (RunMode.container, RunMode.nix)
            or (opts.workspace_plan is not None and not workspace_ok)
        ):
            raise ValueError(
                f"{name} is applied only to a single-directory scan in local "
                f"mode, not to mode={opts.mode.value!r}"
                + (" with a workspace plan" if opts.workspace_plan is not None else "")
            )

    if opts.changed_files_only:
        # Refused here, before logging is set up and before any git process
        # starts, in every mode: the base ref goes to `git diff`, and a value git
        # reads as an option changes what git does. Unchecked without
        # --changed-files-only, because then no diff runs.
        from automated_security_helper.utils.get_scan_set import validate_base_ref

        validate_base_ref(opts.base_ref)

    if opts.mode == RunMode.container and opts.config is None:
        # Before anything reads the config, so the host's own reads (the exit-code
        # fields below) use the file the container is handed. A workspace scan gets
        # ASH_CONFIG as the CLI hands it over, where it is --config's environment
        # variable: the scan inside sees neither the host's environment nor the file.
        opts.config = (
            _ash_config_fallback(opts.source_dir, permit=opts.config_base_gate)
            if opts.workspace_plan is None
            else os.environ.get("ASH_CONFIG") or None
        )

    # First of the refusals: it reads nothing, and the scan cannot finish anyway.
    _refuse_a_source_dir_that_is_not_utf8(opts)
    _refuse_a_container_mount_that_is_not_utf8(opts)
    _refuse_a_container_mount_the_runner_cannot_carry(opts)
    # What this scan reads of the operator's config, read once for every
    # container-mode check that asks (see OperatorConfigReads). The exit-code
    # fields below keep their own load.
    reads = OperatorConfigReads()
    outer_load: Optional[_OuterModeConfigLoad] = None
    if opts.workspace_plan is None and (
        opts.mode == RunMode.nix or (opts.mode == RunMode.container and opts.run)
    ):
        # Before ash.log is opened and before any build, run, mount or clearing
        # of the previous run's output: the scan inside would refuse this
        # config only after all of them. --no-run builds an image and scans
        # nothing, so its config is not judged. A workspace plan was resolved
        # on the host already.
        outer_load = _outer_mode_config_load(opts)
        refusal = outer_load.refusal
        if refusal is not None:
            _printed_config_refusal(3, refusal)
        if opts.mode == RunMode.container:
            # The output directory's link rule first, as OutputDirRefusedExit:
            # the inputs check below applies the same rule with the other inputs
            # and exits with a bare 3, so a link it found first would reach an
            # in-process caller without the link's name. Same code, same message,
            # raised earlier; the check below runs it again for every mode.
            _refuse_symlinked_output_dir(opts)
            # Each path the run would mount and the config the scan inside is
            # handed, before ash.log is opened: a refused scan creates no output
            # directory, writes no log and leaves the previous run's output as it
            # was. _run_container_mode checks again, for a caller that reaches it
            # directly.
            _refuse_container_inputs(opts, None, reads)
    _apply_log_level_env(opts)
    _refuse_symlinked_output_dir(opts)
    _refuse_committed_output(opts)
    # Every write this run makes below the output directory, from ash.log on, is
    # guarded (fs_guard). The registration is this run's and is released when it
    # ends, so a process that runs many scans, as the MCP server does, does not
    # keep guarding every output directory it ever wrote. run_roots releases the
    # roots this run's PluginContexts and sandbox scopes registered at the same
    # time, rather than whenever the collector reaches them.
    from automated_security_helper.utils.sandbox.fs_guard import (
        run_roots,
        writable_root,
    )

    with writable_root(opts.output_dir), run_roots():
        return _run_with_options(opts, scan_start_time, outer_load, reads)


def _run_with_options(
    opts: ScanOptions,
    scan_start_time: float,
    outer_load: "Optional[_OuterModeConfigLoad]" = None,
    reads: "OperatorConfigReads | None" = None,
):
    """The rest of ``run_ash_scan``, from the logger on, with its root registered."""
    logger = _setup_logger(opts)
    _ignore_output_dir_in_git(opts)

    if opts.workspace_plan is not None and opts.mode not in (
        RunMode.container,
        RunMode.nix,
    ):
        # Workspace mode owns its own verdict and its own summary. It does not go
        # through _compute_exit_code, which answers for one directory against one
        # threshold and has no way to express "project A failed, project B did
        # not". Container mode and Nix mode re-execute the workspace scan inside
        # their own environment and read its payload back below: a plan here
        # with --mode nix ran the workspace scan on the host, never entering
        # the shell, so every scanner the flake supplies was MISSING.
        workspace_result = _run_workspace_mode(opts, logger)
        if opts.show_summary:
            _print_workspace_summary(workspace_result, opts, scan_start_time)
        if workspace_result.exit_code != 0:
            sys.exit(workspace_result.exit_code)
        return workspace_result

    # The gate above loaded the file these two read, with the same arguments,
    # so they take its result when the gate loaded the model itself (an image
    # built from this tree). When the image's ASH may hold another schema, the
    # gate parsed the file and built the model from that same document, and
    # the read below takes that document and that model rather than reading
    # the file again. With no gate, one load of this function's own serves both fields;
    # the load is never part of the container chain record. The
    # reads that stay fresh on purpose: _sandbox_modes_requested resolves the
    # whole chain with --sandbox, the overrides and the trusted base, which is
    # not the file alone; _take_own_values_for_record loads with for_run=True,
    # after the inner scan, to repair references. The second
    # container_input_refusal (_run_container_mode) is for callers that reach
    # that function directly; it takes this same record, so the files and
    # extends entries the first refusal read are not read again.
    # The gate's answer about the image, for this read and for the record repair
    # after the inner scan: asking again would name the image's source a second
    # time, after the run's own output. None when the gate did not run, or ran
    # and got no answer (an OSError from the image question itself is deferred to
    # the checks that own that shape), leaves each reader to ask for itself.
    gate_image_answer: Optional[bool] = (
        outer_load.image_may_differ if outer_load is not None else None
    )
    shared = _NOT_LOADED
    if outer_load is not None and outer_load.loaded:
        shared = outer_load.selected
    if shared is _NOT_LOADED:
        # The image-schema branch of the gate parsed the file, built the model
        # from that document and asked about the image; this read takes all
        # three answers, so the file is resolved once and the image's source is
        # named once.
        shared = _load_config_file_or_its_exit_fields(
            opts,
            document=outer_load.document if outer_load is not None else _NOT_LOADED,
            image_may_differ=gate_image_answer,
            model=outer_load.model if outer_load is not None else _NOT_LOADED,
        )
    config_fail_on_findings: Optional[bool] = _resolve_config_fail_on_findings(
        opts, loaded=shared
    )
    # Read from the file before the scan only where the answer cannot wait for the
    # orchestrator's resolution. A local scan's results carry the config it
    # actually resolved, which a client-delivered file is checked in; a pre-read
    # here would let an unchecked read of the same file decide the gate.
    config_fail_on_incomplete_scanners: Optional[bool] = (
        _resolve_config_fail_on_incomplete_scanners(opts, loaded=shared)
        if opts.mode != RunMode.local
        else None
    )
    # Before any mode runs, so that whatever this run writes to reports/ash.sarif
    # (the local report phase, or the container's or nix's inner scan) shows as a
    # change, and a file left by an earlier run does not.
    report_sarif_before = report_sarif_identity(opts.output_dir)
    results: Optional[AshAggregatedResults]
    if opts.mode == RunMode.container:
        results = _run_container_mode(
            opts,
            logger,
            resolved_fail_on_findings=config_fail_on_findings,
            resolved_fail_on_incomplete_scanners=config_fail_on_incomplete_scanners,
            reads=reads,
            image_may_differ=gate_image_answer,
        )
    elif opts.mode == RunMode.nix:
        # No resolved-flag arguments here, unlike container mode, and that asymmetry is
        # deliberate rather than an oversight in the merge that brought these two together.
        # Container mode forwards the flags into the CLI invocation it runs inside the
        # container, because that inner process computes its own verdict. Nix mode returns
        # the parsed results and the verdict is computed once, below, by
        # _compute_exit_code -- which already receives config_fail_on_incomplete_scanners,
        # so nix runs honour it through the shared path.
        results = _run_nix_mode(opts, logger, image_may_differ=gate_image_answer)
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
            logger.error(_no_workspace_payload_message(opts.mode))
        if exit_code != 0:
            sys.exit(exit_code)
        return results

    report_sarif_after = report_sarif_identity(opts.output_dir)
    report_sarif_written_this_run = (
        report_sarif_after is not None and report_sarif_after != report_sarif_before
    )
    # The actionable count the exit code gates on, read ONCE (it parses the
    # persisted SARIF report) and handed to the exit code, the summary and the
    # legend alike, so the three name one number and cannot disagree about it.
    actionable_findings = (
        _gating_actionable_count(results, opts, report_sarif_written_this_run)
        if results is not None
        else 0
    )
    exit_code = _compute_exit_code(
        results,
        opts,
        config_fail_on_findings,
        config_fail_on_incomplete_scanners,
        report_sarif_written_this_run=report_sarif_written_this_run,
        actionable_count=actionable_findings,
    )

    if opts.show_summary:
        _print_summary(results, opts, scan_start_time, actionable_findings)

        if exit_code == 2 and not opts.quiet:
            print_exit_code_legend(opts, actionable_findings)

    _incompleteness = ScanIncompleteness()
    if exit_code == 1:
        # An incomplete scan and a crash share exit 1, so the message has to be
        # chosen from the cause rather than the code. Printing "an exception
        # occurred" for a run whose scanners simply were not installed sends the
        # operator looking for a traceback that does not exist.
        #
        # The same object _compute_exit_code reached its verdict from, so the
        # message, the exit code and the exception below agree on the cause. The
        # scanner and converter rows are empty when the gate is off, because both
        # arms live behind it; the stale-database records are not, because that arm
        # is not behind the gate. The message keeps the scanner arm's precedence
        # over the converter arm when a run trips both, since a scanner that did not
        # run is the more specific finding.
        _incompleteness = scan_incompleteness(
            results,
            gate=_resolve_fail_on_incomplete_scanners(
                results, opts, config_fail_on_incomplete_scanners
            ),
            one_shard_of_a_split=(
                opts.shard_index is not None or opts.shard_count is not None
            ),
        )
        nothing_to_scan = scanners_with_nothing_to_scan(results)
        print_incompleteness_message(
            list(_incompleteness.scanners),
            list(_incompleteness.converters),
            list(_incompleteness.stale_content_databases),
            no_scanner_ran=_incompleteness.no_scanner_ran,
            observed=list(_incompleteness.observed),
            nothing_to_scan=(
                nothing_to_scan_message(results, nothing_to_scan, accept_remedy=False)
                if nothing_to_scan
                else None
            ),
            unevaluated_rules=list(_incompleteness.unevaluated_rules),
            missing_reasons=dict(_incompleteness.missing_reasons),
            could_not_stop=list(_incompleteness.could_not_stop),
        )

    if exit_code == 1 and results is not None and _incompleteness:
        # Still exit 1. The exception adds the reason, for an in-process caller
        # such as the MCP runner that has to tell this from a crash.
        raise ScanIncompleteExit(_incompleteness, results)
    if exit_code != 0:
        sys.exit(exit_code)

    return results
