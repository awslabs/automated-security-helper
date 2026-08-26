# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run a resolved workspace as N independently scoped scans.

Why this module exists
----------------------
Phase 1 produced a plan and refused to act on it. This is the part that acts, and
its whole job is to hold one invariant while doing so:

    For any project P, the findings reported for P and the pass/fail verdict for P
    are identical to what ``ash --source-dir P`` would produce, ABSENT workspace
    policy.

Everything below follows from that. The qualification was added in Phase 3 and is
not a weakening of the invariant; it is the one thing allowed to change a verdict,
and it does so only where an operator wrote a policy file saying so.

Where policy enters, and where it deliberately does not
------------------------------------------------------
Exactly one line applies it: the verdict reads ``project.gate_threshold`` rather
than ``project.severity_threshold``, so a workspace severity ceiling decides which
findings are actionable. Everything else about a project's scan -- which scanners
run, what config they read, what they report -- is still the project's own.

That single point is deliberate. The ceiling changes only the JUDGEMENT of
findings, never their discovery, so a project scanned under a ceiling reports the
same findings as ``ash --source-dir P`` and differs only in how many of them are
counted actionable. An operator can therefore always reproduce a workspace
verdict locally by passing the effective threshold, which ``--dry-run`` prints.

Two policy fields do NOT yet reach the scan, and the reason is a real constraint
rather than an omission. ``workspace.suppressions``, ``workspace.ignore_paths``
and ``workspace.additional_scanners`` have to be visible to the scanners
themselves, which read them from the resolved ``AshConfig``.
``ASHScanOrchestrator.__init__`` unconditionally overwrites its ``config`` field
by calling ``resolve_config`` itself, so a caller cannot hand it a config with
policy merged in. The other available channel, ``config_overrides``, is
string-keyed and FAILS OPEN: ``apply_config_overrides`` logs a warning and
returns the ORIGINAL config when an override does not parse or the result does
not validate. Routing a security policy through it would mean a typo silently
scans with no policy at all, which is the failure direction this whole feature
exists to prevent. Those fields are resolved, validated, pushed down per project
and recorded on the plan; wiring them into the scan needs the orchestrator to
accept a pre-resolved config, which touches the single-project path.

How the scoping is achieved, and why it needs almost no new code
---------------------------------------------------------------
Each project gets its own ``ASHScanOrchestrator``, built with that project's
directory as ``source_dir``, that project's resolved config as ``config_path``,
and ``<workspace-output>/projects/<key>`` as ``output_dir``. Three properties the
requirements ask for then fall out of existing code rather than from a new branch:

* Fresh scanner plugin instances per project. ``ScanPhase._execute_phase``
  constructs a new instance per plugin class per invocation, so a per-project
  engine means per-project instances. This matters because a plugin instance is
  mutable and the scan phase reassigns ``.context`` and ``.results_dir`` in place
  immediately before calling it; a reused instance in a shared thread pool would
  file one project's findings against another.
* Per-project raw scanner output at
  ``projects/<key>/scanners/<scanner>/<target_type>``. The scanner base builds
  ``<output_dir>/scanners/<name>`` and each scanner appends the target type, so a
  per-project ``output_dir`` produces exactly the required tree.
* Single-project mode unchanged. There is no conditional to take: a
  single-directory scan hands the same code an ``output_dir`` with no
  ``projects/`` component and gets the path it always got. That is why this is
  the shape chosen over a workspace-aware branch in ``scanner_plugin.py`` -- a
  branch would have had to be proven not to fire, and this cannot fire.

``tests/unit/workspace/test_project_isolation.py`` pins all three against real
plugin objects, because they are properties of code this module does not own and
nothing else in the suite would notice them moving.

Concurrency: an outer bound over an inner pool, not a replacement
----------------------------------------------------------------
Projects run on a thread pool of ``max_parallel_projects`` workers. Each project's
scan then runs its own scanners on its own inner pool, which is
``min(32, cpu_count + 4)`` workers in ``ScanExecutionEngine.__init__`` -- not 4,
and not the ``thread_pool_max_workers`` MCP setting, which is unrelated. So the
worst-case thread count is the product of the two, and the outer bound is what
keeps that product finite as workspaces grow.

The per-project Rich progress display is disabled. N concurrent ``Live`` displays
write to the same terminal and corrupt each other's output; the workspace emits
plain per-project lines instead.

Process-global state, and the sweep that would have missed it
------------------------------------------------------------
Running N differently-configured scans in one interpreter is new, and it makes
every piece of module-level mutable state a possible cross-project leak. Three
pieces live on ``ash_plugin_manager``, the singleton in ``plugins/__init__.py``:

* ``context`` is written by every ``ScanExecutionEngine.__init__`` through
  ``set_context``, so under parallel projects the last writer wins. It is safe
  today only because nothing reads it -- safety by accident. A reader added later
  would silently see an arbitrary project's context, so
  ``tests/unit/workspace/test_project_isolation.py`` fails if one appears.
* ``plugin_library`` and ``_resolved_plugins`` are the registry, and they were an
  actual defect rather than a hypothetical one: the first project to build an
  engine froze the scanner class list for every project. See
  :func:`prewarm_plugin_registry`.

Worth recording because of how the original audit missed all three. It swept for
module-level assignments of mutable literals (``X = {}``, ``X = []``), found six
benign caches, and concluded the design was safe. The conclusion happened to be
right and the evidence was not: ``ash_plugin_manager = AshPluginManager()`` is an
assignment of an *object*, so it matches no mutable-literal pattern, while its
``_resolved_plugins`` private attribute is process-global mutable state; and
``.context`` is never assigned at module level at all, so there was nothing for
that sweep to find. Any future search for shared state has to cover singleton
instances, attributes set on them later, and the *cache key* of every memo -- the
registry bug was a memo keyed on the literal string ``"scanner"``, carrying
nothing that varied per project.

The other half of that lesson is what evidence counts. A green per-project test
suite proves nothing here, because a leak between differently-configured runs is
invisible to any test that constructs one configuration. The discriminator is to
run the same code twice in one process with *different* configuration and assert
each run saw its own.

Timeouts bound the verdict, not the worker
------------------------------------------
``project_timeout`` is measured from the moment a project *starts*, not from when
it was submitted, so a project queued behind others is not punished for waiting.
On expiry the project is recorded FAILED, the workspace exits non-zero, and every
other project that can still run does.

Rejected: ``future.result(timeout=...)`` over the futures in submission order.
That measures from submission, so with a bound of 2 and a timeout of 60s the
fifth project can be recorded as timed out before it has started.

An abandoned worker costs a pool slot permanently
------------------------------------------------
The worker thread is not killed, because Python cannot preempt a thread. So an
abandoned project keeps its slot for as long as it runs, and the pool
effectively shrinks. Once every slot is held by an abandoned project, nothing
still queued can ever start, and waiting on it would block on threads that are
not coming back.

That was a real defect rather than a theoretical one: the deadline check skipped
any project with no start time, which is exactly a queued one, so a workspace
whose bound was smaller than its project count had no wall-clock bound at all.
Measured -- three projects, one wedged, a 1s budget: at bound 3 the run returned
at 1.0s, and at bound 1 it was still running past 12s. The shipped default bound
is 4, so any workspace of five or more projects was exposed, which is precisely
the shape the wave arithmetic in ``ash_config`` is written for.

Now, when the count of abandoned workers reaches the bound, every project that
has not started is cancelled and recorded FAILED with a message naming the three
ways out: raise the bound, raise the budget, or scan the slow project separately.
Cancelling first matters -- a queued future can still be cancelled, and that stops
it starting after the workspace has already reported it as failed.

A project that has started and is inside its budget is still waited for; only
never-started ones are given up on.

Results from an abandoned worker are discarded
----------------------------------------------
If an abandoned project's scan finishes later, its worker checks before writing
and throws the results away. Otherwise
``projects/<key>/ash_aggregated_results.json`` would hold real findings while the
unified file recorded that project as FAILED with ``finding_count=0`` -- a
contradiction an operator could only resolve by guessing which file to trust, in
a subtree this feature advertises as consumable by existing single-project
tooling.

The residual exposure is process exit. The pool is shut down with ``wait=False``
so the workspace reports immediately, but the interpreter's own exit handler
joins the abandoned thread, so a genuinely wedged project still delays the
process from exiting. Two things bound it: scanners run as subprocesses with
their own timeouts, so a hung *tool* is handled below this layer, and the
residual case is an in-process scanner stuck in Python. Fixing that properly
means a subprocess per project, which is a larger change than this phase and
would move the per-project scan out of ``core/orchestrator.py``.

The changed-files gate is per project, per repository
----------------------------------------------------
``--mode precommit`` and ``--changed-files-only`` are evaluated against each
project's own git repository, because projects in a workspace are independently
versioned and one diff cannot answer for all of them. A project with no changed
files is skipped with ``no-changes``, which is a successful optimisation and does
not colour the exit status; the skip is in the results payload, not only in the
log, because nothing downstream reads stderr.

Diff paths are resolved against ``git rev-parse --show-toplevel`` rather than
against the project directory. ``git diff --name-only`` prints repository-relative
paths regardless of the directory it runs in, so joining them onto the project
directory is wrong whenever a project sits below a larger repository -- and it
silently produces paths that match nothing, which reads as "no changes".

A project that is not a git repository at all is an error under ``precommit``
(exit 2, unless ``--allow-missing-projects``), because precommit's entire premise
is a diff. Under ``--changed-files-only`` it falls back to a full scan, matching
that flag's documented behaviour.

Failure modes and known limitations
-----------------------------------
* The timeout limitation above.
* A project that fails is FAILED, not skipped, and fails the workspace. A project
  that resolution skipped -- missing under ``--allow-missing-projects``, or
  unchanged -- does not, because failing there would make both features useless.
* Findings are filtered to the changed set with
  ``run_ash_scan._filter_results_to_changed_files``, imported lazily. The lazy
  import is what keeps ``workspace`` free of an import-time dependency on
  ``interactions``; duplicating the filter instead would give two
  implementations of "is this finding in the changed set" to keep in step.
* ``max_parallel_projects`` bounds concurrency, and therefore also peak memory:
  the aggregator holds one project's SARIF at a time, so peak is roughly the
  bound times a single scan, not the project count times a single scan.
* Log output from concurrent projects interleaves in one workspace-level log
  file. Each line carries its scanner name but not its project, so reading a
  parallel workspace log is harder than reading a serial one. Per-project logs
  would need the logger to stop being a module-level singleton.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event, Lock
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    WorkspaceDefinitionError,
)
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    SkippedProjectReason,
    WorkspaceExitCode,
    WorkspaceProjectResult,
    WorkspaceResults,
    workspace_exit_code,
)
from automated_security_helper.utils.get_scan_set import (
    get_changed_files,
    git_repository_root,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.workspace.aggregation import (
    RESULTS_FILENAME,
    WorkspaceAggregator,
    count_actionable_results,
    has_finding_at_min_severity,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan
from automated_security_helper.workspace.policy import ceiling_unreachable_counts
from automated_security_helper.workspace.reporting import (
    WorkspaceReportOutcome,
    emit_workspace_reports,
    unsupported_reporter_names,
)

#: How often the outer loop wakes to check per-project deadlines. Small enough
#: that a timeout is reported promptly, large enough not to spin.
_DEADLINE_POLL_SECONDS = 0.05

#: The phase name that selects report generation, as ``run_ash_scan`` spells it.
_REPORT_PHASE = "report"

#: The subtree each project's own output lands in.
PROJECTS_DIR_NAME = "projects"

OrchestratorFactory = Callable[..., Any]


@dataclass(frozen=True)
class ProjectScanSettings:
    """Everything a per-project scan needs that the plan does not already carry.

    Frozen, and every sequence is a tuple, because one instance is read from
    ``max_parallel_projects`` threads at once. A mutable list default would hand
    the same object to every project, and a settable field would invite a caller
    to change it mid-run.
    """

    output_dir: Path
    phases: Tuple[str, ...] = ("convert", "scan", "report")
    enabled_scanners: Tuple[str, ...] = ()
    excluded_scanners: Tuple[str, ...] = ()
    output_formats: Tuple[str, ...] = ()
    config_overrides: Tuple[str, ...] = ()
    ash_plugin_modules: Tuple[str, ...] = ()
    strategy: str = "parallel"
    offline: bool = False
    python_based_plugins_only: bool = False
    ignore_suppressions: bool = False
    min_severity: str = "low"
    fail_on_findings: Optional[bool] = None
    changed_files_only: bool = False
    base_ref: str = "origin/main"
    precommit: bool = False
    cleanup: bool = False
    verbose: bool = False
    debug: bool = False
    simple: bool = False
    color_system: Optional[str] = None
    max_parallel_projects: int = 1
    project_timeout: Optional[float] = None
    allow_missing_projects: bool = False


@dataclass
class WorkspaceRunResult:
    """What a workspace run concluded, and where it wrote it."""

    results_path: Path
    exit_code: int
    payload: WorkspaceResults
    project_durations: Dict[str, float] = field(default_factory=dict)
    #: What the workspace-level report step produced, or ``None`` when the
    #: operator did not ask for the report phase. ``None`` rather than an empty
    #: outcome, so a caller can tell "no reports were requested" from "reports
    #: were requested and every one was withheld".
    report_outcome: Optional["WorkspaceReportOutcome"] = None


@dataclass
class _ProjectRun:
    """One project's outcome plus the SARIF run it produced, if any."""

    outcome: WorkspaceProjectResult
    run: Optional[Dict[str, Any]] = None


def prewarm_plugin_registry(plan: WorkspacePlan, settings: ProjectScanSettings) -> int:
    """Register every plugin the workspace needs, once, before any project starts.

    Why this has to happen up front
    -------------------------------
    ``ScanExecutionEngine.__init__`` registers a project's ``ash_plugin_modules``
    into the module-level ``plugin_library`` and then reads the scanner set back
    through ``ash_plugin_manager.plugin_modules()``, which memoises into
    ``_resolved_plugins``. Whichever project builds its engine first therefore
    freezes the scanner class list for the whole run. Measured before this
    existed, on two real projects where only one declared an external plugin:
    scanning the non-declaring project first made the declaring project LOSE its
    own scanner, and the other order gave the non-declaring project one it never
    asked for. Neither order was correct, at every value of
    ``max_parallel_projects`` -- concurrency only randomises which project is
    wrong.

    Resolution has already refused any workspace whose projects ask for different
    module sets (see ``resolver._validate_plugin_modules``), so there is exactly
    one correct set and registering it here is correct for every project. Doing it
    before the pool starts also removes the ordering nondeterminism entirely, and
    with it the concurrent-registration race in ``plugin_modules``: that function
    iterates ``plugin_library.scanners`` doing imports inside the loop, and a
    second thread registering a new key mid-iteration raises
    ``RuntimeError: dictionary changed size during iteration``, which surfaces as
    a spurious failed project.

    This does not change *which* scanners run for a project. Registration and
    selection are separate mechanisms: this fills the registry, and each
    project's own config still decides enablement through
    ``ScanPhase._execute_phase``'s ``config.enabled`` and enabled/excluded
    filtering. A project that disables a scanner still skips it.

    Returns:
        How many scanner classes the registry resolved to, for logging. Zero
        means plugin discovery found nothing, which is worth seeing in a log
        rather than discovering later as an empty scan.
    """
    from automated_security_helper.plugins import ash_plugin_manager
    from automated_security_helper.plugins.discovery import discover_plugins
    from automated_security_helper.plugins.loader import (
        load_additional_plugin_modules,
        load_internal_plugins,
    )

    load_internal_plugins()

    # Every active project has the same list by now, so the first one speaks for
    # all of them; settings may add more from the CLI.
    declared: Set[str] = set(settings.ash_plugin_modules)
    for project in plan.active_projects:
        declared.update(project.ash_plugin_modules)
    modules = sorted(declared)

    if modules:
        ASH_LOGGER.info(f"Loading workspace plugin modules: {modules}")
        load_additional_plugin_modules(modules)
        discover_plugins(plugin_modules=modules)

    # Resolve once so the memoised list is complete and identical for every
    # project, rather than whatever the first project happened to see.
    resolved = 0
    for plugin_type in ("converter", "scanner", "reporter"):
        found = ash_plugin_manager.plugin_modules(plugin_type)
        if plugin_type == "scanner":
            resolved = len(found)
    ASH_LOGGER.verbose(
        f"Workspace plugin registry pre-warmed with {resolved} scanner class(es)"
    )
    return resolved


def _project_output_dir(settings: ProjectScanSettings, project: ProjectPlan) -> Path:
    """Where one project's own output subtree lives.

    The project key, not its path: the key already has separators replaced by
    dashes, so a nested project like ``apps/web`` becomes one directory named
    ``apps-web`` rather than two levels that could collide with a project
    literally named ``apps``.
    """
    return Path(settings.output_dir) / PROJECTS_DIR_NAME / project.key


def _skipped_outcome(
    project: ProjectPlan,
    settings: ProjectScanSettings,
    reason: SkippedProjectReason,
    detail: Optional[str],
) -> _ProjectRun:
    return _ProjectRun(
        outcome=WorkspaceProjectResult(
            project=project.key,
            relative_path=project.relative_path,
            display_label=project.display_label,
            status=ProjectRunStatus.SKIPPED,
            severity_threshold=project.gate_threshold,
            output_path=_project_output_dir(settings, project)
            .relative_to(Path(settings.output_dir))
            .as_posix(),
            skip_reason=reason,
            skip_detail=detail,
        )
    )


def _failed_outcome(
    project: ProjectPlan,
    settings: ProjectScanSettings,
    error: str,
    *,
    invalid_config: bool = False,
    duration_seconds: float = 0.0,
) -> _ProjectRun:
    return _ProjectRun(
        outcome=WorkspaceProjectResult(
            project=project.key,
            relative_path=project.relative_path,
            display_label=project.display_label,
            status=ProjectRunStatus.FAILED,
            severity_threshold=project.gate_threshold,
            output_path=_project_output_dir(settings, project)
            .relative_to(Path(settings.output_dir))
            .as_posix(),
            error=error,
            invalid_config=invalid_config,
            duration_seconds=duration_seconds,
        )
    )


def changed_file_set(
    project: ProjectPlan, settings: ProjectScanSettings
) -> Optional[Set[Path]]:
    """The changed files inside *project*, or None when no gate applies.

    Returns:
        ``None`` when the gate does not apply -- either it was not requested, or
        git could not answer and the documented fallback is a full scan. An empty
        set when the project is a repository with nothing changed inside it, which
        is the skip signal. Otherwise the absolute paths of the changed files that
        lie within the project.

    Raises:
        WorkspaceDefinitionError: Under ``precommit``, when the project is not a
            git repository and ``--allow-missing-projects`` was not passed.
            Precommit's premise is a diff, so silently scanning everything would
            turn a fast pre-commit hook into a full scan without saying so.
    """
    if not (settings.precommit or settings.changed_files_only):
        return None

    project_path = Path(project.path)
    repository_root = git_repository_root(project_path)
    if repository_root is None:
        if settings.precommit and not settings.allow_missing_projects:
            raise WorkspaceDefinitionError(
                f"project '{project.key}' at '{project.path}' is not a git "
                f"repository, and '--mode precommit' selects files from a git "
                f"diff. Pass '--allow-missing-projects' to scan it in full "
                f"instead, or drop '--mode precommit'."
            )
        ASH_LOGGER.warning(
            f"Project '{project.key}' is not a git repository; scanning it in "
            f"full rather than by diff."
        )
        return None

    changed = get_changed_files(base_ref=settings.base_ref, cwd=project_path)
    if changed is None:
        # git is missing, or the base ref does not exist. get_changed_files has
        # already warned; its documented fallback is a full scan.
        return None

    resolved_project = project_path.resolve()
    inside: Set[Path] = set()
    for relative in changed:
        # Repository-relative, not project-relative. See the module docstring.
        candidate = (repository_root / relative).resolve()
        if candidate == resolved_project or candidate.is_relative_to(resolved_project):
            inside.add(candidate)
    return inside


def _scan_one_project(
    project: ProjectPlan,
    settings: ProjectScanSettings,
    orchestrator_factory: OrchestratorFactory,
    abandoned: Optional[Event] = None,
) -> _ProjectRun:
    """Scan one project in its own scope and reduce it to an outcome plus a run.

    Args:
        abandoned: Set by the outer loop when this project has been given up on
            at its timeout. The worker cannot be interrupted, so it keeps running
            -- but it checks this before writing, because the workspace has
            already recorded the project as FAILED and a later write would leave
            ``projects/<key>/ash_aggregated_results.json`` holding real findings
            that the unified file says do not exist.
    """
    from automated_security_helper.core.enums import ExecutionStrategy, ExportFormat

    started = time.monotonic()
    project_output = _project_output_dir(settings, project)
    output_path = project_output.relative_to(Path(settings.output_dir)).as_posix()

    changed = changed_file_set(project, settings)
    if changed is not None and not changed:
        ASH_LOGGER.info(
            f"Project '{project.key}' has no files changed against "
            f"'{settings.base_ref}'; skipping it."
        )
        return _skipped_outcome(
            project,
            settings,
            SkippedProjectReason.NO_CHANGES,
            f"no files changed against '{settings.base_ref}'",
        )

    project_output.mkdir(parents=True, exist_ok=True)

    try:
        resolved_config = _project_config_with_policy(project, settings)

        orchestrator = orchestrator_factory(
            source_dir=Path(project.path),
            output_dir=project_output,
            work_dir=project_output / ASH_WORK_DIR_NAME,
            enabled_scanners=list(settings.enabled_scanners),
            excluded_scanners=list(settings.excluded_scanners),
            # A pre-resolved config, and NOT config_path or config_overrides
            # alongside it -- the orchestrator refuses that combination, because
            # those are inputs to a resolution it is being told to skip. The
            # `Configuration path:` line it used to log from config_path is
            # emitted by _project_config_with_policy instead.
            resolved_config=resolved_config,
            verbose=settings.verbose or settings.debug,
            debug=settings.debug,
            strategy=(
                ExecutionStrategy.PARALLEL
                if settings.strategy == ExecutionStrategy.PARALLEL.value
                else ExecutionStrategy.SEQUENTIAL
            ),
            no_cleanup=not settings.cleanup,
            output_formats=[ExportFormat(value) for value in settings.output_formats],
            # Never True: concurrent Rich Live displays corrupt the terminal.
            show_progress=False,
            simple_mode=settings.simple,
            show_summary=False,
            color_system=settings.color_system,
            offline=settings.offline,
            existing_results_path=None,
            python_based_plugins_only=settings.python_based_plugins_only,
            ignore_suppressions=settings.ignore_suppressions,
            ash_plugin_modules=list(settings.ash_plugin_modules),
            # The project's own identity, so that its per-project reports can say
            # which project they describe. Ten of the nineteen reporters are ruled
            # PER_PROJECT, and that ruling is only honest if the N artefacts are
            # distinguishable -- which for the four that publish to a shared
            # destination they were not. See ASHScanOrchestrator._apply_metadata.
            metadata={
                "project_name": project.display_label,
                "workspace_project": project.key,
            },
        )
        results = orchestrator.execute_scan(phases=list(settings.phases))
    except ASHConfigValidationError as exc:
        ASH_LOGGER.error(f"Project '{project.key}' has an invalid configuration: {exc}")
        return _failed_outcome(
            project,
            settings,
            f"invalid configuration: {exc}",
            invalid_config=True,
            duration_seconds=time.monotonic() - started,
        )
    except Exception as exc:  # noqa: BLE001 -- one project must not sink the workspace
        ASH_LOGGER.error(f"Project '{project.key}' failed: {exc}")
        return _failed_outcome(
            project,
            settings,
            f"{type(exc).__name__}: {exc}",
            duration_seconds=time.monotonic() - started,
        )

    if changed:
        from automated_security_helper.interactions.run_ash_scan import (
            _filter_results_to_changed_files,
        )

        results = _filter_results_to_changed_files(results, changed, Path(project.path))

    run = _extract_run(results)
    results_list = list(run.get("results") or []) if run else []

    unsuppressed = [entry for entry in results_list if not entry.get("suppressions")]
    # gate_threshold, not severity_threshold: this is where a workspace severity
    # ceiling takes effect on the verdict. Reading the declared value here would
    # leave the ceiling visible in the plan and in --dry-run while changing
    # nothing about which projects fail.
    threshold = project.gate_threshold
    actionable = count_actionable_results(results_list, threshold)
    if actionable and not has_finding_at_min_severity(
        results_list, settings.min_severity
    ):
        # --min-severity is a whole-scan switch in _compute_exit_code, not a
        # per-finding filter. Mirrored here so the verdict matches.
        actionable = 0

    fail_on_findings = _resolve_fail_on_findings(settings, results)

    if abandoned is not None and abandoned.is_set():
        # Given up on while this was running. Do not write, and do not return an
        # outcome -- the outer loop already recorded FAILED for this project, and
        # a per-project results file with real findings beside a unified file
        # saying finding_count=0 is a contradiction an operator would have to
        # resolve by guessing which one to trust.
        ASH_LOGGER.warning(
            f"Project '{project.key}' finished after being abandoned at its "
            f"timeout; discarding its results rather than contradicting the "
            f"workspace verdict already recorded for it."
        )
        return _failed_outcome(
            project,
            settings,
            "abandoned at its project_timeout; the scan completed later and its "
            "results were discarded",
            duration_seconds=time.monotonic() - started,
        )

    _write_project_results(project_output, results)

    # Where the ceiling could not reach, computed from the findings actually
    # present rather than asserted about a scanner. Only when the ceiling really
    # did tighten this project: a disclosure printed on every scan is noise, and
    # noise gets skipped. ceiling_unreachable_counts returns {} when the two
    # thresholds are equal, so this is belt and braces rather than the only guard.
    unreachable: Dict[str, int] = {}
    if project.threshold_tightened_by_policy:
        unreachable = ceiling_unreachable_counts(
            results_list,
            declared_threshold=project.severity_threshold,
            effective_threshold=threshold,
        )

    outcome = WorkspaceProjectResult(
        project=project.key,
        relative_path=project.relative_path,
        display_label=project.display_label,
        status=ProjectRunStatus.COMPLETED,
        severity_threshold=threshold,
        finding_count=len(unsuppressed),
        actionable_finding_count=actionable,
        exceeds_threshold=bool(actionable) and fail_on_findings,
        duration_seconds=time.monotonic() - started,
        output_path=output_path,
        scanners=_scanner_statuses(results),
        ceiling_unreachable_findings=unreachable,
    )
    return _ProjectRun(outcome=outcome, run=run)


def _project_config_with_policy(
    project: ProjectPlan, settings: ProjectScanSettings
) -> Any:
    """One project's config, with CLI overrides applied and policy merged in.

    DO NOT copy ``resolver.py``'s ``resolve_config`` call to write this
    ---------------------------------------------------------------------
    That call is the shape this function must NOT have, and the mistake is
    invisible. The resolver historically resolved without ``config_overrides``,
    so a version of this function that imitates it drops every
    ``--config-overrides`` value silently. The orchestrator skips its own
    resolution when handed a ``resolved_config``, so there is no second chance
    and no error -- the scan simply runs with settings the operator did not
    choose and reports success.

    Note the plan carries only ``config_source``, a path, and not the resolver's
    ``AshConfig`` object. So there is nothing to reuse, which means the wrong
    implementation looks like deliberate re-resolution rather than a shortcut.

    Policy is merged, not substituted
    ---------------------------------
    ``policy_suppressions`` and ``policy_ignore_paths`` are appended to whatever
    the project declared. Replacing either list would silently un-suppress
    findings the project's own config had suppressed -- a security-relevant
    regression that raises no error.

    Args:
        project: The resolved plan entry, carrying the pushed-down policy.
        settings: The run's settings, for ``config_overrides``.

    Returns:
        The ``AshConfig`` to hand the orchestrator as ``resolved_config``.

    Raises:
        ASHConfigValidationError: When the project's config is invalid or an
            override cannot be applied. Fatal rather than dropped; the caller
            records the project FAILED and the run exits 3.
    """
    from automated_security_helper.config.resolve_config import resolve_config

    config = resolve_config(
        config_path=project.config_source,
        source_dir=Path(project.path),
        fallback_to_default=True,
        # Load-bearing. See the warning above.
        config_overrides=list(settings.config_overrides),
    )

    # Preserves the diagnostic the orchestrator used to emit from config_path,
    # which is the only thing dropping that argument costs.
    ASH_LOGGER.verbose(
        f"Project '{project.key}' configuration path: "
        f"{project.config_source or 'ASH default config'}"
    )

    if project.policy_suppressions:
        config.global_settings.suppressions = list(
            config.global_settings.suppressions
        ) + list(project.policy_suppressions)
    if project.policy_ignore_paths:
        config.global_settings.ignore_paths = list(
            config.global_settings.ignore_paths
        ) + list(project.policy_ignore_paths)

    return config


def _extract_run(results: Any) -> Optional[Dict[str, Any]]:
    """The project's single SARIF run as a plain dict, or None.

    Single, because ``SarifReport.merge_sarif_report`` collapses every scanner
    into ``runs[0]``. Anything beyond the first run would be a shape this code has
    never seen, so it is logged rather than silently discarded.
    """
    sarif = getattr(results, "sarif", None)
    runs = getattr(sarif, "runs", None) or []
    if not runs:
        return None
    if len(runs) > 1:
        ASH_LOGGER.warning(
            f"A project scan produced {len(runs)} SARIF runs; workspace mode "
            f"expects one per project and will carry only the first."
        )
    return runs[0].model_dump(by_alias=True, exclude_none=True, mode="json")


def _resolve_fail_on_findings(settings: ProjectScanSettings, results: Any) -> bool:
    """Whether this project's actionable findings should fail it.

    Same precedence as ``_compute_exit_code``: the CLI value, then the project's
    own config, then True.
    """
    if settings.fail_on_findings is not None:
        return settings.fail_on_findings
    config = getattr(results, "ash_config", None)
    configured = getattr(config, "fail_on_findings", None)
    if configured is not None:
        return bool(configured)
    return True


def _scanner_statuses(results: Any) -> Dict[str, str]:
    """Per-scanner final status for one project, as plain strings."""
    statuses: Dict[str, str] = {}
    for name, info in (getattr(results, "scanner_results", None) or {}).items():
        status = getattr(info, "status", None)
        value = getattr(status, "value", status)
        statuses[str(name)] = str(value) if value is not None else "UNKNOWN"
    return statuses


def _write_project_results(project_output: Path, results: Any) -> None:
    """Write the project's own ``ash_aggregated_results.json``.

    Written even for a project with no findings, so that
    ``projects/<key>/`` is a complete single-project output tree an operator can
    point existing tooling at.
    """
    try:
        content = results.model_dump_json(indent=2, by_alias=True)
    except AttributeError:
        content = json.dumps(results, indent=2, default=str)
    project_output.mkdir(parents=True, exist_ok=True)
    (project_output / RESULTS_FILENAME).write_text(content, encoding="utf-8")


def execute_workspace(
    plan: WorkspacePlan,
    settings: ProjectScanSettings,
    *,
    orchestrator_factory: Optional[OrchestratorFactory] = None,
    reporter_classes: Optional[List[type]] = None,
) -> WorkspaceRunResult:
    """Scan every active project in *plan* and write the unified results.

    Args:
        plan: The resolved plan from
            :func:`automated_security_helper.workspace.resolver.resolve_workspace`.
        settings: Everything the per-project scans need beyond the plan.
        orchestrator_factory: Builds one project's orchestrator. Defaults to
            ``ASHScanOrchestrator.create``; injected only by tests, so production
            callers never pass it.
        reporter_classes: The reporters the workspace-level report step considers.
            Defaults to the plugin registry; injected only by tests.

    Returns:
        The unified results path, the process exit code, and the payload.

    Raises:
        WorkspaceDefinitionError: When a project is not a git repository under
            ``precommit`` without ``--allow-missing-projects``, or when an enabled
            reporter declares itself unsupported in workspace mode. Raised rather
            than recorded because nothing has been scanned yet -- that is an
            exit-4 refusal, not a project failure.
    """
    if orchestrator_factory is None:
        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        orchestrator_factory = ASHScanOrchestrator.create

    started = time.monotonic()
    output_dir = Path(settings.output_dir)
    aggregator = WorkspaceAggregator(plan=plan, output_dir=output_dir)

    # Resolution-time skips first, so they appear in the payload even though no
    # work is done for them.
    collected: Dict[str, _ProjectRun] = {}
    for project in plan.projects:
        if project.skipped:
            collected[project.key] = _skipped_outcome(
                project,
                settings,
                project.skip_reason or SkippedProjectReason.ERROR,
                project.skip_detail,
            )

    active = plan.active_projects

    # The gate can refuse the whole run, and it must do so before any project is
    # scanned: reporting a partial workspace and then refusing is worse than
    # refusing outright.
    if settings.precommit or settings.changed_files_only:
        for project in active:
            changed_file_set(project, settings)

    # The pool is sized down to the project count -- no point starting four
    # workers for two projects -- but the payload records the *configured* bound,
    # because that is the knob the operator set. How much parallelism actually
    # happened is min(that, len(projects)), and both numbers are in the payload.
    configured_bound = max(1, settings.max_parallel_projects)
    # Before the pool, never inside it: the registry is process-global and the
    # first project to touch it would otherwise freeze the scanner set for all.
    prewarm_plugin_registry(plan, settings)

    reports_requested = _REPORT_PHASE in settings.phases
    if reports_requested:
        # Before the scan, for two reasons. The operator learns immediately
        # rather than after paying for the whole workspace; and once
        # ``aggregator.write`` has recorded the exit code *into* the results
        # file, a refusal could only be surfaced by exiting with a status that
        # file does not contain -- two answers to one question, which is what
        # models.workspace's exit-code contract exists to avoid.
        #
        # After prewarm_plugin_registry, and that order is load-bearing rather
        # than incidental: reading the reporter set from a cold registry would
        # memoise whatever was resolvable at that moment into
        # ``_resolved_plugins["reporter"]``, and prewarm would then hand every
        # project the memoised subset. That is exactly the defect prewarm exists
        # to fix, reintroduced from the other end.
        #
        # Gated on the report phase because a reporter that cannot produce a
        # workspace artefact is not an operator's problem until they ask for one.
        refusing = unsupported_reporter_names(
            plan,
            output_dir,
            output_formats=settings.output_formats,
            python_based_plugins_only=settings.python_based_plugins_only,
            reporter_classes=reporter_classes,
        )
        if refusing:
            raise WorkspaceDefinitionError(
                f"reporter(s) {', '.join(refusing)} declare that they cannot "
                f"produce a correct report in workspace mode, and are enabled. "
                f"Nothing was scanned. Disable them, narrow --output-format to "
                f"exclude them, or scan the projects separately."
            )

    bound = min(configured_bound, len(active) or 1)
    ASH_LOGGER.info(
        f"Scanning {len(active)} workspace project(s), "
        f"up to {bound} at a time"
        + (
            f", {settings.project_timeout}s per project"
            if settings.project_timeout
            else ""
        )
    )

    collected.update(_run_projects(active, settings, orchestrator_factory, bound))

    for project in plan.projects:
        run = collected.get(project.key)
        if run is None:
            continue
        aggregator.add(run.outcome, run.run, project)
        # Drop the run as soon as it is spooled: peak memory is what makes a
        # 20-project workspace viable.
        run.run = None

    exit_code = int(workspace_exit_code(entry.outcome for entry in collected.values()))
    wall_clock = time.monotonic() - started
    results_path = aggregator.write(
        exit_code=exit_code,
        wall_clock_seconds=wall_clock,
        max_parallel_projects=configured_bound,
        project_timeout=settings.project_timeout,
    )
    payload = aggregator.results_payload(
        exit_code,
        wall_clock,
        max_parallel_projects=configured_bound,
        project_timeout=settings.project_timeout,
    )

    # After the results file, because the merged reporters read it back -- see
    # "Why the whole model is loaded back" in workspace.reporting. Reading the
    # written file rather than a parallel in-memory model is what makes it
    # impossible for the workspace reports to disagree with it.
    report_outcome: Optional[WorkspaceReportOutcome] = None
    if reports_requested:
        report_outcome = emit_workspace_reports(
            plan=plan,
            output_dir=output_dir,
            results_path=results_path,
            output_formats=settings.output_formats,
            python_based_plugins_only=settings.python_based_plugins_only,
            ignore_suppressions=settings.ignore_suppressions,
            reporter_classes=reporter_classes,
        )

    return WorkspaceRunResult(
        results_path=results_path,
        exit_code=exit_code,
        payload=payload,
        project_durations={
            key: entry.outcome.duration_seconds for key, entry in collected.items()
        },
        report_outcome=report_outcome,
    )


def _run_projects(
    active: List[ProjectPlan],
    settings: ProjectScanSettings,
    orchestrator_factory: OrchestratorFactory,
    bound: int,
) -> Dict[str, _ProjectRun]:
    """Run the active projects on a bounded pool, honouring per-project deadlines.

    The deadline is measured from when a project *starts*, which is why the worker
    publishes its own start time. Measuring from submission would time out a
    project that had merely been waiting for a slot.
    """
    if not active:
        return {}

    collected: Dict[str, _ProjectRun] = {}
    start_times: Dict[str, float] = {}
    start_lock = Lock()
    # Set when a project is abandoned, so its worker can tell it has been given
    # up on and stop before writing output the workspace has already contradicted.
    abandoned: Dict[str, Event] = {project.key: Event() for project in active}

    def worker(project: ProjectPlan) -> _ProjectRun:
        with start_lock:
            start_times[project.key] = time.monotonic()
        return _scan_one_project(
            project, settings, orchestrator_factory, abandoned[project.key]
        )

    pool = ThreadPoolExecutor(max_workers=bound)
    try:
        futures: Dict[Future, ProjectPlan] = {
            pool.submit(worker, project): project for project in active
        }
        pending: Set[Future] = set(futures)
        timeout = settings.project_timeout
        # Workers lost to abandoned projects. Each one is a pool slot that will
        # never come back, because the thread cannot be interrupted.
        lost_workers = 0

        while pending:
            done, pending = wait(
                pending,
                timeout=_DEADLINE_POLL_SECONDS if timeout else None,
                return_when=FIRST_COMPLETED,
            )
            for future in done:
                project = futures[future]
                try:
                    collected[project.key] = future.result()
                except Exception as exc:  # noqa: BLE001 -- worker already guards
                    collected[project.key] = _failed_outcome(
                        project, settings, f"{type(exc).__name__}: {exc}"
                    )

            if not timeout:
                continue

            now = time.monotonic()
            for future in list(pending):
                project = futures[future]
                with start_lock:
                    begin = start_times.get(project.key)
                if begin is None:
                    # Queued and never started. It has not overrun a budget
                    # because it has not been given one yet; whether it ever can
                    # is decided below, from how many workers are left.
                    continue
                if now - begin <= timeout:
                    continue
                elapsed = now - begin
                ASH_LOGGER.error(
                    f"Project '{project.key}' exceeded its {timeout}s budget "
                    f"after {elapsed:.1f}s and was abandoned. Its worker cannot "
                    f"be interrupted and will run to completion in the "
                    f"background."
                )
                abandoned[project.key].set()
                lost_workers += 1
                collected[project.key] = _failed_outcome(
                    project,
                    settings,
                    f"timed out after {elapsed:.1f}s, exceeding the "
                    f"{timeout}s project_timeout budget",
                    duration_seconds=elapsed,
                )
                pending.discard(future)

            if lost_workers < bound:
                continue

            # Every worker is held by an abandoned project, so nothing still
            # queued can ever start and waiting would block on threads that are
            # never coming back. Without this the timeout bounded nothing
            # whenever the bound was smaller than the project count -- measured,
            # three projects at bound 1 with a 1s budget ran past 12s -- which
            # is precisely the shape the default bound of 4 produces for a
            # workspace of five.
            never_started = [
                future
                for future in list(pending)
                if start_times.get(futures[future].key) is None
            ]
            for future in never_started:
                project = futures[future]
                # Cancel first: a queued future can still be cancelled, and that
                # stops it starting after we have already reported it failed.
                future.cancel()
                abandoned[project.key].set()
                ASH_LOGGER.error(
                    f"Project '{project.key}' never started: all {bound} worker "
                    f"slot(s) are held by project(s) abandoned at the "
                    f"{timeout}s project_timeout, and an abandoned worker cannot "
                    f"be reclaimed. Raise max_parallel_projects, raise "
                    f"project_timeout, or scan the slow project separately."
                )
                collected[project.key] = _failed_outcome(
                    project,
                    settings,
                    f"never started: all {bound} worker slot(s) were held by "
                    f"project(s) that exceeded the {timeout}s project_timeout",
                )
                pending.discard(future)
            if pending:
                # Anything left here has started and is inside its budget, so it
                # is still worth waiting for.
                continue
            break
    finally:
        # wait=False so an abandoned worker does not delay the workspace result.
        # The interpreter still joins it at exit; see the module docstring.
        pool.shutdown(wait=False)

    return collected


def refused_results(plan: WorkspacePlan, detail: str) -> WorkspaceResults:
    """The payload for a workspace that was refused before anything ran.

    Exists so a caller that refuses at exit 2 can still say *which* 2 it meant.
    See "living with the collision at code 2" in
    :mod:`automated_security_helper.models.workspace`.
    """
    return WorkspaceResults(
        workspace_file=plan.workspace_file,
        workspace_root=plan.workspace_root,
        status="refused",
        exit_code=int(WorkspaceExitCode.WORKSPACE_ERROR),
        projects=[],
        unconvertible_finding_paths=0,
        refusal_detail=detail,
    )
