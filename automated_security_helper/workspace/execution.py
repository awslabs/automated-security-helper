# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run a resolved workspace as N independently scoped scans.

Why this module exists
----------------------
Phase 1 produced a plan and refused to act on it. This is the part that acts, and
its whole job is to hold one invariant while doing so:

    For any project P, the findings reported for P and the pass/fail verdict for P
    are identical to what ``ash --source-dir P`` would produce.

Everything below follows from that. Nothing here applies a workspace-level policy,
because a workspace-level policy can change a project's verdict and that arrives
in a later phase, explicitly and visibly, rather than sneaking in with an
execution change.

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

Timeouts bound the verdict, not the worker
------------------------------------------
``project_timeout`` is measured from the moment a project *starts*, not from when
it was submitted, so a project queued behind others is not punished for waiting.
On expiry the project is recorded FAILED, the workspace exits non-zero, and every
other project still completes.

The worker thread is not killed, because Python cannot preempt a thread. The pool
is shut down with ``wait=False`` so the workspace reports immediately, but the
abandoned worker runs to completion in the background and the interpreter's own
exit handler joins it -- so a genuinely wedged project delays process exit even
though it does not delay the result. Two things bound the exposure: scanners run
as subprocesses with their own timeouts, so a hung *tool* is already handled
below this layer, and the residual case is an in-process scanner stuck in Python.
Fixing it properly means running each project in a subprocess, which is a larger
change than this phase and would move the per-project scan out of
``core/orchestrator.py``.

Rejected: ``future.result(timeout=...)`` over the futures in submission order.
That measures from submission, so with a bound of 2 and a timeout of 60s the
fifth project can be recorded as timed out before it has started.

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
from threading import Lock
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

#: How often the outer loop wakes to check per-project deadlines. Small enough
#: that a timeout is reported promptly, large enough not to spin.
_DEADLINE_POLL_SECONDS = 0.05

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


@dataclass
class _ProjectRun:
    """One project's outcome plus the SARIF run it produced, if any."""

    outcome: WorkspaceProjectResult
    run: Optional[Dict[str, Any]] = None


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
            severity_threshold=project.severity_threshold,
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
            severity_threshold=project.severity_threshold,
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
) -> _ProjectRun:
    """Scan one project in its own scope and reduce it to an outcome plus a run."""
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
        orchestrator = orchestrator_factory(
            source_dir=Path(project.path),
            output_dir=project_output,
            work_dir=project_output / ASH_WORK_DIR_NAME,
            enabled_scanners=list(settings.enabled_scanners),
            excluded_scanners=list(settings.excluded_scanners),
            config_path=project.config_source,
            config_overrides=list(settings.config_overrides),
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
            metadata=None,
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
    threshold = project.severity_threshold
    actionable = count_actionable_results(results_list, threshold)
    if actionable and not has_finding_at_min_severity(
        results_list, settings.min_severity
    ):
        # --min-severity is a whole-scan switch in _compute_exit_code, not a
        # per-finding filter. Mirrored here so the verdict matches.
        actionable = 0

    fail_on_findings = _resolve_fail_on_findings(settings, results)

    _write_project_results(project_output, results)

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
    )
    return _ProjectRun(outcome=outcome, run=run)


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
) -> WorkspaceRunResult:
    """Scan every active project in *plan* and write the unified results.

    Args:
        plan: The resolved plan from
            :func:`automated_security_helper.workspace.resolver.resolve_workspace`.
        settings: Everything the per-project scans need beyond the plan.
        orchestrator_factory: Builds one project's orchestrator. Defaults to
            ``ASHScanOrchestrator.create``; injected only by tests, so production
            callers never pass it.

    Returns:
        The unified results path, the process exit code, and the payload.

    Raises:
        WorkspaceDefinitionError: When a project is not a git repository under
            ``precommit`` without ``--allow-missing-projects``. Raised rather than
            recorded because nothing has been scanned yet and the operator's flags
            are contradictory -- that is an exit-2 refusal, not a project failure.
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
    return WorkspaceRunResult(
        results_path=results_path,
        exit_code=exit_code,
        payload=payload,
        project_durations={
            key: entry.outcome.duration_seconds for key, entry in collected.items()
        },
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

    def worker(project: ProjectPlan) -> _ProjectRun:
        with start_lock:
            start_times[project.key] = time.monotonic()
        return _scan_one_project(project, settings, orchestrator_factory)

    pool = ThreadPoolExecutor(max_workers=bound)
    try:
        futures: Dict[Future, ProjectPlan] = {
            pool.submit(worker, project): project for project in active
        }
        pending: Set[Future] = set(futures)
        timeout = settings.project_timeout

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
                if begin is None or now - begin <= timeout:
                    continue
                elapsed = now - begin
                ASH_LOGGER.error(
                    f"Project '{project.key}' exceeded its {timeout}s budget "
                    f"after {elapsed:.1f}s and was abandoned. Its worker cannot "
                    f"be interrupted and will run to completion in the "
                    f"background."
                )
                collected[project.key] = _failed_outcome(
                    project,
                    settings,
                    f"timed out after {elapsed:.1f}s, exceeding the "
                    f"{timeout}s project_timeout budget",
                    duration_seconds=elapsed,
                )
                pending.discard(future)
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
