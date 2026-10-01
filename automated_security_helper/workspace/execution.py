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
Four places, and no others:

* The verdict reads ``project.gate_threshold`` rather than
  ``project.severity_threshold``, so a workspace severity ceiling decides which
  findings are actionable. This one changes only the JUDGEMENT of findings, never
  their discovery, so a project scanned under a ceiling reports the same findings
  as ``ash --source-dir P`` and differs only in how many are counted actionable.
* :func:`_project_config_with_policy` appends ``workspace.suppressions`` and
  ``workspace.ignore_paths`` to the project's own lists, and switches on each
  scanner in ``workspace.additional_scanners`` that the project had turned off.
* :func:`_tag_policy_origin_findings` marks the findings that came from a scanner
  only the policy asked for, so a reader can tell them from the project's own.
* The verdict then excludes those findings unless ``policy_scanners_gate`` is
  set -- BOTH halves of it, the threshold count and the completeness check. A
  policy scanner whose tool is missing must not fail a project either, or the
  flag is honoured for findings and ignored for the exit code.

An operator can still reproduce a workspace verdict locally, now by passing the
effective threshold and the same scanner set; ``--dry-run`` prints both.

Why these fields were once withheld, and why that reasoning is dead
-------------------------------------------------------------------
This section used to explain that the three config-level policy fields could not
reach the scan. Recorded here rather than deleted, because it was the only
written account of the feature's absence and it was wrong on every count -- a
reader who found it would have been talked out of work that was already
unblocked. It claimed:

* that ``ASHScanOrchestrator.__init__`` unconditionally overwrites ``config`` by
  calling ``resolve_config``, so no caller could hand it a merged config. It does
  not. ``orchestrator.py:257-261`` adopts ``resolved_config`` verbatim when one is
  given, and resolves only in the ``else`` branch at ``:263``. The field exists
  for precisely this purpose, and ``:200-228`` refuses the inputs to the
  resolution it is being told to skip.
* that the alternative channel ``config_overrides`` FAILS OPEN, logging a warning
  and returning the original config. It does not. ``apply_config_overrides``
  raises ``ASHConfigValidationError`` at ``resolve_config.py:154``, ``:161`` and
  ``:169``. That channel is still unused here, but for the narrower reason that a
  string-keyed ``key.path=value`` cannot express "append to this list" -- not
  because it swallows errors.
* that "Two policy fields" were affected, while naming three.

The durable lesson is about the shape of such a record, not about these three
facts. The natural reading is that the paragraph was once true and rotted, and
that is not what happened: ``resolved_config`` landed in b52704b8 (#474) and the
raising ``apply_config_overrides`` in fee0c695 (#475), both on 2026-08-26, and
both are ancestors of 341e46fe (#456) -- the commit that wrote this paragraph on
2026-08-27. So it described a tree that had already stopped existing, on the day
it was written, and the three-named-as-two slip shipped in that same commit. The
mechanism is a long-lived branch: prose written at branch point describes the
tree as it was then, and merging does not re-check it. Nothing caught it because
a docstring has no test, and a claim about two other modules is exactly what a
reviewer of this one will not open.

Which is why anything written in the form "X cannot be done because Y" belongs
next to the file and line of Y. Not for the reader's convenience -- for the
author's, because having to cite the line means having to look at it, and looking
at ``orchestrator.py`` here would have shown ``resolved_config`` already sitting
in the field list.

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
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Set, Tuple

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
from automated_security_helper.utils.atomic_write import write_text_atomically
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.workspace.aggregation import (
    RESULTS_FILENAME,
    WorkspaceAggregator,
    count_actionable_results,
    has_finding_at_min_severity,
    incomplete_scanners_for_project,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan
from automated_security_helper.workspace.policy import (
    ceiling_unreachable_counts,
    normalise_scanner_name,
)
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

#: Marks a finding that came from a scanner only ``workspace.additional_scanners``
#: asked for, rather than one the project enables itself. Written to
#: ``properties.origin`` on the SARIF result and added to ``properties.tags``.
#: The spelling is the one the CLI reference and ``AshWorkspaceConfig.json``
#: already document, so it is a constant rather than a literal at each use.
POLICY_ORIGIN = "workspace-policy"

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
    fail_on_incomplete_scanners: Optional[bool] = None
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
    #: Config file to use for a project that declares none of its own, in place
    #: of ASH's built-in default. A project with an ``.ash.yaml`` is unaffected.
    #:
    #: Must hold the SAME value the plan was resolved with -- ``resolver``'s
    #: ``default_config``. The resolver computes each project's reported threshold
    #: and ``_project_config_with_policy`` below re-resolves at scan time, so a
    #: value set here but not there (or the reverse) makes ``--dry-run`` report a
    #: plan the scan does not run, with nothing raising. The MCP workspace tools
    #: set both from one variable for that reason.
    default_config_path: Optional[str] = None


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

    # Before _extract_run, so the tag is present in both the model written to
    # projects/<key>/ and the dict carried into the unified file.
    _tag_policy_origin_findings(results, project)

    run = _extract_run(results)
    results_list = list(run.get("results") or []) if run else []

    unsuppressed = [entry for entry in results_list if not entry.get("suppressions")]
    policy_origin = [entry for entry in unsuppressed if _is_policy_origin(entry)]

    # What the verdict is allowed to see. Findings from a scanner only the policy
    # added are REPORTED either way -- they are in `unsuppressed` above and carry
    # their tag -- but they decide nothing unless the operator set
    # policy_scanners_gate. A workspace that adds a scanner to gather visibility
    # must not thereby fail projects that never opted into it.
    gating_results = (
        results_list
        if project.policy_scanners_gate
        else [entry for entry in results_list if not _is_policy_origin(entry)]
    )

    # gate_threshold, not severity_threshold: this is where a workspace severity
    # ceiling takes effect on the verdict. Reading the declared value here would
    # leave the ceiling visible in the plan and in --dry-run while changing
    # nothing about which projects fail.
    threshold = project.gate_threshold
    actionable = count_actionable_results(gating_results, threshold)
    if actionable and not has_finding_at_min_severity(
        gating_results, settings.min_severity
    ):
        # --min-severity is a whole-scan switch in _compute_exit_code, not a
        # per-finding filter. Mirrored here so the verdict matches.
        actionable = 0

    fail_on_findings = _resolve_fail_on_findings(settings, results)

    # The completeness half of the verdict, alongside the threshold half above.
    # Without it a project whose scanners never ran reported zero findings and
    # SUCCESS, while `ash --source-dir P` on the same project exited 1 -- the
    # workspace layer mirrored only the threshold pass.
    incomplete = incomplete_scanners_for_project(results)
    fail_on_incomplete = _resolve_fail_on_incomplete_scanners(settings, results)
    # The same policy_scanners_gate exclusion, applied to the completeness half.
    # Without it the flag is honoured for findings and ignored for the exit code:
    # a policy scanner whose tool is absent reads MISSING, MISSING fails the
    # completeness gate, and a workspace adding a scanner "for visibility" would
    # fail every project on every host lacking that tool -- with no finding
    # involved at all. Still reported in `incomplete_scanners`, because an
    # operator has not asked to be told a scan was complete when it was not.
    gating_incomplete = incomplete
    if incomplete and project.policy_scanners and not project.policy_scanners_gate:
        policy_names = {
            normalise_scanner_name(name) for name in project.policy_scanners
        }
        gating_incomplete = [
            name
            for name in incomplete
            if normalise_scanner_name(name) not in policy_names
        ]

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

    statuses = _scanner_statuses(results)
    # After the scan, because "no scanner of this name ran" is the only honest
    # test for a policy scanner that does not exist -- the registry is per
    # project, so nothing earlier can tell a typo from a plugin.
    _warn_on_policy_scanners_that_never_ran(project, statuses)

    outcome = WorkspaceProjectResult(
        project=project.key,
        relative_path=project.relative_path,
        display_label=project.display_label,
        status=ProjectRunStatus.COMPLETED,
        severity_threshold=threshold,
        finding_count=len(unsuppressed),
        actionable_finding_count=actionable,
        policy_origin_finding_count=len(policy_origin),
        exceeds_threshold=bool(actionable) and fail_on_findings,
        duration_seconds=time.monotonic() - started,
        output_path=output_path,
        scanners=statuses,
        incomplete_scanners=incomplete,
        scan_incomplete=bool(gating_incomplete) and fail_on_incomplete,
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
    regression that raises no error. ``policy_scanners`` is likewise additive:
    it only ever sets ``enabled`` to True, and never to False, so a policy
    cannot take away a scanner a project chose to run.

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

    # ``config_source`` is None for a project that declared no config. The plan was
    # resolved with the same fallback, so the resolver already recorded the
    # fallback as this project's config_source when one applied -- this branch
    # covers a plan built without it, and a hand-built plan.
    config_path = project.config_source or settings.default_config_path

    config = resolve_config(
        config_path=config_path,
        source_dir=Path(project.path),
        fallback_to_default=True,
        # Load-bearing. See the warning above.
        config_overrides=list(settings.config_overrides),
    )

    # Preserves the diagnostic the orchestrator used to emit from config_path,
    # which is the only thing dropping that argument costs.
    ASH_LOGGER.verbose(
        f"Project '{project.key}' configuration path: "
        f"{config_path or 'ASH default config'}"
    )

    if project.policy_suppressions:
        config.global_settings.suppressions = list(
            config.global_settings.suppressions
        ) + list(project.policy_suppressions)
    if project.policy_ignore_paths:
        config.global_settings.ignore_paths = list(
            config.global_settings.ignore_paths
        ) + list(project.policy_ignore_paths)
    if project.policy_scanners:
        _enable_policy_scanners(config, project.policy_scanners)

    return config


def _enable_policy_scanners(config: Any, names: Iterable[str]) -> None:
    """Switch on every scanner ``workspace.additional_scanners`` requires.

    Why the config and not ``enabled_scanners``
    ------------------------------------------
    ``ScanPhase._execute_phase`` decides enablement as ``is_in_enabled_scanners
    and is_enabled``, where ``is_enabled`` is ``plugin_instance.config.enabled``
    -- reached from this object through ``AshConfig.get_plugin_config``. So this
    is the half of that conjunction a policy is entitled to move.

    The other half, ``enabled_scanners``, is deliberately left alone. It is the
    operator's own ``--scanners`` allowlist, and a policy widening a run they
    narrowed by hand is the one direction they cannot anticipate. The consequence
    is a real limitation rather than an oversight: ``ash --workspace W --scanners
    bandit`` runs bandit and nothing else, policy or no policy.
    ``test_an_explicit_scanner_selection_still_bounds_the_run`` pins it so the
    decision has to be changed rather than drifted out of.

    Name folding, and why it cannot be a second copy of the rule
    -----------------------------------------------------------
    The policy names a scanner the way an operator types it (``cdk-nag``); the
    config field is the Python name (``cdk_nag``) carrying that spelling as its
    alias. Both are indexed here through
    :func:`~automated_security_helper.workspace.policy.normalise_scanner_name`,
    the same function the classifier used to decide this scanner was policy-added
    in the first place. A private re-implementation would agree with it on every
    unaliased name and disagree on exactly the aliased ones, producing a policy
    that enables nothing while the plan reports that it enabled something.

    A name matching no config entry
    -------------------------------
    An entry is created for it. ``policy.py`` deliberately does not validate
    ``additional_scanners`` against the scanners ASH knows, because the plugin
    registry is not loaded at resolution time and its contents depend on each
    project's ``ash_plugin_modules``. So a name with no declared field is either a
    plugin-provided scanner -- which needs a config entry to be enabled, exactly
    as a hand-written one in the project's YAML would -- or a typo. The two are
    not distinguishable here, so neither a refusal nor a warning is honest at this
    point; :func:`_warn_on_policy_scanners_that_never_ran` reports it after the
    scan, where "it produced no status at all" is a measurement rather than a
    guess.

    Args:
        config: The project's resolved ``AshConfig``, mutated in place.
        names: The policy scanner names, in the policy's own spelling.
    """
    segment = config.scanners
    fields = type(segment).model_fields
    extra = getattr(segment, "__pydantic_extra__", None) or {}

    # Folded name -> the attribute to reach the entry through. Declared fields are
    # indexed under both their Python name and their alias; setdefault keeps a
    # declared field ahead of an extra key that folds to the same thing.
    index: Dict[str, str] = {}
    for field_name, field_info in fields.items():
        index.setdefault(normalise_scanner_name(field_name), field_name)
        if field_info.alias:
            index.setdefault(normalise_scanner_name(field_info.alias), field_name)
    for key in extra:
        index.setdefault(normalise_scanner_name(key), key)

    for name in names:
        target = index.get(normalise_scanner_name(name))
        if target is None:
            # extra="allow" on ScannerConfigSegment, so this lands in
            # __pydantic_extra__ and get_plugin_config finds it by key.
            setattr(segment, name, {"name": name, "enabled": True})
            ASH_LOGGER.verbose(
                f"Workspace policy added scanner '{name}', which this project's "
                f"configuration does not describe; it will run with default "
                f"settings if a plugin provides it."
            )
            continue
        entry = getattr(segment, target, None)
        if entry is None:
            setattr(segment, target, {"name": name, "enabled": True})
        elif isinstance(entry, dict):
            entry["enabled"] = True
        else:
            entry.enabled = True
        ASH_LOGGER.verbose(
            f"Workspace policy enabled scanner '{name}' for this project."
        )


def _is_policy_origin(result: Mapping[str, Any]) -> bool:
    """Whether this SARIF result came from a scanner only the policy added."""
    properties = result.get("properties")
    if not isinstance(properties, Mapping):
        return False
    return properties.get("origin") == POLICY_ORIGIN


def _tag_policy_origin_findings(results: Any, project: ProjectPlan) -> None:
    """Mark findings from a policy-added scanner with ``origin: workspace-policy``.

    Why here, and why on the model
    ------------------------------
    The results MODEL is mutated, not the dict :func:`_extract_run` produces from
    it. Two artefacts are written from these results and an operator reads
    whichever is nearer: ``projects/<key>/ash_aggregated_results.json`` comes from
    the model, the unified workspace file from the extracted dict. Tagging the
    dict alone would leave the per-project file reporting a policy finding as the
    project's own, which is the reading that matters most -- that file is the one
    this feature advertises as consumable by existing single-project tooling.

    Why ``properties.scanner_name`` is the attribution
    -------------------------------------------------
    It is the only per-result one available. ``SarifReport.merge_sarif_report``
    collapses every scanner into ``runs[0]``, so ``tool.driver.name`` names the
    aggregate rather than the scanner that found any given result;
    ``attach_scanner_details`` writes ``properties.scanner_name`` per result for
    exactly this reason and every scanner goes through it. A result with no
    properties is left alone rather than guessed at: nothing attributes it to a
    scanner, so nothing justifies calling it policy-origin.

    Both ``properties.origin`` and a ``workspace-policy`` entry in
    ``properties.tags`` are written. ``origin`` is what the schema and the CLI
    reference document; the tag is what reporters that group by tag can see, and
    the existing tag list is extended rather than replaced so the scanner-name tag
    survives.

    Args:
        results: One project's ``AshAggregatedResults``, mutated in place.
        project: The plan entry, for ``policy_scanners``.
    """
    if not project.policy_scanners:
        return

    wanted = {normalise_scanner_name(name) for name in project.policy_scanners}
    sarif = getattr(results, "sarif", None)
    for run in getattr(sarif, "runs", None) or []:
        for result in getattr(run, "results", None) or []:
            properties = getattr(result, "properties", None)
            if properties is None:
                continue
            scanner = getattr(properties, "scanner_name", None)
            if not isinstance(scanner, str):
                continue
            if normalise_scanner_name(scanner) not in wanted:
                continue
            # PropertyBag is extra="allow", so this creates the field. Plain
            # assignment rather than setattr: `origin` is a constant here, and
            # setattr with a literal name reads as though the name were dynamic.
            properties.origin = POLICY_ORIGIN
            tags = list(getattr(properties, "tags", None) or [])
            if POLICY_ORIGIN not in tags:
                tags.append(POLICY_ORIGIN)
            properties.tags = tags


def _warn_on_policy_scanners_that_never_ran(
    project: ProjectPlan, statuses: Mapping[str, str]
) -> None:
    """Name any policy scanner that produced no status at all.

    The surfacing point ``policy.py`` promises. ``additional_scanners`` is not
    validated against the scanners ASH knows -- it cannot be, at resolution time
    -- and the documented consequence is that a typo "surfaces when execution
    cannot find the scanner". Nothing actually surfaced it. A misspelled scanner
    produced no entry, no message, and a project that passed while the operator
    believed a required scanner had run.

    A WARNING rather than a failure. The plugin registry is per project via
    ``ash_plugin_modules``, so a CI matrix whose runners load different modules
    can legitimately produce this shape for one project and not another -- the
    same reasoning that makes a partly-unresolvable ``--scanners`` allowlist a
    warning in ``ScanPhase``. Distinguished from MISSING deliberately: MISSING
    means the scanner ran and its tool was absent, which ``incomplete_scanners``
    already reports. This is the case where no scanner of that name exists.
    """
    if not project.policy_scanners:
        return

    present = {normalise_scanner_name(name) for name in statuses}
    absent = [
        name
        for name in project.policy_scanners
        if normalise_scanner_name(name) not in present
    ]
    if absent:
        ASH_LOGGER.warning(
            f"Project '{project.key}': workspace policy requires scanner(s) "
            f"{', '.join(absent)}, but no scanner of that name ran. Check the "
            f"spelling in the policy's additional_scanners, and that any plugin "
            f"providing it is listed in ash_plugin_modules."
        )


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


def _resolve_fail_on_incomplete_scanners(
    settings: ProjectScanSettings, results: Any
) -> bool:
    """Whether this project's unrun scanners should fail it.

    Same three-step precedence as ``_resolve_fail_on_findings`` above and as
    ``run_ash_scan._resolve_fail_on_incomplete_scanners``: the CLI value, then the
    project's own config, then True.

    True as the fallback, matching ``AshConfig.fail_on_incomplete_scanners``. The
    two are the same question answered twice, and when they disagreed the answer
    depended on how far config resolution had got before it was asked.

    ``isinstance(..., bool)`` rather than a truthiness test on the config value,
    because this reaches into whatever object the orchestrator handed back: a
    partially-built model or a test double would otherwise contribute a truthy
    non-answer and turn the gate on for a project whose config never mentioned it.
    """
    if settings.fail_on_incomplete_scanners is not None:
        return settings.fail_on_incomplete_scanners
    config = getattr(results, "ash_config", None)
    configured = getattr(config, "fail_on_incomplete_scanners", None)
    if isinstance(configured, bool):
        return configured
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
    # Atomically: this directory is the project's registry entry's output tree, so
    # get_scan_progress may parse this file while the workspace is still running.
    write_text_atomically(project_output / RESULTS_FILENAME, content)


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
