#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Workspace mode over MCP: resolve a ``.code-workspace``, or scan every project in it.

Why this module exists
----------------------
Workspace mode was CLI-only. ``ash --workspace foo.code-workspace`` turns one file
into N projects, scans each with its own config, threshold and policy, and
aggregates the results -- and an MCP client had no way to ask for any of that. The
two tools here are the MCP surface for it: :func:`mcp_resolve_workspace`, the
equivalent of ``--dry-run``, and :func:`mcp_scan_workspace`, the equivalent of the
scan.

Why it does not go through ``run_ash_scan``
------------------------------------------
``interactions/run_ash_scan.py`` dispatches the workspace branch and then calls
``sys.exit`` on a non-zero code, and ``_run_workspace_mode`` calls ``sys.exit`` on
all three of its failure paths. That is right for a process whose only job is one
scan and fatal for a server: ``SystemExit`` derives from ``BaseException``, so the
``except Exception`` handlers wrapping the existing MCP tools do not catch it, and
one malformed ``.code-workspace`` file from one client would terminate the
interpreter and take every other session's in-flight scan with it -- silently,
because from the client's side the connection simply drops.

So these tools call ``workspace/resolver.py::resolve_workspace`` and
``workspace/execution.py::execute_workspace`` directly. Both raise and neither
exits. Every failure comes back as a response dictionary carrying the exit code
the CLI would have exited with, under ``exit_code``, with the meaning
``core/constants.py`` documents for it under ``exit_code_meaning``.

The settings record comes from the CLI's builder
------------------------------------------------
``build_project_scan_settings`` is imported from ``interactions/run_ash_scan.py``
rather than reimplemented. ``ProjectScanSettings`` has 24 optional fields, so a
second construction that omitted one would produce a valid record and a scan that
ran to completion with a setting nobody chose -- ``config_overrides`` and
``ignore_suppressions`` being the two where that is worst. Importing the builder
is the only arrangement in which the two paths cannot drift.

Confinement: every project, refuse the whole workspace
------------------------------------------------------
A single-directory MCP scan names one directory and ``validate_scan_target``
decides whether the server may have it. A workspace scan names one *file* and gets
N directories out of it, none of which the client stated -- a strictly larger
reach, arrived at indirectly. So every resolved project directory is validated,
and one project outside the permitted roots refuses the whole workspace. Scanning
the ones that pass and reporting success is the failure mode workspace mode exists
to avoid: a green result covering fewer projects than the operator believes, with
the passing projects supplying the reassurance.

Two things are deliberately *not* confined: the ``.code-workspace`` file and the
``--workspace-config`` policy file. ``ASH_MCP_ALLOWED_ROOTS`` answers "which
directories may the server read source from and write an output tree into", and
neither of those is that -- each is read once, nothing is written near it, and
``mcp_scan_directory`` already leaves ``config_path`` outside the policy for the
same reason. Confining them would break the ordinary deployment where definitions
and a shared policy live beside checkouts rather than inside one.

Ordering is forced, not chosen
------------------------------
Resolve, then confine, then execute. Confinement needs the resolved project
directories, which only resolution produces, so a workspace that is both malformed
and outside the roots reports the malformation -- which is what the operator can
act on. Every filesystem write, including the ``clean_output`` deletion, happens
after confinement.

Failure modes and known limitations
-----------------------------------
* A project skipped at resolution gets no registry entry. An entry is a claim that
  a scan is pending or running on a directory; making it for a directory nobody
  will scan would block a later legitimate scan of the same path.
* ``execute_workspace`` blocks for as long as the scans take, so it runs off the
  event loop via :func:`asyncio.to_thread`. Leaving it inline would stall every
  other session on the server for the duration.
* Progress is reported as completed projects over total projects, and the project
  key travels in the message. ``ctx.report_progress`` has no project dimension,
  and per-project scanner fractions cannot be summed into a workspace fraction --
  the monitor's scanner estimate only ever grows and is capped below 1.0, so the
  sum would never reach completion.
* ``ScanRegistry`` accepts only LOW/MEDIUM/HIGH/CRITICAL as a threshold, while an
  ASH config may declare ALL. A project declaring ALL is registered at the
  registry's default rather than refused; the real threshold is in the response
  and in the workspace payload, which is where it is read from.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence, Tuple

from automated_security_helper.cli.mcp.progress_monitor import (
    monitor_workspace_progress,
)
from automated_security_helper.cli.mcp.scan_target import (
    ASH_MCP_ALLOWED_ROOTS_ENV,
    validate_scan_target,
)
from automated_security_helper.core.constants import ASH_EXIT_CODES
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    WorkspaceDefinitionError,
)
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
    create_error_response,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    get_scan_registry,
)
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    build_project_scan_settings,
)
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceExitCode,
    WorkspaceResults,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.workspace.execution import (
    PROJECTS_DIR_NAME,
    ProjectScanSettings,
    WorkspaceRunResult,
    execute_workspace,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan
from automated_security_helper.workspace.resolver import resolve_workspace

_logger = ASH_LOGGER

#: What ``ProgressReporter`` callables are handed. Matches
#: ``Context.report_progress``, so ``ctx.report_progress`` can be passed directly.
ProgressReporter = Callable[..., Awaitable[None]]

#: The aggregated-results filename a finished project scan leaves behind. Also
#: what ``clean_output`` removes, and what the progress monitor watches for.
AGGREGATED_RESULTS_FILENAME = "ash_aggregated_results.json"

#: Thresholds ``ScanRegistry.register_scan`` accepts. An ASH config may also
#: declare "ALL", which the registry rejects, so it is normalised away rather than
#: allowed to refuse a whole workspace scan over a per-project setting.
_REGISTRY_SEVERITY_THRESHOLDS = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
_REGISTRY_DEFAULT_SEVERITY_THRESHOLD = "MEDIUM"

#: Exception class to exit code. Ordered and explicit rather than a single
#: ``except Exception``: reporting an ASH bug as exit 4 would send the operator to
#: inspect a workspace file that is correct, and reporting an invalid project
#: config as 4 rather than 3 routes it to the wrong person -- 4 means the
#: operator's workspace definition is wrong, 3 means one project's own config is.
_EXIT_CODE_BY_EXCEPTION: Tuple[Tuple[type, WorkspaceExitCode], ...] = (
    (WorkspaceDefinitionError, WorkspaceExitCode.WORKSPACE_ERROR),
    (ASHConfigValidationError, WorkspaceExitCode.INVALID_PROJECT_CONFIG),
)

#: How a project's outcome closes out its registry entry.
_REGISTRY_STATUS_BY_PROJECT_STATUS: Dict[ProjectRunStatus, MCScanStatus] = {
    ProjectRunStatus.COMPLETED: MCScanStatus.COMPLETED,
    ProjectRunStatus.FAILED: MCScanStatus.FAILED,
    ProjectRunStatus.SKIPPED: MCScanStatus.CANCELLED,
}


# ---------------------------------------------------------------------------
# Responses and exit codes
# ---------------------------------------------------------------------------


def _enum_value(value: Any) -> Any:
    """Return an enum member's value, or the value itself when it is not one."""
    return getattr(value, "value", value)


def _exit_code_for(error: Exception) -> int:
    """Map an exception onto the exit code the CLI would have exited with."""
    for exception_type, code in _EXIT_CODE_BY_EXCEPTION:
        if isinstance(error, exception_type):
            return int(code)
    return int(WorkspaceExitCode.INTERNAL_ERROR)


def _error_response(
    error: Exception,
    operation: str,
    *,
    exit_code: Optional[int] = None,
) -> Dict[str, Any]:
    """Wrap ``create_error_response`` and add the workspace exit code.

    The exit code is what a CLI caller would have seen, so an MCP client can act
    on the same three-way distinction without parsing the message. ``exit_code``
    is passed explicitly only for a refusal that is not an exception in the first
    place -- confinement -- where there is no class to map.

    ``Exception``, deliberately, and not ``BaseException``. Every caller supplies
    one: the three handlers in this module are all ``except Exception``, and the
    confinement path passes an ``MCPResourceError``. A ``BaseException`` parameter
    would imply this function could be handed a ``SystemExit`` or a
    ``KeyboardInterrupt`` and turn it into a response, and neither should be.
    ``SystemExit`` is kept out of this module by not calling the code that raises
    it rather than by catching it, and swallowing ``KeyboardInterrupt`` would leave
    the server unstoppable mid-scan.
    """
    response = create_error_response(error, operation)
    resolved = int(exit_code) if exit_code is not None else _exit_code_for(error)
    response["exit_code"] = resolved
    response["exit_code_meaning"] = ASH_EXIT_CODES.get(resolved, "unknown exit code")
    return response


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def _resolve(
    workspace_file: str,
    workspace_config: Optional[str],
    allow_missing_projects: bool,
    config_overrides: Optional[Sequence[str]],
) -> WorkspacePlan:
    """Resolve the workspace, or raise.

    ``workspace_config`` is passed through as given rather than defaulted to a
    search when it is absent: ``resolve_workspace`` refuses a named policy file
    that does not exist, and falling back to searching would apply different
    policy than the one asked for, silently.
    """
    return resolve_workspace(
        Path(workspace_file),
        allow_missing_projects=allow_missing_projects,
        workspace_config=(
            Path(workspace_config) if workspace_config is not None else None
        ),
        config_overrides=tuple(config_overrides or ()),
    )


def _plan_projects(plan: WorkspacePlan) -> List[Dict[str, Any]]:
    """The plan's per-project decisions, structured.

    Alongside the rendered plan, not instead of it: ``render()`` is for a human
    and its layout is explicitly not a contract, so a client that wants to branch
    on a threshold reads this.
    """
    return [
        {
            "project": project.key,
            "relative_path": project.relative_path,
            "path": project.path,
            "display_label": project.display_label,
            "config_source": project.config_source,
            "scanners": list(project.scanners),
            "severity_threshold": project.severity_threshold,
            "effective_severity_threshold": project.effective_severity_threshold,
            "threshold_tightened_by_policy": project.threshold_tightened_by_policy,
            "policy_scanners": list(project.policy_scanners),
            "skipped": project.skipped,
            "skip_reason": _enum_value(project.skip_reason),
            "skip_detail": project.skip_detail,
        }
        for project in plan.projects
    ]


# ---------------------------------------------------------------------------
# Confinement
# ---------------------------------------------------------------------------


def _refuse_projects_outside_the_permitted_roots(
    plan: WorkspacePlan,
) -> Optional[MCPResourceError]:
    """Validate every project that will be scanned; refuse the whole workspace if any fails.

    Only the active projects. A skipped project is never read from and never
    written to, so refusing a workspace on its account would decline work the
    server was not going to do anyway.

    The workspace root's own containment is not checked, and checking it would be
    worse than useless: the resolver already guarantees every project sits below
    the root, so one allowlisted root would then authorise the whole tree beneath
    it regardless of where the allowlist actually pointed.

    The message names the offending project *keys*. A client looking at N projects
    needs to know which one is the problem, and the key is what the rest of the
    workspace payload attributes by, so it is the only identifier that joins.
    Projects that passed are not named, so the message cannot be read as refusing
    all of them.
    """
    offending: List[Tuple[str, MCPResourceError]] = []
    for project in plan.active_projects:
        refusal = validate_scan_target(project.path)
        if refusal is not None:
            offending.append((project.key, refusal))

    if not offending:
        return None

    refused_paths = {
        key: refusal.context.get("resolved_path", "") for key, refusal in offending
    }
    detail = "; ".join(f"{key} at {path}" for key, path in refused_paths.items())
    return MCPResourceError(
        f"Workspace scan refused: {len(offending)} of {len(plan.active_projects)} "
        f"project(s) resolve outside the permitted roots, so none was scanned: "
        f"{detail}. Scanning the rest and reporting success would report a clean "
        f"result for code that was never examined. Set "
        f"{ASH_MCP_ALLOWED_ROOTS_ENV} to the directories the MCP server may scan, "
        f"or drop those folders from the workspace definition.",
        context={
            "error_category": ErrorCategory.INVALID_PATH.value,
            "workspace_file": plan.workspace_file,
            "refused_projects": sorted(refused_paths),
            "refused_project_paths": refused_paths,
            "suggestions": [
                (
                    f"Set {ASH_MCP_ALLOWED_ROOTS_ENV} to cover every project in "
                    f"the workspace"
                ),
                "Remove the refused folder entries from the .code-workspace file",
            ],
        },
    )


# ---------------------------------------------------------------------------
# Settings, output tree and registry
# ---------------------------------------------------------------------------


def _scan_options(
    plan: WorkspacePlan,
    *,
    output_dir: Optional[str],
    config_overrides: Optional[Sequence[str]],
    scanners: Optional[Sequence[str]],
    excluded_scanners: Optional[Sequence[str]],
    offline: bool,
    allow_missing_projects: bool,
) -> ScanOptions:
    """Assemble the ``ScanOptions`` the shared settings builder reads.

    ``source_dir`` is the workspace root, matching what ``cli/scan.py`` does after
    resolution: it is the tree that gets mounted in container mode and the
    directory whose ASH config supplies the two scheduling knobs, so anything else
    would read the wrong config.

    ``output_dir`` defaults beneath the workspace root rather than beneath the
    process working directory. An MCP server's cwd is whatever the editor or agent
    that launched it happened to have, which is not a location an operator would
    choose for scan output.

    ``color`` is off because an MCP client reads a JSON response and never a
    terminal, so Rich escape sequences here would be control characters inside a
    string.
    """
    workspace_root = Path(plan.workspace_root)
    return ScanOptions(
        source_dir=workspace_root,
        output_dir=(
            Path(output_dir) if output_dir else workspace_root / ".ash" / "ash_output"
        ),
        workspace_plan=plan,
        allow_missing_projects=allow_missing_projects,
        config_overrides=list(config_overrides or []),
        scanners=list(scanners or []),
        excluded_scanners=list(excluded_scanners or []),
        offline=offline,
        color=False,
        quiet=True,
        progress=False,
        show_summary=False,
    )


def _prepare_project_outputs(
    plan: WorkspacePlan,
    settings: ProjectScanSettings,
    *,
    clean_output: bool,
) -> Dict[str, Path]:
    """Create each active project's output directory and return them by key.

    The same layout ``execution._project_output_dir`` uses, because these are the
    same directories: creating them here means the registry entry can name one,
    and the progress monitor can watch one, before the scan starts.

    ``clean_output`` removes a stale aggregated-results file, mirroring the
    single-directory tool. A failure to remove one is logged and not raised: a
    leftover file makes the progress monitor report a project complete early,
    which is worse than the alternative but not worth refusing a scan over.
    """
    outputs: Dict[str, Path] = {}
    for project in plan.active_projects:
        project_output = Path(settings.output_dir) / PROJECTS_DIR_NAME / project.key
        project_output.mkdir(parents=True, exist_ok=True)
        if clean_output:
            stale = project_output / AGGREGATED_RESULTS_FILENAME
            if stale.exists():
                try:
                    stale.unlink()
                except OSError as exc:
                    _logger.warning(
                        f"Could not remove the previous results file for project "
                        f"'{project.key}' at {stale} ({exc}); progress reporting "
                        f"for this project may complete early."
                    )
        outputs[project.key] = project_output
    return outputs


def _registry_severity_threshold(project: ProjectPlan) -> str:
    """The project's gate threshold, in the vocabulary the registry accepts.

    ``ScanRegistry`` validates against LOW/MEDIUM/HIGH/CRITICAL, while an ASH
    config may declare ALL. Passing ALL through would raise out of
    ``register_scan`` and fail the whole workspace scan, which is a wildly
    disproportionate response to one project asking to report everything -- so it
    falls back to the registry's own default. The threshold the scan is actually
    judged against is unaffected; it lives on the plan and in the workspace
    payload, which is where consumers read it.
    """
    declared = project.gate_threshold
    if declared and declared.upper() in _REGISTRY_SEVERITY_THRESHOLDS:
        return declared.upper()
    if declared:
        _logger.debug(
            "MCP workspace scan: project %r declares severity threshold %r, which "
            "the scan registry cannot express; registering at %s instead.",
            project.key,
            declared,
            _REGISTRY_DEFAULT_SEVERITY_THRESHOLD,
        )
    return _REGISTRY_DEFAULT_SEVERITY_THRESHOLD


def _register_projects(
    plan: WorkspacePlan, project_outputs: Dict[str, Path]
) -> Dict[str, str]:
    """Register one scan per active project and return ``{project key: scan id}``.

    N entries rather than one for the batch, because a client that wants to poll
    progress or fetch results needs a handle per project -- and because the
    registry's duplicate rule is per directory, so one entry for N directories
    would leave every one of them unclaimed.

    A partial batch is rolled back. ``register_scan`` refuses a directory that
    already has an active scan, which a workspace sharing a project with another
    in-flight scan will hit; leaving the entries made before that point behind
    would block those directories for a scan that never ran.
    """
    registry = get_scan_registry()
    registered: Dict[str, str] = {}
    try:
        for project in plan.active_projects:
            registered[project.key] = registry.register_scan(
                directory_path=project.path,
                output_directory=str(project_outputs[project.key]),
                severity_threshold=_registry_severity_threshold(project),
                config_path=project.config_source,
            )
    except Exception:
        for scan_id in registered.values():
            registry.update_scan_status(scan_id, MCScanStatus.CANCELLED)
        raise
    return registered


def _close_registrations(
    registered: Dict[str, str],
    payload: Optional[WorkspaceResults],
    *,
    error: Optional[str] = None,
) -> None:
    """Move every entry this call made out of the active set.

    Left pending, they would each block a later scan of the same project
    directory and would make ``list_active_scans`` report work nobody is doing.
    Called on the failure path too, with ``error`` set, for the same reason.
    """
    registry = get_scan_registry()
    outcomes = (
        {entry.project: entry for entry in payload.projects}
        if payload is not None
        else {}
    )
    for key, scan_id in registered.items():
        if error is not None:
            registry.update_scan_status(
                scan_id, MCScanStatus.FAILED, error_message=error
            )
            continue
        outcome = outcomes.get(key)
        if outcome is None:
            # A registered project the payload says nothing about.
            # ``execute_workspace`` reports one entry per plan project, so this
            # does not arise in production -- but a caller that substitutes
            # ``execute_workspace`` reaches it, and an entry left pending would
            # block the next scan of that directory. Closed as completed, because
            # the run returned successfully and nothing says this project did not.
            #
            # Written as an explicit branch rather than leaning on
            # ``.get(None, COMPLETED)``: that reached the same result by looking a
            # None key up in a dict keyed by ProjectRunStatus, which is a type
            # error that happened to behave.
            registry.update_scan_status(scan_id, MCScanStatus.COMPLETED)
            continue
        status = _REGISTRY_STATUS_BY_PROJECT_STATUS.get(
            outcome.status, MCScanStatus.COMPLETED
        )
        if status is MCScanStatus.FAILED:
            registry.update_scan_status(scan_id, status, error_message=outcome.error)
        else:
            registry.update_scan_status(scan_id, status)


def _project_verdicts(
    payload: WorkspaceResults, scan_ids: Dict[str, str]
) -> List[Dict[str, Any]]:
    """The per-project outcome, joined to the scan id the client was handed.

    Per project and not merged, because the first question about a workspace scan
    is which project failed and a merged count cannot answer it.
    """
    return [
        {
            "project": entry.project,
            "display_label": entry.display_label,
            "relative_path": entry.relative_path,
            "status": _enum_value(entry.status),
            "severity_threshold": entry.severity_threshold,
            "finding_count": entry.finding_count,
            "actionable_finding_count": entry.actionable_finding_count,
            "exceeds_threshold": entry.exceeds_threshold,
            "duration_seconds": entry.duration_seconds,
            "output_path": entry.output_path,
            "scan_id": scan_ids.get(entry.project),
            "skip_reason": _enum_value(entry.skip_reason),
            "skip_detail": entry.skip_detail,
            "error": entry.error,
            "invalid_config": entry.invalid_config,
        }
        for entry in payload.projects
    ]


async def _execute(
    plan: WorkspacePlan,
    settings: ProjectScanSettings,
    project_outputs: Dict[str, Path],
    progress_reporter: Optional[ProgressReporter],
) -> WorkspaceRunResult:
    """Run the workspace off the event loop, with a progress monitor beside it.

    ``execute_workspace`` is synchronous and blocks for as long as the scans take,
    which for N repositories is minutes. Awaiting it inline would stall every
    other MCP session on this server, including the progress polls the protocol
    relies on to keep connections alive.

    The monitor is cancelled in a ``finally`` rather than left to finish: once
    execution has returned there is nothing left to report, and an orphaned poll
    loop would keep emitting progress for a scan that is over.
    """
    monitor: Optional["asyncio.Task[None]"] = None
    if progress_reporter is not None and project_outputs:
        monitor = asyncio.create_task(
            monitor_workspace_progress(progress_reporter, dict(project_outputs))
        )
    try:
        # Resolved from this module's globals at call time, so a test that
        # replaces cli.mcp.workspace.execute_workspace is what runs.
        return await asyncio.to_thread(execute_workspace, plan, settings)
    finally:
        if monitor is not None:
            monitor.cancel()
            with suppress(asyncio.CancelledError):
                await monitor


# ---------------------------------------------------------------------------
# The two tools
# ---------------------------------------------------------------------------


async def mcp_resolve_workspace(
    workspace_file: str,
    workspace_config: Optional[str] = None,
    allow_missing_projects: bool = False,
    config_overrides: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Resolve a workspace and return the plan. Scans nothing.

    The MCP equivalent of ``ash --workspace ... --dry-run``, which is
    ``typer.echo(plan.render())`` and an exit at 0. Both halves of that matter
    here. The rendered plan comes back verbatim under ``plan``, because a plan
    reduced to a JSON dump is not the artifact ``render()`` was written to produce
    and the client cannot reconstruct the layout. And nothing is scanned, because
    a client asking what a workspace would do is asking a question -- answering it
    by scanning N repositories is expensive, writes an output tree into each one,
    and takes registry slots that block the real scan the client is about to ask
    for.

    Args:
        workspace_file: Path to the ``.code-workspace`` definition. Not subject to
            ``ASH_MCP_ALLOWED_ROOTS``; it is a config input, not a scan target.
        workspace_config: Path to a workspace policy file. Must exist when given;
            ASH does not fall back to searching, because that would apply
            different policy than the one named. Also not confined.
        allow_missing_projects: Mark absent or unreadable project directories
            skipped instead of refusing the workspace. They stay in the plan, so
            the caller can see which were dropped.
        config_overrides: ``--config-overrides`` values, applied to each project's
            config during resolution so the reported threshold is the one a scan
            would enforce.

    Returns:
        On success, ``success`` True, ``exit_code`` 0, the rendered plan under
        ``plan``, and the same decisions structured under ``projects``. On
        failure, ``create_error_response``'s keys plus ``exit_code``: 4 for a
        workspace definition or policy problem, 3 for a project whose own config
        is invalid, 1 for anything else.
    """
    try:
        plan = _resolve(
            workspace_file, workspace_config, allow_missing_projects, config_overrides
        )
    except Exception as exc:  # noqa: BLE001 -- mapped to an exit code, never raised
        return _error_response(exc, "resolve_workspace")

    return {
        "success": True,
        "exit_code": int(WorkspaceExitCode.SUCCESS),
        "exit_code_meaning": ASH_EXIT_CODES[int(WorkspaceExitCode.SUCCESS)],
        "scanned": False,
        "plan": plan.render(),
        "workspace_file": plan.workspace_file,
        "workspace_root": plan.workspace_root,
        "workspace_config_source": plan.workspace_config_source,
        "allow_missing_projects": plan.allow_missing_projects,
        "projects": _plan_projects(plan),
        "skipped_projects": [
            entry.model_dump(mode="json") for entry in plan.skipped_projects
        ],
        "message": (
            "Resolution and validation only. Nothing was scanned; call "
            "run_ash_workspace_scan to scan this plan."
        ),
    }


async def mcp_scan_workspace(
    workspace_file: str,
    workspace_config: Optional[str] = None,
    allow_missing_projects: bool = False,
    config_overrides: Optional[List[str]] = None,
    output_dir: Optional[str] = None,
    scanners: Optional[List[str]] = None,
    excluded_scanners: Optional[List[str]] = None,
    offline: bool = False,
    clean_output: bool = True,
    progress_reporter: Optional[ProgressReporter] = None,
) -> Dict[str, Any]:
    """Scan every active project in a workspace and return the per-project verdict.

    Resolves, confines, builds the settings through the CLI's own builder,
    registers one scan per project, executes off the event loop, and closes the
    registry entries out. That order is not a preference: confinement needs the
    resolved project directories, so it cannot precede resolution, and every
    filesystem write happens after it.

    Args:
        workspace_file: Path to the ``.code-workspace`` definition. Not confined.
        workspace_config: Path to a workspace policy file. Not confined.
        allow_missing_projects: Skip absent or unreadable project directories
            rather than refusing the workspace. Skipped projects get no registry
            entry and no scan id.
        config_overrides: ``--config-overrides`` values, applied per project.
        output_dir: Where the workspace output tree goes. Defaults to
            ``<workspace root>/.ash/ash_output``.
        scanners: Restrict every project to these scanners.
        excluded_scanners: Exclude these scanners from every project. Takes
            precedence over ``scanners``.
        offline: Run without network access.
        clean_output: Remove a previous per-project aggregated-results file before
            scanning. Runs after confinement, never before it.
        progress_reporter: An awaitable taking ``progress``, ``total`` and
            ``message``. ``Context.report_progress`` satisfies it. Omitted, no
            progress is emitted and the scan is otherwise identical.

    Returns:
        On success, ``success`` True, ``exit_code`` from the workspace run (0, or 2
        when a project exceeded its threshold), ``scan_ids`` mapping project key to
        registry scan id, and ``projects`` carrying each project's verdict.
        ``success`` reports whether the operation completed; the verdict is in
        ``exit_code``, because a scan that found actionable findings ran fine.

        On failure, ``create_error_response``'s keys plus ``exit_code``: 4 for a
        workspace definition, policy or confinement refusal, 3 for a project whose
        own config is invalid, 1 for anything else. Both stages are mapped --
        ``execute_workspace`` raises ``WorkspaceDefinitionError`` too, for an
        enabled reporter that cannot produce a workspace artifact or a project
        that is not a git repository under precommit.
    """
    try:
        plan = _resolve(
            workspace_file, workspace_config, allow_missing_projects, config_overrides
        )
    except Exception as exc:  # noqa: BLE001 -- mapped to an exit code, never raised
        return _error_response(exc, "scan_workspace")

    refusal = _refuse_projects_outside_the_permitted_roots(plan)
    if refusal is not None:
        return _error_response(
            refusal,
            "scan_workspace",
            exit_code=int(WorkspaceExitCode.WORKSPACE_ERROR),
        )

    # `registered` is pre-declared because the failure handler reads it whether or
    # not registration got that far. `settings` and `result` are not: both are
    # assigned inside the try before anything below reads them, and the handler
    # returns rather than falling through, so declaring them Optional would only
    # tell a type checker they might be None on a path that cannot reach the
    # reads.
    registered: Dict[str, str] = {}
    try:
        settings = build_project_scan_settings(
            _scan_options(
                plan,
                output_dir=output_dir,
                config_overrides=config_overrides,
                scanners=scanners,
                excluded_scanners=excluded_scanners,
                offline=offline,
                allow_missing_projects=allow_missing_projects,
            )
        )
        project_outputs = _prepare_project_outputs(
            plan, settings, clean_output=clean_output
        )
        registered = _register_projects(plan, project_outputs)
        result = await _execute(plan, settings, project_outputs, progress_reporter)
    except Exception as exc:  # noqa: BLE001 -- mapped to an exit code, never raised
        _close_registrations(registered, None, error=str(exc))
        return _error_response(exc, "scan_workspace")

    _close_registrations(registered, result.payload)

    exit_code = int(result.exit_code)
    return {
        "success": True,
        "exit_code": exit_code,
        "exit_code_meaning": ASH_EXIT_CODES.get(exit_code, "unknown exit code"),
        "workspace_file": plan.workspace_file,
        "workspace_root": plan.workspace_root,
        "workspace_config_source": plan.workspace_config_source,
        "output_dir": str(settings.output_dir),
        "results_path": str(result.results_path),
        "scan_ids": registered,
        "projects": _project_verdicts(result.payload, registered),
        "skipped_projects": [
            entry.model_dump(mode="json") for entry in plan.skipped_projects
        ],
    }
