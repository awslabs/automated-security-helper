#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Workspace mode over MCP: resolve a ``.code-workspace``, or scan every project in it.

Why this module exists
----------------------
Workspace mode was CLI-only. ``ashx --workspace foo.code-workspace`` turns one file
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

Both tools take a ``session_id``, and it is load-bearing rather than
informational. Confinement grants a session its own sandbox by passing the id to
``validate_scan_target``; without it, a ``.code-workspace`` file inside a tree the
client had just delivered over the protocol had every one of its projects refused
by the boundary that exists to permit exactly that, because no operator lists a
directory the server invented per connection.

The config inputs are confined too, and that reverses an earlier decision
------------------------------------------------------------------------
The ``.code-workspace`` file and the ``--workspace-config`` policy file used to be
deliberately unconfined, on the argument that ``ASH_MCP_ALLOWED_ROOTS`` answers
"which directories may the server read source from and write an output tree into"
and neither of those is that: each is read once, nothing is written near it, and
``mcp_scan_directory`` left ``config_path`` outside the policy for the same reason.
Half of that is still true and the conclusion does not follow. Reading a
caller-named path is a capability in its own right, and an unconfined one is a
file-read oracle -- point ``workspace_file`` at any path on the server and the
parse error or the resolved plan reports something about its content. The read
happens during resolution, before any project directory exists, so confining the
projects does not cover it. That made the *more* interesting half of this surface
the open one. ``config_path`` being unconfined too was a second instance of the
same defect rather than a precedent for it, and it is now confined as well.

Both now go through ``sandbox.validate_config_input``, which bites on a network
transport only. On stdio the caller launched this server and can already read any
file the server can, so the oracle is not a capability it gains there, and
confining would refuse the ordinary deployment where a definition and a shared
policy live beside checkouts rather than inside one. On a network transport that
deployment is served by ``ASH_MCP_ALLOWED_CONFIG_ROOTS`` instead of by confining
nothing.

Ordering is forced, not chosen
------------------------------
Confine the config inputs, then resolve, then confine the projects, then execute.
The config gate has to precede resolution, because resolution is the read it
guards. Project confinement cannot precede resolution, because it needs the
resolved project directories -- so a workspace that is both malformed and outside
the roots reports the malformation, which is what the operator can act on. Every
filesystem write, including the ``clean_output`` deletion, happens after both
gates.

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
"""

from __future__ import annotations

import asyncio
import os
from contextlib import suppress
from pathlib import Path
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    FrozenSet,
    List,
    Optional,
    Sequence,
    Tuple,
)

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
from automated_security_helper.core.resource_management.scan_tracking import (
    coverage_has_gap,
)
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    build_project_scan_settings,
    incomplete_scanner_reason,
)
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceExitCode,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.workspace.execution import (
    PROJECTS_DIR_NAME,
    ProjectScanSettings,
    WorkspaceRunResult,
    execute_workspace,
)
from automated_security_helper.workspace.plan import WorkspacePlan
from automated_security_helper.workspace.resolver import resolve_workspace

_logger = ASH_LOGGER

#: What ``ProgressReporter`` callables are handed. Matches
#: ``Context.report_progress``, so ``ctx.report_progress`` can be passed directly.
ProgressReporter = Callable[..., Awaitable[None]]

#: The aggregated-results filename a finished project scan leaves behind. Also
#: what ``clean_output`` removes, and what the progress monitor watches for.
AGGREGATED_RESULTS_FILENAME = "ash_aggregated_results.json"

#: What a project registers under when its plan carries no threshold at all.
#: Matches ``ScanRegistry.register_scan``'s own default. Reachable only for a
#: hand-built plan, which ``workspace/plan.py`` documents can exist; every plan
#: ``resolve_workspace`` produces gives each active project a threshold.
_UNSTATED_SEVERITY_THRESHOLD = "MEDIUM"

#: Exception class to exit code. Ordered and explicit rather than a single
#: ``except Exception``: reporting an ASH bug as exit 4 would send the operator to
#: inspect a workspace file that is correct, and reporting an invalid project
#: config as 4 rather than 3 routes it to the wrong person -- 4 means the
#: operator's workspace definition is wrong, 3 means one project's own config is.
#: ``ProfileNotRegisteredError`` is listed first and deliberately: it subclasses
#: ``ValueError``, not ``WorkspaceDefinitionError``, so ordering is not what
#: separates them -- but keeping it at the top makes the mapping read in the order
#: a reader will ask about, most-specific first.
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
    default_config: Optional[str] = None,
) -> WorkspacePlan:
    """Resolve the workspace, or raise.

    ``workspace_config`` is passed through as given rather than defaulted to a
    search when it is absent: ``resolve_workspace`` refuses a named policy file
    that does not exist, and falling back to searching would apply different
    policy than the one asked for, silently.

    ``default_config`` is the session's profile, and it has to be passed here as
    well as to the settings builder. Resolution is what computes each project's
    reported threshold, so a profile that reached only execution would make
    ``mcp_resolve_workspace`` report a plan the scan does not run -- and a dry run
    that describes a different scan is worse than no dry run, because it is the
    artifact a client checks before committing to N repository scans.
    """
    return resolve_workspace(
        Path(workspace_file),
        allow_missing_projects=allow_missing_projects,
        workspace_config=(
            Path(workspace_config) if workspace_config is not None else None
        ),
        config_overrides=tuple(config_overrides or ()),
        default_config=Path(default_config) if default_config else None,
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


def _refuse_config_inputs_outside_the_permitted_roots(
    workspace_file: str,
    workspace_config: Optional[str],
    session_id: Optional[str],
) -> Optional[MCPResourceError]:
    """Validate the two caller-named config paths before either is read.

    Before, not after, because resolution *is* the read this guards: a refusal
    reported afterwards would have already answered the question the caller was
    using the tool to ask. That is the one place in this module where a gate
    precedes resolution, and the reason is that its subject is an argument rather
    than something resolution produces.

    Only these two. The per-project ``.ash.yaml`` files a workspace pulls in are
    not caller-named -- each is found inside a project directory that project
    confinement has already accepted -- so gating them here would re-check a
    decision already made and would refuse a legitimate in-tree config on a
    deployment that granted the tree but not its own path as a config root.
    """

    from automated_security_helper.cli.mcp.sandbox import validate_config_input

    for label, candidate in (
        ("workspace definition", workspace_file),
        ("workspace policy", workspace_config),
    ):
        if candidate is None:
            continue
        refusal = validate_config_input(candidate, session_id=session_id)
        if refusal is None:
            continue
        return MCPResourceError(
            f"Workspace scan refused: the {label} file is outside the "
            f"directories this server may read config from. {refusal}",
            context=dict(refusal.context, config_input=label),
        )
    return None


def _refuse_projects_outside_the_permitted_roots(
    plan: WorkspacePlan,
    session_id: Optional[str] = None,
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
        # The session id is passed for the reason run_ash_scan passes it: this
        # session's own sandbox counts as a permitted root, so a workspace whose
        # projects live inside a tree the client delivered over the protocol is
        # scannable. Without it every such project is refused by the boundary
        # that exists to permit it, because no operator lists a directory the
        # server invented per connection.
        refusal = validate_scan_target(project.path, session_id=session_id)
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


class ProfileNotRegisteredError(ValueError):
    """A ``profile`` argument naming something the operator never registered.

    Its own class so ``_error_response`` maps it away from
    ``WorkspaceDefinitionError``: the operator's workspace file is fine, the
    client asked for a profile that does not exist, and reporting exit 4 would
    send somebody to inspect a correct definition.
    """


def _resolve_session_config(
    session_id: Optional[str],
    profile: Optional[str],
) -> Optional[str]:
    """Return the config path a workspace scan should run under, or None.

    Two sources, in order of specificity:

    * ``profile``, naming a registered profile for this one call. Materialized
      into the session's sandbox the same way ``select_profile`` does, so one code
      path produces the file and one boundary covers it.
    * the config this session already bound with ``select_profile``.

    None means neither applies, and then nothing is passed -- each project's own
    ``.ash.yaml`` discovery runs as it always has. Inventing a path here would
    scan every project under configuration nobody chose.

    An unknown ``profile`` raises rather than falling back. A workspace scan is N
    repository scans; running them all under the default config because a profile
    name was misspelled, and reporting success, is the class of outcome this
    module's confinement refusal exists to prevent.
    """

    from automated_security_helper.cli.mcp.profile_registry import (
        get_profile_registry,
        materialize_session_config,
        resolve_session_config_path,
    )

    if profile is not None:
        registry = get_profile_registry()
        entry = registry.get(profile)
        if entry is None:
            known = ", ".join(sorted(registry)) or "none registered"
            raise ProfileNotRegisteredError(
                f"unknown profile {profile!r}; known: {known}"
            )
        return materialize_session_config(session_id, entry.config)

    return resolve_session_config_path(session_id)


def _scan_options(
    plan: WorkspacePlan,
    *,
    output_dir: Optional[str],
    config_overrides: Optional[Sequence[str]],
    scanners: Optional[Sequence[str]],
    excluded_scanners: Optional[Sequence[str]],
    offline: bool,
    allow_missing_projects: bool,
    config_path: Optional[str] = None,
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
        # The session's bound or per-call profile config, or None. Passed through
        # the shared builder rather than set on the settings record afterwards, so
        # the CLI and MCP paths cannot disagree about which field carries it.
        config=config_path,
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

    The threshold registered is the project's own, verbatim -- including "ALL".
    ``get_scan_progress`` echoes this value back, so substituting anything else
    would report a scan at a threshold it is not being judged against.
    """
    registry = get_scan_registry()
    registered: Dict[str, str] = {}
    try:
        for project in plan.active_projects:
            registered[project.key] = registry.register_scan(
                directory_path=project.path,
                output_directory=str(project_outputs[project.key]),
                severity_threshold=(
                    project.gate_threshold or _UNSTATED_SEVERITY_THRESHOLD
                ),
                config_path=project.config_source,
            )
    except Exception:
        for scan_id in registered.values():
            registry.update_scan_status(scan_id, MCScanStatus.CANCELLED)
        raise
    # Claimed as RUNNING, because this call owns every entry's lifecycle from here
    # and closes each one in _close_registrations. That matters to
    # check_scan_progress: an unclaimed PENDING entry takes its status from the
    # results file, and a project's SCAN phase writes a readable one before its
    # REPORT phase has run, so a PENDING project would read as completed while its
    # reports were still being written.
    for scan_id in registered.values():
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
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
            registry.finish_scan(scan_id, MCScanStatus.FAILED, error_message=error)
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
            registry.finish_scan(scan_id, MCScanStatus.COMPLETED)
            continue
        status = _REGISTRY_STATUS_BY_PROJECT_STATUS.get(
            outcome.status, MCScanStatus.COMPLETED
        )
        if status is MCScanStatus.FAILED:
            registry.finish_scan(scan_id, status, error_message=outcome.error)
        elif status is MCScanStatus.COMPLETED:
            # The single-scan rule, applied per project: a project whose run
            # finished but whose completeness gate fired is incomplete, not
            # completed. scan_incomplete is the signal because it is the
            # project's own verdict, computed with the gate and the
            # policy-scanner exclusion already applied; re-deriving it from
            # incomplete_scanners here would ignore both.
            coverage = _project_coverage(outcome)
            if outcome.scan_incomplete and coverage_has_gap(coverage):
                registry.finish_scan(
                    scan_id, MCScanStatus.INCOMPLETE, coverage=coverage
                )
            else:
                registry.finish_scan(scan_id, status, coverage=coverage)
        else:
            registry.finish_scan(scan_id, status)


def _project_coverage(outcome: WorkspaceProjectResult) -> Dict[str, Any]:
    """One project's coverage, in the shape a single scan's progress reports it.

    Built from the facts the project's outcome already carries, so a client
    polling a workspace project and one polling a single scan read the same keys.
    ``incomplete_converters`` and ``unevaluated_rules`` are empty because a
    project's outcome does not record them, and neither of them feeds
    ``scan_incomplete``. ``stale_content_databases`` is empty for the first of
    those reasons only: a stale database does fail the project, and the outcome
    names its scanner in ``incomplete_scanners`` rather than carrying a record
    of its own.
    """
    statuses = outcome.scanners or {}
    rows = []
    for name in outcome.incomplete_scanners:
        status = str(statuses.get(name, ""))
        rows.append(
            {
                "scanner": name,
                "status": status,
                "reason": incomplete_scanner_reason(status),
                "detail": status,
            }
        )
    return {
        "incomplete_scanners": rows,
        "no_scanner_ran": bool(outcome.no_scanner_ran),
        "incomplete_converters": [],
        "unevaluated_rules": [],
        "stale_content_databases": [],
    }


#: Declared ``WorkspaceProjectResult`` fields deliberately withheld from the MCP
#: response. Empty: every field a project's outcome declares is something a client
#: reading that outcome needs. An entry added here must say why.
_WITHHELD_PROJECT_FIELDS: FrozenSet[str] = frozenset()


def _project_verdicts(
    payload: WorkspaceResults, scan_ids: Dict[str, str]
) -> List[Dict[str, Any]]:
    """The per-project outcome, joined to the scan id the client was handed.

    Per project and not merged, because the first question about a workspace scan
    is which project failed and a merged count cannot answer it.

    DERIVED from the model rather than hand-listed, and that is the fix for a
    defect rather than a tidy-up. This function used to build a closed dict naming
    each field, and it named 14 of the 19 the model declared at the time: five --
    ``scanners``, ``incomplete_scanners``, ``scan_incomplete``,
    ``ceiling_unreachable_findings`` and ``sarif_run_index`` -- were declared on
    ``WorkspaceProjectResult`` and silently absent from every response. Nothing
    else under ``cli/mcp/`` mentioned either completeness field, so an MCP client
    had no way at all to learn that a project's scanners did not run -- it saw
    ``finding_count: 0`` and a COMPLETED status. Deriving the projection means the
    next field added to the model cannot fail to propagate, which is what
    ``tests/unit/cli/mcp/test_workspace_verdict_projection.py`` asserts by comparing
    the response's key set against ``model_fields``.

    ``include=`` restricts the dump to *declared* fields. The model sets
    ``extra="allow"``, so an unrestricted dump would also emit whatever a
    forward-compatible producer attached, making the response shape depend on the
    input rather than on the contract. ``mode="json"`` is what turns
    ``ProjectRunStatus`` and ``SkippedProjectReason`` into their string values; it
    replaces the per-field ``_enum_value`` calls this function used to make, and it
    covers a future enum-typed field that those calls would have missed.
    """
    projected = set(WorkspaceProjectResult.model_fields) - _WITHHELD_PROJECT_FIELDS
    verdicts: List[Dict[str, Any]] = []
    for entry in payload.projects:
        verdict = entry.model_dump(mode="json", include=projected)
        verdict["scan_id"] = scan_ids.get(entry.project)
        verdicts.append(verdict)
    return verdicts


def _workspace_scan_incomplete(payload: WorkspaceResults) -> bool:
    """Whether any project's scan was too incomplete to trust.

    Surfaced at the top level of the response as well as per project, because the
    common client shape for this tool is a gate that reads the envelope and never
    walks ``projects``. Such a client saw ``exit_code`` with no statement of why,
    and an incomplete workspace and a failed one share code 1.
    """
    return any(entry.scan_incomplete for entry in payload.projects)


def _workspace_ceiling_unreachable(payload: WorkspaceResults) -> Dict[str, int]:
    """Per scanner, how many findings the severity ceiling could not affect.

    Summed across projects for the same envelope-reading client. Echoed rather
    than left per-project because it qualifies what the verdict means: a ceiling
    that did not reach some findings did not tighten the gate for them, so a pass
    at that ceiling is a weaker statement than it looks.
    """
    totals: Dict[str, int] = {}
    for entry in payload.projects:
        for scanner, count in (entry.ceiling_unreachable_findings or {}).items():
            totals[scanner] = totals.get(scanner, 0) + count
    return totals


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

    ``ASH_OFFLINE`` is set here because that environment variable is the only thing
    scanners actually consult. ``settings.offline`` reaches the orchestrator as a
    declared field (``core/orchestrator.py``) and is never read; the gate scanners use
    is ``is_offline_mode()`` in ``core/constants.py``, which tests
    ``os.environ["ASH_OFFLINE"]``. So before this, requesting ``offline=True`` over MCP
    was accepted, threaded through two layers, and silently did nothing -- the scan ran
    with full network access while reporting that it had not. The CLI already sets the
    variable around its own invocations; this path bypassed that.

    The value is snapshotted and restored rather than set-and-popped. The CLI pops it
    unconditionally, which is safe there because the process runs one scan and exits, but
    a long-lived MCP server started with ``ASH_OFFLINE=YES`` in its own environment would
    have that deployment-level setting silently cleared by the first offline workspace
    scan.

    Known limitation, stated because it is reachable here and not in the CLI: the variable
    is process-global while this server can run sessions concurrently. Two overlapping
    workspace scans with different ``offline`` values share one variable, so the restore
    of the first can land inside the second. Closing that properly means having scanners
    consume the resolved setting instead of the environment, which is a change across
    every scanner rather than a fix to this call site.
    """
    monitor: Optional["asyncio.Task[None]"] = None
    if progress_reporter is not None and project_outputs:
        monitor = asyncio.create_task(
            monitor_workspace_progress(progress_reporter, dict(project_outputs))
        )
    offline_previous = os.environ.get("ASH_OFFLINE")
    if settings.offline:
        os.environ["ASH_OFFLINE"] = "YES"
    try:
        # Resolved from this module's globals at call time, so a test that
        # replaces cli.mcp.workspace.execute_workspace is what runs.
        return await asyncio.to_thread(execute_workspace, plan, settings)
    finally:
        if settings.offline:
            if offline_previous is None:
                os.environ.pop("ASH_OFFLINE", None)
            else:
                os.environ["ASH_OFFLINE"] = offline_previous
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
    session_id: Optional[str] = None,
    profile: Optional[str] = None,
) -> Dict[str, Any]:
    """Resolve a workspace and return the plan. Scans nothing.

    The MCP equivalent of ``ashx --workspace ... --dry-run``, which is
    ``typer.echo(plan.render())`` and an exit at 0. Both halves of that matter
    here. The rendered plan comes back verbatim under ``plan``, because a plan
    reduced to a JSON dump is not the artifact ``render()`` was written to produce
    and the client cannot reconstruct the layout. And nothing is scanned, because
    a client asking what a workspace would do is asking a question -- answering it
    by scanning N repositories is expensive, writes an output tree into each one,
    and takes registry slots that block the real scan the client is about to ask
    for.

    Args:
        workspace_file: Path to the ``.code-workspace`` definition. A config
            input, so it is confined by ``ASH_MCP_ALLOWED_CONFIG_ROOTS`` rather
            than by ``ASH_MCP_ALLOWED_ROOTS``, and on a network transport only.
        workspace_config: Path to a workspace policy file. Must exist when given;
            ASH does not fall back to searching, because that would apply
            different policy than the one named. Confined the same way.
        allow_missing_projects: Mark absent or unreadable project directories
            skipped instead of refusing the workspace. They stay in the plan, so
            the caller can see which were dropped.
        config_overrides: ``--config-overrides`` values, applied to each project's
            config during resolution so the reported threshold is the one a scan
            would enforce.
        session_id: The session this call acts for. Lets a workspace inside a tree
            this session delivered over the protocol resolve, and selects which
            bound profile applies.
        profile: A registered profile to resolve under for this one call, instead
            of whatever this session bound. Unknown names are refused.

    Returns:
        On success, ``success`` True, ``exit_code`` 0, the rendered plan under
        ``plan``, the same decisions structured under ``projects``, and
        ``session_config_path`` -- the config a scan of this plan would run under,
        or None. That last field is why this tool is worth calling before the
        scan: a dry run that reported the plan a *different* config would produce
        is worse than none. On failure, ``create_error_response``'s keys plus
        ``exit_code``: 4 for a workspace definition, policy or confinement
        problem, 3 for a project whose own config is invalid, 1 for anything else.
    """
    refusal = _refuse_config_inputs_outside_the_permitted_roots(
        workspace_file, workspace_config, session_id
    )
    if refusal is not None:
        return _error_response(
            refusal,
            "resolve_workspace",
            exit_code=int(WorkspaceExitCode.WORKSPACE_ERROR),
        )

    try:
        session_config = _resolve_session_config(session_id, profile)
    except (ProfileNotRegisteredError, OSError, RuntimeError) as exc:
        return _error_response(
            exc,
            "resolve_workspace",
            exit_code=int(WorkspaceExitCode.INVALID_PROJECT_CONFIG),
        )

    try:
        plan = _resolve(
            workspace_file,
            workspace_config,
            allow_missing_projects,
            config_overrides,
            default_config=session_config,
        )
    except Exception as exc:  # noqa: BLE001 -- mapped to an exit code, never raised
        return _error_response(exc, "resolve_workspace")

    return {
        "success": True,
        "exit_code": int(WorkspaceExitCode.SUCCESS),
        "exit_code_meaning": ASH_EXIT_CODES[int(WorkspaceExitCode.SUCCESS)],
        "scanned": False,
        "plan": plan.render(),
        "session_id": session_id,
        "session_config_path": session_config,
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
    session_id: Optional[str] = None,
    profile: Optional[str] = None,
) -> Dict[str, Any]:
    """Scan every active project in a workspace and return the per-project verdict.

    Resolves, confines, builds the settings through the CLI's own builder,
    registers one scan per project, executes off the event loop, and closes the
    registry entries out. That order is not a preference: confinement needs the
    resolved project directories, so it cannot precede resolution, and every
    filesystem write happens after it.

    Args:
        workspace_file: Path to the ``.code-workspace`` definition. Confined as a
            config input -- see the module docstring on why that changed.
        workspace_config: Path to a workspace policy file. Confined the same way.
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
        session_id: The session this call acts for. Lets a workspace inside a tree
            this session delivered over the protocol scan, and selects which bound
            profile applies.
        profile: A registered profile to scan under for this one call, instead of
            whatever this session bound. Unknown names refuse the whole scan
            rather than falling back to the default config: a workspace scan is N
            repository scans, and running them all under configuration nobody
            chose while reporting success is what this module refuses everywhere
            else.

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
    # Before resolution, because resolution is the read this gate guards. Every
    # other gate in this function runs after it, for the reasons the module
    # docstring gives.
    config_refusal = _refuse_config_inputs_outside_the_permitted_roots(
        workspace_file, workspace_config, session_id
    )
    if config_refusal is not None:
        return _error_response(
            config_refusal,
            "scan_workspace",
            exit_code=int(WorkspaceExitCode.WORKSPACE_ERROR),
        )

    try:
        session_config = _resolve_session_config(session_id, profile)
    except (ProfileNotRegisteredError, OSError, RuntimeError) as exc:
        return _error_response(
            exc,
            "scan_workspace",
            exit_code=int(WorkspaceExitCode.INVALID_PROJECT_CONFIG),
        )

    try:
        plan = _resolve(
            workspace_file,
            workspace_config,
            allow_missing_projects,
            config_overrides,
            # Same value the settings builder gets below. They must agree; see
            # ``_resolve`` and ``ProjectScanSettings.default_config_path``.
            default_config=session_config,
        )
    except Exception as exc:  # noqa: BLE001 -- mapped to an exit code, never raised
        return _error_response(exc, "scan_workspace")

    refusal = _refuse_projects_outside_the_permitted_roots(plan, session_id)
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
                config_path=session_config,
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
    except BaseException as exc:
        # asyncio.CancelledError, KeyboardInterrupt, SystemExit. _register_projects
        # claimed these entries as RUNNING, and a RUNNING entry's runner decides
        # its status, so leaving them open would read as running forever. Closed
        # as failed, then re-raised so cancellation still propagates.
        _close_registrations(
            registered,
            None,
            error=f"Workspace scan ended without a result: {type(exc).__name__}",
        )
        raise

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
        "session_id": session_id,
        "session_config_path": session_config,
        "scan_ids": registered,
        "scan_incomplete": _workspace_scan_incomplete(result.payload),
        "ceiling_unreachable_findings": _workspace_ceiling_unreachable(result.payload),
        "projects": _project_verdicts(result.payload, registered),
        "skipped_projects": [
            entry.model_dump(mode="json") for entry in plan.skipped_projects
        ],
    }
