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
* A workspace scan counts as one scan against the operator's
  ``max_concurrent_scans``, however many projects it has: its projects' registry
  entries share one slot (``ScanRegistry.register_scan``'s ``slot``). Counted per
  project, a workspace with more projects than the limit could never start, and
  a running one took a slot per project from every single scan.
* The operator's ``scan_timeout_seconds`` covers the whole workspace scan, counted
  from when its thread starts. Past it, every project's entry is closed as failed,
  a project that had already finished included (its files on disk are complete),
  every project still running is stopped the way ``cancel_scan`` stops a single
  scan, and the call returns the timeout. One that fires after the projects finished, while the
  unified results or the workspace reports are written, still fails the call,
  because the registry already says the scans failed; the files on disk are then
  complete.
* ``cancel_scan`` on one project's scan id stops that project only: each project
  runs in its own entry's cancel scope (``workspace/execution.py``).
* A project past its ``project_timeout``, which the scanned workspace's own config
  sets, is stopped the same way, and the call returns once it has stopped. Until
  then the slot and the directories stay taken: released at the timeout, they let
  a short ``project_timeout`` run scanners outside both server limits.
* Progress is reported as completed projects over total projects, and the project
  key travels in the message. ``ctx.report_progress`` has no project dimension,
  and per-project scanner fractions cannot be summed into a workspace fraction --
  the monitor's scanner estimate only ever grows and is capped below 1.0, so the
  sum would never reach completion.
"""

from __future__ import annotations

import asyncio
import functools
import threading
import time
import uuid
from contextlib import nullcontext, suppress
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
)

from automated_security_helper.cli.mcp.profile_registry import session_client_rules
from automated_security_helper.cli.mcp.progress_monitor import (
    ResultsFileState,
    monitor_workspace_progress,
    results_files_before,
)
from automated_security_helper.cli.mcp.sandbox import (
    caller_is_remote,
    config_base_gate,
)
from automated_security_helper.cli.mcp.session_identity import (
    UNIDENTIFIED_SESSION_ID,
)
from automated_security_helper.cli.mcp.sessions import (
    MCPSession,
    ScanCount,
    ScanPresence,
    finish_ended_session,
    get_default_registry,
)
from automated_security_helper.cli.mcp.source_delivery import (
    SOURCE_DELIVERY_BUSY,
    SourceDeliveryBusyError,
)
from automated_security_helper.cli.mcp.scan_target import (
    ASH_MCP_ALLOWED_ROOTS_ENV,
    OUTPUT_TREE_REFUSED_EXIT_CODE,
    validate_scan_target,
)
from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
)
from automated_security_helper.core.committed_output import (
    committed_entries_in_a_workspace_output,
    committed_output_files_error,
)
from automated_security_helper.core.constants import ASH_EXIT_CODES
from automated_security_helper.core.previous_results import SettleHandoff
from automated_security_helper.core.exceptions import (
    ASHConfigEnvNotResolvedError,
    ASHConfigInputNotPermittedError,
    ASHConfigSourceError,
    ASHConfigValidationError,
    ScannerSelectionError,
    WorkspaceDefinitionError,
    WorkspacePathNotUtf8Error,
)
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
    create_error_response,
    validate_output_directory_path,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    OUTPUT_REMOVAL_WAIT_SECONDS,
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
    resolve_workspace_execution_config,
)
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceExitCode,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.utils.error_text import (
    carry_environment_values,
    config_environment_values,
    error_text,
    limit_typed_by_a_value,
    log_unexpected_error,
    timeout_limit_phrase,
)
from automated_security_helper.utils.log import (
    ASH_LOGGER,
    NO_MARKUP,
    current_run_log_scope,
    disown_run_log_scope,
    hold_run_log_scope,
    open_run_log_scope,
    release_run_log_scope,
)
from automated_security_helper.utils.output_dir_links import (
    WHY as OUTPUT_LINK_WHY,
)
from automated_security_helper.utils.output_dir_links import (
    OutputDirLinkRefused,
    ignore_output_dir_in_git,
    refuse_linked_output_dir,
)
from automated_security_helper.utils.terminal_text import shown_on_one_line

#: The remedy for this tool's caller, which names the output tree with output_dir.
MCP_WORKSPACE_OUTPUT_REMEDY = (
    f"{OUTPUT_LINK_WHY} Pass output_dir with a directory that is not a link, or "
    "replace the link with a directory."
)
from automated_security_helper.utils.process_env import (
    hold_environ,
    release_environ,
)
from automated_security_helper.workspace.execution import (
    PROJECTS_DIR_NAME,
    ProjectScanSettings,
    WorkspaceRunResult,
    execute_workspace,
    prewarm_plugin_registry,
    refuse_unresolvable_scanner_selection,
)
from automated_security_helper.workspace.plan import WorkspacePlan
from automated_security_helper.workspace.resolver import resolve_workspace

if TYPE_CHECKING:
    from automated_security_helper.config.client_config_policy import (
        ClientConfigRules,
    )

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

#: The key a workspace scan with no active project registers its output root
#: under. A project key is never empty (``ProjectPlan.key`` has a minimum length
#: of one), so this cannot name a project, and the responses leave it out of
#: ``scan_ids`` (:func:`_scan_ids_of`): it is a claim on the root, not a scan a
#: client can poll.
_ROOT_CLAIM_KEY = ""


class OutputDirectoryNotUsableError(MCPResourceError):
    """A file where a workspace scan's output directory, or a project's, goes.

    Raised before any project is registered (:func:`_refuse_output_files`), with
    the text the scan tools refuse the same file with
    (``mcp_tools.output_directory_refusal``), and reported as they report it:
    ``error_type`` ``output_dir_not_usable``, exit 5, the CLI's code for an
    ``--output-dir`` that is a file.
    """


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
    # An output directory reached through a link: 3, as the CLI exits for every
    # such refusal (OUTPUT_DIR_REFUSED_EXIT_CODE), and not 4, because the
    # workspace definition is not what is wrong.
    (OutputDirLinkRefused, WorkspaceExitCode.INVALID_PROJECT_CONFIG),
    # execute_workspace refuses a --scanners selection no project could run before
    # starting any; the CLI exits with the usage-error code for it.
    (ScannerSelectionError, WorkspaceExitCode.USAGE_ERROR),
    (OutputDirectoryNotUsableError, WorkspaceExitCode.USAGE_ERROR),
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
    is passed explicitly where the error's class alone does not say what was
    refused and the call site does: confinement, a session's profile, a
    client's overrides or policy, a linked output tree, an OSError reading a
    config. Otherwise the class gives the code (_exit_code_for).

    ``Exception``, deliberately, and not ``BaseException``. Every caller supplies
    one: the three handlers in this module are all ``except Exception``, and the
    confinement path passes an ``MCPResourceError``. A ``BaseException`` parameter
    would imply this function could be handed a ``SystemExit`` or a
    ``KeyboardInterrupt`` and turn it into a response, and neither should be.
    ``SystemExit`` is kept out of this module by not calling the code that raises
    it rather than by catching it, and swallowing ``KeyboardInterrupt`` would leave
    the server unstoppable mid-scan.
    """
    from automated_security_helper.cli.mcp_tools import (
        CONFIG_ENV_NOT_RESOLVED,
        CONFIG_INPUT_NOT_PERMITTED,
        ENV_VALUE_IN_LONGER_STRING,
        OUTPUT_DIR_NOT_USABLE,
        config_load_category,
    )
    from automated_security_helper.config.environment_record import (
        EnvironmentValueInPath,
    )

    category: Optional[str] = None
    if (
        not isinstance(error, MCPResourceError)
        and _caused_by(error, ASHConfigValidationError)
        and not _caused_by(error, ASHConfigInputNotPermittedError)
    ):
        # A config refusal, in the category scan_directory answers the same
        # refusal with, so a client that branches on it reads one category
        # from either tool. A refusal of a config input outside the permitted
        # roots keeps its own, below.
        category = config_load_category(error).value
    response = create_error_response(error, operation, category=category)
    if isinstance(error, WorkspaceSessionBusy):
        # Another scan of the session held its lock for the whole wait allowed;
        # nothing of this scan ran. Named so a client can retry on it.
        response["error_type"] = "session_busy"
    if isinstance(error, OutputDirectoryNotUsableError):
        response["error_type"] = OUTPUT_DIR_NOT_USABLE
    if _caused_by(error, EnvironmentValueInPath):
        # A profile whose environment value sits inside a longer string, under
        # the error_type select_profile answers the same refusal with.
        response["error_type"] = ENV_VALUE_IN_LONGER_STRING
    if isinstance(error, WorkspacePathNotUtf8Error):
        # Its message names its paths as they are, and the response is JSON,
        # which cannot hold a lone surrogate: shown once, as a whole, on one
        # line. Through error_text, not str(error), so values carried on the
        # exception stay redacted here as on every other arm.
        response["error"] = str(shown_on_one_line(error_text(error)))
    if _caused_by(error, ASHConfigEnvNotResolvedError):
        # A project config an MCP client delivered that reads from the
        # environment (config_sources.refuse_environment_in_a_delivered_file),
        # under the error_type every other tool reports it with.
        response["error_type"] = CONFIG_ENV_NOT_RESOLVED
    elif _caused_by(error, ASHConfigInputNotPermittedError):
        # A workspace definition or policy the caller names, a discovered
        # workspace policy, or a project config, outside the directories the
        # session may read config from (``validate_config_input``,
        # ``config_base_gate``), under the error_type and the code the other
        # tools report it with: 3,
        # as run_ash_scan gives it and the CLI exits for a config whose chain
        # leaves its root. One refusal, one code, whichever tool refused it.
        response["error_type"] = CONFIG_INPUT_NOT_PERMITTED
        if exit_code is None:
            exit_code = int(WorkspaceExitCode.INVALID_PROJECT_CONFIG)
    resolved = int(exit_code) if exit_code is not None else _exit_code_for(error)
    response["exit_code"] = resolved
    response["exit_code_meaning"] = ASH_EXIT_CODES.get(resolved, "unknown exit code")
    return response


def _caused_by(error: BaseException, kind: type) -> bool:
    """Whether ``error`` is, or was raised from, a ``kind``.

    The resolver re-raises a project's config error with the project named,
    from the original. The shared walk ends on a cyclic chain
    (``raise e from e``), which a bare ``__cause__`` loop never would.
    """
    from automated_security_helper.utils.error_text import caused_by

    return caused_by(error, kind)


def _scan_ids_of(registered: Dict[str, str]) -> Dict[str, str]:
    """The registered entries a client can poll: every project's, not the root claim."""
    return {
        key: scan_id for key, scan_id in registered.items() if key != _ROOT_CLAIM_KEY
    }


def _stopped_response(
    reason: str,
    registered: Dict[str, str],
    timeout_seconds: Optional[float],
    environment_values: Iterable[str] = (),
) -> Dict[str, Any]:
    """The response for a workspace scan the server stopped.

    ``create_error_response``'s keys, as for every other failure here, plus the
    ``scan_ids``: each project's entry records how it ended, and a client can
    read it with get_scan_progress as it would for a single scan.
    ``timeout_seconds`` is the limit that stopped it, or None when its timeout
    did not. ``environment_values`` are the run's environment values: the
    machine-readable copy of the limit follows the same rule as the reason's
    text (timeout_limit_phrase), or the context would carry the number the
    text hides.
    """
    category = (
        ErrorCategory.OPERATION_TIMEOUT
        if timeout_seconds
        else ErrorCategory.UNEXPECTED_ERROR
    )
    context: Dict[str, Any] = {"error_category": category.value}
    if timeout_seconds and not limit_typed_by_a_value(
        timeout_seconds, environment_values
    ):
        # No environment value types to the limit, so the reason shows the
        # number and the context may too.
        context["scan_timeout_seconds"] = timeout_seconds
    response = _error_response(
        MCPResourceError(reason, context=context), "scan_workspace"
    )
    response["scan_ids"] = _scan_ids_of(registered)
    return response


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


class ProjectsOutsideTheRootsError(MCPResourceError):
    """A workspace was refused because a project lies outside the permitted roots.

    Raised from inside resolution, before any project's config is read, and
    reported as the confinement refusal it carries.
    """


def _project_gate(
    workspace_file: str, session_id: Optional[str]
) -> Callable[[Sequence[Tuple[str, Path]]], None]:
    """The confinement check resolution runs before it reads any project config."""

    def gate(projects: Sequence[Tuple[str, Path]]) -> None:
        refusal = _refuse_project_paths_outside_the_permitted_roots(
            projects, workspace_file, session_id
        )
        if refusal is not None:
            raise ProjectsOutsideTheRootsError(str(refusal), context=refusal.context)

    return gate


def _resolve(
    workspace_file: str,
    workspace_config: Optional[str],
    allow_missing_projects: bool,
    config_overrides: Optional[Sequence[str]],
    default_config: Optional[str] = None,
    client_config_rules: Optional["ClientConfigRules"] = None,
    trusted_config: Optional[str] = None,
    remote_client: bool = False,
    permit_base: Optional[Callable[[Path], bool]] = None,
    session_id: Optional[str] = None,
) -> WorkspacePlan:
    """Resolve the workspace, or raise.

    Project confinement runs inside resolution, before any project's own config
    is read (:func:`_project_gate`), so a config outside the permitted roots is
    never parsed; a refusal raises :class:`ProjectsOutsideTheRootsError`.

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

    ``trusted_config`` is the registered profile ``default_config`` is resolved
    against, which differs from it when the client patched the session's profile
    (``_resolve_session_config``).

    ``remote_client`` is ``caller_is_remote`` for the session, and has to reach
    the settings builder too (``_scan_options``), for the same reason. So does
    ``permit_base``, the session's ``config_base_gate``: a project's config that
    is a link out of the directories the session may read config from is refused
    before it is read, as a single-directory scan refuses it.
    """

    return resolve_workspace(
        Path(workspace_file),
        allow_missing_projects=allow_missing_projects,
        workspace_config=(
            Path(workspace_config) if workspace_config is not None else None
        ),
        config_overrides=tuple(config_overrides or ()),
        default_config=Path(default_config) if default_config else None,
        client_config_rules=client_config_rules,
        trusted_config=Path(trusted_config) if trusted_config else None,
        remote_client=remote_client,
        permit_base=permit_base,
        project_gate=_project_gate(workspace_file, session_id),
        # The operator config's !ENV judgement is made for this session, as each
        # project's is: without it a non-default session's own bound profile
        # that uses !ENV was refused at planning and accepted at every scan.
        session_id=session_id,
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
            "operator_config": project.operator_config,
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
    confinement accepted before resolution read it (:func:`_project_gate`) --
    so gating them here would re-check a decision already made and would refuse
    a legitimate in-tree config on a deployment that granted the tree but not
    its own path as a config root. A project's config that is a link out of
    that directory is a different case, and resolution refuses it before
    reading it (``_resolve``'s ``permit_base``).

    The refusal is raised from an ``ASHConfigInputNotPermittedError``, as the
    discovered policy's and a project config's are, so ``_error_response``
    reports all of them as ``config_input_not_permitted`` with exit code 3.
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
        error = MCPResourceError(
            f"Workspace scan refused: the {label} file is outside the "
            f"directories this server may read config from. {refusal}",
            context=dict(refusal.context, config_input=label),
        )
        error.__cause__ = ASHConfigInputNotPermittedError(str(error))
        return error
    return None


def _refuse_a_client_chosen_policy(
    plan: WorkspacePlan,
    session_id: Optional[str] = None,
) -> Optional[MCPResourceError]:
    """Refuse a plan whose workspace policy the operator did not set aside.

    A policy sets suppressions and ignore paths for every project, the fields
    the runtime-override denylist keeps from a client. Under the MCP tools the
    client names the definition and may name the policy, so either way the
    policy file is the client's choice unless it sits where the operator keeps
    config: a directory ``ASH_MCP_ALLOWED_CONFIG_ROOTS`` names, or a profile file
    the server writes in the calling session's ``config/`` directory
    (``client_named_config_is_untrusted``). A file a
    client delivered is always the client's, and so is a policy in a checkout
    the server may scan, named or found beside the definition.

    Checked on the file the resolver applied (``workspace_config_source``, the
    path it was found or named at, which ``client_named_config_is_untrusted``
    judges together with the file it reaches) rather than on a path worked out
    beforehand: discovery runs beside the resolved definition, so a symlinked
    definition, or a file added between a check and the resolution, would make
    a separate lookup check a different file. A policy that reaches a file
    outside what the session may read is refused earlier, before it is read
    (``_resolve``'s ``permit_base``).
    """
    from automated_security_helper.cli.mcp.sandbox import (
        ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV,
        client_named_config_is_untrusted,
        config_is_client_supplied,
    )

    source = plan.workspace_config_source
    if source is None or not client_named_config_is_untrusted(
        Path(source), session_id=session_id
    ):
        return None
    how = (
        "was delivered by an MCP client"
        if config_is_client_supplied(Path(source))
        else f"is not in a directory {ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV} names"
    )
    return MCPResourceError(
        "Workspace scan refused: the workspace policy file "
        f"{Path(source).as_posix()} {how}. A policy sets suppressions and ignore "
        "paths for every project, so only a policy file the operator keeps in a "
        f"directory {ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV} names is used.",
        context={"config_input": "workspace policy"},
    )


def _refuse_a_linked_output_tree(
    plan: WorkspacePlan, output_dir: Optional[str]
) -> Optional[MCPResourceError]:
    """Refuse an output tree with a link in it, before anything is created or moved.

    The workspace scan writes each project's output to ``projects/<key>`` under
    its output directory, and sets that project's previous results aside there.
    The default output directory is ``<workspace root>/.ash/ash_output``, a tree
    the scanned repository controls, so any component of it can be a link to a
    directory nobody named: the moves and the restore marker then land there. A
    single scan refuses the same for its ``.ash/ash_output``
    (``validate_output_tree``); this is the workspace equivalent.

    Checked from the workspace root through ``.ash``, ``ash_output``,
    ``projects`` and each active project's key for the default directory, and
    from a caller-named output directory, which ``validate_scan_target`` already
    confined, through ``projects`` and each key. Every component is checked, so
    a link anywhere along the way is refused, and one pointing inside the tree
    too.

    The caller refuses with ``OUTPUT_TREE_REFUSED_EXIT_CODE`` (3), the code a
    single scan reports for the same link, and not 4: the workspace definition
    and its policy are not what is wrong.
    """
    from automated_security_helper.cli.mcp.scan_target import validate_output_tree

    if output_dir is None:
        base = Path(plan.workspace_root).resolve()
        prefix: Tuple[str, ...] = (".ash", "ash_output")
    else:
        base = Path(output_dir).resolve()
        prefix = ()
    for project in plan.active_projects:
        refusal = validate_output_tree(base, *prefix, PROJECTS_DIR_NAME, project.key)
        if refusal is not None:
            return refusal
    return None


def _refuse_projects_outside_the_permitted_roots(
    plan: WorkspacePlan,
    session_id: Optional[str] = None,
) -> Optional[MCPResourceError]:
    """Validate every project that will be scanned; refuse the whole workspace if any fails."""
    return _refuse_project_paths_outside_the_permitted_roots(
        [(project.key, project.path) for project in plan.active_projects],
        plan.workspace_file,
        session_id,
    )


def _refuse_project_paths_outside_the_permitted_roots(
    projects: Sequence[Tuple[str, Any]],
    workspace_file: str,
    session_id: Optional[str] = None,
) -> Optional[MCPResourceError]:
    """Validate every project that will be scanned; refuse the whole workspace if any fails.

    Run inside resolution, from the definition alone, before any project's own
    config is read, and again on the resolved plan before a scan.

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
    for key, path in projects:
        # The session id is passed for the reason run_ash_scan passes it: this
        # session's own sandbox counts as a permitted root, so a workspace whose
        # projects live inside a tree the client delivered over the protocol is
        # scannable. Without it every such project is refused by the boundary
        # that exists to permit it, because no operator lists a directory the
        # server invented per connection.
        refusal = validate_scan_target(path, session_id=session_id)
        if refusal is not None:
            offending.append((key, refusal))

    if not offending:
        return None

    refused_paths = {
        key: refusal.context.get("resolved_path", "") for key, refusal in offending
    }
    detail = "; ".join(f"{key} at {path}" for key, path in refused_paths.items())
    return MCPResourceError(
        f"Workspace scan refused: {len(offending)} of {len(projects)} "
        f"project(s) resolve outside the permitted roots, so none was scanned: "
        f"{detail}. Scanning the rest and reporting success would report a clean "
        f"result for code that was never examined. Set "
        f"{ASH_MCP_ALLOWED_ROOTS_ENV} to the directories the MCP server may scan, "
        f"or drop those folders from the workspace definition.",
        context={
            "error_category": ErrorCategory.INVALID_PATH.value,
            "workspace_file": workspace_file,
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


def _gate_client_overrides(
    config_overrides: Optional[Sequence[str]],
    session_config: Optional[str],
    session_id: Optional[str] = None,
    profile: Optional[str] = None,
) -> Optional[List[str]]:
    """Refuse ``config_overrides`` the session's runtime-override allowlist does not allow.

    Returns the overrides to hand on. One that only turns an off-host reporter
    off (``runtime_patch._turns_an_off_host_reporter_off``) is accepted and left
    out, with a warning: handed on, it is applied to every project as the
    operator's own and turns the operator's reporter off.

    A workspace scan hands its ``config_overrides`` to ``resolve_config`` as
    ``--config-overrides``, which the trust checks count as the operator's: they
    are replayed onto the trusted base for the sandbox settings and add to the
    trusted ``ash_plugin_modules``. Over MCP the caller is a client, so the same
    gate ``select_profile``'s ``patch_ops`` and ``override_yaml`` go through
    applies: the overrides are applied to the session's config (its bound or
    per-call profile, else the defaults), and the change is checked with
    ``apply_runtime_override`` against the registered profile's
    ``global_settings.mcp.runtime_overrides``. That is the profile as the operator
    registered it, not the session's materialized copy, which a client's
    ``patch_ops`` may have changed. Runtime overrides are off by default, so
    without a profile that enables them no override is accepted.

    Each override is checked twice: by the key it names (``check_runtime_ops``
    on an ``add`` at the pointer it resolves to in the session config), and by
    the change it makes to the session config (``apply_runtime_override``).

    Raises:
        RuntimePatchDeniedError: An override is not allowed.
        ASHConfigValidationError: An override is not ``key=value``
            (``resolve_config.split_config_override``, as for ``--config-overrides``)
            or cannot be applied.
    """
    if not config_overrides:
        return None if config_overrides is None else list(config_overrides)
    from automated_security_helper.config.ash_config import (
        AshConfig,
        RuntimeOverridesConfig,
    )
    from automated_security_helper.config.resolve_config import (
        _override_shown,
        _parse_config_value,
        apply_config_overrides,
        load_config_file_for_run,
    )
    from automated_security_helper.config.runtime_patch import (
        _turns_an_off_host_reporter_off,
        apply_runtime_override,
        check_runtime_ops,
    )

    from automated_security_helper.cli.mcp.profile_registry import (
        session_profile_entry,
    )
    from automated_security_helper.config.client_config_policy import policy_of

    # Loaded as a run loads it, so the config knows what its files read from the
    # environment (_environment_references): a refusal goes to the client, and
    # names a policy entry read from the environment as <value>, as
    # select_profile's does (runtime_patch._PolicyNames).
    if session_config:
        try:
            base = load_config_file_for_run(Path(session_config))[1]
        except ASHConfigValidationError:
            raise
        except Exception as exc:  # noqa: BLE001 -- a file that does not parse is a config error
            # A session config that does not parse is the operator's config
            # that is broken: reported as a scan reports it (exit 3), never as
            # the parser's own error, which the tools answer as an internal
            # error (exit 1). The parser's words can quote the file, so only
            # the error's kind is named.
            raise ASHConfigValidationError(
                f"The session config {Path(session_config).as_posix()} could not "
                f"be loaded ({type(exc).__name__})."
            ) from exc
    else:
        base = AshConfig()
    entry = session_profile_entry(session_id, profile)
    allowlist = (
        policy_of(entry.config) if entry is not None else RuntimeOverridesConfig()
    )
    # Each override is checked by the key it names, whatever it changes. A diff
    # against the session config alone misses one whose value the session config
    # already holds: it changes nothing there, but still overwrites each
    # project's own value. The key is resolved against the session config the
    # way --config-overrides resolves it ('-' and '_' match per segment, and a
    # declared plugin section's spelling folds; see
    # config_sources.resolve_override_segment); the denials match either
    # spelling on their own (runtime_patch._denial_spellings).
    base_dump = base.model_dump()
    kept: List[str] = []
    ignored: List[str] = []
    for override in config_overrides:
        key, separator, raw = str(override).partition("=")
        if not separator or not key.strip():
            # The refusal --config-overrides gives, named by the same function
            # the CLI uses: the key part only where there is an '=', and an
            # entry with none only when it is key-shaped, since what follows
            # an '=' or stands alone can be a credential, and the refusal goes
            # to the client and the log.
            raise ASHConfigValidationError(
                f"Invalid config override: {_override_shown(str(override))}. "
                "Expected format: key.path=value"
            )
        append = key.endswith("+")
        resolved = _resolve_override_key(
            base_dump,
            (key[:-1] if append else key).split("."),
            config_environment_values(base),
        )
        pointer = "/" + "/".join(
            segment.replace("~", "~0").replace("/", "~1") for segment in resolved
        )
        op = {
            "op": "add",
            "path": pointer + ("/-" if append else ""),
            "value": _parse_config_value(raw),
        }
        check_runtime_ops([op], allowlist=allowlist, config=base)
        if _turns_an_off_host_reporter_off(op, base):
            ignored.append(key)
            continue
        kept.append(str(override))
    after = apply_config_overrides(base, kept)
    apply_runtime_override(base, after, allowlist=allowlist)
    # Said only once the call is accepted: a refused call ignored nothing.
    for key in ignored:
        _logger.warning(
            f"Ignoring the config override {key!r} from the MCP client: that "
            "reporter sends findings off the host, so only the operator's "
            "configuration turns it on or off; the projects keep the "
            "operator's setting.",
            extra=NO_MARKUP,
        )
    return kept


def _resolve_override_key(
    config_dict: Dict[str, Any],
    parts: Sequence[str],
    environment_values: Sequence[str] = (),
) -> List[str]:
    """The keys ``apply_config_overrides`` writes ``parts`` to in ``config_dict``.

    The same walk as ``resolve_config._apply_config_override``, through the one
    resolver both share (``config_sources.resolve_override_segment``), so what
    this gate checks is what the apply writes: each segment takes the spelling
    the dict already uses, a spelling of a declared plugin's section folds to
    that section, and a segment under a missing or non-dict value is kept as
    typed.
    """
    from automated_security_helper.config.config_sources import (
        resolve_override_segment,
    )

    resolved: List[str] = []
    current: Any = config_dict
    parent: Optional[str] = None
    for part in parts:
        key = resolve_override_segment(current, parent, part, environment_values)
        resolved.append(key)
        current = current.get(key) if isinstance(current, dict) else None
        parent = key
    return resolved


def _session_config_refusal(error: Exception, operation: str) -> Dict[str, Any]:
    """The workspace tools' answer when the session's config cannot be resolved.

    A config refusal, exit 3, for every error of ``_resolve_session_config``
    except one: a bound profile that is still registered but whose file could
    not be written to the session's workspace again
    (``BoundProfileUnavailableError.workspace_unwritable``). That is the
    server's failure and not the caller's config, so it is answered as the
    scan tools answer it (``_bound_profile_unavailable``): exit 1, the
    category of the writer's error, and a warning in the server log for the
    operator. As a config refusal an unwritable workspace read as the caller's
    own fault and left nothing in the log.

    A session whose workspace another request holds for the sweep's removal
    (``SessionWorkspaceBusyError``, a ``RuntimeError``) is not a config refusal
    either: the file is gone and not written again under that removal, so it is
    answered as the other tools answer the hold, under the error's own
    ``error_type`` and with exit 1, for the client to send the request again.
    The hold reaches here as the chained cause of a
    ``BoundProfileUnavailableError``: the bound profile's rewrite wraps every
    ``RuntimeError`` of the writer in one that reads as an unwritable workspace,
    so the cause is looked at first.
    """
    from automated_security_helper.cli.mcp.sessions import SessionWorkspaceBusyError

    hold = next(
        (
            candidate
            for candidate in (error, getattr(error, "__cause__", None))
            if isinstance(candidate, SessionWorkspaceBusyError)
        ),
        None,
    )
    if hold is not None:
        from automated_security_helper.cli.mcp_tools import (
            REFUSED_INTERNAL_EXIT_CODE,
        )

        response = _error_response(
            hold, operation, exit_code=REFUSED_INTERNAL_EXIT_CODE
        )
        response["error_type"] = hold.error_type
        return response
    if getattr(error, "workspace_unwritable", False):
        from automated_security_helper.cli.mcp_tools import _bound_profile_unavailable

        return _bound_profile_unavailable(error, operation)
    return _error_response(
        error,
        operation,
        exit_code=int(WorkspaceExitCode.INVALID_PROJECT_CONFIG),
    )


def _resolve_session_config(
    session_id: Optional[str],
    profile: Optional[str],
) -> Tuple[Optional[str], Optional[str]]:
    """Return the config a workspace scan should run under and its trusted base.

    ``(config_path, trusted_config_path)``, or ``(None, None)``. Two sources, in
    order of specificity:

    * ``profile``, naming a registered profile for this one call. Materialized
      into the session's sandbox the same way ``select_profile`` does, so one code
      path produces the file and one boundary covers it, under a name of its own
      per profile (``call_profile_filename``), so the session's own binding is
      left as it was and two calls naming different profiles do not rewrite each
      other's file. It is the operator's profile, so it is its own trusted base.
    * the config this session already bound with ``select_profile``, and the
      registered profile it is resolved against. They differ when the client
      patched the profile: the config is then the client's copy in
      ``client-config/``, and the trusted base the profile in ``config/``.
    * for a session that bound none, the server's own config, the file
      ``ASH_CONFIG`` names, as both: it is the operator's config, layered over
      each project's own as ``--config`` is on the CLI. Not when it, or a base
      it extends, is a file an MCP client delivered: that is never layered, and
      ``(None, None)`` is returned as for a server with no ``ASH_CONFIG``.

    None means none of these applies, and then nothing is passed -- each
    project's own ``.ash.yaml`` discovery runs as it always has. Inventing a path
    here would scan every project under configuration nobody chose.

    An unknown ``profile`` raises rather than falling back. A workspace scan is N
    repository scans; running them all under the default config because a profile
    name was misspelled, and reporting success, is the class of outcome this
    module's confinement refusal exists to prevent. So does a bound session whose
    registered copy is gone while its client copy is not: the client's copy is
    never the operator's config, so there is nothing to layer over a project's
    own config and nothing to resolve it against.

    Raises:
        ProfileNotRegisteredError: ``profile`` is not registered.
        RuntimeError: The session's registered copy is missing; exit 3.
    """

    from automated_security_helper.cli.mcp.profile_registry import (
        call_profile_filename,
        get_profile_registry,
        materialize_session_config,
        resolve_session_config_path,
        resolve_session_trusted_config_path,
    )

    if profile is not None:
        registry = get_profile_registry()
        entry = registry.get(profile)
        if entry is None:
            known = ", ".join(sorted(registry)) or "none registered"
            raise ProfileNotRegisteredError(
                f"unknown profile {profile!r}; known: {known}"
            )
        path = materialize_session_config(
            session_id, entry.config, filename=call_profile_filename(profile)
        )
        return path, path

    config_path = resolve_session_config_path(session_id)
    trusted_config_path = resolve_session_trusted_config_path(session_id)
    if config_path is not None and trusted_config_path is None:
        raise RuntimeError(
            "This session's bound profile can no longer be read as the operator "
            "registered it: its copy in the session's config/ directory is gone. "
            "Bind the profile again with select_profile."
        )
    if config_path is None and trusted_config_path is None:
        server_config = _server_config_path()
        return server_config, server_config
    return config_path, trusted_config_path


def _server_config_path() -> Optional[str]:
    """The file ``ASH_CONFIG`` names, unless a file of its chain is a client's."""
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
    from automated_security_helper.config.config_sources import by_every_name
    from automated_security_helper.config.default_config import (
        default_config_document,
    )

    document = default_config_document()
    if document is None:
        return None
    delivered = by_every_name(config_is_client_supplied, document.names)
    if any(delivered(path) for path in document.chain):
        _logger.warning(
            "ASH_CONFIG names a file under the MCP workspace root, which an MCP "
            "client delivered, so it is not layered over the workspace's projects."
        )
        return None
    return document.chain[-1].as_posix()


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
    client_config_rules: Optional["ClientConfigRules"] = None,
    trusted_config_path: Optional[str] = None,
    remote_client: bool = False,
    config_base_gate: Optional[Callable[[Path], bool]] = None,
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
        # The registered profile ``config`` is resolved against, as for the plan.
        trusted_config_path=trusted_config_path,
        # The same rules the plan was resolved with; see ``_resolve``.
        client_config_policy=client_config_rules,
        # And the same caller.
        remote_client=remote_client,
        # And the same gate, which each project's scan applies again.
        config_base_gate=config_base_gate,
        workspace_plan=plan,
        allow_missing_projects=allow_missing_projects,
        config_overrides=list(config_overrides or []),
        # A client's overrides: a tool path they name is not the operator's.
        client_overrides=bool(config_overrides),
        scanners=list(scanners or []),
        excluded_scanners=list(excluded_scanners or []),
        selection_origin="mcp",
        offline=offline,
        # A project whose scan does not finish gets its previous results back
        # (_restore_unfinished_projects), and its registry entry says the files
        # are not its own. The CLI workspace scan deletes them, as it always has.
        keep_previous_results=True,
        color=False,
        quiet=True,
        progress=False,
        show_summary=False,
    )


def _refuse_output_files(plan: WorkspacePlan, settings: ProjectScanSettings) -> None:
    """Refuse a workspace whose output directory, or a project's, is a file.

    The output directory and each active project's ``projects/<key>/``, before
    :func:`_refuse_committed_output` looks beneath them and before any project is
    registered: a file at either name ended the call in the NotADirectoryError of
    :func:`_create_project_outputs`, or in the registry's refusal of that project,
    both exit 1. Raises :class:`OutputDirectoryNotUsableError`. A missing
    directory is not refused: :func:`_create_project_outputs` makes it.
    """
    output_dir = Path(settings.output_dir)
    for directory in (
        output_dir,
        *(
            output_dir / PROJECTS_DIR_NAME / project.key
            for project in plan.active_projects
        ),
    ):
        error = validate_output_directory_path(directory)
        if error is not None:
            raise OutputDirectoryNotUsableError(str(error), context=error.context)


def _refuse_committed_output(
    plan: WorkspacePlan, settings: ProjectScanSettings
) -> None:
    """Refuse a workspace whose output holds a file git tracks where it writes.

    At the root of the output directory, the unified results file, ``reports/``
    and the spool; in each active project's ``projects/<key>/``, every results
    path, as for a scan starting fresh, the previous results a scan sets aside
    included. Before :func:`_create_project_outputs` and before
    ``clean_output`` sets each project's previous results aside
    (:func:`_set_previous_results_aside`), which moves them: the projects' own
    orchestrators refuse their directories too, but only after that move. The CLI
    checks the same paths (``run_ash_scan._committed_entries_this_run_writes``),
    with the same function, which itself raises ``UnverifiedOutputFilesError``,
    also exit 3, when git cannot say what is committed and anything is on disk
    there.
    """
    output_dir = Path(settings.output_dir)
    committed = committed_entries_in_a_workspace_output(
        output_dir,
        (
            output_dir / PROJECTS_DIR_NAME / project.key
            for project in plan.active_projects
        ),
    )
    if committed:
        raise committed_output_files_error(output_dir, committed)


def _bounded_parallelism(settings: ProjectScanSettings) -> ProjectScanSettings:
    """``settings`` with max_parallel_projects at most the default bound.

    The bound comes from the scanned workspace's own config (``workspace:``
    ``max_parallel_projects``, up to 64), while the whole workspace scan counts as
    one scan against the operator's max_concurrent_scans. So a scanned workspace
    could run 64 projects at once, each with a scanner pool of its own, under a
    limit of one scan. Over MCP it gets at most the bound a workspace that sets
    nothing gets, ``min(4, cpu_count)``; it may still set less. The CLI is
    unchanged: there the operator is the one who wrote the config.
    """
    import dataclasses

    from automated_security_helper.config.ash_config import WorkspaceExecutionConfig

    default = WorkspaceExecutionConfig().resolved_max_parallel_projects()
    if settings.max_parallel_projects <= default:
        return settings
    _logger.info(
        f"The workspace config asks for {settings.max_parallel_projects} projects at "
        f"once; an MCP workspace scan runs at most {default}"
    )
    return dataclasses.replace(settings, max_parallel_projects=default)


def _project_outputs(
    plan: WorkspacePlan, settings: ProjectScanSettings
) -> Dict[str, Path]:
    """Each active project's output directory, by key. Nothing is created.

    The same layout ``execution._project_output_dir`` uses, because these are the
    same directories, so the registry entry can name one, and the progress
    monitor can watch one, before the scan starts.

    Nothing is reachable through a link: the workspace's output directory and
    each project's are checked first (utils/output_dir_links.py), and a link
    raises OutputDirLinkRefused, a ValueError the caller reports.
    """
    refuse_linked_output_dir(
        plan.workspace_root,
        settings.output_dir,
        workspace=True,
        remedy=MCP_WORKSPACE_OUTPUT_REMEDY,
    )
    outputs: Dict[str, Path] = {}
    for project in plan.active_projects:
        project_output = Path(settings.output_dir) / PROJECTS_DIR_NAME / project.key
        refuse_linked_output_dir(
            settings.output_dir, project_output, remedy=MCP_WORKSPACE_OUTPUT_REMEDY
        )
        outputs[project.key] = project_output
    return outputs


def _create_project_outputs(
    project_outputs: Dict[str, Path], output_dir: Union[str, Path]
) -> None:
    """Create the workspace's output root and the projects' output directories,
    once _register_projects has claimed them.

    Not before, so a workspace scan refused at max_concurrent_scans leaves no
    output tree under the workspace root for a
    scan that never ran. A failure here is the call's failure, and its handler
    gives the claim back. One that cannot be made is refused as
    :func:`_refuse_output_files` refuses one it can tell beforehand, with the
    error's own reason: under a ``projects`` that cannot be written, it is known
    only now.

    The root, ``output_dir``, is created on its own and first. It used to exist
    only as a side effect of ``mkdir(parents=True)`` on the project folders, so a
    run with no active project (every project missing under
    ``allow_missing_projects``, say) created nothing here, the ``.gitignore``
    writer that follows wrote nothing into a directory that was not there, and
    ``execute_workspace`` then made the root and wrote the unified results beside
    no ``.gitignore``: the first-scan gap, in one case.
    """
    from automated_security_helper.utils.directory_refusals import (
        output_dir_unmakeable,
    )

    for directory in (Path(output_dir), *project_outputs.values()):
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise OutputDirectoryNotUsableError(
                output_dir_unmakeable(
                    directory, error.strerror or type(error).__name__
                ),
                context={
                    "directory_path": str(directory),
                    "error_category": ErrorCategory.INVALID_PARAMETER.value,
                },
            ) from None


def _set_previous_results_aside(project_outputs: Dict[str, Path]) -> None:
    """clean_output: set each project's previous results aside.

    So the progress monitor does not read a previous aggregated-results file as
    this run's (core/previous_results.py). Only after _register_projects: until
    the registry has given this scan the projects, a project's directory may be
    another scan's, and what is there is its output. mcp_scan_workspace puts them
    back for every project that did not finish. A failure is logged and not
    raised: the project's orchestrator sets them aside again when it starts.
    """
    from automated_security_helper.core.previous_results import PreviousResults

    for key, project_output in project_outputs.items():
        try:
            PreviousResults(project_output).set_aside()
        except OSError as exc:
            _logger.warning(
                f"Could not set the previous results of project '{key}' aside in "
                f"{project_output} ({exc}); progress reporting for this project "
                f"may complete early."
            )


def _restore_unfinished_projects(
    project_outputs: Dict[str, Path], registered: Dict[str, str]
) -> None:
    """Put back the previous results of every project whose scan did not finish.

    A project whose orchestrator finished its phases has already dropped them, so
    this is a no-op for it; one that failed before or inside its scan gets them
    back, and its registry entry records that its output directory now holds the
    previous scan's results, so its progress does not report them as its own.
    Never raises: it runs on the paths that decide the workspace verdict.

    Only projects this call registered. A project it could not register belongs
    to another scan, and a held set in its directory is that scan's to settle:
    restoring it would remove the output that scan is writing.
    """
    from automated_security_helper.core.previous_results import (
        PreviousResults,
        holds_restored_results,
    )

    registry = get_scan_registry()
    for key, project_output in project_outputs.items():
        if key not in registered:
            continue
        try:
            PreviousResults(project_output).restore()
        except OSError as exc:
            _logger.error(
                f"Could not put back the previous results of project '{key}' in "
                f"{project_output}: {exc}"
            )
            continue
        entry = registry.get_scan(registered[key])
        if entry is not None:
            entry.output_holds_previous_results = holds_restored_results(project_output)


def _refuse_outputs_another_scan_writes(
    registry: Any,
    plan: WorkspacePlan,
    project_outputs: Dict[str, Path],
    output_dir: Union[str, Path],
) -> None:
    """Refuse a workspace scan whose output directory a live scan is writing.

    The registry refuses a second active scan of one DIRECTORY, by its canonical
    path, and admits two workspace scans whose projects differ but whose output
    directories resolve to one place: both then wrote their spool and unified
    results into it, each run's cleanup removing the other's. The same question
    is asked of each project's output directory here, before anything is
    registered, and it is asked of the registry itself
    (``ScanRegistry.scan_writing_output``): occupancy is the registry's own
    (``ScanRegistryEntry.occupies_its_directory``, under its lock, in its
    canonical form), not a status list. A status list refused the rollback
    entries ``_register_projects`` marks CANCELLED without ever running them, so
    a retry right after a refused or cancelled workspace scan was told its own
    output was being written; and it admitted a timed-out scan whose entries
    are FAILED at once (``_stop_at_timeout``) while its thread still writes for
    seconds, so a second scan was let into exactly that window.

    Then the same question is asked of the workspace's output ROOT,
    ``output_dir`` (``ScanRegistry.scan_writing_within``): the unified results,
    the reports and the spool go there, not into any project's folder, and no
    registry entry names the root, so two workspace scans with different
    projects and one root passed the per-project check and wrote beside each
    other. A live scan whose output tree is the root, lies inside it (another
    workspace's project folder; a single scan aimed into it) or contains it (a
    scan whose cleanup would remove this run's tree) refuses the workspace. The
    per-project check stays first for its message, which names the project.
    """
    for project in plan.active_projects:
        output = project_outputs[project.key]
        if registry.scan_writing_output(str(output)) is None:
            continue
        key = project.key
        raise MCPResourceError(
            f"Output directory for project {key!r} is being written by another "
            f"scan: {output}",
            context={
                "project_key": key,
                "output_directory": str(output),
                "error_category": ErrorCategory.RESOURCE_EXHAUSTED.value,
                "suggestions": [
                    "Wait for the other scan to complete",
                    "Use a different output_dir for this workspace scan",
                ],
            },
        )
    if registry.scan_writing_within(str(output_dir)) is not None:
        raise MCPResourceError(
            f"Output directory {output_dir} is being written by another scan, "
            "or lies inside the output directory of one",
            context={
                "output_directory": str(output_dir),
                "error_category": ErrorCategory.RESOURCE_EXHAUSTED.value,
                "suggestions": [
                    "Wait for the other scan to complete",
                    "Use a different output_dir for this workspace scan",
                ],
            },
        )


def _register_projects(
    plan: WorkspacePlan,
    project_outputs: Dict[str, Path],
    session_id: Optional[str] = None,
    *,
    output_dir: Union[str, Path],
    max_active: Optional[int] = None,
    environment_values: Sequence[str] = (),
) -> Dict[str, str]:
    """Register one scan per active project and return ``{project key: scan id}``.

    ``output_dir`` is the workspace's output root, which the run writes into
    beside the project folders; a live scan writing it, or a tree that shares it,
    refuses the workspace before anything is registered
    (:func:`_refuse_outputs_another_scan_writes`).

    Each entry is recorded under ``session_id``, the session that asked for the
    workspace scan, so the registry tools show it to that session only.

    ``max_active`` is the operator's ``max_concurrent_scans``, None for no limit.
    The entries share one slot, so the workspace takes one: refused like a single
    scan when none is free, and never by its own earlier projects.

    ``environment_values`` are the run's (the projects' configs' and the
    operator chain's), attached to every entry: the registry redacts each
    error message a failure arm applies with them, so the arm closing an
    entry with a bare exception's text does not decide whether a value leaks.
    The run's rather than each project's own, because the arms that close
    these entries hold one failure for the whole run.

    Each entry records that the workspace thread is its runner. From here it
    occupies its directory and the slot until :func:`_release_projects` says that
    thread has stopped, even once it is closed: a timeout or a cancel closes the
    entries at once, while the thread may run on for seconds, stopping scanners
    and putting previous results back.

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
    _refuse_outputs_another_scan_writes(registry, plan, project_outputs, output_dir)
    registered: Dict[str, str] = {}
    slot = str(uuid.uuid4())
    # One wait for the whole batch: each register_scan waits for the removal of an
    # output tree it meets, up to the wait it is given, and a wait per call made
    # a workspace of N projects wait N times as long. Each call gets what is left.
    removal_deadline = time.monotonic() + OUTPUT_REMOVAL_WAIT_SECONDS
    try:
        for project in plan.active_projects:
            registered[project.key] = registry.register_scan(
                directory_path=project.path,
                output_directory=str(project_outputs[project.key]),
                severity_threshold=(
                    project.gate_threshold or _UNSTATED_SEVERITY_THRESHOLD
                ),
                config_path=project.config_source,
                max_active=max_active,
                session_id=session_id,
                slot=slot,
                environment_values=environment_values,
                removal_wait_seconds=max(0.0, removal_deadline - time.monotonic()),
            )
        if not registered:
            # No active project (every project missing under
            # allow_missing_projects, say): the run still writes its unified
            # results and reports into the output root, and with no entry the
            # registry could not tell a second workspace scan of the same root to
            # wait. The workspace root stands for the claim, and it closes with
            # the others.
            registered[_ROOT_CLAIM_KEY] = registry.register_scan(
                directory_path=str(plan.workspace_root),
                output_directory=str(output_dir),
                severity_threshold=_UNSTATED_SEVERITY_THRESHOLD,
                max_active=max_active,
                session_id=session_id,
                slot=slot,
                environment_values=environment_values,
                removal_wait_seconds=max(0.0, removal_deadline - time.monotonic()),
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
        entry = registry.get_scan(scan_id)
        if entry is not None:
            entry.has_runner = True
    return registered


#: The workspace scans this process is running: per scan, the future its thread
#: completes once it has stopped and settled the output directories, with the
#: scan's registry entries and the event that stops its run. stop_running_scans
#: (cli/mcp_tools.py) stops these with the single scans before the server exits:
#: a project's scanner runs in a session of its own and would outlive the
#: process otherwise.
_RUNNING: Dict["asyncio.Future[None]", Tuple[Dict[str, str], CancelEvent]] = {}


def stop_workspace_scans(
    reason: str, promptly: bool = False
) -> List["asyncio.Future[None]"]:
    """Stop every workspace scan of the running loop; return the futures to await.

    Each project is cancelled as cancel_scan cancels it, and the run is stopped
    at its next check. With ``promptly`` each scanner's tool gets
    PROMPT_STOP_GRACE_SECONDS after SIGTERM, as for a single scan. A future is
    done once its scan's thread has stopped and settled; one of another loop
    could never complete here and is left out.
    """
    loop = asyncio.get_running_loop()
    registry = get_scan_registry()
    stopping: List["asyncio.Future[None]"] = []
    for settled, (registered, stop) in list(_RUNNING.items()):
        if settled.get_loop() is not loop or settled.done():
            continue
        _logger.warning(
            f"Stopping a workspace scan of {len(registered)} project(s): {reason}"
        )
        for scan_id in registered.values():
            entry = registry.get_scan(scan_id)
            if promptly and entry is not None:
                entry.cancel_event.stop_promptly = True
            registry.cancel_scan(scan_id)
        if promptly:
            stop.stop_promptly = True
        stop.set()
        stopping.append(settled)
    return stopping


def _release_projects(registered: Dict[str, str]) -> None:
    """Record that the workspace thread has stopped: its entries' runner is done.

    From here a closed entry no longer occupies its directory or the workspace's
    max_concurrent_scans slot. Called by the thread once it has settled the
    output directories, or by the task for a thread that never started.
    """
    registry = get_scan_registry()
    for scan_id in registered.values():
        entry = registry.get_scan(scan_id)
        if entry is not None:
            entry.runner_done.set()


def _close_registrations(
    registered: Dict[str, str],
    payload: Optional[WorkspaceResults],
    *,
    error: Optional[str] = None,
    session_id: Optional[str] = None,
    name_process_ids: Optional[bool] = None,
) -> None:
    """Move every entry this call made out of the active set.

    Left pending, they would each block a later scan of the same project
    directory and would make ``list_active_scans`` report work nobody is doing.
    Called on the failure path too, with ``error`` set, for the same reason.
    ``session_id`` is the calling session's: the coverage kept on each entry
    names the pids of the tools the stop could not end only when that caller is
    local, the same request-scoped reading the response makes. A caller that has
    already read it passes ``name_process_ids``, so every entry and the response
    take one answer; without it the reading is taken once here, not per project.
    """
    if name_process_ids is None:
        name_process_ids = not caller_is_remote(session_id)
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
            # The coverage is kept on the entry and read back by any later
            # progress call. Whether its could_not_stop reasons name pids is
            # decided by the SAME request-scoped predicate the response takes
            # (caller_is_remote, which honours the operator's every-caller-remote
            # override), so what this call returns and what a later progress
            # call reads back agree: read by the process-wide transport alone,
            # the stored coverage kept the pids the response had withheld.
            coverage = _project_coverage(outcome, name_process_ids=name_process_ids)
            if outcome.scan_incomplete and coverage_has_gap(coverage):
                registry.finish_scan(
                    scan_id, MCScanStatus.INCOMPLETE, coverage=coverage
                )
            else:
                registry.finish_scan(scan_id, status, coverage=coverage)
        else:
            registry.finish_scan(scan_id, status)


def _project_coverage(
    outcome: WorkspaceProjectResult, *, name_process_ids: bool = False
) -> Dict[str, Any]:
    """One project's coverage, in the shape a single scan's progress reports it.

    Built from the facts the project's outcome already carries, so a client
    polling a workspace project and one polling a single scan read the same keys.
    ``incomplete_converters`` has the shape ``ScanIncompleteness.to_payload``
    gives it, and so do ``unevaluated_rules`` and ``could_not_stop``: the two
    exit-1 arms no setting silences, read off the outcome's ``unevaluated_rules``
    and ``unstoppable_tools``, both of which feed ``scan_incomplete``. A stale
    content database is in ``stale_content_databases`` and only there, as in a
    single scan's payload: the outcome leaves a scanner listed only for it out of
    ``incomplete_scanners``.

    ``name_process_ids`` False, the default, drops the process ids from the
    ``could_not_stop`` reasons (``without_process_ids``): a caller that forgets
    the flag withholds the pids from a remote client and does not hand them over.
    The executor records each reason naming
    the pid of the tool the stop could not end, and this coverage is stored on
    the registry entry and read back by any later progress call, so on a network
    transport a remote client was handed server-side pids here while the cancel
    warning (``record_cancel_outcome``) deliberately withheld them.
    """
    from automated_security_helper.utils.subprocess_utils import without_process_ids

    def shown(reason: str) -> str:
        return reason if name_process_ids else without_process_ids(reason)

    statuses = outcome.scanners or {}
    # Both fields default empty on an outcome a pre-field ASH wrote; the rows
    # then fall back to the bare status, which is all that outcome recorded.
    details = getattr(outcome, "incomplete_scanner_details", None) or {}
    partial = set(getattr(outcome, "partial_coverage_scanners", None) or ())
    rows = []
    for name in outcome.incomplete_scanners:
        status = str(statuses.get(name, ""))
        rows.append(
            {
                "scanner": name,
                "status": status,
                "reason": incomplete_scanner_reason(status, partial=name in partial),
                "detail": str(details.get(name, status)),
            }
        )
    return {
        "incomplete_scanners": rows,
        "no_scanner_ran": bool(outcome.no_scanner_ran),
        "incomplete_converters": [
            {"converter": name, "reason": reason}
            for name, reason in (outcome.incomplete_converters or {}).items()
        ],
        # Both default empty on an outcome a pre-field ASH wrote.
        "unevaluated_rules": list(getattr(outcome, "unevaluated_rules", None) or []),
        "stale_content_databases": list(outcome.stale_content_databases or []),
        "could_not_stop": [
            {"scanner": name, "reason": shown(str(reason))}
            for name, reason in (
                getattr(outcome, "unstoppable_tools", None) or {}
            ).items()
        ],
    }


#: Declared ``WorkspaceProjectResult`` fields deliberately withheld from the MCP
#: response. Empty: every field a project's outcome declares is something a client
#: reading that outcome needs. An entry added here must say why.
_WITHHELD_PROJECT_FIELDS: FrozenSet[str] = frozenset()


def _project_verdicts(
    payload: WorkspaceResults,
    scan_ids: Dict[str, str],
    *,
    name_process_ids: bool = False,
) -> List[Dict[str, Any]]:
    """The per-project outcome, joined to the scan id the client was handed.

    ``name_process_ids`` False drops the process ids from the
    ``unstoppable_tools`` reasons (``without_process_ids``) and nothing else:
    the field is projected like every other, but its values name the pid of a
    server-side process, which a remote client cannot act on and should not
    learn; the cancel warning already withholds them on a network transport.

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
    from automated_security_helper.utils.subprocess_utils import without_process_ids

    projected = set(WorkspaceProjectResult.model_fields) - _WITHHELD_PROJECT_FIELDS
    verdicts: List[Dict[str, Any]] = []
    for entry in payload.projects:
        verdict = entry.model_dump(mode="json", include=projected)
        if not name_process_ids and verdict.get("unstoppable_tools"):
            verdict["unstoppable_tools"] = {
                name: without_process_ids(str(reason))
                for name, reason in verdict["unstoppable_tools"].items()
            }
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


class _WorkspaceScanClaim:
    """A workspace scan's claim on its session, held until nothing of the scan runs.

    ``mcp_scan_workspace`` claims the session (``MCPSession.try_claim_scan``)
    before it resolves the workspace. ``_execute`` then hands the run to a worker
    thread, and cancelling the call (the client cancels it, or its request ends)
    does not stop that thread: it goes on reading the session's tree and writing
    under it. So the claim is released, and a session that ended meanwhile is
    removed (``finish_ended_session``), by whichever of the two leaves last: the
    call, or the worker it handed the run to. A worker that the call left before
    it started never runs the scan.

    The same object carries the scan's place in the per-session limit
    (``try_start_scan``), released at the same time: its session's place, or, for
    a caller with no session, a place in the count all such callers share
    (``sessions.sessionless_scan_count``). ``claimed`` is the session whose tree
    the scan holds, None when it delivered nothing. ``counted`` holds the scan's
    place, None when no limit applies (stdio).
    """

    def __init__(
        self,
        session_id: Optional[str],
        *,
        claimed: Optional[MCPSession] = None,
        counted: Optional[Union[MCPSession, ScanCount]] = None,
    ) -> None:
        self._session_id = session_id
        self._claimed = claimed
        self._counted = counted
        self._lock = threading.Lock()
        self._holder = "call"  # then "worker", then "released"
        # Threads that read the session's tree before the worker exists (the
        # resolution of the workspace), and whether the call has left. A call
        # cancelled while such a thread runs leaves it running.
        self._threads = 0
        self._call_left = False

    @property
    def claimed(self) -> bool:
        """True when the scan holds its session's tree."""
        return self._claimed is not None

    def thread_starts(self) -> bool:
        """A thread that reads the tree before the worker takes a hold; False if none is left.

        The claim then outlives the call: a call cancelled while the thread runs
        leaves it running, and a claim released at the call's exit let the
        session end, and its tree be removed, under a thread still reading
        configs and running git there. Released by :meth:`thread_returns` once
        the call has left and no thread is left.
        """
        with self._lock:
            if self._holder == "released":
                return False
            self._threads += 1
            return True

    def thread_returns(self) -> None:
        """Give back the hold :meth:`thread_starts` took; release if it was the last."""
        with self._lock:
            self._threads -= 1
            if self._threads or not self._call_left or self._holder != "call":
                return
            self._holder = "released"
        self._release()

    def worker_starts(self) -> bool:
        """Take the claim over for the worker; False if the call already left."""
        with self._lock:
            if self._holder == "released":
                return False
            self._holder = "worker"
            return True

    def worker_declines(self) -> None:
        """Give back to the call a claim the worker took but will not use.

        The worker took the claim, then found the task had abandoned the scan
        and settled it (``SettleHandoff``). The task settles while the call is
        still in its handler, so the claim must stay held until the call leaves:
        it goes back to the call, which releases it at its exit, or, when the
        call has left already, is released here.
        """
        with self._lock:
            if self._holder != "worker":
                return
            if self._threads or not self._call_left:
                self._holder = "call"
                return
            self._holder = "released"
        self._release()

    def worker_returns(self) -> None:
        """Release the claim the worker took; nothing when the call released it.

        ``_run``'s ``finally`` reaches here on every exit, including the one where
        ``worker_starts`` answered False because the call had already left and
        released (``call_returns``). Releasing again there gave away a place in
        the per-session limit, or the session's tree, that another scan of the
        session held by then.
        """
        with self._lock:
            if self._holder != "worker":
                return
            self._holder = "released"
        self._release()

    def call_returns(self) -> None:
        """Release the claim, unless a worker that started or a thread holds it."""
        with self._lock:
            self._call_left = True
            if self._holder != "call" or self._threads:
                return
            self._holder = "released"
        self._release()

    def _release(self) -> None:
        if self._counted is not None:
            self._counted.scan_returned()
        if self._claimed is not None:
            self._claimed.release_scan()
            finish_ended_session(self._session_id)


def _session_holds_something_on_disk(session_id: str, profile: Optional[str]) -> bool:
    """True if the session's sandbox has what a workspace scan of it can read.

    That is a delivered tree (``source``) or a config its profile put there
    (``config``), or a ``profile`` named for this call, which is put there before
    the scan reads it. Checked on disk, so it holds for a tree another server
    sharing the workspace root delivered.
    """
    from automated_security_helper.cli.mcp.sandbox import (
        CONFIG_DIR_NAME,
        SOURCE_DIR_NAME,
    )
    from automated_security_helper.cli.mcp.session_paths import session_directory
    from automated_security_helper.cli.mcp.source_delivery import (
        resolve_workspace_root,
    )

    if profile is not None:
        return True
    try:
        sandbox = session_directory(resolve_workspace_root(), session_id)
        return any(
            (sandbox / name).exists() for name in (SOURCE_DIR_NAME, CONFIG_DIR_NAME)
        )
    except (OSError, ValueError, RuntimeError):
        return False


async def _execute(
    plan: WorkspacePlan,
    settings: ProjectScanSettings,
    project_outputs: Dict[str, Path],
    progress_reporter: Optional[ProgressReporter],
    session_id: Optional[str] = None,
    claim: Optional[_WorkspaceScanClaim] = None,
    settle: Optional[Callable[[], None]] = None,
    handoff: Optional[SettleHandoff] = None,
    stop: Optional[CancelEvent] = None,
    cancel_events: Optional[Mapping[str, CancelEvent]] = None,
    on_thread_start: Optional[Callable[[], None]] = None,
    results_before: Optional[Dict[str, ResultsFileState]] = None,
    lock_wait_seconds: Optional[float] = None,
) -> Optional[WorkspaceRunResult]:
    """Run the workspace off the event loop, with a progress monitor beside it.

    ``lock_wait_seconds`` bounds the wait for the session's scan lock when
    another scan of the session holds it (``_acquire_session_lock``); the
    caller passes its ``scan_timeout_seconds``, so a scan queued behind another
    waits at most as long as it may run, and is refused as busy after that
    rather than started late. None waits without a bound, as before.

    ``results_before`` is what each project's aggregated results file was before
    the caller touched the output directories (``results_files_before``), handed
    to the monitor as its baseline; without it the monitor reads its own as it
    starts, which is after the previous results were set aside.

    Under the session's scan lock, taken on the worker thread as the single-target
    scan takes it, so a delivery into this session is refused while the scans
    read the tree (``source_delivery._no_scan_running``).

    ``execute_workspace`` is synchronous and blocks for as long as the scans take,
    which for N repositories is minutes. Awaiting it inline would stall every
    other MCP session on this server, including the progress polls the protocol
    relies on to keep connections alive.

    The monitor is cancelled in a ``finally`` rather than left to finish: once
    execution has returned there is nothing left to report, and an orphaned poll
    loop would keep emitting progress for a scan that is over.

    Everything the run itself needs is held by the worker thread, from when it
    starts until ``execute_workspace`` returns, because a cancelled call does not
    stop the thread: the session's claim (:class:`_WorkspaceScanClaim`), the
    session's ``ScanPresence`` for the TTL sweep of other servers, and
    ``ASH_OFFLINE`` for an offline scan.

    ``ASH_OFFLINE`` is set because that environment variable is the only thing
    scanners consult. ``settings.offline`` reaches the orchestrator as a declared
    field (``core/orchestrator.py``) and is never read; the gate scanners use is
    ``is_offline_mode()`` in ``core/constants.py``, which tests
    ``os.environ["ASH_OFFLINE"]``. The CLI sets the variable around its own
    invocations, and this path sets it the same way.

    The variable is held (``utils/process_env.hold_environ``) rather than set and
    restored: with two sessions' offline scans overlapping, the first to end would put
    back "unset" while the other still runs, and the last would put back the first
    one's "YES". The last release restores what the server started with, so a
    deployment-level ``ASH_OFFLINE=YES`` survives.

    Known limitation, stated because it is reachable here and not in the CLI: the variable
    is process-global while this server can run sessions concurrently. An online scan
    that overlaps an offline one reads offline mode while the offline one holds it.
    Closing that properly means having scanners consume the resolved setting instead of
    the environment, which is a change across every scanner rather than a fix to this
    call site.

    ``settle`` puts back the previous results of the projects that did not finish.
    It runs on the worker thread once ``execute_workspace`` returns or raises, not
    on the event loop: a cancelled task leaves the thread running, and a restore
    from the loop would race the scans still writing. ``handoff`` covers a task
    cancelled before the thread started (core/previous_results.py). Both are
    optional for a caller with nothing to settle.

    ``stop`` is the cancel scope the run executes in, and ``cancel_events`` the
    per-project events ``execute_workspace`` scopes each project's worker to (see
    its module docstring). ``on_thread_start`` runs on the thread before the run,
    which is where the timeout's clock starts. All three are optional.
    """
    starts = handoff if handoff is not None else SettleHandoff()

    settled = {"done": False}

    def _settle_once() -> None:
        # Before the claim is given back (below): settling puts previous results
        # back under the session's tree, and a claim released first let the
        # session end, and its workspace be removed, while the settle wrote there.
        if settle is not None and not settled["done"]:
            settled["done"] = True
            settle()

    def _run() -> Optional[WorkspaceRunResult]:
        # Before any try/finally: a thread the task abandoned first finds the
        # task has settled the scan already (task_abandons answered True, and the
        # task's own settle followed). Settling again here would restore previous
        # results into directories _release_projects has freed, which another
        # scan may have registered and set aside by now.
        #
        # The claim is taken first and the handoff second, so that no call can
        # leave between them. The other order let the call's exit release the
        # claim after this thread had won the handoff (the task then does not
        # settle) and before it took the claim, and the settle ran with neither
        # the claim nor the presence, on a tree the call's exit may have had
        # removed. This way a thread that wins the handoff already holds the
        # claim, and one that loses it gives the claim back to the call, which
        # releases it after the task's own settle.
        took_the_claim = claim is None or claim.worker_starts()
        if not starts.thread_starts():
            if claim is not None and took_the_claim:
                claim.worker_declines()
            return None
        try:
            if not took_the_claim:
                # The call left without abandoning the handoff: not a path the
                # handlers take, kept as the failure it always was.
                raise RuntimeError("the workspace scan was cancelled before it started")
            claimed = claim is not None and bool(claim.claimed)
            with ScanPresence(session_id if claimed else None):
                # A session that delivered nothing has no tree of its own for the
                # scan to hold, so the scan takes neither its claim nor its lock,
                # and the session may deliver one meanwhile.
                #
                # The settle runs INSIDE the presence: it writes previous results
                # back under the session's tree, and the presence is what keeps
                # another server's TTL sweep off that tree while it does.
                try:
                    with cancel_scope(stop) if stop is not None else nullcontext():
                        if claimed:
                            # The clock starts once the session's lock is held
                            # (_under_session_lock), not while waiting for it;
                            # the wait itself is bounded by lock_wait_seconds
                            # and ended by a cancel.
                            return _under_session_lock(
                                session_id,
                                plan,
                                settings,
                                cancel_events=cancel_events,
                                on_locked=on_thread_start,
                                stop=stop,
                                wait_seconds=lock_wait_seconds,
                            )
                        if on_thread_start is not None:
                            on_thread_start()
                        return _offline_aware(
                            plan, settings, cancel_events=cancel_events
                        )
                finally:
                    _settle_once()
        finally:
            # The claim goes back after the settle (above); worker_returns
            # releases nothing when the call released first. A thread that
            # started but found the call gone (took_the_claim False) reaches
            # here unsettled: the task did not settle, because the thread had
            # started, so this settle is its only one. The handlers abandon the
            # handoff before the call leaves, so that is not a path they take.
            if claim is not None:
                claim.worker_returns()
            _settle_once()

    monitor: Optional["asyncio.Task[None]"] = None
    if progress_reporter is not None and project_outputs:
        monitor = asyncio.create_task(
            monitor_workspace_progress(
                progress_reporter, dict(project_outputs), before=results_before
            )
        )
    try:
        return await asyncio.to_thread(_run)
    finally:
        if monitor is not None:
            monitor.cancel()
            with suppress(asyncio.CancelledError):
                await monitor


_T = TypeVar("_T")


async def _off_the_loop(
    claim: Optional[_WorkspaceScanClaim], function: Callable[[], _T]
) -> _T:
    """Run ``function`` on a worker thread, holding ``claim`` until the thread returns.

    A call cancelled at the await leaves the thread running, and the call's exit
    releases the claim: a session that ended meanwhile was removed
    (``finish_ended_session``) under a thread still reading its configs and
    running git there. The thread takes a hold on the claim before it does
    anything (:meth:`_WorkspaceScanClaim.thread_starts`), so the release follows
    the thread's return when the call has left first. A thread that finds the
    claim already released does nothing, as when the executor drops the job.
    """

    def _held() -> _T:
        if claim is not None and not claim.thread_starts():
            raise RuntimeError("the workspace scan was cancelled before it started")
        try:
            return function()
        finally:
            if claim is not None:
                claim.thread_returns()

    return await asyncio.to_thread(_held)


def _under_session_lock(
    session_id: Optional[str],
    plan: WorkspacePlan,
    settings: ProjectScanSettings,
    cancel_events: Optional[Mapping[str, CancelEvent]] = None,
    on_locked: Optional[Callable[[], None]] = None,
    stop: Optional[threading.Event] = None,
    wait_seconds: Optional[float] = None,
) -> WorkspaceRunResult:
    """``execute_workspace``, holding the session's scan lock when there is a session.

    ``stop`` and ``wait_seconds`` shape the wait for that lock
    (:func:`_acquire_session_lock`): a set ``stop`` ends it as a cancel, and
    ``wait_seconds`` bounds it, refusing the scan as busy when another scan of
    the session still holds the lock at the bound.

    ``ASH_OFFLINE`` is set once the lock is held, not before: a workspace scan
    waiting behind another scan of its session would otherwise hold the
    process-wide variable for that scan's duration too.

    ``on_locked`` runs once the lock is held, right before the run: it is where
    the scan's own clock starts (``_execute``'s ``on_thread_start``). Started
    before the wait, a scan queued behind another scan of its session spent its
    ``scan_timeout_seconds`` waiting and timed out, every project FAILED, having
    scanned nothing, while the call overran its own limit by the wait.

    The in-memory session only (``session_for``): taking its lock creates nothing
    under the workspace root. A caller with no session the server issued
    (``UNIDENTIFIED_SESSION_ID``) has no session to lock, and ``session_for``
    refuses it; its scans are bounded by the count such callers share instead
    (``sessions.sessionless_scan_count``).
    """
    if session_id is None or session_id == UNIDENTIFIED_SESSION_ID:
        if on_locked is not None:
            on_locked()
        return _offline_aware(plan, settings, cancel_events=cancel_events)

    lock = get_default_registry().session_for(session_id).lock
    _acquire_session_lock(lock, session_id, stop=stop, wait_seconds=wait_seconds)
    try:
        if on_locked is not None:
            on_locked()
        return _offline_aware(plan, settings, cancel_events=cancel_events)
    finally:
        lock.release()


#: One slice of the wait for a session's scan lock: how long a cancel, or the
#: wait's own bound, takes to be noticed while another scan of the session runs.
_SESSION_LOCK_POLL_SECONDS = 0.25


class WorkspaceSessionBusy(Exception):
    """Another scan of the session held its lock for the whole wait allowed."""


def _acquire_session_lock(
    lock: threading.Lock,
    session_id: str,
    *,
    stop: Optional[threading.Event],
    wait_seconds: Optional[float],
) -> None:
    """Take ``lock`` for the scan, or refuse once the wait is not worth having.

    A plain ``with lock`` waited without a bound and without a way out: a
    workspace scan queued behind another scan of its session kept its RUNNING
    registry entries and its ``max_concurrent_scans`` place for the whole wait,
    ``scan_timeout_seconds`` did not apply (the clock starts once the lock is
    held, by design), and a cancel could not interrupt the blocking acquire.

    The wait is taken in slices instead: between slices a set ``stop`` ends it
    as a cancel (:class:`ScanCancelled`, which the caller answers as every other
    cancel), and ``wait_seconds``, when given, bounds it, after which the scan is
    refused as :class:`WorkspaceSessionBusy` rather than started late. Both are
    optional; with neither the wait is unbounded, as before, but still in slices.
    """
    deadline = None if not wait_seconds else time.monotonic() + wait_seconds
    while True:
        if lock.acquire(timeout=_SESSION_LOCK_POLL_SECONDS):
            return
        if stop is not None and stop.is_set():
            raise ScanCancelled(
                "the workspace scan was cancelled while waiting for another scan "
                f"of session {session_id} to finish"
            )
        if deadline is not None and time.monotonic() >= deadline:
            raise WorkspaceSessionBusy(
                f"another scan of session {session_id} held its lock for "
                f"{wait_seconds:g} seconds, the limit the workspace scan may wait; "
                "the scan was not started. Retry once that scan finishes."
            )


def _offline_aware(
    plan: WorkspacePlan,
    settings: ProjectScanSettings,
    cancel_events: Optional[Mapping[str, CancelEvent]] = None,
) -> WorkspaceRunResult:
    """``execute_workspace`` with ``ASH_OFFLINE`` held for its duration when requested."""
    # Held under the process-wide environment lock, because other sessions' scans
    # may be copying the environment for a spawn on another thread right now, and
    # counted, so overlapping offline scans keep it until the last one returns.
    offline_held = bool(settings.offline)
    if offline_held:
        hold_environ("ASH_OFFLINE", "YES")
    try:
        # Resolved from this module's globals at call time, so a test that
        # replaces cli.mcp.workspace.execute_workspace is what runs.
        return execute_workspace(plan, settings, cancel_events=cancel_events)
    finally:
        if offline_held:
            release_environ("ASH_OFFLINE")


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
        problem, 3 for a project whose own config is invalid, or a workspace
        definition, policy file or project config outside the directories the
        session may read config from (``config_input_not_permitted``), 1 for
        anything else.
    """
    refusal = _refuse_config_inputs_outside_the_permitted_roots(
        workspace_file, workspace_config, session_id
    )
    if refusal is not None:
        return _error_response(refusal, "resolve_workspace")

    try:
        session_config, trusted_config = _resolve_session_config(session_id, profile)
    except (
        ProfileNotRegisteredError,
        # ASH_CONFIG names a file that cannot be read or parsed: the server's
        # own config is refused with exit 3, as a project's is, instead of the
        # tool raising.
        ASHConfigSourceError,
        OSError,
        RuntimeError,
    ) as exc:
        return _session_config_refusal(exc, "resolve_workspace")

    try:
        config_overrides = _gate_client_overrides(
            config_overrides, session_config, session_id, profile
        )
        rules = session_client_rules(session_id, profile)
    except Exception as exc:  # noqa: BLE001 -- a refusal, reported not raised
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
            client_config_rules=rules,
            trusted_config=trusted_config,
            remote_client=caller_is_remote(session_id),
            permit_base=config_base_gate(session_id),
            session_id=session_id,
        )
    except ProjectsOutsideTheRootsError as exc:
        return _error_response(
            exc,
            "resolve_workspace",
            exit_code=int(WorkspaceExitCode.WORKSPACE_ERROR),
        )
    except OSError as exc:
        # An OSError that escapes resolution is a config it could not read: it
        # refuses the request as a config, exit 3, as mcp_scan_workspace
        # answers the identical failure, so the plan a client
        # checks carries the verdict of the scan it is about to run. The
        # resolver refuses a workspace file, a policy or a project folder it
        # cannot read itself, as a definition (WorkspaceDefinitionError,
        # exit 4).
        return _error_response(
            exc,
            "resolve_workspace",
            exit_code=int(WorkspaceExitCode.INVALID_PROJECT_CONFIG),
        )
    except Exception as exc:  # noqa: BLE001 -- mapped to an exit code, never raised
        return _error_response(exc, "resolve_workspace")

    policy_refusal = _refuse_a_client_chosen_policy(plan, session_id)
    if policy_refusal is not None:
        return _error_response(
            policy_refusal,
            "resolve_workspace",
            exit_code=int(WorkspaceExitCode.WORKSPACE_ERROR),
        )

    # The workspace root's config sets how the scan executes, and scan_workspace
    # refuses one that cannot be loaded (exit 3); read as the scan reads it:
    # under the session's gate, and with the caller's rule for which files may
    # resolve !ENV (config_sources.env_refused_for).
    try:
        resolve_workspace_execution_config(
            Path(plan.workspace_root),
            session_config,
            config_base_gate(session_id),
            remote_client=caller_is_remote(session_id),
            session_id=session_id,
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


async def _scan_workspace(
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
    claim: Optional[_WorkspaceScanClaim] = None,
) -> Dict[str, Any]:
    """``mcp_scan_workspace`` once the session's tree is claimed, if it has one."""
    # Whether this caller is told the process ids of tools a cancel could not end,
    # read once: the response, the coverage stored on each entry and the reasons
    # recorded at a cancel all take this answer, so they agree by construction.
    # Read at each of them it was evaluated at different moments, one of them on
    # the worker thread after a cancelled call had returned.
    name_process_ids = not caller_is_remote(session_id)
    # Before resolution, because resolution is the read this gate guards. Every
    # other gate in this function runs after it, for the reasons the module
    # docstring gives.
    config_refusal = _refuse_config_inputs_outside_the_permitted_roots(
        workspace_file, workspace_config, session_id
    )
    if config_refusal is not None:
        # No explicit code: the refusal is caused by an
        # ASHConfigInputNotPermittedError, which _error_response answers as
        # config_input_not_permitted with exit 3, as mcp_resolve_workspace does
        # for the same refusal.
        return _error_response(config_refusal, "scan_workspace")

    # A caller-named output tree is written into, so it gets the scan roots a
    # scan target gets, checked before anything below creates it. The default,
    # beneath the workspace root, is not caller-named and is left as it was.
    if output_dir is not None:
        output_refusal = validate_scan_target(output_dir, session_id=session_id)
        if output_refusal is not None:
            return _error_response(
                output_refusal,
                "scan_workspace",
                exit_code=int(WorkspaceExitCode.WORKSPACE_ERROR),
            )

    try:
        session_config, trusted_config = _resolve_session_config(session_id, profile)
    except (
        ProfileNotRegisteredError,
        # ASH_CONFIG names a file that cannot be read or parsed: the server's
        # own config is refused with exit 3, as a project's is, instead of the
        # tool raising.
        ASHConfigSourceError,
        OSError,
        RuntimeError,
    ) as exc:
        return _session_config_refusal(exc, "scan_workspace")

    try:
        config_overrides = _gate_client_overrides(
            config_overrides, session_config, session_id, profile
        )
        rules = session_client_rules(session_id, profile)
    except Exception as exc:  # noqa: BLE001 -- a refusal, reported not raised
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
            client_config_rules=rules,
            trusted_config=trusted_config,
            remote_client=caller_is_remote(session_id),
            permit_base=config_base_gate(session_id),
            session_id=session_id,
        )
    except ProjectsOutsideTheRootsError as exc:
        return _error_response(
            exc,
            "scan_workspace",
            exit_code=int(WorkspaceExitCode.WORKSPACE_ERROR),
        )
    except OSError as exc:
        # An OSError that escapes resolution is a config it could not read: it
        # refuses the request as a config, exit 3, as scan_directory answers a
        # config it cannot read, not as an internal error. The resolver
        # refuses a workspace file, a policy or a project folder it cannot
        # read itself, as a definition (WorkspaceDefinitionError, exit 4).
        return _error_response(
            exc,
            "scan_workspace",
            exit_code=int(WorkspaceExitCode.INVALID_PROJECT_CONFIG),
        )
    except Exception as exc:  # noqa: BLE001 -- mapped to an exit code, never raised
        return _error_response(exc, "scan_workspace")

    policy_refusal = _refuse_a_client_chosen_policy(plan, session_id)
    if policy_refusal is not None:
        return _error_response(
            policy_refusal,
            "scan_workspace",
            exit_code=int(WorkspaceExitCode.WORKSPACE_ERROR),
        )

    refusal = _refuse_projects_outside_the_permitted_roots(plan, session_id)
    if refusal is not None:
        return _error_response(
            refusal,
            "scan_workspace",
            exit_code=int(WorkspaceExitCode.WORKSPACE_ERROR),
        )

    output_tree_refusal = _refuse_a_linked_output_tree(plan, output_dir)
    if output_tree_refusal is not None:
        return _error_response(
            output_tree_refusal,
            "scan_workspace",
            exit_code=OUTPUT_TREE_REFUSED_EXIT_CODE,
        )

    # `registered` is pre-declared because the failure handler reads it whether or
    # not registration got that far. `settings` and `result` are not: both are
    # assigned inside the try before anything below reads them, and the handler
    # returns rather than falling through, so declaring them Optional would only
    # tell a type checker they might be None on a path that cannot reach the
    # reads.
    registered: Dict[str, str] = {}
    project_outputs: Dict[str, Path] = {}
    handoff = SettleHandoff()
    # Server limits, read from the operator's config and never from a project's
    # (cli/mcp_tools._resource_limits). Read per scan, as for a single scan. A
    # refused or unreadable operator config answers as a config, exit 3, like
    # scan_directory's read of the same file; resolution above usually refuses
    # it first, so this guards the read against reordering.
    from automated_security_helper.cli.mcp_tools import _resource_limits

    try:
        limits = _resource_limits()
    except (ASHConfigValidationError, OSError) as error:
        # Through the same builder scan_directory and get_config answer with,
        # so one unreadable operator config reads as one category -- exit 3 and
        # config_load_category's value -- on this path too. Resolution usually
        # refuses the same file first, wrapped in ASHConfigValidationError, and
        # that path already carries the category; this guard answered a bare
        # OSError with _error_response's default category, which only a
        # reordering of the reads would have exposed.
        from automated_security_helper.cli.mcp_tools import _config_load_failure

        return _config_load_failure(error, None, operation="scan_workspace")
    # The run's redaction set: every project config's environment values and
    # the operator chain's, as a single scan's (mcp_tools._run_scan_async).
    # Attached to each registered entry, so the registry redacts every error
    # message a failure arm applies, and read by the timeout's limit token.
    from automated_security_helper.cli.mcp_tools import _operator_environment_values
    from automated_security_helper.workspace.execution import (
        workspace_environment_values,
    )

    environment_values = tuple(
        dict.fromkeys(
            (*workspace_environment_values(plan), *_operator_environment_values(limits))
        )
    )
    timeout_seconds = limits.scan_timeout_seconds or None
    # What stops the run: `stop` is the scope execute_workspace runs in, and each
    # project's own entry's cancel event is the scope of that project's worker,
    # so cancel_scan on one project's scan id stops that project only. The
    # timeout and a cancelled task set them all.
    stop = CancelEvent()
    cancel_events: Dict[str, CancelEvent] = {}
    timed_out: List[str] = []
    loop = asyncio.get_running_loop()
    timeout_handles: List[asyncio.TimerHandle] = []
    ended = False
    # Completed once the thread has settled, or the task has for a thread that
    # never started; registered in _RUNNING from registration on.
    settled: Optional["asyncio.Future[None]"] = None

    def _stop_projects() -> None:
        stop.set()
        for event in cancel_events.values():
            event.set()

    def _record_the_tools_the_stop_could_not_end() -> None:
        """Put the tools the stop could not end on every project entry the server stopped.

        Each project's worker runs under its entry's cancel event, chained to
        `stop`, and the subprocess layer records a tool it could not end on the
        chain's root (CancelEvent.note_could_not_stop), which is `stop`: the
        records are the workspace's, not one project's. They are attached,
        through record_cancel_outcome, to each registered entry the server
        stopped (the timeout and a cancelled task close them FAILED and set
        their events), so a client polling any project is told its output
        directory may still be written to. Called on the thread before the
        projects' directories are let go (_settle), and on the task once the
        entries are closed, because either may run first; a pair already
        recorded is not recorded twice. Whether the stored reasons name the
        process ids is decided by the same request-scoped predicate the response
        takes (caller_is_remote, honouring the operator's every-caller-remote
        override), never by the process-wide transport alone, so a later
        progress call reads back what this call's response showed; for a remote
        caller the reasons name the tools only. Never raises: it runs inside the
        settle, which must finish.
        """
        try:
            records = stop.could_not_stop_records()
            if not records:
                return
            registry = get_scan_registry()
            attached = [
                scan_id
                for scan_id in registered.values()
                if registry.record_cancel_outcome(
                    scan_id, records, name_process_ids=name_process_ids
                )
            ]
            if attached:
                named = ", ".join(f"{tool} (pid {pid})" for tool, pid in records)
                _logger.warning(
                    f"Workspace scan of {plan.workspace_file} was stopped, but "
                    f"{len(records)} scanner tool(s) could not be stopped and may "
                    f"still be running: {named}"
                )
        except Exception as recording_error:  # noqa: BLE001 -- the settle must go on
            _logger.warning(
                "Workspace scan: the tools the stop could not end were not "
                f"recorded: {type(recording_error).__name__}"
            )

    def _stop_at_timeout() -> None:
        # The entries are closed as failed first, so their status says why, and
        # then the run is stopped; _close_registrations leaves a closed entry
        # alone, so the reason stays. As for a single scan
        # (mcp_tools._run_scan_async), a timer that closes no entry, because
        # every scan had already ended (cancelled, say), reports nothing: none of
        # them timed out. A list, not any() over a generator, so every entry is
        # closed and not only the first. The limit prints through the shared
        # phrase every timeout message uses (timeout_limit_phrase), under this
        # tool's own option name, so a limit that ever comes from the
        # environment cannot ride the reason as a bare number and the two
        # tools' timeout texts cannot drift. The phrase, not the bare token:
        # composing the option name around timeout_limit_token printed
        # "scan_timeout_seconds of the configured scan_timeout" -- two option
        # names, the second one the directory scan's -- whenever an
        # environment value typed to the limit.
        limit = timeout_limit_phrase(
            timeout_seconds, environment_values, option_name="scan_timeout_seconds"
        )
        registry = get_scan_registry()
        closed = [
            registry.finish_scan(
                scan_id,
                MCScanStatus.FAILED,
                f"Scan exceeded the server's {limit} and was cancelled",
            )
            for scan_id in registered.values()
        ]
        if not any(closed):
            return
        timed_out.append(
            f"Workspace scan exceeded the server's {limit} and was cancelled"
        )
        _stop_projects()
        _logger.error(f"Workspace scan of {plan.workspace_file} failed: {timed_out[0]}")

    def _arm_timeout(seconds: float) -> None:
        # Not after the call ended: its finally has already cancelled the
        # handles, and a timer armed now would fail entries closed long ago.
        if not ended:
            timeout_handles.append(loop.call_later(seconds, _stop_at_timeout))

    def _start_the_clock() -> None:
        # On the workspace thread, as it starts: time spent before that is not
        # the scan's.
        if timeout_seconds:
            loop.call_soon_threadsafe(_arm_timeout, timeout_seconds)

    def _mark_settled() -> None:
        if settled is not None and not settled.done():
            settled.set_result(None)

    # The scan's log scope, which the tool's wrapper opened and holds. The
    # thread the workspace runs on holds it too, from here: cancelling this
    # task does not stop that thread, and its last lines (settling the
    # projects' previous results in _settle) are the scan's, so the scope must
    # outlive the task. _settle runs exactly once -- on the thread once it ran
    # (_execute's finally), or on this task when the thread never starts
    # (SettleHandoff) -- and lets the share go in its finally, after the
    # settling's own lines. The flag guards the paths before the hold exists.
    log_scope = current_run_log_scope()
    thread_share = {"held": False}

    def _release_the_threads_share() -> None:
        if thread_share["held"]:
            thread_share["held"] = False
            release_run_log_scope(log_scope)

    def _settle() -> None:
        try:
            try:
                _restore_unfinished_projects(project_outputs, registered)
            finally:
                # Before the projects' directories are let go: a tool still
                # running would write into one of them.
                _record_the_tools_the_stop_could_not_end()
                _release_projects(registered)
                # Called on the thread or on the loop; the future is the loop's.
                with suppress(RuntimeError):  # the loop is closed: nobody awaits it
                    loop.call_soon_threadsafe(_mark_settled)
        finally:
            _release_the_threads_share()

    hold_run_log_scope(log_scope)
    thread_share["held"] = True
    try:
        try:

            def _resolve_and_refuse() -> Tuple[ProjectScanSettings, Dict[str, Path]]:
                resolved_settings = build_project_scan_settings(
                    _scan_options(
                        plan,
                        output_dir=output_dir,
                        config_overrides=config_overrides,
                        scanners=scanners,
                        excluded_scanners=excluded_scanners,
                        offline=offline,
                        allow_missing_projects=allow_missing_projects,
                        config_path=session_config,
                        client_config_rules=rules,
                        trusted_config_path=trusted_config,
                        remote_client=caller_is_remote(session_id),
                        config_base_gate=config_base_gate(session_id),
                    )
                )
                # A file where an output directory goes, exit 5, then committed
                # files where the scan writes, exit 3: both before any directory
                # is created or any previous results are set aside.
                _refuse_output_files(plan, resolved_settings)
                _refuse_committed_output(plan, resolved_settings)
                resolved_settings = _bounded_parallelism(resolved_settings)
                return resolved_settings, _project_outputs(plan, resolved_settings)

            # Off the event loop: the settings read every project's config and
            # the committed-output check runs one git subprocess per existing
            # project output directory (30 s timeout each), which on the loop
            # stalled every other MCP session for the whole of it.
            #
            # The claim is held by the thread until it returns (_off_the_loop):
            # a call cancelled here leaves the thread reading the session's
            # tree, and the call's exit must not release the claim under it.
            settings, project_outputs = await _off_the_loop(claim, _resolve_and_refuse)

            # The selection pre-check, before any output or registry work: a
            # refused command line registers nothing, creates nothing and sets
            # no previous results aside. execute_workspace keeps its own
            # prewarm and pre-check for callers that reach it another way; the
            # duplicate prewarm is idempotent. On the worker pool, like the
            # scan itself, because the prewarm imports plugin modules.
            def _selection_preflight() -> None:
                prewarm_plugin_registry(plan, settings)
                refuse_unresolvable_scanner_selection(plan, settings)

            await asyncio.to_thread(_selection_preflight)
            registered = _register_projects(
                plan,
                project_outputs,
                session_id,
                output_dir=settings.output_dir,
                # 0 or None is no limit.
                max_active=limits.max_concurrent_scans or None,
                environment_values=environment_values,
            )
            # Failing here closes the entries and, the thread never having
            # started, releases them (_settle) in the handler below.
            _create_project_outputs(project_outputs, settings.output_dir)
            # Once the output directory exists (created above, on its own, so
            # a run with no active project has it too): ignore_output_dir_in_git
            # writes nothing into a directory that is not there yet, and before
            # the move a first workspace scan never wrote the .gitignore. A
            # project at the workspace root would read every project's output
            # below it; see ignore_output_dir_in_git. A link at the name was
            # refused before anything was registered (_project_outputs examines
            # it with the other link checks); one made since raises
            # OutputLinkRefused, an OutputDirLinkRefused too.
            ignore_output_dir_in_git(plan.workspace_root, settings.output_dir)
            registry = get_scan_registry()
            for key, scan_id in registered.items():
                entry = registry.get_scan(scan_id)
                if entry is not None:
                    cancel_events[key] = entry.cancel_event
            settled = loop.create_future()
            _RUNNING[settled] = (registered, stop)
            settled.add_done_callback(lambda done: _RUNNING.pop(done, None))
            # The monitor's baseline, read before the set-aside below: taken
            # after it, every results file read as absent, and a failed
            # project's restore of its previous file counted as completion.
            results_before = results_files_before(project_outputs)
            if clean_output:
                _set_previous_results_aside(project_outputs)
            result = await _execute(
                plan,
                settings,
                project_outputs,
                progress_reporter,
                session_id=session_id,
                claim=claim,
                settle=_settle,
                handoff=handoff,
                stop=stop,
                cancel_events=cancel_events,
                on_thread_start=_start_the_clock,
                results_before=results_before,
                lock_wait_seconds=timeout_seconds,
            )
            if result is None:
                # _execute answers None only from a thread that did not run
                # because this task gave up first, and then this await has
                # raised already. Failed like any other error if it ever does.
                raise RuntimeError("the workspace scan's thread did not run")
        except ScanCancelled:
            # The run stopped at one of execute_workspace's checks, which only
            # `stop` makes it reach: the timeout, here. A project's own cancel is
            # that project's outcome and never arrives here. The thread has
            # settled the output directories itself. The tools the stop could
            # not end are on `stop` (the exception carries the same records):
            # attached once the entries are closed, in case the thread's own
            # record found them still open.
            reason = timed_out[0] if timed_out else "Workspace scan was cancelled"
            _close_registrations(
                registered,
                None,
                error=reason,
                session_id=session_id,
                name_process_ids=name_process_ids,
            )
            _record_the_tools_the_stop_could_not_end()
            return _stopped_response(
                reason,
                registered,
                timeout_seconds if timed_out else None,
                environment_values,
            )
        except Exception as exc:  # noqa: BLE001 -- mapped to an exit code, never raised
            # The run's own failure can quote a value a project's config read
            # from the environment. The entries' close redacts with each
            # entry's registered set, but the response at the end prints the
            # exception's own text, and error_text redacts only values the
            # exception carries. Carried here, so the response redacts too.
            carry_environment_values(exc, environment_values)
            if isinstance(exc, MCPResourceError):
                # The response also shows the error's context, whose strings
                # no printer redacts (create_error_response shows them as
                # they are), so it is redacted here with the same values, as
                # the single-scan arm redacts its own (mcp_tools' scan arm).
                from automated_security_helper.cli.mcp_tools import (
                    _context_without_values,
                )

                try:
                    exc.context = _context_without_values(
                        exc.context, environment_values
                    )
                except Exception:  # noqa: BLE001 -- this arm IS the error handler
                    # Whatever the walker could not take, the failure is
                    # still answered structured. The context is dropped
                    # rather than shown: unredacted it could hold exactly
                    # what the redaction hides.
                    exc.context = {
                        "context": (
                            "(not shown: the error's context could not be redacted)"
                        )
                    }
            try:
                _close_registrations(
                    registered,
                    None,
                    error=error_text(exc),
                    session_id=session_id,
                    name_process_ids=name_process_ids,
                )
            except Exception as close_error:  # noqa: BLE001 -- the error that reached this arm wins
                # Logged and swallowed: this arm maps the run's own failure to
                # an exit code, and a close failure escaping here would replace
                # that mapping with a raw traceback at the caller. Through
                # log_unexpected_error, so values the close error carries
                # (carry_environment_values) are redacted from its text and
                # traceback; a raw exception log printed both unredacted.
                log_unexpected_error(
                    _logger,
                    close_error,
                    "Workspace scan: closing the scan entries failed after an error",
                )
            finally:
                # The thread puts them back itself once it ran; this is for the
                # paths where it never did. In a finally: a close that raises
                # must not keep the settling, and the thread share's release
                # inside it, from running.
                if handoff.task_abandons():
                    _settle()
            return _error_response(exc, "scan_workspace")
        except BaseException as exc:
            # asyncio.CancelledError, KeyboardInterrupt, SystemExit. _register_projects
            # claimed these entries as RUNNING, and a RUNNING entry's runner decides
            # its status, so leaving them open would read as running forever. Closed
            # as failed, then re-raised so cancellation still propagates. Cancelling
            # the task does not stop the workspace thread, so the run is stopped as
            # well: every project stops at its next check and the thread settles
            # the output directories. A thread that never started cannot, so this
            # task does.
            # Events only, and first: the run must be told to stop before
            # anything in this arm that can raise, or every project keeps
            # scanning after the cancel.
            _stop_projects()
            try:
                _close_registrations(
                    registered,
                    None,
                    error=f"Workspace scan ended without a result: {type(exc).__name__}",
                    session_id=session_id,
                    name_process_ids=name_process_ids,
                )
                # The entries are closed and their events set: a tool the stop
                # could not end, recorded on `stop` by then, is attached here;
                # the thread attaches what it finds later, once.
                _record_the_tools_the_stop_could_not_end()
            except Exception as close_error:  # noqa: BLE001 -- the cancellation wins
                # Logged and swallowed: the raise below must re-raise the
                # cancellation, not a close failure that would swallow it.
                # Through log_unexpected_error, as in the arm above, so a
                # carried env value never reaches stderr raw.
                log_unexpected_error(
                    _logger,
                    close_error,
                    "Workspace scan: closing the scan entries failed during cancellation",
                )
            finally:
                # In a finally, as in the arm above: closing the entries must
                # not keep the settling from running.
                if handoff.task_abandons():
                    _settle()
            raise
    finally:
        ended = True
        for handle in timeout_handles:
            handle.cancel()

    if timed_out:
        # The timeout fired after the run's last check, while it wrote the
        # unified results or the reports. The entries already say the scans
        # failed, so the call says so too.
        return _stopped_response(
            timed_out[0], registered, timeout_seconds, environment_values
        )

    _close_registrations(
        registered,
        result.payload,
        session_id=session_id,
        name_process_ids=name_process_ids,
    )

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
        "scan_ids": _scan_ids_of(registered),
        "scan_incomplete": _workspace_scan_incomplete(result.payload),
        "ceiling_unreachable_findings": _workspace_ceiling_unreachable(result.payload),
        # The request-scoped signal decides whether this client is told the
        # pids in unstoppable_tools: a remote caller cannot act on a server
        # pid and should not learn it (the cancel warning's rule).
        "projects": _project_verdicts(
            result.payload,
            registered,
            name_process_ids=name_process_ids,
        ),
        "skipped_projects": [
            entry.model_dump(mode="json") for entry in plan.skipped_projects
        ],
    }


def _in_a_run_log_scope_of_its_own(
    tool: Callable[..., Awaitable[Dict[str, Any]]],
) -> Callable[..., Awaitable[Dict[str, Any]]]:
    """*tool* inside a run log scope the server opens for it (utils/log.py).

    A workspace scan is a run the server hosts, as a directory scan is: what
    its own context logs, and the thread executing the workspace (which
    asyncio.to_thread runs in a copy of it), belongs to it and reaches no
    other session's ash.log; and while it runs, a line of no run's reaches no
    run's handlers. It writes no ash.log of its own, so its lines go where the
    server's own lines go. Opened, never joined, and closed by the run's last
    writer: this call holds the scope and lets go on every way out, and the
    tool holds it for the thread the workspace runs on, whose last lines --
    settling the projects' previous results -- are the scan's. Cancelling the
    call does not stop that thread, so a scope closed here would retire while
    the thread still wrote under it, and every handler the run added
    afterwards would be tagged with the retired scope, with no close coming.
    """

    @functools.wraps(tool)
    async def scoped(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        scope, token = open_run_log_scope()
        hold_run_log_scope(scope)
        try:
            return await tool(*args, **kwargs)
        finally:
            disown_run_log_scope(token)
            release_run_log_scope(scope)

    return scoped


@_in_a_run_log_scope_of_its_own
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

    A scan by a session that has delivered a tree, or whose profile put a config
    in its sandbox, claims the session (``MCPSession.try_claim_scan``) from before
    the workspace is resolved until the scan's worker thread returns, even when
    the call is cancelled first: ``clear_source``, ``set_source_git`` and
    ``set_source_zip_finalize`` are refused meanwhile with ``source_delivery_busy``,
    and a session that ends meanwhile is removed once the worker returns. The
    scan is refused the same way while one of those calls is changing the tree.
    A session that has delivered nothing has nothing of its own for the scan to
    hold, so its scan of a directory the operator granted takes no claim and
    creates nothing under the workspace root.

    Args:
        workspace_file: Path to the ``.code-workspace`` definition. Confined as a
            config input -- see the module docstring on why that changed.
        workspace_config: Path to a workspace policy file. Confined the same way.
        allow_missing_projects: Skip absent or unreadable project directories
            rather than refusing the workspace. Skipped projects get no registry
            entry and no scan id.
        config_overrides: ``--config-overrides`` values, applied per project.
        output_dir: Where the workspace output tree goes. Defaults to
            ``<workspace root>/.ash/ash_output``. When given, confined like a
            scan target, because it is written into.
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
        On success, ``success`` True, ``scan_ids`` mapping project key to registry
        scan id, ``projects`` carrying each project's verdict, and ``exit_code``,
        the workspace's verdict as ``workspace_exit_code`` derives it from the
        projects' outcomes: 3 when a project's own config is invalid; else 2 when
        a project has actionable findings, findings at or above its effective
        severity threshold; else 1 when a project failed, or completed with a
        scanner that did not run to the end; 4 when no project was attempted and
        none was skipped as unchanged; 0 when none of these holds. ``success``
        reports whether the operation completed; the verdict is in ``exit_code``,
        because a scan that found actionable findings ran fine.

        On failure, ``create_error_response``'s keys plus ``exit_code``: 4 for a
        workspace definition, policy or confinement refusal, 3 for an invalid
        config (a project's own, the session's profile, or a refused config
        override), a workspace definition, policy file or project config outside
        the directories the session may read config from
        (``config_input_not_permitted``), or a
        link in the output tree, 5 for a ``scanners`` /
        ``excluded_scanners`` selection no project could run, 1 for anything
        else, the server's scan_timeout_seconds and a full max_concurrent_scans
        included. Both stages are mapped -- ``execute_workspace`` raises
        ``WorkspaceDefinitionError`` too, for an enabled reporter that cannot
        produce a workspace artifact or a project that is not a git repository
        under precommit, and ``ScannerSelectionError`` for that selection. The
        tool's own preflight makes the selection check first, before any
        project is registered or any output work happens.
    """
    from automated_security_helper.cli.mcp.sessions import (
        per_session_scan_limit,
        session_scan_limit_refusal,
        sessionless_scan_count,
    )

    limit = per_session_scan_limit(session_id)
    session: Optional[MCPSession] = None
    claims_tree = False
    if session_id is not None and session_id != UNIDENTIFIED_SESSION_ID:
        claims_tree = _session_holds_something_on_disk(session_id, profile)
        if claims_tree or limit is not None:
            try:
                # The in-memory session: neither hold creates anything on disk.
                session = get_default_registry().session_for(session_id)
            except ValueError:
                # An id that names no directory has no delivered tree to hold;
                # the checks below refuse it.
                session = None
    claimed = session if claims_tree else None
    if claimed is not None and not claimed.try_claim_scan():
        response = _error_response(
            SourceDeliveryBusyError(
                "the delivered source of this session is being changed; "
                "start the workspace scan after the change finishes"
            ),
            "scan_workspace",
        )
        response["error_type"] = SOURCE_DELIVERY_BUSY
        return response
    counted: Optional[Union[MCPSession, ScanCount]] = None
    if limit is not None:
        # One place, however many projects: in the session's count, or, for a
        # caller with no session, in the one all such callers share.
        counted = session if session is not None else sessionless_scan_count()
        if not counted.try_start_scan(limit):
            if claimed is not None:
                claimed.release_scan()
            return session_scan_limit_refusal(
                "scan_workspace", limit, shared=session is None
            )
    claim: Optional[_WorkspaceScanClaim] = None
    if claimed is not None or counted is not None:
        claim = _WorkspaceScanClaim(session_id, claimed=claimed, counted=counted)
    try:
        return await _scan_workspace(
            workspace_file=workspace_file,
            workspace_config=workspace_config,
            allow_missing_projects=allow_missing_projects,
            config_overrides=config_overrides,
            output_dir=output_dir,
            scanners=scanners,
            excluded_scanners=excluded_scanners,
            offline=offline,
            clean_output=clean_output,
            progress_reporter=progress_reporter,
            session_id=session_id,
            profile=profile,
            claim=claim,
        )
    finally:
        # A worker that started holds the claim until it returns.
        if claim is not None:
            claim.call_returns()
