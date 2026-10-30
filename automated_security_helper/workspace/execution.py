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
The worker thread is not killed, because Python cannot preempt a thread. The
abandon does set the project's cancel event, so a scan that checks its scope
stops and frees its slot; until that check -- or forever, for a scan that
never makes one -- the abandoned project keeps its slot, and the pool
effectively shrinks. Once every slot is held by an abandoned project, nothing
still queued can ever start, and waiting on it would block on threads that
may not be coming back.

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

What is kept from such a worker is the set of secret values its findings
exposed. Its reports were written before the abandon could be seen, and another
project may pass one of those values on a command line, so once the pool has
given the stop a bounded grace (``_ABANDONED_STOP_GRACE_SECONDS``, measured on
the clock from the abandon) a worker that came back puts its values into the
workspace masking set; its own results and reports were discarded on its way
back (they contradicted the recorded verdict), so what it left under
``projects/<key>`` is the tools' own output, which the masking leaves alone for
every project. A worker that has not come back is named on its project's error and in
the log, with the grace it was given: its values are not in the set, and its
output was not masked for the others' secrets.

The residual exposure is process exit. The pool is shut down with ``wait=False``
so the workspace reports once that grace is spent, but the interpreter's own exit handler
joins the abandoned thread, so a genuinely wedged project still delays the
process from exiting. Two things bound it: scanners run as subprocesses with
their own timeouts, so a hung *tool* is handled below this layer, and the
residual case is an in-process scanner stuck in Python. Fixing that properly
means a subprocess per project, which is a larger change than this phase and
would move the per-project scan out of ``core/orchestrator.py``.

Stopping a project, or the whole run, from outside
--------------------------------------------------
The MCP server runs a workspace scan in its own process, so it stops one the way
it stops a single scan: cooperatively (core/cancellation.py). It passes
``cancel_events``, one event per project key. Each project's worker runs inside
its project's cancel scope, so setting one event stops that project at its next
check, its running scanner's child process included, and the project is recorded
FAILED while the others carry on. A project whose event is set before it starts
does not start. The caller can also run ``execute_workspace`` itself inside a
cancel scope: once that event is set, the run raises ``ScanCancelled`` before the
projects start, before the unified results file is written, and before the
workspace reports, so a run stopped there writes neither. The server's
``scan_timeout_seconds`` sets every event.

With events, a project abandoned at its ``project_timeout`` has its event set
too, and the pool is waited for before the run goes on: the abandoned project
stops as a cancelled one does instead of running on unseen, and the caller can
hold what it reserved for the run until its scanners have stopped. Its worker
is given ``_ABANDONED_STOP_GRACE_SECONDS`` to come back before it counts
toward the bound in "An abandoned worker costs a pool slot permanently": a
project still queued starts on it once the stop is done. Counted at once, it
would fail every queued project as never started at a bound of one, the moment
the first was abandoned, with its worker about to be free; never counted, as it
once was, a scan that never checks its scope held its slot for the rest of its
run, the queued projects were never given up on, and neither ``project_timeout``
nor the server's scan timeout bounded the run.

The CLI passes no events. The pool then builds one per project, chained to the
submitting thread's ambient scan-wide event when there is one, so an abandoned
CLI project is stopped the way a cancelled scan stops, and a cancel of the
whole run reaches CLI projects too. What only caller-given events add is the
shutdown wait: without them the workspace result does not wait for an
abandoned project's stop to finish.

The changed-files gate is per project, per repository
----------------------------------------------------
``--changed-files-only`` is evaluated against each project's own git repository,
because projects in a workspace are independently versioned and one diff cannot
answer for all of them. A project with no changed files is skipped with
``no-changes``, which is a successful optimisation and does not colour the exit
status; the skip is in the results payload, not only in the log, because nothing
downstream reads stderr.

Diff paths are resolved against ``git rev-parse --show-toplevel`` rather than
against the project directory. ``git diff --name-only`` prints repository-relative
paths regardless of the directory it runs in, so joining them onto the project
directory is wrong whenever a project sits below a larger repository -- and it
silently produces paths that match nothing, which reads as "no changes".

``--mode precommit`` does not arm this gate. It selects a fast scanner set and
nothing else, which is what it means for a single project, and a workspace that
read it as "diff-scoped" gave one flag two meanings. The diff it would have used
is the wrong one besides: ``<base_ref>...HEAD`` cannot see the staged content a
pre-commit hook is called about. A diff-scoped precommit needs its own flag and
``git diff --cached``.

A project that is not a git repository is scanned with every finding reported,
matching ``--changed-files-only``'s documented behaviour.

Failure modes and known limitations
-----------------------------------
* The timeout limitation above.
* A project that fails is FAILED, not skipped, and fails the workspace. A project
  that resolution skipped -- missing under ``--allow-missing-projects``, or
  unchanged -- does not, because failing there would make both features useless.
* Findings are filtered to the changed set by the project's own scan engine
  (``changed_files`` on the orchestrator), before its summary counts and
  reports are written, with the same ``utils.changed_files`` filter
  single-directory mode uses; two implementations of "is this finding in the
  changed set" would have to be kept in step.
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
import contextvars
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from threading import Event, Lock
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Collection,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

if TYPE_CHECKING:
    from automated_security_helper.config.client_config_policy import (
        ClientConfigRules,
    )

from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
    current_cancel_event,
    link_parent,
    raise_if_cancelled,
)
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.scanner_selection import (
    SelectionOrigin,
    selection_after_exclusions,
)
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    ScannerSelectionError,
    WorkspaceDefinitionError,
)
from automated_security_helper.core.unified_metrics import recorded_error
from automated_security_helper.models.core import IgnoreFileExclusions
from automated_security_helper.models.workspace import (
    SCANNER_EXIT_CODE_UNRECORDED,
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
    git_repository_root_problem,
    validate_base_ref,
)
from automated_security_helper.utils.atomic_write import write_text_atomically
from automated_security_helper.utils.error_text import (
    config_environment_values,
    error_text,
)
from automated_security_helper.utils.inner_run_outcome import report_file_written_as
from automated_security_helper.utils.output_dir_links import (
    OutputDirLinkRefused,
    refuse_linked_output_dir,
)
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.report_path_links import linked_report_path
from automated_security_helper.utils.scan_source import recorded_scan_source
from automated_security_helper.utils.secret_masking import (
    exposed_secret_values,
    mask_secret_shapes_in_text,
    mask_secret_values_in_text,
    mask_secret_values_in_tree,
    mask_secrets_in_results,
    shapes_of_secret_values,
)
from automated_security_helper.utils.subprocess_utils import SANDBOX_STOP_GRACE_SECONDS
from automated_security_helper.workspace.aggregation import (
    POLICY_ORIGIN,
    RESULTS_FILENAME,
    OwnThresholdResolver,
    WorkspaceAggregator,
    actionable_results_by_scanner,
    converter_refusals_for_project,
    has_finding_at_min_severity,
    incomplete_converters_for_project,
    inputs_not_scanned_for_project,
    is_policy_origin,
    result_is_suppressed,
    rewrite_workspace_block,
    stale_content_databases_for_project,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan
from automated_security_helper.workspace.policy import (
    ceiling_unreachable_counts,
    normalise_scanner_name,
)
from automated_security_helper.workspace.reporting import (
    MANIFEST_FILENAME,
    WorkspaceReportOutcome,
    emit_workspace_reports,
    exit_code_after_report_step,
    refuse_linked_workspace_report_paths,
    unsupported_reporter_names,
)

#: How often the outer loop wakes to check per-project deadlines. Small enough
#: that a timeout is reported promptly, large enough not to spin.
_DEADLINE_POLL_SECONDS = 0.05

#: The margin, in seconds, the grace below allows past the subprocess layer's own
#: stop grace: the SIGKILL that ends that grace, and the worker's return through
#: the scan's own cleanup to the pool.
_STOP_GRACE_MARGIN_SECONDS = 1.0

#: How long, in seconds from the abandon's own clock read, an abandoned
#: project's worker is given to come back after its stop was requested, before
#: its slot is counted lost for the projects still queued and the secret values
#: its findings exposed are declared missing from the workspace masking set
#: rather than waited for without bound. Derived from the stop itself, not
#: asserted: a stop reaches a scanner's child through the subprocess layer's
#: SIGTERM, ``SANDBOX_STOP_GRACE_SECONDS`` of waiting, then SIGKILL
#: (``utils/subprocess_utils._stop_grace``), so a worker whose tool ignores
#: SIGTERM comes back only after that grace, and a shorter one here wrote its
#: slot off, and failed every queued project as never started at a bound of one,
#: while the stop was still going to free it. A worker still busy after this
#: long is between scope checks and may not come back for the rest of its scan.
#: Large against a stop, still small against any ``project_timeout``. One grace
#: for every abandoned worker, with or without a caller-given event: the stop
#: reaches the child the same way on both paths, and whether the pool waits for
#: the worker at shutdown says nothing about when its slot frees for a queued
#: project. Measured on the clock and not in polls: a poll ends at every
#: completion (``FIRST_COMPLETED``), so a grace counted in polls was spent in far
#: less than it named whenever other projects were finishing.
_ABANDONED_STOP_GRACE_SECONDS = SANDBOX_STOP_GRACE_SECONDS + _STOP_GRACE_MARGIN_SECONDS

#: The phase name that selects report generation, as ``run_ash_scan`` spells it.
_REPORT_PHASE = "report"

#: The subtree each project's own output lands in.
PROJECTS_DIR_NAME = "projects"

# POLICY_ORIGIN, the marker of a finding from a scanner only
# ``workspace.additional_scanners`` asked for, and is_policy_origin, its reader,
# are imported from workspace.aggregation above: one home, read by the executor
# that writes the marker and by the rollup that honours it.

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
    #: Who gave the two selections above: "mcp" from the MCP workspace tool, whose
    #: SKIPPED rows and selection refusals name its scanners and excluded_scanners
    #: parameters; "cli" for the flags.
    selection_origin: SelectionOrigin = "cli"
    output_formats: Tuple[str, ...] = ()
    config_overrides: Tuple[str, ...] = ()
    #: ``config_overrides`` came from an MCP client, not the operator; see
    #: ``resolve_config(client_overrides=)``.
    client_overrides: bool = False
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
    #: Recorded from ``--mode precommit`` and read by nothing here. It used to arm
    #: the diff gate, which is now ``changed_files_only`` alone -- see
    #: ``changed_file_set``. Workspace mode has never applied the fast scanner set
    #: that the mode selects for a single project (``run_ash_scan._run_local_mode``
    #: does that, and only there), so the mode currently has no workspace effect at
    #: all. Kept because the field is what a caller sets, and porting the scanner
    #: set is a separate change to the scanner selection, not to this gate.
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
    #: of ASH's built-in default. For a project with an ``.ash.yaml``, the plan's
    #: ``operator_config`` names the operator's file layered over it.
    #:
    #: Must hold the SAME value the plan was resolved with -- ``resolver``'s
    #: ``default_config``. The resolver computes each project's reported threshold
    #: and ``_project_config_with_policy`` below re-resolves at scan time, so a
    #: value set here but not there (or the reverse) makes ``--dry-run`` report a
    #: plan the scan does not run, with nothing raising. The MCP workspace tools
    #: set both from one variable for that reason.
    default_config_path: Optional[str] = None
    #: The operator's config the trust checks take as the trusted base, when it is
    #: not ``default_config_path``: the registered profile, when an MCP client
    #: patched the session's copy and ``default_config_path`` names that copy.
    #: None takes ``default_config_path``. The same value as the resolver's
    #: ``trusted_config``, for the reason given above.
    trusted_config_path: Optional[str] = None
    #: The rules a project config an MCP client delivered is checked against,
    #: the session's (config/client_config_policy.py). Set by the MCP workspace
    #: tools with the same value they resolved the plan with; None takes the
    #: trusted base's, which is ``default_config_path``'s.
    client_config_rules: Optional["ClientConfigRules"] = None
    #: The run was started by a remote MCP client, so a project config the
    #: operator did not set aside resolves no ``!ENV`` (``resolve_config``). The
    #: same value the plan was resolved with.
    remote_client: bool = False
    #: The MCP session's gate (``cli/mcp/sandbox.config_base_gate``), or None.
    #: Each project's config file and its bases must resolve to a file it
    #: permits, as for the plan (``resolver.resolve_workspace``'s
    #: ``permit_base``), so a link changed after the plan is refused too.
    config_base_gate: Optional[Callable[[Path], bool]] = None
    #: Keep each project's previous results until its scan has its own, instead
    #: of deleting them when it starts (core/previous_results.py). The MCP
    #: workspace tool sets it, and puts back the previous results of every
    #: project that did not finish; the CLI does not, and deletes them, as it
    #: always has.
    keep_previous_results: bool = False


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
    #: The raw values the project's own masking found (``exposed_secret_values``),
    #: so every other project's outputs can be masked with them too.
    secret_values: Set[str] = field(default_factory=set)
    #: The project's ``metadata.plugin_load_errors``, for the workspace results'
    #: own: the modules its scan could not import, with the error.
    plugin_load_errors: Dict[str, str] = field(default_factory=dict)
    #: An orchestrator ran for this project this run, so what is under
    #: ``projects/<key>`` is this run's output and the cross-project masking
    #: rewrites it: a finished scan's, a scan that raised after writing its
    #: reports, or the tools' output an abandoned worker's discard left. False
    #: for a project the workspace never handed to an orchestrator, or whose
    #: abandoned worker has not come back: what is there then is an earlier
    #: run's, or still being written.
    output_written: bool = False


def workspace_plugin_modules(
    plan: WorkspacePlan, settings: ProjectScanSettings
) -> List[str]:
    """The plugin modules the workspace's scans name, sorted.

    Every active project has the same list by now (resolution refuses a
    workspace whose projects disagree), so the projects speak for all of them;
    settings may add more from the CLI. Each entry is split on commas and
    stripped, the way a scan reads its own list. :func:`prewarm_plugin_registry`
    loads these, and the workspace report step considers only ASH's built-in
    reporters and theirs.
    """
    from automated_security_helper.config.plugin_module_trust import (
        split_plugin_modules,
    )

    declared: Set[str] = set(split_plugin_modules(settings.ash_plugin_modules))
    for project in plan.active_projects:
        declared.update(split_plugin_modules(project.ash_plugin_modules))
    return sorted(declared)


def workspace_module_names(plan: WorkspacePlan) -> Dict[str, str]:
    """How one workspace run names its plugin modules: the projects' maps merged.

    ``plugin_module_trust.merged_module_names`` over every active project's
    ``plugin_module_names``. Used by the prewarm and given to every project's
    engine, so a name any project read from the environment stays masked in the
    whole run's output -- a project that writes the same name literally would
    otherwise print the other project's value from its own engine.
    """
    from automated_security_helper.config.plugin_module_trust import (
        merged_module_names,
    )

    return merged_module_names(
        *(
            getattr(project, "plugin_module_names", None) or {}
            for project in plan.active_projects
        )
    )


def _masked_modules_of_run(plan: WorkspacePlan) -> AbstractContextManager[None]:
    """The scope a registry read of this run is made in: the modules a project
    read from the environment are named by their masks in the lines a
    resolution of the registry writes, inside a longer module name as well.

    A resolution re-imports every registration whenever any has changed, and in
    a process that serves several sessions (the MCP server) that can be the
    first read after the pre-warm, so every read the run makes outside the
    pre-warm is made inside this scope too.
    """
    from automated_security_helper.plugins.loader import masked_module_scope
    from automated_security_helper.plugins.plugin_manager import masked_module_names

    return masked_module_names(masked_module_scope(workspace_module_names(plan)))


def _budget_token(limit: Any) -> str:
    """``project_timeout`` as every timeout message prints its limit
    (error_text.timeout_limit_token): whole, in its quoted token, '60' s.

    With no values: the workspace block is read from the root's config file,
    whose strict load refuses a reference to the environment there, so no
    environment value is this limit.
    """
    from automated_security_helper.utils.error_text import timeout_limit_token

    return timeout_limit_token(limit, ())


def workspace_environment_values(plan: WorkspacePlan) -> Tuple[str, ...]:
    """The values and keys every active project's config read from the
    environment, each once (``ProjectPlan._environment_values``).

    What the prewarm carries on an error it raises, for the run's failure
    handlers, which hold no project config: a plugin module that crashes at
    import can quote any of them, not only its own name.
    """
    merged: Dict[str, None] = {}
    for project in plan.active_projects:
        merged.update(dict.fromkeys(getattr(project, "_environment_values", ())))
    return tuple(merged)


def prewarm_plugin_registry(plan: WorkspacePlan, settings: ProjectScanSettings) -> int:
    """Register every plugin the workspace needs, once, before any project starts.

    Why this happens up front
    -------------------------
    ``ScanExecutionEngine.__init__`` imports a project's ``ash_plugin_modules``,
    which registers their plugins into the module-level ``plugin_library``, and
    then resolves the registry through ``ash_plugin_manager.plugin_modules()``.
    Each engine selects only the built-in plugins and its own modules'
    (``plugins.loader.scan_plugin_filter``), and a resolve reads the registry again
    after a new registration, so the order in which projects start does not decide
    the set. Importing and resolving once before the pool means no worker does
    import work or resolves a registry another worker is registering into.

    Resolution has already refused any workspace whose projects ask for different
    module sets (see ``resolver._validate_plugin_modules``), so there is exactly
    one set and registering it here is correct for every project.
    ``plugin_modules`` does not rely on the pre-warm to avoid the
    concurrent-registration race (another thread registering a key while it
    iterates the registry would raise ``RuntimeError: dictionary changed size
    during iteration``): it iterates a copy of the registrations.

    This does not change *which* scanners run for a project. Registration and
    selection are separate mechanisms: this fills the registry, each project's
    engine selects from it by its own modules, and the project's config still
    decides enablement through ``ScanPhase._execute_phase``'s ``config.enabled``
    and enabled/excluded filtering. A project that disables a scanner still skips
    it.

    Returns:
        How many scanner classes the registry resolved to, for logging. Zero
        means plugin discovery found nothing, which is worth seeing in a log
        rather than discovering later as an empty scan.

    Raises:
        ASHConfigValidationError: A project or ``--ash-plugin-modules`` names a
            module outside the plugin namespace; nothing has been imported.
    """
    from automated_security_helper.config.plugin_module_trust import (
        environment_only_plugin_modules,
    )
    from automated_security_helper.plugins import ash_plugin_manager
    from automated_security_helper.plugins.discovery import discover_plugins
    from automated_security_helper.plugins.loader import (
        PluginLoadRecord,
        load_additional_plugin_modules,
        load_internal_plugins,
        refuse_failed_plugin_imports,
        refuse_plugin_modules_outside_namespace,
    )

    modules = workspace_plugin_modules(plan, settings)
    # How the refusal and every log line below name each entry: the run-wide
    # map, so an entry any project's config read from the environment is
    # named by its masked form; a name in no map, the command line's, is
    # named as it is. Each project's engine is given the same map.
    shown = workspace_module_names(plan)
    # Before anything is imported or any project starts: a name outside the plugin
    # namespace refuses the workspace with exit 3, as it refuses a single scan,
    # and nothing is imported.
    refuse_plugin_modules_outside_namespace(modules, shown=shown)

    load_internal_plugins()
    # The run's own --ash-plugin-modules; the rest only the projects name.
    operator, _ = _workspace_plugin_modules(plan, settings)

    if modules:
        ASH_LOGGER.info(
            f"Loading workspace plugin modules: {[shown.get(m, m) for m in modules]}"
        )
        # A configured module that fails to import refuses the run with exit 3,
        # as a single scan does, whatever the selection: without this, --dry-run
        # exited 0 for a command line the real run refuses, and a --scanners
        # selection naming the failed module's scanner was answered as a usage
        # error. One record, scoped to this call: the three workspace callers
        # all come through here. Raised inside the carrying try below, so the
        # env-read values ride on the refusal too; the bare raise keeps its
        # type, so the exit-3 mapping holds.
        record: PluginLoadRecord = {}
        # One list for both arms: what the loader redacts recorded text with (a
        # tolerated import failure never reaches the except arm), and what that
        # arm carries on an error raised out of this span.
        environment_values = (
            *workspace_environment_values(plan),
            *(name for name, label in shown.items() if label != name),
        )
        try:
            if operator:
                load_additional_plugin_modules(
                    operator,
                    shown=shown,
                    record=record,
                    values=environment_values,
                )
                discover_plugins(plugin_modules=operator, shown=shown, failed=record)
            # A module only the projects name is imported as an untrusted config's,
            # like ScanExecutionEngine imports one, so that a later scan in this
            # process that does not load it is not offered what it registered. The
            # plan does not say which project configs are the operator's, so each
            # project's engine records those its own config trusts
            # (ash_plugin_manager.trust_plugin_modules) when it is built.
            for module_name in modules:
                if module_name in operator:
                    continue
                with ash_plugin_manager.untrusted_import(module_name):
                    load_additional_plugin_modules(
                        [module_name],
                        shown=shown,
                        record=record,
                        values=environment_values,
                    )
                    discover_plugins(
                        plugin_modules=[module_name], shown=shown, failed=record
                    )
            # The scan prints str(error), so the environment remedy for an entry
            # only ASH_PLUGIN_MODULES contributed is built into the message here.
            # The run's option list is `operator`; the projects' entries are the
            # configs'.
            refuse_failed_plugin_imports(
                modules,
                record,
                shown=shown,
                environment_only=environment_only_plugin_modules(
                    operator,
                    [
                        name
                        for project in plan.active_projects
                        for name in project.ash_plugin_modules
                    ],
                ),
            )
        except Exception as error:
            # A module that crashes at import can quote its own name, or any
            # other value a project's config read from the environment, and the
            # run's failure handler has no project config to redact that text
            # with: every such value rides on the error
            # (error_text.carried_environment_values).
            from automated_security_helper.utils.error_text import (
                carry_environment_values,
            )

            carry_environment_values(error, environment_values)
            raise
    ash_plugin_manager.trust_plugin_modules(operator)

    # Resolve once so the memoised list is complete and identical for every
    # project, rather than whatever the first project happened to see.
    resolved = 0
    # Inside the run's masked modules: the lines a resolution writes name a
    # registered module as it was recorded, and an entry a project read from
    # the environment is named by its mask there too, inside a longer module
    # name as well.
    with _masked_modules_of_run(plan):
        for plugin_type in ("converter", "scanner", "reporter"):
            found = ash_plugin_manager.plugin_modules(plugin_type)
            if plugin_type == "scanner":
                resolved = len(found)
    ASH_LOGGER.verbose(
        f"Workspace plugin registry pre-warmed with {resolved} scanner class(es)"
    )
    return resolved


def _workspace_plugin_modules(
    plan: WorkspacePlan, settings: ProjectScanSettings
) -> Tuple[List[str], List[str]]:
    """The run's ``--ash-plugin-modules``, and every module the run loads, sorted.

    The second list is those and every active project's ``ash_plugin_modules``.
    """
    from automated_security_helper.config.plugin_module_trust import (
        split_plugin_modules,
    )

    operator = sorted(split_plugin_modules(settings.ash_plugin_modules))
    declared: Set[str] = set(operator)
    for project in plan.active_projects:
        declared.update(project.ash_plugin_modules)
    return operator, sorted(declared)


def _reporter_classes_of_run(
    plan: WorkspacePlan, settings: ProjectScanSettings
) -> List[type]:
    """:func:`workspace_reporter_classes` for a caller that holds the run's
    masked-module scope (:func:`_masked_modules_of_run`) already."""
    from automated_security_helper.plugins import ash_plugin_manager

    _, modules = _workspace_plugin_modules(plan, settings)
    reporters = ash_plugin_manager.plugin_modules("reporter")
    return ash_plugin_manager.plugins_loaded_by({"reporter": reporters}, modules)[
        "reporter"
    ]


def workspace_reporter_classes(
    plan: WorkspacePlan, settings: ProjectScanSettings
) -> List[type]:
    """The reporters the workspace-level report step considers.

    Every reporter class the registry resolved that this run's plugin modules
    (``_workspace_plugin_modules``) or the operator's load. The registry is the
    process's, so under the MCP server it also holds reporters an earlier scan's
    untrusted config loaded; this run did not choose those
    (``AshPluginManager.plugins_loaded_by``). Called after
    ``prewarm_plugin_registry``, so the resolved list is the warm one.
    """
    # The registry lines these two reads can write name an entry a project
    # read from the environment by its mask, as the prewarm's do.
    with _masked_modules_of_run(plan):
        return _reporter_classes_of_run(plan, settings)


def refuse_unresolvable_scanner_selection(
    plan: WorkspacePlan, settings: ProjectScanSettings
) -> None:
    """Refuse a ``--scanners`` selection no project could run, before any project starts.

    A single scan makes these two checks inside the scan:
    ``ScanExecutionEngine`` refuses a selection that ``--exclude-scanners`` cancels,
    and ``ScanPhase`` one that names no registered scanner. In a workspace each
    project runs its own scan, and ``_scan_one_project`` records any exception as
    that project's failure, so a mistyped name ran every project and the workspace
    exited 1 instead of refusing the command line. Made here instead, once, after
    :func:`prewarm_plugin_registry` has loaded the one plugin-module set every
    project shares, with the builders every selection refusal shares --
    ``core.scanner_selection.selection_after_exclusions`` for the cancelled
    selection, ``community_scanner_refusal`` for the one that names a community
    scanner whose module this run did not load, and
    ``refuse_selection_matching_no_scanner`` for the one that matches nothing --
    so the answer is the one each project's scan phase would reach, in the same
    words, named for the selection's origin. That this
    refusal lands before any project ran is this function's position in
    :func:`execute_workspace`, not a sentence of the message.

    Judged against this workspace's plugins only, not the whole registry. The
    registry is process-wide: in a process that runs more than one scan -- the
    MCP server above all -- it holds every module any earlier scan, session or
    tool loaded. Read whole, it would leak another session's scanner names into a
    refusal the client sees, and would accept a name only another session's
    plugins provide, which then selects nothing in any project here. The scope is
    the
    engine's own: ASH's built-ins plus :func:`workspace_plugin_modules`, through
    the same ``plugins_of`` filter each project's engine resolves with. A
    project's config may narrow further, never widen, so this scope refuses
    nothing a project would run.

    Refused only when the names are certain. A scanner class that declares no
    name is configured under a name only its built config carries, which this
    check cannot read, so a selection that matches nothing is deferred to each
    project's scan phase instead of refused. Every scanner ASH ships declares
    its name, so for stock ASH the deferral never happens.

    Raises:
        ScannerSelectionError: For either case; the CLI exits with the usage-error
            code for it.
    """
    from automated_security_helper.base.plugin_config import (
        declared_plugin_name,
        split_plugin_names,
    )
    from automated_security_helper.core.scanner_selection import (
        community_scanner_refusal,
        refuse_selection_matching_no_scanner,
    )
    from automated_security_helper.plugins import ash_plugin_manager
    from automated_security_helper.plugins.loader import plugins_of

    # Split as the engine splits, so `--scanners bandit,semgrep` is two names here
    # too. Read whole, it was one name no scanner has, and the workspace refused a
    # selection every single scan accepts.
    requested = split_plugin_names(settings.enabled_scanners)
    if not requested:
        return
    # The flags for a CLI run, the MCP workspace tool's parameters for its own.
    remaining = selection_after_exclusions(
        requested,
        split_plugin_names(settings.excluded_scanners),
        settings.selection_origin,
    )
    scope = plugins_of(workspace_plugin_modules(plan, settings))
    declared_names = []
    with _masked_modules_of_run(plan):
        scanner_classes = ash_plugin_manager.plugin_modules(
            "scanner", filter_callback=scope
        )
    for plugin_class in scanner_classes:
        declared = declared_plugin_name(plugin_class)
        if declared is None:
            return
        declared_names.append(declared)
    # A selection that resolves to nothing and names a community scanner ASH
    # ships whose module this run did not load is refused naming the module to
    # add (and any misspelled name beside it), in the one text the engine and
    # the scan phase raise; read as spelling advice alone, it sent the operator
    # to fix a name that was right.
    refusal = community_scanner_refusal(remaining, declared_names, scanner_classes)
    if refusal:
        raise ScannerSelectionError(refusal)
    refuse_selection_matching_no_scanner(
        remaining, declared_names, settings.selection_origin
    )


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

    Gated on ``changed_files_only`` alone, and deliberately not on ``precommit``.
    Single-project mode reads the same one flag, so arming it from the mode made
    one invocation mean "diff-scoped" for a workspace and "fast scanners only" for
    a single project. It was also the wrong diff: ``<base_ref>...HEAD`` cannot see
    the staged content a pre-commit hook is called about, so a project unchanged
    since the base ref was skipped however much was staged in it. A diff-scoped
    precommit needs its own flag and ``git diff --cached``.

    Returns:
        ``None`` when the gate does not apply -- either it was not requested, or
        git could not answer and the documented fallback is to report every
        finding. An empty set when the project is a repository with nothing
        changed inside it, which is the skip signal. Otherwise the absolute paths
        of the changed files that lie within the project.
    """
    if not settings.changed_files_only:
        return None

    project_path = Path(project.path)
    # The project's own environment-read values, for the git stderr line a
    # root-problem clause can quote.
    values = tuple(getattr(project, "_environment_values", ()) or ())
    repository_root = git_repository_root(project_path, values=values)
    if repository_root is None:
        # NO_MARKUP: the problem carries the path and git's own text, and a "[/"
        # in either is a closing Rich tag that raises instead of printing.
        ASH_LOGGER.warning(
            f"Project '{project.key}': "
            f"{git_repository_root_problem(project_path, values=values)}; "
            f"reporting all of its findings, not only those in changed files.",
            extra=NO_MARKUP,
        )
        return None

    changed = get_changed_files(base_ref=settings.base_ref, cwd=project_path)
    if changed is None:
        # git is missing, or the base ref does not exist. get_changed_files has
        # already warned; its documented fallback is to report every finding.
        return None

    resolved_project = project_path.resolve()
    inside: Set[Path] = set()
    for relative in changed:
        # Repository-relative, not project-relative. See the module docstring.
        try:
            candidate = (repository_root / relative).resolve()
        except (ValueError, OSError, RuntimeError):
            # A name that cannot be resolved is no file inside the project. A
            # committed symlink loop (`loop -> loop`) raises RuntimeError on
            # CPython 3.10-3.12, whose non-strict Path.resolve stats the result
            # (check_eloop); 3.13 stopped doing that. The entry does not join the
            # changed set rather than the gate raising out of _scan_one_project.
            continue
        if candidate == resolved_project or candidate.is_relative_to(resolved_project):
            inside.add(candidate)
    return inside


def _scanner_threshold_resolver(
    results: Any,
    project: ProjectPlan,
    environment_read: Optional[Set[str]] = None,
) -> OwnThresholdResolver:
    """The threshold governing each of this project's scanners, by scanner name.

    The same resolution ``_compute_exit_code`` makes for a single scan, read from
    the configuration the results record: a scanner with its own
    ``options.severity_threshold`` is judged by it (source ``"config"``), and every
    other scanner, and a finding naming no scanner, by the project-wide threshold
    (``None`` here, which the counter reads as ``project.gate_threshold``).

    The workspace ceiling binds a scanner's own setting whenever the workspace
    declares one (``ProjectPlan.severity_ceiling``), not only when it moved the
    project-wide value: a ceiling MEDIUM over a project declaring MEDIUM
    tightened nothing, and a scanner's own CRITICAL option stepped under it. A
    ceiling that could be stepped under by one scanner's looser option would not
    be a ceiling. ``stricter_of`` is the same combination the resolver used for
    the project-wide threshold.

    *environment_read*, when given, collects the names of the scanners whose own
    threshold the scan read from an environment variable (``${VAR}`` in an
    external section): the value grades the findings as it did in the scan, and
    the caller that publishes thresholds (:func:`_recorded_scanner_thresholds`)
    leaves those scanners out, as the report rows print the reference and never
    the environment's value.

    Memoised per name because the resolver dumps the scanners config on every
    call and a project's run carries one result per finding. Imported inside the
    function because the calculator imports the models this module imports.
    """
    from automated_security_helper.core.scanner_statistics_calculator import (
        ScannerStatisticsCalculator,
    )
    from automated_security_helper.utils.severity_ladder import stricter_of

    cache: Dict[str, Optional[str]] = {}

    def resolve(scanner_name: Optional[str]) -> Optional[str]:
        if not scanner_name:
            return None
        if scanner_name not in cache:
            own: Optional[str] = None
            try:
                value, _shown, source, from_env = (
                    ScannerStatisticsCalculator.get_scanner_threshold_details(
                        results, scanner_name
                    )
                )
            except Exception as error:  # noqa: BLE001 -- an unreadable config grades as the project does
                value, source, from_env = None, "unavailable", False
                ASH_LOGGER.debug(
                    f"Project '{project.key}': the threshold of scanner "
                    f"'{scanner_name}' could not be read from the recorded "
                    f"configuration ({error_text(error)}); its findings are graded "
                    f"at the project's threshold",
                    extra=NO_MARKUP,
                )
            if source == "config" and isinstance(value, str) and value:
                own = value.upper()
                if project.severity_ceiling:
                    own = stricter_of(own, project.severity_ceiling)
                if from_env and environment_read is not None:
                    environment_read.add(scanner_name)
            cache[scanner_name] = own
        return cache[scanner_name]

    return resolve


def _recorded_scanner_thresholds(
    resolve: OwnThresholdResolver,
    statuses: Mapping[str, str],
    results: Sequence[Mapping[str, Any]],
    environment_read: Collection[str] = frozenset(),
) -> Dict[str, str]:
    """Per scanner, the threshold the verdict graded it by when it is the scanner's own.

    The scanners asked are the ones the project recorded a status for and the
    ones its findings name, so a scanner that ran and found nothing is recorded
    too (a reader grading a later finding of its kind needs it) and a finding from
    a scanner no row recorded is not left out. *resolve* is the project's
    :func:`_scanner_threshold_resolver`, whose answer is already upper-cased and
    has the workspace ceiling folded in; its ``None`` means "the project's
    threshold", which ``severity_threshold`` already records, so that scanner is
    left out of the map.

    A scanner in *environment_read* (its threshold was read from an environment
    variable) is left out too, after it has been resolved: the unified results
    and the MCP payloads this map reaches would otherwise publish the
    environment's value, which every report surface withholds (the statistics
    calculator prints the written ``${VAR}`` reference in its place). A reader
    then grades that scanner by ``severity_threshold``, the one divergence from
    the verdict this field accepts, and the field's description says so.
    """
    names = set(statuses)
    for result in results:
        if not isinstance(result, Mapping):
            continue
        properties = result.get("properties")
        if not isinstance(properties, Mapping):
            continue
        name = properties.get("scanner_name")
        if isinstance(name, str) and name:
            names.add(name)
    recorded: Dict[str, str] = {}
    for name in sorted(names):
        own = resolve(name)
        if own and name not in environment_read:
            recorded[name] = own
    return recorded


def _coverage_fields(results: Any) -> Dict[str, Any]:
    """The six ``WorkspaceProjectResult`` coverage fields, from one read of *results*.

    The read is ``scan_incompleteness(results, gate=True)``, the object
    ``_compute_exit_code`` asks the same questions of, so a project's outcome and
    ``ash --source-dir P`` on it answer from one source. This function makes the
    call itself, and is its only production consumer, so the choice of ``gate=True``
    (the facts whatever the gate resolves to; the gate decides ``scan_incomplete``
    separately) lives here and a test that calls this function exercises it. A
    workspace project is never one shard of a split (``ProjectScanSettings`` carries
    no shard fields), so ``one_shard_of_a_split`` is not passed and
    ``no_scanner_ran`` is the plain set-level answer.

    ``unevaluated_rules`` and ``unstoppable_tools`` are the two exit-1 arms
    ``_compute_exit_code`` asks with the gate on or off. They used to be read into
    the same object and dropped here, so a project that exits 1 alone on a rule
    that raised, or on a tool ASH could not stop, passed inside a workspace.

    Imported inside the function because ``run_ash_scan`` imports this module for
    workspace mode; a module-level import closes that into a cycle.
    """
    from automated_security_helper.interactions.run_ash_scan import (
        scan_incompleteness,
    )

    coverage = scan_incompleteness(results, gate=True)
    return {
        "incomplete_scanners": [name for name, _status in coverage.scanners],
        "incomplete_scanner_details": dict(coverage.scanners),
        "partial_coverage_scanners": list(coverage.partial_coverage),
        "no_scanner_ran": coverage.no_scanner_ran,
        "unevaluated_rules": list(coverage.unevaluated_rules),
        "unstoppable_tools": dict(coverage.could_not_stop),
    }


def _scan_one_project(
    project: ProjectPlan,
    settings: ProjectScanSettings,
    orchestrator_factory: OrchestratorFactory,
    abandoned: Optional["_AbandonGate"] = None,
    module_names: Optional[Mapping[str, str]] = None,
) -> _ProjectRun:
    """Scan one project in its own scope and reduce it to an outcome plus a run.

    Args:
        abandoned: The outer loop's gate for this project, set when it has been
            given up on at its timeout. The abandon also sets the project's
            cancel event, but a scan between scope checks keeps running -- so
            the write below is claimed through the gate first
            (``try_commit``): the workspace has already recorded an abandoned
            project as FAILED, and a later write would leave
            ``projects/<key>/`` holding real findings that the unified file says
            do not exist. The claim and the abandon are taken under one lock, so
            a project is either committed or abandoned, never both.
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

    # Before the mkdir, which would follow a link at projects/ or projects/<key>.
    # Checked from the workspace's output directory down, so both are examined, and
    # the project's working directories with them. The orchestrator checks again
    # from the project's own directory.
    try:
        refuse_linked_output_dir(settings.output_dir, project_output)
    except OutputDirLinkRefused as refusal:
        ASH_LOGGER.error(f"Project '{project.key}' was not scanned: {refusal}")
        return _failed_outcome(
            project,
            settings,
            str(refusal),
            duration_seconds=time.monotonic() - started,
        )
    project_output.mkdir(parents=True, exist_ok=True)

    # True once an orchestrator exists for this project: from then on whatever
    # the scan writes under projects/<key>/ is this run's, however the scan ends.
    # The failed outcomes below carry it as output_written, so the cross-project
    # masking rewrites the reports a scan saved before it raised, and leaves a
    # previous run's files alone for a project that never reached a scan.
    handed = False
    try:
        resolved_config = _project_config_with_policy(project, settings)

        orchestrator = orchestrator_factory(
            source_dir=Path(project.path),
            output_dir=project_output,
            work_dir=project_output / ASH_WORK_DIR_NAME,
            # The workspace's output directory holds every project's output and
            # the unified results: for a project at the workspace root it is in
            # the scanned tree, and it is ASH's own output like project_output.
            workspace_output_dir=Path(settings.output_dir),
            enabled_scanners=list(settings.enabled_scanners),
            excluded_scanners=list(settings.excluded_scanners),
            selection_origin=settings.selection_origin,
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
            # None or non-empty here: an empty set skipped the project above. The
            # project's engine drops findings outside these files before its
            # summary counts and reports are written.
            changed_files=changed,
            keep_previous_results=settings.keep_previous_results,
            python_based_plugins_only=settings.python_based_plugins_only,
            ignore_suppressions=settings.ignore_suppressions,
            ash_plugin_modules=list(settings.ash_plugin_modules),
            # The run-wide naming the prewarm used (workspace_module_names), so
            # this project's engine never prints a name another project read
            # from the environment.
            plugin_module_names=dict(module_names or {}),
            # The project's own identity, so that its per-project reports can say
            # which project they describe. Ten of the nineteen reporters are ruled
            # PER_PROJECT, and that ruling is only honest if the N artefacts are
            # distinguishable -- which for the four that publish to a shared
            # destination they were not. See ASHScanOrchestrator._apply_metadata.
            metadata={
                "project_name": project.display_label,
                "workspace_project": project.key,
                # As in single-directory mode: True when the changed-files filter
                # narrows this project's results to this changed-file set, so what
                # they leave out is not fixed; an explicit False on a full scan.
                "changed_files_only": changed is not None,
                # The project's directory within its repository; see
                # utils/scan_source.py. The container launcher's label names the
                # workspace mount, not this project.
                "scan_source": recorded_scan_source(
                    Path(project.path),
                    git_repository_root,
                    snapshot_environ(),
                    workspace_project=True,
                ),
            },
        )
        handed = True
        results = orchestrator.execute_scan(phases=list(settings.phases))
        # The reduction runs under the arms below, not after them: it reads and
        # writes files (_verdict_results, _write_project_results), validates the
        # outcome's fields and takes the commit-or-abandon gate. A raise from any
        # of that used to leave this function unguarded, so the poll recorded a
        # plain FAILED outcome with output_written False: the reports the scan
        # had saved were never re-masked, the secret values its findings exposed
        # never reached the masking set, and an abandoned project's output was
        # never discarded.
        return _reduce_project_scan(
            project,
            settings,
            results,
            project_output=project_output,
            output_path=output_path,
            started=started,
            abandoned=abandoned,
            resolved_config=resolved_config,
        )
    except ScanCancelled:
        # A BaseException, so the arm below does not see it. The cancelled
        # outcome is built here, where ``handed`` is known, and not in the
        # worker: the poll cancels ONE project at its budget and the run goes
        # on to write unified results, so the reports that project saved before
        # the cancel reached it are this run's files and the masking pass has
        # to see them, as it does a raise's (the arm below). Was the cancel
        # this project's abandon (the gate is taken)? Then that output goes the
        # way of a raise's too: the results and reports hold findings the FAILED
        # verdict already recorded says do not exist. Claimed through the gate
        # for the reason given in the arm below. Any other cancel (the run's,
        # the caller's) takes the claim and leaves the output in place.
        ASH_LOGGER.info(f"Project '{project.key}' stopped: it was cancelled")
        if handed and abandoned is not None and not _claim_commit(abandoned):
            _discard_project_output(project_output)
        cancelled = _failed_outcome(
            project,
            settings,
            "cancelled",
            duration_seconds=time.monotonic() - started,
        )
        cancelled.output_written = handed
        return cancelled
    except ASHConfigValidationError as exc:
        # The label the single-directory CLI prints ("Scan refused" for committed
        # files in the way), and the text logged as data: a committed file's name
        # can hold Rich markup. error_text: the error goes to the log, the unified
        # results and the MCP response, and a pydantic error's own text quotes
        # the refused input.
        from automated_security_helper.core.committed_output import refusal_label
        from automated_security_helper.utils.log import NO_MARKUP

        label = refusal_label(exc)
        ASH_LOGGER.error(
            f"Project '{project.key}': {label}: {error_text(exc)}", extra=NO_MARKUP
        )
        # The same gate the arm below takes. A refusal raised after the output
        # was handed (the orchestrator refused the config as it ran) left what
        # the scan had saved in place for an abandoned project, and a poll abandon
        # landing after this verdict could overwrite the exit-3 refusal with a
        # timeout verdict; claimed, neither happens.
        if handed and abandoned is not None and not _claim_commit(abandoned):
            _discard_project_output(project_output)
        refused = _failed_outcome(
            project,
            settings,
            f"{label}: {error_text(exc)}",
            invalid_config=True,
            duration_seconds=time.monotonic() - started,
        )
        refused.output_written = handed
        return refused
    except Exception as exc:  # noqa: BLE001 -- one project must not sink the workspace
        ASH_LOGGER.error(f"Project '{project.key}' failed: {error_text(exc)}")
        if handed and abandoned is not None and not _claim_commit(abandoned):
            # The scan may have saved its results and reports under
            # projects/<key>/ before it raised; the workspace already recorded
            # this project FAILED at its timeout, so those leftovers go too.
            # Claimed, not read: a plain is_set() read left a window in which
            # a poll abandon landing after it recorded the timeout verdict
            # while these files stayed. The claim takes the decision once: a
            # worker that raised owns its FAILED outcome, and the poll can no
            # longer abandon it.
            _discard_project_output(project_output)
        failed = _failed_outcome(
            project,
            settings,
            f"{type(exc).__name__}: {error_text(exc)}",
            duration_seconds=time.monotonic() - started,
        )
        # A scan that raised after writing its reports left this run's files
        # under projects/<key>/, with the other projects' secret values in
        # clear where it quoted them; the masking pass rewrites them like any
        # finished project's. Before this every FAILED project was skipped.
        failed.output_written = handed
        return failed


def _reduce_project_scan(
    project: ProjectPlan,
    settings: ProjectScanSettings,
    results: Any,
    *,
    project_output: Path,
    output_path: str,
    started: float,
    abandoned: Optional["_AbandonGate"],
    resolved_config: Any,
) -> _ProjectRun:
    """Reduce a finished scan's results to the project's outcome and SARIF run.

    Called by ``_scan_one_project`` from inside its try, after the orchestrator
    returned, so that every arm there (a cancel, a config refusal, any other
    raise) covers this half too: the commit-or-abandon claim, the discard of an
    abandoned project's output and ``output_written`` for the masking pass are
    decided once, in those arms, for a raise before the scan and a raise after it
    alike. Nothing in here is new; it is the half of ``_scan_one_project`` that
    used to run after the arms, where a raise reached the pool's own guard as a
    plain failure.
    """
    # Before _extract_run, so the tag is present in both the model written to
    # projects/<key>/ and the dict carried into the unified file.
    _tag_policy_origin_findings(results, project)

    run = _extract_run(results)
    # Counted where a single scan counts them: from the SARIF report this scan's
    # reporter wrote when there is one, else from the model. The run carried into
    # the unified file takes the same list, so the counts, the exit code and the
    # unified findings agree on every suppression.
    results_list = _verdict_results(results, run, project_output, project)
    if run is not None:
        run["results"] = results_list

    # A suppression that has not taken effect (rejected, underReview) hides
    # nothing: the same reading the per-scanner counts and the flat finding make.
    unsuppressed = [entry for entry in results_list if not result_is_suppressed(entry)]
    policy_origin = [entry for entry in unsuppressed if is_policy_origin(entry)]

    # What the verdict is allowed to see. Findings from a scanner only the policy
    # added are REPORTED either way -- they are in `unsuppressed` above and carry
    # their tag -- but they decide nothing unless the operator set
    # policy_scanners_gate. A workspace that adds a scanner to gather visibility
    # must not thereby fail projects that never opted into it.
    gating_results = (
        results_list
        if project.policy_scanners_gate
        else [entry for entry in results_list if not is_policy_origin(entry)]
    )

    # gate_threshold, not severity_threshold: this is where a workspace severity
    # ceiling takes effect on the verdict. Reading the declared value here would
    # leave the ceiling visible in the plan and in --dry-run while changing
    # nothing about which projects fail.
    threshold = project.gate_threshold
    # Graded per scanner, as _compute_exit_code grades a single scan: a scanner
    # with its own options.severity_threshold is judged by it, every other one by
    # the project's threshold. Judging every finding against the one project
    # threshold gave a project a workspace verdict that differed from
    # `ash --source-dir P` the moment its config tightened or relaxed one scanner.
    environment_read: Set[str] = set()
    scanner_threshold = _scanner_threshold_resolver(results, project, environment_read)
    actionable_by_scanner = actionable_results_by_scanner(
        gating_results,
        threshold,
        threshold_for=scanner_threshold,
    )
    actionable = sum(actionable_by_scanner.values())
    if actionable and not has_finding_at_min_severity(
        gating_results,
        settings.min_severity,
        threshold,
        threshold_for=scanner_threshold,
    ):
        # --min-severity is a whole-scan switch in _compute_exit_code, not a
        # per-finding filter. Mirrored here so the verdict matches, and the
        # split carried to the rollup is zeroed with it. The gate is handed the
        # same two thresholds the count used: a finding its own scanner's
        # threshold made non-actionable was not counted above, so it is not the
        # finding that keeps the count standing, here as in _compute_exit_code.
        actionable = 0
        actionable_by_scanner = dict.fromkeys(actionable_by_scanner, 0)

    fail_on_findings = _resolve_fail_on_findings(settings, results)

    # The completeness half of the verdict, alongside the threshold half above.
    # Without it a project whose scanners never ran reported zero findings and
    # SUCCESS, while `ash --source-dir P` on the same project exited 1 -- the
    # workspace layer mirrored only the threshold pass.
    #
    # One scan_incompleteness read, taken inside _coverage_fields, supplies six
    # coverage fields below (the names, the display details, the partial-audit names,
    # the set-level "nothing ran" answer, the rules no scanner could evaluate and the
    # tools ASH could not stop), so they cannot disagree with each other or with
    # what _compute_exit_code reads.
    coverage_fields = _coverage_fields(results)
    incomplete = coverage_fields["incomplete_scanners"]
    # The set-level question is not implied by the per-entry list. The per-entry
    # pass has to tolerate SKIPPED -- that is how --exclude-scanners records work
    # this run was never meant to do -- so a project in which every entry is SKIPPED
    # clears it having measured nothing. Without this field such a project reported
    # zero findings and SUCCESS while `ash --source-dir P` on it exited 1.
    measured_nothing = coverage_fields["no_scanner_ran"]
    # The converter question _compute_exit_code also asks: a notebook that could
    # not be converted, or a converter that crashed, is coverage the scanners never
    # had. Without it a project inside a workspace passed where `ash --source-dir P`
    # exited 1. Not subject to the policy-scanner exclusion below, which is about
    # scanners a policy added; converters are not added by policy.
    incomplete_conversions = incomplete_converters_for_project(results)
    # Reported in a field of its own, as a single scan's payload does, and not in
    # `incomplete` above, which leaves out a scanner listed only for it.
    stale = stale_content_databases_for_project(results)
    fail_on_incomplete = _resolve_fail_on_incomplete_scanners(settings, results)
    # The same policy_scanners_gate exclusion, applied to the completeness half.
    # Without it the flag is honoured for findings and ignored for the exit code:
    # a policy scanner whose tool is absent reads MISSING, MISSING fails the
    # completeness gate, and a workspace adding a scanner "for visibility" would
    # fail every project on every host lacking that tool -- with no finding
    # involved at all. Still reported in `incomplete_scanners`, because an
    # operator has not asked to be told a scan was complete when it was not.
    gating_incomplete = incomplete
    # The same exclusion for a stale content database: a scanner only the policy
    # added, with the gate off, "cannot fail the project" (policy_origin_finding_count),
    # and its database's age is no more the project's doing than its MISSING tool
    # is. Still reported in stale_content_databases, as the incomplete scanner is.
    gating_stale = stale
    if project.policy_scanners and not project.policy_scanners_gate:
        policy_names = {
            normalise_scanner_name(name) for name in project.policy_scanners
        }
        gating_incomplete = [
            name
            for name in incomplete
            if normalise_scanner_name(name) not in policy_names
        ]
        gating_stale = [
            record
            for record in stale
            if normalise_scanner_name(str(record.get("scanner") or ""))
            not in policy_names
        ]

    if abandoned is not None and not _claim_commit(abandoned):
        # Given up on while this was running. Do not write, and do not return an
        # outcome -- the outer loop already recorded FAILED for this project, and
        # a per-project results file with real findings beside a unified file
        # saying finding_count=0 is a contradiction an operator would have to
        # resolve by guessing which one to trust. The claim above is what makes
        # this exclusive: once it succeeds the outer loop can no longer abandon
        # this project, and once the loop has abandoned it the claim fails.
        ASH_LOGGER.warning(
            f"Project '{project.key}' finished after being abandoned at its "
            f"timeout; discarding its results rather than contradicting the "
            f"workspace verdict already recorded for it."
        )
        # Skipping the write below is not enough: the scan phase saved
        # projects/<key>/ash_aggregated_results.json and the project's reports
        # itself before this check ran, so they already hold the findings the
        # verdict says do not exist. Removed, as the message above says.
        _discard_project_output(project_output)
        late = _failed_outcome(
            project,
            settings,
            "abandoned at its project_timeout; the scan completed later and its "
            "results were discarded",
            duration_seconds=time.monotonic() - started,
        )
        # The verdict is discarded; the secret values the findings exposed are
        # not. The scan ran before the abandon could be seen, and another
        # project may pass one of these values on a command line, so they join
        # the workspace masking set when the pool reads this result back
        # (_run_projects). Nothing of this project's reports is left to mask
        # with the other projects' values; what the discard leaves under
        # projects/<key> is the tools' own output, which the masking leaves
        # alone for every project.
        late.secret_values = exposed_secret_values(results)
        late.output_written = True
        return late

    _write_project_results(project_output, results)

    # Where the ceiling could not reach, computed from the findings actually
    # present rather than asserted about a scanner. Only when the ceiling really
    # did tighten this project: a disclosure printed on every scan is noise, and
    # noise gets skipped. ceiling_unreachable_counts returns {} when the two
    # thresholds are equal, so this is belt and braces rather than the only guard.
    # The same policy_scanners_gate exclusion as the verdict's: a non-gating policy
    # scanner's findings are judged at no threshold, so the ceiling never claimed
    # them, and counting their level-only findings here told the operator the
    # ceiling could not reach findings the gate never judged.
    unreachable: Dict[str, int] = {}
    if project.threshold_tightened_by_policy:
        non_gating: Set[str] = set()
        if project.policy_scanners and not project.policy_scanners_gate:
            non_gating = _policy_scanner_names(project)
        unreachable = ceiling_unreachable_counts(
            results_list,
            declared_threshold=project.severity_threshold,
            effective_threshold=threshold,
            non_gating_scanners=non_gating,
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
        # The gates a reader needs to regrade this project's findings as the
        # verdict did: each scanner's own threshold where it has one, and whether
        # a policy scanner's findings decided anything. The unified file carries
        # no ash_config, so without these the merged reporters and the MCP
        # result filters graded every project at ASH's default and reported a
        # non-gating policy finding as a failure.
        scanner_thresholds=_recorded_scanner_thresholds(
            scanner_threshold, statuses, results_list, environment_read
        ),
        # The names of the scanners left out of that map because their value
        # came from the environment: a reader then knows the project gate it
        # falls back to for them is not the gate the verdict used. Names only;
        # the values stay unpublished.
        withheld_scanner_thresholds=sorted(environment_read),
        finding_count=len(unsuppressed),
        actionable_finding_count=actionable,
        policy_origin_finding_count=len(policy_origin),
        policy_scanners_gate=bool(project.policy_scanners_gate),
        exceeds_threshold=bool(actionable) and fail_on_findings,
        duration_seconds=time.monotonic() - started,
        output_path=output_path,
        scanners=statuses,
        scanner_reasons=_scanner_reasons(
            results, config_environment_values(resolved_config)
        ),
        **coverage_fields,
        # The unified results carry no per-target reports, so without this the
        # merged summaries and the console could not name what went unscanned.
        inputs_not_scanned=inputs_not_scanned_for_project(
            results, project.relative_path
        ),
        incomplete_converters=incomplete_conversions,
        # The inputs behind incomplete_converters, and the refusals that leave the
        # scan complete, each at its workspace-relative path: the unified file
        # holds no per-project converter rows, so this is the only place the
        # merged summaries can read which input went unconverted.
        converter_refusals=converter_refusals_for_project(
            results, project.relative_path
        ),
        stale_content_databases=stale,
        # A stale content database under `content_db_staleness: fail` fails the project
        # whatever fail_on_incomplete says, matching _compute_exit_code's own arm for it:
        # `ash --source-dir P` exits 1 on it, so P inside a workspace must not pass.
        # The same holds for a rule a scanner could not evaluate and for a tool ASH
        # could not stop: _compute_exit_code returns 1 on either with the gate off,
        # and neither is subject to the policy-scanner exclusion above, because a
        # rule that raised reports nothing about compliance with it and a tool still
        # running may write into this project's output after the verdict read it,
        # whichever config asked for the scanner.
        scan_incomplete=(
            (
                bool(gating_incomplete)
                or measured_nothing
                or bool(incomplete_conversions)
            )
            and fail_on_incomplete
        )
        or bool(gating_stale)
        or bool(coverage_fields["unevaluated_rules"])
        or bool(coverage_fields["unstoppable_tools"]),
        ceiling_unreachable_findings=unreachable,
        ignore_file_exclusions=_ignore_file_exclusions_of(results),
    )
    outcome.carry_scanner_exit_codes(_scanner_exit_codes(results))
    outcome.carry_scanner_actionable_counts(actionable_by_scanner)
    outcome.carry_scanner_flags(_scanner_flags(results))
    return _ProjectRun(
        outcome=outcome,
        run=run,
        secret_values=exposed_secret_values(results),
        plugin_load_errors=dict(
            getattr(getattr(results, "metadata", None), "plugin_load_errors", None)
            or {}
        ),
        output_written=True,
    )


def _ignore_file_exclusions_of(results: Any) -> Optional[IgnoreFileExclusions]:
    """The project's ``metadata.ignore_file_exclusions``, or None when it has none."""
    record = getattr(getattr(results, "metadata", None), "ignore_file_exclusions", None)
    if isinstance(record, IgnoreFileExclusions):
        return record
    if isinstance(record, dict):
        return IgnoreFileExclusions.model_validate(record)
    return None


def _workspace_root(project: ProjectPlan) -> Path:
    """The workspace root, which every project path sits below."""
    root = Path(project.path)
    for _ in PurePosixPath(project.relative_path).parts:
        root = root.parent
    return root


def _same_file(first: Optional[str | Path], second: Optional[str | Path]) -> bool:
    """Whether two optional paths name the same file, or are both None."""
    if first is None or second is None:
        return first is None and second is None
    return Path(first).resolve() == Path(second).resolve()


def _check_the_plans_operator_config(
    project: ProjectPlan, settings: ProjectScanSettings
) -> None:
    """Refuse a project whose plan does not layer the operator config the scan names.

    The scan layers the file the plan recorded (``project.operator_config``), so
    the plan's ``--dry-run`` is what runs. That holds only for a plan resolved
    with the same operator config as these settings: a plan resolved without one,
    or with another, would be scanned without the operator's final fields. And
    the file must not have changed since the plan was resolved
    (``operator_config_digest``), or the scan would run settings the plan did not
    report. Either is refused for this project, as a config error.

    Raises:
        ASHConfigValidationError: The plan and these settings disagree, or the
            operator config changed since the plan.
    """
    from automated_security_helper.config.resolve_config import operator_config_digest
    from automated_security_helper.workspace.resolver import _operator_config

    operator = _operator_config(
        Path(settings.default_config_path) if settings.default_config_path else None,
        Path(settings.trusted_config_path) if settings.trusted_config_path else None,
    )
    # A project with no config of its own uses the default config alone, so
    # nothing is layered over it.
    own_config = project.config_source is not None and not _same_file(
        project.config_source, settings.default_config_path
    )
    expected = operator if own_config else None
    if not _same_file(project.operator_config, expected):
        raise ASHConfigValidationError(
            f"Project '{project.key}' was planned with operator config "
            f"{project.operator_config or 'none'}, but this scan is run with "
            f"{expected.as_posix() if expected else 'none'}. Resolve the workspace "
            "again with the same --config as the scan."
        )
    # The digest is read from the operator's file itself, the one the resolver
    # took it from (its `_operator_config`, the same value `operator` holds
    # here), for every project the file governs: layered over the project's own
    # config, or the project's config itself because it declares none. Reading
    # `project.operator_config` instead left the second kind unchecked, since
    # that field is None for it, and a rewrite of the operator's file between
    # plan and scan went undetected for every project without a config of its
    # own. The layering check above has already settled which file this is.
    # The plan records the digest, not the path, for the second kind, so a
    # mismatch here is "not the content the plan was made from", whether the
    # same file was rewritten or another file now holds the operator's role;
    # the message says that and names the remedy both cases share.
    if (
        operator is not None
        and project.operator_config_digest is not None
        and operator_config_digest(operator) != project.operator_config_digest
    ):
        raise ASHConfigValidationError(
            f"The operator config {operator.as_posix()} does not hold the "
            f"content project '{project.key}' was planned with (its digest "
            "differs from the plan's), so the scan would not run the plan. "
            "Resolve the workspace again with the same --config as the scan."
        )


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
    from automated_security_helper.config.config_sources import (
        check_discovered_source,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    _check_the_plans_operator_config(project, settings)

    # ``config_source`` is None for a project that declared no config. The plan was
    # resolved with the same fallback, so the resolver already recorded the
    # fallback as this project's config_source when one applied -- this branch
    # covers a plan built without it, and a hand-built plan.
    config_path = project.config_source or settings.default_config_path
    if config_path is not None:
        # Checked again here, not only by the plan: the file is read now, and a
        # link can change between the two (config_sources, "Base paths").
        check_discovered_source(Path(config_path), settings.config_base_gate)

    config = resolve_config(
        config_path=config_path,
        source_dir=Path(project.path),
        fallback_to_default=True,
        # Load-bearing. See the warning above.
        config_overrides=list(settings.config_overrides),
        # The whole workspace is scanned, so a config anywhere under its root was
        # written by the repository, not only one under this project.
        scanned_root=_workspace_root(project),
        client_overrides=settings.client_overrides,
        # The operator's file is the trusted base for every project, and the
        # file the plan layered over a project's own config
        # (resolver._resolve_project_config) is that same file, so a field the
        # operator set is its trusted value.
        trusted_config_path=(
            settings.trusted_config_path
            if settings.trusted_config_path is not None
            else settings.default_config_path
        ),
        client_config_policy=settings.client_config_rules,
        remote_client=settings.remote_client,
        # Read from the plan rather than re-derived from the settings, so the
        # scan layers exactly the file --dry-run reported.
        overlay_config_path=project.operator_config,
        permit_base=settings.config_base_gate,
    )

    # The scanners' own checks on tool config file paths (config/path_trust.py)
    # use the same tree as the checks above: the whole workspace.
    config._scanned_root = _workspace_root(project)

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


#: Section bodies that cannot carry an ``enabled`` field: the resolver's
#: ``_section_is_on`` reads every one of them as off (a bare boolean is that
#: boolean), so a policy that requires the scanner meets them here.
_NO_SECTION_BODY = (bool, str, bytes, int, float, list, tuple, set, frozenset)


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

    # Folded name -> the attributes to reach its entries through, declared fields
    # first. Declared fields are indexed under both their Python name and their
    # alias. Every attribute that folds to the name is kept, not one of them:
    # a declared scanner can have spellings of its name beside it
    # (``detect.secrets`` beside ``detect-secrets``), and the plan refuses two
    # extra sections that fold to a name the policy requires. The scan reads a
    # declared scanner's own section, or one section among the extra ones, so
    # switching on every section leaves it an enabled one whichever it reads. A
    # spelling beside a declared scanner is switched on as well, although the
    # lookup never reads it as that scanner's.
    index: Dict[str, List[str]] = {}

    def add(folded: str, attribute: str) -> None:
        attributes = index.setdefault(folded, [])
        if attribute not in attributes:
            attributes.append(attribute)

    for field_name, field_info in fields.items():
        add(normalise_scanner_name(field_name), field_name)
        if field_info.alias:
            add(normalise_scanner_name(field_info.alias), field_name)
    for key in extra:
        add(normalise_scanner_name(key), key)

    for name in names:
        targets = index.get(normalise_scanner_name(name))
        if not targets:
            # extra="allow" on ScannerConfigSegment, so this lands in
            # __pydantic_extra__ and get_plugin_config finds it by key.
            setattr(segment, name, {"name": name, "enabled": True})
            ASH_LOGGER.verbose(
                f"Workspace policy added scanner '{name}', which this project's "
                f"configuration does not describe; it will run with default "
                f"settings if a plugin provides it."
            )
            continue
        for target in targets:
            entry = getattr(segment, target, None)
            if entry is None or isinstance(entry, _NO_SECTION_BODY):
                # No body, a bare boolean (``acme: false``), another scalar or a
                # list: nothing in it can carry ``enabled``, which is why the
                # resolver read the section as off and listed the scanner as
                # policy-added. Replaced with a body that can; assigning
                # ``.enabled`` on a bool raised AttributeError here.
                setattr(segment, target, {"name": name, "enabled": True})
            elif isinstance(entry, dict):
                entry["enabled"] = True
            else:
                entry.enabled = True
        ASH_LOGGER.verbose(
            f"Workspace policy enabled scanner '{name}' for this project."
        )


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

    wanted = _policy_scanner_names(project)
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


def _scanner_flags(results: Any) -> Dict[str, Tuple[bool, bool]]:
    """Per scanner, the row's ``(excluded, dependencies_satisfied)``, as plain bools.

    Read from the same rows the statuses come from, for the rollup's two flags
    of the same names. Deriving them from the rolled-up status read an
    operator-excluded scanner whose tool was also absent (a MISSING row with
    ``excluded`` set) as not excluded, and a scanner that had nothing to scan (a
    SKIPPED row with ``excluded`` unset) as excluded.
    """
    flags: Dict[str, Tuple[bool, bool]] = {}
    for name, info in (getattr(results, "scanner_results", None) or {}).items():
        flags[str(name)] = (
            bool(getattr(info, "excluded", False)),
            bool(getattr(info, "dependencies_satisfied", True)),
        )
    return flags


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


def _policy_scanner_names(project: ProjectPlan) -> Set[str]:
    """The normalized names of the scanners only the policy added to *project*."""
    return {normalise_scanner_name(name) for name in project.policy_scanners or ()}


def _tag_policy_origin_entries(
    entries: Iterable[Dict[str, Any]], project: ProjectPlan
) -> None:
    """:func:`_tag_policy_origin_findings` for results already reduced to dicts.

    For the entries of the SARIF report a project's reporter wrote before the
    model was tagged (:func:`_verdict_results`): the same rule, read from the
    same attribution, so an entry counted from the file is excluded by
    ``policy_scanners_gate`` exactly as its model twin is.
    """
    wanted = _policy_scanner_names(project)
    if not wanted:
        return
    for entry in entries:
        properties = entry.get("properties")
        if not isinstance(properties, dict):
            continue
        scanner = properties.get("scanner_name")
        if (
            not isinstance(scanner, str)
            or normalise_scanner_name(scanner) not in wanted
        ):
            continue
        properties["origin"] = POLICY_ORIGIN
        tags = list(properties.get("tags") or [])
        if POLICY_ORIGIN not in tags:
            tags.append(POLICY_ORIGIN)
        properties["tags"] = tags


def _verdict_results(
    results: Any,
    run: Optional[Dict[str, Any]],
    project_output: Path,
    project: ProjectPlan,
) -> List[Dict[str, Any]]:
    """The SARIF results this project's verdict counts, read where a single scan reads them.

    ``_compute_exit_code`` counts a single scan's actionable findings from the
    SARIF report the scan's own SARIF reporter wrote this run
    (``report_file_written_as``, the ``reports_written`` record the report phase
    leaves on the model), because the reporter serializes every suppression where
    the in-memory model's ``result.suppressions`` is not reliably set. The
    workspace counted from the model (:func:`_extract_run`), so a project's
    workspace verdict and ``ash --source-dir P`` could disagree on a suppressed
    finding. One function supplies the counts and the run carried into the
    unified file, so the two cannot drift from each other.

    The model's results are the fallback: no SARIF report recorded (the report
    phase did not run, or the format was not selected), a recorded name that is
    not a file in the project's ``reports/`` (``confined_report_path``), a link
    where the file would be read (``linked_report_path``: the project's own scan
    already refused a link where its reporter writes, so one found here appeared
    after it, and the model is the honest reading), or a file that cannot be
    read or parsed. The recorded name is this run's by construction: the
    project's orchestrator runs with ``existing_results_path=None``, and a model
    loaded from a file has the record stripped, so the identity check a single
    scan makes for ``--use-existing`` has nothing to guard here.

    The report was written before :func:`_tag_policy_origin_findings` tagged the
    model, so the file's entries are tagged here the same way; otherwise the
    ``policy_scanners_gate`` exclusion would silently stop excluding.

    What is taken from the file is its FIRST run's ``results``, the same rule
    :func:`_extract_run` applies to the model (``SarifReport.merge_sarif_report``
    collapses every scanner into ``runs[0]``; more runs is a shape this code has
    not seen, logged and not silently folded in); reading every run's results
    into one list, as this once did, would have counted a second run's findings
    that the carried run's ``tool`` and ``rules`` say nothing about. A file with
    no run is unusable as a count and falls back to the model, as an unreadable
    one does. The run carried into the unified file is the model's (its ``tool``,
    ``rules`` and ``invocations``) with these results in it: the SARIF reporter
    writes the model's rule table in the model's order and sets each result's
    ``ruleIndex`` to its position there (the rule-index pass in
    ``plugin_modules/ash_builtin/reporters/sarif_reporter.py``), so the indices
    agree; what the reporter changes on the way out (the
    suppressions it serializes, the masking it applied) is what the count must
    see, and is why the file is read at all.
    """
    from automated_security_helper.base.reporter_plugin import confined_report_path

    model_results = list(run.get("results") or []) if run else []
    name = report_file_written_as(results, "sarif")
    if not name:
        return model_results
    reports_dir = project_output / "reports"
    linked = linked_report_path(reports_dir, ["ash.sarif", name])
    if linked is not None:
        ASH_LOGGER.warning(
            f"Project '{project.key}': {linked}; its verdict is counted from the "
            f"scan's own results rather than through the link.",
            extra=NO_MARKUP,
        )
        return model_results
    target = confined_report_path(reports_dir, name)
    if target is None or not target.is_file():
        return model_results
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        ASH_LOGGER.warning(
            f"Project '{project.key}': could not read its SARIF report "
            f"{target.name} to count its verdict ({error_text(error)}); counted "
            f"from the scan's own results instead.",
            extra=NO_MARKUP,
        )
        return model_results
    runs = document.get("runs") if isinstance(document, dict) else None
    if not isinstance(runs, list) or not runs or not isinstance(runs[0], dict):
        ASH_LOGGER.warning(
            f"Project '{project.key}': its SARIF report {target.name} carries no "
            f"run to count its verdict from; counted from the scan's own results "
            f"instead.",
            extra=NO_MARKUP,
        )
        return model_results
    if len(runs) > 1:
        ASH_LOGGER.warning(
            f"Project '{project.key}': its SARIF report {target.name} carries "
            f"{len(runs)} runs; workspace mode expects one per project and counts "
            f"only the first.",
            extra=NO_MARKUP,
        )
    entries: List[Dict[str, Any]] = [
        entry for entry in runs[0].get("results") or [] if isinstance(entry, dict)
    ]
    _tag_policy_origin_entries(entries, project)
    return entries


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
    project's own config, then a fallback.

    True as the fallback, and the reason does not depend on what
    ``AshConfig.fail_on_incomplete_scanners`` defaults to. Step 2 accepts any
    ``bool`` the project's config carries, and every real ``AshConfig`` carries one,
    so step 3 only decides a project for which no config model was available at
    all. In workspace mode that means the orchestrator returned results without a
    config, which is not a state to read as "the operator opted out of the
    completeness gate" -- a project whose config never loaded is exactly the
    project whose scanner statuses are least trustworthy, so the gate stays on.

    That argument is stated without reference to the model's polarity on purpose.
    An earlier version of this docstring argued from the two fallbacks differing,
    and named the model default as ``False``; when that default moved, every clause
    resting on the comparison became false at once and the paragraph invited a
    maintainer to adjudicate a divergence that no longer existed. The two happen to
    agree at present. If the model default moves again, this fallback stays ``True``
    for the reason above rather than for agreement with it.

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


def _scanner_exit_codes(results: Any) -> Dict[str, Optional[int]]:
    """Per-scanner exit code for one project, from the rows the statuses come from.

    A row carries a code only when the scanner produced a target report that said
    what its tool exited with; otherwise ``exit_code`` was never set and its
    ``model_fields_set`` does not name it, which is how a recorded 0 is told from the
    field's default. A row with no recorded integer reads
    ``SCANNER_EXIT_CODE_UNRECORDED``, except a SKIPPED one: SKIPPED is a complete,
    operator-chosen outcome, so its entry reads what the row itself dumps for
    ``exit_code`` (nothing, which the rollup writes as null) and never claims the
    run did not finish.
    """
    statuses = _scanner_statuses(results)
    codes: Dict[str, Optional[int]] = {}
    for name, info in (getattr(results, "scanner_results", None) or {}).items():
        recorded = getattr(info, "exit_code", None)
        was_set = "exit_code" in getattr(info, "model_fields_set", ())
        if was_set and isinstance(recorded, int) and not isinstance(recorded, bool):
            codes[str(name)] = recorded
        elif statuses.get(str(name)) == "SKIPPED":
            codes[str(name)] = None
        else:
            codes[str(name)] = SCANNER_EXIT_CODE_UNRECORDED
    return codes


#: The tools' own output in a project's output tree, which output-formats.md says
#: is not masked: what each scanner wrote, and the converted copies of the source.
_TOOL_OUTPUT_DIRS = frozenset({"scanners", ASH_WORK_DIR_NAME})


def _mask_project_output(
    project_output: Path, values: Set[str], shapes: List[Any]
) -> None:
    """Mask a finished project's output tree with the values every project exposed.

    The results file is read back as a model, masked with ``values`` and
    ``shapes`` and rewritten, so it records the workspace's shapes too. Every
    other file -- the project's own reports, which cannot be re-rendered without
    running its reporters again -- has each value masked in every text form a
    report writes it (``mask_secret_values_in_text``), and then each token of
    ``shapes`` masked as the results file masks them
    (``mask_secret_shapes_in_text``): a value another project knows only by its
    masked form was masked by shape in the results file and left in clear here.
    The tools' own output (``_TOOL_OUTPUT_DIRS``) and links are left alone.
    """
    if not project_output.is_dir():
        return
    results_file = project_output / RESULTS_FILENAME
    for path in sorted(project_output.rglob("*")):
        relative = path.relative_to(project_output)
        if relative.parts[0] in _TOOL_OUTPUT_DIRS:
            continue
        if path.is_symlink() or not path.is_file():
            continue
        # pathlib's ``**`` does not descend into a linked directory, so no file
        # below one is reached here on the ordinary path. A directory that is
        # replaced by a link between the walk and this read would be, and its
        # rewrite would land outside this tree; refused like the link itself,
        # as defence in depth rather than the common case.
        if any(
            (project_output / Path(*relative.parts[: index + 1])).is_symlink()
            for index in range(len(relative.parts) - 1)
        ):
            continue
        if path == results_file:
            _remask_results_file(path, values, shapes)
            continue
        data = path.read_bytes()
        try:
            text, encoding = data.decode("utf-8"), "utf-8"
        except UnicodeDecodeError:
            # Not UTF-8: read byte for byte, so the rewrite changes nothing else.
            text, encoding = data.decode("latin-1"), "latin-1"
        masked = mask_secret_shapes_in_text(
            mask_secret_values_in_text(text, values), shapes
        )
        if masked != text:
            write_text_atomically(path, masked, encoding=encoding)


def _remask_results_file(path: Path, values: Set[str], shapes: List[Any]) -> None:
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    try:
        model = AshAggregatedResults.model_validate_json(
            path.read_text(encoding="utf-8")
        )
    except ValueError as error:
        # A file this run wrote moments ago that no longer parses: mask it as text
        # rather than leave it as it is.
        ASH_LOGGER.warning(f"Could not read {path} to mask it again: {error}")
        text = path.read_text(encoding="utf-8", errors="replace")
        write_text_atomically(
            path,
            mask_secret_shapes_in_text(
                mask_secret_values_in_text(text, values), shapes
            ),
        )
        return
    mask_secrets_in_results(model, values=values, shapes=shapes)
    write_text_atomically(path, model.model_dump_json(indent=2, by_alias=True))


def _scanner_reasons(results: Any, values: Iterable[str] = ()) -> Dict[str, str]:
    """Per-scanner reason for one project's SKIPPED, MISSING and ERROR rows.

    For SKIPPED and MISSING, the row's own skipped_reason or missing_reason,
    whichever its status takes, as the project's results file has it (the
    metrics rebuild has already put its "no reason was recorded" wording on a
    row that had none). For ERROR, which has no reason field, the first error
    the scanner's reports recorded (``recorded_error``), redacted with *values*,
    the project config's environment values: a scanner whose constructor raised
    says so here, where an MCP client reads it. A row with no text to give is
    left out, so the rollup names only what a project's own row says.
    """
    reasons: Dict[str, str] = {}
    for name, info in (getattr(results, "scanner_results", None) or {}).items():
        status = getattr(info, "status", None)
        value = str(getattr(status, "value", status))
        if value == "SKIPPED":
            reason = getattr(info, "skipped_reason", None)
        elif value == "MISSING":
            reason = getattr(info, "missing_reason", None)
        elif value == "ERROR":
            reason = recorded_error(results, str(name), values)
        else:
            continue
        if isinstance(reason, str) and reason:
            reasons[str(name)] = reason
    return reasons


class _AbandonGate:
    """One project's commit-or-abandon decision, taken exactly once.

    The deadline poll abandons an overrunning project and records it FAILED; the
    worker, when its scan returns, writes the project's output. Between the
    poll's read of the clock and its abandon, a worker could pass a plain
    ``is_set()`` check, write real findings, and still be recorded FAILED with
    none. So both sides take the decision under one lock: the worker's
    :meth:`try_commit` wins only while nothing has abandoned the project, and
    the poll's :meth:`set` wins only while nothing has committed it. The loser
    does nothing of its own: an abandoned worker discards what the scan wrote,
    and a poll that finds the project committed leaves it to be collected.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._abandoned = False
        self._committed = False

    def is_set(self) -> bool:
        with self._lock:
            return self._abandoned

    def set(self) -> bool:
        """Abandon the project. False, and nothing changes, once it has committed."""
        with self._lock:
            if self._committed:
                return False
            self._abandoned = True
            return True

    def try_commit(self) -> bool:
        """Claim the write. False, and nothing changes, once the project is abandoned."""
        with self._lock:
            if self._abandoned:
                return False
            self._committed = True
            return True


def _claim_commit(abandoned: Any) -> bool:
    """Claim the right to write this project's output; False once it is abandoned.

    An :class:`_AbandonGate` takes the decision under its lock. A caller that
    still hands in a plain event gets the old read, which cannot exclude the
    abandon racing the write.
    """
    claim = getattr(abandoned, "try_commit", None)
    if claim is not None:
        return bool(claim())
    return not abandoned.is_set()


def _close_never_started(future: Any, gate: Any, key: str) -> bool:
    """Decide a queued project the closing pool found not started.

    True: record it FAILED as never started. False: it started in the moment
    between the pool's read of it as queued and this call, and its worker has
    already claimed its write, so its own outcome stands and the next pass
    collects it.

    Cancel first: a queued future can still be cancelled, and that stops it
    starting after it has been reported failed. A future the cancel could not
    stop had started in that window (the start_lock gap the pool's read cannot
    see through). The gate then decides as it does for every other worker: an
    abandon that takes it marks the worker's output for discard when the scan
    returns, and a worker that has already committed keeps its outcome, so the
    never-started verdict is not written over a project that ran. Both shapes
    of the window are logged; before this the sweep cancelled, abandoned and
    recorded the project in that order with no read of what the cancel found.
    """
    cancelled = future.cancel()
    if not gate.set():
        ASH_LOGGER.warning(
            f"Project '{key}' started as the pool was closing and committed its "
            f"results before it could be abandoned; its own outcome stands and is "
            f"collected, not recorded as never started."
        )
        return False
    if not cancelled:
        ASH_LOGGER.warning(
            f"Project '{key}' started as the pool was closing, after it was read as "
            f"queued; it is abandoned, and the output its scan writes is discarded "
            f"when it returns."
        )
    return True


#: What a project's scan writes under ``projects/<key>/`` that an abandon has to
#: take back: the results file the scan phase saves and the report phase's
#: directory. Named, rather than "everything but the tools' output", because the
#: directory can hold what an operator kept: ``keep_previous_results`` passes
#: through to the project's orchestrator, and an abandon that lands before the
#: scan rewrote the directory would otherwise remove an earlier run's files that
#: were never this run's to remove.
_SCAN_OUTPUT_NAMES = frozenset({RESULTS_FILENAME, "reports"})


def _discard_project_output(project_output: Path) -> None:
    """Remove what a scan wrote under ``projects/<key>/`` before it was abandoned.

    The scan phase writes ``projects/<key>/ash_aggregated_results.json`` on its
    own (``AshAggregatedResults.save_model``), and its report phase writes the
    project's own reports beside it, before ``_scan_one_project`` can see that
    the project was abandoned. Declining the workspace's own write left all of
    that in place: real findings in the project's subtree beside a unified file
    recording the project FAILED with none. Those two names (``_SCAN_OUTPUT_NAMES``)
    are what is removed, and they are removed whatever run wrote them: a
    results file beside a FAILED verdict contradicts it whether this run or an
    earlier one left it, and this run's reporters rewrite the same report names.
    A report an earlier run wrote in a format this run did not select goes with
    the directory; that is the one thing ``keep_previous_results`` kept that an
    abandon does not. Everything else there (the tools' own output,
    ``_TOOL_OUTPUT_DIRS``; a file this run did not write) is left as it was. A
    link at either of the two names is unlinked, never followed: ``Path.unlink``
    removes the link entry and leaves its target, and a results file reached
    through a link would otherwise still read as present beside the FAILED
    verdict. A link at any other name is left alone, as every other write here
    refuses to follow one.
    """
    import shutil

    try:
        entries = list(project_output.iterdir())
    except FileNotFoundError:
        return
    except OSError as error:
        ASH_LOGGER.warning(
            f"Could not list the abandoned project's output {project_output}: "
            f"{error_text(error)}",
            extra=NO_MARKUP,
        )
        return
    for path in entries:
        if path.name not in _SCAN_OUTPUT_NAMES:
            continue
        try:
            if path.is_symlink():
                # Before the directory test, which follows the link: the link
                # entry goes and its target is not touched.
                path.unlink(missing_ok=True)
            elif path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
        except OSError as error:
            ASH_LOGGER.warning(
                f"Could not remove the abandoned project's output {path}: "
                f"{error_text(error)}",
                extra=NO_MARKUP,
            )


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
    cancel_events: Optional[Mapping[str, Event]] = None,
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
            Defaults to the built-in reporters plus those of the workspace's
            plugin modules (:func:`workspace_plugin_modules`), and of those only
            the ones this run's plugin modules load
            (:func:`workspace_reporter_classes`); injected only by tests.
        cancel_events: Per project key, the event that cancels that project's
            scan; see "Stopping a project, or the whole run, from outside" in the
            module docstring. A project with no event gets one the pool builds,
            chained to the submitting thread's ambient scan-wide event, so it
            still stops on abandon and on a scan-wide cancel; what only
            caller-given events add is that the pool waits for their stops at
            shutdown. None, as the CLI passes, for none.

    Returns:
        The unified results path, the process exit code, and the payload. A run
        whose projects gave exit 0 or 2 gives exit 1 when the report step left a
        report or the manifest unwritten; the results file then records 1 too.

    Raises:
        WorkspaceDefinitionError: When an enabled reporter declares itself
            unsupported in workspace mode. Raised rather than recorded because
            nothing has been scanned yet -- that is an exit-4 refusal, not a
            project failure.
        InvalidBaseRefError: When ``changed_files_only`` is set and
            ``validate_base_ref`` refuses ``base_ref``. Checked once, before any
            project runs or any output is written, rather than failing each
            project with the same error.
        ReportPathRefused: When a selected reporter's file name is not a file
            name, before any project is scanned (``ReportPathLinkRefused``, its
            subclass, when a path a workspace report would be written to is a
            link: before any project is scanned, or when the report step starts if
            the link appeared during the scan).
        ScanCancelled: When run inside a cancel scope whose event is set, at the
            first check after it was set: before the projects start, before the
            unified results file is written, or before the workspace reports.
    """
    if settings.changed_files_only:
        validate_base_ref(settings.base_ref)

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

    # The pool is sized down to the project count -- no point starting four
    # workers for two projects -- but the payload records the *configured* bound,
    # because that is the knob the operator set. How much parallelism actually
    # happened is min(that, len(projects)), and both numbers are in the payload.
    configured_bound = max(1, settings.max_parallel_projects)
    # Before the pool, never inside it: the registry is process-global and the
    # first project to touch it would otherwise freeze the scanner set for all.
    prewarm_plugin_registry(plan, settings)
    if reporter_classes is None:
        # The workspace's own reporters, as each project's engine selects its own:
        # the registry also holds whatever another scan in this process imported.
        # Both filters apply: the run's plugin modules (scan_plugin_filter), and
        # what this run's own imports registered (workspace_reporter_classes).
        # Both reads run in one entry of the run's scope, which is why the
        # second filter's source is the function that holds none of its own.
        from automated_security_helper.plugins import ash_plugin_manager
        from automated_security_helper.plugins.loader import scan_plugin_filter

        with _masked_modules_of_run(plan):
            loaded = _reporter_classes_of_run(plan, settings)
            reporter_classes = [
                cls
                for cls in ash_plugin_manager.plugin_modules(
                    "reporter",
                    scan_plugin_filter(workspace_plugin_modules(plan, settings)),
                )
                if cls in loaded
            ]
    refuse_unresolvable_scanner_selection(plan, settings)

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
        # than incidental: the reporter set read from a cold registry is whatever
        # was resolvable at that moment, a subset of what prewarm registers, and
        # the check would then pass or refuse on the wrong set.
        #
        # Gated on the report phase because a reporter that cannot produce a
        # workspace artefact is not an operator's problem until they ask for one.
        refusing = unsupported_reporter_names(
            plan,
            output_dir,
            output_formats=settings.output_formats,
            python_based_plugins_only=settings.python_based_plugins_only,
            reporter_classes=reporter_classes,
            plugin_modules=workspace_plugin_modules(plan, settings),
        )
        if refusing:
            raise WorkspaceDefinitionError(
                f"reporter(s) {', '.join(refusing)} declare that they cannot "
                f"produce a correct report in workspace mode, and are enabled. "
                f"Nothing was scanned. Disable them, narrow --output-format to "
                f"exclude them, or scan the projects separately."
            )
        # Here for the same two reasons: a link at a workspace report path
        # refuses the run before any project is scanned. With the workspace's
        # plugin modules, as the two calls beside it pass them: without them only
        # the built-in reporters were built here, and a plugin-module reporter's
        # bad file name, collision or link was refused only after every project
        # had been scanned.
        refuse_linked_workspace_report_paths(
            plan,
            output_dir,
            output_formats=settings.output_formats,
            python_based_plugins_only=settings.python_based_plugins_only,
            reporter_classes=reporter_classes,
            plugin_modules=workspace_plugin_modules(plan, settings),
        )

    raise_if_cancelled()
    bound = min(configured_bound, len(active) or 1)
    ASH_LOGGER.info(
        f"Scanning {len(active)} workspace project(s), "
        f"up to {bound} at a time"
        + (
            f", {_budget_token(settings.project_timeout)} per project"
            if settings.project_timeout
            else ""
        )
    )

    collected.update(
        _run_projects(
            active,
            settings,
            orchestrator_factory,
            bound,
            cancel_events,
            # One naming of the run's plugin modules for every project's engine,
            # the map the prewarm named them by.
            module_names=workspace_module_names(plan),
        )
    )

    # Stopped while the projects ran: nothing below runs, so a stopped run writes
    # no unified results and no workspace reports.
    raise_if_cancelled()
    # A value one project's secret finding exposed is masked in every project's
    # output, not only its own: one password used by two services is reported in
    # one and passed on a command line in the other. Each project's scan masked
    # its outputs against its own findings, so they are masked again here with
    # the values all of them exposed, and the runs before they are spooled.
    exposed = set().union(*(entry.secret_values for entry in collected.values()))
    shapes = shapes_of_secret_values(exposed)
    if exposed:
        for project in plan.projects:
            run = collected.get(project.key)
            if run is None:
                continue
            if (
                run.outcome.status is not ProjectRunStatus.COMPLETED
                and not run.output_written
            ):
                # Nothing of this run's is under projects/<key> for a project the
                # workspace never handed to an orchestrator (an unchanged skip, a
                # link refusal, a config refused before the scan, never started)
                # or whose abandoned worker has not come back. What is there is a
                # previous run's output, or still being written; rewriting it
                # gave stale results a fresh mtime and nothing else. A project
                # whose scan raised after an orchestrator existed is NOT skipped:
                # the reports it saved before the raise are this run's and quote
                # the other projects' values. An abandoned project whose worker
                # did come back has only the tools' own output there (the worker
                # discarded the reports with the results), which the walk below
                # leaves alone as it does for every finished project.
                continue
            project_output = _project_output_dir(settings, project)
            # The same refusal the scan made before writing there. A project whose
            # projects/<key> was a link was recorded FAILED without a scan, and is
            # in `collected` all the same; walking and rewriting through that link
            # would write into whatever it points at.
            try:
                refuse_linked_output_dir(settings.output_dir, project_output)
            except OutputDirLinkRefused as refusal:
                ASH_LOGGER.warning(
                    f"Project '{project.key}': its output is not re-masked: {refusal}",
                    extra=NO_MARKUP,
                )
                continue
            _mask_project_output(project_output, exposed, shapes)

    for project in plan.projects:
        run = collected.get(project.key)
        if run is None:
            continue
        if exposed and run.run is not None:
            mask_secret_values_in_tree(run.run, exposed, shapes)
        aggregator.add(run.outcome, run.run, project)
        # Drop the run as soon as it is spooled: peak memory is what makes a
        # 20-project workspace viable.
        run.run = None

    exit_code = int(workspace_exit_code(entry.outcome for entry in collected.values()))
    wall_clock = time.monotonic() - started
    from automated_security_helper.plugins.loader import combined_plugin_load_errors

    results_path = aggregator.write(
        exit_code=exit_code,
        wall_clock_seconds=wall_clock,
        max_parallel_projects=configured_bound,
        project_timeout=settings.project_timeout,
        secret_value_shapes=shapes,
        # In workspace-file order, as the projects are written.
        plugin_load_errors=combined_plugin_load_errors(
            collected[project.key].plugin_load_errors
            for project in plan.projects
            if project.key in collected
        ),
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
        raise_if_cancelled()
        report_outcome = emit_workspace_reports(
            plan=plan,
            output_dir=output_dir,
            results_path=results_path,
            output_formats=settings.output_formats,
            python_based_plugins_only=settings.python_based_plugins_only,
            ignore_suppressions=settings.ignore_suppressions,
            reporter_classes=reporter_classes,
            plugin_modules=workspace_plugin_modules(plan, settings),
        )
        # After the results file, so the file is restamped when this changes the
        # answer: it records "the process status this run exited with", and a
        # failed report step is part of what that status answers for.
        reported_exit_code = exit_code_after_report_step(exit_code, report_outcome)
        if reported_exit_code != exit_code:
            ASH_LOGGER.error(
                "The workspace report step did not write everything it owed, so "
                f"the run exits {reported_exit_code} rather than {exit_code}. "
                f"See {MANIFEST_FILENAME} in the reports directory."
            )
            exit_code = reported_exit_code
            payload = payload.model_copy(update={"exit_code": exit_code})
            if not rewrite_workspace_block(results_path, payload):
                ASH_LOGGER.warning(
                    f"Could not record exit code {exit_code} in {results_path}; "
                    "the file still holds the code the projects alone gave."
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
    cancel_events: Optional[Mapping[str, Event]] = None,
    module_names: Optional[Mapping[str, str]] = None,
) -> Dict[str, _ProjectRun]:
    """Run the active projects on a bounded pool, honouring per-project deadlines.

    ``module_names`` is the run-wide naming of the plugin modules
    (:func:`workspace_module_names`), handed to every project's engine.

    The deadline is measured from when a project *starts*, which is why the worker
    publishes its own start time. Measuring from submission would time out a
    project that had merely been waiting for a slot.

    Every project runs inside a cancel scope, entered in its worker because a
    pool thread does not inherit the caller's context. The scope's event is
    the caller's where ``cancel_events`` gave one, linked on the submitting
    thread to its ambient scan-wide event; a project without one gets an
    event the pool builds with that ambient event as its parent
    (:func:`link_parent`), so a cancel of the whole scan reaches every
    project either way. A project's ``ScanCancelled`` is its own outcome,
    FAILED, and not the workspace's: caught here, it does not escape and
    stop the other projects.

    A project given up on at its ``project_timeout``, or because no worker is
    left to run it, has its effective event set, so it stops the way a
    cancelled scan stops, child processes included. With ``cancel_events``
    its worker is given ``_ABANDONED_STOP_GRACE_SECONDS`` to come back
    before it counts among the workers lost to abandoned projects, which decide
    when a queued project is given up on (a scan that never checks its scope
    held its slot uncounted, and the queued projects waited on it without any
    bound), and the pool is waited for before this returns. That wait ends when
    the stops have ended, not at ``project_timeout`` or the server's scan
    timeout: a scan that never checks its scope holds the return until its
    tool's SIGTERM-then-SIGKILL has run its course (``SANDBOX_STOP_GRACE_SECONDS``),
    and a worker wedged outside any child stop holds it for as long as it runs.
    What the grace bounds is when the projects still queued are given up on,
    not the return. That is what lets the MCP server hold the workspace's
    max_concurrent_scans slot and its projects' directories until the scanners
    have stopped: ``project_timeout`` comes from the scanned workspace's own
    config, and without the wait a short one would leave scanners running
    outside both server limits. Without ``cancel_events`` (the CLI) an
    abandoned worker is still stopped through its pool-built event, but the
    pool is shut down without waiting for the stop to finish, so the
    workspace result is not delayed by it; the interpreter joins the worker
    at exit (see the module docstring), and until its scan next checks its
    scope the worker's slot stays occupied, which is what the give-up
    bookkeeping below still counts.
    """
    if not active:
        return {}

    collected: Dict[str, _ProjectRun] = {}
    start_times: Dict[str, float] = {}
    start_lock = Lock()
    # Set when a project is abandoned, so its worker can tell it has been given
    # up on and stop before writing output the workspace has already contradicted;
    # the worker claims its write through the same gate, so the two cannot cross.
    abandoned: Dict[str, _AbandonGate] = {
        project.key: _AbandonGate() for project in active
    }

    # Each project's effective cancel event, built here on the submitting
    # thread because the pool worker that enters its scope has no ambient
    # context for cancel_scope's own linking to read (link_parent's
    # docstring). A caller-given event is linked to this thread's ambient
    # scan-wide event; a project without one gets its own, constructed with
    # that ambient event as its parent, so abandoning it stops it the way a
    # cancelled scan stops and a scan-wide cancel reaches it. Before this, a
    # project without a caller event could not be stopped at all.
    ambient = current_cancel_event()
    events: Dict[str, Event] = {}
    for project in active:
        event = (cancel_events or {}).get(project.key)
        if event is None:
            event = CancelEvent(parent=ambient)
        else:
            link_parent(event, ambient)
        events[project.key] = event

    def _cancel(project: ProjectPlan) -> None:
        """Stop a project given up on, through its effective event."""
        events[project.key].set()

    # The futures of the projects abandoned at their budget, each still running
    # when it was given up on. Read back after the pool is done with them: the
    # worker's own result is FAILED too and is not what is recorded, but it
    # carries the secret values the project's findings exposed, which the
    # workspace masking set needs whatever the verdict.
    abandoned_futures: Dict[Future, ProjectPlan] = {}

    def worker(project: ProjectPlan) -> _ProjectRun:
        with start_lock:
            start_times[project.key] = time.monotonic()
        cancel_event = events[project.key]
        began = time.monotonic()
        try:
            with cancel_scope(cancel_event):
                # A project cancelled while it waited for a worker does not start.
                raise_if_cancelled()
                return _scan_one_project(
                    project,
                    settings,
                    orchestrator_factory,
                    abandoned[project.key],
                    module_names=module_names,
                )
        except ScanCancelled:
            # Only the cancel before the scan reaches _scan_one_project lands
            # here (a project cancelled while it waited for a worker); a cancel
            # inside the scan returns its outcome from there, where whether the
            # output was handed is known. Nothing was written: output_written
            # keeps its default.
            ASH_LOGGER.info(
                f"Project '{project.key}' stopped: it was cancelled before it started"
            )
            return _failed_outcome(
                project,
                settings,
                "cancelled",
                duration_seconds=time.monotonic() - began,
            )

    pool = ThreadPoolExecutor(max_workers=bound)
    try:
        futures: Dict[Future, ProjectPlan] = {
            # With a copy of this context: the scanned-tree scope the run entered
            # (utils/subprocess_utils.scanning_tree) is per context, and a pool
            # thread would otherwise start without it.
            pool.submit(contextvars.copy_context().run, worker, project): project
            for project in active
        }
        pending: Set[Future] = set(futures)
        timeout = settings.project_timeout
        # The clock (time.monotonic) at which each abandoned project's worker was
        # told to stop. Each such worker is a pool slot that does not come back
        # until the project's scan next checks its scope, or its tool's stop
        # (SIGTERM, the subprocess layer's grace, SIGKILL) returns it. Every
        # abandoned worker, with or without a caller-given event, is given
        # _ABANDONED_STOP_GRACE_SECONDS for that to free the slot before the
        # slot is counted lost: the stop reaches the child the same way on both
        # paths, and counting a slot lost in the poll after the abandon, as the
        # path without events once did, failed every queued project as never
        # started while the stop was about to free it. A worker still busy after
        # the grace is between scope checks and may never check again, and not
        # counting it left the projects still queued waiting on it without any
        # bound. Read from the futures each poll, not kept as a tally, so a
        # worker whose project has since ended counts as free: a project still
        # queued then starts on it instead of being failed as never started. The
        # same clock read feeds the wait after the loop and the note a worker
        # that never came back is given, so the grace they name is the one spent.
        abandoned_at: Dict[Future, float] = {}

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
                        project, settings, f"{type(exc).__name__}: {error_text(exc)}"
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
                if future.done():
                    # Finished in the gap between the wait above returning and
                    # this read of the clock. Its result stands and the next poll
                    # collects it; abandoning it here recorded a project that had
                    # completed, and had already written its per-project results,
                    # as FAILED with no findings.
                    continue
                elapsed = now - begin
                if not abandoned[project.key].set():
                    # The worker claimed its write between the clock read above
                    # and this abandon: the scan has finished and its output
                    # stands. Its result is collected at the next pass, as a
                    # future found done above is.
                    continue
                stoppable = (cancel_events or {}).get(project.key) is not None
                ASH_LOGGER.error(
                    f"Project '{project.key}' exceeded its {_budget_token(timeout)} "
                    f"budget after {elapsed:.1f}s and was abandoned. "
                    + (
                        "It is being stopped, the way a cancelled scan stops."
                        if stoppable
                        else "It is being stopped, the way a cancelled scan "
                        "stops; the workspace result does not wait for its "
                        "stop to finish."
                    )
                )
                abandoned_futures[future] = project
                abandoned_at[future] = now
                _cancel(project)
                collected[project.key] = _failed_outcome(
                    project,
                    settings,
                    f"timed out after {elapsed:.1f}s, exceeding the "
                    f"{_budget_token(timeout)} project_timeout budget",
                    duration_seconds=elapsed,
                )
                pending.discard(future)

            # Strictly later than the abandon's own clock read, so a worker is
            # never counted held in the poll that abandoned it; one grace for
            # every abandoned worker, whatever stops it (see the constant).
            held = [
                future
                for future, since in abandoned_at.items()
                if not future.done() and now - since > _ABANDONED_STOP_GRACE_SECONDS
            ]
            if len(held) < bound:
                continue

            # Every worker is held by an abandoned project whose stop has not
            # freed it, so nothing still queued can start and waiting would block
            # on threads that may not be coming back. Without this the timeout bounded nothing
            # whenever the bound was smaller than the project count -- measured,
            # three projects at bound 1 with a 1s budget ran past 12s -- which
            # is precisely the shape the default bound of 4 produces for a
            # workspace of five.
            # A future that is running has started: its worker took the slot a
            # stop just freed and has not yet recorded its start time (the
            # start_lock window). It is judged against its budget on a later poll,
            # not failed as never started while it runs.
            never_started = [
                future
                for future in list(pending)
                if start_times.get(futures[future].key) is None and not future.running()
            ]
            for future in never_started:
                project = futures[future]
                # Cancel, then abandon through the gate; a worker that started in
                # the window and already claimed its write keeps its outcome, and
                # the next pass collects it (_close_never_started).
                if not _close_never_started(
                    future, abandoned[project.key], project.key
                ):
                    continue
                _cancel(project)
                ASH_LOGGER.error(
                    f"Project '{project.key}' never started: all {bound} worker "
                    f"slot(s) are held by project(s) abandoned at the "
                    f"{_budget_token(timeout)} project_timeout whose stop has not "
                    f"freed them, and a worker that has not stopped is not "
                    f"waited for. Raise max_parallel_projects, raise "
                    f"project_timeout, or scan the slow project separately."
                )
                collected[project.key] = _failed_outcome(
                    project,
                    settings,
                    f"never started: all {bound} worker slot(s) were held by "
                    f"project(s) that exceeded the {_budget_token(timeout)} "
                    f"project_timeout",
                )
                pending.discard(future)
            if pending:
                # Anything left here has started and is inside its budget, so it
                # is still worth waiting for.
                continue
            break

        # Every abandoned worker was told to stop. Give the stops what is left of
        # one bounded grace, measured from each abandon's own clock read, so a
        # worker that comes back inside it brings the secret values its
        # project's findings exposed into the masking set. Bounded, never open:
        # a worker still busy after it is between scope checks. The wait is the
        # same with or without caller-given events; what differs is the shutdown
        # below. With events it then waits for every stop, so a worker that was
        # still busy here is joined there all the same (the caller holds its
        # limits until the stops are done). Without events the shutdown does not
        # wait, so this grace is the only time such a worker is given to bring
        # its values back; one that has not come back by then is named as
        # unmasked, with the grace it was given.
        stopping = [future for future in abandoned_futures if not future.done()]
        if stopping:
            now = time.monotonic()
            remaining = max(
                _ABANDONED_STOP_GRACE_SECONDS - (now - abandoned_at[future])
                for future in stopping
            )
            if remaining > 0:
                wait(stopping, timeout=remaining)
    finally:
        # Without caller-given events, wait=False: an abandoned worker is told
        # to stop through its pool-built event, but its scan may not check its
        # scope for a while, and waiting past the grace above would delay the
        # workspace result; the interpreter still joins it at exit (see the
        # module docstring). With them every worker was told to stop, and the
        # caller holds its limits until the stops are done.
        pool.shutdown(wait=cancel_events is not None)

    _read_back_abandoned_workers(abandoned_futures, collected, abandoned_at)
    return collected


def _read_back_abandoned_workers(
    abandoned_futures: Mapping[Future, ProjectPlan],
    collected: Dict[str, _ProjectRun],
    abandoned_at: Mapping[Future, float],
) -> None:
    """Carry what an abandoned worker brought back onto its recorded outcome.

    The verdict recorded at the abandon stands. A worker that came back brought
    the secret values its project's findings exposed, so the recorded run takes
    them and the workspace masking covers the other projects' output with them.
    It left only the tools' own output under ``projects/<key>`` (it discarded
    the results and reports that contradicted the verdict), which the masking
    leaves alone for every project. A worker that has not come back (its scan is
    between scope checks, and the pool did not wait for it) is named on the
    project's error, which the unified results and the workspace reports show,
    and in the log, with the time it was given, read from *abandoned_at*'s clock:
    the values its findings exposed are not in the masking set and its own output
    was not masked for the other projects' secrets. Loud, because a report that
    silently kept a value in clear is what the masking exists to prevent.
    """
    now = time.monotonic()
    for future, project in abandoned_futures.items():
        recorded = collected.get(project.key)
        if recorded is None:
            continue
        if future.done() and not future.cancelled():
            try:
                late = future.result()
            except Exception as exc:  # noqa: BLE001 -- the worker already guards
                # The worker guards every raise of the scan and its reduction, so
                # a raise reaching here came from the worker itself. Said, not
                # skipped: what this worker brought back is lost the same way a
                # worker that never came back loses it, and the docstring's
                # promise is that such a loss is loud.
                note = (
                    f"its worker raised {type(exc).__name__}: {error_text(exc)}; "
                    "the secret values its findings exposed did not reach the "
                    "workspace masking set and its own output was not masked for "
                    "the other projects' secrets"
                )
                ASH_LOGGER.error(f"Project '{project.key}': {note}.")
                recorded.outcome.error = (
                    f"{recorded.outcome.error or 'abandoned'}; {note}"
                )
                continue
            recorded.secret_values = set(late.secret_values)
            recorded.output_written = late.output_written
            continue
        # The grace this worker was in fact given, not the one configured: the
        # note used to say "2s" whatever had elapsed, which on the path without
        # caller-given events was often milliseconds.
        given = now - abandoned_at.get(future, now)
        note = (
            f"its scan had not stopped {given:.1f}s after it was abandoned, so the "
            "secret values its findings exposed did not reach the workspace masking "
            "set and its own output was not masked for the other projects' secrets"
        )
        ASH_LOGGER.error(f"Project '{project.key}': {note}.")
        recorded.outcome.error = f"{recorded.outcome.error or 'abandoned'}; {note}"


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
