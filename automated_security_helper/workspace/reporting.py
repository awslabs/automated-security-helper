# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Emit the workspace-level reports, and account for the ones deliberately not emitted.

Why this module exists
----------------------
Phase 2a scanned N projects and wrote a unified ``ash_aggregated_results.json``,
and stopped there. It emitted no workspace-level *report* at all, and the reason
was one line in ``github_ghas_reporter``: ``run = sarif.runs[0]``. Against an
N-run SARIF that emits the first project's findings and drops the rest -- no
exception, no warning, a smaller file nobody can tell is incomplete. Shipping a
workspace-level report step meant first making it impossible for a reporter to
fail that way quietly.

So each reporter declares a
:class:`~automated_security_helper.base.reporter_plugin.ReporterWorkspaceBehaviour`
and this module holds it to the declaration. It never asks a reporter to handle a
shape the reporter has not said it handles, and it never lets a withheld artefact
be merely absent -- every reporter, including the ones that deliberately produce
nothing here, gets an entry in ``reports/workspace-reports.json`` saying what
happened and where the alternative is.

The manifest is the point, not a convenience
-------------------------------------------
An operator who ran a workspace scan and looks for ``reports/ash.cdx.json`` will
not find one, because an SBOM for N independently versioned deliverables is N
SBOMs. Without the manifest that absence is indistinguishable from a bug, from a
disabled reporter, and from a reporter that crashed. With it, the answer is a
machine-readable list of the N per-project files that replace it -- and a list of
which of those actually exist on disk, because a per-project report is written by
that project's own report phase and a project can be skipped or can fail.

Why the whole model is loaded back, giving up Phase 2a's streaming bound
----------------------------------------------------------------------
``WorkspaceAggregator`` streams: it holds one project's SARIF at a time, so peak
memory is bounded by ``max_parallel_projects`` rather than by project count. A
merged reporter cannot work that way -- ``csv``, ``html`` and the rest need every
finding at once, and there is no streaming reporter API to give them.

So this reads the unified file back as one ``AshAggregatedResults``. Three things
make that acceptable rather than a regression:

* It happens after every scan has finished, so the *scanning* peak -- which is
  the one that scales with concurrency -- is unchanged. The two peaks do not add.
* The peak here is the size of a file the operator already has on disk and that
  any consumer of it faces anyway.
* Reading the written file rather than keeping a parallel in-memory model means
  the workspace reports cannot disagree with the results file. An in-memory model
  would have been cheaper and would have introduced a second source of truth.

Reporter enablement comes from the default config, not from any project's
------------------------------------------------------------------------
There is no workspace-level config in this phase; it arrives in Phase 3. So which
reporters run *here* is decided by ASH's default config plus ``--output-format``.

The consequence is worth stating plainly: a project that disables ``html`` still
gets a workspace-level ``html`` report. That is defensible -- the workspace
artefact is a workspace-level concern, and a project's config governs its own
``projects/<key>/reports/`` subtree, which is untouched by this module -- but it
is a real limitation and not a design anyone would choose from scratch. The
alternative considered was to withhold a merged artefact whenever any project
disabled that reporter, which was rejected because it makes one project's config
silently govern a workspace-level output, and because the operator has no way to
express the override until Phase 3 gives them one.

Failure modes and known limitations
-----------------------------------
* A reporter that raises is recorded in the manifest with its error and does not
  stop the others. One broken reporter must not cost an operator every other
  report. The failure does *not* fail the run: a reporter error is not a finding,
  and ``execute_workspace``'s exit code is a verdict about code under scan.
  The same holds for a reporter that cannot be constructed (its entry carries
  the construction error, under its declared name), for a unified results file
  that cannot be loaded (every reporter that needed it is recorded failed), and
  for a link that appears at a report's name after the pre-write check (that
  reporter is recorded failed and the others still write). A reporter whose
  ``is_python_only`` raises is excluded as not Python-only, as ``ReportPhase``
  excludes it, rather than taking the step down. Error text goes through
  ``error_text`` and ``traceback_text`` (utils/error_text.py), so a value a
  config read from the environment is not written into the manifest or the log.
* A cancel request (``core/cancellation``) is honored before each reporter runs
  and before the manifest is written, as ``ReportPhase`` honors one before each
  of its reporters: the step raises ``ScanCancelled`` and runs no further
  reporter. What a reporter wrote before the cancel stays on disk, as the
  results file does; the manifest is not written, so nothing claims the step
  completed.
* Two selected reporters with one configured name (a plugin bug) get two
  manifest entries, the second keyed as ``<name> (<class name>)``, and their
  artefacts and failures are recorded under the same keys. Keying both on the
  name lost one reporter's record while both wrote files.
* An ``UNSUPPORTED`` reporter *does* fail the run, at
  ``WorkspaceExitCode.INTERNAL_ERROR``, and only when the run would otherwise
  have succeeded. It does not override exit 2 or 3: those are verdicts about the
  code under scan, and a reporter that cannot render them is not one. No
  reporter shipped here declares ``UNSUPPORTED``; the path is
  built and tested so the enum member is a mechanism rather than a comment.
* A reporter that ASH's default config leaves off (the AWS reporters) is listed
  with the per-project artefacts that exist on disk, whatever its workspace
  behaviour, because the projects' own configs decided whether it ran and every
  project's report phase writes the reporters that project enables. Only the
  projects that wrote one are listed, and none is reported missing: the step
  cannot tell a project whose config left the reporter off from one whose report
  phase failed. With no artefact on disk it is recorded as ``skipped: disabled``.
  A reporter ``--output-format`` or ``--python-based-plugins-only`` excluded is
  recorded by that reason first: the exclusion applied to every project's own
  report phase too, so a per-project artefact on disk would be an earlier run's
  and is not listed as this run's.
* A symlink or directory junction at ``reports/``, at a file a workspace-level
  reporter writes there, or at the manifest refuses the run with
  ``ReportPathLinkRefused`` (exit 1), before any project is scanned
  (:func:`refuse_linked_workspace_report_paths`). One that appears while the
  projects are scanned is refused when the report step starts, before anything is
  written; the results file has been written by then, with the exit code the
  projects gave. A selected reporter's file name that is not a file name, for a
  per-project reporter too, refuses the run before any project is scanned
  (``ReportPathRefused``). See utils/report_path_links.py.
* The per-project artefact paths in the manifest are derived from each reporter's
  configured ``extension``, which is how ``ReportPhase`` derives the filename it
  writes. A reporter that writes extra files under its own steam -- as
  ``unused_suppressions`` does with its markdown companion -- is not fully
  enumerated. Enumerating by globbing the directory instead was rejected: it
  would attribute any stale file left by a previous run to a reporter that did
  not write it.
* Nothing here validates that a merged reporter's output is well-formed for its
  format. That belongs to the reporter, and the per-reporter tests in
  ``tests/unit/workspace/test_workspace_reporting.py`` assert content rather than
  only existence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from automated_security_helper.base.plugin_config import (
    declared_config_model,
    plugin_config_key,
    section_enabled,
)
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
    off_host_reporter_refused,
    reporter_classes_for_run,
    reporter_companion_file_names,
    reporter_file_name,
    reporter_file_names,
    reporter_matches_requested_formats,
    write_report_file,
)
from automated_security_helper.core.cancellation import raise_if_cancelled
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceExitCode,
)
from automated_security_helper.utils.error_text import error_text, traceback_text
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.report_path_links import (
    ensure_reports_dir,
    refuse_colliding_report_names,
    refuse_linked_report_paths,
    refuse_report_names_outside,
)
from automated_security_helper.workspace.plan import WorkspacePlan

#: Where workspace-level reports land, mirroring the ``reports/`` directory a
#: single-directory scan produces so existing tooling needs no new path.
REPORTS_DIR_NAME = "reports"

#: The account of what every reporter did. Named for what it is rather than
#: ``manifest.json``, so it is obvious in a directory listing beside the reports.
MANIFEST_FILENAME = "workspace-reports.json"

#: The subtree holding each project's own complete output, as
#: ``execution.PROJECTS_DIR_NAME`` writes it. Duplicated as a literal rather than
#: imported, because importing ``execution`` here would make the dependency
#: circular once ``execution`` calls this module.
PROJECTS_DIR_NAME = "projects"

#: Why a reporter was not considered at workspace level. Recorded distinctly
#: rather than collapsed into one "skipped" flag, because each sends the operator
#: somewhere different: to the config, to ``--output-format``, or to the
#: reporter's own missing dependencies.
SKIP_DISABLED = "disabled"
SKIP_UNSATISFIED_DEPENDENCIES = "dependencies-unsatisfied"
SKIP_NOT_REQUESTED = "not-in-requested-output-formats"
SKIP_NOT_PYTHON_ONLY = "non-python-dependencies-excluded"

#: Behaviours that produce a workspace-level artefact. ``WORKSPACE_SCOPED`` is in
#: the set but is not a merge, which is why ``covers_projects`` is recorded
#: separately in the manifest.
_EMITTING_BEHAVIOURS = frozenset(
    {
        ReporterWorkspaceBehaviour.MERGED,
        ReporterWorkspaceBehaviour.WORKSPACE_SCOPED,
    }
)


@dataclass
class WorkspaceReportOutcome:
    """What the workspace-level report step produced, and what it refused to."""

    #: None when the manifest could not be written; the reason is logged.
    manifest_path: Optional[Path]
    workspace_artifacts: Dict[str, Path] = field(default_factory=dict)
    per_project_reporters: Tuple[str, ...] = ()
    unsupported_reporters: Tuple[str, ...] = ()
    failed_reporters: Dict[str, str] = field(default_factory=dict)

    @property
    def refused(self) -> bool:
        """Whether any enabled reporter declared itself unusable at this level.

        Separate from ``failed_reporters`` on purpose. A reporter that raised is
        a bug in that reporter; a reporter that declared ``UNSUPPORTED`` is a
        correct statement that the operator has asked for something the format
        cannot express. The two are told apart in the log and the manifest; both
        end the run non-zero, through :func:`exit_code_after_report_step`.
        """
        return bool(self.unsupported_reporters)

    @property
    def failed(self) -> bool:
        """Whether the report step left something unwritten that it owed.

        A reporter that raised, a report file that could not be written, a
        manifest that could not be written, or a reporter that refused. A
        reporter that returned no content, a per-project reporter whose artefact
        is missing, and a reporter that was not considered are not failures of
        this step: the manifest records each, and none owed a workspace file.
        """
        return bool(self.failed_reporters) or self.manifest_path is None or self.refused


def exit_code_after_report_step(exit_code: int, outcome: WorkspaceReportOutcome) -> int:
    """The workspace exit code once the report step has run.

    A report step that left something unwritten (see
    :attr:`WorkspaceReportOutcome.failed`) turns a run that would exit 0 or 2 into
    ``INTERNAL_ERROR``: the operator asked for reports and some did not arrive,
    and exit 0 would tell a CI gate they did. It ranks where
    ``workspace_exit_code`` ranks an incomplete project, above findings (2) and
    below an invalid project configuration (3); 4 means nothing was scanned. The
    failure stays in the manifest and the log.

    Args:
        exit_code: What ``workspace_exit_code`` derived from the projects.
        outcome: What the report step produced.

    Returns:
        *exit_code*, or ``INTERNAL_ERROR`` when it was ``SUCCESS`` or
        ``ACTIONABLE_FINDINGS`` and the step failed.
    """
    if outcome.failed and exit_code in (
        int(WorkspaceExitCode.SUCCESS),
        int(WorkspaceExitCode.ACTIONABLE_FINDINGS),
    ):
        return int(WorkspaceExitCode.INTERNAL_ERROR)
    return exit_code


def _reporter_name(instance: ReporterPluginBase) -> str:
    """The reporter's configured name, or its class name as a last resort.

    The configured name is what an operator writes in ``--output-format`` and in
    config, so it is what the manifest is keyed on. A reporter whose config
    somehow carries no name still has to appear in the manifest -- being
    unnameable is not a reason to go unrecorded.
    """
    name = getattr(getattr(instance, "config", None), "name", None)
    return str(name) if name else instance.__class__.__name__


def _report_filename(instance: ReporterPluginBase) -> str:
    """The filename ``ReportPhase`` would give this reporter's output.

    The same function ``ReportPhase._execute_phase`` names its file with, including
    the ``ash.txt`` fallback for a reporter that declares no extension, so a
    workspace-level report and a per-project one are never named differently for
    the same reporter.
    """
    return reporter_file_name(instance)


def _disabled_by_config(instance: ReporterPluginBase) -> bool:
    """Whether the operator turned this reporter off. Cheap, and never touches IO."""
    config = getattr(instance, "config", None)
    return config is not None and getattr(config, "enabled", True) is False


def _dependencies_unsatisfied(instance: ReporterPluginBase) -> bool:
    """Whether the reporter's own dependency check refuses.

    Separate from :func:`_disabled_by_config`, and reported as a different reason,
    because the two send the operator somewhere different: the config, versus
    credentials or an install. Conflating them told an operator with no AWS
    credentials that they had disabled the reporter.

    Also separate because this one performs IO. ``SecurityHubReporter`` and
    ``BedrockSummaryReporter`` call AWS inside it, so it must not be on any path
    that runs before a scan -- see :func:`unsupported_reporter_names`.
    """
    try:
        return not instance.validate_plugin_dependencies()
    except Exception as exc:  # noqa: BLE001 -- a broken check must not stop the step
        ASH_LOGGER.warning(
            f"Reporter {_reporter_name(instance)} raised while validating its "
            f"dependencies and is treated as unavailable: {exc}"
        )
        return True


def _matches_requested_formats(
    instance: ReporterPluginBase, output_formats: Sequence[str]
) -> bool:
    """Whether ``--output-format`` selected this reporter.

    An empty request means every reporter, matching ``ReportPhase``: an operator
    who passed no ``--output-format`` asked for the default set, not for nothing.

    Delegates so that this and ``ReportPhase`` cannot answer differently. They
    used to hold two copies of the comparison and both had the same bug -- they
    matched the requested format names against each reporter's ``extension``,
    which only coincides with the name for four of the fifteen reporters. A
    workspace scan asked for ``markdown`` produced no markdown report and said
    nothing about it, exactly as a single-directory scan did.
    """
    return reporter_matches_requested_formats(instance, output_formats)


def _load_workspace_model(results_path: Path):
    """The unified results, as the model reporters expect.

    Validated through ``AshAggregatedResults`` rather than handed round as a dict
    because every reporter is written against the model -- and because validation
    is the check that the hand-assembled JSON the aggregator streams is actually
    well formed. A malformed unified file surfaces here, before any reporter
    reads half of it.
    """
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    return AshAggregatedResults.model_validate_json(
        results_path.read_text(encoding="utf-8")
    )


def _projects_with_a_completed_run(results_path: Path) -> Optional[set]:
    """The keys of the projects the results file records a completed scan for.

    ``None`` when the file says nothing about projects (an older or foreign
    results file), so the caller judges by the filesystem alone. Read with
    ``json`` rather than through the model, so a per-project-only run never
    materialises the whole model for one field.

    Why: a per-project report present on disk belongs to this run only when this
    run's scan of that project completed. Nothing clears ``projects/`` between
    runs into one output directory, so a file an earlier run wrote was listed as
    this run's for a project this run skipped, or that failed before its own
    output was set up.
    """
    try:
        document = json.loads(Path(results_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    workspace = document.get("workspace") if isinstance(document, dict) else None
    projects = workspace.get("projects") if isinstance(workspace, dict) else None
    if not isinstance(projects, list):
        return None
    return {
        entry.get("project")
        for entry in projects
        if isinstance(entry, dict)
        and entry.get("status") == ProjectRunStatus.COMPLETED.value
    }


def _per_project_artifacts(
    plan: WorkspacePlan,
    output_dir: Path,
    filename: str,
    completed: Optional[set] = None,
) -> Tuple[List[Dict[str, str]], List[str]]:
    """Where a per-project reporter's N artefacts are, and which are missing.

    Every project in the plan is listed, including skipped ones, so that a
    consumer reading the manifest sees the full set the operator asked for. The
    missing list is what distinguishes "this project was skipped" from "the
    manifest is pointing at nothing", which an operator would otherwise have to
    resolve by checking the filesystem by hand.

    *completed*, when given, is the set of project keys this run's scan
    completed (:func:`_projects_with_a_completed_run`): a project outside it is
    missing whatever is on disk, because a file there is an earlier run's.
    """
    entries: List[Dict[str, str]] = []
    missing: List[str] = []
    for project in plan.projects:
        relative = (
            Path(PROJECTS_DIR_NAME) / project.key / REPORTS_DIR_NAME / filename
        ).as_posix()
        entries.append({"project": project.key, "path": relative})
        ran = completed is None or project.key in completed
        if not ran or not (output_dir / relative).is_file():
            missing.append(project.key)
    return entries, missing


def _present_per_project_artifacts(
    plan: WorkspacePlan,
    output_dir: Path,
    filename: str,
    completed: Optional[set] = None,
) -> List[Dict[str, str]]:
    """The per-project artefacts of ``filename`` that this run wrote, in plan order."""
    entries, missing = _per_project_artifacts(plan, output_dir, filename, completed)
    return [entry for entry in entries if entry["project"] not in missing]


def _remove_previous_workspace_reports(reports_dir: Path, selection) -> None:
    """Remove the workspace-level files of every reporter in *selection* that an
    earlier run into this output directory left in *reports_dir*.

    Nothing clears ``reports/`` before this step, so a file a previous run wrote
    for a reporter that this run skips, that raises, or that returns nothing
    stayed beside this run's manifest and read as this run's. Only a regular
    file at a reporter's own name is removed; a link there was refused before
    this ran.

    The previous run's manifest goes with them. This step writes its own
    manifest last, so a step that stops before then (a cancel before a reporter,
    a link that appeared at a report's name after the pre-write check) would
    otherwise leave the old manifest in place, naming as its artefacts the files
    removed here.
    """
    for instance, _behaviour, _skipped in selection:
        for name in reporter_file_names(instance):
            _remove_previous_file(reports_dir, name)
    _remove_previous_file(reports_dir, MANIFEST_FILENAME)


def _remove_previous_file(reports_dir: Path, name: str) -> None:
    """Remove the regular file at *name* in *reports_dir*, if that is what is there."""
    path = reports_dir / name
    if Path(name).name != name or path.is_symlink() or not path.is_file():
        return
    try:
        path.unlink()
    except OSError as exc:
        ASH_LOGGER.warning(f"Could not remove the previous run's report {path}: {exc}")


def _default_reporter_classes(plugin_modules: Sequence[str] = ()) -> List[type]:
    """The reporter classes of this workspace run's own plugin modules.

    ``execution.prewarm_plugin_registry`` has already resolved the ``reporter``
    type before any project ran, so this reads a warm, complete registry rather
    than triggering discovery here -- which under the old lazy behaviour would
    have made the resolved set depend on when it was first asked for.

    Only ASH's built-ins and ``plugin_modules`` (the modules the workspace's
    projects and command line name, ``execution.workspace_plugin_modules``): the
    registry is process-wide, and a reporter another run's module registered in
    it was built, checked and run here (``reporter_classes_for_run``).
    """
    return reporter_classes_for_run(plugin_modules)


@dataclass
class _ConstructionFailure:
    """Why a reporter never became an instance, and whether that owed a report.

    ``skipped`` is the ``SKIP_*`` reason the step would have given the reporter
    had it been built: ``SKIP_DISABLED`` when its config section turns it off
    (or an off-host reporter is refused), ``SKIP_NOT_REQUESTED`` when
    ``--output-format`` names other reporters. ``None`` means the step would
    have run it, so the failure is the step's: the operator asked for its report
    and nothing could be built to write one. A reporter nobody asked for, or
    that the default config leaves off (the AWS reporters, a plugin's), is
    recorded in the manifest and does not fail the run: before this, a disabled
    reporter raising in ``__init__`` turned a run with ``--output-format sarif``
    into exit 1 after every project was scanned, where ``ash --source-dir`` on
    the same project passed.
    """

    error: str
    skipped: Optional[str]


def _construction_skip_reason(
    reporter_class: type, key: str, config: Any, output_formats: Sequence[str]
) -> Optional[str]:
    """The ``SKIP_*`` reason a reporter that could not be built would have had.

    Decided from the two inputs that need no instance: the config section the
    default config holds for the reporter (a dict, read as ``section_enabled``
    reads every section), or, for a reporter the default config has no section
    for (a plugin's), the defaults its declared config model states, which is
    what the base builds such a reporter on; and the requested formats, matched
    as ``reporter_matches_requested_formats`` matches them, by the configured
    name. ``--python-based-plugins-only`` asks the instance, so under that flag
    an unbuildable reporter counts as one the step would have run.
    """
    enabled = True
    name: Any = None
    if config is not None:
        enabled = section_enabled(config) and not off_host_reporter_refused(
            reporter_class, config
        )
        name = (
            config.get("name")
            if isinstance(config, Mapping)
            else getattr(config, "name", None)
        )
    else:
        declared = declared_config_model(reporter_class, ReporterPluginConfigBase)
        field = (getattr(declared, "model_fields", None) or {}).get("enabled")
        if field is not None and getattr(field, "default", True) is False:
            enabled = False
    if not enabled:
        return SKIP_DISABLED
    if isinstance(output_formats, str):
        output_formats = (output_formats,) if output_formats else ()
    if not output_formats:
        return None
    requested = {str(getattr(fmt, "value", fmt)) for fmt in output_formats}
    return None if str(name or key) in requested else SKIP_NOT_REQUESTED


def _build_instance(
    reporter_class: type,
    context,
    config_lookup,
    construction_failures: Optional[Dict[str, _ConstructionFailure]] = None,
    output_formats: Sequence[str] = (),
) -> Optional[ReporterPluginBase]:
    """Construct *reporter_class*, or record why it could not be.

    A failure is logged and, when *construction_failures* is given, recorded
    there under the reporter's declared name (``plugin_config_key``), so the
    manifest can carry an entry for a reporter that never became an instance.
    Before this the reporter was absent from the manifest and from
    ``failed_reporters`` alike, the silence the manifest exists to prevent.
    Whether the failure fails the step is decided here too
    (:class:`_ConstructionFailure`), from *output_formats* and the config.

    The name and the config are read once, before the constructor: a
    ``plugin_config_key`` that raises is recorded under the class name instead
    of escaping from the handler and taking the step down with no manifest.
    """
    plugin_name = getattr(reporter_class, "__name__", "Unknown")
    key = plugin_name
    config = None
    try:
        key = plugin_config_key(reporter_class)
        config = config_lookup(key)
        return reporter_class(context=context, config=config)
    except Exception as exc:  # noqa: BLE001 -- mirrors ReportPhase's tolerance
        described = f"{type(exc).__name__}: {error_text(exc)}"
        ASH_LOGGER.error(
            f"Could not construct reporter {plugin_name} for workspace-level "
            f"reporting: {described}"
        )
        if construction_failures is not None:
            construction_failures[key] = _ConstructionFailure(
                error=f"the reporter could not be constructed: {described}",
                skipped=_construction_skip_reason(
                    reporter_class, key, config, output_formats
                ),
            )
        return None


def _is_python_only(instance: ReporterPluginBase, name: str) -> bool:
    """``instance.is_python_only()``, read as ``ReportPhase`` reads it.

    A reporter whose check raises is excluded under ``--python-based-plugins-only``
    rather than taking the whole step down: the flag asks for the reporters known
    to need nothing beyond Python, and one that cannot answer is not known to.
    """
    try:
        return bool(instance.is_python_only())
    except Exception as exc:  # noqa: BLE001 -- a broken check must not break the step
        ASH_LOGGER.warning(
            f"Reporter {name} raised while reporting whether it is Python-only and "
            f"is excluded under --python-based-plugins-only: {error_text(exc)}"
        )
        return False


def _declared_behaviour(reporter_class: type, name: str) -> ReporterWorkspaceBehaviour:
    """The behaviour *reporter_class* declares, as a member of the enum.

    ``workspace_behaviour`` is a ClassVar nothing enforces, so a reporter can
    declare it as a plain string. A string naming a member (``"merged"``, or the
    member's name in any case) is read as that member. Anything else is read as
    UNSUPPORTED, with the declaration named in the log: this step never asks a
    reporter to handle a shape it has not said it handles, and a declaration ASH
    cannot read says nothing. Before this, a string reached ``behaviour.value``
    in the manifest entry and took the whole report step down.
    """
    declared = getattr(
        reporter_class, "workspace_behaviour", ReporterWorkspaceBehaviour.PER_PROJECT
    )
    if isinstance(declared, ReporterWorkspaceBehaviour):
        return declared
    if isinstance(declared, str):
        for member in ReporterWorkspaceBehaviour:
            if declared == member.value or declared.lower() == member.name.lower():
                return member
    ASH_LOGGER.error(
        f"Reporter {name} declares workspace_behaviour {declared!r}, which is not "
        f"a ReporterWorkspaceBehaviour; it is treated as unsupported in workspace "
        f"mode until the declaration is fixed."
    )
    return ReporterWorkspaceBehaviour.UNSUPPORTED


def _selected_reporters(
    *,
    context,
    config_lookup,
    output_formats: Sequence[str],
    python_based_plugins_only: bool,
    reporter_classes: Optional[Sequence[type]],
    check_dependencies: bool = True,
    plugin_modules: Sequence[str] = (),
    construction_failures: Optional[Dict[str, _ConstructionFailure]] = None,
):
    """Every constructible reporter, with its declared behaviour and skip reason.

    Yields ``(instance, behaviour, skipped)``. ``skipped`` is ``None`` for a
    reporter that will run, and otherwise one of the ``SKIP_*`` reasons -- yielded
    rather than filtered out, because the manifest has to account for those too.
    Filtering them here is what made six of the nineteen shipped reporters absent
    from a real run's manifest with nothing to say why. A reporter that cannot be
    constructed yields nothing and is recorded in *construction_failures* when
    the caller passes a dict (:func:`_build_instance`).

    The reasons are decided in the order the operator's own switches apply:
    ``--python-based-plugins-only`` and ``--output-format`` first, because they
    excluded the reporter from every project's report phase too, and the default
    config's ``enabled`` after them. Deciding "disabled" first listed a reporter
    the formats excluded as considered, with an earlier run's per-project files
    as this run's.

    One place, because two callers need exactly the same selection and a
    divergence between them would be invisible: :func:`unsupported_reporter_names`
    refuses a run *before* any project is scanned, and
    :func:`emit_workspace_reports` accounts for the same set *after*. If the
    pre-flight checked a different set than the report step, a reporter could
    pass the gate and then refuse -- at which point the results file on disk and
    the process exit status would disagree about the same run, with no rule for
    which one a consumer should believe.
    """
    classes = (
        list(reporter_classes)
        if reporter_classes is not None
        else _default_reporter_classes(plugin_modules)
    )
    for reporter_class in classes:
        instance = _build_instance(
            reporter_class,
            context,
            config_lookup,
            construction_failures,
            output_formats=output_formats,
        )
        if instance is None:
            continue
        name = _reporter_name(instance)
        behaviour = _declared_behaviour(reporter_class, name)

        # Each reason is reported distinctly rather than collapsed into "skipped",
        # because they route the operator to different knobs: disabled means edit
        # the config, not-requested means widen --output-format, and unavailable
        # means the reporter's own dependencies are unsatisfied.
        #
        # The dependency check is last, and only for a reporter that produces an
        # artefact at workspace level: it can contact a remote service (the AWS
        # reporters call STS or DescribeHub), and a reporter this step does not
        # run -- not requested, or per-project, whose check its own project's
        # scan made -- is not checked here.
        skipped: Optional[str] = None
        if python_based_plugins_only and not _is_python_only(instance, name):
            skipped = SKIP_NOT_PYTHON_ONLY
        if skipped is None and not _matches_requested_formats(instance, output_formats):
            skipped = SKIP_NOT_REQUESTED
        if skipped is None and (
            _disabled_by_config(instance)
            or off_host_reporter_refused(
                reporter_class, config_lookup(plugin_config_key(reporter_class))
            )
        ):
            skipped = SKIP_DISABLED
        if (
            skipped is None
            and check_dependencies
            and behaviour in _EMITTING_BEHAVIOURS
            and _dependencies_unsatisfied(instance)
        ):
            skipped = SKIP_UNSATISFIED_DEPENDENCIES

        if skipped is not None:
            ASH_LOGGER.debug(
                f"Reporter {name} not considered at workspace level: {skipped}"
            )
        yield instance, behaviour, skipped


def _workspace_context(
    workspace_root: str, output_dir: Path, ignore_suppressions: bool = False
):
    """The plugin context and config-lookup workspace-level reporters are built with.

    The config is ASH's default, because no workspace-level config exists in this
    phase. See "Reporter enablement" in the module docstring for what that means
    and what was rejected.
    """
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    config = AshConfig()
    context = PluginContext(
        source_dir=Path(workspace_root),
        output_dir=Path(output_dir),
        config=config,
        ignore_suppressions=ignore_suppressions,
    )

    def config_lookup(plugin_name: str):
        try:
            return config.get_plugin_config(
                plugin_type="reporter", plugin_name=plugin_name
            )
        except Exception:  # noqa: BLE001 -- an unknown reporter takes its default
            return None

    return context, config_lookup


def _workspace_report_file_names(selection) -> List[str]:
    """Every file the workspace report step writes in ``reports/``.

    The files of each reporter that will produce a workspace-level artefact, as the
    reporter names them, and the manifest. ``selection`` is what
    :func:`_selected_reporters` yields.
    """
    names: List[str] = []
    for instance, behaviour, skipped in selection:
        if skipped is None and behaviour in _EMITTING_BEHAVIOURS:
            names.extend(reporter_file_names(instance))
    names.append(MANIFEST_FILENAME)
    return names


def _workspace_report_main_names(selection, every_behaviour: bool = False) -> List[str]:
    """The report file (``ash.<extension>``) of each reporter that will emit one.

    With ``every_behaviour``, of every selected reporter, including those that
    write only in each project's own ``reports/``.
    """
    return [
        reporter_file_name(instance)
        for instance, behaviour, skipped in selection
        if skipped is None and (every_behaviour or behaviour in _EMITTING_BEHAVIOURS)
    ]


def _workspace_report_companion_names(
    selection, every_behaviour: bool = False
) -> List[Tuple[str, str]]:
    """``(reporter, name)`` for each file such a reporter writes beside its report."""
    return [
        (_reporter_name(instance), name)
        for instance, behaviour, skipped in selection
        if skipped is None and (every_behaviour or behaviour in _EMITTING_BEHAVIOURS)
        for name in reporter_companion_file_names(instance)
    ]


def _workspace_report_writers(
    selection, every_behaviour: bool = False
) -> List[Tuple[str, Tuple[str, ...]]]:
    """``(who, names)`` for each reporter that will write, as ``refuse_colliding_report_names`` takes them.

    Of the reporters that emit a workspace-level file, with the manifest the step
    writes beside them; with ``every_behaviour``, of every selected reporter, as
    each project's report phase runs them, and without the manifest.
    """
    writers: List[Tuple[str, Tuple[str, ...]]] = [
        (f"the {_reporter_name(instance)} reporter", reporter_file_names(instance))
        for instance, behaviour, skipped in selection
        if skipped is None and (every_behaviour or behaviour in _EMITTING_BEHAVIOURS)
    ]
    if not every_behaviour:
        writers.append(("the workspace report step", (MANIFEST_FILENAME,)))
    return writers


def refuse_linked_workspace_report_paths(
    plan: WorkspacePlan,
    output_dir: Path,
    *,
    output_formats: Sequence[str] = (),
    python_based_plugins_only: bool = False,
    reporter_classes: Optional[Sequence[type]] = None,
    plugin_modules: Sequence[str] = (),
) -> None:
    """Refuse the run when a workspace report would be written through a link.

    *plugin_modules* are the workspace's plugin modules, as
    :func:`unsupported_reporter_names` and :func:`emit_workspace_reports` take
    them. They matter only when *reporter_classes* is unset: then only ASH's
    built-in reporters and those of these modules are built here. The
    production caller passes the run's reporter classes, which already hold the
    plugin modules' reporters (``execution.workspace_reporter_classes``), and
    the selection reads those; it is given here as well so the three callers of
    :func:`_selected_reporters` build the same set whichever way they are called.

    Run before any project is scanned, for the reason
    :func:`unsupported_reporter_names` is: nothing gets scanned or written, so the
    results file and the exit status cannot disagree. Nothing clears the
    workspace's ``reports/`` before the report step, so a link there now is a link
    there then. :func:`emit_workspace_reports` checks again before it writes. No
    dependency validation, for the same reason as there, so the links checked are
    at the files of every enabled reporter that writes a workspace-level file.

    The file names of every selected reporter are checked as well, those that
    write only in each project's ``reports/`` included: a name that is not a file
    in a reports directory would otherwise be refused by each project's report
    phase after that project was scanned. Like the rest of this step, the names
    come from ASH's default config and ``--output-format``, not from a project's
    config (see "Reporter enablement" above), so narrowing ``--output-format`` is
    how to leave such a reporter out.

    Raises:
        ReportPathRefused: A selected reporter's file name is not a file name.
        ReportNameCollision: Two selected reporters would write the same file, or
            a workspace-level reporter would write the manifest's.
        ReportPathLinkRefused: ``reports/``, one of those reporters' files or the
            manifest is a symlink or a directory junction.
    """
    context, config_lookup = _workspace_context(plan.workspace_root, Path(output_dir))
    selection = list(
        _selected_reporters(
            context=context,
            config_lookup=config_lookup,
            output_formats=output_formats,
            python_based_plugins_only=python_based_plugins_only,
            reporter_classes=reporter_classes,
            check_dependencies=False,
            plugin_modules=plugin_modules,
        )
    )
    refuse_report_names_outside(
        Path(output_dir) / REPORTS_DIR_NAME,
        _workspace_report_main_names(selection, every_behaviour=True),
        _workspace_report_companion_names(selection, every_behaviour=True),
    )
    # Two reporters writing one file: in each project's reports/, where every
    # selected reporter writes, and in the workspace's, beside the manifest.
    refuse_colliding_report_names(
        Path(output_dir) / REPORTS_DIR_NAME,
        _workspace_report_writers(selection, every_behaviour=True),
    )
    refuse_colliding_report_names(
        Path(output_dir) / REPORTS_DIR_NAME, _workspace_report_writers(selection)
    )
    refuse_linked_report_paths(
        Path(output_dir) / REPORTS_DIR_NAME, _workspace_report_file_names(selection)
    )


def unsupported_reporter_names(
    plan: WorkspacePlan,
    output_dir: Path,
    *,
    output_formats: Sequence[str] = (),
    python_based_plugins_only: bool = False,
    reporter_classes: Optional[Sequence[type]] = None,
    plugin_modules: Sequence[str] = (),
) -> Tuple[str, ...]:
    """Enabled reporters that declare they cannot work in workspace mode.

    Answered from declarations and config alone -- no model, no results file, no
    scan, and deliberately no dependency validation.

    That last exclusion is not an optimisation. The AWS reporters call AWS inside
    ``validate_plugin_dependencies`` (Security Hub ``DescribeHub``, the others
    STS), so validating here would put live API calls on the path *before every
    workspace scan* -- latency and log noise on a run they cannot affect.
    :func:`emit_workspace_reports` checks dependencies only for a reporter that
    emits a workspace-level artefact, so an enabled ``UNSUPPORTED`` reporter is
    refused here and recorded as unsupported there, whether or not its
    dependencies are satisfied: whether the format can express a workspace does
    not depend on a credential being present.

    Why a pre-flight at all:

    An operator who has enabled a reporter that cannot produce a correct artefact
    for a workspace should be told before ASH spends the scan, not after. Failing
    at the end would also put the results file and the process exit status in
    conflict, because ``WorkspaceAggregator.write`` records the exit code *into*
    the file: a reporting refusal discovered afterwards could only be surfaced by
    exiting with a status the file does not contain. Refusing up front means
    nothing is scanned and nothing is written, so the two cannot disagree -- the
    same argument ``models.workspace`` makes for keeping exit 4 distinct from
    exit 2.

    Returns:
        The configured names, in registry order. Empty is the normal case: no
        reporter shipped in this repository declares ``UNSUPPORTED``.
    """
    context, config_lookup = _workspace_context(plan.workspace_root, Path(output_dir))
    return tuple(
        _reporter_name(instance)
        for instance, behaviour, skipped in _selected_reporters(
            context=context,
            config_lookup=config_lookup,
            output_formats=output_formats,
            python_based_plugins_only=python_based_plugins_only,
            reporter_classes=reporter_classes,
            check_dependencies=False,
            plugin_modules=plugin_modules,
        )
        # ``skipped is None`` is what makes disabling the documented way out
        # actually work: a reporter the operator turned off must not refuse a run
        # it is not part of.
        if skipped is None and behaviour is ReporterWorkspaceBehaviour.UNSUPPORTED
    )


def emit_workspace_reports(
    plan: WorkspacePlan,
    output_dir: Path,
    results_path: Path,
    *,
    output_formats: Sequence[str] = (),
    python_based_plugins_only: bool = False,
    ignore_suppressions: bool = False,
    reporter_classes: Optional[Sequence[type]] = None,
    plugin_modules: Sequence[str] = (),
) -> WorkspaceReportOutcome:
    """Run the workspace-level report step and write the manifest.

    Args:
        plan: The resolved workspace plan. Supplies the project list the manifest
            enumerates, and the workspace root the reporters are rooted at.
        output_dir: The workspace output directory -- the parent of both
            ``reports/`` and ``projects/``.
        results_path: The unified ``ash_aggregated_results.json`` the aggregator
            wrote. Read back rather than passed as a model; see the module
            docstring.
        output_formats: Format names the operator asked for, as ``ExportFormat``
            values. Empty means all. Not extensions -- see
            :func:`_matches_requested_formats`.
        python_based_plugins_only: Excludes reporters with non-Python
            dependencies, matching ``--python-based-plugins-only``.
        ignore_suppressions: Threaded onto the plugin context so a reporter that
            reads it sees the same value the projects' scans did.
        reporter_classes: Injected only by tests. Production callers take the
            registry, which ``prewarm_plugin_registry`` has already resolved.
        plugin_modules: The plugin modules this workspace run names
            (``execution.workspace_plugin_modules``). With ``reporter_classes``
            unset, only ASH's built-in reporters and those of these modules are
            considered.

    Returns:
        What was written, what was withheld, and what refused. The caller passes
        it to :func:`exit_code_after_report_step`; nothing here calls
        ``sys.exit``.

    Raises:
        ReportPathRefused: A file name a reporter here would write is not a file
            name. Nothing is written.
        ReportNameCollision: Two reporters here, or a reporter and the manifest,
            would write the same file. Nothing is written.
        ReportPathLinkRefused: ``reports/``, a file a reporter here would write or
            the manifest is a link, checked before any reporter runs. Nothing is
            written. A link that appears at a reporter's file after that check
            is recorded against that reporter instead, and the manifest is still
            written; one at the manifest's own name raises when it is written.
        ScanCancelled: The scan was cancelled before a reporter ran or before the
            manifest was written. Reports already written stay; no manifest.
    """
    # The reports and the manifest are written as ASH's other output: never through
    # a link below the output directory (write_report_file replaces each file
    # through fs_guard's atomic write).
    output_dir = Path(output_dir)
    reports_dir = ensure_reports_dir(output_dir / REPORTS_DIR_NAME)

    context, config_lookup = _workspace_context(
        plan.workspace_root, output_dir, ignore_suppressions
    )

    manifest_reporters: Dict[str, Dict[str, Any]] = {}
    artifacts: Dict[str, Path] = {}
    per_project: List[str] = []
    unsupported: List[str] = []
    failures: Dict[str, str] = {}
    construction_failures: Dict[str, _ConstructionFailure] = {}

    # Loaded lazily, so a workspace whose every reporter is per-project never
    # pays the cost of materialising the whole model. A load that fails is
    # remembered, so every reporter that needed the model is recorded failed
    # and the manifest is still written.
    model = None
    model_failure: Optional[str] = None

    selection = list(
        _selected_reporters(
            context=context,
            config_lookup=config_lookup,
            output_formats=output_formats,
            python_based_plugins_only=python_based_plugins_only,
            reporter_classes=reporter_classes,
            plugin_modules=plugin_modules,
            construction_failures=construction_failures,
        )
    )
    # Before any reporter runs and before the manifest: a link that appeared
    # after refuse_linked_workspace_report_paths ran is refused here, with
    # nothing written.
    refuse_report_names_outside(
        reports_dir,
        _workspace_report_main_names(selection),
        _workspace_report_companion_names(selection),
    )
    refuse_colliding_report_names(reports_dir, _workspace_report_writers(selection))
    refuse_linked_report_paths(reports_dir, _workspace_report_file_names(selection))
    # After the refusals, so nothing is removed on a run that writes nothing, and
    # before any reporter writes, so a previous run's file never outlives it.
    _remove_previous_workspace_reports(reports_dir, selection)

    # Which projects this run scanned to completion, read once from the results
    # file on the first per-project reporter that needs it.
    completed_runs: List[Optional[set]] = []

    def completed() -> Optional[set]:
        if not completed_runs:
            completed_runs.append(_projects_with_a_completed_run(Path(results_path)))
        return completed_runs[0]

    for key, failure in construction_failures.items():
        # A reporter that never became an instance still gets its entry, under
        # its declared name. It fails the step only when the step would have run
        # it (the operator asked for its report and nothing could even be built
        # to write one); one the config leaves off or the formats exclude is
        # recorded with that reason, as a built one would be, and fails nothing
        # (_ConstructionFailure).
        manifest_reporters[key] = {
            "behaviour": None,
            "considered": False,
            "covers_projects": False,
            "workspace_artifact": None,
            "per_project_artifacts": [],
            "missing_per_project_artifacts": [],
            "error": failure.error,
        }
        if failure.skipped is not None:
            manifest_reporters[key]["skipped"] = failure.skipped
            ASH_LOGGER.debug(
                f"Reporter {key} could not be constructed and would not have run "
                f"at workspace level ({failure.skipped}); recorded, not a failure."
            )
            continue
        failures[key] = failure.error

    for instance, behaviour, skipped in selection:
        name = _reporter_name(instance)
        # One record per reporter: a second reporter with the same configured
        # name (a plugin bug) is keyed with its class name as well, so neither
        # overwrites the other's entry, artefact or failure.
        key = name
        if key in manifest_reporters:
            key = f"{name} ({instance.__class__.__name__})"
            ASH_LOGGER.warning(
                f"Two selected reporters are named {name!r}; the second is "
                f"recorded as {key!r} in the workspace report manifest."
            )
        filename = _report_filename(instance)
        entry: Dict[str, Any] = {
            "behaviour": behaviour.value,
            "considered": skipped is None,
            "covers_projects": behaviour is ReporterWorkspaceBehaviour.MERGED,
            "workspace_artifact": None,
            "per_project_artifacts": [],
            "missing_per_project_artifacts": [],
        }
        manifest_reporters[key] = entry

        if skipped == SKIP_DISABLED:
            # Disabled by ASH's default config, which is what this step reads, but
            # each project's scan read its own config. A reporter the default
            # leaves off -- the AWS reporters -- may have run in the projects
            # whose config enabled it, whatever its workspace behaviour, so list
            # what they wrote rather than call it disabled. A project with no
            # artefact is not missing one: its config may simply leave the
            # reporter off. No merged artefact exists, so covers_projects is off.
            present = _present_per_project_artifacts(
                plan, output_dir, filename, completed()
            )
            if present:
                per_project.append(key)
                entry["considered"] = True
                entry["covers_projects"] = False
                entry["per_project_artifacts"] = present
                ASH_LOGGER.verbose(
                    f"Reporter {name} is off in the default config but per-project; "
                    f"{len(present)} project(s) wrote its artefact."
                )
                continue

        if skipped is not None:
            # Recorded rather than omitted. Six of the nineteen shipped reporters
            # land here on a default run -- yaml, spdx and the four AWS ones ship
            # disabled -- and an operator asking where their yaml report went deserves an
            # answer rather than silence. Silence is the defect this manifest
            # exists to prevent; only the reason differs from a withheld artefact.
            entry["skipped"] = skipped
            entry["covers_projects"] = False
            continue

        if behaviour is ReporterWorkspaceBehaviour.UNSUPPORTED:
            unsupported.append(key)
            entry["covers_projects"] = False
            entry["error"] = (
                "the reporter declares that it cannot produce a correct artefact "
                "in workspace mode; disable it or scan the projects separately"
            )
            ASH_LOGGER.error(
                f"Reporter {name} declares itself unsupported in workspace mode. "
                f"No report was produced for it, and the workspace run will not "
                f"report success. Disable it, or scan the projects separately."
            )
            continue

        if behaviour is ReporterWorkspaceBehaviour.PER_PROJECT:
            per_project.append(key)
            entries, missing = _per_project_artifacts(
                plan, output_dir, filename, completed()
            )
            entry["per_project_artifacts"] = entries
            entry["missing_per_project_artifacts"] = missing
            ASH_LOGGER.verbose(
                f"Reporter {name} is per-project in workspace mode; "
                f"{len(entries) - len(missing)} of {len(entries)} per-project "
                f"artefact(s) present. No merged artefact is produced."
            )
            if missing:
                ASH_LOGGER.warning(
                    f"Reporter {name} has no artefact for project(s) "
                    f"{', '.join(missing)}. Those projects were skipped, failed, "
                    f"had the reporter disabled, or left it out of their own "
                    f"output_formats."
                )
            continue

        if behaviour not in _EMITTING_BEHAVIOURS:  # pragma: no cover - defensive
            # Unreachable while the enum has four members and the three above are
            # handled. Kept so that adding a fifth fails loudly here rather than
            # silently producing nothing.
            failures[key] = f"unhandled workspace behaviour {behaviour!r}"
            entry["error"] = failures[key]
            entry["covers_projects"] = False
            ASH_LOGGER.error(f"Reporter {name}: {failures[key]}")
            continue

        # As ReportPhase before each of its reporters: a cancelled scan runs no
        # further reporter. Outside any try, so nothing below records it.
        raise_if_cancelled()

        if model is None and model_failure is None:
            try:
                model = _load_workspace_model(Path(results_path))
            except Exception as exc:  # noqa: BLE001 -- the manifest still has to say what happened
                model_failure = (
                    f"the unified results file {Path(results_path).name!r} could "
                    f"not be loaded: {type(exc).__name__}: {error_text(exc)}"
                )
                ASH_LOGGER.error(f"Workspace report step: {model_failure}")
                ASH_LOGGER.debug(f"Results load traceback: {traceback_text(exc)}")
        if model is None:
            # Every reporter that needed the model fails the same way, recorded
            # per reporter so the manifest names each report that did not arrive.
            failures[key] = model_failure or "the unified results could not be loaded"
            entry["error"] = failures[key]
            entry["covers_projects"] = False
            continue

        try:
            content = instance.report(model)
        except Exception as exc:  # noqa: BLE001 -- one reporter must not sink the rest
            failures[key] = f"{type(exc).__name__}: {error_text(exc)}"
            entry["error"] = failures[key]
            entry["covers_projects"] = False
            ASH_LOGGER.error(
                f"Reporter {name} failed at workspace level: {failures[key]}"
            )
            ASH_LOGGER.debug(f"Reporter traceback: {traceback_text(exc)}")
            continue

        if content is None:
            # The contract is a str. None is a reporter that did not return
            # (a missing return, an early exit), not one with nothing to say, so
            # it is a failure like a raise: the operator asked for a report and
            # the reporter produced no answer. Recorded apart from the empty
            # string below, which several reporters legitimately return.
            failures[key] = "the reporter returned None instead of a report"
            entry["error"] = failures[key]
            entry["covers_projects"] = False
            ASH_LOGGER.error(f"Reporter {name}: {failures[key]}")
            continue

        if not content:
            # Not an error: several reporters legitimately return nothing when
            # they have nothing to say. Recorded so that "returned nothing" is
            # distinguishable from "was never run". No artefact covers anything.
            entry["error"] = "the reporter returned no content"
            entry["covers_projects"] = False
            ASH_LOGGER.verbose(f"Reporter {name} returned no content")
            continue

        try:
            target = write_report_file(reports_dir, filename, content)
        except Exception as exc:  # noqa: BLE001 -- one reporter's write must not sink the rest, or the manifest
            # write_report_file returns None for an OSError; anything else (a
            # link that appeared at the file's name after the pre-write check,
            # a reporter returning a non-str, a filesystem error outside
            # OSError) used to abort the step here, with earlier reports written
            # and no manifest to say what happened. Nothing was written for this
            # reporter, so recording it keeps the "nothing through a link" rule.
            failures[key] = (
                f"report file {filename!r} could not be written in {reports_dir}: "
                f"{type(exc).__name__}: {error_text(exc)}"
            )
            entry["error"] = failures[key]
            entry["covers_projects"] = False
            ASH_LOGGER.error(f"Reporter {name}: {failures[key]}")
            ASH_LOGGER.debug(f"Reporter write traceback: {traceback_text(exc)}")
            continue
        if target is None:
            failures[key] = (
                f"report file {filename!r} could not be written in {reports_dir}"
            )
            entry["error"] = failures[key]
            entry["covers_projects"] = False
            ASH_LOGGER.error(f"Reporter {name}: {failures[key]}")
            continue
        artifacts[key] = target
        entry["workspace_artifact"] = target.relative_to(output_dir).as_posix()
        ASH_LOGGER.info(f"Writing workspace {name} report to {target}")

    # Before the manifest, as before each reporter: a manifest written after a
    # cancel would say the step completed.
    raise_if_cancelled()
    manifest_path = write_report_file(
        reports_dir,
        MANIFEST_FILENAME,
        json.dumps(
            {
                "workspace_file": plan.workspace_file,
                "workspace_root": plan.workspace_root,
                "projects": [project.key for project in plan.projects],
                "reporters": manifest_reporters,
            },
            indent=2,
        ),
    )

    return WorkspaceReportOutcome(
        manifest_path=manifest_path,
        workspace_artifacts=artifacts,
        per_project_reporters=tuple(per_project),
        unsupported_reporters=tuple(unsupported),
        failed_reporters=failures,
    )
