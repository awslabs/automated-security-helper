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
* An ``UNSUPPORTED`` reporter *does* fail the run, at
  ``WorkspaceExitCode.INTERNAL_ERROR``, and only when the run would otherwise
  have succeeded. It does not override exit 2 or 3, for the reason recorded in
  ``models.workspace``: a finding is a certainty and must not be suppressed by
  anything weaker. No reporter shipped here declares ``UNSUPPORTED``; the path is
  built and tested so the enum member is a mechanism rather than a comment.
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
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.utils.log import ASH_LOGGER
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

    manifest_path: Path
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
        cannot express. The first is logged, the second changes the exit code.
        """
        return bool(self.unsupported_reporters)


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

    Mirrors ``ReportPhase._execute_phase`` exactly, including its ``ash.txt``
    fallback for a reporter that declares no extension, so a workspace-level
    report and a per-project one are never named differently for the same
    reporter.
    """
    extension = getattr(getattr(instance, "config", None), "extension", None)
    return f"ash.{extension}" if extension else "ash.txt"


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
    """
    if not output_formats:
        return True
    extension = getattr(getattr(instance, "config", None), "extension", None)
    return extension in output_formats


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


def _per_project_artifacts(
    plan: WorkspacePlan, output_dir: Path, filename: str
) -> Tuple[List[Dict[str, str]], List[str]]:
    """Where a per-project reporter's N artefacts are, and which are missing.

    Every project in the plan is listed, including skipped ones, so that a
    consumer reading the manifest sees the full set the operator asked for. The
    missing list is what distinguishes "this project was skipped" from "the
    manifest is pointing at nothing", which an operator would otherwise have to
    resolve by checking the filesystem by hand.
    """
    entries: List[Dict[str, str]] = []
    missing: List[str] = []
    for project in plan.projects:
        relative = (
            Path(PROJECTS_DIR_NAME) / project.key / REPORTS_DIR_NAME / filename
        ).as_posix()
        entries.append({"project": project.key, "path": relative})
        if not (output_dir / relative).is_file():
            missing.append(project.key)
    return entries, missing


def _default_reporter_classes() -> List[type]:
    """Every reporter class the plugin registry resolved.

    ``execution.prewarm_plugin_registry`` has already resolved the ``reporter``
    type before any project ran, so this reads a warm, complete registry rather
    than triggering discovery here -- which under the old lazy behaviour would
    have made the resolved set depend on when it was first asked for.
    """
    from automated_security_helper.plugins import ash_plugin_manager

    return list(ash_plugin_manager.plugin_modules("reporter"))


def _build_instance(
    reporter_class: type, context, config_lookup
) -> Optional[ReporterPluginBase]:
    plugin_name = getattr(reporter_class, "__name__", "Unknown")
    try:
        return reporter_class(
            context=context,
            config=config_lookup(plugin_name.lower()),
        )
    except Exception as exc:  # noqa: BLE001 -- mirrors ReportPhase's tolerance
        ASH_LOGGER.error(
            f"Could not construct reporter {plugin_name} for workspace-level "
            f"reporting: {exc}"
        )
        return None


def _selected_reporters(
    *,
    context,
    config_lookup,
    output_formats: Sequence[str],
    python_based_plugins_only: bool,
    reporter_classes: Optional[Sequence[type]],
    check_dependencies: bool = True,
):
    """Every constructible reporter, with its declared behaviour and skip reason.

    Yields ``(instance, behaviour, skipped)``. ``skipped`` is ``None`` for a
    reporter that will run, and otherwise one of the ``SKIP_*`` reasons -- yielded
    rather than filtered out, because the manifest has to account for those too.
    Filtering them here is what made six of the nineteen shipped reporters absent
    from a real run's manifest with nothing to say why.

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
        else _default_reporter_classes()
    )
    for reporter_class in classes:
        instance = _build_instance(reporter_class, context, config_lookup)
        if instance is None:
            continue
        name = _reporter_name(instance)
        behaviour = getattr(
            reporter_class,
            "workspace_behaviour",
            ReporterWorkspaceBehaviour.PER_PROJECT,
        )

        # Each reason is reported distinctly rather than collapsed into "skipped",
        # because they route the operator to different knobs: disabled means edit
        # the config, not-requested means widen --output-format, and unavailable
        # means the reporter's own dependencies are unsatisfied.
        skipped: Optional[str] = None
        if _disabled_by_config(instance):
            skipped = SKIP_DISABLED
        elif check_dependencies and _dependencies_unsatisfied(instance):
            skipped = SKIP_UNSATISFIED_DEPENDENCIES
        if skipped is None and python_based_plugins_only:
            if not instance.is_python_only():
                skipped = SKIP_NOT_PYTHON_ONLY
        if skipped is None and not _matches_requested_formats(instance, output_formats):
            skipped = SKIP_NOT_REQUESTED

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


def unsupported_reporter_names(
    plan: WorkspacePlan,
    output_dir: Path,
    *,
    output_formats: Sequence[str] = (),
    python_based_plugins_only: bool = False,
    reporter_classes: Optional[Sequence[type]] = None,
) -> Tuple[str, ...]:
    """Enabled reporters that declare they cannot work in workspace mode.

    Answered from declarations and config alone -- no model, no results file, no
    scan, and deliberately no dependency validation.

    That last exclusion is not an optimisation. ``SecurityHubReporter`` and
    ``BedrockSummaryReporter`` call AWS inside
    ``validate_plugin_dependencies``, so validating here would put live API calls
    on the path *before every workspace scan* -- latency and log noise on a run
    they cannot affect, since a reporter whose dependencies are unsatisfied is
    already skipped by :func:`emit_workspace_reports`. It also means the two
    answers differ in one narrow case, on purpose: a reporter that is enabled,
    declares ``UNSUPPORTED``, and has unsatisfied dependencies refuses the run
    here rather than being quietly skipped later. That is the right direction --
    the operator's configuration asks for something the format cannot do, and
    telling them so does not depend on whether an unrelated credential happens to
    be present.

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
        output_formats: Extensions the operator asked for. Empty means all.
        python_based_plugins_only: Excludes reporters with non-Python
            dependencies, matching ``--python-based-plugins-only``.
        ignore_suppressions: Threaded onto the plugin context so a reporter that
            reads it sees the same value the projects' scans did.
        reporter_classes: Injected only by tests. Production callers take the
            registry, which ``prewarm_plugin_registry`` has already resolved.

    Returns:
        What was written, what was withheld, and what refused. The caller folds
        ``refused`` into the exit code; nothing here calls ``sys.exit``.
    """
    output_dir = Path(output_dir)
    reports_dir = output_dir / REPORTS_DIR_NAME
    reports_dir.mkdir(parents=True, exist_ok=True)

    context, config_lookup = _workspace_context(
        plan.workspace_root, output_dir, ignore_suppressions
    )

    manifest_reporters: Dict[str, Dict[str, Any]] = {}
    artifacts: Dict[str, Path] = {}
    per_project: List[str] = []
    unsupported: List[str] = []
    failures: Dict[str, str] = {}

    # Loaded lazily, so a workspace whose every reporter is per-project never
    # pays the cost of materialising the whole model.
    model = None

    for instance, behaviour, skipped in _selected_reporters(
        context=context,
        config_lookup=config_lookup,
        output_formats=output_formats,
        python_based_plugins_only=python_based_plugins_only,
        reporter_classes=reporter_classes,
    ):
        name = _reporter_name(instance)
        filename = _report_filename(instance)
        entry: Dict[str, Any] = {
            "behaviour": behaviour.value,
            "considered": skipped is None,
            "covers_projects": behaviour is ReporterWorkspaceBehaviour.MERGED,
            "workspace_artifact": None,
            "per_project_artifacts": [],
            "missing_per_project_artifacts": [],
        }
        manifest_reporters[name] = entry

        if skipped is not None:
            # Recorded rather than omitted. Six of the nineteen shipped reporters
            # land here on a default run -- yaml and spdx ship disabled, and the
            # four AWS ones report unsatisfied dependencies without credentials --
            # and an operator asking where their yaml report went deserves an
            # answer rather than silence. Silence is the defect this manifest
            # exists to prevent; only the reason differs from a withheld artefact.
            entry["skipped"] = skipped
            entry["covers_projects"] = False
            continue

        if behaviour is ReporterWorkspaceBehaviour.UNSUPPORTED:
            unsupported.append(name)
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
            per_project.append(name)
            entries, missing = _per_project_artifacts(plan, output_dir, filename)
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
                    f"or had the reporter disabled."
                )
            continue

        if behaviour not in _EMITTING_BEHAVIOURS:  # pragma: no cover - defensive
            # Unreachable while the enum has four members and the three above are
            # handled. Kept so that adding a fifth fails loudly here rather than
            # silently producing nothing.
            failures[name] = f"unhandled workspace behaviour {behaviour!r}"
            entry["error"] = failures[name]
            ASH_LOGGER.error(f"Reporter {name}: {failures[name]}")
            continue

        if model is None:
            model = _load_workspace_model(Path(results_path))

        try:
            content = instance.report(model)
        except Exception as exc:  # noqa: BLE001 -- one reporter must not sink the rest
            failures[name] = f"{type(exc).__name__}: {exc}"
            entry["error"] = failures[name]
            ASH_LOGGER.error(f"Reporter {name} failed at workspace level: {exc}")
            ASH_LOGGER.debug(f"Reporter traceback: {traceback.format_exc()}")
            continue

        if not content:
            # Not an error: several reporters legitimately return nothing when
            # they have nothing to say. Recorded so that "returned nothing" is
            # distinguishable from "was never run".
            entry["error"] = "the reporter returned no content"
            ASH_LOGGER.verbose(f"Reporter {name} returned no content")
            continue

        target = reports_dir / filename
        target.write_text(content, encoding="utf-8")
        artifacts[name] = target
        entry["workspace_artifact"] = target.relative_to(output_dir).as_posix()
        ASH_LOGGER.info(f"Writing workspace {name} report to {target}")

    manifest_path = reports_dir / MANIFEST_FILENAME
    manifest_path.write_text(
        json.dumps(
            {
                "workspace_file": plan.workspace_file,
                "workspace_root": plan.workspace_root,
                "projects": [project.key for project in plan.projects],
                "reporters": manifest_reporters,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    return WorkspaceReportOutcome(
        manifest_path=manifest_path,
        workspace_artifacts=artifacts,
        per_project_reporters=tuple(per_project),
        unsupported_reporters=tuple(unsupported),
        failed_reporters=failures,
    )
