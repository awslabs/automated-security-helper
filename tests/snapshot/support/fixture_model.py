# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The canonical snapshot input: a fixture repository and the model ASH builds from it.

Every snapshot of a reporter, of the aggregated results file and of anything else that
renders a scan result starts here, so one set of findings and one set of scanner
statuses is what every surface is asserted against. The fixture data lives in
tests/test_data/snapshot_fixture/ (its README lists every finding and status); ASH's
self-scan ignores that tree (``tests/test_data/**`` in .ash/.ash.yaml ignore_paths).

Why the model is built through ASH's own code and not by hand
-------------------------------------------------------------
A hand-assembled ``AshAggregatedResults`` snapshots what the test author believed the
pipeline produces. Building it through the pipeline snapshots what it does produce, so
a change to aggregation, suppression or metrics shows up in every reporter snapshot
that depends on it. The steps mirror a real ``ash scan``:

1. Each scanner in ``scanner_outputs/scanners.yaml`` becomes the
   ``ScanResultsContainer`` the executor would build for it
   (``ScannerExecutor._execute_scanner``): SARIF sanitized and suppressed, severity
   counts from ``get_severity_metrics_from_sarif``, status from
   ``ScanResultsContainer.determine_status``. Excluded and missing scanners use the
   container factories ``ScanPhase`` uses, plus the ``scanner_results`` row it writes.
2. Every container goes through ``ScanResultProcessor.process_container``.
3. The report-phase preamble from ``ScanExecutionEngine.execute_phases``: a final
   ``apply_suppressions_to_sarif`` over the merged SARIF, then
   ``populate_metrics_from_unified_source``. :func:`build_fixture_model` returns the
   model at this point, which is what reporters receive.
4. :func:`finalize_fixture_model` applies what happens after the report phase: the
   ``finally`` block that stamps ``summary_stats`` start, end and duration and
   re-populates metrics. That is the state ``ash_aggregated_results.json`` is written
   from.

The workspace variants run ``workspace.execution.execute_workspace`` for real over
tests/test_data/snapshot_fixture/workspace, resolving the plan with
``resolve_workspace``. Only the per-project orchestrator is replaced, by one whose
``execute_scan`` returns that project's model from steps 1-4, which is the seam
``execute_workspace`` exposes for exactly this. The unified file is then loaded the way
``workspace.reporting`` loads it for the merged reporters.

What is pinned, and how
-----------------------
Time is pinned at the source rather than masked afterwards: :func:`pin_clock` swaps the
module-level ``datetime`` of every module that stamps "now" into a result for
:class:`FrozenDatetime`, and replaces ``uuid.uuid4`` with a counter. Scanner start and
end times and durations come from the manifest. ``time.monotonic`` in the workspace
executor is pinned so project durations and the wall clock are zero. What cannot be
pinned at the source is the ASH version: ``AshAggregatedResults``'s default SARIF run
calls ``get_ash_version()`` when the class body executes, so the version is left real
and the shared normalizer masks it everywhere as ``<ASH_VERSION>``.
"""

from __future__ import annotations

import importlib
import itertools
import json
import uuid
from datetime import datetime as _RealDatetime
from datetime import timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from tests.snapshot.support.normalize import REPO_ROOT

FIXTURE_ROOT = REPO_ROOT / "tests" / "test_data" / "snapshot_fixture"
FIXTURE_REPO = FIXTURE_ROOT / "repo"
FIXTURE_CONFIG = FIXTURE_REPO / ".ash" / ".ash.yaml"
SCANNER_OUTPUTS = FIXTURE_ROOT / "scanner_outputs"
WORKSPACE_ROOT = FIXTURE_ROOT / "workspace"
WORKSPACE_FILE = WORKSPACE_ROOT / "snapshot.code-workspace"
#: Lists a third folder, ``docs``, that does not exist, so resolution with
#: ``allow_missing_projects`` records it as a skipped project.
SKIPPED_WORKSPACE_FILE = WORKSPACE_ROOT / "snapshot-with-skipped.code-workspace"

#: When the fixture scan starts. Deliberately not near any real "today": the
#: normalizer masks today's date, and a pinned instant must not depend on that.
SCAN_STARTED = _RealDatetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
#: How long the whole fixture scan took, wall clock.
SCAN_DURATION_SECONDS = 42.0
#: When the report phase runs. Reporters that print "generated at" or a delta
#: from the scan time read the clock here, so the delta is a fixed 42 seconds.
REPORT_TIME = SCAN_STARTED + timedelta(seconds=SCAN_DURATION_SECONDS)


# --------------------------------------------------------------------------- #
# Clock and identifiers
# --------------------------------------------------------------------------- #


class _Clock:
    """The instant every patched ``datetime.now()`` returns. Advanced by phase."""

    def __init__(self) -> None:
        self.now = SCAN_STARTED

    def set(self, instant: _RealDatetime) -> None:
        self.now = instant


CLOCK = _Clock()


class _FrozenDatetimeMeta(type):
    # isinstance(real_datetime, FrozenDatetime) must stay True: the patched
    # modules test ``isinstance(x, datetime)`` against values that were built
    # elsewhere with the real class.
    def __instancecheck__(cls, instance: object) -> bool:
        return isinstance(instance, _RealDatetime)

    def __subclasscheck__(cls, subclass: type) -> bool:
        return issubclass(subclass, _RealDatetime)


class FrozenDatetime(_RealDatetime, metaclass=_FrozenDatetimeMeta):
    """``datetime`` with ``now``/``utcnow``/``today`` reading :data:`CLOCK`.

    A naive ``now()`` returns the UTC wall clock rather than local time, so a
    snapshot taken in one time zone matches one taken in another.
    """

    @classmethod
    def now(cls, tz=None):  # type: ignore[override]
        if tz is None:
            return CLOCK.now.replace(tzinfo=None)
        return CLOCK.now.astimezone(tz)

    @classmethod
    def utcnow(cls):  # type: ignore[override]
        return CLOCK.now.replace(tzinfo=None)

    @classmethod
    def today(cls):  # type: ignore[override]
        return CLOCK.now.replace(tzinfo=None)


#: Modules that stamp the current time, or a fresh uuid, into something a user
#: reads. Each binds ``datetime`` at module level with ``from datetime import
#: datetime``, which is what :func:`pin_clock` replaces.
CLOCK_PINNED_MODULES = (
    "automated_security_helper.models.asharp_model",
    # FlatVulnerability.detected_at, in every csv / flat-json / gitlab row.
    "automated_security_helper.models.flat_vulnerability",
    "automated_security_helper.utils.suppression_matcher",
    "automated_security_helper.base.reporter_plugin",
    "automated_security_helper.core.execution_engine",
    "automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter",
    "automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter",
    "automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter",
    "automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter",
    "automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter",
    "automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter",
    "automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter",
    "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter",
    "automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter",
)


def pin_clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    """Pin "now" and uuid4 for the rest of the test. Returns the clock to advance."""
    CLOCK.set(SCAN_STARTED)
    for name in CLOCK_PINNED_MODULES:
        module = importlib.import_module(name)
        if getattr(module, "datetime", None) is _RealDatetime:
            monkeypatch.setattr(module, "datetime", FrozenDatetime)
    counter = itertools.count(1)
    monkeypatch.setattr(uuid, "uuid4", lambda: uuid.UUID(int=next(counter), version=4))
    return CLOCK


# --------------------------------------------------------------------------- #
# Single-directory scan
# --------------------------------------------------------------------------- #


def fixture_config(config_path: Path = FIXTURE_CONFIG):
    """The fixture repository's own ``.ash/.ash.yaml``, loaded the way ASH loads it."""
    from automated_security_helper.config.ash_config import AshConfig

    return AshConfig.from_file(config_path)


def fixture_plugin_context(
    tmp_path: Path, config=None, source_dir: Path = FIXTURE_REPO
):
    """The context reporters and the scan phase see: fixture repo in, tmp out."""
    from automated_security_helper.base.plugin_context import PluginContext

    return PluginContext(
        source_dir=source_dir,
        output_dir=tmp_path / "ash_output",
        config=config if config is not None else fixture_config(),
    )


def _load_manifest(manifest_dir: Path) -> list[dict[str, Any]]:
    data = yaml.safe_load((manifest_dir / "scanners.yaml").read_text(encoding="utf-8"))
    return list(data["scanners"])


def _scanner_threshold(config, name: str) -> str | None:
    """The scanner-level threshold the executor passes to ``determine_status``."""
    plugin_config = config.get_plugin_config(plugin_type="scanner", plugin_name=name)
    options = getattr(plugin_config, "options", None)
    return getattr(options, "severity_threshold", None)


def _ran_container(entry: dict[str, Any], manifest_dir: Path, context, offset: float):
    """What ``ScannerExecutor._execute_scanner`` builds for a scanner that returned."""
    from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
    from automated_security_helper.models.scan_results_container import (
        ScanResultsContainer,
    )
    from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
        CycloneDXReport,
    )
    from automated_security_helper.schemas.sarif_schema_model import SarifReport
    from automated_security_helper.utils.sarif_utils import (
        apply_suppressions_to_sarif,
        sanitize_sarif_paths,
    )

    name = entry["name"]
    start = SCAN_STARTED + timedelta(seconds=offset)
    end = start + timedelta(seconds=float(entry["duration_seconds"]))
    container = ScanResultsContainer(
        scanner_name=name,
        target=context.source_dir,
        target_type="source",
        start_time=start,
        end_time=end,
        duration=(end - start).total_seconds(),
        metadata={"scanner_version": entry["version"]},
    )

    if entry["outcome"] == "error":
        # A tracking scanner that attempted one target and failed on it: the
        # per-target counters are what make determine_status return ERROR.
        container.report_type = "sarif"
        container.record_target_attempt(1)
        container.record_target_failure(entry["failed_target"], entry["error"])
        raw = SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": name}}, "results": []}],
            }
        )
    else:
        payload = json.loads((manifest_dir / entry["output"]).read_text("utf-8"))
        if payload.get("bomFormat") == "CycloneDX":
            container.report_type = "cyclonedx"
            raw = CycloneDXReport.model_validate(payload)
        else:
            container.report_type = "sarif"
            raw = SarifReport.model_validate(payload)

    container.raw_results = raw
    if isinstance(raw, SarifReport):
        raw = sanitize_sarif_paths(raw, context.source_dir)
        raw = apply_suppressions_to_sarif(sarif_report=raw, plugin_context=context)
        executor = ScannerExecutor(
            plugin_context=context, progress_display=None, scanner_tasks=[]
        )
        container.severity_counts, container.finding_count = (
            executor._extract_metrics_from_sarif(raw)
        )
    container.status = container.determine_status(
        _scanner_threshold(context.config, name)
    )
    return container


def _scan_phase(model, manifest_dir: Path, context):
    """Steps 1 and 2 of the module docstring: containers through process_container."""
    from automated_security_helper.core.enums import ScannerStatus
    from automated_security_helper.core.phases.scan_result_processor import (
        ScanResultProcessor,
    )
    from automated_security_helper.models.asharp_model import ScannerTargetStatusInfo
    from automated_security_helper.models.scan_results_container import (
        ScanResultsContainer,
    )

    processor = ScanResultProcessor(plugin_context=context)
    offset = 0.0
    for entry in _load_manifest(manifest_dir):
        name = entry["name"]
        outcome = entry["outcome"]
        if outcome == "excluded":
            # ScanPhase._execute_phase, the --exclude-scanners branch.
            model = processor.process_container(
                ScanResultsContainer.for_excluded(name), model
            )
            model.scanner_results[name] = ScannerTargetStatusInfo(
                status=ScannerStatus.SKIPPED, excluded=True, dependencies_satisfied=True
            )
        elif outcome == "missing":
            # ScanPhase._execute_phase, the unsatisfied-dependencies branch.
            model = processor.process_container(
                ScanResultsContainer.for_missing_deps(name), model
            )
            model.scanner_results[name] = ScannerTargetStatusInfo(
                status=ScannerStatus.MISSING,
                dependencies_satisfied=False,
                excluded=False,
            )
        elif outcome in ("ran", "error"):
            container = _ran_container(entry, manifest_dir, context, offset)
            offset += float(entry["duration_seconds"])
            model = processor.process_container(container, model)
        else:
            raise ValueError(f"unknown outcome {outcome!r} for scanner {name!r}")
    return model


def _build_model(
    manifest_dir: Path, context, *, metadata: dict[str, str] | None = None
):
    """Steps 1-3 of the module docstring, for any manifest and source tree."""
    from automated_security_helper.core.unified_metrics import (
        populate_metrics_from_unified_source,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

    CLOCK.set(SCAN_STARTED)
    # ScanExecutionEngine.__init__, which builds the model every phase mutates.
    # `datetime` here is whatever the engine module binds, so it is the pinned
    # clock once pin_clock has run.
    from automated_security_helper.core import execution_engine

    model = AshAggregatedResults(
        name=f"ASH Scan {execution_engine.datetime.now().isoformat()}",
        description="Aggregated security scan results",
        ash_config=context.config,
    )
    # ASHScanOrchestrator._apply_metadata, for a workspace project.
    for key, value in (metadata or {}).items():
        setattr(model.metadata, key, value)

    model = _scan_phase(model, manifest_dir, context)
    model.save_model(context.output_dir)

    # ScanExecutionEngine.execute_phases, `case "report":` before ReportPhase.
    model.sarif = apply_suppressions_to_sarif(
        sarif_report=model.sarif,
        plugin_context=context,
        used_suppressions=model.used_suppressions,
    )
    model = populate_metrics_from_unified_source(aggregated_results=model)
    CLOCK.set(REPORT_TIME)
    return model


def finalize_fixture_model(model):
    """Step 4: the state after the run, which ``ash_aggregated_results.json`` holds.

    ``ScanExecutionEngine.execute_phases`` stamps the timing in its ``finally``
    block, after the report phase, and re-populates metrics for the summary table.
    Mutates and returns ``model``.
    """
    from automated_security_helper.core.unified_metrics import (
        populate_metrics_from_unified_source,
    )

    stats = model.metadata.summary_stats
    stats.start = SCAN_STARTED
    stats.end = REPORT_TIME
    stats.duration = SCAN_DURATION_SECONDS
    return populate_metrics_from_unified_source(aggregated_results=model)


def build_fixture_model(tmp_path: Path, context=None):
    """The single-directory fixture scan, as the report phase hands it to reporters.

    Call :func:`pin_clock` first (the ``fixture_model`` fixture does), or the
    model carries the real time of the run.
    """
    context = context or fixture_plugin_context(tmp_path)
    return _build_model(SCANNER_OUTPUTS, context)


# --------------------------------------------------------------------------- #
# Workspace scan
# --------------------------------------------------------------------------- #


class _FixtureOrchestrator:
    """Stands in for ``ASHScanOrchestrator`` with one project's fixture scan.

    Everything ``execute_workspace`` does around the orchestrator is real; this
    only replaces running scanners with steps 1-4 over the project's manifest
    under ``scanner_outputs/workspace/<key>/``.
    """

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs

    @classmethod
    def create(cls, **kwargs: Any) -> "_FixtureOrchestrator":
        return cls(**kwargs)

    def execute_scan(self, phases=None):
        from automated_security_helper.base.plugin_context import PluginContext

        source_dir = Path(self.kwargs["source_dir"])
        context = PluginContext(
            source_dir=source_dir,
            output_dir=Path(self.kwargs["output_dir"]),
            config=self.kwargs["resolved_config"],
        )
        metadata = dict(self.kwargs.get("metadata") or {})
        model = _build_model(
            SCANNER_OUTPUTS / "workspace" / source_dir.name,
            context,
            metadata=metadata,
        )
        return finalize_fixture_model(model)


def build_fixture_workspace_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    with_skipped_project: bool = False,
):
    """The workspace fixture scan, as ``workspace.reporting`` hands it to reporters.

    Two scanned projects, ``api`` (threshold MEDIUM, one HIGH bandit finding, a
    MISSING npm-audit) and ``web`` (threshold HIGH, one HIGH checkov finding and
    one MEDIUM semgrep finding below its threshold). ``with_skipped_project`` adds
    ``docs``, which does not exist and is skipped with reason ``error``.
    """
    from automated_security_helper.workspace import execution
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        execute_workspace,
    )
    from automated_security_helper.workspace.reporting import _load_workspace_model
    from automated_security_helper.workspace.resolver import resolve_workspace

    # Project durations and the workspace wall clock are differences of
    # time.monotonic(); a constant makes every one of them 0.0.
    monkeypatch.setattr(execution, "time", SimpleNamespace(monotonic=lambda: 1000.0))
    plan = resolve_workspace(
        SKIPPED_WORKSPACE_FILE if with_skipped_project else WORKSPACE_FILE,
        allow_missing_projects=with_skipped_project,
    )
    settings = ProjectScanSettings(
        output_dir=tmp_path / "ash_output",
        phases=("convert", "scan"),
        max_parallel_projects=1,
    )
    result = execute_workspace(
        plan, settings, orchestrator_factory=_FixtureOrchestrator.create
    )
    model = _load_workspace_model(result.results_path)
    CLOCK.set(REPORT_TIME)
    return model


def workspace_reporter_context(model, tmp_path: Path):
    """The context ``emit_workspace_reports`` builds its merged reporters with.

    ASH's default config rooted at the workspace root, not any project's config,
    because no workspace-level config exists (see ``workspace.reporting``).
    """
    from automated_security_helper.workspace.reporting import _workspace_context

    context, _ = _workspace_context(
        model.workspace.workspace_root, tmp_path / "ash_output"
    )
    return context


__all__ = [
    "CLOCK",
    "FIXTURE_CONFIG",
    "FIXTURE_REPO",
    "FIXTURE_ROOT",
    "FrozenDatetime",
    "REPORT_TIME",
    "SCAN_STARTED",
    "SCANNER_OUTPUTS",
    "build_fixture_model",
    "build_fixture_workspace_model",
    "finalize_fixture_model",
    "fixture_config",
    "fixture_plugin_context",
    "pin_clock",
    "workspace_reporter_context",
]
