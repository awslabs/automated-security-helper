#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``build_project_scan_settings`` is the one place a workspace run's settings are built.

Why this file exists
--------------------
``ProjectScanSettings`` is a wide record, and until now it was built inline
inside ``_run_workspace_mode``. The MCP workspace tools need the same record
from the same inputs, and there are only two ways to give it to them: extract
the construction, or write it a second time.

Writing it twice is the failure this file exists to prevent, and it is a quiet
one. Every field is optional with a plausible default, so a second construction
that omits one produces a valid ``ProjectScanSettings`` and a scan that runs to
completion with a setting the caller did not choose. Nothing raises. The two
fields where that is worst are ``config_overrides`` -- dropping it silently
scans with different configuration, which ``workspace/execution.py`` already
carries a warning about -- and ``ignore_suppressions``, where the default is the
lenient direction.

So the construction moves out verbatim, and this file pins the mapping field by
field. That is the only form of "provably behaviour-preserving" available here:
comparing the extracted function against the inline construction is impossible
once the extraction has happened, because after it both sides are the same code
and the comparison is a tautology. An explicit table of expected values is not,
and it keeps failing usefully for as long as the mapping exists.

Every value in the table differs from the dataclass default
-----------------------------------------------------------
Deliberately, and it is what gives the table teeth. A builder that forgets to
wire a field leaves it at its default, so an expectation equal to the default
would pass. ``project_timeout`` is the field this constrains most: its dataclass
default is ``None`` and so is ``WorkspaceExecutionConfig``'s, so the fixture
writes an ASH config at the workspace root that sets it -- which also pins that
the builder reads the *workspace root's* config for the two scheduling knobs
rather than leaving them at the dataclass defaults.

The field list comes from the dataclass, not from this file
-----------------------------------------------------------
:meth:`TestTheFieldTableIsComplete.test_the_expectation_covers_every_field`
compares the table's keys against ``dataclasses.fields(ProjectScanSettings)``,
so a field added later fails that assertion until the table accounts for it. A
hardcoded count would have gone stale silently.
"""

from __future__ import annotations

import dataclasses
import importlib
import json
import platform
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from automated_security_helper.core.enums import (
    ExecutionPhase,
    ExecutionStrategy,
    ExportFormat,
    RunMode,
)
from automated_security_helper.interactions.run_ash_scan import ScanOptions
from automated_security_helper.workspace.execution import ProjectScanSettings

MODULE_UNDER_TEST = "automated_security_helper.cli.mcp.workspace"
RUN_ASH_SCAN_MODULE = "automated_security_helper.interactions.run_ash_scan"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _builder():
    """The extracted builder, looked up at call time.

    Module-level, not a method: both ``_run_workspace_mode`` and the MCP path
    have to reach it, and the MCP path cannot import a private method off a
    function.
    """
    module = importlib.import_module(RUN_ASH_SCAN_MODULE)
    return getattr(module, "build_project_scan_settings")


def _field_names() -> Tuple[str, ...]:
    return tuple(field.name for field in dataclasses.fields(ProjectScanSettings))


def _as_dict(settings: ProjectScanSettings) -> Dict[str, Any]:
    return {name: getattr(settings, name) for name in _field_names()}


def _defaults() -> Dict[str, Any]:
    """Each field's dataclass default, or a sentinel where it has none."""
    out: Dict[str, Any] = {}
    for field in dataclasses.fields(ProjectScanSettings):
        if field.default is not dataclasses.MISSING:
            out[field.name] = field.default
    return out


@pytest.fixture(autouse=True)
def _isolate_process_state(monkeypatch):
    """Keep the ambient policy and the scan registry out of these measurements.

    ``ASH_MCP_ALLOWED_ROOTS`` is cleared because the MCP test at the end of this
    module runs a real workspace scan through the tool, and an allowlist
    inherited from the environment would refuse it -- reporting a confinement
    failure for a test about a settings record.

    The scan registry is replaced because ``mcp_scan_workspace`` registers into
    a module-level singleton with no reset, and leaving entries behind would
    make the registration tests in ``test_workspace_registration.py`` depend on
    whether this module ran first.
    """
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )


def _expected_color_system() -> Any:
    """The one expected value that legitimately depends on the platform.

    ``color_system`` is forced to ``"windows"`` there regardless of the flag,
    because Rich needs the legacy console driver. Both arms of the flag are
    pinned separately in
    :meth:`TestPlatformAndFlagMappings.test_color_system_follows_the_color_flag`;
    here the table just needs the value for ``color=True``.
    """
    return "windows" if platform.system() == "Windows" else "auto"


def _opts(tmp_path: Path) -> ScanOptions:
    """A ``ScanOptions`` whose every mapped field is set away from its default.

    ``workspace_plan`` is left ``None`` on purpose: the builder does not read it,
    and supplying one would mean building a plan for a test about a settings
    record.
    """
    root = tmp_path / "work"
    # exist_ok, because TestBothCallersUseTheSharedBuilder builds its plan in
    # the same directory before calling this.
    root.mkdir(parents=True, exist_ok=True)
    # Read by _resolve_workspace_execution_config, which searches the workspace
    # root for ASH's own config. .ash.yaml is the second name it tries.
    (root / ".ash.yaml").write_text(
        "workspace:\n  max_parallel_projects: 7\n  project_timeout: 90.0\n",
        encoding="utf-8",
    )
    return ScanOptions(
        source_dir=root,
        output_dir=tmp_path / "out",
        config=None,
        config_overrides=["global_settings.severity_threshold=HIGH"],
        offline=True,
        strategy=ExecutionStrategy.SEQUENTIAL,
        scanners=["bandit", "semgrep"],
        excluded_scanners=["cdk-nag"],
        output_formats=[ExportFormat.CSV, ExportFormat.HTML],
        cleanup=True,
        phases=[ExecutionPhase.CONVERT, ExecutionPhase.SCAN],
        inspect=False,
        python_based_plugins_only=True,
        simple=True,
        verbose=True,
        debug=True,
        color=True,
        fail_on_findings=False,
        ignore_suppressions=True,
        min_severity="high",
        changed_files_only=True,
        base_ref="origin/release",
        mode=RunMode.precommit,
        ash_plugin_modules=["my_plugins"],
        allow_missing_projects=True,
    )


def _expected(tmp_path: Path) -> Dict[str, Any]:
    """The record ``_opts`` must produce, field by field.

    Transcribed from the construction as it stood inline in
    ``_run_workspace_mode``, not computed from it. Tuples throughout, because
    ``ProjectScanSettings`` is frozen and read from ``max_parallel_projects``
    threads at once -- a list here would compare unequal and that is the point.
    """
    return {
        "output_dir": tmp_path / "out",
        "phases": ("convert", "scan"),
        "enabled_scanners": ("bandit", "semgrep"),
        "excluded_scanners": ("cdk-nag",),
        "output_formats": ("csv", "html"),
        "config_overrides": ("global_settings.severity_threshold=HIGH",),
        "ash_plugin_modules": ("my_plugins",),
        "strategy": "sequential",
        "offline": True,
        "python_based_plugins_only": True,
        "ignore_suppressions": True,
        "min_severity": "high",
        "fail_on_findings": False,
        "changed_files_only": True,
        "base_ref": "origin/release",
        "precommit": True,
        "cleanup": True,
        "verbose": True,
        "debug": True,
        "simple": True,
        "color_system": _expected_color_system(),
        "max_parallel_projects": 7,
        "project_timeout": 90.0,
        "allow_missing_projects": True,
    }


# ---------------------------------------------------------------------------
# 1. The table is complete, and every entry is a discriminator
# ---------------------------------------------------------------------------


class TestTheFieldTableIsComplete:
    """Guards on the table itself, so the mapping test below cannot go stale."""

    def test_the_expectation_covers_every_field(self, tmp_path):
        """A field added to ``ProjectScanSettings`` fails here until it is mapped.

        The alternative -- asserting a field count -- goes stale the other way:
        it fails when a field is added, says nothing about which, and passes
        again as soon as somebody bumps the number without touching the table.
        """
        expected = _expected(tmp_path)

        assert set(expected) == set(_field_names()), (
            "ProjectScanSettings gained or lost a field; extend _expected() so "
            "the mapping stays covered. Missing from the table: "
            f"{sorted(set(_field_names()) - set(expected))}; no longer a field: "
            f"{sorted(set(expected) - set(_field_names()))}"
        )

    def test_every_expected_value_differs_from_the_dataclass_default(self, tmp_path):
        """The property that makes an unwired field fail rather than pass.

        Without it, an expectation that happens to equal the default is
        satisfied by a builder that never mentioned the field -- the exact
        omission this file exists to catch, passing.
        """
        expected = _expected(tmp_path)
        defaults = _defaults()

        colliding = {
            name: value
            for name, value in expected.items()
            if name in defaults and defaults[name] == value
        }
        assert colliding == {}, (
            "these expected values equal the dataclass default, so a builder "
            f"that never set the field would still pass: {colliding}"
        )


# ---------------------------------------------------------------------------
# 2. The mapping itself
# ---------------------------------------------------------------------------


class TestTheBuilderProducesTheDocumentedRecord:
    """One call, one record, compared across every field."""

    def test_the_record_matches_field_for_field(self, tmp_path):
        settings = _builder()(_opts(tmp_path))

        assert isinstance(settings, ProjectScanSettings)
        assert _as_dict(settings) == _expected(tmp_path)

    def test_the_sequence_fields_are_tuples_not_lists(self, tmp_path):
        """``ProjectScanSettings`` documents why, and the dict compare hides it.

        ``("a",) == ["a"]`` is False, so the comparison above would catch a list
        -- but it would report it as a value mismatch, which reads like a wrong
        value rather than a wrong type. The record is frozen and shared across
        threads precisely so no project can mutate another's settings; a list
        would leave that open.
        """
        settings = _builder()(_opts(tmp_path))

        for name in (
            "phases",
            "enabled_scanners",
            "excluded_scanners",
            "output_formats",
            "config_overrides",
            "ash_plugin_modules",
        ):
            assert isinstance(getattr(settings, name), tuple), (
                f"{name} must be a tuple; got {type(getattr(settings, name)).__name__}"
            )

    def test_the_builder_takes_only_the_options(self, tmp_path):
        """One required argument, so both callers can reach it the same way.

        A builder that also demanded the workspace execution config, or a plan,
        would push part of the construction back out to its callers and put the
        duplication back where it started.
        """
        settings = _builder()(_opts(tmp_path))

        assert isinstance(settings, ProjectScanSettings)


# ---------------------------------------------------------------------------
# 3. The branches inside the mapping
# ---------------------------------------------------------------------------


class TestPhaseSelection:
    """``phases`` is the only field with real logic behind it."""

    def _opts_with(self, tmp_path: Path, **overrides) -> ScanOptions:
        base = _opts(tmp_path)
        return base.model_copy(update=overrides)

    def test_no_selected_phase_falls_back_to_the_full_set(self, tmp_path):
        """An empty selection means "everything", not "nothing".

        A workspace run with no phases would convert nothing, scan nothing and
        exit 0, which is the failure direction the whole feature is built to
        avoid.
        """
        settings = _builder()(self._opts_with(tmp_path, phases=[], inspect=False))

        assert settings.phases == ("convert", "scan", "report")

    def test_the_phases_keep_their_pipeline_order(self, tmp_path):
        """Order is not incidental: convert feeds scan, which feeds report.

        Selected out of order in the options, expected in pipeline order out --
        an implementation that echoed the caller's order would fail.
        """
        settings = _builder()(
            self._opts_with(
                tmp_path,
                phases=[
                    ExecutionPhase.REPORT,
                    ExecutionPhase.CONVERT,
                    ExecutionPhase.SCAN,
                ],
            )
        )

        assert settings.phases == ("convert", "scan", "report")

    def test_inspect_is_appended_when_selected_as_a_phase(self, tmp_path):
        settings = _builder()(
            self._opts_with(
                tmp_path,
                phases=[
                    ExecutionPhase.CONVERT,
                    ExecutionPhase.SCAN,
                    ExecutionPhase.REPORT,
                    ExecutionPhase.INSPECT,
                ],
                inspect=False,
            )
        )

        assert settings.phases == ("convert", "scan", "report", "inspect")

    def test_inspect_is_appended_when_requested_by_its_own_flag(self, tmp_path):
        """``--inspect`` is a separate switch from ``--phases inspect``.

        Two routes to one phase, and the builder has to honour both. Pinned
        separately because an implementation that read only ``opts.phases``
        passes the test above and drops the flag.
        """
        settings = _builder()(
            self._opts_with(
                tmp_path,
                phases=[ExecutionPhase.CONVERT, ExecutionPhase.SCAN],
                inspect=True,
            )
        )

        assert settings.phases == ("convert", "scan", "inspect")


class TestPlatformAndFlagMappings:
    """The two fields whose value is not a straight copy of an option."""

    def _opts_with(self, tmp_path: Path, **overrides) -> ScanOptions:
        return _opts(tmp_path).model_copy(update=overrides)

    def test_color_system_follows_the_color_flag(self, tmp_path):
        """Off means ``None``, not ``"auto"``.

        The flag exists so a caller with no terminal gets no escape sequences.
        Passing ``"auto"`` regardless would put them in the output, which for an
        MCP client reading a log means control characters in a JSON string.
        """
        if platform.system() == "Windows":
            # Rich needs the legacy driver on Windows whatever the flag says,
            # so there is only one value to pin there.
            assert (
                _builder()(self._opts_with(tmp_path, color=True)).color_system
                == "windows"
            )
            assert (
                _builder()(self._opts_with(tmp_path, color=False)).color_system
                == "windows"
            )
            return

        assert _builder()(self._opts_with(tmp_path, color=True)).color_system == "auto"
        assert _builder()(self._opts_with(tmp_path, color=False)).color_system is None

    def test_precommit_is_derived_from_the_run_mode(self, tmp_path):
        """``precommit`` is a mode, not a boolean option, on the way in.

        Both arms, because a builder that hardcoded either one would pass a
        single-arm test.
        """
        assert _builder()(self._opts_with(tmp_path, mode=RunMode.precommit)).precommit
        assert not _builder()(self._opts_with(tmp_path, mode=RunMode.local)).precommit

    def test_the_enum_valued_options_arrive_as_strings(self, tmp_path):
        """``ProjectScanSettings`` holds plain strings, and it has to.

        The record is compared and serialised, and an ``ExportFormat`` member is
        neither equal to its own value nor JSON-serialisable without help. This
        is the assertion that catches a builder passing the enum members
        straight through, which would otherwise only surface deep inside
        ``_scan_one_project`` where ``ExportFormat(value)`` is applied to them.
        """
        settings = _builder()(
            self._opts_with(
                tmp_path,
                strategy=ExecutionStrategy.PARALLEL,
                output_formats=[ExportFormat.SARIF, ExportFormat.CSV],
            )
        )

        assert settings.strategy == "parallel"
        assert settings.output_formats == ("sarif", "csv")
        assert all(isinstance(value, str) for value in settings.output_formats)
        assert all(
            not isinstance(value, ExportFormat) for value in settings.output_formats
        )


class TestTheSchedulingKnobsComeFromTheWorkspaceRoot:
    """``max_parallel_projects`` and ``project_timeout`` are read, not defaulted."""

    def test_without_a_config_the_documented_defaults_apply(self, tmp_path):
        """No ASH config at the root: bound 4, no timeout.

        Note that 4 is *not* the dataclass default, which is 1. So this is a
        real assertion about the builder consulting
        ``WorkspaceExecutionConfig.resolved_max_parallel_projects`` rather than
        leaving the field alone.
        """
        root = tmp_path / "bare"
        root.mkdir()
        opts = _opts(tmp_path).model_copy(update={"source_dir": root, "config": None})

        settings = _builder()(opts)

        assert settings.max_parallel_projects == 4
        assert settings.project_timeout is None

    def test_an_unreadable_config_falls_back_rather_than_raising(self, tmp_path):
        """These are scheduling knobs, so a bad config must not refuse the scan.

        ``_resolve_workspace_execution_config`` warns and uses the defaults. The
        builder inherits that, and the MCP path depends on it: raising here would
        be an exception with no workspace-level meaning, which the exit-code
        mapping would have to report as an internal error for what is really a
        typo in a config file.
        """
        root = tmp_path / "broken"
        root.mkdir()
        (root / ".ash.yaml").write_text(
            "workspace: [not, a, mapping]\n", encoding="utf-8"
        )
        opts = _opts(tmp_path).model_copy(update={"source_dir": root, "config": None})

        settings = _builder()(opts)

        assert settings.max_parallel_projects == 4
        assert settings.project_timeout is None


# ---------------------------------------------------------------------------
# 4. Both callers actually go through it
# ---------------------------------------------------------------------------


class TestBothCallersUseTheSharedBuilder:
    """Extraction is only worth anything if the duplicates are gone.

    An extracted function that nobody calls is the worst outcome available: the
    field-by-field tests above all pass, and the two real code paths keep their
    own constructions and drift apart. These tests substitute a sentinel record
    for the builder's output and check that it is what reaches
    ``execute_workspace`` -- which no inline construction can produce.
    """

    @staticmethod
    def _install_sentinel(monkeypatch, tmp_path: Path) -> ProjectScanSettings:
        # A real directory, not a made-up one. The identity assertion below does
        # not care what is in the record, but the caller under test may derive a
        # registry output directory from it, and a path that does not exist would
        # fail that for a reason unrelated to what is being pinned.
        output_dir = tmp_path / "sentinel-output"
        output_dir.mkdir(parents=True, exist_ok=True)
        sentinel = ProjectScanSettings(
            output_dir=output_dir,
            base_ref="sentinel/ref",
            min_severity="sentinel",
        )
        run_ash_scan_module = importlib.import_module(RUN_ASH_SCAN_MODULE)

        def _fake_builder(opts):
            return sentinel

        monkeypatch.setattr(
            run_ash_scan_module, "build_project_scan_settings", _fake_builder
        )
        mcp_module = importlib.import_module(MODULE_UNDER_TEST)
        if hasattr(mcp_module, "build_project_scan_settings"):
            monkeypatch.setattr(
                mcp_module, "build_project_scan_settings", _fake_builder
            )
        return sentinel

    @staticmethod
    def _capture_executions(monkeypatch) -> List[Tuple[Any, Any]]:
        from automated_security_helper.models.workspace import WorkspaceResults
        from automated_security_helper.workspace import execution as execution_module
        from automated_security_helper.workspace.execution import WorkspaceRunResult

        calls: List[Tuple[Any, Any]] = []

        def _record(plan, settings, **kwargs):
            calls.append((plan, settings))
            payload = WorkspaceResults(
                workspace_file=plan.workspace_file,
                workspace_root=plan.workspace_root,
                status="completed",
                exit_code=0,
                projects=[],
                unconvertible_finding_paths=0,
            )
            return WorkspaceRunResult(
                results_path=Path(settings.output_dir) / "ash_workspace_results.json",
                exit_code=0,
                payload=payload,
            )

        monkeypatch.setattr(execution_module, "execute_workspace", _record)
        mcp_module = importlib.import_module(MODULE_UNDER_TEST)
        if hasattr(mcp_module, "execute_workspace"):
            monkeypatch.setattr(mcp_module, "execute_workspace", _record)
        return calls

    @staticmethod
    def _plan(tmp_path: Path):
        from automated_security_helper.workspace.resolver import resolve_workspace

        root = tmp_path / "work"
        (root / "api").mkdir(parents=True, exist_ok=True)
        workspace = root / "dev.code-workspace"
        workspace.write_text(
            json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8"
        )
        return workspace, resolve_workspace(workspace)

    def test_run_workspace_mode_uses_it(self, tmp_path, monkeypatch):
        """The CLI path stops building its own record.

        This is the assertion that says the inline construction was *removed*
        rather than left in place beside the new function.
        """
        from automated_security_helper.interactions.run_ash_scan import (
            _run_workspace_mode,
        )

        _workspace_file, plan = self._plan(tmp_path)
        sentinel = self._install_sentinel(monkeypatch, tmp_path)
        executions = self._capture_executions(monkeypatch)
        opts = _opts(tmp_path).model_copy(update={"workspace_plan": plan})

        _run_workspace_mode(opts, logger=None)

        assert len(executions) == 1
        _plan_arg, settings = executions[0]
        assert settings is sentinel, (
            "_run_workspace_mode built its own ProjectScanSettings instead of "
            "calling build_project_scan_settings"
        )

    @pytest.mark.asyncio
    async def test_the_mcp_workspace_scan_uses_it(self, tmp_path, monkeypatch):
        """And so does the MCP path, from the other side of the extraction.

        The two paths assemble their options differently -- one from typer
        arguments, one from MCP tool parameters -- but the record they hand to
        ``execute_workspace`` has to come from the same construction, or the
        drift the extraction prevents comes back through the new caller.
        """
        workspace_file, _plan = self._plan(tmp_path)
        sentinel = self._install_sentinel(monkeypatch, tmp_path)
        executions = self._capture_executions(monkeypatch)

        module = importlib.import_module(MODULE_UNDER_TEST)
        response = await module.mcp_scan_workspace(workspace_file=str(workspace_file))

        assert response["success"] is True, response.get("error")
        assert len(executions) == 1
        _plan_arg, settings = executions[0]
        assert settings is sentinel, (
            "the MCP workspace tool built its own ProjectScanSettings instead "
            "of calling build_project_scan_settings"
        )
