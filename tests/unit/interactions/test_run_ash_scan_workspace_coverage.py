# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Workspace mode: execution-config resolution, dispatch, verdict, and summary.

Why this file exists
--------------------
A workspace scan reaches an exit code by a different route than a single-
directory scan. It does not go through ``_compute_exit_code`` at all: each
project's verdict is computed during execution and reduced to one process status
by ``workspace_exit_code``, because "project A failed, project B did not" has no
expression as a single threshold comparison. That means the whole route --
``_resolve_workspace_execution_config`` -> ``_run_workspace_mode`` ->
``_print_workspace_summary`` -> the ``sys.exit`` in ``run_ash_scan`` -- had no
coverage of its failure and refusal branches.

Exit codes asserted here (``models.workspace.WorkspaceExitCode``):
0 success, 1 internal error, 2 actionable findings, 3 invalid project config,
4 workspace definition or policy error. Code 4 is the one that is workspace-only:
a refusal, where nothing was scanned and no results file exists, which is why it
does not collide with the 2 that means "a project exceeded its threshold".

Why the execution knobs come from the workspace root's config
------------------------------------------------------------
``max_parallel_projects`` and ``project_timeout`` are read from the root, never
from a project, because how many projects run at once is not a project's
decision. An unreadable config falls back to defaults rather than refusing the
scan: these are scheduling knobs and cannot change any verdict.

No projects are scanned. ``execute_workspace`` is replaced by a recorder, so what
is asserted is the ``ProjectScanSettings`` ASH would have handed it and what it
does with each outcome.
"""

from __future__ import annotations

import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.config.ash_config import (
    AshConfig,
    WorkspaceExecutionConfig,
)
from automated_security_helper.core.enums import ExecutionPhase, RunMode
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    WorkspaceDefinitionError,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _print_workspace_summary,
    _resolve_workspace_execution_config,
    _run_workspace_mode,
    run_ash_scan,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    SkippedProjectReason,
    WorkspaceExitCode,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.workspace import execution as workspace_execution
from automated_security_helper.workspace.execution import WorkspaceRunResult
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

AshConfig.model_rebuild()


_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Strip rich's ANSI styling, which it inserts inside phrases as well as around."""
    return _ANSI_ESCAPE.sub("", text)


def _unwrapped(text: str) -> str:
    """Also join rich's hard wrap, which breaks mid-token at the console width.

    A temporary directory is long enough that rich splits a path across lines --
    ``dev.code-work\\nspace`` -- so any assertion naming a path has to be
    wrap-insensitive or it fails on text that is plainly on screen.
    """
    return _plain(text).replace("\n", "")


class _RecordingLogger:
    """Only the levels the workspace path calls; anything else is an AttributeError."""

    def __init__(self):
        self.records: Dict[str, List[str]] = {
            "verbose": [],
            "debug": [],
            "info": [],
            "warning": [],
            "error": [],
            "exception": [],
        }

    def verbose(self, message):
        self.records["verbose"].append(str(message))

    def debug(self, message):
        self.records["debug"].append(str(message))

    def info(self, message):
        self.records["info"].append(str(message))

    def warning(self, message):
        self.records["warning"].append(str(message))

    def error(self, message):
        self.records["error"].append(str(message))

    def exception(self, message):
        self.records["exception"].append(str(message))


@pytest.fixture
def logger() -> _RecordingLogger:
    return _RecordingLogger()


def _plan(root: Path, *keys: str) -> WorkspacePlan:
    return WorkspacePlan(
        workspace_file=(root / "dev.code-workspace").as_posix(),
        workspace_root=root.as_posix(),
        projects=[
            ProjectPlan(
                key=key,
                relative_path=key,
                path=(root / key).as_posix(),
                label=key,
                display_label=key,
                severity_threshold="MEDIUM",
            )
            for key in keys
        ],
    )


def _project(
    key: str, status: ProjectRunStatus, **overrides: Any
) -> WorkspaceProjectResult:
    fields: Dict[str, Any] = {
        "project": key,
        "relative_path": key,
        "display_label": key,
        "status": status,
        "output_path": "projects/" + key,
    }
    fields.update(overrides)
    return WorkspaceProjectResult(**fields)


def _run_result(
    root: Path,
    *,
    exit_code: int = 0,
    projects: List[WorkspaceProjectResult] | None = None,
    unconvertible: int = 0,
) -> WorkspaceRunResult:
    payload = WorkspaceResults(
        workspace_file=(root / "dev.code-workspace").as_posix(),
        workspace_root=root.as_posix(),
        exit_code=exit_code,
        projects=projects or [],
        unconvertible_finding_paths=unconvertible,
    )
    return WorkspaceRunResult(
        results_path=root / "out" / "ash_aggregated_results.json",
        exit_code=exit_code,
        payload=payload,
    )


# ---------------------------------------------------------------------------
# _resolve_workspace_execution_config
# ---------------------------------------------------------------------------


class TestResolveWorkspaceExecutionConfig:
    def test_no_config_file_yields_the_defaults(self, tmp_path):
        config = _resolve_workspace_execution_config(
            ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")
        )

        assert isinstance(config, WorkspaceExecutionConfig)
        assert config.max_parallel_projects is None
        assert config.project_timeout is None

    def test_the_root_config_supplies_both_knobs(self, tmp_path):
        (tmp_path / ".ash.yaml").write_text(
            "project_name: ws\nworkspace:\n"
            "  max_parallel_projects: 3\n  project_timeout: 45.5\n",
            encoding="utf-8",
        )

        config = _resolve_workspace_execution_config(
            ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")
        )

        assert config.max_parallel_projects == 3
        assert config.project_timeout == 45.5

    def test_a_config_under_the_dot_ash_directory_is_discovered(self, tmp_path):
        dot_ash = tmp_path / ".ash"
        dot_ash.mkdir()
        (dot_ash / "ash.yaml").write_text(
            "project_name: ws\nworkspace:\n  max_parallel_projects: 7\n",
            encoding="utf-8",
        )

        config = _resolve_workspace_execution_config(
            ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")
        )

        assert config.max_parallel_projects == 7

    def test_an_explicit_config_path_is_used_without_discovery(self, tmp_path):
        explicit = tmp_path / "chosen.yaml"
        explicit.write_text(
            "project_name: ws\nworkspace:\n  max_parallel_projects: 2\n",
            encoding="utf-8",
        )
        (tmp_path / ".ash.yaml").write_text(
            "project_name: ws\nworkspace:\n  max_parallel_projects: 9\n",
            encoding="utf-8",
        )

        config = _resolve_workspace_execution_config(
            ScanOptions(
                source_dir=tmp_path,
                output_dir=tmp_path / "out",
                config=explicit.as_posix(),
            )
        )

        assert config.max_parallel_projects == 2

    def test_an_unreadable_config_falls_back_rather_than_refusing_the_scan(
        self, tmp_path, caplog
    ):
        """These are scheduling knobs; refusing to scan over one would be a poor trade."""
        (tmp_path / ".ash.yaml").write_text(
            "workspace: [this: is: not: valid\n", encoding="utf-8"
        )

        with caplog.at_level(logging.WARNING):
            config = _resolve_workspace_execution_config(
                ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")
            )

        assert config.max_parallel_projects is None
        assert "using defaults" in caplog.text


# ---------------------------------------------------------------------------
# _run_workspace_mode
# ---------------------------------------------------------------------------


@pytest.fixture
def recorded_workspace_execution(monkeypatch):
    """Replace execute_workspace; record the plan and settings it was handed."""
    recorded: Dict[str, Any] = {"plans": [], "settings": []}

    def install(result=None, raises: BaseException | None = None):
        def fake_execute_workspace(plan, settings):
            recorded["plans"].append(plan)
            recorded["settings"].append(settings)
            if raises is not None:
                raise raises
            return result

        monkeypatch.setattr(
            workspace_execution, "execute_workspace", fake_execute_workspace
        )
        return recorded

    return install


class TestRunWorkspaceModeSettings:
    def test_the_run_result_is_returned_unchanged(
        self, recorded_workspace_execution, logger, tmp_path
    ):
        expected = _run_result(tmp_path)
        recorded = recorded_workspace_execution(result=expected)
        plan = _plan(tmp_path, "api")
        opts = ScanOptions(
            source_dir=tmp_path, output_dir=tmp_path / "out", workspace_plan=plan
        )

        assert _run_workspace_mode(opts, logger) is expected
        assert recorded["plans"][0] is plan

    def test_the_root_configs_parallelism_bound_reaches_the_settings(
        self, recorded_workspace_execution, logger, tmp_path
    ):
        (tmp_path / ".ash.yaml").write_text(
            "project_name: ws\nworkspace:\n"
            "  max_parallel_projects: 2\n  project_timeout: 60.0\n",
            encoding="utf-8",
        )
        recorded = recorded_workspace_execution(result=_run_result(tmp_path))
        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            workspace_plan=_plan(tmp_path, "api"),
        )

        _run_workspace_mode(opts, logger)

        settings = recorded["settings"][0]
        assert settings.max_parallel_projects == 2
        assert settings.project_timeout == 60.0

    def test_an_empty_phase_list_falls_back_to_the_standard_three(
        self, recorded_workspace_execution, logger, tmp_path
    ):
        recorded = recorded_workspace_execution(result=_run_result(tmp_path))
        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            workspace_plan=_plan(tmp_path, "api"),
            phases=[],
        )

        _run_workspace_mode(opts, logger)

        assert recorded["settings"][0].phases == ("convert", "scan", "report")

    def test_phases_are_ordered_by_the_pipeline_not_by_the_request(
        self, recorded_workspace_execution, logger, tmp_path
    ):
        recorded = recorded_workspace_execution(result=_run_result(tmp_path))
        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            workspace_plan=_plan(tmp_path, "api"),
            phases=[ExecutionPhase.REPORT, ExecutionPhase.CONVERT],
        )

        _run_workspace_mode(opts, logger)

        assert recorded["settings"][0].phases == ("convert", "report")

    def test_the_inspect_flag_appends_the_inspect_phase(
        self, recorded_workspace_execution, logger, tmp_path
    ):
        recorded = recorded_workspace_execution(result=_run_result(tmp_path))
        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            workspace_plan=_plan(tmp_path, "api"),
            phases=[ExecutionPhase.SCAN],
            inspect=True,
        )

        _run_workspace_mode(opts, logger)

        assert recorded["settings"][0].phases == ("scan", "inspect")

    def test_precommit_mode_is_forwarded_as_a_flag(
        self, recorded_workspace_execution, logger, tmp_path
    ):
        recorded = recorded_workspace_execution(result=_run_result(tmp_path))
        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            workspace_plan=_plan(tmp_path, "api"),
            mode=RunMode.precommit,
        )

        _run_workspace_mode(opts, logger)

        assert recorded["settings"][0].precommit is True

    def test_allow_missing_projects_is_forwarded(
        self, recorded_workspace_execution, logger, tmp_path
    ):
        recorded = recorded_workspace_execution(result=_run_result(tmp_path))
        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            workspace_plan=_plan(tmp_path, "api"),
            allow_missing_projects=True,
        )

        _run_workspace_mode(opts, logger)

        assert recorded["settings"][0].allow_missing_projects is True


class TestRunWorkspaceModeOffline:
    def test_offline_is_set_for_the_run_and_removed_afterwards(
        self, recorded_workspace_execution, logger, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        seen: Dict[str, Any] = {}

        def capture(plan, settings):
            seen["offline_env"] = os.environ.get("ASH_OFFLINE")
            return _run_result(tmp_path)

        monkeypatch.setattr(workspace_execution, "execute_workspace", capture)
        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            workspace_plan=_plan(tmp_path, "api"),
            offline=True,
        )

        _run_workspace_mode(opts, logger)

        assert seen["offline_env"] == "YES"
        assert "ASH_OFFLINE" not in os.environ


class TestRunWorkspaceModeFailures:
    def test_a_workspace_definition_error_exits_four(
        self, recorded_workspace_execution, logger, tmp_path, capsys
    ):
        """A refusal: nothing was scanned, so code 4 cannot be confused with a finding."""
        recorded_workspace_execution(
            raises=WorkspaceDefinitionError("two folders resolve to the same path")
        )
        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            workspace_plan=_plan(tmp_path, "api"),
        )

        with pytest.raises(SystemExit) as excinfo:
            _run_workspace_mode(opts, logger)

        assert excinfo.value.code == int(WorkspaceExitCode.WORKSPACE_ERROR)
        assert excinfo.value.code == 4
        assert "two folders resolve to the same path" in capsys.readouterr().err

    def test_an_invalid_project_config_exits_three(
        self, recorded_workspace_execution, logger, tmp_path, capsys
    ):
        recorded_workspace_execution(
            raises=ASHConfigValidationError("unknown severity threshold")
        )
        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            workspace_plan=_plan(tmp_path, "api"),
        )

        with pytest.raises(SystemExit) as excinfo:
            _run_workspace_mode(opts, logger)

        assert excinfo.value.code == int(WorkspaceExitCode.INVALID_PROJECT_CONFIG)
        assert excinfo.value.code == 3
        assert "ERROR (3) Invalid configuration" in _plain(capsys.readouterr().out)

    def test_any_other_failure_exits_one(
        self, recorded_workspace_execution, logger, tmp_path, capsys
    ):
        recorded_workspace_execution(raises=RuntimeError("thread pool died"))
        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            workspace_plan=_plan(tmp_path, "api"),
        )

        with pytest.raises(SystemExit) as excinfo:
            _run_workspace_mode(opts, logger)

        assert excinfo.value.code == int(WorkspaceExitCode.INTERNAL_ERROR)
        assert excinfo.value.code == 1
        assert logger.records["exception"], "the traceback should have been logged"
        assert "ERROR (1) Exiting due to exception during ASH workspace" in _plain(
            capsys.readouterr().out
        )

    def test_the_offline_env_var_is_removed_even_when_the_run_fails(
        self, recorded_workspace_execution, logger, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        recorded_workspace_execution(raises=RuntimeError("thread pool died"))
        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            workspace_plan=_plan(tmp_path, "api"),
            offline=True,
        )

        with pytest.raises(SystemExit):
            _run_workspace_mode(opts, logger)

        assert "ASH_OFFLINE" not in os.environ


# ---------------------------------------------------------------------------
# _print_workspace_summary
# ---------------------------------------------------------------------------


class TestPrintWorkspaceSummary:
    @pytest.fixture
    def mixed_outcomes(self, tmp_path) -> WorkspaceRunResult:
        return _run_result(
            tmp_path,
            exit_code=int(WorkspaceExitCode.ACTIONABLE_FINDINGS),
            unconvertible=3,
            projects=[
                _project(
                    "docs",
                    ProjectRunStatus.SKIPPED,
                    skip_reason=SkippedProjectReason.NO_CHANGES,
                ),
                _project("legacy", ProjectRunStatus.FAILED, error="git clone missing"),
                _project(
                    "api",
                    ProjectRunStatus.COMPLETED,
                    severity_threshold="MEDIUM",
                    finding_count=7,
                    actionable_finding_count=2,
                    exceeds_threshold=True,
                    duration_seconds=12.25,
                ),
                _project(
                    "web",
                    ProjectRunStatus.COMPLETED,
                    severity_threshold="HIGH",
                    finding_count=1,
                    actionable_finding_count=0,
                    exceeds_threshold=False,
                    duration_seconds=3.5,
                ),
            ],
        )

    def test_each_project_gets_its_own_line_with_its_own_verdict(
        self, mixed_outcomes, tmp_path, capsys
    ):
        """The first question about a workspace scan is which project failed."""
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")

        _print_workspace_summary(mixed_outcomes, opts, time.time())

        out = _plain(capsys.readouterr().out)
        assert "skipped  docs (no-changes)" in out
        assert "failed   legacy: git clone missing" in out
        assert "FAIL     api -- 2 actionable of 7 at threshold MEDIUM" in out
        assert "pass     web -- 0 actionable of 1 at threshold HIGH" in out

    def test_a_skip_without_a_recorded_reason_reads_as_unspecified(
        self, tmp_path, capsys
    ):
        result = _run_result(
            tmp_path,
            projects=[_project("docs", ProjectRunStatus.SKIPPED)],
        )
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")

        _print_workspace_summary(result, opts, time.time())

        assert "skipped  docs (unspecified)" in _plain(capsys.readouterr().out)

    def test_the_workspace_file_and_both_output_locations_are_named(
        self, mixed_outcomes, tmp_path, capsys
    ):
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")

        _print_workspace_summary(mixed_outcomes, opts, time.time())

        out = _unwrapped(capsys.readouterr().out)
        assert "dev.code-workspace" in out
        assert "Aggregated results:" in out
        assert (tmp_path / "out" / "projects").as_posix() in out
        assert (tmp_path / "out" / "ash_aggregated_results.json").as_posix() in out

    def test_unconvertible_finding_paths_are_reported_as_still_included(
        self, mixed_outcomes, tmp_path, capsys
    ):
        """Counted rather than dropped: dropping one is a silent false negative."""
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")

        _print_workspace_summary(mixed_outcomes, opts, time.time())

        out = _plain(capsys.readouterr().out)
        assert "3 finding path(s) could not be expressed" in out
        assert "they are still reported" in out

    def test_no_unconvertible_paths_means_no_notice(self, tmp_path, capsys):
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")

        _print_workspace_summary(_run_result(tmp_path), opts, time.time())

        assert "could not be expressed" not in _plain(capsys.readouterr().out)

    def test_quiet_prints_nothing_at_all(self, mixed_outcomes, tmp_path, capsys):
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out", quiet=True)

        _print_workspace_summary(mixed_outcomes, opts, time.time())

        assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# run_ash_scan -- workspace dispatch and verdict
# ---------------------------------------------------------------------------


@pytest.fixture
def quiet_logger(monkeypatch) -> _RecordingLogger:
    """Swap in a recording logger so run_ash_scan does not build a real one."""
    recorder = _RecordingLogger()
    monkeypatch.setattr(ras, "_setup_logger", lambda opts: recorder)
    return recorder


class TestRunAshScanWorkspaceDispatch:
    def test_a_clean_workspace_run_returns_the_run_result(
        self, quiet_logger, monkeypatch, tmp_path
    ):
        expected = _run_result(tmp_path, exit_code=0)
        monkeypatch.setattr(ras, "_run_workspace_mode", lambda opts, logger: expected)

        returned = run_ash_scan(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            workspace_plan=_plan(tmp_path, "api"),
            mode=RunMode.local,
            show_summary=False,
        )

        assert returned is expected

    def test_the_workspace_verdict_becomes_the_process_exit_code(
        self, quiet_logger, monkeypatch, tmp_path
    ):
        """Workspace mode owns its verdict; it is not re-derived on the host."""
        monkeypatch.setattr(
            ras,
            "_run_workspace_mode",
            lambda opts, logger: _run_result(
                tmp_path, exit_code=int(WorkspaceExitCode.ACTIONABLE_FINDINGS)
            ),
        )

        with pytest.raises(SystemExit) as excinfo:
            run_ash_scan(
                source_dir=tmp_path,
                output_dir=tmp_path / "out",
                workspace_plan=_plan(tmp_path, "api"),
                mode=RunMode.local,
                show_summary=False,
            )

        assert excinfo.value.code == 2

    def test_the_per_project_summary_is_printed_when_asked_for(
        self, quiet_logger, monkeypatch, tmp_path, capsys
    ):
        monkeypatch.setattr(
            ras,
            "_run_workspace_mode",
            lambda opts, logger: _run_result(
                tmp_path,
                projects=[
                    _project(
                        "api",
                        ProjectRunStatus.COMPLETED,
                        severity_threshold="MEDIUM",
                    )
                ],
            ),
        )

        run_ash_scan(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            workspace_plan=_plan(tmp_path, "api"),
            mode=RunMode.local,
            show_summary=True,
        )

        out = _plain(capsys.readouterr().out)
        assert "ASH Workspace Scan Completed" in out
        assert "api" in out

    def test_show_summary_off_suppresses_the_summary(
        self, quiet_logger, monkeypatch, tmp_path, capsys
    ):
        monkeypatch.setattr(
            ras, "_run_workspace_mode", lambda opts, logger: _run_result(tmp_path)
        )

        run_ash_scan(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            workspace_plan=_plan(tmp_path, "api"),
            mode=RunMode.local,
            show_summary=False,
        )

        assert "ASH Workspace Scan Completed" not in _plain(capsys.readouterr().out)

    def test_a_single_directory_scan_never_reaches_workspace_mode(
        self, quiet_logger, monkeypatch, tmp_path
    ):
        def should_not_run(opts, logger):
            raise AssertionError("workspace mode ran for a single-directory scan")

        monkeypatch.setattr(ras, "_run_workspace_mode", should_not_run)
        monkeypatch.setattr(ras, "_run_local_mode", lambda opts, logger: (None, None))

        with pytest.raises(SystemExit) as excinfo:
            run_ash_scan(
                source_dir=tmp_path,
                output_dir=tmp_path / "out",
                mode=RunMode.local,
                show_summary=False,
            )

        assert excinfo.value.code == 1


class TestRunAshScanContainerWorkspaceVerdict:
    def test_the_containers_own_verdict_is_used_rather_than_re_derived(
        self, quiet_logger, monkeypatch, tmp_path
    ):
        """`ash --workspace` already ran inside the container; re-deriving on the
        host from a merged model would answer a different question."""
        results = AshAggregatedResults(
            workspace=WorkspaceResults(
                workspace_file=(tmp_path / "dev.code-workspace").as_posix(),
                workspace_root=tmp_path.as_posix(),
                exit_code=0,
            )
        )
        monkeypatch.setattr(
            ras,
            "_run_container_mode",
            lambda opts, logger, resolved_fail_on_findings=None: results,
        )

        returned = run_ash_scan(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            workspace_plan=_plan(tmp_path, "api"),
            mode=RunMode.container,
            show_summary=False,
        )

        assert returned is results

    def test_a_failing_container_workspace_exits_with_its_own_code(
        self, quiet_logger, monkeypatch, tmp_path
    ):
        results = AshAggregatedResults(
            workspace=WorkspaceResults(
                workspace_file=(tmp_path / "dev.code-workspace").as_posix(),
                workspace_root=tmp_path.as_posix(),
                exit_code=int(WorkspaceExitCode.ACTIONABLE_FINDINGS),
            )
        )
        monkeypatch.setattr(
            ras,
            "_run_container_mode",
            lambda opts, logger, resolved_fail_on_findings=None: results,
        )

        with pytest.raises(SystemExit) as excinfo:
            run_ash_scan(
                source_dir=tmp_path,
                output_dir=tmp_path / "out",
                workspace_plan=_plan(tmp_path, "api"),
                mode=RunMode.container,
                show_summary=False,
            )

        assert excinfo.value.code == 2

    def test_a_missing_workspace_payload_is_an_internal_error_not_a_pass(
        self, quiet_logger, monkeypatch, tmp_path
    ):
        """No payload means no per-project verdict; treating that as 0 would pass
        a workspace nobody judged."""
        monkeypatch.setattr(
            ras,
            "_run_container_mode",
            lambda opts, logger, resolved_fail_on_findings=None: (
                AshAggregatedResults()
            ),
        )

        with pytest.raises(SystemExit) as excinfo:
            run_ash_scan(
                source_dir=tmp_path,
                output_dir=tmp_path / "out",
                workspace_plan=_plan(tmp_path, "api"),
                mode=RunMode.container,
                show_summary=False,
            )

        assert excinfo.value.code == int(WorkspaceExitCode.INTERNAL_ERROR)
        assert excinfo.value.code == 1
        assert any(
            "no workspace payload" in message
            for message in quiet_logger.records["error"]
        )
