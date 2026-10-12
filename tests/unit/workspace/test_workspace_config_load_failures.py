# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Workspace mode refuses a project config it cannot load, with exit 3.

A workspace reads configs in two places: the resolver, for each project's own
config and for the default config (``--config`` / an MCP profile) a project without
one falls back to, and the executor, which resolves each project's config again at
scan time. Both must refuse a config file that is named but missing, or present but
unparseable, the way they refuse a schema-invalid one, so no project is planned
or scanned with the built-in defaults in place of its config.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import WorkspaceExitCode
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    execute_workspace,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan
from automated_security_helper.workspace.resolver import resolve_workspace

GOOD_YAML = """\
global_settings:
  suppressions:
    - rule_id: B101
      path: "**"
      reason: fixture
"""
BAD_YAML = GOOD_YAML + "  extra: [unclosed\n"
BAD_JSON = '{"project_name": "api",'
NON_UTF8 = b"project_name: api\n# \xff\xfe\n"


@pytest.fixture(autouse=True)
def _no_ash_config_variable(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _write(path: Path, content: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def _workspace(root: Path, *keys: str) -> Path:
    for key in keys:
        (root / key).mkdir(parents=True, exist_ok=True)
    path = root / "team.code-workspace"
    path.write_text(
        json.dumps({"folders": [{"path": key} for key in keys]}), encoding="utf-8"
    )
    return path


class TestResolver:
    @pytest.mark.parametrize(
        ("relative", "content"),
        [
            pytest.param(".ash/ash.yaml", BAD_YAML, id="yaml_syntax"),
            pytest.param(".ash.json", BAD_JSON, id="json_syntax"),
            pytest.param(".ash/.ash.yaml", NON_UTF8, id="not_utf8"),
        ],
    )
    def test_project_config_that_cannot_be_parsed_is_refused(
        self, tmp_path, relative, content
    ):
        workspace = _workspace(tmp_path, "api")
        _write(tmp_path / "api" / relative, content)

        with pytest.raises(ASHConfigValidationError) as excinfo:
            resolve_workspace(workspace)

        assert "api" in str(excinfo.value)

    def test_missing_default_config_is_refused(self, tmp_path):
        """The file a project without its own config is told to use must exist."""
        workspace = _workspace(tmp_path, "api")

        with pytest.raises(ASHConfigValidationError, match="profile.yaml"):
            resolve_workspace(workspace, default_config=tmp_path / "profile.yaml")

    def test_control_schema_invalid_project_config_is_already_refused(self, tmp_path):
        workspace = _workspace(tmp_path, "api")
        _write(tmp_path / "api" / ".ash" / "ash.yaml", "global_settings: 7\n")

        with pytest.raises(ASHConfigValidationError):
            resolve_workspace(workspace)

    def test_control_project_without_a_config_takes_the_default(self, tmp_path):
        workspace = _workspace(tmp_path, "api")

        plan = resolve_workspace(workspace)

        assert plan.projects[0].config_source is None


class _RecordingOrchestrator:
    """Stands in for the orchestrator; records the config each project was given."""

    built: List[Dict[str, Any]] = []
    lock = threading.Lock()

    def __init__(self, **kwargs: Any) -> None:
        config = kwargs["resolved_config"]
        with _RecordingOrchestrator.lock:
            _RecordingOrchestrator.built.append(
                {
                    "project": Path(kwargs["source_dir"]).name,
                    "suppressions": len(config.global_settings.suppressions or []),
                }
            )

    @classmethod
    def create(cls, **kwargs: Any) -> "_RecordingOrchestrator":
        return cls(**kwargs)

    def execute_scan(self, phases=None):
        return AshAggregatedResults()


@pytest.fixture
def recording_orchestrator():
    _RecordingOrchestrator.built = []
    yield _RecordingOrchestrator
    _RecordingOrchestrator.built = []


def _plan(root: Path, config_source: str | None = None) -> WorkspacePlan:
    project = root / "api"
    (project / "src").mkdir(parents=True, exist_ok=True)
    (project / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace_file = _workspace(root, "api")
    return WorkspacePlan(
        workspace_file=workspace_file.as_posix(),
        workspace_root=root.as_posix(),
        projects=[
            ProjectPlan(
                key="api",
                relative_path="api",
                path=project.as_posix(),
                label="api",
                display_label="api",
                severity_threshold="MEDIUM",
                config_source=config_source,
            )
        ],
    )


def _execute(root: Path, plan: WorkspacePlan, **settings: Any):
    return execute_workspace(
        plan,
        ProjectScanSettings(output_dir=root / "out", phases=("scan",), **settings),
        orchestrator_factory=_RecordingOrchestrator.create,
    )


class TestExecutor:
    def test_missing_default_config_fails_the_project_with_exit_three(
        self, tmp_path, recording_orchestrator
    ):
        root = tmp_path / "ws"
        plan = _plan(root)

        outcome = _execute(
            root, plan, default_config_path=str(tmp_path / "profile.yaml")
        )

        assert recording_orchestrator.built == [], (
            f"the project was scanned with {recording_orchestrator.built}"
        )
        assert outcome.payload.projects[0].invalid_config is True
        assert outcome.exit_code == WorkspaceExitCode.INVALID_PROJECT_CONFIG

    def test_unparseable_project_config_fails_the_project_with_exit_three(
        self, tmp_path, recording_orchestrator
    ):
        """The file the plan recorded no longer parses when the scan starts."""
        root = tmp_path / "ws"
        config = _write(root / "api" / ".ash" / "ash.yaml", BAD_YAML)
        plan = _plan(root, config_source=config.as_posix())

        outcome = _execute(root, plan)

        assert recording_orchestrator.built == [], (
            f"the project was scanned with {recording_orchestrator.built}"
        )
        assert outcome.payload.projects[0].invalid_config is True
        assert outcome.exit_code == WorkspaceExitCode.INVALID_PROJECT_CONFIG

    def test_control_loadable_default_config_reaches_the_scan(
        self, tmp_path, recording_orchestrator
    ):
        root = tmp_path / "ws"
        plan = _plan(root)
        profile = _write(tmp_path / "profile.yaml", GOOD_YAML)

        _execute(root, plan, default_config_path=str(profile))

        assert recording_orchestrator.built == [{"project": "api", "suppressions": 1}]


@pytest.fixture
def scan_started(monkeypatch) -> List[str]:
    """Replace each project's scan with a probe that records the project name."""
    started: List[str] = []

    def _probe(self, phases=None):
        started.append(Path(self.source_dir).name)
        return AshAggregatedResults()

    monkeypatch.setattr(ASHScanOrchestrator, "execute_scan", _probe)
    return started


def _cli(root: Path, *args: str):
    return CliRunner().invoke(
        app,
        [
            "scan",
            "--no-progress",
            "--workspace",
            str(root / "team.code-workspace"),
            "--output-dir",
            str(root / "out"),
            *args,
        ],
    )


class TestAshScanWorkspaceCommand:
    def test_dry_run_with_an_unparseable_project_config_exits_three(
        self, tmp_path, monkeypatch, scan_started
    ):
        monkeypatch.chdir(tmp_path)
        _workspace(tmp_path, "api")
        _write(tmp_path / "api" / ".ash" / ".ash.yaml", BAD_YAML)

        result = _cli(tmp_path, "--dry-run")

        assert scan_started == []
        assert result.exit_code == 3, result.output[-2000:]

    def test_dry_run_with_a_workspace_root_config_that_does_not_parse_exits_three(
        self, tmp_path, monkeypatch, scan_started
    ):
        """The workspace root's config sets how the run executes, and the real run
        refuses it with exit 3; the dry run must not report the plan as fine."""
        monkeypatch.chdir(tmp_path)
        _workspace(tmp_path, "api", "web")
        _write(tmp_path / "api" / ".ash" / ".ash.yaml", GOOD_YAML)
        _write(tmp_path / "web" / ".ash" / ".ash.yaml", GOOD_YAML)
        _write(
            tmp_path / ".ash" / ".ash.yaml", "workspace:\n  max_parallel_projects: [\n"
        )

        result = _cli(tmp_path, "--dry-run")

        assert scan_started == []
        assert result.exit_code == 3, result.output[-2000:]
        assert ".ash.yaml" in result.output

    def test_control_dry_run_with_a_loadable_project_config_exits_zero(
        self, tmp_path, monkeypatch, scan_started
    ):
        monkeypatch.chdir(tmp_path)
        _workspace(tmp_path, "api")
        _write(tmp_path / "api" / ".ash" / ".ash.yaml", GOOD_YAML)

        result = _cli(tmp_path, "--dry-run")

        assert scan_started == []
        assert result.exit_code == 0, result.output[-2000:]


def _api_workspace_scan(root: Path, config: str | None):
    """run_ash_scan in workspace mode, as ``ash scan --workspace`` calls it.

    Returns the SystemExit code, or None when it returned. Called directly rather
    than through CliRunner: there, a workspace scan that gets as far as execution
    ends with CliRunner itself raising "I/O operation on closed file" while it
    reads the captured output, so the exit code is never seen.
    """
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    plan = resolve_workspace(root / "team.code-workspace")
    try:
        run_ash_scan(
            source_dir=str(root),
            output_dir=str(root / "out"),
            config=config,
            workspace_plan=plan,
            show_summary=False,
            progress=False,
        )
    except SystemExit as exc:
        return exc.code
    return None


class TestRunAshScanWorkspaceMode:
    """``--config`` in workspace mode is the default for a project without one."""

    def test_missing_config_exits_three(self, tmp_path, scan_started):
        _workspace(tmp_path, "api")

        status = _api_workspace_scan(tmp_path, str(tmp_path / "nope.yaml"))

        assert scan_started == [], f"projects scanned: {scan_started}"
        assert status == 3

    def test_control_loadable_config_reaches_the_scan(self, tmp_path, scan_started):
        _workspace(tmp_path, "api")
        profile = _write(tmp_path / "profile.yaml", GOOD_YAML)

        status = _api_workspace_scan(tmp_path, str(profile))

        assert scan_started == ["api"]
        assert status != 3
