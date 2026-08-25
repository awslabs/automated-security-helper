# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the workspace-mode CLI surface of ``ash scan``.

Phase 1 resolves and validates; it never scans. These tests assert that from
the outside -- by checking that the scan entry point is not reached and that no
output directory appears -- rather than by reading the implementation.

Exit codes come from ``models.workspace.WorkspaceExitCode``: 2 for a workspace
definition or policy error, 3 for a project whose own config is invalid.
"""

import json

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.models.workspace import WorkspaceExitCode


runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_ash_env(monkeypatch):
    """ASH_SOURCE_DIR would otherwise make --source-dir look explicitly set."""
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_CONFIG", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def no_scan(monkeypatch):
    """Replace the scan entry point with a recorder, so reaching it is visible."""
    calls = []

    def _record(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr(
        "automated_security_helper.cli.scan.run_ash_scan", _record, raising=True
    )
    return calls


def _workspace(root, folders, name="dev.code-workspace"):
    path = root / name
    path.write_text(
        json.dumps({"folders": [{"path": p} for p in folders]}), encoding="utf-8"
    )
    return path


def _project(root, relative, config=None):
    project = root / relative
    project.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (project / ".ash").mkdir(exist_ok=True)
        (project / ".ash" / "ash.yaml").write_text(config, encoding="utf-8")
    return project


def _invoke(*args):
    return runner.invoke(app, ["scan", *args])


def _all_output(result, capsys):
    """Everything the operator would see, from whichever stream captured it.

    ``pytest.ini`` sets ``log_cli = True``, and pytest's live-logging handler
    suspends and resumes global capture around every record it emits. Resuming
    re-points ``sys.stdout``/``sys.stderr`` at pytest's capture objects, which
    overwrites the streams ``CliRunner`` installed, so anything written after a
    log record lands in pytest's capture rather than in ``result.output``. Any
    test whose path emits a log record at INFO or above has to read both.
    """
    captured = capsys.readouterr()
    return result.output + captured.out + captured.err


# ---------------------------------------------------------------------------
# 7. --workspace and --source-dir are mutually exclusive
# ---------------------------------------------------------------------------


def test_workspace_with_source_dir_is_an_error(tmp_path, no_scan):
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api"])

    result = _invoke(
        "--workspace", str(workspace), "--source-dir", str(tmp_path), "--dry-run"
    )

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert "--source-dir" in result.output
    assert not no_scan


def test_source_dir_from_the_environment_also_conflicts(tmp_path, no_scan, monkeypatch):
    """Silently preferring one would hide which tree was scanned."""
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api"])
    monkeypatch.setenv("ASH_SOURCE_DIR", str(tmp_path))

    result = _invoke("--workspace", str(workspace), "--dry-run")

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert "ASH_SOURCE_DIR" in result.output
    assert not no_scan


# ---------------------------------------------------------------------------
# 8. and 9. --workspace auto
# ---------------------------------------------------------------------------


def test_auto_discovery_uses_the_single_candidate(tmp_path, no_scan, monkeypatch):
    _project(tmp_path, "api")
    _workspace(tmp_path, ["api"])
    monkeypatch.chdir(tmp_path)

    result = _invoke("--workspace", "auto", "--dry-run")

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    assert "api" in result.output
    assert not no_scan


def test_auto_discovery_with_two_candidates_lists_both(tmp_path, no_scan, monkeypatch):
    _project(tmp_path, "api")
    _workspace(tmp_path, ["api"], name="alpha.code-workspace")
    _workspace(tmp_path, ["api"], name="beta.code-workspace")
    monkeypatch.chdir(tmp_path)

    result = _invoke("--workspace", "auto", "--dry-run")

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert "alpha.code-workspace" in result.output
    assert "beta.code-workspace" in result.output
    assert not no_scan


def test_auto_discovery_with_no_candidate_is_an_error(tmp_path, no_scan, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = _invoke("--workspace", "auto", "--dry-run")

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert "code-workspace" in result.output
    assert not no_scan


def test_a_file_literally_named_auto_is_still_treated_as_discovery(
    tmp_path, no_scan, monkeypatch
):
    """``auto`` is a reserved word for this flag; a file of that name does not
    silently take priority."""
    (tmp_path / "auto").write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = _invoke("--workspace", "auto", "--dry-run")

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert "code-workspace" in result.output


# ---------------------------------------------------------------------------
# 1. and 12. Fail-closed definition errors surface as exit 2
# ---------------------------------------------------------------------------


def test_missing_project_exits_two_and_names_the_path(tmp_path, no_scan):
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api", "not-cloned-yet"])

    result = _invoke("--workspace", str(workspace), "--dry-run")

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert "not-cloned-yet" in result.output
    assert not no_scan


def test_allow_missing_projects_opts_out_and_discloses_the_skip(tmp_path, no_scan):
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api", "not-cloned-yet"])

    result = _invoke(
        "--workspace", str(workspace), "--allow-missing-projects", "--dry-run"
    )

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    assert "not-cloned-yet" in result.output
    assert "skipped" in result.output.lower()
    assert not no_scan


def test_empty_folders_list_exits_two(tmp_path, no_scan):
    workspace = tmp_path / "dev.code-workspace"
    workspace.write_text(json.dumps({"folders": []}), encoding="utf-8")

    result = _invoke("--workspace", str(workspace), "--dry-run")

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert not no_scan


def test_malformed_workspace_file_exits_two(tmp_path, no_scan):
    workspace = tmp_path / "dev.code-workspace"
    workspace.write_text("{not json", encoding="utf-8")

    result = _invoke("--workspace", str(workspace), "--dry-run")

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert not no_scan


def test_absent_workspace_file_exits_two(tmp_path, no_scan):
    result = _invoke("--workspace", str(tmp_path / "gone.code-workspace"), "--dry-run")

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert not no_scan


def test_incompatible_scanner_pins_exit_two(tmp_path, no_scan):
    _project(
        tmp_path,
        "api",
        'project_name: api\nscanners:\n  semgrep:\n    options:\n      tool_version: ">=1.125.0,<2.0.0"\n',
    )
    _project(
        tmp_path,
        "web",
        'project_name: web\nscanners:\n  semgrep:\n    options:\n      tool_version: ">=2.0.0"\n',
    )
    workspace = _workspace(tmp_path, ["api", "web"])

    result = _invoke("--workspace", str(workspace), "--dry-run")

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert "semgrep" in result.output
    assert not no_scan


def test_an_invalid_project_config_exits_three(tmp_path, no_scan, capsys):
    """A distinct code, because it routes to a different person than exit 2."""
    _project(tmp_path, "api", "project_name: api\nglobal_settings: 7\n")
    workspace = _workspace(tmp_path, ["api"])

    result = _invoke("--workspace", str(workspace), "--dry-run")

    assert result.exit_code == WorkspaceExitCode.INVALID_PROJECT_CONFIG
    # Config resolution logs at ERROR on this path, so see _all_output.
    output = _all_output(result, capsys)
    assert "api" in output
    assert "invalid configuration" in output
    assert not no_scan


# ---------------------------------------------------------------------------
# 14. --dry-run prints the plan, exits 0, and runs nothing
# ---------------------------------------------------------------------------


def test_dry_run_prints_the_plan_and_exits_zero(tmp_path, no_scan):
    _project(tmp_path, "services/api", "project_name: Payments API\n")
    _project(tmp_path, "shared-infra")
    workspace = _workspace(tmp_path, ["services/api", "shared-infra"])

    result = _invoke("--workspace", str(workspace), "--dry-run")

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    assert "services-api" in result.output
    assert "Payments API" in result.output
    assert "shared-infra" in result.output


def test_dry_run_invokes_no_scanner(tmp_path, no_scan):
    """Asserted from behaviour: the scan entry point is never reached, and no
    output directory appears anywhere under the workspace."""
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api"])
    before = sorted(p.name for p in tmp_path.rglob("*"))

    result = _invoke("--workspace", str(workspace), "--dry-run")

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    assert no_scan == []
    assert sorted(p.name for p in tmp_path.rglob("*")) == before
    assert not list(tmp_path.rglob("ash_aggregated_results.json"))
    assert not list(tmp_path.rglob("ash_output"))


def test_dry_run_works_through_the_default_callback_too(tmp_path, no_scan):
    """``ash --workspace ... --dry-run`` with no subcommand takes the callback
    path, which is a separate registration in cli/main.py."""
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api"])

    result = runner.invoke(app, ["--workspace", str(workspace), "--dry-run"])

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    assert "api" in result.output
    assert not no_scan


# ---------------------------------------------------------------------------
# Workspace mode without --dry-run must not fall through to a single-dir scan
# ---------------------------------------------------------------------------


def test_workspace_without_dry_run_refuses_rather_than_scanning_one_directory(
    tmp_path, no_scan
):
    """Phase 1 ships no execution. Falling through would scan the workspace
    root as one project and exit 0, reporting a result for a scan nobody asked
    for."""
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api"])

    result = _invoke("--workspace", str(workspace))

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert "--dry-run" in result.output
    assert not no_scan


def test_dry_run_without_workspace_is_an_error(tmp_path, no_scan):
    """Ignoring it would run a full scan for someone who asked for none."""
    result = _invoke("--source-dir", str(tmp_path), "--dry-run")

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert "--workspace" in result.output
    assert not no_scan


def test_allow_missing_projects_without_workspace_is_an_error(tmp_path, no_scan):
    result = _invoke("--source-dir", str(tmp_path), "--allow-missing-projects")

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert "--workspace" in result.output
    assert not no_scan


# ---------------------------------------------------------------------------
# A normal scan is untouched by any of this
# ---------------------------------------------------------------------------


def test_a_scan_without_workspace_flags_still_reaches_the_scan_entry_point(
    tmp_path, no_scan
):
    _project(tmp_path, "api")

    result = _invoke("--source-dir", str(tmp_path / "api"))

    assert result.exit_code == 0, result.output
    assert len(no_scan) == 1
    assert no_scan[0]["source_dir"] == str(tmp_path / "api")
