# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the workspace-mode CLI surface of ``ash scan``.

Resolution failures never reach the scan, and these tests assert that from the
outside -- by checking that the scan entry point is not reached and that no
output directory appears -- rather than by reading the implementation. The
success path now does reach it, so the same recorder proves the opposite: that
the resolved plan, and the workspace root as the scan root, arrive intact.

Exit codes come from ``models.workspace.WorkspaceExitCode``: 4 for a workspace
definition or policy error, 3 for a project whose own config is invalid. Every
assertion below names the enum member rather than the integer, so a test cannot
keep passing while meaning the wrong thing if the contract moves again -- which
it already has once, from 2 to 4. The one place the literal value is pinned is
``test_a_workspace_error_is_not_the_findings_exit_code``, which exists to catch
the specific regression of collapsing 4 back onto 2.
"""

import json
from pathlib import Path

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
# The exit-code contract itself
# ---------------------------------------------------------------------------


def test_a_workspace_error_is_not_the_findings_exit_code(tmp_path, no_scan):
    """The one place in this file that pins the literal value.

    Everything else names the enum member, which is what keeps those tests
    meaningful if the contract moves. But an enum-only assertion cannot catch the
    specific regression this code exists to prevent: collapsing the
    workspace-error code back onto 2. Exit 2 means a scan ran and found
    actionable findings; a workspace refusal means nothing was scanned at all. A
    CI job reading 2 as "review the findings" would treat a workspace that never
    ran as a successful scan with issues, which is fail-open.

    Asserted through the real CLI rather than off the enum, so it covers the
    value the process actually returns.
    """
    workspace = tmp_path / "dev.code-workspace"
    workspace.write_text(json.dumps({"folders": []}), encoding="utf-8")

    result = _invoke("--workspace", str(workspace), "--dry-run")

    assert result.exit_code == 4
    assert result.exit_code != WorkspaceExitCode.ACTIONABLE_FINDINGS
    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert not no_scan


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
# 1. and 12. Fail-closed definition errors surface as exit 4
# ---------------------------------------------------------------------------


def test_missing_project_is_a_workspace_error_and_names_the_path(tmp_path, no_scan):
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


def test_empty_folders_list_is_a_workspace_error(tmp_path, no_scan):
    workspace = tmp_path / "dev.code-workspace"
    workspace.write_text(json.dumps({"folders": []}), encoding="utf-8")

    result = _invoke("--workspace", str(workspace), "--dry-run")

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert not no_scan


def test_malformed_workspace_file_is_a_workspace_error(tmp_path, no_scan):
    workspace = tmp_path / "dev.code-workspace"
    workspace.write_text("{not json", encoding="utf-8")

    result = _invoke("--workspace", str(workspace), "--dry-run")

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert not no_scan


def test_a_null_character_folder_entry_is_a_workspace_error(tmp_path, no_scan):
    """Not exit 1 with a traceback, which is what pathlib's ValueError produced."""
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api", "bad\x00entry"])

    result = _invoke("--workspace", str(workspace), "--dry-run")

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert not no_scan


def test_absent_workspace_file_is_a_workspace_error(tmp_path, no_scan):
    result = _invoke("--workspace", str(tmp_path / "gone.code-workspace"), "--dry-run")

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert not no_scan


def test_incompatible_scanner_pins_are_a_workspace_error(tmp_path, no_scan):
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


def test_an_invalid_project_config_is_an_invalid_config_error(
    tmp_path, no_scan, capsys
):
    """A distinct code, because it routes to a different person than a
    workspace definition error: the workspace is fine, one project is not."""
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
# Workspace mode without --dry-run runs the scans, scoped to the plan
# ---------------------------------------------------------------------------


def test_workspace_without_dry_run_reaches_the_scan_entry_point(tmp_path, no_scan):
    """Phase 2a executes. Falling through to a single-directory scan of the
    workspace root would report a result for a scan nobody asked for, so the
    plan has to arrive at the scan entry point."""
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api"])

    result = _invoke("--workspace", str(workspace))

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    assert len(no_scan) == 1
    assert no_scan[0]["workspace_plan"] is not None


def test_the_scan_root_is_the_workspace_root_not_a_project(tmp_path, no_scan):
    """Container mode mounts source_dir at /src, and every project has to be
    reachable below it."""
    _project(tmp_path, "api")
    _project(tmp_path, "web")
    workspace = _workspace(tmp_path, ["api", "web"])

    _invoke("--workspace", str(workspace))

    assert Path(no_scan[0]["source_dir"]).resolve() == tmp_path.resolve()


def test_the_plan_handed_to_the_scan_is_the_one_dry_run_would_print(tmp_path, no_scan):
    """Resolved once. Re-resolving for execution would let the two drift, which
    is the whole reason --dry-run exists."""
    _project(tmp_path, "services/api", "project_name: Payments API\n")
    _project(tmp_path, "shared-infra")
    workspace = _workspace(tmp_path, ["services/api", "shared-infra"])

    _invoke("--workspace", str(workspace))

    plan = no_scan[0]["workspace_plan"]
    assert [p.key for p in plan.projects] == ["services-api", "shared-infra"]
    assert plan.projects[0].label == "Payments API"


def test_allow_missing_projects_reaches_the_scan_entry_point(tmp_path, no_scan):
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api", "not-cloned-yet"])

    result = _invoke("--workspace", str(workspace), "--allow-missing-projects")

    assert result.exit_code == WorkspaceExitCode.SUCCESS, result.output
    assert no_scan[0]["allow_missing_projects"] is True
    plan = no_scan[0]["workspace_plan"]
    assert [e.project for e in plan.skipped_projects] == ["not-cloned-yet"]


def test_a_definition_error_still_refuses_before_scanning(tmp_path, no_scan):
    """Execution must not weaken the fail-closed set."""
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api", "not-cloned-yet"])

    result = _invoke("--workspace", str(workspace))

    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
    assert not no_scan


def test_no_source_dir_is_passed_alongside_the_workspace_plan(tmp_path, no_scan):
    """The CLI derives source_dir from the plan; it must not also forward the
    operator's --source-dir, which is rejected earlier anyway."""
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api"])

    _invoke("--workspace", str(workspace))

    call = no_scan[0]
    assert call["source_dir"] == call["workspace_plan"].workspace_root


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
