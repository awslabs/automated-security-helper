"""Refusals that tell the reader what to type name the subjects of ``ash scan``.

A refusal that ends "pass '--workspace <file>'" sends the reader to the form that now
prints a deprecation line of its own, and one that says "via --source-dir" or "'ash
merge'" names spellings that are deprecated. The endings pinned here name what
replaces them:

* a workspace option given with no workspace file says to run ``ash scan workspace``;
* ``auto`` with no workspace file in the directory, or with more than one, says to name
  one with ``ash scan workspace <file>`` and, for the empty directory, to scan a single
  directory with ``ash scan fs <path>``;
* a workspace folder entry that is the workspace root says to use ``ash scan fs
  <path>`` for a single directory;
* the refusal of a shard selection beside a workspace names ``ash results merge`` and
  gives each CI job one project with ``ash scan fs <project>``.

The refusals are the engine's own, reached through the real command line; none of them
gets as far as a scan.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.models.workspace import WorkspaceExitCode

pytestmark = pytest.mark.unit

#: The spellings the refusals used to end with, none of which they may name now.
LEGACY_INSTRUCTIONS = (
    "'--workspace <file>'",
    "'--workspace auto'",
    "drop '--workspace'",
    "'--source-dir' instead",
    "via --source-dir",
    "'ash merge'",
)


def _invoke(args: list[str]):
    return CliRunner().invoke(app, args, prog_name="ash")


def _one_line(text: str) -> str:
    return " ".join(text.split())


def _names_no_legacy_spelling(text: str) -> None:
    for spelling in LEGACY_INSTRUCTIONS:
        assert spelling not in text, (spelling, text)


@pytest.fixture(autouse=True)
def _in_an_empty_directory(tmp_path, monkeypatch):
    """The working directory is where ``auto`` looks, so it holds nothing unless a row
    puts a workspace file there; no variable of the host names a file or a policy."""
    monkeypatch.chdir(tmp_path)
    for name in (
        "ASH_SOURCE_DIR",
        "ASH_OUTPUT_DIR",
        "ASH_CONFIG",
        "ASH_WORKSPACE",
        "ASH_WORKSPACE_CONFIG",
    ):
        monkeypatch.delenv(name, raising=False)


def _workspace(root: Path, name: str, folders: list[str]) -> Path:
    path = root / name
    path.write_text(
        json.dumps({"folders": [{"path": folder} for folder in folders]}),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(
    "args",
    [
        pytest.param(["scan", "--dry-run"], id="scan-dry-run"),
        pytest.param(["--dry-run"], id="bare-dry-run"),
        pytest.param(
            ["scan", "--allow-missing-projects"], id="scan-allow-missing-projects"
        ),
        pytest.param(
            ["scan", "--workspace-config", "policy.yaml"], id="scan-workspace-config"
        ),
    ],
)
def test_a_workspace_option_with_no_file_says_to_run_the_workspace_subject(args):
    result = _invoke(args)

    text = _one_line(result.output)
    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR, result.output
    assert "only applies in workspace mode" in text, text
    assert "`ash scan workspace <file>`" in text, text
    assert "`ash scan workspace auto`" in text, text
    _names_no_legacy_spelling(text)


def test_auto_with_no_workspace_file_names_the_subject_and_fs(tmp_path):
    result = _invoke(["scan", "workspace", "auto"])

    text = _one_line(result.output)
    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR, result.output
    assert "No '*.code-workspace' file found" in text, text
    assert "Name one with `ash scan workspace <file>`" in text, text
    assert "scan a single directory with `ash scan fs <path>`" in text, text
    _names_no_legacy_spelling(text)


def test_auto_with_two_workspace_files_names_the_subject_and_lists_them(tmp_path):
    _workspace(tmp_path, "a.code-workspace", ["api"])
    _workspace(tmp_path, "b.code-workspace", ["web"])

    result = _invoke(["scan", "workspace", "auto"])

    text = _one_line(result.output)
    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR, result.output
    assert "`ash scan workspace auto` needs exactly one" in text, text
    assert "Name one with `ash scan workspace <file>`:" in text, text
    assert "a.code-workspace" in text and "b.code-workspace" in text, text
    _names_no_legacy_spelling(text)


def test_a_folder_that_is_the_workspace_root_says_to_scan_the_directory_with_fs(
    tmp_path,
):
    (tmp_path / "api").mkdir()
    workspace = _workspace(tmp_path, "dev.code-workspace", [".", "api"])

    result = _invoke(["scan", "workspace", str(workspace), "--dry-run"])

    text = _one_line(result.output)
    assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR, result.output
    assert "names the workspace root itself" in text, text
    assert "use `ash scan fs <path>` instead of `ash scan workspace`" in text, text
    _names_no_legacy_spelling(text)


def test_the_shard_refusal_beside_a_workspace_names_the_merge_command_and_fs(tmp_path):
    workspace = _workspace(tmp_path, "dev.code-workspace", ["api"])

    result = _invoke(
        [
            "scan",
            "--workspace",
            str(workspace),
            "--shard-index",
            "1",
            "--shard-count",
            "2",
        ]
    )

    text = _one_line(result.output)
    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "cannot be combined with --workspace" in text, text
    assert "'ash results merge' can prove the shards" in text, text
    assert "one project with `ash scan fs <project>` and shard that" in text, text
    _names_no_legacy_spelling(text)
