# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tab completion of the ``ash`` entry, measured through click's completion protocol.

Typer and click answer a completion request from environment variables, with no
shell involved: ``_ASH_COMPLETE=complete_bash`` selects the bash format, and
``COMP_WORDS`` and ``COMP_CWORD`` carry the line and the word under the cursor.
Each case below starts the real entry point in a child process with that
environment and reads what it prints, so the rows hold what a user's TAB gets.

What is pinned: ``ash scan <TAB>`` offers every subject, ``fs`` and ``workspace``, and
nothing else; the subject-less form (``ash scan --mo<TAB>``) stays silent, because the
group takes no scan options of its own; ``ash scan fs --sh<TAB>`` completes the
options of ``fs``; ``ash scan workspace --<TAB>`` completes the options of
``workspace``, the three only it takes among them and none that only ``fs`` takes;
``--show-completion`` and ``--install-completion`` produce a script for a named shell.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404 - fixed argv, sys.executable, no shell
import sys
from pathlib import Path

import pytest
import typer.main
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from tests.utils.helpers import importing_this_checkout

pytestmark = pytest.mark.unit

_ENTRY = (
    "import sys\n"
    "sys.argv[0] = 'ash'\n"
    "from automated_security_helper.cli.entrypoint import main\n"
    "main()\n"
)


def _complete(words: str, cword: int, tmp_path: Path) -> list[str]:
    """The candidates the entry prints for the line *words*, cursor on word *cword*."""
    environ = {
        **os.environ,
        "_ASH_COMPLETE": "complete_bash",
        "COMP_WORDS": words,
        "COMP_CWORD": str(cword),
    }
    completed = subprocess.run(  # nosec B603 - fixed argv, no shell
        [sys.executable, "-c", importing_this_checkout(_ENTRY)],
        env=environ,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    return [line for line in completed.stdout.splitlines() if line]


def test_completion_is_live_on_the_entry_and_offers_the_root_commands(tmp_path):
    assert _complete("ash sc", 1, tmp_path) == ["scan"]


def _long_options(command) -> set[str]:
    """Every ``--`` spelling the options a click command declares are offered under."""
    return {
        spelling
        for param in command.params
        if param.param_type_name == "option" and not param.hidden
        for spelling in (*param.opts, *param.secondary_opts)
        if spelling.startswith("--")
    }


def _subjects() -> dict:
    """The subjects of ``scan``, read from the real command tree."""
    return typer.main.get_command(app).commands["scan"].commands


def test_scan_offers_its_subjects_and_nothing_else(tmp_path):
    assert _complete("ash scan ", 2, tmp_path) == ["fs", "workspace"]


def test_scan_offers_every_subject_the_cli_has(tmp_path):
    # Read from the command tree, so a subject the CLI gains is offered or this fails;
    # the literal beside it keeps an empty read of the tree from passing.
    offered = set(_complete("ash scan ", 2, tmp_path))

    assert offered == set(_subjects())
    assert {"fs", "workspace"} <= offered


def test_a_partial_subject_completes(tmp_path):
    assert _complete("ash scan f", 2, tmp_path) == ["fs"]
    assert _complete("ash scan w", 2, tmp_path) == ["workspace"]


def test_the_subject_less_form_stays_silent(tmp_path):
    assert _complete("ash scan --mo", 2, tmp_path) == []


def test_fs_options_complete(tmp_path):
    assert _complete("ash scan fs --sh", 3, tmp_path) == [
        "--show-summary",
        "--shard-index",
        "--shard-count",
    ]


def test_workspace_offers_its_own_options_and_none_that_only_fs_takes(tmp_path):
    subjects = _subjects()
    workspace_alone = _long_options(subjects["workspace"]) - _long_options(
        subjects["fs"]
    )
    fs_alone = _long_options(subjects["fs"]) - _long_options(subjects["workspace"])
    # Held to literals too, so a read of the tree that came back empty cannot pass:
    # the workspace scan's three options are its own, and the directory, archive and
    # shard options are fs's.
    assert workspace_alone == {
        "--workspace-config",
        "--allow-missing-projects",
        "--dry-run",
    }
    assert {
        "--source-dir",
        "--archive",
        "--use-existing",
        "--shard-index",
        "--shard-count",
    } <= fs_alone

    offered = set(_complete("ash scan workspace --", 3, tmp_path))

    assert workspace_alone <= offered
    assert not fs_alone & offered, sorted(fs_alone & offered)
    assert "--mode" in offered, "the options both subjects take are offered too"


@pytest.mark.parametrize(
    ("prefix", "option"),
    [
        ("--dry", "--dry-run"),
        ("--work", "--workspace-config"),
        ("--allow-m", "--allow-missing-projects"),
    ],
)
def test_a_workspace_option_completes_under_workspace_and_not_under_fs(
    tmp_path, prefix, option
):
    assert _complete(f"ash scan workspace {prefix}", 3, tmp_path) == [option]
    assert _complete(f"ash scan fs {prefix}", 3, tmp_path) == []


def test_an_option_value_choice_completes_under_fs(tmp_path):
    assert set(_complete("ash scan fs --mode ", 4, tmp_path)) == {
        "precommit",
        "container",
        "local",
        "nix",
    }


@pytest.mark.parametrize("shell", ["bash", "zsh", "fish", "powershell"])
def test_show_completion_prints_a_script_for_a_named_shell(shell):
    result = CliRunner().invoke(app, ["--show-completion", shell], prog_name="ash")

    assert result.exit_code == 0, result.output
    assert "_ASH_COMPLETE" in result.stdout


def test_install_completion_writes_under_the_home_it_is_given(tmp_path, monkeypatch):
    # A scratch HOME, so nothing of the real one is touched.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    result = CliRunner().invoke(app, ["--install-completion", "bash"], prog_name="ash")

    assert result.exit_code == 0, result.output
    written = [path for path in tmp_path.rglob("*") if path.is_file()]
    assert written, "install-completion wrote nothing under the scratch home"
    assert all(str(path).startswith(str(tmp_path)) for path in written)
