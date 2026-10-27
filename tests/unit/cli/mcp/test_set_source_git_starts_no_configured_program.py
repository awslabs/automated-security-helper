# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""set_source_git's clone, fetch and checkout start no program git config names.

The MCP server clones a delivered repository into the session's workspace and
checks out the requested ref. git config can name programs for those commands
to start: ``core.hooksPath``, where git looks for the post-checkout hook that a
clone and a checkout run, and ``core.fsmonitor``, which git runs when it
refreshes the index. Each command is built by ``utils/git_command.git_argv``,
whose ``-c core.fsmonitor=false -c core.hooksPath=/dev/null`` outrank every
config file. Here the global config sets both to commands that leave a marker;
the first test proves with plain git that the marker appears.
"""

from __future__ import annotations

import os
import shlex
import stat
import subprocess  # nosec B404
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd

_SESSION = "session-hooks"


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(  # nosec B603 B607 -- list args, no shell, fixture repos only
        [
            "git",
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            *args,
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )


def _marks(marker: Path) -> int:
    return marker.read_text(encoding="utf-8").count("ran") if marker.exists() else 0


@pytest.fixture
def delivery(tmp_path, monkeypatch):
    """A local repository to deliver, tagged v1, and a global git config whose
    post-checkout hook and fsmonitor leave a marker.

    Returns:
        (source, workspace_root, marker)
    """
    marker = tmp_path / "ran.txt"
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    hook = hooks / "post-checkout"
    hook.write_text(
        f"#!/bin/sh\necho ran >> {shlex.quote(marker.as_posix())}\n", encoding="utf-8"
    )
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR)
    config = tmp_path / "gitconfig"
    fsmonitor = f"echo ran >> {shlex.quote(marker.as_posix())}; false"
    config.write_text(
        "[core]\n"
        f"\thooksPath = {hooks.as_posix()}\n"
        f'\tfsmonitor = "{fsmonitor}"\n'
        '[protocol "file"]\n'
        "\tallow = always\n",
        encoding="utf-8",
    )
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    source = tmp_path / "source-repo"
    source.mkdir()
    _git(source, "init", "-q")
    (source / "README.md").write_text("delivered\n", encoding="utf-8")
    _git(source, "add", "README.md")
    _git(source, "commit", "-qm", "one")
    _git(source, "tag", "v1")
    return source, tmp_path / "workspaces", marker


@pytest.mark.skipif(os.name == "nt", reason="the marker hook is a shell script")
def test_plain_git_runs_the_configured_hook_and_fsmonitor(delivery, tmp_path):
    """The control: the same clone without the options leaves the marker."""
    source, _workspace, marker = delivery

    subprocess.run(  # nosec B603 B607 -- the control, plain git
        ["git", "clone", "--", str(source), str(tmp_path / "plain-clone")],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        check=True,
        timeout=60,
    )

    assert _marks(marker) > 0


@pytest.mark.skipif(os.name == "nt", reason="the marker hook is a shell script")
@pytest.mark.parametrize("ref", [None, "v1"], ids=["default-branch", "at-a-ref"])
def test_set_source_git_runs_no_configured_program(delivery, ref):
    source, workspace, marker = delivery

    target = sd.set_source_git(
        url=str(source), ref=ref, workspace_root=workspace, session_id=_SESSION
    )
    try:
        assert (target / "README.md").is_file()
        assert _marks(marker) == 0
    finally:
        sd.clear_source(_SESSION, workspace_root=workspace)
