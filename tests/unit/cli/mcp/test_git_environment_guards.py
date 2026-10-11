# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each guard in the environment ``set_source_git`` runs git with holds on its own.

``test_set_source_git_uses_no_server_credentials.py`` checks the environment as a
whole. Three guards there can each hide another's absence, so these check them
one at a time:

* ssh as git runs it offers no identity file and no agent, checks host keys
  strictly against the system known-hosts file only, and has no proxy. ssh reads
  the default identity files from the account's home in the password database,
  not from ``$HOME``, so only ``IdentityFile=none`` keeps the server's own keys
  out.
* git's ``HOME`` is the session's own directory. ``HOME`` is where git and
  libcurl look for ``.netrc``, whose credentials curl sends to a matching host.
* the global git config is switched off even when ``HOME`` names a directory
  with a ``.gitconfig`` in it, so the ``HOME`` override is not the only thing
  standing between git and the server's credential helpers.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd

_REAL_RUN = subprocess.run


@pytest.fixture
def git_env(tmp_path, monkeypatch) -> Dict[str, Any]:
    """Run one delivery with git replaced, and return what git would have got."""
    server_home = tmp_path / "server-home"
    server_home.mkdir()
    (server_home / ".netrc").write_text(
        "machine git.example.invalid login server password server-secret\n"
    )
    (server_home / ".gitconfig").write_text("[credential]\n\thelper = planted-global\n")
    (server_home / ".config" / "git").mkdir(parents=True)
    (server_home / ".config" / "git" / "config").write_text(
        "[credential]\n\thelper = planted-xdg\n"
    )
    monkeypatch.setenv("HOME", str(server_home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    workspace = tmp_path / "ws"
    workspace.mkdir()
    calls: List[Dict[str, Any]] = []

    def _record(cmd, **kwargs):
        calls.append({"cmd": list(cmd), "env": dict(kwargs.get("env") or {})})

        class _Done:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Done()

    monkeypatch.setattr(sd.subprocess, "run", _record)
    sd.set_source_git(
        url="https://git.example.invalid/team/repo.git",
        workspace_root=workspace,
        session_id="guards",
    )
    assert calls, "the delivery never reached git"
    return {"env": calls[0]["env"], "cmd": calls[0]["cmd"], "server_home": server_home}


def test_ssh_offers_no_identity_and_checks_host_keys_strictly(git_env) -> None:
    ssh = shutil.which("ssh")
    if ssh is None:
        pytest.skip("ssh is not installed")
    command = shlex.split(git_env["env"]["GIT_SSH_COMMAND"])
    assert Path(command[0]).name == "ssh"

    printed = _REAL_RUN(
        [ssh, *command[1:], "-G", "git.example.invalid"],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": os.environ.get("PATH", "")},
    ).stdout.splitlines()
    settings: Dict[str, List[str]] = {}
    for line in printed:
        key, _, value = line.partition(" ")
        settings.setdefault(key.lower(), []).append(value)

    assert settings.get("identityfile") == ["none"], settings.get("identityfile")
    assert settings.get("identityagent") == ["none"]
    assert settings.get("stricthostkeychecking") == ["true"]
    assert settings.get("userknownhostsfile") == [os.devnull]
    assert settings.get("batchmode") == ["yes"]
    assert "proxycommand" not in settings and "proxyjump" not in settings


def test_git_home_is_the_session_directory_with_no_netrc(git_env) -> None:
    home = git_env["env"].get("HOME")

    assert home, "git would fall back to the account's own home and its .netrc"
    assert Path(home) != git_env["server_home"]
    assert not (Path(home) / ".netrc").exists()


def test_global_config_is_off_even_with_the_servers_home(git_env, tmp_path) -> None:
    git = shutil.which("git")
    assert git, "git is required to evaluate configuration scopes"
    env = dict(git_env["env"])
    env["HOME"] = str(git_env["server_home"])  # as if the HOME guard were gone
    outside = tmp_path / "outside-any-repo"
    outside.mkdir()
    flags: List[str] = []
    cmd = git_env["cmd"]
    for i, part in enumerate(cmd):
        if part == "-c":
            flags += ["-c", cmd[i + 1]]

    helpers = _REAL_RUN(
        [git, *flags, "config", "--get-all", "credential.helper"],
        env=env,
        cwd=outside,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.split("\n")

    assert not [h for h in helpers if h.startswith("planted-")], helpers
