# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The host ``ASH_MCP_GIT_ALLOWED_HOSTS`` is checked against is the host ssh dials.

``test_set_source_git_host_allowlist.py`` compares ``remote_clone_host`` with an
expected string. These run the real tool and the real git, with ssh replaced by
a recorder, and ask the real ``ssh -G`` which host the argument git passed
resolves to. Every url the tool accepts must make ssh dial exactly the host the
allowlist was checked against, and every url it refuses must never reach ssh.
An ``ssh://`` url with ``%``, ``?``, ``#``, ``[`` or ``]`` before the path is
refused.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp_tools import mcp_set_source_git
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS

_RECORDER = """\
import json
import sys

argv = sys.argv[1:]
if "-G" in argv:
    # git's probe for which ssh this is; answering it makes git use OpenSSH options.
    sys.exit(0)
with open({record!r}, "a", encoding="utf-8") as record:
    record.write(json.dumps(argv) + "\\n")
sys.exit(1)
"""

URLS = [
    "ssh://allowed.example/team/repo.git",
    "ssh://git@allowed.example/team/repo.git",
    "ssh://git@allowed.example:2222/team/repo.git",
    "ssh://Allowed.Example./team/repo.git",
    "ssh://other.example%2f@allowed.example/repo",
    "ssh://other.example%2F@allowed.example/repo",
    "ssh://allowed.example#@other.example/repo",
    "ssh://allowed.example?@other.example/repo",
    "ssh://other.example:2222%2f@allowed.example/repo",
    "ssh://allowed.example%23@other.example/repo",
    "ssh://user@other.example@allowed.example/repo",
    "ssh://allowed.example:22@other.example/repo",
    "ssh://[allowed.example]/repo",
    "git@allowed.example:team/repo.git",
    "allowed.example:team/repo.git",
    "other.example%2f@allowed.example:repo",
    "allowed.example#@other.example:repo",
    "allowed.example?@other.example:repo",
    "user@other.example@allowed.example:repo",
]


@pytest.fixture
def ssh_calls(tmp_path, monkeypatch) -> Path:
    record = tmp_path / "ssh-calls.jsonl"
    recorder = tmp_path / "record_ssh.py"
    recorder.write_text(_RECORDER.format(record=str(record)), encoding="utf-8")
    monkeypatch.setattr(
        sd,
        "_GIT_SSH_COMMAND",
        f"{shlex.quote(sys.executable)} {shlex.quote(str(recorder))}",
    )
    return record


def _recorded(record: Path) -> List[List[str]]:
    if not record.exists():
        return []
    return [json.loads(line) for line in record.read_text().splitlines() if line]


def _host_ssh_dials(destination: str) -> str:
    ssh = shutil.which("ssh")
    assert ssh, "ssh is required to read the host ssh would connect to"
    printed = subprocess.run(
        [ssh, "-F", os.devnull, "-G", destination],
        capture_output=True,
        text=True,
        check=False,
        env={k: v for k, v in os.environ.items() if k != "SSH_AUTH_SOCK"},
        timeout=CHILD_TIMEOUT_SECONDS,
    ).stdout
    for line in printed.splitlines():
        key, _, value = line.partition(" ")
        if key.lower() == "hostname":
            return value.lower().rstrip(".")
    raise AssertionError(f"ssh -G printed no hostname for {destination!r}")


@pytest.mark.parametrize("url", URLS)
def test_ssh_dials_the_host_the_allowlist_was_checked_against(
    url, ssh_calls, monkeypatch
) -> None:
    assert shutil.which("git"), "git is required to see what git passes to ssh"
    try:
        checked = sd.remote_clone_host(url)
    except ValueError:
        checked = None
    # Allow exactly the host ASH reads, so a refusal can only come from the url.
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", checked or "allowed.example")

    result = mcp_set_source_git(url=url, session_id="clone-session")

    calls = _recorded(ssh_calls)
    if checked is None:
        assert result.get("success") is False, result
        assert calls == [], f"a refused url reached ssh: {calls}"
        return
    assert calls, f"git never ran ssh for an accepted url: {result}"
    for argv in calls:
        # git passes [options...] <destination> <remote command>.
        assert _host_ssh_dials(argv[-2]) == checked, (url, argv)


@pytest.mark.parametrize(
    "url", ["ssh://[allowed.example]/repo", "https://[allowed.example]/repo"]
)
def test_a_url_python_cannot_split_is_refused_rather_than_raised(
    url, ssh_calls, monkeypatch
) -> None:
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "allowed.example")

    result = mcp_set_source_git(url=url, session_id="clone-session")

    assert result.get("success") is False, result
    assert _recorded(ssh_calls) == []
