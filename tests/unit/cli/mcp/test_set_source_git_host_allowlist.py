# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How ``set_source_git`` reads a clone url's host and applies the operator's list.

``test_set_source_git_uses_no_server_credentials.py`` covers the refusals and
the environment. These pin the host parser the allowlist depends on: the host
compared is the one git connects to, a url this parser cannot state
unambiguously is refused rather than guessed at, and an allowed host does reach
git with the protocol and redirect limits in place.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp_tools import mcp_set_source_git


@pytest.fixture(autouse=True)
def workspace(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.delenv("ASH_MCP_GIT_ALLOWED_HOSTS", raising=False)
    return root


@pytest.fixture
def git(monkeypatch) -> List[Dict[str, Any]]:
    calls: List[Dict[str, Any]] = []

    def _run(cmd, **kwargs):
        calls.append({"cmd": list(cmd), "env": kwargs.get("env")})

        class _Done:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Done()

    monkeypatch.setattr(sd, "_run_git", _run)
    return calls


@pytest.mark.parametrize(
    "url, host",
    [
        ("https://Git.Example.com/team/repo.git", "git.example.com"),
        ("https://git.example.com./team/repo.git", "git.example.com"),
        ("https://user:pw@git.example.com:8443/r.git", "git.example.com"),
        ("https://git.example.com@other.example.net/r.git", "other.example.net"),
        ("ssh://git@git.example.com:2222/team/repo.git", "git.example.com"),
        ("git@git.example.com:team/repo.git", "git.example.com"),
        ("git.example.com:team/repo.git", "git.example.com"),
    ],
)
def test_the_host_compared_is_the_one_git_connects_to(url, host) -> None:
    assert sd.remote_clone_host(url) == host


@pytest.mark.parametrize(
    "url",
    [
        "http://git.example.com/r.git",
        "git://git.example.com/r.git",
        "ftp://git.example.com/r.git",
        "file:///srv/repo",
        "/srv/repo",
        "https://git.example.com\\@other.example.net/r.git",
        "https://git.example.com /r.git",
        "https://[::1]/r.git",
        "https://-oProxyCommand=x/r.git",
    ],
)
def test_a_url_with_no_unambiguous_remote_host_is_refused(url) -> None:
    with pytest.raises(ValueError):
        sd.remote_clone_host(url)


def test_an_allowed_host_reaches_git_with_the_limits_in_place(git, monkeypatch) -> None:
    monkeypatch.setenv(
        "ASH_MCP_GIT_ALLOWED_HOSTS", "other.example.org, git.example.com"
    )

    result = mcp_set_source_git(
        url="https://git.example.com/team/repo.git", session_id="s-1"
    )

    assert result.get("success") is True, result
    clone = git[0]["cmd"]
    for option in (
        "credential.helper=",
        "protocol.allow=never",
        "protocol.https.allow=always",
        "protocol.ssh.allow=always",
        "http.followRedirects=false",
    ):
        assert option in clone, clone
    env = git[0]["env"]
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert "-F" in env["GIT_SSH_COMMAND"]
    assert "IdentityAgent=none" in env["GIT_SSH_COMMAND"]
    assert "StrictHostKeyChecking=yes" in env["GIT_SSH_COMMAND"]


def test_the_allowlist_matches_the_host_not_a_prefix_or_suffix(
    git, monkeypatch
) -> None:
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "example.com")

    results = [
        mcp_set_source_git(url=url, session_id="s-1")
        for url in (
            "https://git.example.com/r.git",
            "https://example.com.other.example.net/r.git",
            "https://example.com@other.example.net/r.git",
        )
    ]

    assert all(r.get("error_type") == "clone_host_not_permitted" for r in results), (
        results
    )
    assert not git


def test_the_core_function_refuses_what_every_caller_must_not_clone(git) -> None:
    for url in ("http://git.example.com/r.git", "/srv/repo", "file:///srv/repo"):
        with pytest.raises(ValueError):
            sd.set_source_git(url=url, session_id="s-1")
    assert not git
