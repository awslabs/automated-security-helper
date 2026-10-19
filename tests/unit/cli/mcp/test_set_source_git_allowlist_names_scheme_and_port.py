# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ASH_MCP_GIT_ALLOWED_HOSTS`` entries are ``[scheme://]host[:port]``.

A bare host allows the default port of the url's scheme, https 443 and ssh 22,
on either scheme. ``host:port`` allows that port, and ``https://host`` or
``ssh://host`` that scheme only. An entry that cannot be read allows nothing.
"""

from __future__ import annotations

import itertools
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp_tools import mcp_set_source_git

_sessions = itertools.count()


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
        calls.append({"cmd": list(cmd)})

        class _Done:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Done()

    monkeypatch.setattr(sd, "_run_git", _run)
    return calls


def _clone(url: str) -> Dict[str, Any]:
    return mcp_set_source_git(url=url, session_id=f"clone-{next(_sessions)}")


ALLOWED = [
    ("git.example.com", "https://git.example.com/r.git"),
    ("git.example.com", "https://git.example.com:443/r.git"),
    ("git.example.com", "ssh://git@git.example.com/r.git"),
    ("git.example.com", "ssh://git@git.example.com:22/r.git"),
    ("git.example.com", "git@git.example.com:team/r.git"),
    ("Git.Example.COM", "https://git.example.com/r.git"),
    ("git.example.com.", "https://git.example.com/r.git"),
    ("other.example.org, git.example.com", "https://git.example.com/r.git"),
    ("git.example.com:8443", "https://git.example.com:8443/r.git"),
    ("git.example.com:8443", "ssh://git@git.example.com:8443/r.git"),
    ("Git.Example.COM:443", "https://git.example.com/r.git"),
    ("git.example.com:22", "git@git.example.com:team/r.git"),
    ("https://git.example.com", "https://git.example.com/r.git"),
    ("https://git.example.com:8443", "https://git.example.com:8443/r.git"),
    ("ssh://git.example.com", "ssh://git@git.example.com/r.git"),
    ("ssh://git.example.com", "git@git.example.com:team/r.git"),
    ("ssh://git.example.com:2222", "ssh://git@git.example.com:2222/r.git"),
]

REFUSED = [
    # A bare host is the default port, not every port.
    ("git.example.com", "https://git.example.com:6379/r.git"),
    ("git.example.com", "ssh://git@git.example.com:2222/r.git"),
    ("git.example.com", "https://git.example.com:22/r.git"),
    ("git.example.com", "ssh://git@git.example.com:443/r.git"),
    # A named port is that port only.
    ("git.example.com:8443", "https://git.example.com/r.git"),
    ("git.example.com:8443", "https://git.example.com:9443/r.git"),
    ("git.example.com:8443", "git@git.example.com:team/r.git"),
    ("git.example.com:22", "https://git.example.com/r.git"),
    # A named scheme is that scheme only.
    ("https://git.example.com", "ssh://git@git.example.com/r.git"),
    ("https://git.example.com", "git@git.example.com:team/r.git"),
    ("ssh://git.example.com", "https://git.example.com/r.git"),
    ("ssh://git.example.com:2222", "https://git.example.com:2222/r.git"),
    ("https://git.example.com", "https://git.example.com:8443/r.git"),
    # An entry that cannot be read allows nothing.
    ("git.example.com:abc", "https://git.example.com/r.git"),
    ("git.example.com:", "https://git.example.com/r.git"),
    ("git.example.com:99999", "https://git.example.com/r.git"),
    ("http://git.example.com", "https://git.example.com/r.git"),
    ("gopher://git.example.com", "https://git.example.com/r.git"),
    ("*.example.com", "https://git.example.com/r.git"),
    # The host still has to be the url's.
    ("example.com:8443", "https://git.example.com:8443/r.git"),
    ("other.example.org:8443", "https://git.example.com:8443/r.git"),
]


@pytest.mark.parametrize("entries, url", ALLOWED)
def test_an_entry_allows_the_scheme_and_port_it_names(
    entries, url, git, monkeypatch
) -> None:
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", entries)

    result = _clone(url)

    assert result.get("success") is True, result
    assert git, "git never ran for an allowed url"


@pytest.mark.parametrize("entries, url", REFUSED)
def test_an_entry_does_not_allow_another_scheme_or_port(
    entries, url, git, monkeypatch
) -> None:
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", entries)

    result = _clone(url)

    assert result.get("success") is False, result
    assert result.get("error_type") == "clone_host_not_permitted", result
    assert not git, "git ran for a refused url"


def test_the_refusal_for_a_listed_host_names_the_scheme_and_port(
    git, monkeypatch
) -> None:
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")

    result = _clone("https://git.example.com:6379/r.git")

    assert "6379" in result.get("error", ""), result
    assert "https" in result.get("error", ""), result


def test_the_refusal_for_an_unlisted_host_names_the_host(git, monkeypatch) -> None:
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")

    result = _clone("https://other.example.org/r.git")

    assert "other.example.org" in result.get("error", ""), result


def test_an_unset_list_allows_no_remote(git) -> None:
    result = _clone("https://git.example.com/r.git")

    assert result.get("error_type") == "clone_host_not_permitted", result
    assert not git
