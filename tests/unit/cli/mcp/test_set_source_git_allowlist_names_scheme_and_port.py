# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ASH_MCP_GIT_ALLOWED_HOSTS`` entries are ``[scheme://]host[:port]``.

A bare host allows the default port of the url's scheme, https 443 and ssh 22,
on either scheme. ``host:port`` allows that port, and ``https://host`` or
``ssh://host`` that scheme only. An entry that cannot be read allows nothing.
"""

from __future__ import annotations

import itertools
import logging
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp_tools import mcp_set_source_git
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

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


#: 8443 written in digits that are not ASCII. ``int`` reads both as 8443.
_ARABIC_INDIC_8443 = (
    "\N{ARABIC-INDIC DIGIT EIGHT}\N{ARABIC-INDIC DIGIT FOUR}"
    "\N{ARABIC-INDIC DIGIT FOUR}\N{ARABIC-INDIC DIGIT THREE}"
)
_FULLWIDTH_8443 = (
    "\N{FULLWIDTH DIGIT EIGHT}\N{FULLWIDTH DIGIT FOUR}"
    "\N{FULLWIDTH DIGIT FOUR}\N{FULLWIDTH DIGIT THREE}"
)

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
    # Digits of another script are digits to str.isdigit and to int, but not a port.
    (f"git.example.com:{_ARABIC_INDIC_8443}", "https://git.example.com:8443/r.git"),
    (f"git.example.com:{_FULLWIDTH_8443}", "https://git.example.com:8443/r.git"),
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


@pytest.mark.parametrize("port", ["0", "00", "000"])
def test_an_entry_naming_port_zero_allows_nothing(port, monkeypatch) -> None:
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", f"git.example.com:{port}")

    assert sd._git_allowed_entries() == []
    assert sd.git_allowed_hosts() == frozenset()


@pytest.mark.parametrize(
    "entry, expected",
    [
        ("git.example.com:1", ("git.example.com", 1)),
        ("git.example.com:65535", ("git.example.com", 65535)),
    ],
)
def test_the_ends_of_the_port_range_are_still_read(
    entry, expected, monkeypatch
) -> None:
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", entry)

    assert [(host, port) for _, host, port in sd._git_allowed_entries()] == [expected]


@pytest.mark.parametrize(
    "url",
    [
        "https://git.example.com:0/r.git",
        "ssh://git@git.example.com:0/r.git",
        "ssh://git@git.example.com:00/r.git",
    ],
)
def test_a_url_naming_port_zero_is_refused(url, git, monkeypatch) -> None:
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com,git.example.com:0")

    with pytest.raises(ValueError):
        sd.remote_clone_endpoint(url)
    result = _clone(url)

    assert result.get("success") is False, result
    assert result.get("error_type") == "clone_url_not_permitted", result
    assert not git, "git ran for a url naming port 0"


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


def test_an_entry_that_cannot_be_read_is_logged_once_by_its_position(
    monkeypatch, caplog
) -> None:
    """The dropped entry is named by position, not by its text, so the operator
    learns which one was skipped without the log quoting the list."""
    monkeypatch.setenv(
        "ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com, git.example.com:abc"
    )

    with caplog.at_level(logging.WARNING, logger=ASH_LOGGER.name):
        entries = sd._git_allowed_entries()

    assert entries == [(None, "git.example.com", None)]
    warnings = [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING
    ]
    assert len(warnings) == 1, warnings
    assert "ASH_MCP_GIT_ALLOWED_HOSTS" in warnings[0]
    assert "entry 2" in warnings[0]
    assert "abc" not in warnings[0]


def test_a_list_that_reads_whole_logs_nothing(monkeypatch, caplog) -> None:
    """Control for the warning: every entry readable, no record."""
    monkeypatch.setenv(
        "ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com, ssh://git.example.com:2222"
    )

    with caplog.at_level(logging.WARNING, logger=ASH_LOGGER.name):
        entries = sd._git_allowed_entries()

    assert len(entries) == 2
    assert [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING
    ] == []
