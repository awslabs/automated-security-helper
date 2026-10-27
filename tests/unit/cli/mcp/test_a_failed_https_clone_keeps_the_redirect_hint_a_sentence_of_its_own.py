# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The redirect hint on a failed https clone is a sentence of its own.

A clone over https can fail because the host answered with a redirect, which
the git environment refuses to follow, and git's message says nothing of why. The
client is told what to do about it. The hint applies to that one cause only, and
the failure text is shown to the client as one message, so:

* the hint starts a new sentence after git's text, with a full stop between them;
* it is worded as conditional ("if the host answered with a redirect"), because
  git's text does not say a redirect was the cause;
* when git printed nothing, the message does not start with a space or a stray
  full stop.

Every cell is DISARMED: ``_run_git`` is a double and nothing runs git or reaches
the network.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp_tools import mcp_set_source_git

HINT_STARTS = "If the host answered with a redirect"


@pytest.fixture(autouse=True)
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "ws"
    root.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")
    return root


def _a_clone_that_fails_with(monkeypatch, *, stdout: str = "", stderr: str = ""):
    class _Failed:
        returncode = 128

    _Failed.stdout = stdout
    _Failed.stderr = stderr
    monkeypatch.setattr(sd, "_run_git", lambda cmd, **kwargs: _Failed())


def _the_error(url: str = "https://git.example.com/team/repo") -> str:
    result = mcp_set_source_git(url=url, session_id="s-1")
    assert result.get("success") is False, result
    assert result.get("error_type") == "git_clone_failed", result
    return result["error"]


def test_the_hint_follows_gits_text_after_a_full_stop(monkeypatch) -> None:
    _a_clone_that_fails_with(monkeypatch, stderr="fatal: repository not found")

    error = _the_error()

    assert error == (
        "git clone failed (exit 128): fatal: repository not found. "
        f"{HINT_STARTS}, HTTP redirects are not followed; give the URL the host "
        "redirects to (for example with the .git suffix)."
    ), error


def test_the_hint_does_not_double_a_full_stop_gits_text_ends_with(monkeypatch) -> None:
    _a_clone_that_fails_with(monkeypatch, stderr="fatal: the remote hung up.")

    error = _the_error()

    assert "hung up. " + HINT_STARTS in error, error
    assert ".." not in error, error


def test_the_hint_stands_alone_when_git_printed_nothing(monkeypatch) -> None:
    _a_clone_that_fails_with(monkeypatch)

    error = _the_error()

    assert error.startswith(f"git clone failed (exit 128): {HINT_STARTS}"), error
    assert "  " not in error, error


def test_a_failed_ssh_clone_gets_no_hint(monkeypatch) -> None:
    """Control: ssh has no redirect to refuse, so its failure keeps git's words
    and gains none."""
    _a_clone_that_fails_with(monkeypatch, stderr="fatal: Could not read from remote")

    error = _the_error("ssh://git@git.example.com/team/repo.git")

    assert error == "git clone failed (exit 128): fatal: Could not read from remote"
