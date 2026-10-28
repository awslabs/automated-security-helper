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
from types import SimpleNamespace
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
        # pragma: allowlist nextline secret
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


def test_every_git_command_follows_no_http_redirect_and_skips_lfs_smudge(
    git, monkeypatch
) -> None:
    """Every git command ``set_source_git`` builds -- the clone, the fetch and the
    checkout -- carries ``-c http.followRedirects=false`` before its subcommand and
    runs with ``GIT_LFS_SKIP_SMUDGE=1`` in its environment. The checkout does not
    usually reach the network, so the settings ride every command rather than only
    the ones documented as contacting the remote."""
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")

    result = mcp_set_source_git(
        url="https://git.example.com/team/repo.git", ref="main", session_id="s-1"
    )

    assert result.get("success") is True, result
    assert len(git) == 3, git
    for subcommand in ("clone", "fetch", "checkout"):
        hit = next((call for call in git if subcommand in call["cmd"]), None)
        assert hit is not None, (subcommand, git)
        argv, env = hit["cmd"], hit["env"]
        assert "http.followRedirects=false" in argv, argv
        setting = argv.index("http.followRedirects=false")
        assert argv[setting - 1] == "-c", argv
        assert setting < argv.index(subcommand), argv
        assert env.get("GIT_LFS_SKIP_SMUDGE") == "1", (subcommand, env)


def test_every_git_command_starts_no_background_maintenance(git, monkeypatch) -> None:
    """Fails on a delivery whose git may start ``gc --auto`` or a maintenance run
    after the clone or the fetch: that process runs detached inside the staging
    directory and, on Windows, a handle it holds there makes the rename of the
    finished clone into place fail. Every command carries both settings before its
    subcommand."""
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")

    result = mcp_set_source_git(
        url="https://git.example.com/team/repo.git", ref="main", session_id="s-1"
    )

    assert result.get("success") is True, result
    assert len(git) == 3, git
    for subcommand in ("clone", "fetch", "checkout"):
        hit = next((call for call in git if subcommand in call["cmd"]), None)
        assert hit is not None, (subcommand, git)
        argv = hit["cmd"]
        for setting in ("gc.auto=0", "maintenance.auto=false"):
            assert setting in argv, (subcommand, argv)
            position = argv.index(setting)
            assert argv[position - 1] == "-c", argv
            assert position < argv.index(subcommand), argv


def test_a_server_that_turns_lfs_smudging_on_does_not_reach_git(
    git, monkeypatch
) -> None:
    """The environment git runs with is built from an allowlist, so a
    ``GIT_LFS_SKIP_SMUDGE=0`` in the server's own environment does not turn the
    transfer back on."""
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")
    monkeypatch.setenv("GIT_LFS_SKIP_SMUDGE", "0")

    result = mcp_set_source_git(
        url="https://git.example.com/team/repo.git", session_id="s-1"
    )

    assert result.get("success") is True, result
    assert git[0]["env"]["GIT_LFS_SKIP_SMUDGE"] == "1", git[0]["env"]


def test_a_failed_https_clone_says_redirects_are_not_followed(monkeypatch) -> None:
    """A host that answers with a redirect makes git refuse it, and the message
    git prints says nothing of why. The client is told what to give instead."""
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")

    class _Failed:
        returncode = 128
        stdout = ""
        stderr = "fatal: unable to access: The requested URL returned error: 302"

    monkeypatch.setattr(sd, "_run_git", lambda cmd, **kwargs: _Failed())

    result = mcp_set_source_git(
        url="https://git.example.com/team/repo", session_id="s-1"
    )

    assert result.get("success") is False, result
    assert result.get("error_type") == "git_clone_failed", result
    assert "returned error: 302" in result["error"], result
    assert "HTTP redirects are not followed" in result["error"], result
    assert "the .git suffix" in result["error"], result


@pytest.mark.parametrize(
    "git_says",
    [
        "fatal: write error: No space left on device",
        (
            "error: unable to write file pack-1.pack\nfatal: There is not enough "
            "space on the disk."
        ),
    ],
    ids=["posix", "windows"],
)
def test_a_clone_that_ran_out_of_disk_says_a_redelivery_needs_room_for_both_trees(
    monkeypatch, workspace, git_says
) -> None:
    """A re-delivery clones beside the source already delivered, so a repository that
    fits once may not fit twice, and git's own words say only that the disk is full.
    The client is told what to do about it, after git's text."""
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")
    _a_delivered_source(workspace)
    monkeypatch.setattr(
        sd,
        "_run_git",
        lambda cmd, **kwargs: SimpleNamespace(
            returncode=128, stdout="", stderr=git_says
        ),
    )

    result = mcp_set_source_git(
        url="https://git.example.com/team/repo.git", session_id="s-1"
    )

    assert result.get("success") is False, result
    assert result.get("error_type") == "git_clone_failed", result
    assert git_says.splitlines()[-1] in result["error"], result
    assert "room for both" in result["error"], result
    assert "clear_source" in result["error"], result
    # A full disk is not a redirect, though this is an https url.
    assert "redirect" not in result["error"], result


def _a_delivered_source(workspace: Path) -> None:
    """What a re-delivery to session ``s-1`` finds: a tree at ``source/``."""
    (workspace / "s-1" / "source").mkdir(parents=True)


def _git_that_runs_out_of_disk_at(
    monkeypatch,
    step: str,
    says: str = "error: unable to write file a.py: No space left on device",
) -> List[List[str]]:
    """Git answers 128 with ``says`` at ``step`` (clone, fetch or checkout) and 0 at
    the others. Returns the commands it was asked to run."""
    commands: List[List[str]] = []

    def run_git(cmd, **kwargs):
        commands.append(list(cmd))
        if step in cmd:
            return SimpleNamespace(returncode=128, stdout="", stderr=says)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(sd, "_run_git", run_git)
    return commands


def test_a_checkout_that_ran_out_of_disk_says_the_same(monkeypatch, workspace) -> None:
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")
    _a_delivered_source(workspace)
    _git_that_runs_out_of_disk_at(monkeypatch, "checkout")

    result = mcp_set_source_git(
        url="https://git.example.com/team/repo.git", ref="main", session_id="s-1"
    )

    assert result.get("error_type") == "git_checkout_failed", result
    assert "No space left on device" in result["error"], result
    assert "clear_source" in result["error"], result


def test_a_fetch_that_ran_out_of_disk_is_not_read_as_a_mistyped_ref(
    monkeypatch, workspace
) -> None:
    """Fails on a fetch whose failure is dropped: the checkout then runs on the ref,
    git cannot find it in the shallow clone, and the client reads ``pathspec ... did
    not match`` as a typo in the ref when the disk was full."""
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")
    _a_delivered_source(workspace)
    commands = _git_that_runs_out_of_disk_at(monkeypatch, "fetch")

    result = mcp_set_source_git(
        url="https://git.example.com/team/repo.git", ref="release", session_id="s-1"
    )

    assert result.get("success") is False, result
    assert result.get("error_type") == "git_clone_failed", result
    assert "git fetch" in result["error"], result
    assert "No space left on device" in result["error"], result
    assert "room for both" in result["error"], result
    assert not any("checkout" in cmd for cmd in commands), commands


@pytest.mark.parametrize("step", ["clone", "fetch", "checkout"])
def test_a_first_delivery_that_ran_out_of_disk_is_not_told_to_free_a_source(
    monkeypatch, step
) -> None:
    """There is no delivered source to free on a first delivery, so ``clear_source``
    would free nothing and wipe the session's workspace. The client is told only that
    the disk is full, after git's own text."""
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")
    _git_that_runs_out_of_disk_at(monkeypatch, step)

    result = mcp_set_source_git(
        url="https://git.example.com/team/repo.git", ref="main", session_id="s-1"
    )

    assert result.get("success") is False, result
    assert "No space left on device" in result["error"], result
    assert result["error"].rstrip().endswith("The disk is full."), result
    assert "clear_source" not in result["error"], result
    assert "room for both" not in result["error"], result


#: What git prints when the SERVER's disk is full: the server's own messages arrive
#: with a ``remote: `` prefix, in the server's language, and git adds its own line.
_REMOTE_DISK_FULL = (
    "remote: fatal: write error: No space left on device\n"
    "fatal: the remote end hung up unexpectedly"
)


@pytest.mark.parametrize(
    "detail, full",
    [
        ("fatal: write error: No space left on device", True),
        ("remote: fatal: write error: No space left on device", False),
        ("remote: error: No space left on device\nfatal: early EOF", False),
        ("  remote: not enough space on the disk", False),
        ("remote: Resolving deltas\nerror: No space left on device", True),
        ("error: No space left on device\nremote: Total 3 (delta 0)", True),
    ],
    ids=[
        "local",
        "remote-only",
        "remote-then-git",
        "remote-indented",
        "remote-then-local",
        "local-then-remote",
    ],
)
def test_only_a_line_git_wrote_itself_says_that_our_disk_is_full(detail, full) -> None:
    """A line the remote relayed says the remote's disk is full. A message of ours
    that comes with remote lines still counts."""
    assert sd._is_disk_full(detail) is full


def test_a_remote_that_ran_out_of_disk_is_not_told_to_clear_our_source(
    monkeypatch, workspace
) -> None:
    """Fails on a full-disk check that reads the whole of git's message: the client,
    which has a delivered source, is told to call ``clear_source`` and lose it, and
    its disk was never short."""
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")
    _a_delivered_source(workspace)
    monkeypatch.setattr(
        sd,
        "_run_git",
        lambda cmd, **kwargs: SimpleNamespace(
            returncode=128, stdout="", stderr=_REMOTE_DISK_FULL
        ),
    )

    result = mcp_set_source_git(
        url="https://git.example.com/team/repo.git", session_id="s-1"
    )

    assert result.get("error_type") == "git_clone_failed", result
    assert "remote: fatal: write error" in result["error"], result
    assert "clear_source" not in result["error"], result
    assert "room for both" not in result["error"], result
    assert "The disk is full" not in result["error"], result


def test_a_fetch_that_a_remote_could_not_serve_goes_on_to_the_checkout(
    monkeypatch,
) -> None:
    """A fetch that fails is not the end of a delivery: the ref may be in the clone
    already, and the checkout says if it is not. Only a fetch that failed for want of
    our own disk ends it."""
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")
    commands = _git_that_runs_out_of_disk_at(monkeypatch, "fetch", _REMOTE_DISK_FULL)

    result = mcp_set_source_git(
        url="https://git.example.com/team/repo.git", ref="release", session_id="s-1"
    )

    assert result.get("success") is True, result
    assert any("checkout" in cmd for cmd in commands), commands


def test_a_clone_that_failed_for_another_reason_is_not_told_about_room(
    monkeypatch,
) -> None:
    """Control: the hint is for a full disk only."""
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")
    monkeypatch.setattr(
        sd,
        "_run_git",
        lambda cmd, **kwargs: SimpleNamespace(
            returncode=128, stdout="", stderr="fatal: repository not found"
        ),
    )

    result = mcp_set_source_git(
        url="ssh://git@git.example.com/team/repo.git", session_id="s-1"
    )

    assert result.get("error_type") == "git_clone_failed", result
    assert "repository not found" in result["error"], result
    assert "clear_source" not in result["error"], result


def test_a_failed_ssh_clone_is_not_told_about_redirects(monkeypatch) -> None:
    """Control: ssh has no redirect to refuse, so its failure keeps git's words."""
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")

    class _Failed:
        returncode = 128
        stdout = ""
        stderr = "fatal: Could not read from remote repository."

    monkeypatch.setattr(sd, "_run_git", lambda cmd, **kwargs: _Failed())

    result = mcp_set_source_git(
        url="ssh://git@git.example.com/team/repo.git", session_id="s-1"
    )

    assert result.get("success") is False, result
    assert "Could not read from remote repository" in result["error"], result
    assert "redirect" not in result["error"], result


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


def test_a_clone_url_the_validator_passes_and_the_host_check_refuses_is_named(
    git, monkeypatch
) -> None:
    url = "git://git.example.com/team/repo.git"
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")
    # The shape the case needs: the validator and the local-path check let it by,
    # and only the host check refuses it.
    assert sd._validate_clone_url(url) == url
    assert sd.local_clone_path(url) is None
    with pytest.raises(ValueError):
        sd.remote_clone_host(url)

    result = mcp_set_source_git(url=url, session_id="s-1")

    assert result["success"] is False, result
    assert result["error_type"] == "clone_url_not_permitted", result
    assert result["error"], result
    assert not git


def test_the_core_function_refuses_what_every_caller_must_not_clone(git) -> None:
    for url in ("http://git.example.com/r.git", "/srv/repo", "file:///srv/repo"):
        with pytest.raises(ValueError):
            sd.set_source_git(url=url, session_id="s-1")
    assert not git


@pytest.mark.parametrize(
    "url",
    [
        "https://elsewhere.example.net/team/repo.git",
        "git@elsewhere.example.net:team/repo.git",
    ],
    ids=["https", "scp-like"],
)
@pytest.mark.parametrize(
    "allowed", [None, "git.example.com"], ids=["list-unset", "another-host-listed"]
)
def test_a_host_outside_the_allowed_set_is_refused_before_any_fetch(
    git, workspace, monkeypatch, url, allowed
) -> None:
    if allowed is not None:
        monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", allowed)

    result = mcp_set_source_git(url=url, ref="main", session_id="s-1")

    assert result.get("success") is False, result
    assert result.get("error_type") == "clone_host_not_permitted", result
    assert "elsewhere.example.net" in result["error"], result
    assert not git, git
    assert not (workspace / "s-1").exists()


@pytest.mark.parametrize(
    "url",
    [
        "http://git.example.com/r.git",
        "git://git.example.com/r.git",
        "https://[::1]/r.git",
    ],
)
def test_a_remote_url_with_no_readable_allowed_host_is_refused_before_any_fetch(
    git, workspace, monkeypatch, url
) -> None:
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")

    result = mcp_set_source_git(url=url, session_id="s-1")

    assert result.get("success") is False, result
    assert result.get("error_type") == "clone_url_not_permitted", result
    assert not git, git
    assert not (workspace / "s-1").exists()
