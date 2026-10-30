#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Five gaps in the sandbox gates, each pinned by the input that passed it.

* A client-delivered config is judged with ``Path.resolve``, which on Python
  3.12 and older raises for a link that leads back to itself, so a scanned tree
  holding one made the scanner's construction raise.
* ``session_sandbox`` validated an id with a separator-only rule, so ids the
  registry, source delivery and the TTL sweep refuse (a control character, a
  hidden delete name) still got a sandbox root.
* A gate given a malformed id degraded to the LOCAL caller's sandbox, with the
  permissive denylist fallback and unconfined config reads.
* The session's own ``config/`` directory, spelled in another case on a
  case-insensitive volume, was not refused as a scan target: the check matched
  ancestors by identity and the directory itself by text alone.
* On Windows the gates resolved a client-named path before refusing it, which
  opens a connection to the host a UNC path names. A link is now read, hop by
  hop, and refused only when it leads to a share or cannot be read; a link to a
  local name is judged as what it names, as on every other platform.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import sandbox
from automated_security_helper.cli.mcp.sandbox import (
    ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV,
    ASH_MCP_ALLOWED_ROOTS_ENV,
    ASH_MCP_TRANSPORT_ENV,
    CONFIG_DIR_NAME,
    config_is_client_supplied,
    session_sandbox,
    validate_config_input,
    validate_scan_target_in_sandbox,
)
from automated_security_helper.cli.mcp.session_paths import hidden_deleting_name
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
)

pytestmark = pytest.mark.unit

OWN = "session-a"


@pytest.fixture(autouse=True)
def _stdio_no_grant_workspace_under_tmp(monkeypatch, tmp_path):
    monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.delenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, raising=False)
    monkeypatch.setenv(ASH_MCP_TRANSPORT_ENV, "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp"))


def _delivered(session_id: str) -> Path:
    source = session_sandbox(session_id).source_dir
    source.mkdir(parents=True, exist_ok=True)
    return source


class TestAClientConfigWithASymlinkLoopIsJudgedNotRaised:
    def test_a_self_referencing_link_in_a_delivered_tree_is_the_clients(self, tmp_path):
        """Red at the base on Python 3.12 and older: Path.resolve raised RuntimeError."""
        source = _delivered(OWN)
        loop = source / ".semgrepignore"
        loop.symlink_to(loop.name)

        assert config_is_client_supplied(loop) is True

    def test_a_self_referencing_link_outside_the_workspace_is_not(self, tmp_path):
        """Control: the same shape elsewhere is judged, as before, not raised."""
        _delivered(OWN)
        loop = tmp_path / "elsewhere" / ".semgrepignore"
        loop.parent.mkdir()
        loop.symlink_to(loop.name)

        assert config_is_client_supplied(loop) is False


class TestSessionSandboxRefusesTheIdsEveryOtherBuilderRefuses:
    @pytest.mark.parametrize(
        "session_id",
        [
            "tab\there",
            "x" * 300,
            "has space",
            hidden_deleting_name("gone"),
        ],
        ids=["control-char", "too-long", "space", "hidden-delete-shape"],
    )
    def test_an_id_the_registry_refuses_gets_no_sandbox(self, session_id):
        """Red at the base: each of these passed the separator-only rule."""
        with pytest.raises(ValueError):
            session_sandbox(session_id)

    @pytest.mark.parametrize("session_id", ["a/b", "..", "a\\b", ""])
    def test_the_separator_rule_still_holds(self, session_id):
        """Control: what the old rule refused is still refused."""
        with pytest.raises(ValueError):
            session_sandbox(session_id)

    def test_a_plain_id_still_gets_its_sandbox(self):
        assert session_sandbox("session-a").root is not None


class TestAMalformedIdDegradesToARemoteCallersSandbox:
    def test_a_malformed_id_gets_no_local_fallback(self, tmp_path):
        """Red at the base: the gate fell back to the local denylist and permitted it.

        A client that sent an id the server did not issue is not the process
        that launched the server, so it gets the operator's grant alone, which
        here is nothing.
        """
        target = tmp_path / "checkout"
        target.mkdir()

        refusal = validate_scan_target_in_sandbox(target, session_id="a/b")

        assert refusal is not None
        assert refusal.context["error_category"] == ErrorCategory.INVALID_PATH.value

    def test_a_malformed_id_still_reads_no_config_unconfined(self, tmp_path):
        config = tmp_path / "checkout" / ".ash.yaml"
        config.parent.mkdir()
        config.write_text("{}")

        assert validate_config_input(config, session_id="a/b") is not None

    def test_the_operators_grant_still_applies_to_it(self, monkeypatch, tmp_path):
        """Control: the grant is what such a caller may reach, and it may."""
        granted = tmp_path / "granted"
        granted.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(granted))

        assert validate_scan_target_in_sandbox(granted, session_id="a/b") is None

    def test_the_local_caller_with_no_id_keeps_its_fallback(self, tmp_path):
        """Control: the degrade changes nothing for the caller that named no id."""
        target = tmp_path / "checkout"
        target.mkdir()

        assert validate_scan_target_in_sandbox(target, session_id=None) is None


@pytest.fixture
def case_folding_volume(monkeypatch):
    """``os.path.samefile`` as a case-insensitive volume answers it."""
    real_samefile = os.path.samefile

    def samefile(first, second):
        if os.fspath(first).lower() == os.fspath(second).lower():
            return True
        return real_samefile(first, second)

    monkeypatch.setattr(os.path, "samefile", samefile)


class TestTheServerConfigDirIsRefusedInAnotherCase:
    def test_the_directory_itself_respelled_is_refused(self, case_folding_volume):
        """Red at the base: a path below it was refused by identity, itself by text only."""
        sandbox_of_own = session_sandbox(OWN)
        assert sandbox_of_own.root is not None
        config_dir = sandbox_of_own.root / CONFIG_DIR_NAME
        config_dir.mkdir(parents=True)
        respelled = config_dir.with_name(CONFIG_DIR_NAME.upper())

        exact = validate_scan_target_in_sandbox(config_dir, session_id=OWN)
        other_case = validate_scan_target_in_sandbox(respelled, session_id=OWN)

        assert exact is not None and "profiles the server writes" in str(exact)
        assert other_case is not None, "the respelled config/ was permitted"
        assert "profiles the server writes" in str(other_case)

    def test_the_delivered_source_is_still_permitted(self, case_folding_volume):
        """Control: the identity match does not widen to the session's own tree."""
        mine = _delivered(OWN)

        assert validate_scan_target_in_sandbox(mine, session_id=OWN) is None


class TestWindowsRefusesBeforeResolving:
    @pytest.fixture(autouse=True)
    def _on_windows(self, monkeypatch):
        monkeypatch.setattr(sandbox, "_running_on_windows", lambda: True)

    @pytest.mark.parametrize(
        "spelling", ["//server/share/tree", "\\\\server\\share\\tree"]
    )
    def test_a_network_share_is_refused_without_resolving(self, monkeypatch, spelling):
        """Red at the base: the path was resolved (the share opened) before any refusal."""
        resolved = []
        real_resolve = Path.resolve

        def recording_resolve(self, strict=False):
            resolved.append(str(self))
            return real_resolve(self, strict=strict)

        monkeypatch.setattr(Path, "resolve", recording_resolve)

        refusal = validate_scan_target_in_sandbox(spelling, session_id=OWN)

        assert refusal is not None
        assert "network share" in str(refusal)
        assert all("server" not in p for p in resolved), resolved

    @pytest.mark.parametrize(
        "spelling", ["\\\\server\\share\\tree", "//server/share/tree"]
    )
    def test_a_link_to_a_network_share_is_refused_unresolved(
        self, monkeypatch, tmp_path, spelling
    ):
        """The link's name is read, never resolved: no resolve sees the server."""
        link = tmp_path / "link"
        link.symlink_to(spelling)
        resolved = []
        real_resolve = Path.resolve

        def recording_resolve(self, strict=False):
            resolved.append(str(self))
            return real_resolve(self, strict=strict)

        monkeypatch.setattr(Path, "resolve", recording_resolve)

        refusal = validate_scan_target_in_sandbox(link, session_id=OWN)

        assert refusal is not None
        assert "is a link that leads to a network share" in str(refusal)
        assert refusal.context["resolved_path"] == str(link)
        assert all("server" not in p for p in resolved), resolved

    def test_a_chain_of_links_ending_at_a_share_is_refused(self, tmp_path):
        """Every hop is read: a local link to a link to a share is the share."""
        last = tmp_path / "last"
        last.symlink_to("\\\\server\\share\\tree")
        middle = tmp_path / "middle"
        middle.symlink_to("last")
        first = tmp_path / "first"
        first.symlink_to(middle)

        refusal = validate_config_input(first, session_id=OWN)

        assert refusal is not None
        assert "is a link that leads to a network share" in str(refusal)

    def test_a_link_to_a_local_directory_is_judged_resolved(self, tmp_path):
        """A linked checkout is the checkout: the gates judge what it names.

        At the base every link was refused unresolved on Windows, so a linked
        scan target, a junction in a repository and a dangling link in a tree
        were refused for being links rather than judged as what they name; thirteen
        tests of the MCP tools that follow links read red on Windows.
        """
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)

        assert sandbox._refusal_before_resolving("Scan target", link) is None

    def test_a_config_input_that_is_a_local_link_is_judged_resolved(self, tmp_path):
        real = tmp_path / "real.yaml"
        real.write_text("{}")
        link = tmp_path / "link.yaml"
        link.symlink_to(real)

        assert sandbox._refusal_before_resolving("Config input", link) is None

    def test_a_link_to_nothing_local_is_judged_resolved(self, tmp_path):
        """A dangling link names a local path: resolving it opens nothing remote."""
        link = tmp_path / "link.yaml"
        link.symlink_to(tmp_path / "gone.yaml")

        assert sandbox._refusal_before_resolving("Config input", link) is None

    def test_a_link_whose_name_cannot_be_read_is_refused(self, monkeypatch, tmp_path):
        """A reparse point with no readable name could lead anywhere: refused."""
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)

        def unreadable(path, *args, **kwargs):
            raise OSError(22, "not a symbolic link or junction")

        monkeypatch.setattr(os, "readlink", unreadable)

        refusal = validate_scan_target_in_sandbox(link, session_id=OWN)

        assert refusal is not None
        assert "is a link whose target the MCP server cannot read" in str(refusal)

    def test_a_chain_past_the_hop_bound_is_refused(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sandbox, "_LINK_HOPS", 2)
        third = tmp_path / "third"
        third.mkdir()
        second = tmp_path / "second"
        second.symlink_to(third)
        first = tmp_path / "first"
        first.symlink_to(second)
        zero = tmp_path / "zero"
        zero.symlink_to(first)

        refusal = validate_scan_target_in_sandbox(zero, session_id=OWN)

        assert refusal is not None
        assert "cannot read" in str(refusal)

    @pytest.mark.parametrize(
        ("text", "share"),
        [
            ("\\\\server\\share\\tree", True),
            ("//server/share/tree", True),
            ("\\\\?\\UNC\\server\\share\\tree", True),
            ("\\\\?\\unc\\server\\share", True),
            ("\\\\?\\C:\\repo", False),
            ("\\\\.\\C:\\repo", False),
            ("C:\\repo", False),
            ("/srv/repo", False),
        ],
    )
    def test_the_share_spelling_reads_the_extended_form(self, text, share):
        """``\\\\?\\C:\\...``, the form a junction's name takes, is a local volume."""
        assert sandbox._names_a_windows_share(text) is share

    def test_a_plain_local_directory_is_judged_as_before(self, tmp_path):
        """Control: the Windows check refuses only what resolving would open."""
        target = tmp_path / "checkout"
        target.mkdir()

        assert validate_scan_target_in_sandbox(target, session_id=OWN) is None


def test_off_windows_nothing_is_refused_before_resolving(tmp_path):
    """Control: on POSIX resolving opens nothing, and a linked target is judged resolved."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)

    assert sandbox._refusal_before_resolving("Scan target", link) is None
