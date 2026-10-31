#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Five gaps in the sandbox gates, each pinned by the input that passed it.

* A client-delivered config is judged with ``Path.resolve``, which on Python
  3.12 and older raises for a link that leads back to itself, so a scanned tree
  holding one made the scanner's construction raise. The named-config judgment
  kept the same call after the delivered-config one had moved off it.
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
    client_named_config_is_untrusted,
    config_is_client_supplied,
    session_sandbox,
    validate_config_input,
    validate_scan_target_in_sandbox,
)
from automated_security_helper.cli.mcp.session_paths import hidden_deleting_name
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
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

    def test_a_named_config_that_is_a_self_referencing_link_is_judged(
        self, monkeypatch, tmp_path
    ):
        """Red at the base on Python 3.12 and older: the named-config judgment
        still resolved with Path.resolve after the delivered-config judgment had
        moved to os.path.realpath, and raised RuntimeError on the loop.

        Both candidates are built before any is judged (the tuple is the
        generator's iterable), so every loop raised at the base, inside a granted
        root or not. The loop sits in a granted config root here so that the
        cured judgment has an answer to assert: the operator's, not raised.
        """
        _delivered(OWN)
        granted = tmp_path / "granted-config"
        granted.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, str(granted))
        loop = granted / "ash.yaml"
        loop.symlink_to(loop.name)

        assert client_named_config_is_untrusted(loop, OWN) is False

    def test_a_scan_target_that_is_a_self_referencing_link_is_judged(self, tmp_path):
        """Red at the base on Python 3.12 and older: the scan-target gate resolved
        with Path.resolve and raised RuntimeError on the loop, escaping the gate
        as an exception. Judged now: a remote caller's loop outside its sandbox is
        refused, not raised on."""
        _delivered(OWN)
        loop = tmp_path / "elsewhere" / "checkout"
        loop.parent.mkdir()
        loop.symlink_to(loop.name)

        refusal = validate_scan_target_in_sandbox(loop, session_id=OWN)

        assert isinstance(refusal, MCPResourceError)


class TestSessionSandboxRefusesTheIdsEveryOtherBuilderRefuses:
    @pytest.mark.parametrize(
        "session_id",
        [
            "tab\there",
            "x" * 300,
            "has space",
            hidden_deleting_name("gone"),
            ".",
        ],
        ids=["control-char", "too-long", "space", "hidden-delete-shape", "dot"],
    )
    def test_an_id_the_registry_refuses_gets_no_sandbox(self, session_id):
        """Red at the base: each of these passed the separator-only rule.

        The single period is the one pathlib drops: ``shared / "."`` is the
        shared root itself, so a sandbox for it would own every sibling.
        """
        with pytest.raises(ValueError):
            session_sandbox(session_id)

    @pytest.mark.parametrize("session_id", ["a/b", "..", "a\\b"])
    def test_the_separator_rule_still_holds(self, session_id):
        """Control: what the old rule refused is still refused."""
        with pytest.raises(ValueError):
            session_sandbox(session_id)

    def test_an_empty_id_is_the_local_callers_sandbox(self):
        """An empty id names no session and is not validated as one.

        ``session_sandbox`` validates an id only when it is non-empty (its
        docstring: it raises "if session_id is non-empty but could not name a
        single directory"), so the empty string is the caller that named none:
        no sandbox root, the local caller's denylist fallback. Asserted as such:
        the product makes no raise for an empty id.
        """
        sandbox_of_nobody = session_sandbox("")

        assert sandbox_of_nobody.session_id is None
        assert sandbox_of_nobody.root is None
        assert sandbox_of_nobody.fall_back_to_denylist is True

    def test_a_plain_id_still_gets_its_sandbox(self):
        assert session_sandbox("session-a").root is not None

    @pytest.mark.parametrize(
        "session_id",
        [
            ".",
            "..",
            "a/b",
            "a\\b",
            "tab\there",
            "x" * 300,
            "has space",
            "ends.",
            "CON",
            hidden_deleting_name("gone"),
            "session-a",
            "a.b_c-d~e+f=g",
        ],
        # Explicit ids: the hidden delete name carries a fresh uuid4 per
        # process, and xdist refuses a file whose workers collect different ids.
        ids=[
            "dot",
            "dotdot",
            "slash",
            "backslash",
            "control-char",
            "too-long",
            "space",
            "trailing-period",
            "device-name",
            "hidden-delete-shape",
            "plain",
            "punctuation-admitted",
        ],
    )
    def test_the_sandbox_and_the_path_validator_agree(self, session_id):
        """Parity: the sandbox refuses an id exactly when the shared validator does.

        Every builder of a session path (the registry, source delivery, the TTL
        sweep) applies ``session_paths.validated_path_component``; the sandbox
        applies it through ``_validated_session_component``. This asserts the
        two cannot drift: an id the validator refuses gets no sandbox, and an id
        it admits gets one with a root.
        """
        from automated_security_helper.cli.mcp.session_paths import (
            validated_path_component,
        )

        try:
            validated_path_component(session_id, "session_id")
        except ValueError:
            with pytest.raises(ValueError):
                session_sandbox(session_id)
        else:
            assert session_sandbox(session_id).root is not None


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


def _record_what_is_touched(monkeypatch):
    """Record the path handed to every call that can open a share given its name.

    On Windows each of ``Path.resolve``, ``os.lstat``, ``os.stat`` and
    ``os.path.realpath`` opens the host a UNC name carries, and the last two
    follow a link they are given. The gate resolves with ``os.path.realpath``, so
    a recorder on ``Path.resolve`` alone cannot see it move. The paths are kept
    per call, as strings, so a test can ask which call saw a path.
    """
    touched = {"resolve": [], "lstat": [], "stat": [], "realpath": []}
    real_resolve = Path.resolve

    def recording_resolve(self, strict=False):
        touched["resolve"].append(str(self))
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", recording_resolve)
    for module, name in ((os, "lstat"), (os, "stat"), (os.path, "realpath")):
        real = getattr(module, name)

        def recording(path, *args, _real=real, _name=name, **kwargs):
            touched[_name].append(os.fspath(path))
            return _real(path, *args, **kwargs)

        monkeypatch.setattr(module, name, recording)
    return touched


class TestWindowsRefusesBeforeResolving:
    @pytest.fixture(autouse=True)
    def _on_windows(self, monkeypatch):
        monkeypatch.setattr(sandbox, "_running_on_windows", lambda: True)

    @pytest.mark.parametrize(
        "spelling", ["//server/share/tree", "\\\\server\\share\\tree"]
    )
    def test_a_network_share_is_refused_without_resolving(self, monkeypatch, spelling):
        """Red at the base: the path was resolved (the share opened) before any refusal.

        On Windows every filesystem call on a UNC name opens the share, not only
        ``Path.resolve``: ``os.lstat`` (the link check the gate runs on a name
        that is not a share spelling), ``os.stat`` and ``os.path.realpath``. So
        those are recorded too, and the refusal has to come before any of them
        sees the server's name.
        """
        resolved = []
        real_resolve = Path.resolve

        def recording_resolve(self, strict=False):
            resolved.append(str(self))
            return real_resolve(self, strict=strict)

        monkeypatch.setattr(Path, "resolve", recording_resolve)
        touched = []
        for module, name in ((os, "lstat"), (os, "stat"), (os.path, "realpath")):
            real = getattr(module, name)

            def recording(path, *args, _real=real, **kwargs):
                touched.append(os.fspath(path))
                return _real(path, *args, **kwargs)

            monkeypatch.setattr(module, name, recording)

        refusal = validate_scan_target_in_sandbox(spelling, session_id=OWN)

        assert refusal is not None
        assert "network share" in str(refusal)
        assert all("server" not in p for p in resolved + touched), (resolved, touched)

    @pytest.mark.parametrize(
        "spelling", ["\\\\server\\share\\tree", "//server/share/tree"]
    )
    def test_a_link_to_a_network_share_is_refused_unresolved(
        self, monkeypatch, tmp_path, spelling
    ):
        """The link's name is read, never resolved: nothing follows the link.

        ``Path.resolve``, ``os.path.realpath`` and ``os.stat`` all follow the link
        they are given, so none of them may be handed the link's own path before
        the refusal (``os.lstat`` may: it opens the link's entry, not its
        target). The regression this pins is the resolve that moves above the
        pre-resolve check and opens the share it was meant to refuse; a recorder
        on ``Path.resolve`` alone saw nothing of it once the gate resolved with
        ``os.path.realpath``, and what it stored was the link's own path, which
        never holds the server's name.
        """
        link = tmp_path / "link"
        link.symlink_to(spelling)
        touched = _record_what_is_touched(monkeypatch)

        refusal = validate_scan_target_in_sandbox(link, session_id=OWN)

        assert refusal is not None
        assert "is a link that leads to a network share" in str(refusal)
        assert refusal.context["resolved_path"] == str(link)
        following = touched["resolve"] + touched["stat"] + touched["realpath"]
        assert str(link) not in following, touched
        assert touched["lstat"], "the walk examined nothing"
        assert all("server" not in p for paths in touched.values() for p in paths), (
            touched
        )

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

    def test_a_reparse_point_readlink_refuses_as_no_symlink_is_refused(
        self, monkeypatch, tmp_path
    ):
        """CPython raises ValueError, not OSError, for a name-surrogate reparse
        point that is no symbolic link or junction; the gate reads that as a
        name it cannot read, not as an exception escaping the tool."""
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)

        def not_a_symlink(path, *args, **kwargs):
            raise ValueError("not a symbolic link")

        monkeypatch.setattr(os, "readlink", not_a_symlink)

        refusal = validate_scan_target_in_sandbox(link, session_id=OWN)

        assert refusal is not None
        assert "is a link whose target the MCP server cannot read" in str(refusal)

    def test_a_hop_that_cannot_be_examined_is_refused(self, monkeypatch, tmp_path):
        """A hop under a directory the process cannot search may be a link to a
        share nobody here can see, so the chain is refused as unjudged rather
        than admitted as local: a link -> an unexaminable entry -> a share would
        otherwise pass the gate and be resolved."""
        real = tmp_path / "real"
        real.mkdir()
        second = tmp_path / "second"
        second.symlink_to(real)
        first = tmp_path / "first"
        first.symlink_to(second)
        real_lstat = os.lstat

        def unsearchable(path, *args, **kwargs):
            # Matched by the entry's name, not its spelling: on Windows the walk
            # reaches ``second`` through the extended-form target ``os.readlink``
            # gives for ``first`` (``\\\\?\\C:\\...\\second``), which an equality
            # test against ``str(second)`` never meets.
            if os.path.basename(os.fspath(path).rstrip("\\/")) == second.name:
                raise PermissionError(13, "permission denied")
            return real_lstat(path, *args, **kwargs)

        monkeypatch.setattr(os, "lstat", unsearchable)

        refusal = validate_scan_target_in_sandbox(first, session_id=OWN)

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
            ("\\\\?\\GLOBALROOT\\Device\\LanmanRedirector\\server\\share", True),
            ("\\\\?\\GLOBALROOT\\??\\UNC\\server\\share", True),
            ("\\\\?\\GLOBALROOT\\Device\\Mup\\server\\share", True),
            ("\\\\.\\pipe\\ash", True),
            ("\\\\?\\Volume{0000}\\repo", True),
            ("\\\\?\\", True),
            ("\\??\\UNC\\server\\share", True),
            ("\\??\\GLOBALROOT\\Device\\Mup\\server\\share", True),
            ("\\\\?/GLOBALROOT/Device/Mup/server/share", True),
            ("\\\\?\\C:repo", True),
            ("\\\\?\\c:", True),
            ("\\\\.\\C:", True),
            ("\\\\?\\C:\\repo", False),
            ("\\\\.\\C:\\repo", False),
            ("\\??\\C:\\repo", False),
            ("\\\\?\\C:\\", False),
            ("//?/D:/repo", False),
            ("C:\\repo", False),
            ("C:repo", False),
            ("\\repo", False),
            ("/srv/repo", False),
        ],
    )
    def test_the_share_spelling_reads_the_extended_form(self, text, share):
        """Only a drive letter after ``\\\\?\\``, ``\\\\.\\`` or ``\\??\\`` is a local volume.

        The object namespace (``GLOBALROOT``, through which a redirector or a
        mounted share is reached by another name), a named pipe, a volume GUID, a
        drive-relative ``C:repo`` behind the prefix and a bare ``C:`` behind it
        (the volume's device object, which ``\\\\.\\C:`` opens raw) are refused with
        the UNC spellings: none is a directory on a local volume the server may
        open. A forward slash is a separator, so a mixed spelling is judged by
        what it names. A device other than ``UNC`` is not read as local.
        """
        assert sandbox._names_a_windows_share(text) is share

    @pytest.mark.parametrize(
        "spelling",
        [
            "\\\\?\\GLOBALROOT\\Device\\LanmanRedirector\\server\\share\\tree",
            "\\\\?\\GLOBALROOT\\??\\UNC\\server\\share\\tree",
            "\\\\?\\GLOBALROOT\\Device\\Mup\\server\\share\\tree",
            "\\\\.\\pipe\\ash",
            "\\??\\UNC\\server\\share\\tree",
            "\\\\?\\C:server\\share",
            "\\\\.\\C:",
        ],
    )
    def test_a_device_namespace_path_is_refused_without_resolving(
        self, monkeypatch, spelling
    ):
        """A client-named path in the device namespace reaches no filesystem call.

        Judged by its text alone: ``Path.resolve``, ``os.lstat``, ``os.stat`` and
        ``os.path.realpath`` are all recorded, and none is handed the spelling
        (a relative name here, so a call on it carries the spelling inside the
        working directory's path). ``Path.resolve`` alone was recorded before,
        and the gate resolves with ``os.path.realpath``.
        """
        touched = _record_what_is_touched(monkeypatch)

        refusal = validate_scan_target_in_sandbox(spelling, session_id=OWN)

        assert refusal is not None
        assert "network share or a device path" in str(refusal)
        assert not [p for paths in touched.values() for p in paths if spelling in p], (
            touched
        )

    def test_a_drive_letter_extended_path_is_judged_as_before(self, tmp_path):
        """Control: the extended form of a local path is not refused by spelling.

        Off a Windows host the spelling is not a path of this filesystem, so the
        pre-resolve gate alone is checked: it returns None and the ordinary gates
        judge the path.
        """
        assert (
            sandbox._refusal_before_resolving("Scan target", "\\\\?\\C:\\repo") is None
        )

    def test_a_plain_local_directory_is_judged_as_before(self, tmp_path):
        """Control: the Windows check refuses only what resolving would open.

        Judged for the caller that named no session: that caller is local, and
        with no grant its denylist fallback admits a directory under tmp_path, so
        the only refusal this test could meet is the pre-resolve one, and there
        is none. For a session id the gates read a remote caller whose scan roots
        are its own sandbox alone, and a tmp_path directory is refused as outside
        the permitted roots whatever the platform, which is what an earlier shape
        of this test asked for and read red on.
        """
        target = tmp_path / "checkout"
        target.mkdir()

        assert sandbox._refusal_before_resolving("Scan target", target) is None
        assert validate_scan_target_in_sandbox(target, session_id=None) is None


def test_off_windows_nothing_is_refused_before_resolving(tmp_path, monkeypatch):
    """Control: on POSIX resolving opens nothing, so nothing is refused first.

    The platform check is set to False here, not left to the host, and the
    cases are the ones the Windows check refuses: a link to a share and a share
    spelling. A local link, which the Windows walk also answers None for, would
    pass whether or not the platform check ran.
    """
    monkeypatch.setattr(sandbox, "_running_on_windows", lambda: False)
    link = tmp_path / "link"
    link.symlink_to("\\\\server\\share")

    assert sandbox._refusal_before_resolving("Scan target", link) is None
    assert (
        sandbox._refusal_before_resolving("Scan target", "\\\\server\\share\\tree")
        is None
    )
