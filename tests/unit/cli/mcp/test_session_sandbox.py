#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Confinement is a per-session capability, not a process-global env var.

Why this file exists
--------------------
``ASH_MCP_ALLOWED_ROOTS`` bounded the scan surface for the *process*. Four
consequences followed from that, and each one is a test below:

1. Two concurrent sessions could get identical reach, so session A could name
   session B's delivered source tree as its scan target and read it. On a network
   transport those are two different tenants. ``TestOneSessionCannotReachAnother``
   is the test that fails without the change.

   Measured precisely, because the shape is narrower than it first looks and the
   narrower shape is what the fix has to address. ``validate_scan_target``
   already appended *this* session's own workspace to the allowlist and never a
   sibling's, so with the variable SET the two sessions were already isolated --
   the pre-change measurement confirms it. The hole was that the session
   allowance lived entirely inside the ``if allowed:`` branch: with the variable
   UNSET, which is the default, that branch is skipped and the fall-through
   denylist decides. It names six system directories, none of which is the MCP
   workspace root, so every session could read every other session's delivered
   source and most of the filesystem besides.

   So consequence 1 was a symptom of consequence 2 rather than an independent
   defect, and "make the allowlist per-session" would have fixed nothing -- it
   already was. What fixes it is an explicit deny that does not depend on
   configuration at all: a sibling's sandbox is refused on every transport and
   under every grant, which is
   ``test_a_sibling_is_refused_even_with_no_allowlist_configured``.
2. An unset allowlist was permissive -- everything outside a short list of system
   directories was accepted. For a server reachable over HTTP that is the wrong
   default. ``TestDenyByDefaultOnANetworkTransport`` pins the new one, and
   ``TestStdioKeepsItsAmbientAuthority`` pins that the local case did NOT change,
   because refusing every unconfigured deployment is the more damaging failure.
3. Authority was ambient -- inherited from whatever launched the server -- rather
   than a capability held by the session. Every test here resolves a sandbox for a
   named session and asks that object, which is what makes 1 and 2 expressible at
   all.
4. The trust boundary was split. Scan targets were confined and *config inputs*
   were not, so the file that names N scan targets sat outside the boundary its
   targets sat inside. ``TestConfigInputsAreConfined`` closes it, and
   ``TestACentralPolicyFileStillWorksWhenGranted`` keeps the deployment the old
   asymmetry existed to serve.

What is deliberately NOT changed
--------------------------------
``ASH_MCP_ALLOWED_ROOTS`` still works and still means the same thing. It is now
the operator-grant layer feeding each session's sandbox rather than the whole
mechanism. Deprecating it would have broken every deployment that sets it in
exchange for nothing: the variable was never the defect, and the operator still
needs some way to say which of its own directories the server may scan.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.sandbox import (
    ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV,
    ASH_MCP_ALLOWED_ROOTS_ENV,
    ASH_MCP_TRANSPORT_ENV,
    session_sandbox,
    set_server_transport,
    transport_is_networked,
    validate_config_input,
)
from automated_security_helper.cli.mcp.scan_target import (
    _denied_root_values,
    validate_scan_target,
)


@pytest.fixture(autouse=True)
def _clean_policy_env(monkeypatch, tmp_path):
    """Every test starts from no grant, stdio, and its own workspace root.

    ``ASH_MCP_WORKSPACE_ROOT`` is pointed at ``tmp_path`` so a sandbox resolves
    somewhere this test owns rather than under the developer's real
    ``~/.cache/ash-mcp``, which would make one test's session directory visible
    to the next run.

    The transport is delenv'd rather than set, so the default path is what most
    tests exercise; the ones that need a network transport set it themselves via
    :func:`set_server_transport`. ``monkeypatch`` reverts all of it, which is the
    reason the transport lives in the environment -- see
    ``test_the_transport_does_not_leak_between_callers``.
    """
    monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.delenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, raising=False)
    # setenv, not delenv. monkeypatch only records an undo for a key it saw, so
    # delenv on an absent key records nothing and a test that then SETS it leaks
    # the value into every later test in the process -- which is how the
    # module-global version of this knob broke 32 unrelated tests.
    monkeypatch.setenv(ASH_MCP_TRANSPORT_ENV, "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))


def _delivered_tree(session_id: str) -> Path:
    """Materialize the tree ``set_source_zip_finalize`` would leave for a session.

    Built through ``session_sandbox`` rather than by joining paths by hand, so
    the test cannot pass against a sandbox whose layout differs from the one
    source delivery actually writes into.
    """
    sandbox = session_sandbox(session_id)
    sandbox.source_dir.mkdir(parents=True, exist_ok=True)
    (sandbox.source_dir / "app.py").write_text("x = 1\n", encoding="utf-8")
    return sandbox.source_dir


# ---------------------------------------------------------------------------
# 1. The headline: one session cannot reach another's tree
# ---------------------------------------------------------------------------


class TestOneSessionCannotReachAnother:
    """Two concurrent sessions are two boundaries, not one shared one."""

    def test_a_session_may_scan_its_own_delivered_tree(self):
        """Positive control, and it has to come first.

        Without this, the refusal below could be produced by a sandbox that
        permits nothing at all -- which would "pass" the isolation test while
        breaking source delivery entirely.
        """
        mine = _delivered_tree("session-a")
        assert validate_scan_target(mine, session_id="session-a") is None

    def test_a_sibling_is_refused_even_with_no_allowlist_configured(self):
        """The cross-tenant read. THIS is the case that fails before the change.

        No ``ASH_MCP_ALLOWED_ROOTS``, which is the default. On the old code the
        session allowance was only consulted inside the ``if allowed:`` branch,
        so an unset variable skipped it and left the six-system-directory
        denylist as the only rule -- and the MCP workspace root is not in it.
        Session A naming session B's path was accepted, ASH scanned it, and wrote
        an output tree into the victim's sandbox on the way.

        Pre-change measurement, same geometry:
            session-a -> SIBLING session-b tree : PERMITTED
        """
        _delivered_tree("session-a")
        theirs = _delivered_tree("session-b")

        refusal = validate_scan_target(theirs, session_id="session-a")

        assert refusal is not None, (
            "session-a was permitted to scan session-b's delivered source tree; "
            "on a network transport those are two tenants and this is a "
            "cross-tenant read plus a write into the victim's sandbox"
        )

    def test_the_refusal_does_not_reveal_whether_the_sibling_exists(self):
        """A live sibling and an imaginary one must refuse identically.

        Not "the message must not contain the sibling's id" -- it does, because
        the caller supplied that path and is being told which of its own inputs
        was refused. The property that matters is non-enumerability: if a refusal
        for a session that exists differed in any way from one for a session that
        does not, the tool would be an oracle for listing live tenants.

        Compared after masking the id out of both, so the assertion is about
        everything else in the message rather than about the one part that is
        legitimately different.
        """
        _delivered_tree("session-a")
        live = _delivered_tree("session-b")
        imaginary = live.parent.parent / "no-such-session" / "source"

        live_refusal = validate_scan_target(live, session_id="session-a")
        absent_refusal = validate_scan_target(imaginary, session_id="session-a")

        assert live_refusal is not None and absent_refusal is not None
        masked_live = str(live_refusal).replace("session-b", "SID")
        masked_absent = str(absent_refusal).replace("no-such-session", "SID")
        assert masked_live == masked_absent, (
            "the refusal for a session that exists differs from one for a "
            "session that does not, so the tool enumerates live tenants"
        )
        assert (
            live_refusal.context["error_category"]
            == absent_refusal.context["error_category"]
        )

    def test_a_sibling_stays_refused_when_an_allowlist_is_configured(self, tmp_path):
        """Regression guard, not a new behavior: this already held.

        Kept because the fix reorganizes which branch the session allowance
        lives in, and the obvious way to get that wrong is to make the sandbox
        the *only* root and lose the operator grant, or to widen the grant to the
        shared workspace root and re-open every sibling. Either shows up here.
        """
        checkout = tmp_path / "checkout"
        checkout.mkdir()
        os.environ[ASH_MCP_ALLOWED_ROOTS_ENV] = str(checkout)
        try:
            mine = _delivered_tree("session-a")
            theirs = _delivered_tree("session-b")
            assert validate_scan_target(mine, session_id="session-a") is None
            assert validate_scan_target(checkout, session_id="session-a") is None
            assert validate_scan_target(theirs, session_id="session-a") is not None
        finally:
            os.environ.pop(ASH_MCP_ALLOWED_ROOTS_ENV, None)

    def test_a_session_with_no_id_cannot_reach_any_sandbox(self):
        """A caller that named no session gets no session's sandbox.

        The deny is keyed on "not mine", and a caller with no id owns nothing, so
        every sandbox is somebody else's. Without this, omitting the header would
        be a way around the boundary.
        """
        theirs = _delivered_tree("session-b")

        assert validate_scan_target(theirs) is not None

    def test_the_shared_workspace_root_is_not_reachable_by_anyone(self):
        """The parent of every sandbox holds every tenant's source.

        Permitting it would hand any session the whole set in one path, which is
        the same defect as the previous test with a shorter reach.
        """
        _delivered_tree("session-a")
        shared_root = session_sandbox("session-a").root.parent

        assert validate_scan_target(shared_root, session_id="session-a") is not None

    def test_an_operator_grant_does_not_dissolve_the_boundary(self, tmp_path):
        """A grant widens reach into the operator's tree, not into a sibling.

        The failure this separates out: implementing the grant by appending the
        *workspace root* to the allowlist. That would satisfy "a session can
        scan its own delivery" and simultaneously re-open every sibling.
        """
        checkout = tmp_path / "checkout"
        checkout.mkdir()
        os.environ[ASH_MCP_ALLOWED_ROOTS_ENV] = str(checkout)
        try:
            theirs = _delivered_tree("session-b")
            assert validate_scan_target(checkout, session_id="session-a") is None
            assert validate_scan_target(theirs, session_id="session-a") is not None
        finally:
            os.environ.pop(ASH_MCP_ALLOWED_ROOTS_ENV, None)


# ---------------------------------------------------------------------------
# 2. Deny by default, but only where it does not break the local case
# ---------------------------------------------------------------------------


class TestDenyByDefaultForARemoteCaller:
    """A connected client gets its sandbox and nothing else.

    Every test here identifies the caller by a real session id, which is what
    ``caller_is_remote`` reads. ``set_server_transport`` is exercised separately
    in ``TestTheTransportEnvVarIsASecondTrigger`` -- keeping the two apart is what
    shows the session id alone is sufficient, rather than the tests passing
    because both signals happened to agree.
    """

    def test_an_arbitrary_directory_is_refused_when_nothing_is_granted(self, tmp_path):
        """No allowlist and a remote caller means deny, not "almost allow".

        Under the old default this directory was accepted: it is not one of the
        six system directories the fallback denylist names, and nothing else
        applied.
        """
        somewhere = tmp_path / "someone-elses-checkout"
        somewhere.mkdir()

        assert validate_scan_target(somewhere, session_id="session-a") is not None

    def test_the_sessions_own_sandbox_is_still_permitted(self):
        """Deny-by-default must not deny the one thing the server itself created.

        Without this a remote caller would be refused every delivered tree, which
        is the whole point of having source delivery.
        """
        mine = _delivered_tree("session-a")

        assert validate_scan_target(mine, session_id="session-a") is None

    def test_an_explicit_grant_re_opens_the_operators_own_tree(self, tmp_path):
        """The operator keeps a lever; it is just no longer the default."""
        checkout = tmp_path / "checkout"
        checkout.mkdir()
        os.environ[ASH_MCP_ALLOWED_ROOTS_ENV] = str(checkout)
        try:
            assert validate_scan_target(checkout, session_id="session-a") is None
        finally:
            os.environ.pop(ASH_MCP_ALLOWED_ROOTS_ENV, None)


class TestTheTransportEnvVarIsASecondTrigger:
    """``ASH_MCP_TRANSPORT`` closes the no-session-header gap.

    A streamable-HTTP client that sends no ``Mcp-Session-Id`` resolves to the
    stdio sentinel, so the session-id signal alone reads it as local. The MCP spec
    has the server assign an id at ``initialize``, so that is not the normal case,
    but an operator can say so explicitly and this is the test that it works.
    """

    def test_it_makes_a_default_session_caller_remote(self, tmp_path):
        from automated_security_helper.cli.mcp.profile_registry import (
            DEFAULT_SESSION_ID,
        )

        somewhere = tmp_path / "someone-elses-checkout"
        somewhere.mkdir()
        assert validate_scan_target(somewhere, session_id=DEFAULT_SESSION_ID) is None

        set_server_transport("streamable-http")
        assert (
            validate_scan_target(somewhere, session_id=DEFAULT_SESSION_ID) is not None
        ), "ASH_MCP_TRANSPORT did not override the session-id signal"


class TestStdioKeepsItsAmbientAuthority:
    """The local deployment did not change, and that is deliberate.

    stdio serves exactly one client, which launched the server itself, in the
    tree the developer meant. Ambient authority is the correct model there, the
    working directory has always been the documented default, and flipping this
    to deny would refuse every existing local install for no gain -- the caller
    already has the server's own filesystem privileges.

    A stdio call resolves to ``DEFAULT_SESSION_ID``, which is exactly how
    ``caller_is_remote`` tells it from a connected client, so these tests pass
    that sentinel rather than a made-up id.
    """

    def test_an_ordinary_checkout_is_permitted_with_no_session(self, tmp_path):
        checkout = tmp_path / "my-project"
        checkout.mkdir()

        assert validate_scan_target(checkout) is None

    def test_an_ordinary_checkout_is_permitted_for_the_default_session(self, tmp_path):
        """The shape a real stdio tool call has, rather than session_id=None."""
        from automated_security_helper.cli.mcp.profile_registry import (
            DEFAULT_SESSION_ID,
        )

        checkout = tmp_path / "my-project"
        checkout.mkdir()

        assert validate_scan_target(checkout, session_id=DEFAULT_SESSION_ID) is None

    def test_a_config_input_is_not_confined_for_a_local_caller(self, tmp_path):
        """A definition beside a checkout keeps working on stdio.

        This is the capability ``TestTheWorkspaceFileIsNotConfined`` protected, and
        for a local caller it is unchanged -- which is why that file still passes
        unmodified.
        """
        from automated_security_helper.cli.mcp.profile_registry import (
            DEFAULT_SESSION_ID,
        )

        stray = tmp_path / "elsewhere" / "dev.code-workspace"
        stray.parent.mkdir(parents=True)
        stray.write_text("{}", encoding="utf-8")

        assert validate_config_input(stray, session_id=DEFAULT_SESSION_ID) is None

    def test_a_system_directory_is_still_refused(self):
        """The old safety net survives the move onto the sandbox.

        The target comes from the policy's own ``_denied_root_values()`` rather
        than being written out here. The literal ``"/etc"`` this used to assert
        names nothing on Windows: ``pathlib`` reads a leading separator with no
        drive as relative to the current drive, so it resolves to ``C:\\etc``, an
        ordinary directory the policy has no reason to refuse, and
        ``is_absolute()`` is False for it besides. The assertion was demanding the
        wrong answer rather than detecting a missing one -- the denylist has named
        the Windows locations since confinement landed.

        Restating a Windows spelling here instead would have swapped that for a
        worse bug: two lists that must agree and are never compared against each
        other. So what this asserts is the end-to-end path -- that a directory the
        policy *names* as denied is in fact refused on whatever platform is
        running -- while the *contents* of the list stay pinned per platform by
        ``test_scan_target.py::TestDeniedRootSet``. Neither test duplicates the
        other, and there is no second list to drift.

        Existence is deliberately not arranged for: the policy judges a target
        without touching the filesystem, which
        ``test_nonexistent_path_is_still_judged_by_policy`` pins directly, so the
        first denied root works as a target whether or not this host has one.
        """
        denied = _denied_root_values()
        assert denied, "the policy names no denied directories on this platform"

        assert validate_scan_target(denied[0]) is not None


# ---------------------------------------------------------------------------
# 3. The split trust boundary: config inputs
# ---------------------------------------------------------------------------


class TestConfigInputsAreConfined:
    """The file that NAMES N scan targets now sits inside a boundary too.

    Reading a caller-named path is itself a capability, and an unconfined one is
    a file-read oracle: point ``workspace_file`` at any path on the server and
    the parse error or the resolved plan reports something about its content. The
    targets being confined does not help, because the read happens during
    resolution, before any target exists.
    """

    def test_a_config_file_outside_every_root_is_refused(self, tmp_path):
        set_server_transport("streamable-http")
        stray = tmp_path / "elsewhere" / "ash.yaml"
        stray.parent.mkdir(parents=True)
        stray.write_text("project_name: x\n", encoding="utf-8")

        assert validate_config_input(stray, session_id="session-a") is not None

    def test_a_config_file_inside_the_scan_grant_is_permitted(self, tmp_path):
        """The common case: ``.ash.yaml`` beside the code it configures.

        A grant that permits scanning a tree has to permit reading the config
        that lives in it, or every in-tree config becomes unreachable.
        """
        set_server_transport("streamable-http")
        checkout = tmp_path / "checkout"
        checkout.mkdir()
        config = checkout / ".ash.yaml"
        config.write_text("project_name: x\n", encoding="utf-8")
        os.environ[ASH_MCP_ALLOWED_ROOTS_ENV] = str(checkout)
        try:
            assert validate_config_input(config, session_id="session-a") is None
        finally:
            os.environ.pop(ASH_MCP_ALLOWED_ROOTS_ENV, None)

    def test_a_config_materialized_into_the_session_sandbox_is_permitted(self):
        """A bound profile lands in the sandbox, so the sandbox is a config root.

        Without this, binding a profile would write a config the scan is then
        refused permission to read -- the feature would break itself.
        """
        set_server_transport("streamable-http")
        sandbox = session_sandbox("session-a")
        sandbox.config_dir.mkdir(parents=True, exist_ok=True)
        bound = sandbox.config_dir / "ash.yaml"
        bound.write_text("project_name: x\n", encoding="utf-8")

        assert validate_config_input(bound, session_id="session-a") is None

    def test_a_sibling_sessions_bound_config_is_not_readable(self):
        """Config confinement is per-session for the same reason scans are."""
        set_server_transport("streamable-http")
        theirs = session_sandbox("session-b")
        theirs.config_dir.mkdir(parents=True, exist_ok=True)
        bound = theirs.config_dir / "ash.yaml"
        bound.write_text("project_name: theirs\n", encoding="utf-8")

        assert validate_config_input(bound, session_id="session-a") is not None


class TestACentralPolicyFileStillWorksWhenGranted:
    """One policy file governing several checkouts stays possible.

    This is the deployment the old "workspace file is not confined" asymmetry
    existed to serve, and the argument for it was sound: a shared policy has to
    live outside the trees it governs. What was wrong was the *mechanism* --
    serving that need by confining nothing at all, so an arbitrary path was also
    accepted. An explicit config grant serves the same deployment and refuses
    everything else.
    """

    def test_a_granted_config_root_outside_the_scan_roots_is_permitted(self, tmp_path):
        set_server_transport("streamable-http")
        checkout = tmp_path / "checkout"
        checkout.mkdir()
        central = tmp_path / "central"
        central.mkdir()
        policy = central / "policy.yaml"
        policy.write_text("workspace:\n  max_severity_threshold: HIGH\n", "utf-8")

        os.environ[ASH_MCP_ALLOWED_ROOTS_ENV] = str(checkout)
        os.environ[ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV] = str(central)
        try:
            assert validate_config_input(policy, session_id="session-a") is None
            # The config grant must NOT become a scan grant. A policy file's
            # directory is read from, never scanned or written into, and
            # conflating the two would let an operator widen the scan surface by
            # naming a config location.
            assert validate_scan_target(central, session_id="session-a") is not None
        finally:
            os.environ.pop(ASH_MCP_ALLOWED_ROOTS_ENV, None)
            os.environ.pop(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, None)


# ---------------------------------------------------------------------------
# 4. Guard the guard
# ---------------------------------------------------------------------------


def test_two_sessions_resolve_to_different_sandboxes():
    """If they collided, every isolation assertion above would be vacuous."""
    a = session_sandbox("session-a")
    b = session_sandbox("session-b")

    assert a.root != b.root
    assert a.source_dir != b.source_dir
    assert a.config_dir != b.config_dir


class TestTheTransportIsNotLeakyProcessState:
    """Regression: the transport used to be a module global, and it leaked.

    ``mcp_command`` set it once, and a process that built a streamable-HTTP app
    and then did anything else left every later call evaluated as though it came
    from the network. Caught by ``test_mcp_get_scan_results``, which started
    refusing a path it had every right to read -- and only because an unrelated
    test ran before it. The direction is fail-closed, so it surfaced as a
    confusing refusal rather than an unsafe accept, which is why it is worth a
    test rather than only a fix.

    Holding it in the environment is what fixes it: ``monkeypatch`` reverts an
    env var between tests and cannot revert a module global.
    """

    def test_the_default_is_local_when_nothing_set_it(self):
        assert transport_is_networked() is False

    def test_setting_it_is_visible_immediately(self):
        set_server_transport("streamable-http")
        assert transport_is_networked() is True

    def test_it_is_stored_where_monkeypatch_can_revert_it(self):
        """The mechanism, asserted directly.

        Without this the two tests above would pass against a module global and
        the leak would come back the next time somebody refactored it.
        """
        set_server_transport("sse")
        assert os.environ[ASH_MCP_TRANSPORT_ENV] == "sse"

    def test_the_variable_is_spelled_the_way_other_files_hardcode_it(self):
        """``test_workspace_session_and_profile.py`` hardcodes this string.

        It hardcodes it on purpose -- importing the constant into an autouse
        fixture makes that whole file ERROR rather than FAIL when run against the
        pre-change code, which destroys its value as before/after evidence. This
        assertion is what keeps the duplicated literal from drifting.
        """
        assert ASH_MCP_TRANSPORT_ENV == "ASH_MCP_TRANSPORT"

    def test_mcp_command_does_not_write_it(self):
        """ASH reads this variable and never writes it.

        The regression this pins: ``mcp_command`` used to call
        ``set_server_transport(transport)``, and because the value outlives the
        command, a process that started a streamable-HTTP server and then did
        anything else evaluated every later call as remote. In the test suite that
        was ``test_mcp_streamable_http.py`` followed by 32 refusals in tests with
        nothing to do with transports.

        Asserted by source inspection rather than by calling ``mcp_command``, which
        would start a server. Crude, but it is the assertion that actually matters
        -- the alternative is a test that passes right up until somebody adds the
        call back.
        """
        import inspect

        from automated_security_helper.cli import mcp as mcp_package

        source = inspect.getsource(mcp_package.mcp_command)
        assert "set_server_transport(" not in source, (
            "mcp_command writes ASH_MCP_TRANSPORT, which outlives it and makes "
            "every later call in the process read as remote. The transport is "
            "inferred per call from the session id; leave the variable to the "
            "operator."
        )


def test_a_session_id_that_could_traverse_is_refused():
    """An id is one path component. Sanitizing would merge two tenants.

    ``session_identity.resolve_session_id`` already refuses these at the
    transport edge; this is the second gate, for a caller that reaches the
    sandbox directly.
    """
    for bad in ("../session-b", "a/b", "..", "."):
        with pytest.raises(ValueError):
            session_sandbox(bad)
