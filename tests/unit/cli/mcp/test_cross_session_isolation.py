#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One MCP session must not reach another's delivered source tree.

Why this file is separate from ``test_session_sandbox.py``
---------------------------------------------------------
That file imports ``cli.mcp.sandbox``, which is new. Run against the code as it
stood before the sandbox existed it produces a *collection error*, and a
collection error is not evidence of anything: it says the test is new, not that
the behavior was wrong. A regression test for a security defect has to fail
against the defective code for the reason the defect exists.

So this file imports nothing that the fix introduced. ``validate_scan_target``
and ``source_delivery`` are both pre-existing public API with unchanged
signatures, which makes this module collectable and runnable on either side of
the change. Measured on 70e382aa and on the fix:

    before:  3 failed, 2 passed
    after:   5 passed

The three that failed are the sibling read, the shared-root read, and the
no-session read. The two that passed are the positive control and the
already-working grant case, and they have to pass on both sides -- a test that
only goes green after the change tells you the behavior moved, and a control that
was green all along is what tells you it moved in the right direction.

What the defect was, precisely
------------------------------
``validate_scan_target`` did append *this* session's own workspace to the
allowlist and never a sibling's, so with ``ASH_MCP_ALLOWED_ROOTS`` SET the two
sessions were already isolated -- ``test_a_sibling_is_refused_when_a_grant_is_set``
passed before the change and still does. But that logic lived entirely inside the
``if allowed:`` branch. With the variable UNSET, which is the default, the branch
is skipped and a six-entry system-directory denylist is the only rule -- and the
MCP workspace root is not one of the six. So on a default deployment session A
could name session B's delivered tree, ASH would scan it, and it would write an
output tree into the victim's sandbox on the way.

The consequence worth spelling out: this was not "the allowlist is process-global
rather than per-session". It already was per-session. It was "the per-session part
only runs when an optional variable happens to be set", which is why the fix is a
deny that consults neither the grant nor the transport.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.scan_target import validate_scan_target
from automated_security_helper.cli.mcp.source_delivery import (
    _session_workspace,
    resolve_workspace_root,
)


@pytest.fixture
def workspace_root(tmp_path, monkeypatch) -> Path:
    """Point the MCP workspace root at a directory this test owns.

    Without this the sessions below resolve under the developer's real
    ``~/.cache/ash-mcp`` and one run leaves directories visible to the next.
    """
    root = tmp_path / "mcp-workspaces"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    return resolve_workspace_root().expanduser().resolve()


def _deliver(workspace_root: Path, session_id: str) -> Path:
    """Materialize what ``set_source_zip_finalize`` leaves for a session.

    Built through ``_session_workspace`` and the ``source`` subdirectory name that
    ``source_delivery`` itself uses, so the geometry cannot drift from the code
    under test.
    """
    tree = _session_workspace(workspace_root, session_id) / "source"
    tree.mkdir(parents=True, exist_ok=True)
    # pragma: allowlist nextline secret
    (tree / "app.py").write_text("SECRET = 'tenant data'\n", encoding="utf-8")
    return tree


def test_a_session_may_scan_the_tree_it_delivered(workspace_root):
    """Positive control, and it has to come first.

    Without it the two refusals below could be produced by a policy that permits
    nothing at all -- which would satisfy "isolated" while breaking source
    delivery outright. Passed before the change and after.
    """
    mine = _deliver(workspace_root, "session-a")

    assert validate_scan_target(mine, session_id="session-a") is None


def test_a_sibling_is_refused_when_no_grant_is_configured(workspace_root):
    """The defect. FAILED before the change.

    No ``ASH_MCP_ALLOWED_ROOTS``, which is the default deployment. Before the
    fix this returned None and the scan proceeded.
    """
    _deliver(workspace_root, "session-a")
    theirs = _deliver(workspace_root, "session-b")

    assert validate_scan_target(theirs, session_id="session-a") is not None, (
        "session-a was permitted to scan session-b's delivered source tree. On a "
        "network transport those are two tenants: this is a cross-tenant read, "
        "plus a write of an output tree into the victim's sandbox."
    )


def test_the_shared_workspace_root_is_refused_when_no_grant_is_configured(
    workspace_root,
):
    """The same defect with a shorter reach. FAILED before the change.

    The parent of every sandbox holds every tenant's source, so permitting it
    hands one caller the whole set in a single path.
    """
    _deliver(workspace_root, "session-a")

    assert validate_scan_target(workspace_root, session_id="session-a") is not None


def test_a_sibling_is_refused_when_a_grant_is_set(workspace_root, tmp_path):
    """Regression guard, not new behavior: this already held. Passed before.

    Kept because the fix reorganizes which branch the session allowance lives in,
    and the two obvious ways to get that wrong both show up here -- making the
    sandbox the only root loses the operator grant, and granting the shared
    workspace root re-opens every sibling.
    """
    checkout = tmp_path / "operator-checkout"
    checkout.mkdir()
    os.environ["ASH_MCP_ALLOWED_ROOTS"] = str(checkout)
    try:
        mine = _deliver(workspace_root, "session-a")
        theirs = _deliver(workspace_root, "session-b")

        assert validate_scan_target(mine, session_id="session-a") is None
        assert validate_scan_target(checkout, session_id="session-a") is None
        assert validate_scan_target(theirs, session_id="session-a") is not None
    finally:
        os.environ.pop("ASH_MCP_ALLOWED_ROOTS", None)


def test_a_caller_with_no_session_reaches_no_sandbox(workspace_root):
    """A caller that named no session owns nothing, so every sandbox is a sibling's.

    FAILED before the change, and I had expected it to pass -- worth recording,
    because the reason I was wrong is the shape of the defect. I assumed a caller
    with no session id was refused a sandbox by the absence of an allowance. It was
    not: with no grant configured the allowlist branch never ran, so there was no
    allowance to lack, and the fall-through denylist permitted the path outright.
    Every route into that branch was open, not just the sibling one.

    Also a guard against writing the deny rule as "refuse a sandbox that is not
    mine" in a way that lets "no session" mean "owns all".
    """
    theirs = _deliver(workspace_root, "session-b")

    assert validate_scan_target(theirs) is not None
