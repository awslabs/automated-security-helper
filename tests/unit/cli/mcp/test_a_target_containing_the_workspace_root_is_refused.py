#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan target that contains the shared workspace root is refused.

``_sibling_refusal`` refused a target at or inside the shared workspace root
that was not the caller's own sandbox. A target the root is inside -- the
root's parent, the home directory, a tree the operator granted above it -- was
not inside the root by text or by file identity, so it passed the gate, and a
scan of it walked every session's delivered source: the disclosure the gate
exists to refuse, reached from one directory up.

The gate is independent of the grant and of the transport, so both the local
caller with no grant and the network caller whose grant names the parent are
refused. The refusal shows the caller's own path and names no other session.
"""

from __future__ import annotations

import os

import pytest

from automated_security_helper.cli.mcp.sandbox import (
    ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV,
    ASH_MCP_ALLOWED_ROOTS_ENV,
    ASH_MCP_TRANSPORT_ENV,
    session_sandbox,
    shared_workspace_root,
    validate_scan_target_in_sandbox,
)
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
)

pytestmark = pytest.mark.unit

OWN = "session-a"
SIBLING = "session-b"

CONTAINS = "contains the MCP session workspace area"


@pytest.fixture(autouse=True)
def _workspace_root_under_tmp_path(monkeypatch, tmp_path):
    monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.delenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, raising=False)
    monkeypatch.setenv(ASH_MCP_TRANSPORT_ENV, "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "home" / "mcp"))


def _delivered(session_id: str):
    source = session_sandbox(session_id).source_dir
    source.mkdir(parents=True, exist_ok=True)
    return source


@pytest.mark.parametrize("levels_up", [1, 2])
@pytest.mark.parametrize("caller", [None, OWN], ids=["local-no-id", "session"])
def test_an_ancestor_of_the_workspace_root_is_refused_to_a_local_caller(
    tmp_path, levels_up, caller
):
    """The defect: the local caller with no grant could scan one directory up.

    At the base the gate found the parent neither inside the root nor the
    caller's, the local fallback denies only a few system directories, and the
    scan was permitted over both sessions' delivered trees.

    Two callers: the local one that named no session (``None``, the sandbox
    with the denylist fallback, which is the caller the defect was about) and a
    session's. An earlier shape passed only the session id, so the sessionless
    branch of the refusal was never pinned.
    """
    _delivered(OWN)
    _delivered(SIBLING)
    shared = shared_workspace_root()
    assert shared is not None
    target = shared.parents[levels_up - 1]

    refusal = validate_scan_target_in_sandbox(target, session_id=caller)

    assert refusal is not None, f"{target} contains every session's source"
    assert refusal.context["error_category"] == ErrorCategory.INVALID_PATH.value
    assert CONTAINS in str(refusal)


def test_a_grant_above_the_workspace_root_does_not_admit_it(monkeypatch, tmp_path):
    """The network caller whose operator grant names the parent is refused too.

    The grant admits the parent to ``permits_scan``; the gate runs first and is
    independent of the grant, as it is for a sibling's tree under a grant.
    """
    _delivered(OWN)
    _delivered(SIBLING)
    shared = shared_workspace_root()
    assert shared is not None
    monkeypatch.setenv(ASH_MCP_TRANSPORT_ENV, "streamable-http")
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(shared.parent))

    refusal = validate_scan_target_in_sandbox(shared.parent, session_id=OWN)

    assert refusal is not None
    assert CONTAINS in str(refusal)


def test_the_refusal_shows_the_callers_path_and_no_session(tmp_path):
    """The path shown is the one the caller named; no sibling id appears."""
    _delivered(OWN)
    _delivered(SIBLING)
    shared = shared_workspace_root()
    assert shared is not None

    refusal = validate_scan_target_in_sandbox(shared.parent, session_id=OWN)

    assert refusal is not None
    assert refusal.context["resolved_path"] == str(shared.parent)
    assert SIBLING not in str(refusal)
    assert SIBLING not in str(refusal.context)


def test_a_directory_beside_the_workspace_root_is_not_taken_for_an_ancestor(
    monkeypatch, tmp_path
):
    """Control: a sibling directory of the root contains nothing of it.

    Three siblings, so a text prefix match in either direction would refuse
    one of them: the root's name is a prefix of the first's (``mcp`` of
    ``mcp-2``, the old inside-the-root text bug), the second's name is a prefix
    of the root's (``mc`` of ``mcp``, the ancestor branch's text bug: a check
    written as ``str(root).startswith(str(target))`` refuses it), and the
    third's is a prefix of the root's parent (``hom`` of ``home``). The gate
    compares path components and file identity, not characters. The directories
    are granted: a caller with a session id is a network caller
    (``caller_is_remote``), and a network caller reaches a directory outside its
    own sandbox only through the operator's grant. The grant does not admit an
    ancestor (the test above), so what admits these is the gate not firing.
    """
    _delivered(OWN)
    shared = shared_workspace_root()
    assert shared is not None
    beside = shared.with_name(shared.name + "-2")
    beside.mkdir()
    prefix_of_root = shared.with_name(shared.name[:-1])
    prefix_of_root.mkdir()
    prefix_of_parent = shared.parent.with_name(shared.parent.name[:-1])
    prefix_of_parent.mkdir()
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    granted = (beside, prefix_of_root, prefix_of_parent, checkout)
    monkeypatch.setenv(
        ASH_MCP_ALLOWED_ROOTS_ENV, os.pathsep.join(str(path) for path in granted)
    )

    for outside in granted:
        refusal = validate_scan_target_in_sandbox(outside, session_id=OWN)
        assert refusal is None, f"{outside} was refused: {refusal}"


def test_the_callers_own_tree_and_the_root_itself_are_judged_as_before(tmp_path):
    """Control: the ancestor branch changes neither the own-tree nor the root case.

    The caller's own sandbox is permitted, and the root itself is still refused
    as a sibling area (the root is inside itself, so the ancestor branch does
    not take it).
    """
    mine = _delivered(OWN)
    shared = shared_workspace_root()
    assert shared is not None

    assert validate_scan_target_in_sandbox(mine, session_id=OWN) is None
    root_refusal = validate_scan_target_in_sandbox(shared, session_id=OWN)
    assert root_refusal is not None
    assert root_refusal.context["resolved_path"] == "<another session's workspace>"
