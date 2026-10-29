#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sibling-session gate tells directories apart by file identity.

``_server_config_dir_refusal`` and ``config_is_client_supplied`` match a path's
ancestors with ``os.path.samefile``, so on a case-insensitive volume (macOS by
default) two spellings that differ only in letter case are one directory to
them. ``_sibling_refusal`` and ``SessionSandbox.owns`` compared the text of two
resolved paths instead. ``resolve`` does not fold case, so a sibling session's
tree named through the workspace root spelled in another case was outside the
shared workspace area to them, and the sibling was not refused. The same
comparison read the caller's own sandbox, spelled in another case, as somebody
else's.

The volume is simulated rather than required: ``os.path.samefile`` is replaced by
a version that folds case, so these cells read the same on a case-sensitive host.
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
    shared_workspace_root,
    validate_config_input,
    validate_scan_target_in_sandbox,
)

pytestmark = pytest.mark.unit

OWN = "session-a"
SIBLING = "session-b"

#: What a sibling refusal reports in place of the sibling's path. No other refusal
#: in the module reports it, so it tells a sibling refusal from a legacy one.
SIBLING_MARKER = "<another session's workspace>"


@pytest.fixture(autouse=True)
def _no_grant_on_stdio_in_a_workspace_of_its_own(monkeypatch, tmp_path):
    """No grant, stdio, and a workspace root under ``tmp_path``."""
    monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.delenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, raising=False)
    monkeypatch.setenv(ASH_MCP_TRANSPORT_ENV, "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))


@pytest.fixture
def case_folding_volume(monkeypatch):
    """Make ``os.path.samefile`` answer as a case-insensitive volume would.

    Two names that differ only in letter case are one file there. A pair that
    does not is left to the real function, so a directory that is truly another
    one is still another one, and a missing path still raises ``OSError``.
    """
    real_samefile = os.path.samefile

    def samefile(first, second):
        if os.fspath(first).lower() == os.fspath(second).lower():
            return True
        return real_samefile(first, second)

    monkeypatch.setattr(os.path, "samefile", samefile)


def _delivered(session_id: str) -> Path:
    """The source directory of ``session_id``, made as the sandbox lays it out."""
    source = session_sandbox(session_id).source_dir
    source.mkdir(parents=True, exist_ok=True)
    return source


def _respelled(path: Path, how: str) -> Path:
    """``path`` below the workspace root, with one part of it in upper case.

    ``root`` upper-cases the workspace root's own name; ``session`` upper-cases
    the session directory under it.
    """
    shared = shared_workspace_root()
    assert shared is not None
    below = path.relative_to(shared)
    if how == "root":
        return shared.with_name(shared.name.upper()) / below
    session, *rest = below.parts
    return shared / session.upper() / Path(*rest)


def _is_sibling_refusal(refusal) -> bool:
    return refusal is not None and refusal.context["resolved_path"] == SIBLING_MARKER


@pytest.mark.parametrize("how", ["root", "session"])
def test_a_siblings_tree_is_refused_in_any_spelling_of_its_path(
    case_folding_volume, how
):
    """The defect, in its `root` spelling. The `session` spelling is a control.

    Spelled with the workspace root in another case, the sibling's tree was not
    inside the shared area by text, so nothing refused it. Spelled with the
    session directory in another case it was inside by text and not the
    caller's, so it was refused before the change too.
    """
    _delivered(OWN)
    theirs = _delivered(SIBLING)

    exact = validate_scan_target_in_sandbox(theirs, session_id=OWN)
    respelled = validate_scan_target_in_sandbox(_respelled(theirs, how), session_id=OWN)

    assert _is_sibling_refusal(exact), "the exact spelling is no longer refused"
    assert _is_sibling_refusal(respelled), (
        f"session-b's tree was not refused when spelled with its {how} in another "
        "case, though the exact spelling is"
    )
    assert respelled.context["error_category"] == exact.context["error_category"]


def test_the_shared_workspace_root_is_refused_in_another_case(case_folding_volume):
    """The path that is itself the root, not a path below it.

    The ancestors of a path never include the path, so matching ancestors alone
    leaves this one open while its exact spelling is refused.
    """
    _delivered(OWN)
    shared = shared_workspace_root()
    assert shared is not None

    exact = validate_scan_target_in_sandbox(shared, session_id=OWN)
    respelled = validate_scan_target_in_sandbox(
        shared.with_name(shared.name.upper()), session_id=OWN
    )

    assert _is_sibling_refusal(exact), "the exact spelling is no longer refused"
    assert _is_sibling_refusal(respelled)


def test_a_sibling_config_is_refused_in_another_case(case_folding_volume):
    """The config gate asks the same question of a config file's path."""
    _delivered(OWN)
    theirs = _delivered(SIBLING)

    exact = validate_config_input(theirs / ".ash.yaml", session_id=OWN)
    respelled = validate_config_input(
        _respelled(theirs, "root") / ".ash.yaml", session_id=OWN
    )

    assert _is_sibling_refusal(exact), "the exact spelling is no longer refused"
    assert _is_sibling_refusal(respelled)


@pytest.mark.parametrize("how", ["root", "session"])
def test_a_session_owns_its_own_tree_in_any_spelling_of_its_path(
    case_folding_volume, how
):
    mine = _delivered(OWN)

    assert session_sandbox(OWN).owns(mine) is True
    assert session_sandbox(OWN).owns(_respelled(mine, how)) is True


@pytest.mark.parametrize("how", ["root", "session"])
def test_a_session_does_not_own_a_siblings_tree_in_any_spelling(
    case_folding_volume, how
):
    """Control: the identity check must not turn into "everything is mine"."""
    _delivered(OWN)
    theirs = _delivered(SIBLING)

    assert session_sandbox(OWN).owns(theirs) is False
    assert session_sandbox(OWN).owns(_respelled(theirs, how)) is False


@pytest.mark.parametrize("how", ["root", "session"])
def test_a_sessions_own_tree_is_not_refused_as_a_sibling_in_another_case(
    case_folding_volume, how
):
    """The `root` spelling is a control; `session` was refused before the change.

    The text comparison put the caller's own sandbox, spelled with its session
    directory in another case, inside the shared area and outside itself.
    """
    mine = _delivered(OWN)

    refusal = validate_scan_target_in_sandbox(_respelled(mine, how), session_id=OWN)

    assert not _is_sibling_refusal(refusal)
    assert refusal is None


@pytest.mark.parametrize("how", ["root", "session"])
def test_a_sessions_own_config_is_not_refused_in_another_case(case_folding_volume, how):
    """A config input in the caller's own tree is the caller's in any spelling.

    The sibling gate takes the respelled path as the caller's by file identity.
    The roots gate has to agree, or the caller's own config is refused as outside
    the permitted roots.
    """
    mine = _delivered(OWN)

    refusal = validate_config_input(_respelled(mine, how) / ".ash.yaml", session_id=OWN)

    assert not _is_sibling_refusal(refusal)
    assert refusal is None


@pytest.mark.parametrize("how", ["root", "session"])
def test_a_siblings_config_stays_refused_in_any_spelling_of_its_path(
    case_folding_volume, how
):
    """Control: accepting the caller's own config in any spelling takes no sibling's.

    The sibling gate runs before the roots gate, so a sibling's config is refused
    as a sibling's whatever the roots gate accepts.
    """
    _delivered(OWN)
    theirs = _delivered(SIBLING)

    refusal = validate_config_input(
        _respelled(theirs, how) / ".ash.yaml", session_id=OWN
    )

    assert _is_sibling_refusal(refusal)


def test_a_different_directory_is_still_a_different_directory(
    case_folding_volume, tmp_path
):
    """Control: a directory that only looks like the workspace area is not in it.

    Its name starts with the root's, and it holds a ``session-b/source`` of its
    own, so a prefix match or a case-folded match on the whole name would take
    it for the sibling's tree.
    """
    _delivered(OWN)
    lookalike = tmp_path / "mcp-workspaces-2" / SIBLING / "source"
    lookalike.mkdir(parents=True)
    elsewhere = tmp_path / "checkout"
    elsewhere.mkdir()

    for outside in (lookalike, elsewhere):
        assert not _is_sibling_refusal(
            validate_scan_target_in_sandbox(outside, session_id=OWN)
        )
        assert session_sandbox(OWN).owns(outside) is False
