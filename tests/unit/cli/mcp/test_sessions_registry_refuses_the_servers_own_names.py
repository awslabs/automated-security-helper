# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The session registry refuses the names the server keeps under its workspace root.

``MCPSessionRegistry.session_for`` validated an id as a path component and refused
the unidentified sentinel, and nothing else: ``.stdio-servers`` and
``.ash-mcp-scans`` (the presence registries), their case variants, and ``.lock``
(the guard file both registries lock) all made a session. A session named
``.lock`` has its scan presence holder where the guard file is, so its scans
registered nothing, with a warning, and its workspace could never be ended or
swept. A reserved name that reached ``end_session`` had the directory of that name
removed as a session's workspace, which for ``.ash-mcp-scans`` is the registry
every server sharing the root locks. The stdio session's own id stays admitted:
its workspace is a session's.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace
from automated_security_helper.cli.mcp.sessions import (
    PRESENCE_LOCK_NAME,
    SCAN_PRESENCE_DIR,
    STDIO_SERVERS_DIR,
    MCPSessionRegistry,
    ScanPresence,
    end_session,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    # Private, as a root ASH makes itself is: a listable root draws the
    # once-per-directory warning about the live session ids, which the
    # "warns of nothing" tests below would otherwise read as their own.
    workspace.mkdir(mode=0o700)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    sessions.reset_default_registry_for_tests()
    sessions._ended_while_scanning.clear()
    yield workspace
    sessions.reset_default_registry_for_tests()
    sessions._ended_while_scanning.clear()


@pytest.fixture
def warnings(monkeypatch) -> List[str]:
    """Every warning the module logs, rendered."""
    from automated_security_helper.utils.log import ASH_LOGGER

    seen: List[str] = []

    def record(message, *args, **kwargs) -> None:
        seen.append(message % args if args else message)

    monkeypatch.setattr(ASH_LOGGER, "warning", record)
    return seen


@pytest.mark.parametrize(
    ("name", "refusal"),
    [
        (STDIO_SERVERS_DIR, "cannot name a session"),
        (SCAN_PRESENCE_DIR, "cannot name a session"),
        (SCAN_PRESENCE_DIR.upper(), "cannot name a session"),
        (PRESENCE_LOCK_NAME, "cannot name a session"),
        (PRESENCE_LOCK_NAME.upper(), "cannot name a session"),
        # Windows drops a trailing period, so this spelling would name the
        # guard file's directory. The path-component rules run first and refuse
        # every trailing period with their own words (session_paths
        # validated_path_component), before the reserved-name check is reached.
        (PRESENCE_LOCK_NAME + ".", "must not end with '[.]'"),
        # The same Windows spellings of the two registry directories, and the
        # trailing space Windows drops as well (outside the character class, so
        # refused by the class before the reserved check is reached).
        (STDIO_SERVERS_DIR + ".", "must not end with '[.]'"),
        (SCAN_PRESENCE_DIR + ".", "must not end with '[.]'"),
        (PRESENCE_LOCK_NAME + " ", "may contain only"),
        (STDIO_SERVERS_DIR + " ", "may contain only"),
        (SCAN_PRESENCE_DIR + ". ", "may contain only"),
    ],
)
def test_a_name_the_server_keeps_for_itself_is_refused(tmp_path, name, refusal) -> None:
    registry = MCPSessionRegistry(workspace_parent=tmp_path / "sessions")

    with pytest.raises(ValueError, match=refusal):
        registry.session_for(name)
    assert name not in registry


@pytest.mark.parametrize(
    "name",
    [
        STDIO_SERVERS_DIR + ".",
        STDIO_SERVERS_DIR + " ",
        SCAN_PRESENCE_DIR + ".",
        SCAN_PRESENCE_DIR.upper() + ". ",
        PRESENCE_LOCK_NAME + " ",
    ],
)
def test_the_reserved_check_reads_a_name_as_windows_opens_it(name) -> None:
    """The refusals above catch these spellings at the path-component rules, which
    run first. The reserved-name check is its own gate, used where an id is not
    validated as a component (the sweep, a name read off disk), and Windows
    opens each of these as the reserved name itself."""
    from automated_security_helper.cli.mcp.session_identity import (
        is_reserved_session_id,
    )

    assert is_reserved_session_id(name), name


def test_the_stdio_session_and_an_ordinary_id_are_admitted(tmp_path) -> None:
    registry = MCPSessionRegistry(workspace_parent=tmp_path / "sessions")

    assert registry.session_for(DEFAULT_SESSION_ID).id == DEFAULT_SESSION_ID
    assert registry.session_for("ordinary-id").id == "ordinary-id"


def test_ending_the_scan_registrys_name_leaves_the_registry_on_disk(root) -> None:
    registry_dir = root / SCAN_PRESENCE_DIR
    holder = registry_dir / "another-session"
    holder.mkdir(parents=True)
    guard = registry_dir / PRESENCE_LOCK_NAME
    guard.touch()
    entry = holder / "4242-entry"
    entry.touch()

    ended = end_session(SCAN_PRESENCE_DIR)

    assert ended is True
    assert entry.is_file(), "the presence registry was removed as a workspace"
    assert guard.is_file()
    assert sessions.get_default_registry().get(SCAN_PRESENCE_DIR) is None


def test_a_scan_of_the_lock_name_registers_nothing_and_warns_of_nothing(
    root, warnings
) -> None:
    mark_session_workspace(root / PRESENCE_LOCK_NAME)
    registry_dir = root / SCAN_PRESENCE_DIR
    registry_dir.mkdir()
    guard = registry_dir / PRESENCE_LOCK_NAME
    guard.touch()

    with ScanPresence(PRESENCE_LOCK_NAME) as presence:
        registered = presence._entry

    assert registered is None
    assert guard.is_file()
    assert warnings == []
