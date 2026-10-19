# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Housekeeping that meets a filesystem error keeps going and fails safe.

Session cleanup, the presence registries and the sweep all touch files other
processes can hold, remove or replace. Each of these arms handles one error:

* removing a session whose id cannot name a directory still clears its state;
* a state write for such an id is not held against the sweep, and not refused;
* a stdio server whose exit check fails still drops its own entry, and leaves the
  default workspace alone;
* an entry that cannot be opened, or cannot be removed, counts as a live server
  (or a live scan): nothing is deleted on a guess;
* a scan presence that cannot be registered leaves the scan unregistered;
* a presence check that fails reports no scan held;
* a child whose mtime cannot be read is ignored when a workspace's last use is
  taken;
* touching a workspace never raises.

The Windows-only arms of the same functions (``msvcrt`` locking and the refusal to
open a file another process holds) cannot be reached on this platform and have no
cell here.
"""

from __future__ import annotations

import builtins
import contextlib
import os
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import (
    profile_registry,
    sessions,
    source_delivery,
)
from automated_security_helper.cli.mcp.profile_registry import (
    DEFAULT_SESSION_ID,
    clear_session_state,
    get_session_state,
)
from automated_security_helper.cli.mcp.sessions import (
    SCAN_PRESENCE_DIR,
    STDIO_SERVERS_DIR,
    ScanPresence,
    StdioServerPresence,
)


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    sessions.reset_default_registry_for_tests()
    yield workspace
    sessions.reset_default_registry_for_tests()
    clear_session_state()


def _refuse_opening(monkeypatch, target: Path) -> None:
    """``open`` raises OSError for ``target`` and works for everything else."""
    real_open = builtins.open

    def open_(file, *args, **kwargs):
        if isinstance(file, (str, os.PathLike)) and str(file) == str(target):
            raise OSError("simulated: the file cannot be opened")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", open_)


def _refuse_unlinking(monkeypatch, target: Path) -> None:
    real_unlink = Path.unlink

    def unlink(self, *args, **kwargs):
        if str(self) == str(target):
            raise OSError("simulated: the file cannot be removed")
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", unlink)


# -- removing a session ------------------------------------------------------------


def test_removing_a_session_whose_id_names_no_directory_still_clears_its_state(
    monkeypatch,
) -> None:
    session_id = "never-had-a-workspace"
    registry = sessions.get_default_registry()
    get_session_state(session_id)
    cleared: list = []
    disconnected: list = []

    def remove_session_workspace(_session_id: str) -> None:
        raise ValueError("simulated: the id names no directory")

    monkeypatch.setattr(
        source_delivery, "remove_session_workspace", remove_session_workspace
    )
    real_clear = profile_registry.clear_session_state
    monkeypatch.setattr(
        profile_registry,
        "clear_session_state",
        lambda sid=None: (cleared.append(sid), real_clear(sid)),
    )
    monkeypatch.setattr(registry, "disconnect", disconnected.append)

    sessions._remove_session_state(session_id)

    assert cleared == [session_id]
    assert disconnected == [session_id]
    assert session_id not in profile_registry._session_state


# -- a state write for an id that names no directory ----------------------------


@pytest.mark.parametrize(
    "session_id",
    ["a/b", "..", "x" * 300, "bad\x00id"],
    ids=["separator", "parent", "too-long", "nul-byte"],
)
def test_a_state_write_for_an_id_that_names_no_directory_runs_unheld(
    session_id,
) -> None:
    ran = []

    with sessions.writing_session_state(session_id):
        ran.append(True)

    assert ran == [True]


def test_a_state_write_for_a_real_session_is_held() -> None:
    registry = sessions.get_default_registry()
    session = registry.session_for("real-1")
    assert session.try_begin_sweep() is True
    session.end_sweep()

    with sessions.writing_session_state("real-1"):
        # While the write runs, the sweep cannot take the session.
        assert session.try_begin_sweep() is False
    assert session.try_begin_sweep() is True
    session.end_sweep()


# -- the stdio servers' registry -----------------------------------------------------


def test_a_stdio_exit_check_that_fails_still_drops_the_servers_own_entry(
    root, monkeypatch
) -> None:
    default = sessions.get_default_registry().get_or_create(DEFAULT_SESSION_ID)
    presence = StdioServerPresence()
    presence.__enter__()
    entry = presence._entry
    assert entry is not None and entry.is_file()

    def fail(_handle) -> None:
        raise OSError("simulated: the registry lock cannot be taken")

    monkeypatch.setattr(sessions, "_lock_blocking", fail)

    presence.__exit__(None, None, None)

    assert not entry.exists()
    assert presence._entry is None and presence._handle is None
    assert default.workspace_root is not None and default.workspace_root.is_dir()


def test_an_entry_that_cannot_be_opened_counts_as_a_live_server(
    root, monkeypatch
) -> None:
    registry = root / STDIO_SERVERS_DIR
    registry.mkdir()
    entry = registry / "1234-abcd"
    entry.write_bytes(b"")
    # Control: a free entry belongs to a server that died, and is removed.
    assert StdioServerPresence._another_server_is_live(registry) is False
    assert not entry.exists()

    entry.write_bytes(b"")
    _refuse_opening(monkeypatch, entry)

    assert StdioServerPresence._another_server_is_live(registry) is True
    assert entry.exists()


def test_an_entry_that_cannot_be_removed_counts_as_a_live_server(
    root, monkeypatch
) -> None:
    registry = root / STDIO_SERVERS_DIR
    registry.mkdir()
    entry = registry / "1234-abcd"
    entry.write_bytes(b"")
    _refuse_unlinking(monkeypatch, entry)

    assert StdioServerPresence._another_server_is_live(registry) is True
    assert entry.exists()


# -- the running scans' registry ---------------------------------------------------


@pytest.mark.parametrize("error", [OSError, ValueError, RuntimeError])
def test_a_scan_presence_that_cannot_be_registered_leaves_the_scan_unregistered(
    root, monkeypatch, error
) -> None:
    def workspace_root() -> Path:
        raise error("simulated: no usable workspace root")

    monkeypatch.setattr(sessions, "_workspace_root", workspace_root)

    with ScanPresence("scan-session-1") as presence:
        assert presence._entry is None and presence._handle is None

    assert not (root / SCAN_PRESENCE_DIR).exists()


def test_a_scan_presence_registers_when_the_workspace_exists(root) -> None:
    sessions.get_default_registry().get_or_create("scan-session-1")

    with ScanPresence("scan-session-1") as presence:
        assert presence._entry is not None and presence._entry.is_file()
        assert sessions.scan_presence_held("scan-session-1") is True

    assert sessions.scan_presence_held("scan-session-1") is False


def test_a_scan_entry_that_cannot_be_opened_counts_as_a_live_scan(
    root, monkeypatch
) -> None:
    holder = root / SCAN_PRESENCE_DIR / "scan-session-1"
    holder.mkdir(parents=True)
    entry = holder / "1234-abcd"
    entry.write_bytes(b"")
    # Control: a free entry is a scan whose server died, and is removed.
    assert sessions._a_scan_holds(holder) is False
    assert not entry.exists()

    entry.write_bytes(b"")
    _refuse_opening(monkeypatch, entry)

    assert sessions._a_scan_holds(holder) is True
    assert entry.exists()


def test_a_presence_check_that_fails_reports_no_scan_held(root, monkeypatch) -> None:
    @contextlib.contextmanager
    def guard(_root: Path):
        raise OSError("simulated: the presence lock cannot be taken")
        yield  # pragma: no cover

    monkeypatch.setattr(sessions, "_scan_presence_guard", guard)

    assert sessions.scan_presence_held("scan-session-1") is False


# -- last use ----------------------------------------------------------------------


def test_a_child_whose_mtime_cannot_be_read_is_ignored(tmp_path, monkeypatch) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    readable = sandbox / "readable"
    unreadable = sandbox / "unreadable"
    readable.write_bytes(b"")
    unreadable.write_bytes(b"")
    os.utime(readable, (2_000_000, 2_000_000))
    os.utime(unreadable, (9_000_000, 9_000_000))
    os.utime(sandbox, (1_000_000, 1_000_000))
    real_lstat = Path.lstat

    def lstat(self, *args, **kwargs):
        if self.name == "unreadable":
            raise OSError("simulated: the child vanished")
        return real_lstat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", lstat)

    assert sessions._last_used(sandbox) == 2_000_000


# -- touching a workspace ----------------------------------------------------------


def test_touching_a_workspace_refreshes_its_last_use(root) -> None:
    sessions.get_default_registry().get_or_create("touched-1")
    sandbox = root / "touched-1"
    os.utime(sandbox, (1_000_000, 1_000_000))

    sessions.touch_session_workspace("touched-1")

    assert sandbox.stat().st_mtime > 1_000_000


@pytest.mark.parametrize(
    "session_id", ["a/b", "..", "x" * 300], ids=["separator", "parent", "too-long"]
)
def test_touching_a_workspace_for_an_id_that_names_no_directory_is_a_no_op(
    root, session_id
) -> None:
    sessions.touch_session_workspace(session_id)

    assert list(root.iterdir()) == []


@pytest.mark.parametrize("error", [OSError, ValueError, RuntimeError])
def test_touching_a_workspace_never_raises(root, monkeypatch, error) -> None:
    def resolve_workspace_root() -> Path:
        raise error("simulated: no usable workspace root")

    monkeypatch.setattr(
        source_delivery, "resolve_workspace_root", resolve_workspace_root
    )

    sessions.touch_session_workspace("touched-1")


def test_touching_a_workspace_survives_a_failed_timestamp_update(
    root, monkeypatch
) -> None:
    sessions.get_default_registry().get_or_create("touched-1")

    def utime(*args, **kwargs) -> None:
        raise OSError("simulated: the timestamp cannot be set")

    monkeypatch.setattr(os, "utime", utime)

    sessions.touch_session_workspace("touched-1")
