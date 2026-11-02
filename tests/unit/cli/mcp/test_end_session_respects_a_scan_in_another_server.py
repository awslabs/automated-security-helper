# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``end_session`` leaves the tree a scan in another server sharing the root is reading.

A scan holds its session's claim in the process that runs it, and a locked entry
under ``<root>/.ash-mcp-scans/<session id>/`` for every server sharing the root
(``sessions.ScanPresence``). Ending a session in a server that has no claim of its
own must still see that entry: removing the tree under a running scan can turn its
result into a clean one. Nothing in this process learns when the scan elsewhere
returns, so the deferred removal is the TTL sweep's. Whatever removes a session's
workspace also drops the entries of scans that died and the empty directory that
held them.
"""

from __future__ import annotations

import contextlib
import errno
import itertools
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

import pytest

from automated_security_helper.cli.mcp import (
    profile_registry,
    sessions,
    source_delivery,
)
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS, KillAfter

_HOLDER = """
import sys
from automated_security_helper.cli.mcp.sessions import ScanPresence
with ScanPresence(sys.argv[1]):
    print("held", flush=True)
    sys.stdin.readline()
"""


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    # delivered_session_count reads this process-wide record; a record another
    # test left would count here.
    monkeypatch.setattr(source_delivery, "_SESSION_SOURCE_DIRS", {})
    sessions.reset_default_registry_for_tests()
    sessions.reset_guard_refusal_warning_for_tests()
    sessions._ended_while_scanning.clear()
    # The delivered-source records live for the process. Two cells below assert
    # delivered_session_count() against absolute values, so a record another
    # test module left behind on this xdist worker would shift every count by
    # one. Start from empty and put the stranger's records back afterwards.
    saved_sources = dict(source_delivery._SESSION_SOURCE_DIRS)
    source_delivery._SESSION_SOURCE_DIRS.clear()
    yield workspace
    sessions.reset_default_registry_for_tests()
    sessions.reset_guard_refusal_warning_for_tests()
    sessions._ended_while_scanning.clear()
    source_delivery._SESSION_SOURCE_DIRS.clear()
    source_delivery._SESSION_SOURCE_DIRS.update(saved_sources)


def _sandbox(root: Path, session_id: str) -> Path:
    sandbox = mark_session_workspace(root / session_id)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return sandbox


@contextlib.contextmanager
def _scan_in_another_process(root: Path, session_id: str):
    env = dict(os.environ, ASH_MCP_WORKSPACE_ROOT=str(root))
    child = subprocess.Popen(
        [sys.executable, "-c", _HOLDER, session_id],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        with KillAfter(child, "the process holding the scan presence"):
            line = child.stdout.readline()
            assert line.strip() == "held", child.stderr.read()
            yield
    finally:
        if child.stdin:
            child.stdin.close()
        try:
            child.wait(timeout=CHILD_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=CHILD_TIMEOUT_SECONDS)
            raise


@pytest.mark.integration
def test_ending_a_session_defers_while_a_scan_in_another_server_runs(root) -> None:
    sandbox = _sandbox(root, "elsewhere")

    with _scan_in_another_process(root, "elsewhere"):
        removed_now = sessions.end_session("elsewhere")
        kept = (sandbox / "source" / "app.py").is_file()
        deferred = "elsewhere" in sessions._ended_while_scanning

    assert removed_now is False
    assert kept, "the tree a scan in another server was reading was removed"
    assert deferred


@pytest.mark.integration
def test_the_ttl_sweep_removes_the_deferred_session_once_that_scan_is_gone(
    root,
) -> None:
    """Nothing in this process learns that the scan elsewhere returned: the sweep
    is the collector (see ``end_session``)."""
    sandbox = _sandbox(root, "elsewhere")
    with _scan_in_another_process(root, "elsewhere"):
        assert sessions.end_session("elsewhere") is False
        assert sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600) == []
        assert sandbox.is_dir(), "the sweep removed the tree under the running scan"

    removed = sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600)

    assert removed == ["elsewhere"]
    assert not sandbox.exists()
    assert not (root / sessions.SCAN_PRESENCE_DIR / "elsewhere").exists()
    assert "elsewhere" not in sessions._ended_while_scanning


@pytest.mark.unit
def test_ending_a_session_drops_the_entry_a_dead_scan_left(root) -> None:
    sandbox = _sandbox(root, "orphaned")
    holder = root / sessions.SCAN_PRESENCE_DIR / "orphaned"
    holder.mkdir(parents=True)
    (holder / "12345-deadbeef").write_bytes(b"")

    assert sessions.end_session("orphaned") is True

    assert not sandbox.exists()
    assert not holder.exists(), "the dead scan's entry and its directory were kept"


@pytest.fixture
def ash_log():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    previous = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous)


@pytest.mark.unit
def test_a_presence_guard_that_cannot_be_taken_clears_the_memory_and_warns(
    root, monkeypatch, ash_log
) -> None:
    """Unable to prove no scan holds the session, end_session leaves the tree on
    disk for the sweep, and does not keep the session's state in memory for the
    life of the process."""
    sandbox = _sandbox(root, "unreadable")
    profile_registry.bind_session_config(
        "unreadable", config=AshConfig(), profile_name="strict"
    )
    source_delivery._set_session_source_dir("unreadable", sandbox / "source")
    registry = sessions.get_default_registry()
    registry.session_for("unreadable")

    def refused(_root, **_kwargs):
        raise PermissionError(errno.EACCES, "Permission denied")

    try:
        with monkeypatch.context() as patched:
            patched.setattr(sessions, "_scan_presence_guard", refused)
            removed_now = sessions.end_session("unreadable")

        assert removed_now is False
        assert (sandbox / "source" / "app.py").is_file()
        assert "unreadable" not in registry
        assert not profile_registry.session_has_binding("unreadable")
        assert source_delivery.get_session_source_dir("unreadable") is None
        assert source_delivery.delivered_session_count() == 0
        assert "unreadable" not in sessions._ended_while_scanning
        warned = [r.getMessage() for r in ash_log if "presence lock" in r.getMessage()]
        assert len(warned) == 1, warned
        assert str(root / sessions.SCAN_PRESENCE_DIR / ".lock") in warned[0]
        assert f"errno {errno.EACCES} EACCES" in warned[0], warned[0]
        assert "file locks" not in warned[0], "a permission error is not a lock report"

        removed = sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600)

        assert removed == ["unreadable"], "a sweep whose guard succeeds collects it"
        assert not sandbox.exists()
    finally:
        profile_registry.clear_all_session_state()
        source_delivery._drop_session_source_dir("unreadable")


@pytest.mark.unit
def test_forgetting_a_session_drops_its_delivered_source_record(
    root, monkeypatch, ash_log
) -> None:
    """On a root that refuses the lock for good, the forget drops the
    delivered-source record and the registry entry, and the refused sweep
    leaves both dropped: it opens no registry entry for the tree it cannot
    remove. A record left behind would keep ``delivered_session_count``
    inflated by ended sessions and read as bound the next time the entry is
    opened."""
    sandbox = _sandbox(root, "unreadable")
    profile_registry.bind_session_config(
        "unreadable", config=AshConfig(), profile_name="strict"
    )
    source_delivery._set_session_source_dir("unreadable", sandbox / "source")
    registry = sessions.get_default_registry()
    registry.session_for("unreadable")
    assert source_delivery.delivered_session_count() == 1

    def refused(_root, **_kwargs):
        raise PermissionError("the presence registry cannot be opened")

    # Permanent: the sweep below hits the same refusal.
    monkeypatch.setattr(sessions, "_scan_presence_guard", refused)

    try:
        assert sessions.end_session("unreadable") is False

        assert source_delivery.get_session_source_dir("unreadable") is None
        assert source_delivery.delivered_session_count() == 0
        assert "unreadable" not in registry

        # The sweep's guard is refused again before any session is looked up,
        # so it removes nothing and opens no registry entry: the forget stands
        # with no eviction pass and no clock set by hand.
        assert sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600) == []
        assert (sandbox / "source" / "app.py").is_file()

        assert registry.get("unreadable") is None, "the sweep re-created the entry"
        assert "unreadable" not in registry, "the forget was undone by the sweep"
        assert source_delivery.delivered_session_count() == 0
    finally:
        profile_registry.clear_all_session_state()
        source_delivery._drop_session_source_dir("unreadable")


@pytest.fixture
def registry_calls(monkeypatch) -> List[str]:
    """Every ``session_for`` and ``forget`` call on any registry, in order."""
    calls: List[str] = []
    real_session_for = sessions.MCPSessionRegistry.session_for
    real_forget = sessions.MCPSessionRegistry.forget

    def session_for(self, session_id):
        calls.append(f"session_for:{session_id}")
        return real_session_for(self, session_id)

    def forget(self, session_id):
        calls.append(f"forget:{session_id}")
        return real_forget(self, session_id)

    monkeypatch.setattr(sessions.MCPSessionRegistry, "session_for", session_for)
    monkeypatch.setattr(sessions.MCPSessionRegistry, "forget", forget)
    return calls


def _refuse_the_presence_guard(
    monkeypatch, error: Optional[OSError] = None
) -> List[Path]:
    """Make every ``_scan_presence_guard`` call raise; the list records each attempt.

    The double takes the guard's keyword arguments too (the sweep asks for the
    lock with a bounded ``wait``), so a call of either shape reaches the raise.
    """
    attempts: List[Path] = []
    raised = error or PermissionError(errno.EACCES, "Permission denied")

    def refused(guard_root, **_kwargs):
        attempts.append(guard_root)
        raise raised

    monkeypatch.setattr(sessions, "_scan_presence_guard", refused)
    return attempts


@pytest.mark.unit
def test_a_refused_sweep_opens_no_entry_for_two_stale_trees(
    root, monkeypatch, registry_calls
) -> None:
    """Two trees, so a lookup placed ahead of the guard for the first tree only
    does not pass: the refused sweep leaves the registry as it found it and
    tries the guard once for the pass."""
    sandboxes = [_sandbox(root, name) for name in ("stale-a", "stale-b")]
    attempts = _refuse_the_presence_guard(monkeypatch)

    assert sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600) == []

    registry = sessions.get_default_registry()
    assert len(registry) == 0, "the sweep opened a registry entry"
    assert "stale-a" not in registry and "stale-b" not in registry
    assert len(attempts) == 1, "one guard attempt for the pass, not one per tree"
    assert all((s / "source" / "app.py").is_file() for s in sandboxes)


@pytest.mark.unit
def test_a_refused_sweep_does_not_add_and_remove_an_entry(
    root, monkeypatch, registry_calls
) -> None:
    """An entry opened and forgotten again within the pass leaves the map as it
    was, so the cell reads the registry's calls, not its final contents."""
    _sandbox(root, "stale-c")
    _refuse_the_presence_guard(monkeypatch)

    assert sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600) == []

    assert registry_calls == [], registry_calls


@pytest.mark.unit
def test_a_sweep_with_nothing_stale_never_takes_the_guard(root, monkeypatch) -> None:
    """The guard is tried only when a workspace is stale: a root with nothing to
    remove gets no registry directory and no lock file from the sweep."""
    _sandbox(root, "fresh")
    attempts = _refuse_the_presence_guard(monkeypatch)

    assert sessions.sweep_stale_workspaces(3600.0, now=time.time()) == []

    assert attempts == []
    assert not (root / sessions.SCAN_PRESENCE_DIR).exists()


def _guard_warnings(ash_log) -> List[str]:
    """The warnings about a refused presence guard, from any place that reports one."""
    return [
        r.getMessage()
        for r in ash_log
        if "Could not take the scan presence lock" in r.getMessage()
    ]


@pytest.mark.unit
def test_a_permanently_refused_guard_keeps_the_tree_and_the_process_warns_once(
    root, monkeypatch, ash_log
) -> None:
    """On a filesystem that reports it cannot lock files, every sweep is refused
    the same way, so nothing removes the tree. The process warns once for the
    refusal, at the first place that meets it (here end_session), with the
    errno; the sweeps that follow add no second warning."""
    sandbox = _sandbox(root, "refused")
    _refuse_the_presence_guard(monkeypatch, OSError(errno.ENOLCK, "No locks available"))

    assert sessions.end_session("refused") is False
    assert sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600) == []
    assert sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600) == []

    assert (sandbox / "source" / "app.py").is_file(), "nothing can remove the tree"
    warned = _guard_warnings(ash_log)
    assert len(warned) == 1, warned
    assert "while ending session 'refused'" in warned[0], warned[0]
    assert f"errno {errno.ENOLCK} ENOLCK: No locks available" in warned[0], warned[0]
    assert "stays on disk after it ends or goes idle" in warned[0], warned[0]
    assert "cannot lock files" in warned[0], warned[0]


_SITES = ("end_session", "scan", "sweep")
_FIRST_SEEN = {
    "end_session": "while ending session 'ended'",
    "scan": "while registering a scan of session 'scanned'",
    "sweep": "while running the TTL sweep",
}


def _meet_the_refusal_at(site: str) -> None:
    if site == "end_session":
        sessions.end_session("ended")
    elif site == "scan":
        with sessions.ScanPresence("scanned"):
            pass
    else:
        sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600)


@pytest.mark.parametrize("order", list(itertools.permutations(_SITES)))
@pytest.mark.unit
def test_one_latch_serves_end_session_the_scan_and_the_sweep(
    order, root, monkeypatch, ash_log
) -> None:
    """The three places that take the guard share one warning per refusal, in
    any order, and the one warning names the place that met it first."""
    for name in ("ended", "scanned", "stale"):
        _sandbox(root, name)
    _refuse_the_presence_guard(monkeypatch, OSError(errno.ENOLCK, "No locks available"))

    for site in order:
        _meet_the_refusal_at(site)

    warned = _guard_warnings(ash_log)
    assert len(warned) == 1, (order, warned)
    assert _FIRST_SEEN[order[0]] in warned[0], (order, warned[0])


@pytest.mark.unit
def test_ending_many_sessions_at_shutdown_warns_once(
    root, monkeypatch, ash_log
) -> None:
    """``_end_all_on_shutdown`` ends every issued session in a row."""
    names = [f"issued-{index}" for index in range(5)]
    for name in names:
        _sandbox(root, name)
    _refuse_the_presence_guard(monkeypatch, OSError(errno.ENOLCK, "No locks available"))

    for name in names:
        assert sessions.end_session(name) is False

    assert len(_guard_warnings(ash_log)) == 1, _guard_warnings(ash_log)


@pytest.mark.unit
def test_a_failure_to_open_the_guard_is_not_reported_as_a_lock_refusal(
    root, monkeypatch, ash_log
) -> None:
    """mkdir, open and Windows lock-timeout failures say nothing about lock
    support: the warning carries the errno and says the failure may clear."""
    for number, text in (
        (errno.EMFILE, "Too many open files"),
        (errno.EROFS, "Read-only file system"),
        (errno.ENOSPC, "No space left on device"),
        (errno.EDEADLK, "Resource deadlock avoided"),
    ):
        sessions.reset_guard_refusal_warning_for_tests()
        _sandbox(root, f"stale-{number}")
        _refuse_the_presence_guard(monkeypatch, OSError(number, text))
        ash_log.clear()

        assert sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600) == []

        swept = _guard_warnings(ash_log)
        assert len(swept) == 1, swept
        assert f"errno {number} " in swept[0] and text in swept[0], swept[0]
        assert "cannot lock files" not in swept[0], swept[0]
        assert "may clear" in swept[0], swept[0]


@pytest.mark.unit
def test_a_refusal_after_a_taken_guard_is_reported_again(
    root, monkeypatch, ash_log
) -> None:
    """The warn-once latch spends the warning on a first, possibly transient
    failure; a guard that is taken afterwards clears it, so a later permanent
    refusal is reported with its own errno."""
    first = _sandbox(root, "first")

    with monkeypatch.context() as patched:
        _refuse_the_presence_guard(
            patched, OSError(errno.EMFILE, "Too many open files")
        )
        assert sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600) == []
    assert len(_guard_warnings(ash_log)) == 1
    assert first.is_dir()

    # The guard is real again: this pass takes it and removes the tree.
    assert sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600) == ["first"]
    assert sessions._guard_refusal_warned is False, "a taken guard clears the latch"

    _sandbox(root, "second")
    with monkeypatch.context() as patched:
        _refuse_the_presence_guard(patched, OSError(errno.ENOLCK, "No locks available"))
        assert sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600) == []

    swept = _guard_warnings(ash_log)
    assert len(swept) == 2, swept
    assert f"errno {errno.EMFILE} " in swept[0] and "may clear" in swept[0], swept[0]
    assert f"errno {errno.ENOLCK} " in swept[1], swept[1]
    assert "cannot lock files" in swept[1], swept[1]


@pytest.mark.parametrize(
    "number,is_lock_refusal",
    [
        (errno.ENOLCK, True),
        (errno.EOPNOTSUPP, True),
        (errno.ENOSYS, True),
        (errno.EACCES, False),
        (errno.EROFS, False),
        (errno.ENOSPC, False),
        (errno.EMFILE, False),
        (errno.EDEADLK, False),
        (None, False),
    ],
)
@pytest.mark.unit
def test_only_the_lock_errnos_class_a_failure_as_a_lock_refusal(
    number, is_lock_refusal
) -> None:
    error = OSError(number, "x") if number is not None else OSError("no errno")

    assert sessions._is_lock_refusal(error) is is_lock_refusal


@pytest.mark.unit
def test_an_error_with_no_errno_is_described_by_its_type() -> None:
    assert sessions._describe_os_error(OSError("no errno")) == "OSError: no errno"
    assert (
        sessions._describe_os_error(OSError(errno.EACCES, "Permission denied"))
        == f"errno {errno.EACCES} EACCES: Permission denied"
    )


@pytest.mark.unit
def test_an_error_that_names_a_file_is_described_with_it() -> None:
    error = OSError(errno.ESTALE, "FAKE stale file handle", "FAKE-registry-dir")

    assert sessions._describe_os_error(error) == (
        f"errno {errno.ESTALE} ESTALE: FAKE stale file handle: FAKE-registry-dir"
    )


@pytest.mark.unit
def test_an_error_that_names_two_files_is_described_with_both() -> None:
    error = OSError(
        errno.EXDEV, "FAKE cross-device link", "FAKE-source", None, "FAKE-target"
    )

    assert sessions._describe_os_error(error) == (
        f"errno {errno.EXDEV} EXDEV: FAKE cross-device link: FAKE-source -> FAKE-target"
    )


@pytest.mark.unit
def test_ending_the_default_session_reads_the_scan_presence_registry(root) -> None:
    """Every stdio server of one user shares ``__default__``, so a scan of it in
    a sibling server holds a presence entry like a replica's scan of a session,
    and ending it reads the registry as for any session. With no scan held, the
    workspace goes and no entry of its own is left behind."""
    default = mark_session_workspace(root / profile_registry.DEFAULT_SESSION_ID)
    (default / "source").mkdir()

    assert sessions.end_session(profile_registry.DEFAULT_SESSION_ID) is True

    assert not default.exists()
    holder = root / sessions.SCAN_PRESENCE_DIR / profile_registry.DEFAULT_SESSION_ID
    assert not holder.exists()


@pytest.mark.unit
def test_a_guard_that_cannot_be_taken_does_not_strand_the_default_workspace(
    root, monkeypatch
) -> None:
    default = mark_session_workspace(root / profile_registry.DEFAULT_SESSION_ID)

    def refused(_root, **_kwargs):
        raise PermissionError("the presence registry cannot be opened")

    monkeypatch.setattr(sessions, "_scan_presence_guard", refused)

    assert sessions.end_session(profile_registry.DEFAULT_SESSION_ID) is True
    assert not default.exists()


@pytest.mark.unit
def test_ending_an_unknown_session_creates_nothing_under_the_root(root) -> None:
    assert sessions.end_session("never-existed") is True

    assert sorted(p.name for p in root.iterdir()) == []


@pytest.mark.unit
def test_the_reset_helper_clears_a_latch_a_refusal_set(root) -> None:
    sessions._warn_guard_refused_once(root, PermissionError(errno.EACCES, "x"), "a")
    assert sessions._guard_refusal_warned is True

    sessions.reset_guard_refusal_warning_for_tests()

    assert sessions._guard_refusal_warned is False


@pytest.mark.unit
def test_the_conftest_reset_clears_a_latch_a_refusal_set(root, monkeypatch) -> None:
    """The autouse conftest fixture resets MCP session state through
    ``_drop_mcp_session_state``; called directly, so the cell proves the latch
    is part of that reset without depending on which cell ran before it or on
    how xdist ordered the file.
    ``test_the_reset_helper_clears_a_latch_a_refusal_set`` above covers only the
    sessions-module helper, not the conftest plumbing."""
    from tests.conftest import _drop_mcp_session_state

    _sandbox(root, "latch-set-by-a-refusal")
    _refuse_the_presence_guard(monkeypatch)
    sessions.end_session("latch-set-by-a-refusal")
    assert sessions._guard_refusal_warned is True

    _drop_mcp_session_state()

    assert sessions._guard_refusal_warned is False
