# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Clone limits match the archive channel's, and deliveries exclude in-flight writes.

Why this exists
---------------
The clone channel bounded bytes but not entry count, so a repository of many
tiny files could exhaust inodes on the workspace volume; its size reader treated
any unreadable entry as zero bytes; and one message said a command "was stopped"
after it had already exited. Separately, the four delivery tools run on worker
threads, so a clear of the session's tree could run while a chunk of an upload
was being appended, and two chunks of one upload could both read the same next
sequence number.

The git here is a stand-in script that writes many small files.
"""

from __future__ import annotations

import asyncio
import base64
import os
import sys
import textwrap
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp_tools import mcp_set_source_git
from automated_security_helper.utils.subprocess_utils import clear_find_executable_cache

URL = "https://git.example.invalid/team/repo.git"
SESSION = "interlock-session"

_FAKE_GIT = """\
import sys
from pathlib import Path

argv = sys.argv[1:]
if "clone" not in argv:
    sys.exit(0)
target = Path(argv[-1])
target.mkdir(parents=True, exist_ok=True)
for index in range({count}):
    (target / f"f{{index}}").write_text("x")
"""


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    root = tmp_path / "ws"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.invalid")
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    sessions.reset_default_registry_for_tests()
    yield root
    clear_find_executable_cache()
    sessions.reset_default_registry_for_tests()


@pytest.fixture
def fake_git(workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    monkeypatch.setattr(sd, "GIT_TIMEOUT_SECONDS", 10)

    def install(*, count: int) -> None:
        script = bin_dir / "git"
        script.write_text(
            f"#!{sys.executable}\n" + textwrap.dedent(_FAKE_GIT.format(count=count))
        )
        script.chmod(0o755)
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
        clear_find_executable_cache()

    return install


# ---------------------------------------------------------------------------
# S1: the clone channel has the archive channel's entry cap.
# ---------------------------------------------------------------------------


def test_a_clone_within_the_entry_cap_succeeds(fake_git, monkeypatch) -> None:
    """Positive control: the cap does not refuse a clone that stays under it."""

    monkeypatch.setattr(sd, "_MAX_FILES", 50)
    fake_git(count=10)

    result = mcp_set_source_git(url=URL, session_id=SESSION)

    assert result.get("success") is True, result


def test_a_clone_past_the_entry_cap_is_refused(
    fake_git, workspace, monkeypatch
) -> None:
    monkeypatch.setattr(sd, "_MAX_FILES", 50)
    fake_git(count=120)

    result = mcp_set_source_git(url=URL, session_id=SESSION)

    assert result.get("success") is False, result
    assert result.get("error_type") == "clone_too_large", result
    assert not (workspace / SESSION / "source").exists()


# ---------------------------------------------------------------------------
# S2: a tree that cannot be read is refused, not measured as empty.
# ---------------------------------------------------------------------------


def test_an_unreadable_tree_is_refused_not_measured_as_zero(
    tmp_path: Path, monkeypatch
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "blob").write_bytes(b"x" * 2048)
    real = os.scandir

    def deny(path: Any = ".") -> Any:
        if os.fspath(path) == os.fspath(tree):
            raise PermissionError(13, "Permission denied", os.fspath(path))
        return real(path)

    monkeypatch.setattr(os, "scandir", deny)

    with pytest.raises(sd.CloneTooLargeError):
        sd._refuse_oversized(tree)


def test_an_unreadable_entry_is_refused_not_counted_as_zero(
    tmp_path: Path, monkeypatch
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "blob").write_bytes(b"x" * 2048)
    real = os.lstat

    def deny(path: Any, *args: Any, **kwargs: Any) -> Any:
        if os.fspath(path).endswith("blob"):
            raise PermissionError(13, "Permission denied", os.fspath(path))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", deny)

    with pytest.raises(sd.CloneTooLargeError):
        sd._refuse_oversized(tree)


def test_an_entry_that_vanishes_mid_walk_is_still_measured(
    tmp_path: Path, monkeypatch
) -> None:
    """Positive control: a file git removed between listing and reading is not a refusal."""

    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "kept").write_bytes(b"x" * 16)
    (tree / "gone").write_bytes(b"x" * 16)
    real = os.lstat

    def vanish(path: Any, *args: Any, **kwargs: Any) -> Any:
        if os.fspath(path).endswith("gone"):
            raise FileNotFoundError(2, "No such file", os.fspath(path))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", vanish)

    assert sd._tree_bytes(tree) == 16
    sd._refuse_oversized(tree)


# ---------------------------------------------------------------------------
# S3: the wording of the size refusal matches what happened.
# ---------------------------------------------------------------------------


def test_a_command_that_exited_oversized_is_not_said_to_be_stopped(
    tmp_path: Path, monkeypatch
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "blob").write_bytes(b"x" * 4096)
    monkeypatch.setattr(sd, "MAX_CLONE_BYTES", 1024)

    with pytest.raises(sd.CloneTooLargeError) as after_exit:
        sd._refuse_oversized(tree)
    with pytest.raises(sd.CloneTooLargeError) as while_running:
        sd._refuse_oversized(tree, running=True)

    assert "stopped" not in str(after_exit.value)
    assert "stopped" in str(while_running.value)


# ---------------------------------------------------------------------------
# F1: a change excludes in-flight writes, and a write excludes a change.
# ---------------------------------------------------------------------------


def _chunk(upload: str, sequence: int, data: bytes, last: bool = False) -> dict:
    return sd.set_source_zip_chunk(
        upload,
        sequence,
        base64.b64encode(data).decode(),
        last,
        session_id=SESSION,
    )


def test_a_clear_is_refused_while_a_chunk_is_being_appended(
    workspace, monkeypatch
) -> None:
    inside = threading.Event()
    release = threading.Event()
    real = sd._append_zip_chunk

    def held(*args: Any, **kwargs: Any) -> Any:
        inside.set()
        assert release.wait(10), "the clear never finished"
        return real(*args, **kwargs)

    monkeypatch.setattr(sd, "_append_zip_chunk", held)
    outcome: Dict[str, Any] = {}

    def append() -> None:
        outcome["chunk"] = _chunk("u1", 0, b"abc")

    thread = threading.Thread(target=append)
    thread.start()
    try:
        assert inside.wait(10), "the chunk never started"
        with pytest.raises(sd.SourceDeliveryBusyError):
            sd.clear_source(SESSION)
    finally:
        release.set()
        thread.join(10)

    assert outcome["chunk"]["next_sequence"] == 1
    part = workspace / SESSION / "incoming" / "u1.zip.part"
    assert part.read_bytes() == b"abc"


def test_a_chunk_is_refused_while_a_change_holds_the_session(workspace) -> None:
    with sd._no_scan_running(SESSION):
        with pytest.raises(sessions.SessionWorkspaceBusyError):
            _chunk("u1", 0, b"abc")

    assert _chunk("u1", 0, b"abc")["next_sequence"] == 1


def test_a_session_ended_during_a_write_is_removed_when_the_write_ends(
    workspace,
) -> None:
    from automated_security_helper.cli.mcp.session_paths import mark_session_workspace

    sandbox = mark_session_workspace(workspace / SESSION)
    with sessions.writing_session_state(SESSION):
        assert sessions.end_session(SESSION) is False
        assert sandbox.exists(), "removed under a write in progress"

    assert not sandbox.exists()


# ---------------------------------------------------------------------------
# L2: chunks of one upload are applied one at a time.
# ---------------------------------------------------------------------------


def test_two_chunks_with_one_sequence_number_accept_exactly_one(
    workspace, monkeypatch
) -> None:
    real = sd._read_next_sequence

    def slow_read(*args: Any, **kwargs: Any) -> int:
        value = real(*args, **kwargs)
        time.sleep(0.4)
        return value

    monkeypatch.setattr(sd, "_read_next_sequence", slow_read)
    results: List[Any] = []

    def send(data: bytes) -> None:
        try:
            results.append(_chunk("u2", 0, data))
        except ValueError as exc:
            results.append(exc)

    threads = [
        threading.Thread(target=send, args=(b"AAAA",)),
        threading.Thread(target=send, args=(b"BBBB",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(20)

    accepted = [r for r in results if isinstance(r, dict)]
    refused = [r for r in results if isinstance(r, ValueError)]
    assert len(accepted) == 1 and len(refused) == 1, results
    part = workspace / SESSION / "incoming" / "u2.zip.part"
    assert part.stat().st_size == 4


# ---------------------------------------------------------------------------
# L5: deliveries run on their own bounded executor.
# ---------------------------------------------------------------------------


def test_delivery_handlers_use_their_own_bounded_executor(
    workspace, monkeypatch
) -> None:
    from unittest.mock import MagicMock

    from automated_security_helper.cli import mcp_server

    seen: Dict[str, Any] = {}

    def record(*args: Any, **kwargs: Any) -> dict:
        seen["thread"] = threading.current_thread().name
        return {"success": True}

    async def anoop(*args: Any, **kwargs: Any) -> None:
        return None

    ctx = MagicMock()
    ctx.headers = {"mcp-session-id": SESSION}
    for name in ("info", "error", "debug", "warning", "report_progress"):
        setattr(ctx, name, MagicMock(side_effect=anoop))
    monkeypatch.setattr(mcp_server, "mcp_clear_source", record)

    asyncio.run(mcp_server.clear_source(ctx))

    assert seen["thread"].startswith("ash-mcp-delivery"), seen
    executor = mcp_server._DELIVERY_EXECUTOR
    assert executor._max_workers == sd.DELIVERY_MAX_WORKERS
