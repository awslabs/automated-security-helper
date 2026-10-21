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
import errno
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

    with pytest.raises(sd.CloneTreeUnreadableError):
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

    with pytest.raises(sd.CloneTreeUnreadableError):
        sd._refuse_oversized(tree)


def test_an_unreadable_tree_is_not_reported_as_too_large(
    tmp_path: Path, monkeypatch
) -> None:
    """The two refusals tell a client opposite things (shrink the request, or not)."""

    tree = tmp_path / "tree"
    tree.mkdir()
    real = os.scandir

    def deny(path: Any = ".") -> Any:
        if os.fspath(path) == os.fspath(tree):
            raise PermissionError(13, "Permission denied", os.fspath(path))
        return real(path)

    monkeypatch.setattr(os, "scandir", deny)

    with pytest.raises(sd.CloneTreeUnreadableError) as unreadable:
        sd._refuse_oversized(tree)

    assert not isinstance(unreadable.value, sd.CloneTooLargeError)
    assert sd.CLONE_TREE_UNREADABLE != sd.CLONE_TOO_LARGE


def test_an_unreadable_tree_is_reported_by_its_own_error_type(
    fake_git, workspace, monkeypatch
) -> None:
    fake_git(count=3)
    real = os.scandir

    def deny_the_clone_target(path: Any = ".") -> Any:
        # A descriptor (shutil.rmtree's own scan) is passed through.
        if isinstance(path, (str, os.PathLike)) and os.fspath(path).endswith(
            os.sep + "source"
        ):
            raise PermissionError(13, "Permission denied", os.fspath(path))
        return real(path)

    monkeypatch.setattr(os, "scandir", deny_the_clone_target)

    result = mcp_set_source_git(url=URL, session_id=SESSION)

    assert result.get("success") is False, result
    assert result.get("error_type") == "clone_tree_unreadable", result
    assert not (workspace / SESSION / "source").exists()


def test_a_path_that_changes_kind_during_a_poll_is_not_an_error(
    tmp_path: Path,
) -> None:
    """A directory the walker listed becomes a file before it is scanned."""

    tree = tmp_path / "tree"
    (tree / "a").mkdir(parents=True)
    (tree / "a" / "inner").write_bytes(b"x" * 8)
    (tree / "keep").write_bytes(b"x" * 16)
    real = os.scandir

    def swapped(path: Any = ".") -> Any:
        if os.fspath(path) == os.fspath(tree / "a"):
            raise NotADirectoryError(20, "Not a directory", os.fspath(path))
        return real(path)

    with pytest.MonkeyPatch.context() as patched:
        patched.setattr(os, "scandir", swapped)

        size, entries = sd._tree_extent(tree, running=True)
        sd._refuse_oversized(tree, running=True)

        with pytest.raises(NotADirectoryError):
            sd._tree_extent(tree)
        with pytest.raises(sd.CloneTreeUnreadableError):
            sd._refuse_oversized(tree)

    assert size >= 16 and entries >= 2


def test_a_directory_that_becomes_a_file_under_a_live_poll_does_not_stop_the_command(
    tmp_path: Path, monkeypatch
) -> None:
    """The kind of a path changes between the walker listing it and scanning it,
    as ``git checkout`` does to a path that is a directory at one ref and a file at
    another. The error is the operating system's own."""

    tree = tmp_path / "tree"
    (tree / "a").mkdir(parents=True)
    (tree / "a" / "inner").write_bytes(b"x" * 8)
    real = os.scandir
    swapped: List[str] = []

    def swap_then_scan(path: Any = ".") -> Any:
        if (
            isinstance(path, (str, os.PathLike))
            and os.fspath(path) == os.fspath(tree / "a")
            and not swapped
        ):
            swapped.append("swapped")
            (tree / "a" / "inner").unlink()
            (tree / "a").rmdir()
            (tree / "a").write_text("now a file")
        return real(path)

    monkeypatch.setattr(os, "scandir", swap_then_scan)
    monkeypatch.setattr(sd, "GIT_POLL_SECONDS", 0.05)

    result = sd._run_git(
        [sys.executable, "-c", "import time; time.sleep(0.5)"],
        env=dict(os.environ),
        grows_in=tree,
    )

    assert swapped == ["swapped"], "the poll never reached the directory"
    assert result.returncode == 0


def test_a_checkout_that_turns_a_directory_into_a_file_is_not_refused(
    tmp_path: Path, monkeypatch
) -> None:
    """A real repository: a path is a directory at the default branch and a file at
    the ref, and ``git checkout --detach`` to the ref is not refused by the walker."""

    import shutil
    import subprocess

    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not installed")
    repo = tmp_path / "repo"
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }

    def run(*argv: str) -> None:
        subprocess.run(  # nosec B603 - a fixture repository in tmp_path, no remote
            [git, "-C", str(repo), *argv],
            check=True,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    repo.mkdir()
    run("init", "-q", "-b", "main")
    (repo / "a").mkdir()
    (repo / "a" / "inner").write_text("x")
    run("add", "-A")
    run("commit", "-q", "-m", "directory")
    run("rm", "-q", "-r", "a")
    (repo / "a").write_text("now a file")
    run("add", "-A")
    run("commit", "-q", "-m", "file")
    run("checkout", "-q", "HEAD~1")

    monkeypatch.setattr(sd, "GIT_POLL_SECONDS", 0.01)
    result = sd._run_git(
        [git, "-C", str(repo), "checkout", "--detach", "main"],
        env=env,
        grows_in=repo,
    )

    assert result.returncode == 0, result.stderr
    assert (repo / "a").is_file()


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


def test_an_entry_that_vanishes_during_a_live_poll_is_still_measured(
    tmp_path: Path, monkeypatch
) -> None:
    """Positive control: the removal race is tolerated while the command runs too."""

    tree = tmp_path / "tree"
    (tree / "a").mkdir(parents=True)
    (tree / "keep").write_bytes(b"x" * 16)
    real = os.scandir

    def gone(path: Any = ".") -> Any:
        if os.fspath(path) == os.fspath(tree / "a"):
            raise FileNotFoundError(2, "No such file", os.fspath(path))
        return real(path)

    monkeypatch.setattr(os, "scandir", gone)

    size, entries = sd._tree_extent(tree, running=True)
    sd._refuse_oversized(tree, running=True)

    assert size >= 16 and entries >= 1


@pytest.mark.parametrize(
    ("code", "name"),
    [
        (errno.ENAMETOOLONG, "File name too long"),
        (errno.EACCES, "Permission denied"),
        (errno.EMFILE, "Too many open files"),
    ],
)
def test_a_subtree_the_live_poll_cannot_walk_is_refused_not_left_uncounted(
    tmp_path: Path, monkeypatch, code: int, name: str
) -> None:
    """A read error that is not one of git's own rewrites stops the command.

    The poll while git writes is the only size check until the command exits,
    so a subtree it cannot open must refuse the delivery rather than count as
    empty for the rest of the run.
    """

    tree = tmp_path / "tree"
    (tree / "a").mkdir(parents=True)
    (tree / "a" / "inner").write_bytes(b"x" * 8)
    real = os.scandir

    def deny(path: Any = ".") -> Any:
        if os.fspath(path) == os.fspath(tree / "a"):
            raise OSError(code, name, os.fspath(path))
        return real(path)

    monkeypatch.setattr(os, "scandir", deny)

    with pytest.raises(sd.CloneTreeUnreadableError):
        sd._refuse_oversized(tree, running=True)


def test_an_entry_the_live_poll_cannot_stat_is_refused_not_counted_as_zero(
    tmp_path: Path, monkeypatch
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "blob").write_bytes(b"x" * 2048)
    real = os.lstat

    def deny(path: Any, *args: Any, **kwargs: Any) -> Any:
        if os.fspath(path).endswith("blob"):
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", deny)

    with pytest.raises(sd.CloneTreeUnreadableError):
        sd._refuse_oversized(tree, running=True)


def test_a_subtree_the_live_poll_cannot_read_stops_the_command(
    tmp_path: Path, monkeypatch
) -> None:
    """The refusal reaches the process-group kill path, not only the caller."""

    tree = tmp_path / "tree"
    (tree / "a").mkdir(parents=True)
    (tree / "a" / "inner").write_bytes(b"x" * 8)
    pidfile = tmp_path / "child.pid"
    real = os.scandir

    def deny(path: Any = ".") -> Any:
        # Refuse only once the stand-in command has written its pid, so the
        # order is fixed: the command runs, then a poll cannot read the
        # subtree, then the refusal stops the command.
        if (
            isinstance(path, (str, os.PathLike))
            and os.fspath(path) == os.fspath(tree / "a")
            and pidfile.exists()
        ):
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
        return real(path)

    monkeypatch.setattr(os, "scandir", deny)
    monkeypatch.setattr(sd, "GIT_POLL_SECONDS", 0.05)
    # A short time limit bounds the run if the refusal never fires; the test
    # then fails on the error type instead of waiting out the default.
    monkeypatch.setattr(sd, "GIT_TIMEOUT_SECONDS", 5)

    child = (
        "import os, pathlib, time; "
        f"p = pathlib.Path({str(pidfile)!r}); "
        "q = p.with_suffix('.tmp'); "
        "q.write_text(str(os.getpid())); "
        "os.replace(q, p); "
        "time.sleep(3600)"
    )
    with pytest.raises(sd.CloneTreeUnreadableError):
        sd._run_git([sys.executable, "-c", child], env=dict(os.environ), grows_in=tree)

    assert pidfile.exists() and pidfile.read_text(), (
        "the stand-in command never started"
    )
    pid = int(pidfile.read_text())
    for _ in range(200):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        if Path(f"/proc/{pid}/stat").exists():
            try:
                state = (
                    Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
                )
            except (OSError, IndexError):
                break
            if state == "Z":
                break
        time.sleep(0.05)
    else:
        pytest.fail("the command kept running after the poll's refusal")


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


def _chunk_through_the_tool(sequence: int = 0) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_set_source_zip_chunk

    return mcp_set_source_zip_chunk(
        upload_id="u1",
        sequence=sequence,
        data_b64=base64.b64encode(b"abc").decode(),
        last=False,
        session_id=SESSION,
    )


def test_try_begin_write_says_why_it_refused(workspace) -> None:
    session = sessions.get_default_registry().session_for(SESSION)

    assert session.try_begin_write() is None
    session.end_write()

    assert session.try_begin_change() is None
    try:
        assert session.try_begin_write() == sessions.WRITE_REFUSED_BY_CHANGE
    finally:
        session.end_change()

    assert session.try_begin_sweep()
    try:
        assert session.try_begin_write() == sessions.WRITE_REFUSED_BY_SWEEP
    finally:
        session.end_sweep()


def test_a_chunk_refused_by_a_change_gets_the_one_type_and_retry_rule(
    workspace,
) -> None:
    """One ``error_type`` and one retry rule, right whether or not the hold removed
    the upload: send the same chunk again, and start from the first chunk only on
    an out-of-order answer."""

    session = sessions.get_default_registry().session_for(SESSION)
    assert session.try_begin_change() is None
    try:
        with pytest.raises(sessions.SessionWorkspaceBusyError) as refused:
            _chunk("u1", 0, b"abc")
        result = _chunk_through_the_tool()
    finally:
        session.end_change()

    assert result["success"] is False, result
    assert sessions.SESSION_WORKSPACE_BUSY == "session_workspace_busy"
    assert result["error_type"] == "session_workspace_busy"
    assert "again as it is" in str(refused.value)
    assert "out-of-order" in str(refused.value)
    assert _chunk("u1", 0, b"abc")["next_sequence"] == 1


def test_a_chunk_refused_by_the_sweep_gets_the_same_type_and_retry_rule(
    workspace,
) -> None:
    """The sweep's hold can end without removing anything (the age re-check keeps
    a session used meanwhile), so its refusal never claims the upload is gone."""

    session = sessions.get_default_registry().session_for(SESSION)
    assert session.try_begin_sweep()
    try:
        with pytest.raises(sessions.SessionWorkspaceBusyError) as refused:
            _chunk("u1", 0, b"abc")
        result = _chunk_through_the_tool()
    finally:
        session.end_sweep()

    assert result["error_type"] == "session_workspace_busy"
    assert "again as it is" in str(refused.value)
    assert "out-of-order" in str(refused.value)
    assert "is gone" not in str(refused.value)
    assert _chunk("u1", 0, b"abc")["next_sequence"] == 1


def _zip_bytes() -> bytes:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app/main.py", "print('hello')\n")
    return buffer.getvalue()


def test_a_chunk_is_accepted_while_a_clone_runs_and_both_land(
    workspace, fake_git, monkeypatch
) -> None:
    fake_git(count=1)  # a git on PATH for the executable lookup; the clone is stubbed
    inside = threading.Event()
    release = threading.Event()

    def slow_clone(url: str, ref: Any, *, target: Path, **kwargs: Any) -> None:
        (target / "cloned.txt").write_text("from the clone")
        inside.set()
        assert release.wait(10), "the chunk never finished"

    monkeypatch.setattr(sd, "_clone", slow_clone)
    outcome: Dict[str, Any] = {}

    def clone() -> None:
        outcome["source"] = sd.set_source_git(URL, session_id=SESSION)

    thread = threading.Thread(target=clone)
    thread.start()
    try:
        assert inside.wait(10), "the clone never started"
        chunk = _chunk("u1", 0, b"abc")
    finally:
        release.set()
        thread.join(10)

    assert chunk["next_sequence"] == 1
    assert (outcome["source"] / "cloned.txt").read_text() == "from the clone"
    assert (workspace / SESSION / "incoming" / "u1.zip.part").read_bytes() == b"abc"


def test_a_chunk_of_another_upload_is_accepted_while_a_finalize_runs(
    workspace, monkeypatch
) -> None:
    import hashlib

    data = _zip_bytes()
    assert _chunk("done", 0, data, last=True)["last"] is True
    inside = threading.Event()
    release = threading.Event()
    real = sd._validate_zip_member

    def held(name: str) -> None:
        inside.set()
        assert release.wait(10), "the chunk never finished"
        real(name)

    monkeypatch.setattr(sd, "_validate_zip_member", held)
    outcome: Dict[str, Any] = {}

    def finalize() -> None:
        outcome["source"] = sd.set_source_zip_finalize(
            "done", hashlib.sha256(data).hexdigest(), session_id=SESSION
        )

    thread = threading.Thread(target=finalize)
    thread.start()
    try:
        assert inside.wait(10), "the finalize never started"
        chunk = _chunk("next", 0, b"xyz")
    finally:
        release.set()
        thread.join(10)

    assert chunk["next_sequence"] == 1
    assert (outcome["source"] / "app" / "main.py").is_file()
    assert (workspace / SESSION / "incoming" / "next.zip.part").read_bytes() == b"xyz"


def _zip_with(name: str) -> bytes:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(f"app/{name}.txt", name)
    return buffer.getvalue()


def test_a_finalize_extracts_the_bytes_it_hashed_when_the_path_is_renamed_over(
    workspace, tmp_path: Path, monkeypatch
) -> None:
    """The checksum and the extraction read one open handle.

    The injected rename below is the move a retry chunk's ``last=True``
    promotion performs on ``incoming/<id>.zip``. Whatever lands at the path
    between the hash and the extract, the tree that is extracted is the one
    whose sha256 was checked.
    """
    import hashlib

    hashed = _zip_with("hashed")
    other = tmp_path / "other.zip"
    other.write_bytes(_zip_with("swapped"))
    assert _chunk("race", 0, hashed, last=True)["last"] is True

    state: Dict[str, Any] = {}
    real_open = Path.open

    def swap_after_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        fh = real_open(self, *args, **kwargs)
        if self.name == "race.zip" and args[:1] == ("rb",) and "swapped" not in state:
            state["swapped"] = True
            os.replace(other, self)
        return fh

    monkeypatch.setattr(Path, "open", swap_after_open)

    source = sd.set_source_zip_finalize(
        "race", hashlib.sha256(hashed).hexdigest(), session_id=SESSION
    )

    assert state.get("swapped") is True, "the injected rename never ran"
    assert (source / "app" / "hashed.txt").is_file(), (
        "the extracted tree is not the one whose sha256 was checked"
    )
    assert not (source / "app" / "swapped.txt").exists(), (
        "bytes whose sha256 was never checked were extracted"
    )


def test_a_finalize_holds_its_uploads_lock_while_it_works(
    workspace, monkeypatch
) -> None:
    """A chunk of the same upload takes the same lock, so it waits, never races."""
    import hashlib

    data = _zip_with("locked")
    assert _chunk("u-lock", 0, data, last=True)["last"] is True
    seen: Dict[str, Any] = {}
    real = sd._validate_zip_member

    def observe(name: str) -> None:
        seen["held"] = sd._upload_lock(SESSION, "u-lock").locked()
        real(name)

    monkeypatch.setattr(sd, "_validate_zip_member", observe)

    sd.set_source_zip_finalize(
        "u-lock", hashlib.sha256(data).hexdigest(), session_id=SESSION
    )

    assert seen.get("held") is True, "finalize ran without the upload's lock"


def test_a_profile_selection_and_a_clone_do_not_refuse_each_other(workspace) -> None:
    """``select_profile`` writes through ``writing_session_state``, as a chunk does."""

    with sd._no_scan_running(SESSION, removes_workspace=False):
        with sessions.writing_session_state(SESSION):
            pass

    with sessions.writing_session_state(SESSION):
        with sd._no_scan_running(SESSION, removes_workspace=False):
            pass


def test_a_clear_and_a_write_still_refuse_each_other(workspace) -> None:
    with sd._no_scan_running(SESSION):
        with pytest.raises(sessions.SessionWorkspaceBusyError):
            with sessions.writing_session_state(SESSION):
                pass

    with sessions.writing_session_state(SESSION):
        with pytest.raises(sd.SourceDeliveryBusyError):
            with sd._no_scan_running(SESSION):
                pass


def test_a_write_that_ends_between_the_refused_change_and_the_pending_mark(
    workspace, monkeypatch
) -> None:
    """The three steps in the order that used to leave the session behind.

    The end of the session is refused its change because a write is in progress,
    the write then ends and looks for a pending removal, and only after that does
    the end of the session mark the removal pending. The end comes from an anyio
    worker thread (``http_sessions``) and the write from a delivery thread, so the
    steps can interleave this way; here they are driven in that order.
    """

    from automated_security_helper.cli.mcp.session_paths import mark_session_workspace

    sandbox = mark_session_workspace(workspace / SESSION)
    write = sessions.writing_session_state(SESSION)
    write.__enter__()
    real = sessions.MCPSession.try_begin_change
    write_ended: List[str] = []

    def interleaved(self: Any, *args: Any, **kwargs: Any) -> Any:
        refused = real(self, *args, **kwargs)
        if refused is not None and not write_ended:
            write_ended.append("ended")
            write.__exit__(None, None, None)
        return refused

    monkeypatch.setattr(sessions.MCPSession, "try_begin_change", interleaved)

    sessions.end_session(SESSION)

    assert write_ended == ["ended"], "the end of the session was never refused"
    assert not sandbox.exists(), (
        "the session was left on disk with nothing to remove it"
    )
    assert SESSION not in sessions._ended_while_scanning


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
    # The bound is the explicit constant, never the executor's host-dependent
    # default (5-6 workers on a small container; 32 on a big host, since
    # os.cpu_count ignores cgroup quotas before Python 3.13).
    assert mcp_server._DELIVERY_EXECUTOR._max_workers == sd.DELIVERY_MAX_WORKERS
    assert sd.DELIVERY_MAX_WORKERS == 8


def test_a_chunk_append_completes_while_the_clone_pool_is_saturated(
    workspace,
) -> None:
    from automated_security_helper.cli import mcp_server
    from automated_security_helper.cli.mcp_tools import mcp_set_source_zip_chunk

    gate = threading.Event()
    started = threading.Semaphore(0)
    threads: List[str] = []

    def blocked_clone() -> None:
        threads.append(threading.current_thread().name)
        started.release()
        assert gate.wait(20), "the chunk never finished"

    async def scenario() -> Dict[str, Any]:
        clones = [
            asyncio.ensure_future(mcp_server._run_clone(blocked_clone))
            for _ in range(sd.CLONE_MAX_WORKERS)
        ]
        loop = asyncio.get_running_loop()
        for _ in range(sd.CLONE_MAX_WORKERS):
            took = await loop.run_in_executor(None, started.acquire, True, 10)
            assert took, "a blocked clone never started"
        try:
            return await asyncio.wait_for(
                mcp_server._run_delivery(
                    mcp_set_source_zip_chunk,
                    upload_id="u1",
                    sequence=0,
                    data_b64=base64.b64encode(b"abc").decode(),
                    last=False,
                    session_id=SESSION,
                ),
                timeout=10,
            )
        finally:
            gate.set()
            await asyncio.gather(*clones)

    chunk = asyncio.run(scenario())

    assert chunk["success"] is True, chunk
    assert len(threads) == sd.CLONE_MAX_WORKERS
    assert all(name.startswith("ash-mcp-clone") for name in threads), threads
    assert (workspace / SESSION / "incoming" / "u1.zip.part").read_bytes() == b"abc"


def test_the_clone_tool_runs_on_the_clone_pool(workspace, monkeypatch) -> None:
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
    monkeypatch.setattr(mcp_server, "mcp_set_source_git", record)

    asyncio.run(mcp_server.set_source_git(ctx, url=URL))

    assert seen["thread"].startswith("ash-mcp-clone"), seen
