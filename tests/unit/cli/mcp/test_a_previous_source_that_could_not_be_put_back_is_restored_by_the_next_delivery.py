# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A previous source left under a hidden name is put back by the next delivery.

Why this file exists
--------------------
A delivery sets the previously delivered tree aside (``.source.replaced-<hex>``),
renames its staging directory onto ``source/``, and when that is refused puts the
previous tree back. When the put-back is refused too, nothing is at ``source/``,
the session's record still names it, and the previous source sits under its hidden
name. The next delivery to the session swept every ``.source.replaced-*`` tree as
scratch, so a delivery that then failed left the session with no source at all and
the only copy of the previous one deleted, although the tool text says a failed
delivery leaves the source delivered before it.

What the code does now
----------------------
At the start of a delivery, before the sweep, a missing ``source/`` with exactly one
hidden previous tree and a record that names ``source/`` gets that tree renamed back
(``_put_a_lost_source_back``). The record is what separates the lost previous source
from scratch: ``clear_source`` and ``end_session`` drop it, and a server that
restarted has none, so a tree they left behind is swept as before. More than one
hidden tree is not guessed between and none of them is deleted: while ``source/`` is
missing and the record names it, every ``.source.replaced-*`` tree is kept and one
warning says so. A rename that is refused again is logged, the tree is kept out of
the sweep, and the delivery goes on.

Only whole trees carry the hidden name. A tree that is being deleted is first
renamed to ``.source.trash-<hex>``, so a delete that stops partway leaves a
half-deleted tree under the trash name, which is swept and never put back. Without
that, the half-deleted tree of one delivery and the whole previous tree of a later
one are two hidden trees, the sweep deletes the whole one, and the half-deleted one
is the only tree left to put back.

How the tests work
------------------
The state a double put-back failure leaves is built by hand: no ``source/``, one
hidden tree holding ``old.txt``, the record naming ``source/``. ``_run_git`` is a
double (an exit 128 for the failing delivery, a working clone for the other); no
process starts. ``Path.rename`` is replaced where a test needs the put-back to be
refused, and the module's logger where a test reads what was logged. The sequence
with a half-deleted tree is driven through the deliveries themselves, with
``_remove_tree`` replaced by a double that deletes ``a.txt`` of a hidden tree and
then stops.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import io
import subprocess
import zipfile
from pathlib import Path
from typing import List
from unittest.mock import MagicMock

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd

pytestmark = pytest.mark.unit

SESSION = "put-back"
URL = "https://example.com/foo.git"
GIT = "/opt/git/bin/git"
HIDDEN = f"{sd._REPLACED_DIR_PREFIX}{'ab' * 16}"


@pytest.fixture(autouse=True)
def delivery_state(monkeypatch) -> None:
    monkeypatch.setattr(sd, "_git_executable", lambda: GIT)
    monkeypatch.setattr(sd, "_SESSION_SOURCE_DIRS", {})
    monkeypatch.setattr(sd, "_RENAME_WAIT_SECONDS", 0)


@pytest.fixture
def logged(monkeypatch) -> MagicMock:
    logger = MagicMock()
    monkeypatch.setattr(sd, "_logger", logger)
    return logger


def _hidden_previous_source(tmp_path: Path, name: str = HIDDEN) -> Path:
    """Add a hidden tree holding ``old.txt`` to the session's workspace."""
    hidden = tmp_path / SESSION / name
    hidden.mkdir(parents=True)
    (hidden / "old.txt").write_text("old\n")
    return hidden


def _a_lost_source(tmp_path: Path) -> Path:
    """What a refused put-back leaves: no ``source/``, one hidden tree, the record
    naming ``source/``. Returns the path of ``source/``."""
    _hidden_previous_source(tmp_path)
    source = tmp_path / SESSION / "source"
    sd._set_session_source_dir(SESSION, source)
    return source


def _scratch(tmp_path: Path) -> List[str]:
    return sorted(
        p.name for p in (tmp_path / SESSION).iterdir() if p.name.startswith(".source.")
    )


def _a_clone_that_fails(cmd, *, env):
    return subprocess.CompletedProcess(cmd, 128, "", "fatal: unable to access")


def _a_clone_that_works(cmd, *, env):
    if "clone" in cmd:
        target = Path(cmd[-1])
        target.mkdir(parents=True, exist_ok=True)
        (target / "cloned.txt").write_text("new delivery\n")
    return subprocess.CompletedProcess(cmd, 0, "", "")


def _deliver_from_git(tmp_path: Path) -> Path:
    return sd.set_source_git(url=URL, workspace_root=tmp_path, session_id=SESSION)


def test_a_delivery_that_fails_leaves_the_restored_previous_source(
    tmp_path, monkeypatch
) -> None:
    """Fails on a sweep that deletes the hidden tree: the failed delivery would leave
    no source and the only copy of the previous one deleted."""
    source = _a_lost_source(tmp_path)
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_fails)

    with pytest.raises(sd.GitCommandError, match="git clone failed"):
        _deliver_from_git(tmp_path)

    assert (source / "old.txt").read_text() == "old\n"
    assert sd.get_session_source_dir(SESSION) == source
    assert _scratch(tmp_path) == []


def test_a_delivery_that_works_replaces_the_restored_previous_source(
    tmp_path, monkeypatch
) -> None:
    source = _a_lost_source(tmp_path)
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_works)

    delivered = _deliver_from_git(tmp_path)

    assert delivered == source
    assert (delivered / "cloned.txt").read_text() == "new delivery\n"
    assert not (delivered / "old.txt").exists()
    assert sd.get_session_source_dir(SESSION) == source
    assert _scratch(tmp_path) == []


def test_a_zip_delivery_replaces_the_restored_previous_source(tmp_path) -> None:
    source = _a_lost_source(tmp_path)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("new.txt", "new\n")
    payload = buffer.getvalue()
    sd.set_source_zip_chunk(
        upload_id="u1",
        sequence=0,
        data_b64=base64.b64encode(payload).decode("ascii"),
        last=True,
        workspace_root=tmp_path,
        session_id=SESSION,
    )

    delivered = sd.set_source_zip_finalize(
        upload_id="u1",
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        workspace_root=tmp_path,
        session_id=SESSION,
    )

    assert delivered == source
    assert (delivered / "new.txt").read_text() == "new\n"
    assert not (delivered / "old.txt").exists()
    assert _scratch(tmp_path) == []


def test_a_hidden_tree_with_no_record_is_scratch_and_is_not_brought_back(
    tmp_path, monkeypatch
) -> None:
    """The record is what makes the hidden tree the previous source. After
    ``clear_source`` or a restart there is none, and the tree is swept as before."""
    _hidden_previous_source(tmp_path)
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_fails)

    with pytest.raises(sd.GitCommandError):
        _deliver_from_git(tmp_path)

    assert not (tmp_path / SESSION / "source").exists()
    assert _scratch(tmp_path) == []
    assert sd.get_session_source_dir(SESSION) is None


OTHER_HIDDEN = f"{sd._REPLACED_DIR_PREFIX}{'cd' * 16}"


def test_two_hidden_trees_are_kept_and_not_guessed_between(
    tmp_path, monkeypatch, logged
) -> None:
    """Fails on a sweep that deletes every hidden tree when there are two: one of
    them is the previous source the record names, and a delivery that then fails
    leaves the session with none. Neither is put back, because nothing says which is
    the source; both are kept, and one warning says so without naming a path."""
    source = _a_lost_source(tmp_path)
    _hidden_previous_source(tmp_path, OTHER_HIDDEN)
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_fails)

    with pytest.raises(sd.GitCommandError):
        _deliver_from_git(tmp_path)

    assert not source.exists()
    assert _scratch(tmp_path) == sorted([HIDDEN, OTHER_HIDDEN])
    for name in (HIDDEN, OTHER_HIDDEN):
        assert (tmp_path / SESSION / name / "old.txt").read_text() == "old\n"
    assert sd.get_session_source_dir(SESSION) == source
    assert logged.warning.call_count == 1, logged.warning.call_args_list
    said = str(logged.warning.call_args)
    for text in (HIDDEN, OTHER_HIDDEN, SESSION, str(tmp_path)):
        assert text not in said, said


def test_trees_kept_for_want_of_a_guess_go_once_a_delivery_has_worked(
    tmp_path, monkeypatch
) -> None:
    """The kept trees are not a leak: the delivery that works puts a source at
    ``source/``, and the next delivery sweeps them as it sweeps any scratch."""
    _a_lost_source(tmp_path)
    _hidden_previous_source(tmp_path, OTHER_HIDDEN)
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_works)

    first = _deliver_from_git(tmp_path)
    assert (first / "cloned.txt").exists()
    assert _scratch(tmp_path) == sorted([HIDDEN, OTHER_HIDDEN])

    _deliver_from_git(tmp_path)

    assert _scratch(tmp_path) == []


def _a_clone_that_runs_out_of_disk(cmd, *, env):
    return subprocess.CompletedProcess(
        cmd, 128, "", "fatal: write error: No space left on device"
    )


def test_a_full_disk_with_kept_previous_trees_is_told_to_clear_them(
    tmp_path, monkeypatch
) -> None:
    """Fails on advice that looks at ``source/`` alone. The session has no
    ``source/`` but keeps two whole previous trees, each a source's worth of space,
    and ``clear_source`` frees them. The client was told only that the disk is full."""
    _a_lost_source(tmp_path)
    _hidden_previous_source(tmp_path, OTHER_HIDDEN)
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_runs_out_of_disk)

    with pytest.raises(sd.GitCommandError) as caught:
        _deliver_from_git(tmp_path)

    message = str(caught.value)
    assert "No space left on device" in message, message
    assert "clear_source" in message, message
    assert "previous source" in message, message
    assert "room for both" not in message, message


def test_a_full_disk_with_nothing_kept_is_told_only_that_it_is_full(
    tmp_path, monkeypatch
) -> None:
    """Control: no ``source/`` and no kept tree, so ``clear_source`` frees nothing
    and is not offered."""
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_runs_out_of_disk)

    with pytest.raises(sd.GitCommandError) as caught:
        _deliver_from_git(tmp_path)

    message = str(caught.value)
    assert message.rstrip().endswith("The disk is full."), message
    assert "clear_source" not in message, message


@pytest.mark.parametrize(
    "a_source_is_delivered", [True, False], ids=["with-a-source", "without-one"]
)
def test_the_error_of_a_full_disk_still_says_the_disk_is_full(
    tmp_path, monkeypatch, a_source_is_delivered
) -> None:
    """Fails on a re-raise that builds the error anew: the advice is added to the
    message, and the flag that says the disk is full is lost with the original."""
    if a_source_is_delivered:
        (tmp_path / SESSION / "source").mkdir(parents=True)
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_runs_out_of_disk)

    with pytest.raises(sd.GitCommandError) as caught:
        _deliver_from_git(tmp_path)

    assert caught.value.disk_full is True


def test_control_the_error_of_another_failure_does_not_say_the_disk_is_full(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_fails)

    with pytest.raises(sd.GitCommandError) as caught:
        _deliver_from_git(tmp_path)

    assert caught.value.disk_full is False


def _a_clone_that_writes(files):
    """A ``_run_git`` double whose clone writes ``files`` (name -> text)."""

    def run_git(cmd, *, env):
        if "clone" in cmd:
            target = Path(cmd[-1])
            target.mkdir(parents=True, exist_ok=True)
            for name, text in files.items():
                (target / name).write_text(text)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    return run_git


def _a_delete_that_stops_after_a_txt(monkeypatch) -> None:
    """``_remove_tree`` double: a tree that sits beside ``source/`` under a ``.source.``
    name and holds ``b.txt`` loses ``a.txt`` and is reported as not gone, each time it
    is asked, as a delete that something resists after the first file. Every other
    tree is deleted for real."""
    real = sd._remove_tree

    def remove_tree(path) -> bool:
        path = Path(path)
        if path.name.startswith(".source.") and (path / "b.txt").exists():
            (path / "a.txt").unlink(missing_ok=True)
            return False
        return real(path)

    monkeypatch.setattr(sd, "_remove_tree", remove_tree)


def test_a_tree_whose_delete_stopped_partway_is_not_left_under_the_hidden_name(
    tmp_path, monkeypatch
) -> None:
    """Fails on a delete in place: the half-deleted previous tree is then left under
    ``.source.replaced-<hex>``, the name a lost previous source is put back from. It
    is renamed to a trash name first, so only whole trees carry the hidden name."""
    session_dir = tmp_path / SESSION
    monkeypatch.setattr(
        sd, "_run_git", _a_clone_that_writes({"a.txt": "one\n", "b.txt": "one\n"})
    )
    _deliver_from_git(tmp_path)
    _a_delete_that_stops_after_a_txt(monkeypatch)
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_writes({"c.txt": "two\n"}))

    delivered = _deliver_from_git(tmp_path)

    assert (delivered / "c.txt").read_text() == "two\n"
    hidden = [
        p for p in session_dir.iterdir() if p.name.startswith(sd._REPLACED_DIR_PREFIX)
    ]
    assert hidden == [], hidden
    (half,) = [p for p in session_dir.iterdir() if p.name.startswith(".source.")]
    assert [p.name for p in half.iterdir()] == ["b.txt"]


def test_a_half_deleted_tree_never_becomes_the_source_over_a_whole_one(
    tmp_path, monkeypatch
) -> None:
    """The sequence of the review, driven through the deliveries. Delivery 2 replaces
    the first tree and cannot finish deleting it (it keeps ``b.txt``). Delivery 3 sets
    the second tree aside and can neither move its own clone into place nor put the
    second tree back, so ``source/`` is missing and the record names it. Delivery 4
    fails at its clone. The second tree is the previous source and must be back at
    ``source/`` whole; the half-deleted first tree must not be what is there, and
    the whole one must not have been deleted for the half-deleted one's sake."""
    session_dir = tmp_path / SESSION
    source = session_dir / "source"
    monkeypatch.setattr(
        sd, "_run_git", _a_clone_that_writes({"a.txt": "one\n", "b.txt": "one\n"})
    )
    _deliver_from_git(tmp_path)
    _a_delete_that_stops_after_a_txt(monkeypatch)
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_writes({"c.txt": "two\n"}))
    _deliver_from_git(tmp_path)

    monkeypatch.setattr(sd, "_run_git", _a_clone_that_writes({"d.txt": "three\n"}))
    real_rename = Path.rename

    def rename(path, target):
        if Path(target).name == "source":
            raise PermissionError(errno.EACCES, "Access is denied")
        return real_rename(path, target)

    with monkeypatch.context() as refused:
        refused.setattr(Path, "rename", rename)
        with pytest.raises(sd.SessionWorkspaceError):
            _deliver_from_git(tmp_path)
    assert not source.exists()
    assert sd.get_session_source_dir(SESSION) == source

    monkeypatch.setattr(sd, "_run_git", _a_clone_that_fails)
    with pytest.raises(sd.GitCommandError):
        _deliver_from_git(tmp_path)

    assert (source / "c.txt").read_text() == "two\n"
    assert not (source / "b.txt").exists()
    assert sd.get_session_source_dir(SESSION) == source


def test_a_hidden_tree_the_sweep_cannot_delete_is_left_under_the_trash_name(
    tmp_path, monkeypatch
) -> None:
    """The sweep deletes a hidden tree beside a delivered ``source/`` the same way a
    swap does, so a delete that stops partway leaves the remnant under the trash
    name, not under the hidden name."""
    source = tmp_path / SESSION / "source"
    source.mkdir(parents=True)
    sd._set_session_source_dir(SESSION, source)
    stale = _hidden_previous_source(tmp_path)
    (stale / "a.txt").write_text("a\n")
    (stale / "b.txt").write_text("b\n")
    _a_delete_that_stops_after_a_txt(monkeypatch)
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_fails)

    with pytest.raises(sd.GitCommandError):
        _deliver_from_git(tmp_path)

    assert not stale.exists()
    (half,) = [
        p for p in (tmp_path / SESSION).iterdir() if p.name.startswith(".source.")
    ]
    assert not half.name.startswith(sd._REPLACED_DIR_PREFIX), half.name
    assert (half / "b.txt").exists()


def test_a_replaced_tree_that_cannot_be_renamed_for_deletion_stays_whole(
    tmp_path, monkeypatch, logged
) -> None:
    """The rename to the trash name is refused: the tree is not deleted in place. It
    stays whole under its hidden name, which is where a put-back would look for it,
    and the delivery that replaced it is not ended by that."""
    first_source = tmp_path / SESSION / "source"
    first_source.mkdir(parents=True)
    (first_source / "old.txt").write_text("old\n")
    sd._set_session_source_dir(SESSION, first_source)
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_works)
    real_rename = Path.rename

    def rename(path, target):
        if Path(target).name.startswith(".source.trash-"):
            raise PermissionError(errno.EACCES, "Access is denied")
        return real_rename(path, target)

    monkeypatch.setattr(Path, "rename", rename)

    delivered = _deliver_from_git(tmp_path)

    assert (delivered / "cloned.txt").exists()
    (kept,) = [
        p for p in (tmp_path / SESSION).iterdir() if p.name.startswith(".source.")
    ]
    assert kept.name.startswith(sd._REPLACED_DIR_PREFIX), kept.name
    assert (kept / "old.txt").read_text() == "old\n"
    assert logged.warning.call_count == 1, logged.warning.call_args_list


def test_control_a_hidden_tree_beside_a_delivered_source_is_scratch(
    tmp_path, monkeypatch
) -> None:
    """Control: ``source/`` exists, so nothing is put back and the hidden tree is
    deleted as before."""
    source = tmp_path / SESSION / "source"
    source.mkdir(parents=True)
    (source / "kept.txt").write_text("kept\n")
    sd._set_session_source_dir(SESSION, source)
    _hidden_previous_source(tmp_path)
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_fails)

    with pytest.raises(sd.GitCommandError):
        _deliver_from_git(tmp_path)

    assert (source / "kept.txt").read_text() == "kept\n"
    assert not (source / "old.txt").exists()
    assert _scratch(tmp_path) == []


def test_a_put_back_that_is_refused_again_keeps_the_hidden_tree_and_says_so(
    tmp_path, monkeypatch, logged
) -> None:
    """The only copy of the previous source is not deleted because it could not be
    renamed back this time: it stays for the next delivery, and a warning names it."""
    source = _a_lost_source(tmp_path)
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_fails)
    real_rename = Path.rename

    def rename(path, target):
        if path.name.startswith(sd._REPLACED_DIR_PREFIX):
            raise PermissionError(errno.EACCES, "Access is denied")
        return real_rename(path, target)

    monkeypatch.setattr(Path, "rename", rename)

    with pytest.raises(sd.GitCommandError):
        _deliver_from_git(tmp_path)

    assert not source.exists()
    assert (tmp_path / SESSION / HIDDEN / "old.txt").read_text() == "old\n"
    assert logged.warning.call_count == 1, logged.warning.call_args_list
    assert HIDDEN in str(logged.warning.call_args), logged.warning.call_args
