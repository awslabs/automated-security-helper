# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two publishes of one tool's license directory into one ASH_THIRD_PARTY_DIR.

The Dockerfile sets ASH_THIRD_PARTY_DIR for every pinned install, so two
installs of one tool can publish into the same directory at once. The one that
loses the race used to fail twice over: its rename of the old directory aside hit
FileNotFoundError when the other publish had already moved it, and its rename of
the new directory into place hit "Directory not empty" when the other publish had
already put the same files there.

A publish whose forward rename fails puts the old entry back. When that restore
fails as well and nothing is at the name, the old entry is whole only in the
publish's work directory, which used to be deleted with it. It is kept now, and its
path is printed.

That rule is fail-safe: the work directory is kept from the moment the old entry may
be the only complete copy, and deleted only once the new entry is in place, the old
one is restored, an identical entry from a concurrent publish stands, or an entry is
confirmed at the name. Two cases the first version missed: the aside step itself
failing twice (the EXDEV copy succeeded, the removal stopped part way and the copy
back failed), and the check for an entry at the name raising.

Nothing here reaches the network or starts a process. The failures are fakes at
os.replace, shutil and pathlib; no real filesystem fault is produced.
"""

from __future__ import annotations

import errno
import importlib.util
import os
import shutil
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "automated_security_helper" / "assets" / "install-pinned-tool.py"


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "_install_pinned_tool_pubrace", SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = _load_script()


def _staged(tmp_path: Path, text: bytes) -> Path:
    staged = tmp_path / "staging" / "demo"
    staged.mkdir(parents=True)
    (staged / "LICENSE").write_bytes(text)
    return staged


def _other_publish_wins(monkeypatch, final: Path, text: bytes) -> None:
    """Just before this call's rename into place, another publish gets there."""
    real = os.replace

    def replace(src, dst, *args, **kwargs):
        if Path(dst) == final and Path(src).name == "incoming":
            final.mkdir()
            (final / "LICENSE").write_bytes(text)
        return real(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", replace)


class TestTheLoserOfAConcurrentPublish:
    def test_it_finds_the_same_files_in_place_and_succeeds(self, tmp_path, monkeypatch):
        third_party = tmp_path / "third-party"
        third_party.mkdir()
        final = third_party / "demo"
        _other_publish_wins(monkeypatch, final, b"new\n")

        published = installer.publish_third_party(
            _staged(tmp_path, b"new\n"), third_party
        )

        assert published == final
        assert (final / "LICENSE").read_bytes() == b"new\n"
        assert sorted(p.name for p in third_party.iterdir()) == ["demo"]

    def test_other_files_in_place_are_still_an_error(self, tmp_path, monkeypatch):
        """Control: only the same files count as someone else's finished publish."""
        third_party = tmp_path / "third-party"
        third_party.mkdir()
        final = third_party / "demo"
        _other_publish_wins(monkeypatch, final, b"something else\n")

        with pytest.raises(OSError) as raised:
            installer.publish_third_party(_staged(tmp_path, b"new\n"), third_party)

        assert raised.value.errno in (errno.ENOTEMPTY, errno.EEXIST, errno.EACCES)
        assert sorted(p.name for p in third_party.iterdir()) == ["demo"]

    def test_an_old_directory_the_other_publish_moved_aside_is_not_an_error(
        self, tmp_path, monkeypatch
    ):
        third_party = tmp_path / "third-party"
        final = third_party / "demo"
        final.mkdir(parents=True)
        (final / "LICENSE").write_bytes(b"old\n")
        real = os.replace

        def replace(src, dst, *args, **kwargs):
            if Path(src) == final:
                (final / "LICENSE").unlink()
                final.rmdir()
                raise FileNotFoundError(errno.ENOENT, "No such file or directory")
            return real(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "replace", replace)

        published = installer.publish_third_party(
            _staged(tmp_path, b"new\n"), third_party
        )

        assert (published / "LICENSE").read_bytes() == b"new\n"
        assert sorted(p.name for p in third_party.iterdir()) == ["demo"]


class TestAFailedRestoreDoesNotLoseTheOldEntry:
    @staticmethod
    def _old_entry(tmp_path: Path) -> "tuple[Path, Path]":
        third_party = tmp_path / "third-party"
        final = third_party / "demo"
        final.mkdir(parents=True)
        (final / "LICENSE").write_bytes(b"old\n")
        return third_party, final

    def test_the_old_entry_is_kept_in_the_work_directory(
        self, tmp_path, monkeypatch, capsys
    ):
        third_party, final = self._old_entry(tmp_path)
        real = os.replace

        def replace(src, dst, *args, **kwargs):
            if Path(dst) == final and Path(src).name == "incoming":
                raise OSError(errno.ENOSPC, "No space left on device")
            if Path(dst) == final and Path(src).name == "old":
                raise OSError(errno.EACCES, "Permission denied")
            return real(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "replace", replace)

        with pytest.raises(PermissionError):
            installer.publish_third_party(_staged(tmp_path, b"new\n"), third_party)

        assert not final.exists()
        kept = [
            p
            for p in third_party.iterdir()
            if p.name.startswith(installer._PUBLISH_WORK_PREFIX)
        ]
        assert len(kept) == 1, "the work directory holding the old entry was deleted"
        assert (kept[0] / "old" / "LICENSE").read_bytes() == b"old\n"
        assert str(kept[0] / "old") in capsys.readouterr().err

    @staticmethod
    def _keep_the_old_entry(monkeypatch, final: Path) -> None:
        """Make a publish end with the old entry only in its work directory."""
        real = os.replace

        def replace(src, dst, *args, **kwargs):
            if Path(dst) == final and Path(src).name == "incoming":
                raise OSError(errno.ENOSPC, "No space left on device")
            if Path(dst) == final and Path(src).name == "old":
                raise OSError(errno.EACCES, "Permission denied")
            return real(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "replace", replace)

    def _fail_one_publish(self, tmp_path: Path) -> "tuple[Path, Path]":
        third_party, final = self._old_entry(tmp_path)
        with pytest.MonkeyPatch.context() as patch:
            self._keep_the_old_entry(patch, final)
            with pytest.raises(PermissionError):
                installer.publish_third_party(_staged(tmp_path, b"new\n"), third_party)
        kept = [
            p
            for p in third_party.iterdir()
            if p.name.startswith(installer._PUBLISH_WORK_PREFIX)
        ]
        assert len(kept) == 1, "the work directory holding the old entry was deleted"
        return third_party, kept[0]

    def test_the_kept_directory_is_marked_with_the_tools_name(self, tmp_path):
        _, kept = self._fail_one_publish(tmp_path)

        marker = kept / installer._PUBLISH_KEPT_MARKER
        assert marker.read_text(encoding="utf-8").strip() == "demo"

    def test_a_later_publish_of_the_same_tool_removes_the_kept_directory(
        self, tmp_path
    ):
        """with-retry runs the install again; the old copy is superseded by then."""
        # Red before: nothing removed the kept directory, so a retried install that
        # succeeded shipped the previous license files in a hidden directory.
        third_party, _ = self._fail_one_publish(tmp_path)

        published = installer.publish_third_party(
            _staged(tmp_path / "again", b"newer\n"), third_party
        )

        assert (published / "LICENSE").read_bytes() == b"newer\n"
        assert sorted(p.name for p in third_party.iterdir()) == ["demo"]

    def test_a_later_publish_of_another_tool_leaves_the_kept_directory(self, tmp_path):
        """Control: only the tool the old copy belongs to supersedes it."""
        third_party, kept = self._fail_one_publish(tmp_path)
        other = tmp_path / "again" / "other"
        other.mkdir(parents=True)
        (other / "LICENSE").write_bytes(b"other\n")

        installer.publish_third_party(other, third_party)

        assert (kept / "old" / "LICENSE").read_bytes() == b"old\n"
        assert sorted(p.name for p in third_party.iterdir()) == sorted(
            [kept.name, "other"]
        )

    def test_a_second_failing_publish_keeps_the_first_kept_directory(self, tmp_path):
        """A publish removes kept directories only when it finishes, not when it starts."""
        # Nothing showed this: a publish that cleared the tool's kept directories at its
        # start would lose the only complete old entry when the retry fails as well.
        third_party, first = self._fail_one_publish(tmp_path)

        with pytest.MonkeyPatch.context() as patch:
            self._keep_the_old_entry(patch, third_party / "demo")
            with pytest.raises(OSError) as raised:
                installer.publish_third_party(
                    _staged(tmp_path / "second", b"newer\n"), third_party
                )

        assert raised.value.errno == errno.ENOSPC
        assert (first / "old" / "LICENSE").read_bytes() == b"old\n"
        marker = first / installer._PUBLISH_KEPT_MARKER
        assert marker.read_text(encoding="utf-8").strip() == "demo"
        assert [
            p
            for p in third_party.iterdir()
            if p.name.startswith(installer._PUBLISH_WORK_PREFIX)
        ] == [first]

    def test_a_work_directory_without_the_marker_is_left_alone(self, tmp_path):
        """Control: another publish's work directory that is still in use."""
        third_party = tmp_path / "third-party"
        live = third_party / f"{installer._PUBLISH_WORK_PREFIX}live"
        (live / "incoming").mkdir(parents=True)
        (live / "incoming" / "LICENSE").write_bytes(b"in flight\n")

        installer.publish_third_party(_staged(tmp_path, b"new\n"), third_party)

        assert (live / "incoming" / "LICENSE").read_bytes() == b"in flight\n"

    def test_an_entry_a_concurrent_publish_put_there_makes_the_old_one_surplus(
        self, tmp_path, monkeypatch
    ):
        """Control: with something at the name, nothing is kept and nothing leaks."""
        third_party, final = self._old_entry(tmp_path)
        _other_publish_wins(monkeypatch, final, b"something else\n")

        with pytest.raises(OSError):
            installer.publish_third_party(_staged(tmp_path, b"new\n"), third_party)

        assert (final / "LICENSE").read_bytes() == b"something else\n"
        assert sorted(p.name for p in third_party.iterdir()) == ["demo"]

    def test_a_restore_that_works_leaves_no_work_directory(self, tmp_path, monkeypatch):
        """Control: the old entry goes back and the work directory is removed."""
        third_party, final = self._old_entry(tmp_path)
        real = os.replace

        def replace(src, dst, *args, **kwargs):
            if Path(dst) == final and Path(src).name == "incoming":
                raise OSError(errno.ENOSPC, "No space left on device")
            return real(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "replace", replace)

        with pytest.raises(OSError) as raised:
            installer.publish_third_party(_staged(tmp_path, b"new\n"), third_party)

        assert raised.value.errno == errno.ENOSPC
        assert (final / "LICENSE").read_bytes() == b"old\n"
        assert sorted(p.name for p in third_party.iterdir()) == ["demo"]

    def test_an_aside_step_that_fails_twice_keeps_the_complete_old_entry(
        self, tmp_path, monkeypatch, capsys
    ):
        """EXDEV copy ok, removal part way, copy back fails: ``old`` is the only whole copy."""
        # Red before: the decision to keep the work directory was made only in the
        # restore's except clause, so an exception out of the aside step reached the
        # finally clause with nothing marked and it deleted the work directory,
        # ``old`` with it.
        third_party, final = self._old_entry(tmp_path)
        (final / "SOURCE").write_bytes(b"old source\n")
        real_replace, real_rmtree, real_copytree = (
            os.replace,
            shutil.rmtree,
            shutil.copytree,
        )

        def replace(src, dst, *args, **kwargs):
            if Path(src) == final:
                raise OSError(errno.EXDEV, "Invalid cross-device link")
            return real_replace(src, dst, *args, **kwargs)

        def rmtree(path, *args, **kwargs):
            if Path(path) == final:
                (final / "LICENSE").unlink()
                raise PermissionError(errno.EACCES, "Permission denied")
            return real_rmtree(path, *args, **kwargs)

        def copytree(src, dst, *args, **kwargs):
            if Path(dst) == final:
                raise OSError(errno.ENOSPC, "No space left on device")
            return real_copytree(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "replace", replace)
        monkeypatch.setattr(shutil, "rmtree", rmtree)
        monkeypatch.setattr(shutil, "copytree", copytree)

        with pytest.raises(OSError) as raised:
            installer.publish_third_party(_staged(tmp_path, b"new\n"), third_party)

        assert raised.value.errno == errno.ENOSPC
        kept = [
            p
            for p in third_party.iterdir()
            if p.name.startswith(installer._PUBLISH_WORK_PREFIX)
        ]
        assert len(kept) == 1, "the work directory holding the old entry was deleted"
        assert {p.name: p.read_bytes() for p in (kept[0] / "old").iterdir()} == {
            "LICENSE": b"old\n",
            "SOURCE": b"old source\n",
        }
        assert str(kept[0] / "old") in capsys.readouterr().err

    def test_a_check_for_the_entry_that_raises_keeps_the_old_entry(
        self, tmp_path, monkeypatch, capsys
    ):
        """After a failed restore, asking whether the name holds an entry raises."""
        # Red before: ``final.is_symlink() or final.exists()`` in the restore's
        # except clause raised before the work directory was marked to be kept, so
        # the finally clause deleted it, and the old entry in it.
        third_party, final = self._old_entry(tmp_path)
        real_replace = os.replace
        armed = {"on": False}

        def replace(src, dst, *args, **kwargs):
            if Path(dst) == final and Path(src).name == "incoming":
                raise OSError(errno.ENOSPC, "No space left on device")
            if Path(dst) == final and Path(src).name == "old":
                armed["on"] = True
                raise OSError(errno.EACCES, "Permission denied")
            return real_replace(src, dst, *args, **kwargs)

        real_exists, real_is_symlink = Path.exists, Path.is_symlink
        # The check raises EIO, not the EACCES the failed restore raised, and each
        # call is counted, so the test can tell the check ran and what it raised.
        asked: list[str] = []

        def exists(self, *args, **kwargs):
            if armed["on"] and self == final:
                asked.append("exists")
                raise OSError(errno.EIO, "Input/output error")
            return real_exists(self, *args, **kwargs)

        def is_symlink(self):
            if armed["on"] and self == final:
                asked.append("is_symlink")
                raise OSError(errno.EIO, "Input/output error")
            return real_is_symlink(self)

        monkeypatch.setattr(os, "replace", replace)
        monkeypatch.setattr(Path, "exists", exists)
        monkeypatch.setattr(Path, "is_symlink", is_symlink)

        with pytest.raises(PermissionError):
            installer.publish_third_party(_staged(tmp_path, b"new\n"), third_party)

        assert asked, "the check for an entry at the name never ran"

        kept = [
            p
            for p in third_party.iterdir()
            if p.name.startswith(installer._PUBLISH_WORK_PREFIX)
        ]
        assert len(kept) == 1, "the work directory holding the old entry was deleted"
        assert (kept[0] / "old" / "LICENSE").read_bytes() == b"old\n"
        assert str(kept[0] / "old") in capsys.readouterr().err

    def test_an_identical_entry_from_a_concurrent_publish_leaves_nothing_behind(
        self, tmp_path, monkeypatch
    ):
        """Control: the old entry was moved aside, the other publish's files stand."""
        third_party, final = self._old_entry(tmp_path)
        _other_publish_wins(monkeypatch, final, b"new\n")

        published = installer.publish_third_party(
            _staged(tmp_path, b"new\n"), third_party
        )

        assert (published / "LICENSE").read_bytes() == b"new\n"
        assert sorted(p.name for p in third_party.iterdir()) == ["demo"]

    def test_a_replaced_entry_leaves_no_work_directory(self, tmp_path):
        """Control: the ordinary replace of an old entry deletes the work directory."""
        third_party, _ = self._old_entry(tmp_path)

        published = installer.publish_third_party(
            _staged(tmp_path, b"new\n"), third_party
        )

        assert (published / "LICENSE").read_bytes() == b"new\n"
        assert sorted(p.name for p in third_party.iterdir()) == ["demo"]


class TestAKeptDirectoryGoesOnlyWhileAnEntryStands:
    """The directory a publish kept is removed by another publish only if the name holds an entry.

    A publish that moved the entry another publish had just placed aside, and failed to
    put it back, keeps that entry as the only copy. Removing the directory because a
    publish of the same tool "finished" left the name empty with both reported done.
    """

    @staticmethod
    def _keep_a_directory(third_party: Path, entry: bytes) -> Path:
        kept = third_party / f"{installer._PUBLISH_WORK_PREFIX}other"
        (kept / "old").mkdir(parents=True)
        (kept / "old" / "LICENSE").write_bytes(entry)
        (kept / installer._PUBLISH_KEPT_MARKER).write_text("demo\n", encoding="utf-8")
        return kept

    def test_it_stays_when_the_entry_this_call_placed_is_gone(
        self, tmp_path, monkeypatch
    ):
        # Red before: the call that placed the entry deleted every directory marked
        # for the tool, whether or not its entry was still at the name, and the
        # directory it deleted held the only copy of what it had published.
        third_party = tmp_path / "third-party"
        third_party.mkdir()
        final = third_party / "demo"
        kept = third_party / f"{installer._PUBLISH_WORK_PREFIX}other"
        real = os.replace

        def replace(src, dst, *args, **kwargs):
            real(src, dst, *args, **kwargs)
            if Path(dst) == final and Path(src).name == "incoming":
                # A second publish of the tool moves this entry aside, and its
                # restore fails: the entry is now only in the directory it kept.
                kept.mkdir()
                real(final, kept / "old")
                (kept / installer._PUBLISH_KEPT_MARKER).write_text(
                    "demo\n", encoding="utf-8"
                )

        monkeypatch.setattr(os, "replace", replace)

        installer.publish_third_party(_staged(tmp_path, b"new\n"), third_party)

        assert not final.exists()
        assert kept.exists(), "the directory holding the only copy was deleted"
        assert (kept / "old" / "LICENSE").read_bytes() == b"new\n"

    def test_it_goes_when_an_entry_stands_at_the_name(self, tmp_path):
        """Control: the retried install of the tool supersedes the old copy."""
        third_party = tmp_path / "third-party"
        third_party.mkdir()
        kept = self._keep_a_directory(third_party, b"old\n")

        installer.publish_third_party(_staged(tmp_path, b"new\n"), third_party)

        assert not kept.exists()
        assert sorted(p.name for p in third_party.iterdir()) == ["demo"]

    def test_it_goes_when_the_files_prove_the_entry_though_asking_raises(
        self, tmp_path, monkeypatch
    ):
        """Control: the staged files at the name are enough where exists() raises."""
        third_party = tmp_path / "third-party"
        third_party.mkdir()
        final = third_party / "demo"
        kept = self._keep_a_directory(third_party, b"old\n")
        real_replace, real_exists = os.replace, Path.exists
        armed = {"on": False}

        def replace(src, dst, *args, **kwargs):
            real_replace(src, dst, *args, **kwargs)
            if Path(dst) == final and Path(src).name == "incoming":
                armed["on"] = True

        def exists(self, *args, **kwargs):
            if armed["on"] and self == final:
                raise PermissionError(errno.EACCES, "Permission denied")
            return real_exists(self, *args, **kwargs)

        def is_symlink(self):
            if armed["on"] and self == final:
                raise PermissionError(errno.EACCES, "Permission denied")
            return real_is_symlink(self)

        real_is_symlink = Path.is_symlink
        monkeypatch.setattr(os, "replace", replace)
        monkeypatch.setattr(Path, "exists", exists)
        monkeypatch.setattr(Path, "is_symlink", is_symlink)

        installer.publish_third_party(_staged(tmp_path, b"new\n"), third_party)

        assert not kept.exists()
