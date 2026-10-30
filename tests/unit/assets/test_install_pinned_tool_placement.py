# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Where install-pinned-tool puts the executable and the license files.

Each class pins one way the install could leave the destination wrong:

* The executable moved with ``shutil.move`` from the system temp directory. Across
  filesystems that is a copy in place: it writes through a symlink at the
  destination, and an interrupt leaves a half-written executable. Onto a directory
  it moved the file inside and reported success at a path nothing runs.
* A destination that is executable but unreadable made the already-installed check
  raise instead of reinstalling.
* License files were published before the executable was extracted and checked, so a
  failed extraction left the new release's license directory beside an old binary.
* They were still published before the executable was copied beside its destination,
  so a copy that ran out of space (ENOSPC, EIO, EACCES) left the same state. The copy
  now comes first and only a rename follows the publish. The staged file is always
  copied into a file made beside the destination, never renamed in from the staging
  directory, so the file has the destination directory's label, ACLs and group.
* Two installs of one tool with ``third_party_dir`` set: the one that loses the
  license publish finds the same files in place and still installs the binary.
* ``publish_third_party`` deleted the old license directory before the move, and
  could not delete a symlink or a file at all.
* A zip archive's directory entry that carried the member's name counted as a
  second copy of the executable.

Nothing here reaches the network or starts a process.
"""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import io
import os
import shutil
import tarfile
import tempfile
import types
import zipfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "automated_security_helper" / "assets" / "install-pinned-tool.py"

_PAYLOAD = b"#!/bin/sh\necho demo\n"
_LICENSE = b"demo license text\n"


def _load_script():
    spec = importlib.util.spec_from_file_location("_install_pinned_tool_place", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = _load_script()


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _tar(members: dict) -> bytes:
    """A reproducible tar.gz: mtime pinned, so its digest is stable across calls."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mtime = 0
            info.mode = 0o755
            bundle.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


class _Setup:
    """A fake table with one tool, ``demo``, and an archive served from memory."""

    def __init__(self, monkeypatch, executable_digest: "str | None" = None):
        self.archive = _tar({"demo": _PAYLOAD, "LICENSE": _LICENSE})
        self.downloads: list = []
        self.asset = types.SimpleNamespace(
            tool="demo",
            version="1.0.0",
            url="https://example.invalid/demo.tar.gz",
            sha256=_sha(self.archive),
            install_as="demo",
            member_name="demo",
            executable_digest=executable_digest or _sha(_PAYLOAD),
            archive=True,
        )
        self.entry = types.SimpleNamespace(
            tool="demo",
            version="1.0.0",
            distribution=None,
            files=(
                types.SimpleNamespace(
                    name="LICENSE", url=None, sha256=None, from_archive=True
                ),
            ),
            source_notice=lambda installed_from=None: "demo notice\n",
        )
        pins = types.SimpleNamespace(
            ToolNotProvisionableError=LookupError,
            get_tool_asset=lambda tool, platform_name, arch: self.asset,
            get_third_party_license=lambda tool: self.entry,
        )
        monkeypatch.setattr(installer, "load_pins", lambda root: pins)
        monkeypatch.setattr(installer.platform, "machine", lambda: "x86_64")
        monkeypatch.setattr(installer.platform, "system", lambda: "Linux")

        def download(url, target):
            self.downloads.append(url)
            target.write_bytes(self.archive)
            return _sha(self.archive)

        monkeypatch.setattr(installer, "download", download)

    def install(self, bin_dir: Path, third_party_dir: "Path | None" = None) -> Path:
        return installer.install("demo", bin_dir, Path("unused"), third_party_dir)


def _cross_device(monkeypatch) -> None:
    """Make a rename between two different directories fail as across filesystems.

    The staging directory and the destination are siblings on one disk in a test,
    so ``os.rename`` always works between them. A rename inside one directory still
    works, which is what a file staged beside its destination relies on.
    """

    def guard(real):
        def renamer(src, dst, *args, **kwargs):
            if os.path.dirname(os.fspath(src)) != os.path.dirname(os.fspath(dst)):
                raise OSError(errno.EXDEV, "Invalid cross-device link")
            return real(src, dst, *args, **kwargs)

        return renamer

    monkeypatch.setattr(os, "rename", guard(os.rename))
    monkeypatch.setattr(os, "replace", guard(os.replace))


class TestTheExecutableIsPlacedWithOneRename:
    def test_a_directory_at_the_destination_is_refused_before_downloading(
        self, tmp_path, monkeypatch
    ):
        setup = _Setup(monkeypatch)
        bin_dir = tmp_path / "bin"
        (bin_dir / "demo").mkdir(parents=True)
        with pytest.raises(SystemExit) as raised:
            setup.install(bin_dir)
        assert raised.value.code == installer._EXIT_USAGE
        assert "is a directory" in str(raised.value)
        assert setup.downloads == []
        assert list((bin_dir / "demo").iterdir()) == []

    def test_a_cross_filesystem_install_does_not_write_through_a_symlink(
        self, tmp_path, monkeypatch
    ):
        setup = _Setup(monkeypatch)
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.write_bytes(b"some other file\n")
        (bin_dir / "demo").symlink_to(elsewhere)
        _cross_device(monkeypatch)

        installed = setup.install(bin_dir)

        assert elsewhere.read_bytes() == b"some other file\n", (
            "the install wrote through the symlink onto the file it points at"
        )
        assert not installed.is_symlink()
        assert installed.read_bytes() == _PAYLOAD
        assert os.access(installed, os.X_OK)

    def test_an_interrupted_copy_leaves_the_existing_binary_alone(
        self, tmp_path, monkeypatch
    ):
        setup = _Setup(monkeypatch)
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        existing = bin_dir / "demo"
        existing.write_bytes(b"#!/bin/sh\necho old\n")
        existing.chmod(0o755)
        _cross_device(monkeypatch)

        def half_written(src, dst, *args, **kwargs):
            Path(dst).write_bytes(Path(src).read_bytes()[:4])
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(installer.shutil, "copyfile", half_written)

        with pytest.raises(OSError):
            setup.install(bin_dir)

        assert existing.read_bytes() == b"#!/bin/sh\necho old\n"
        assert sorted(p.name for p in bin_dir.iterdir()) == ["demo"], (
            "a partial file was left beside the destination"
        )

    def test_a_plain_install_leaves_one_executable_and_no_partial_file(
        self, tmp_path, monkeypatch
    ):
        """Control for the three tests above."""
        setup = _Setup(monkeypatch)
        bin_dir = tmp_path / "bin"
        installed = setup.install(bin_dir)
        assert sorted(p.name for p in bin_dir.iterdir()) == ["demo"]
        assert installed.read_bytes() == _PAYLOAD
        assert os.access(installed, os.X_OK)


class TestAnUnreadableBinaryAtTheDestination:
    def test_it_is_replaced_instead_of_aborting_the_install(
        self, tmp_path, monkeypatch
    ):
        setup = _Setup(monkeypatch)
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        existing = bin_dir / "demo"
        existing.write_bytes(b"#!/bin/sh\necho old\n")
        existing.chmod(0o755)
        real_hash = installer._sha256_file

        def unreadable(path):
            # Mode 0111 would do this for any user but root; raising here makes the
            # case the same whoever runs the test.
            if Path(path) == existing:
                raise PermissionError(errno.EACCES, "Permission denied", str(path))
            return real_hash(path)

        monkeypatch.setattr(installer, "_sha256_file", unreadable)

        installed = setup.install(bin_dir)

        assert installed.read_bytes() == _PAYLOAD
        assert setup.downloads == [setup.asset.url]


class TestLicensesWaitForTheCheckedExecutable:
    def test_a_failed_digest_check_publishes_no_license_directory(
        self, tmp_path, monkeypatch
    ):
        setup = _Setup(monkeypatch, executable_digest="0" * 64)
        third_party = tmp_path / "third-party"
        with pytest.raises(SystemExit) as raised:
            setup.install(tmp_path / "bin", third_party)
        assert raised.value.code == installer._EXIT_INTEGRITY
        assert not (third_party / "demo").exists(), (
            "license files for a release that was not installed were published"
        )
        assert not (tmp_path / "bin" / "demo").exists()

    def test_a_good_install_publishes_them_beside_the_binary(
        self, tmp_path, monkeypatch
    ):
        """Control: the licenses still land when the executable checks out."""
        setup = _Setup(monkeypatch)
        third_party = tmp_path / "third-party"
        setup.install(tmp_path / "bin", third_party)
        assert (third_party / "demo" / "LICENSE").read_bytes() == _LICENSE
        assert (tmp_path / "bin" / "demo").read_bytes() == _PAYLOAD


_OLD_BINARY = b"#!/bin/sh\necho old\n"


class TestAFailedPlacementLeavesTheLicensesAlone:
    """Publishing the license directory comes after the copy beside the destination.

    Everything here runs under ``tmp_path`` with the download stubbed.
    """

    @staticmethod
    def _old_install(tmp_path: Path):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        existing = bin_dir / "demo"
        existing.write_bytes(_OLD_BINARY)
        existing.chmod(0o755)
        third_party = tmp_path / "third-party"
        (third_party / "demo").mkdir(parents=True)
        (third_party / "demo" / "LICENSE").write_bytes(b"old license\n")
        return bin_dir, existing, third_party

    @staticmethod
    def _staging_is_another_filesystem(monkeypatch, bin_dir: Path) -> None:
        """Only a rename from outside ``bin_dir`` into it fails as across filesystems.

        The license publish and the final rename inside ``bin_dir`` stay real, so
        the failure is in the copy and nowhere else.
        """
        real = os.replace

        def replace(src, dst, *args, **kwargs):
            if Path(dst).parent == bin_dir and Path(src).parent != bin_dir:
                raise OSError(errno.EXDEV, "Invalid cross-device link")
            return real(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "replace", replace)

    def test_a_copy_that_runs_out_of_space_keeps_the_old_licenses_and_binary(
        self, tmp_path, monkeypatch
    ):
        setup = _Setup(monkeypatch)
        bin_dir, existing, third_party = self._old_install(tmp_path)
        self._staging_is_another_filesystem(monkeypatch, bin_dir)
        real_copyfile = shutil.copyfile

        def full_disk(src, dst, *args, **kwargs):
            # Only the copy beside the destination fails; copytree's copies into
            # the license work directory go through the real function.
            if Path(dst).parent == bin_dir:
                Path(dst).write_bytes(Path(src).read_bytes()[:4])
                raise OSError(errno.ENOSPC, "No space left on device")
            return real_copyfile(src, dst, *args, **kwargs)

        monkeypatch.setattr(shutil, "copyfile", full_disk)

        with pytest.raises(OSError) as raised:
            setup.install(bin_dir, third_party)

        assert raised.value.errno == errno.ENOSPC
        assert existing.read_bytes() == _OLD_BINARY
        assert (third_party / "demo" / "LICENSE").read_bytes() == b"old license\n", (
            "the new release's license directory was published beside the old binary"
        )
        assert sorted(p.name for p in bin_dir.iterdir()) == ["demo"], (
            "a partial file was left beside the destination"
        )
        assert sorted(p.name for p in third_party.iterdir()) == ["demo"]

    def test_a_failed_publish_removes_the_copied_executable(
        self, tmp_path, monkeypatch
    ):
        """The copy is made first, so a publish that fails has a file to clean up."""
        setup = _Setup(monkeypatch)
        bin_dir, existing, third_party = self._old_install(tmp_path)

        def refuse(staged, directory):
            raise OSError(errno.EACCES, "Permission denied")

        monkeypatch.setattr(installer, "publish_third_party", refuse)

        with pytest.raises(PermissionError):
            setup.install(bin_dir, third_party)

        assert existing.read_bytes() == _OLD_BINARY
        assert sorted(p.name for p in bin_dir.iterdir()) == ["demo"], (
            "a partial file was left beside the destination"
        )

    def test_a_good_install_replaces_both_together(self, tmp_path, monkeypatch):
        """Control: with nothing failing, the new binary and the new licenses land."""
        setup = _Setup(monkeypatch)
        bin_dir, _, third_party = self._old_install(tmp_path)

        setup.install(bin_dir, third_party)

        assert (bin_dir / "demo").read_bytes() == _PAYLOAD
        assert (third_party / "demo" / "LICENSE").read_bytes() == _LICENSE
        assert sorted(p.name for p in bin_dir.iterdir()) == ["demo"]


class TestTwoInstallsOfOneTool:
    def test_the_loser_of_the_license_publish_still_installs_the_binary(
        self, tmp_path, monkeypatch
    ):
        """Through ``install``, with ``third_party_dir`` set, as the image sets it."""
        setup = _Setup(monkeypatch)
        bin_dir = tmp_path / "bin"
        third_party = tmp_path / "third-party"
        final = third_party / "demo"
        real = os.replace

        def other_install_publishes_first(src, dst, *args, **kwargs):
            if Path(dst) == final and Path(src).name == "incoming":
                final.mkdir()
                (final / "LICENSE").write_bytes(_LICENSE)
                # The installer writes SOURCE with write_text, which ends a line
                # with the platform's newline (CRLF on Windows). The other install
                # is the same installer, so its file is written the same way; LF
                # bytes would differ from this call's copy on Windows and the
                # identical-entry check would refuse a loser that is in fact done.
                (final / "SOURCE").write_text("demo notice\n", encoding="utf-8")
            return real(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "replace", other_install_publishes_first)

        installed = setup.install(bin_dir, third_party)

        assert installed.read_bytes() == _PAYLOAD
        assert (final / "LICENSE").read_bytes() == _LICENSE
        assert sorted(p.name for p in third_party.iterdir()) == ["demo"]
        assert sorted(p.name for p in bin_dir.iterdir()) == ["demo"]


class TestPreparingTheExecutable:
    @staticmethod
    def _staged(tmp_path: Path) -> Path:
        staged = tmp_path / "staging" / "demo"
        staged.parent.mkdir()
        staged.write_bytes(_PAYLOAD)
        (tmp_path / "bin").mkdir()
        return staged

    def test_a_staged_file_on_the_same_filesystem_is_copied_not_renamed(self, tmp_path):
        staged = self._staged(tmp_path)

        partial = installer._prepare_executable(staged, tmp_path / "bin" / "demo")

        assert partial.parent == tmp_path / "bin"
        assert partial.read_bytes() == _PAYLOAD
        assert staged.read_bytes() == _PAYLOAD, "the staged file was renamed away"
        if os.name != "nt":
            assert partial.stat().st_mode & 0o777 == 0o755

    @pytest.mark.skipif(os.name == "nt", reason="inode numbers are not stable here")
    def test_the_file_beside_the_destination_keeps_the_inode_made_there(
        self, tmp_path, monkeypatch
    ):
        """A renamed-in file keeps the staging directory's label and loses the
        destination directory's default ACLs and group; the file created there has
        the destination's, so the bytes must be written into it."""
        staged = self._staged(tmp_path)
        made: list = []
        real_mkstemp = tempfile.mkstemp

        def mkstemp(*args, **kwargs):
            descriptor, name = real_mkstemp(*args, **kwargs)
            made.append(os.fstat(descriptor).st_ino)
            return descriptor, name

        monkeypatch.setattr(tempfile, "mkstemp", mkstemp)

        partial = installer._prepare_executable(staged, tmp_path / "bin" / "demo")

        assert made == [partial.stat().st_ino]

    def test_a_copy_that_fails_leaves_nothing_beside_the_destination(
        self, tmp_path, monkeypatch
    ):
        staged = self._staged(tmp_path)

        def full_disk(src, dst, *args, **kwargs):
            Path(dst).write_bytes(Path(src).read_bytes()[:4])
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(shutil, "copyfile", full_disk)

        with pytest.raises(OSError) as raised:
            installer._prepare_executable(staged, tmp_path / "bin" / "demo")

        assert raised.value.errno == errno.ENOSPC
        assert list((tmp_path / "bin").iterdir()) == []
        assert staged.read_bytes() == _PAYLOAD


def _staged_license_dir(tmp_path: Path, text: bytes) -> Path:
    staged = tmp_path / "staging" / "demo"
    staged.mkdir(parents=True)
    (staged / "LICENSE").write_bytes(text)
    return staged


class TestPublishingTheLicenseDirectory:
    def test_a_symlink_at_the_destination_is_replaced_not_followed(self, tmp_path):
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "LICENSE").write_bytes(b"not ours\n")
        third_party = tmp_path / "third-party"
        third_party.mkdir()
        (third_party / "demo").symlink_to(elsewhere, target_is_directory=True)

        final = installer.publish_third_party(
            _staged_license_dir(tmp_path, b"new\n"), third_party
        )

        assert not final.is_symlink()
        assert (final / "LICENSE").read_bytes() == b"new\n"
        assert (elsewhere / "LICENSE").read_bytes() == b"not ours\n"

    def test_a_file_at_the_destination_is_replaced(self, tmp_path):
        third_party = tmp_path / "third-party"
        third_party.mkdir()
        (third_party / "demo").write_bytes(b"a stray file\n")

        final = installer.publish_third_party(
            _staged_license_dir(tmp_path, b"new\n"), third_party
        )

        assert (final / "LICENSE").read_bytes() == b"new\n"

    def test_a_failed_move_keeps_the_old_directory(self, tmp_path, monkeypatch):
        third_party = tmp_path / "third-party"
        old = third_party / "demo"
        old.mkdir(parents=True)
        (old / "LICENSE").write_bytes(b"old\n")
        staged = _staged_license_dir(tmp_path, b"new\n")

        def refuse_the_new_directory(real):
            def mover(src, dst, *args, **kwargs):
                # Only the step that puts the new directory at its name fails; the
                # old directory, when set aside, may be put back.
                if Path(dst) == old and Path(src).name != "old":
                    raise OSError(errno.ENOSPC, "No space left on device")
                return real(src, dst, *args, **kwargs)

            return mover

        monkeypatch.setattr(os, "replace", refuse_the_new_directory(os.replace))
        monkeypatch.setattr(
            installer.shutil, "move", refuse_the_new_directory(installer.shutil.move)
        )

        with pytest.raises(OSError):
            installer.publish_third_party(staged, third_party)

        assert (old / "LICENSE").read_bytes() == b"old\n", (
            "the old license directory was deleted before the new one was in place"
        )
        assert sorted(p.name for p in third_party.iterdir()) == ["demo"]

    @pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
    def test_the_modes_are_world_readable(self, tmp_path):
        """Control: the copy keeps the modes the image's non-root user needs."""
        third_party = tmp_path / "third-party"
        final = installer.publish_third_party(
            _staged_license_dir(tmp_path, b"new\n"), third_party
        )
        assert final.stat().st_mode & 0o777 == 0o755
        assert (final / "LICENSE").stat().st_mode & 0o777 == 0o644


class TestAZipDirectoryEntryIsNotAMember:
    def test_a_directory_named_like_the_member_is_not_a_second_copy(self, tmp_path):
        archive = tmp_path / "bundle.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("tools/demo/", b"")
            bundle.writestr("bin/demo", _PAYLOAD)

        destination = tmp_path / "out"
        installer.extract_member(archive, "demo", destination)

        assert destination.read_bytes() == _PAYLOAD

    def test_two_files_of_the_name_are_still_refused(self, tmp_path):
        archive = tmp_path / "bundle.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("one/demo", b"x")
            bundle.writestr("two/demo", b"y")

        with pytest.raises(SystemExit) as raised:
            installer.extract_member(archive, "demo", tmp_path / "out")
        assert "refusing to guess" in str(raised.value)
