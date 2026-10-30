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
import tarfile
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
