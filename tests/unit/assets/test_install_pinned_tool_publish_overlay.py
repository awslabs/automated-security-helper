# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""publish_third_party over a directory that cannot be renamed (EXDEV).

On Docker overlay2 without ``redirect_dir``, renaming a directory that lives in a
lower image layer fails with EXDEV although the destination is in the same tree.
A reinstall over an earlier layer's license directory (the "license files are
missing or incomplete, reinstalling" path, or a downstream image running the
installer again) meets it. ``publish_third_party`` falls back to copying the old
directory aside and deleting it, and keeps the old directory whole when either
step fails.

Nothing here reaches the network or starts a process.
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
        "_install_pinned_tool_overlay", SCRIPT
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


def _old_directory(tmp_path: Path) -> "tuple[Path, Path]":
    third_party = tmp_path / "third-party"
    old = third_party / "demo"
    old.mkdir(parents=True)
    (old / "LICENSE").write_bytes(b"old\n")
    (old / "SOURCE").write_bytes(b"old source\n")
    return third_party, old


def _exdev_for(monkeypatch, directory: Path) -> None:
    """os.replace fails EXDEV for ``directory`` itself, as a lower layer's does."""
    real = os.replace

    def replace(src, dst, *args, **kwargs):
        if Path(src) == directory:
            raise OSError(errno.EXDEV, "Invalid cross-device link", str(src))
        return real(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", replace)


class TestAnExdevOnTheOldDirectory:
    def test_the_old_directory_is_copied_aside_and_the_new_one_installed(
        self, tmp_path, monkeypatch
    ):
        third_party, old = _old_directory(tmp_path)
        staged = _staged(tmp_path, b"new\n")
        _exdev_for(monkeypatch, old)

        final = installer.publish_third_party(staged, third_party)

        assert {p.name: p.read_bytes() for p in final.iterdir()} == {
            "LICENSE": b"new\n"
        }
        assert sorted(p.name for p in third_party.iterdir()) == ["demo"]

    def test_a_failed_copy_leaves_the_old_directory_whole_and_no_partial_copy(
        self, tmp_path, monkeypatch
    ):
        third_party, old = _old_directory(tmp_path)
        staged = _staged(tmp_path, b"new\n")
        _exdev_for(monkeypatch, old)
        real_copytree = shutil.copytree

        def copytree(src, dst, *args, **kwargs):
            if Path(src) == old:
                Path(dst).mkdir()
                (Path(dst) / "LICENSE").write_bytes(b"ol")
                raise OSError(errno.ENOSPC, "No space left on device")
            return real_copytree(src, dst, *args, **kwargs)

        monkeypatch.setattr(shutil, "copytree", copytree)

        with pytest.raises(OSError):
            installer.publish_third_party(staged, third_party)

        assert {p.name: p.read_bytes() for p in old.iterdir()} == {
            "LICENSE": b"old\n",
            "SOURCE": b"old source\n",
        }
        assert sorted(p.name for p in third_party.iterdir()) == ["demo"]

    def test_a_failed_removal_is_made_good_from_the_copy(self, tmp_path, monkeypatch):
        third_party, old = _old_directory(tmp_path)
        staged = _staged(tmp_path, b"new\n")
        _exdev_for(monkeypatch, old)
        real_rmtree = shutil.rmtree

        def rmtree(path, *args, **kwargs):
            if Path(path) == old:
                (old / "LICENSE").unlink()
                raise PermissionError(errno.EACCES, "Permission denied", str(path))
            return real_rmtree(path, *args, **kwargs)

        monkeypatch.setattr(shutil, "rmtree", rmtree)

        with pytest.raises(PermissionError):
            installer.publish_third_party(staged, third_party)

        assert {p.name: p.read_bytes() for p in old.iterdir()} == {
            "LICENSE": b"old\n",
            "SOURCE": b"old source\n",
        }
        assert sorted(p.name for p in third_party.iterdir()) == ["demo"]

    def test_a_failure_to_install_the_new_directory_puts_the_old_one_back(
        self, tmp_path, monkeypatch
    ):
        third_party, old = _old_directory(tmp_path)
        staged = _staged(tmp_path, b"new\n")
        real = os.replace

        def replace(src, dst, *args, **kwargs):
            if Path(src) == old:
                raise OSError(errno.EXDEV, "Invalid cross-device link", str(src))
            if Path(dst) == old and Path(src).name == "incoming":
                raise OSError(errno.ENOSPC, "No space left on device")
            return real(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "replace", replace)

        with pytest.raises(OSError):
            installer.publish_third_party(staged, third_party)

        assert (old / "LICENSE").read_bytes() == b"old\n"
        assert sorted(p.name for p in third_party.iterdir()) == ["demo"]

    def test_an_exdev_on_something_that_is_not_a_directory_is_not_swallowed(
        self, tmp_path, monkeypatch
    ):
        third_party = tmp_path / "third-party"
        third_party.mkdir()
        stray = third_party / "demo"
        stray.write_bytes(b"a stray file\n")
        staged = _staged(tmp_path, b"new\n")
        _exdev_for(monkeypatch, stray)

        with pytest.raises(OSError) as raised:
            installer.publish_third_party(staged, third_party)

        assert raised.value.errno == errno.EXDEV
