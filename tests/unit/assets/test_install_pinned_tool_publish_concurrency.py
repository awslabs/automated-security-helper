# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two publishes of one tool's license directory into one ASH_THIRD_PARTY_DIR.

The Dockerfile sets ASH_THIRD_PARTY_DIR for every pinned install, so two
installs of one tool can publish into the same directory at once. The one that
loses the race used to fail twice over: its rename of the old directory aside hit
FileNotFoundError when the other publish had already moved it, and its rename of
the new directory into place hit "Directory not empty" when the other publish had
already put the same files there.

Nothing here reaches the network or starts a process.
"""

from __future__ import annotations

import errno
import importlib.util
import os
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
