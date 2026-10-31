# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config another user owns is written in place, not replaced.

Why this file exists
--------------------
The staged write of an ``ash config`` command renames a new file over the config,
and the new file belongs to the process that wrote it. Handing it back to the
owner needs the privilege to change an owner, which only root has; the refusal
is swallowed. A config in a shared directory that its owner can write but this
user may replace (a group-writable directory) therefore ended up owned by the
editor, and its owner lost write access to it. Such a file is now written in
place, which keeps its owner, its mode and its other names.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.cli.config import (
    _owned_by_another_user,
    _write_config_bytes,
    _write_config_text,
)
from automated_security_helper.utils.output_dir_links import OutputDirLinkRefused
from automated_security_helper.utils.sandbox.fs_guard import writable_root

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(not hasattr(os, "geteuid"), reason="no user ids here"),
]


def _someone_else(monkeypatch: pytest.MonkeyPatch, config: Path) -> None:
    """Make this process look like a user other than the config's owner."""
    other = config.stat().st_uid + 1
    monkeypatch.setattr(os, "geteuid", lambda: other)


def test_a_file_of_another_user_is_not_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red at the base: the staged write made a new file, so the inode changed
    (and with it the owner, on a host where the chown is refused)."""
    config = tmp_path / ".ash.yaml"
    config.write_text("project_name: before\n", encoding="utf-8")
    inode = config.stat().st_ino
    _someone_else(monkeypatch, config)

    _write_config_text(config, "project_name: after\n")

    assert config.read_text(encoding="utf-8") == "project_name: after\n"
    assert config.stat().st_ino == inode


def test_the_bytes_writer_leaves_a_file_of_another_user_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / ".ash.yaml"
    config.write_bytes(b"project_name: before\n")
    inode = config.stat().st_ino
    _someone_else(monkeypatch, config)

    _write_config_bytes(config, b"project_name: after\n")

    assert config.read_bytes() == b"project_name: after\n"
    assert config.stat().st_ino == inode


def test_a_file_of_the_writer_is_still_replaced(tmp_path: Path) -> None:
    """The positive control: the staged write is still the way for a file this
    process owns, so the test above is not a write that is always in place."""
    config = tmp_path / ".ash.yaml"
    config.write_text("project_name: before\n", encoding="utf-8")
    inode = config.stat().st_ino

    _write_config_text(config, "project_name: after\n")

    assert config.read_text(encoding="utf-8") == "project_name: after\n"
    assert config.stat().st_ino != inode


def test_root_and_a_missing_file_are_not_another_users(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / ".ash.yaml"
    config.write_text("x: 1\n", encoding="utf-8")
    status = config.stat()
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    assert not _owned_by_another_user(status)
    assert not _owned_by_another_user(None)


def _text_of(writer: Any) -> Any:
    """The text the writer is given: str for the text writer, bytes for the other."""
    return (lambda s: s) if writer is _write_config_text else (lambda s: s.encode())


@pytest.mark.parametrize("writer", [_write_config_text, _write_config_bytes])
def test_a_hard_linked_file_of_another_user_is_refused_below_a_guarded_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, writer: Any
) -> None:
    """Red at the base: the owner check raised before the guard was asked, and
    the in-place fallback wrote through the second name of the file."""
    root = tmp_path / "out"
    root.mkdir()
    elsewhere = tmp_path / "elsewhere.yaml"
    elsewhere.write_bytes(b"project_name: before\n")
    config = root / ".ash.yaml"
    try:
        os.link(elsewhere, config)
    except OSError:
        pytest.skip("hard links are not available here")
    _someone_else(monkeypatch, config)

    with writable_root(root):
        with pytest.raises(OutputDirLinkRefused):
            writer(config, _text_of(writer)("project_name: after\n"))

    assert elsewhere.read_bytes() == b"project_name: before\n"
    assert config.read_bytes() == b"project_name: before\n"


@pytest.mark.parametrize("writer", [_write_config_text, _write_config_bytes])
def test_a_file_under_a_symlinked_directory_is_refused_below_a_guarded_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, writer: Any
) -> None:
    """Red at the base: the same fallback wrote through a link the guard refuses."""
    root = tmp_path / "out"
    root.mkdir()
    real = tmp_path / "real"
    real.mkdir()
    (real / ".ash.yaml").write_bytes(b"project_name: before\n")
    try:
        os.symlink(real, root / "linked", target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are not available here")
    config = root / "linked" / ".ash.yaml"
    _someone_else(monkeypatch, config)

    with writable_root(root):
        with pytest.raises(OutputDirLinkRefused):
            writer(config, _text_of(writer)("project_name: after\n"))

    assert (real / ".ash.yaml").read_bytes() == b"project_name: before\n"


@pytest.mark.parametrize("writer", [_write_config_text, _write_config_bytes])
def test_a_plain_file_of_another_user_below_a_guarded_root_is_written_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, writer: Any
) -> None:
    """The positive control: one name, no link, so the guard accepts it and the
    in-place write is still made, with the inode kept."""
    root = tmp_path / "out"
    root.mkdir()
    config = root / ".ash.yaml"
    config.write_bytes(b"project_name: before\n")
    inode = config.stat().st_ino
    _someone_else(monkeypatch, config)

    with writable_root(root):
        writer(config, _text_of(writer)("project_name: after\n"))

    assert config.read_bytes() == b"project_name: after\n"
    assert config.stat().st_ino == inode
