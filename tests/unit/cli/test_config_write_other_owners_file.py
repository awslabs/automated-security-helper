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

import pytest

from automated_security_helper.cli.config import (
    _owned_by_another_user,
    _write_config_bytes,
    _write_config_text,
)

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
