# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which session file a client's config path names is decided by file identity.

The runner copies the session's profile for the scan when the client's config
path is that file, so a ``select_profile`` rebind while the scan waits at the
session lock cannot give it a file whose environment values the redaction set
never saw. The decision used to compare the typed text against the registry's
spelling: a client that typed the same file with a ``..`` in it, as a relative
path, or through a link got no copy, and the scan loaded the live profile.

These cells pin the helpers that make the decision. Every file is under the
cell's ``tmp_path``; nothing reads the real environment.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp_tools import (
    _names_the_same_file,
    _session_file_named_by,
)


def _a_session_file(tmp_path: Path) -> Path:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    session_file = config_dir / "ash.yaml"
    session_file.write_text("project_name: a\n", encoding="utf-8")
    return session_file


def test_session_file_named_by_tells_the_same_file_by_identity(tmp_path):
    """A ``..`` form, a relative path, a symlink and a hard link name the
    session's file; another file, and a path that is nothing, do not. The answer
    is the session's own spelling."""
    session_file = _a_session_file(tmp_path)
    config_dir = session_file.parent
    other = config_dir / "other.yaml"
    other.write_text("project_name: b\n", encoding="utf-8")
    symlink = tmp_path / "alias.yaml"
    try:
        symlink.symlink_to(session_file)
    except OSError:
        pytest.skip("this platform does not let the cell make a symlink")
    hardlink = tmp_path / "hard.yaml"
    os.link(session_file, hardlink)
    dotdot = str(config_dir / ".." / "config" / "ash.yaml")
    spelled = str(session_file)

    assert _session_file_named_by(spelled, spelled) == session_file
    assert _session_file_named_by(dotdot, spelled) == session_file
    assert _session_file_named_by(str(symlink), spelled) == session_file
    assert _session_file_named_by(str(hardlink), spelled) == session_file
    assert _session_file_named_by(str(other), spelled) is None
    assert _session_file_named_by(str(tmp_path / "missing.yaml"), spelled) is None
    # The first matching session file wins, and a None entry is skipped.
    assert _session_file_named_by(dotdot, None, spelled, str(other)) == session_file
    assert _session_file_named_by(dotdot) is None


def test_session_file_named_by_follows_a_relative_path(tmp_path, monkeypatch):
    session_file = _a_session_file(tmp_path)
    monkeypatch.chdir(tmp_path)

    assert _session_file_named_by("config/ash.yaml", str(session_file)) == session_file
    assert _session_file_named_by("config/nope.yaml", str(session_file)) is None


def test_a_file_that_is_not_there_yet_is_told_apart_by_its_resolved_path(tmp_path):
    """Neither side can be statted, so identity has nothing to compare: the
    resolved paths decide, and a different missing file is a different file."""
    gone = tmp_path / "config" / "gone.yaml"
    dotdot = str(tmp_path / "config" / ".." / "config" / "gone.yaml")

    assert _names_the_same_file(dotdot, str(gone)) is True
    assert (
        _names_the_same_file(str(tmp_path / "config" / "else.yaml"), str(gone)) is False
    )


@pytest.mark.parametrize("named", ["", "has\x00a-nul-byte"])
def test_a_path_that_cannot_be_statted_is_not_the_session_file_and_raises_nothing(
    tmp_path, named
):
    session_file = _a_session_file(tmp_path)

    assert _names_the_same_file(named, str(session_file)) is False
