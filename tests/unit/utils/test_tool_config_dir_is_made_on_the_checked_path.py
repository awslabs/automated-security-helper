# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""utils/tool_config_dir makes a scanner's config directory on the path it checked.

The private-directory check walks the candidate's resolved path, but the
directory used to be made, and the files written, through the path as given, so
a symbolic link in TMPDIR or the output directory was walked again by a path the
check never saw. The directory is now made under the resolved path, and that path
is resolved once: the check is given it and does not resolve it again, so a link
pointed elsewhere after the check is not followed.
"""

from __future__ import annotations

import os
import sys
import tempfile

import pytest

from automated_security_helper.utils import tool_config_dir

pytestmark = pytest.mark.unit


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_the_directory_is_made_under_the_resolved_temporary_directory(
    tmp_path, monkeypatch
):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(link))
    # The ownership walk is not this test's subject: every candidate passes it.
    monkeypatch.setattr(tool_config_dir, "_changeable_by_others", lambda path: None)

    made = tool_config_dir._new_directory(None, None)

    try:
        assert made.parent == real.resolve()
        assert "link" not in made.parts
    finally:
        os.rmdir(made)


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_a_link_pointed_elsewhere_after_the_check_is_not_followed(
    tmp_path, monkeypatch
):
    checked = tmp_path / "checked"
    checked.mkdir(mode=0o700)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(checked, target_is_directory=True)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(link))
    seen = []

    def check_then_repoint(path):
        # What another account could do between the check and the use, were the
        # link resolved again after it.
        seen.append(path)
        link.unlink()
        link.symlink_to(elsewhere, target_is_directory=True)
        return None

    monkeypatch.setattr(tool_config_dir, "_changeable_by_others", check_then_repoint)

    made = tool_config_dir._new_directory(None, None)

    try:
        assert seen == [checked.resolve()], seen
        assert made.parent == checked.resolve(), made
        assert list(elsewhere.iterdir()) == []
    finally:
        os.rmdir(made)
