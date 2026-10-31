# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``link_locations`` reports a Windows directory junction as a link location.

Every other link check in this family counts a junction as a link
(``scanned_tree._is_link_stat``). ``link_locations`` asked ``Path.is_symlink``,
which says a junction is none, so a junction on the way to a file was stepped
through as a plain directory: the who-chose-this-file checks never saw it, and
the later components were examined under the junction's name rather than where
it leads. A junction cannot be made here, so the stand-in below reports a real
directory as Windows reports a junction (``os.lstat`` gives the reparse-point
attribute and the mount-point tag; ``os.readlink`` gives its target), the shape
``test_a_junction_is_a_link_to_containment_and_trust.py`` uses.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.utils.link_locations import link_locations

pytestmark = pytest.mark.unit

#: The junction stand-in runs everywhere; only the test that also makes a real
#: symlink needs the privilege Windows runners lack.
needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)

#: IO_REPARSE_TAG_MOUNT_POINT, the reparse tag of a junction.
MOUNT_POINT_TAG = 0xA0000003


class _JunctionStat:
    """The stat of the directory a junction leads to, as lstat reports a junction."""

    def __init__(self, target: os.stat_result) -> None:
        self._target = target
        self.st_file_attributes = stat.FILE_ATTRIBUTE_REPARSE_POINT
        self.st_reparse_tag = MOUNT_POINT_TAG

    def __getattr__(self, name: str) -> Any:
        return getattr(self._target, name)


def _as_a_junction(monkeypatch: pytest.MonkeyPatch, junction: Path, target: Path):
    real_lstat = os.lstat
    real_readlink = os.readlink
    shown = str(junction)

    def lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if os.fspath(path) == shown and not args and not kwargs:
            return _JunctionStat(os.stat(str(target)))
        return real_lstat(path, *args, **kwargs)

    def readlink(path: Any, *args: Any, **kwargs: Any) -> Any:
        if os.fspath(path) == shown:
            return str(target)
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "readlink", readlink)


def test_a_junction_on_the_way_is_a_link_location(tmp_path, monkeypatch):
    tree = Path(os.path.realpath(tmp_path))
    target = tree / "real"
    (target / "sub").mkdir(parents=True)
    (target / "sub" / "config.yaml").write_text("a: 1\n", encoding="utf-8")
    junction = tree / "junction"
    junction.mkdir()
    _as_a_junction(monkeypatch, junction, target)

    assert not junction.is_symlink()
    assert link_locations(junction / "sub" / "config.yaml") == [junction]


@needs_symlinks
def test_a_link_behind_a_junction_is_found_where_the_junction_leads(
    tmp_path, monkeypatch
):
    tree = Path(os.path.realpath(tmp_path))
    target = tree / "real"
    target.mkdir()
    (tree / "elsewhere").mkdir()
    (tree / "elsewhere" / "config.yaml").write_text("a: 1\n", encoding="utf-8")
    (target / "config.yaml").symlink_to(tree / "elsewhere" / "config.yaml")
    junction = tree / "junction"
    junction.mkdir()
    _as_a_junction(monkeypatch, junction, target)

    found = link_locations(junction / "config.yaml")

    assert found == [junction, target / "config.yaml"]


def test_control_a_plain_directory_is_no_link_location(tmp_path):
    tree = Path(os.path.realpath(tmp_path))
    (tree / "plain" / "sub").mkdir(parents=True)
    (tree / "plain" / "sub" / "config.yaml").write_text("a: 1\n", encoding="utf-8")

    assert link_locations(tree / "plain" / "sub" / "config.yaml") == []


def test_control_a_missing_component_is_stepped_through(tmp_path):
    tree = Path(os.path.realpath(tmp_path))

    assert link_locations(tree / "missing" / "config.yaml") == []
