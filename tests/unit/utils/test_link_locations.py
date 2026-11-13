# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``link_locations`` finds every symlink a path lookup follows, where each one sits."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.utils.link_locations import (
    MAX_LINKS_FOLLOWED,
    link_locations,
    without_extended_prefix,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "readlink, spelled",
    [
        ("\\\\?\\C:\\a\\b", "C:\\a\\b"),
        ("\\\\?\\UNC\\host\\share\\f", "\\\\host\\share\\f"),
        ("C:\\a\\b", "C:\\a\\b"),
        ("\\\\host\\share\\f", "\\\\host\\share\\f"),
        ("../a/b", "../a/b"),
        ("/a/b", "/a/b"),
    ],
)
def test_the_win32_extended_length_prefix_is_dropped_from_a_link_target(
    readlink: str, spelled: str
) -> None:
    """``os.readlink`` gives ``\\\\?\\C:\\a`` on Windows; the walk names the place ``C:\\a``."""
    assert without_extended_prefix(readlink) == spelled


def _symlink(link: Path, target: Path | str) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"cannot create a symlink here: {exc}")


def test_a_path_without_links_has_none(tmp_path: Path) -> None:
    real = Path(os.path.realpath(tmp_path))
    (real / "a.yaml").write_text("x: 1\n", encoding="utf-8")

    assert link_locations(real / "a.yaml") == []


def test_each_link_on_the_way_is_found_where_it_sits(tmp_path: Path) -> None:
    real = Path(os.path.realpath(tmp_path))
    target = real / "host" / "ash.yaml"
    target.parent.mkdir()
    target.write_text("x: 1\n", encoding="utf-8")
    # tree/.ash -> other/dir, and other/dir/.ash.yaml -> host/ash.yaml.
    _symlink(real / "other" / "dir" / ".ash.yaml", target)
    _symlink(real / "tree" / ".ash", real / "other" / "dir")

    found = link_locations(real / "tree" / ".ash" / ".ash.yaml")

    assert found == [real / "tree" / ".ash", real / "other" / "dir" / ".ash.yaml"]


def test_a_relative_link_and_a_dotdot_after_it_follow_the_target(
    tmp_path: Path,
) -> None:
    real = Path(os.path.realpath(tmp_path))
    (real / "a" / "b").mkdir(parents=True)
    (real / "a" / "f.yaml").write_text("x: 1\n", encoding="utf-8")
    _symlink(real / "tree" / "lnk", "../a/b")

    # tree/lnk/.. is a/, not tree/, because the kernel applies .. to the target.
    found = link_locations(real / "tree" / "lnk" / ".." / "f.yaml")

    assert found == [real / "tree" / "lnk"]


def test_a_loop_stops(tmp_path: Path) -> None:
    real = Path(os.path.realpath(tmp_path))
    _symlink(real / "x", real / "y")
    _symlink(real / "y", real / "x")

    found = link_locations(real / "x" / "f.yaml")

    assert len(found) == MAX_LINKS_FOLLOWED
