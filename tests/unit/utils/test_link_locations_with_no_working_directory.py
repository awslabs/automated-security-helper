# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``link_locations`` reads the working directory only for a relative path.

The trust checks that call it judge config files by absolute path, and with the
working directory deleted every one of them raised ``FileNotFoundError`` out of
``os.getcwd()`` before the walk began, although an absolute path needs no
directory to start from. A relative path still does, so it still raises: an
empty answer there would read as "no links" to a check that decides who wrote a
file.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.link_locations import link_locations


def _delete_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # os.rmdir of the process's working directory is PermissionError on Windows,
    # so every deleted-cwd cell skips there through this one helper.
    if sys.platform == "win32":
        pytest.skip("the working directory cannot be removed on Windows")
    launched = tmp_path / "launched-here"
    launched.mkdir()
    monkeypatch.chdir(launched)
    os.rmdir(launched)
    with pytest.raises(FileNotFoundError):
        os.getcwd()


def _symlink(link: Path, target: Path | str) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"cannot create a symlink here: {exc}")


def test_an_absolute_path_is_walked_with_the_working_directory_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = Path(os.path.realpath(tmp_path))
    target = real / "host" / "ash.yaml"
    target.parent.mkdir()
    target.write_text("x: 1\n", encoding="utf-8")
    # The deletion comes before the link is made: a platform that cannot make
    # one skips, whatever the working directory.
    _delete_cwd(real, monkeypatch)
    _symlink(real / "tree" / ".ash.yaml", target)

    found = link_locations(real / "tree" / ".ash.yaml")

    assert found == [real / "tree" / ".ash.yaml"]


def test_a_dotdot_after_a_link_is_walked_with_the_working_directory_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The walk is the same walk: a ``..`` after a link applies to the link's
    target, and a link reached through a link is found, with no working
    directory to start from."""
    real = Path(os.path.realpath(tmp_path))
    (real / "a" / "b").mkdir(parents=True)
    (real / "a" / "f.yaml").write_text("x: 1\n", encoding="utf-8")
    _delete_cwd(real, monkeypatch)
    _symlink(real / "tree" / "lnk", "../a/b")

    found = link_locations(str(real / "tree" / "lnk" / ".." / "f.yaml"))

    assert found == [real / "tree" / "lnk"]


def test_control_the_same_path_gives_the_same_answer_with_a_live_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = Path(os.path.realpath(tmp_path))
    target = real / "host" / "ash.yaml"
    target.parent.mkdir()
    target.write_text("x: 1\n", encoding="utf-8")
    _symlink(real / "tree" / ".ash.yaml", target)
    monkeypatch.chdir(real)

    found = link_locations(real / "tree" / ".ash.yaml")

    assert found == [real / "tree" / ".ash.yaml"]


def test_control_a_relative_path_is_taken_from_a_live_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = Path(os.path.realpath(tmp_path))
    (real / "a").mkdir()
    _symlink(real / "tree" / "lnk", real / "a")
    monkeypatch.chdir(real)

    found = link_locations("tree/lnk/f.yaml")

    assert found == [real / "tree" / "lnk"]


def test_a_relative_path_with_the_working_directory_deleted_still_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not an empty list: with nowhere to start from, "no links" would be a
    claim the walk never made."""
    _delete_cwd(Path(os.path.realpath(tmp_path)), monkeypatch)

    with pytest.raises(FileNotFoundError):
        link_locations("tree/.ash.yaml")
