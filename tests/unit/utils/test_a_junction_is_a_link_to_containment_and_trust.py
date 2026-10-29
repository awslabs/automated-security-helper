# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A Windows junction counts as a link where a symbolic link does.

Why this exists
---------------
``Path.is_symlink()`` and ``os.path.islink()`` say a Windows junction is no
link, so two checks read the reparse point instead:

- ``path_containment.validate_contained_path`` refuses a project directory that
  is a junction as it refuses a symlink, wherever it leads;
- ``sandbox_grants.links_followed``, which lists the links a config path's
  resolution follows for the trust decision, counts a junction's directory and
  steps ``<junction>/..`` up from where it leads, not from the junction's name.

Both ask ``config_sources._is_a_link``: a symlink, or on Windows any reparse
point. A junction cannot be made here, so each cell takes a path that leads where
a junction would (a real directory, or a symbolic link) and reports it as Windows
reports a junction: ``os.lstat`` gives a directory with the reparse-point
attribute and the mount-point tag, and ``os.path.islink`` says it is no link.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.unit

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


def _as_a_junction(monkeypatch: pytest.MonkeyPatch, junction: Path) -> None:
    real_lstat = os.lstat
    real_islink = os.path.islink
    shown = str(junction)

    def lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if os.fspath(path) == shown and not args and not kwargs:
            return _JunctionStat(os.stat(shown))
        return real_lstat(path, *args, **kwargs)

    def islink(path: Any) -> bool:
        return False if os.fspath(path) == shown else real_islink(path)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os.path, "islink", islink)


def test_control_the_stand_in_is_no_link_to_the_old_checks(tmp_path, monkeypatch):
    junction = tmp_path / "proj"
    junction.mkdir()
    _as_a_junction(monkeypatch, junction)

    assert not junction.is_symlink()
    assert not os.path.islink(junction)
    assert not stat.S_ISLNK(os.lstat(junction).st_mode)


def test_a_project_directory_that_is_a_junction_is_refused(tmp_path, monkeypatch):
    from automated_security_helper.utils.path_containment import (
        PathContainmentViolation,
        validate_contained_path,
    )

    root = tmp_path / "root"
    (root / "proj").mkdir(parents=True)
    _as_a_junction(monkeypatch, (root / "proj").resolve())

    result = validate_contained_path("proj", root)

    assert result.error is not None, "a junction passed as a project directory"
    assert result.error.violation is PathContainmentViolation.SYMLINK


def test_control_a_plain_project_directory_is_accepted(tmp_path):
    from automated_security_helper.utils.path_containment import (
        validate_contained_path,
    )

    root = tmp_path / "root"
    (root / "proj").mkdir(parents=True)

    assert validate_contained_path("proj", root).error is None


def test_a_junction_a_config_path_passes_through_is_followed(tmp_path, monkeypatch):
    from automated_security_helper.config.sandbox_grants import links_followed

    real = tmp_path / "elsewhere" / "ops"
    real.mkdir(parents=True)
    (real / "cfg.yaml").write_text("project_name: x\n", encoding="utf-8")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    # Leads where a junction would; reported below as Windows reports one.
    junction = checkout / "ops"
    junction.symlink_to(real, target_is_directory=True)
    _as_a_junction(monkeypatch, junction)

    followed = links_followed(junction / "cfg.yaml")

    assert junction in followed, followed


# A reparse point is a link only when it names another path: its tag has the
# name-surrogate bit, as a symlink's and a junction's do. A OneDrive placeholder
# (a cloud tag) is the file or directory it appears to be, and Windows opens it
# so. And Windows applies ".." lexically, before any link in front of it.

#: IO_REPARSE_TAG_CLOUD_6, a OneDrive placeholder: no name-surrogate bit.
CLOUD_TAG = 0x9000601A


def _as_a_placeholder(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    real_lstat = os.lstat
    shown = str(path)

    def lstat(candidate: Any, *args: Any, **kwargs: Any) -> Any:
        if os.fspath(candidate) == shown and not args and not kwargs:
            placeholder = _JunctionStat(os.stat(shown))
            placeholder.st_reparse_tag = CLOUD_TAG
            return placeholder
        return real_lstat(candidate, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)


def test_a_placeholder_directory_is_no_link_to_trust(tmp_path, monkeypatch):
    from automated_security_helper.config.sandbox_grants import links_followed

    placeholder = tmp_path / "od"
    placeholder.mkdir()
    (tmp_path / "target.yaml").write_text("project_name: x\n", encoding="utf-8")
    link = placeholder / "cfg.yaml"
    link.symlink_to(tmp_path / "target.yaml")
    _as_a_placeholder(monkeypatch, placeholder)

    followed = links_followed(link)

    assert placeholder not in followed, followed
    assert link in followed, followed


def test_on_windows_a_parent_step_is_lexical(tmp_path, monkeypatch):
    from automated_security_helper.config import sandbox_grants

    ops = tmp_path / "ops"
    junction = ops / "j"
    (tmp_path / "elsewhere").mkdir()
    junction.mkdir(parents=True)
    (ops / "repo").mkdir()
    (tmp_path / "x.yaml").write_text("project_name: x\n", encoding="utf-8")
    link = ops / "repo" / "lnk.yaml"
    link.symlink_to(tmp_path / "x.yaml")
    _as_a_junction(monkeypatch, junction)
    monkeypatch.setattr(sandbox_grants, "_applies_parent_steps_lexically", lambda: True)

    followed = sandbox_grants.links_followed(junction / ".." / "repo" / "lnk.yaml")

    # Windows opens ops/repo/lnk.yaml: the ".." is gone before j is looked at.
    assert link in followed, followed
    assert junction not in followed, followed


def test_a_reparse_point_readlink_cannot_read_ends_the_walk_at_it(
    tmp_path, monkeypatch
):
    """Windows' readlink raises ValueError for a name-surrogate reparse point it
    cannot read as a link. The walk records the point and stops there, as it does
    for an OSError, and raises nothing."""
    from automated_security_helper.config import sandbox_grants

    point = tmp_path / "ops"
    point.mkdir()
    _as_a_junction(monkeypatch, point)
    real_readlink = os.readlink
    shown = str(point)

    def readlink(path: Any, *args: Any, **kwargs: Any) -> Any:
        if os.fspath(path) == shown:
            raise ValueError("not a symbolic link")
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "readlink", readlink)

    followed = sandbox_grants.links_followed(point / "cfg.yaml")

    assert followed, "the reparse point was not counted as a link"
    assert followed[-1] == point, followed


def test_a_placeholder_project_directory_is_accepted(tmp_path, monkeypatch):
    from automated_security_helper.utils.path_containment import (
        validate_contained_path,
    )

    root = tmp_path / "root"
    (root / "proj").mkdir(parents=True)
    _as_a_placeholder(monkeypatch, (root / "proj").resolve())

    assert validate_contained_path("proj", root).error is None
