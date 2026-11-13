# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The guards' walk of the package refuses a tree it did not read whole."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from tests.unit.walked_package import PACKAGE, package_sources

pytestmark = pytest.mark.unit

#: The package's modules, by their path in it, as the walk finds them now.
_MODULES = sorted(
    source.relative_to(PACKAGE).as_posix() for source in package_sources()
)


def _copy_of_the_package(root: Path) -> Path:
    """An empty module at each of the package's module paths."""
    for module in _MODULES:
        (root / module).parent.mkdir(parents=True, exist_ok=True)
        (root / module).write_text("", encoding="utf-8")
    return root


def _link(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as error:  # Windows without the symlink privilege
        pytest.skip(f"cannot make a link here: {error}")


def _parts():
    return sorted({str(Path(module).parent) for module in _MODULES} - {"."})


def test_a_copy_of_the_package_is_walked_whole(tmp_path):
    walked = package_sources(_copy_of_the_package(tmp_path / "pkg"))

    assert [s.relative_to(tmp_path / "pkg").as_posix() for s in walked] == _MODULES


@pytest.mark.parametrize("part", _parts())
def test_a_tree_without_one_part_is_refused(tmp_path, part):
    """ash_aws_plugins moved out left 222 modules, above the floor of 200, and
    the reporters moved out left 212."""
    package = _copy_of_the_package(tmp_path / "pkg")
    shutil.rmtree(package / part)

    with pytest.raises(AssertionError):
        package_sources(package)


def test_a_part_the_walk_cannot_read_is_refused(tmp_path):
    """A walk that cannot list a directory skipped it without a word."""
    package = _copy_of_the_package(tmp_path / "pkg")
    unreadable = package / "utils" / "sandbox"
    unreadable.chmod(0)
    try:
        if os.access(unreadable, os.R_OK):
            pytest.skip("this user can read a directory with no permissions")
        with pytest.raises((AssertionError, OSError)):
            package_sources(package)
    finally:
        unreadable.chmod(0o755)


def test_a_part_reached_through_a_link_is_refused(tmp_path):
    """A walk does not follow a linked directory, so its modules went unread."""
    package = _copy_of_the_package(tmp_path / "pkg")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    shutil.move(package / "utils" / "sandbox", elsewhere / "sandbox")
    _link(package / "utils" / "sandbox", elsewhere / "sandbox", directory=True)

    with pytest.raises(AssertionError, match="linked"):
        package_sources(package)


def test_a_module_reached_through_a_link_is_refused(tmp_path):
    package = _copy_of_the_package(tmp_path / "pkg")
    (tmp_path / "outside.py").write_text("", encoding="utf-8")
    _link(package / "utils" / "linked.py", tmp_path / "outside.py")

    with pytest.raises(AssertionError, match="linked"):
        package_sources(package)


def test_a_new_part_must_be_named_before_it_is_walked(tmp_path):
    """A part the list does not name is a failure too: a guard's reader would not
    know whether its walk covers it."""
    package = _copy_of_the_package(tmp_path / "pkg")
    (package / "utils" / "new_part").mkdir()
    (package / "utils" / "new_part" / "__init__.py").write_text("", encoding="utf-8")

    with pytest.raises(AssertionError, match="not named"):
        package_sources(package)
