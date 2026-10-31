# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``..`` in a name is applied the way the platform that opens the name applies it.

POSIX follows a link and then steps up from where it leads, so ``link/..`` is the
parent of the link's target. Windows removes each ``..`` before it looks at any
link (``_applies_parent_steps_lexically``), so there ``link/..`` is the directory
the link sits in. ``_walk_links`` already folded the name lexically on Windows;
``as_named``, ``_as_named`` and the targets of the links the walk follows applied
the POSIX order on every platform, and judged a location the platform never opens.

The Windows rule is switched on with a stand-in for the platform check, so these
tests run on any platform with symlinks. ``scanned_trees`` names the scan root with
``as_named`` like every other scan-root name, so a root spelled ``link/..`` is the
checkout the kernel steps into, not the directory textually above ``link``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.config import sandbox_grants
from automated_security_helper.config.sandbox_grants import (
    as_named,
    in_any_checkout,
    scanned_trees,
)
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

_POSIX_ORDER_NEEDED = pytest.mark.skipif(
    os.name == "nt", reason="Windows applies every .. before it follows a link"
)


def _symlink_or_skip(link: Path, target) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlinks are not available here: {error}")


@pytest.fixture
def _outside_every_checkout(tmp_path):
    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )


@pytest.fixture
def lexical_platform(monkeypatch):
    monkeypatch.setattr(sandbox_grants, "_applies_parent_steps_lexically", lambda: True)


@pytest.fixture
def link_into_deep_directory(tmp_path):
    """``x/link`` names ``real/deep``; a ``..`` after it means two different
    directories: ``x`` textually, ``real`` once the link is followed."""
    (tmp_path / "x").mkdir()
    (tmp_path / "real" / "deep").mkdir(parents=True)
    _symlink_or_skip(tmp_path / "x" / "link", tmp_path / "real" / "deep")
    return tmp_path


_NAMERS = pytest.mark.parametrize(
    "namer",
    [as_named, sandbox_grants._as_named],
    ids=["as_named", "_as_named"],
)


@_NAMERS
def test_a_platform_that_folds_dotdot_first_names_the_directory_above_the_link(
    namer, link_into_deep_directory, lexical_platform
):
    root = link_into_deep_directory
    name = root / "x" / "link" / ".." / "cfg.yaml"

    assert namer(name) == root / "x" / "cfg.yaml"


@_NAMERS
@_POSIX_ORDER_NEEDED
def test_a_platform_that_follows_the_link_first_names_the_parent_of_its_target(
    namer, link_into_deep_directory
):
    root = link_into_deep_directory
    name = root / "x" / "link" / ".." / "cfg.yaml"

    assert namer(name) == root / "real" / "cfg.yaml"


def test_a_links_own_dotdot_is_folded_before_the_links_in_it_are_read(
    tmp_path, lexical_platform
):
    """``lnk`` names ``jump/../x.yaml``. Folded first, the target is ``x.yaml``
    beside ``lnk`` and ``jump`` is never looked at, so only ``lnk`` is a link the
    walk follows."""
    (tmp_path / "other" / "deep").mkdir(parents=True)
    _symlink_or_skip(tmp_path / "jump", Path("other") / "deep")
    _symlink_or_skip(tmp_path / "lnk", Path("jump") / ".." / "x.yaml")

    links, decided = sandbox_grants._walk_links(tmp_path / "lnk")

    assert decided is True
    assert links == [tmp_path / "lnk"]


@_POSIX_ORDER_NEEDED
def test_a_links_own_dotdot_follows_the_link_in_it_on_a_posix_platform(tmp_path):
    (tmp_path / "other" / "deep").mkdir(parents=True)
    _symlink_or_skip(tmp_path / "jump", Path("other") / "deep")
    _symlink_or_skip(tmp_path / "lnk", Path("jump") / ".." / "x.yaml")

    links, decided = sandbox_grants._walk_links(tmp_path / "lnk")

    assert decided is True
    assert links == [tmp_path / "lnk", tmp_path / "jump"]


@_POSIX_ORDER_NEEDED
def test_a_scan_root_spelled_through_a_link_names_the_checkout_the_kernel_steps_into(
    tmp_path, monkeypatch, _outside_every_checkout
):
    """``x/link`` leads into ``repo/sub``, so ``x/link/..`` opens ``repo``. The
    textual fold, ``x``, is a directory the scan never names and must not become
    a scanned tree."""
    monkeypatch.delenv("PWD", raising=False)
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    (repo / "sub").mkdir()
    (tmp_path / "x").mkdir()
    _symlink_or_skip(tmp_path / "x" / "link", repo / "sub")

    trees = scanned_trees(tmp_path / "x" / "link" / "..")

    assert trees == [repo]
