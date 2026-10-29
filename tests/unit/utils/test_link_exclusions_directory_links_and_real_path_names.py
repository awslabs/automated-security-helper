# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two exclusion values that would have hidden files the scan should read.

``syft_excludes`` wrote ``./<dir>/**`` for a directory whose every walked file is
ignored. The walk never enters a link to a directory, but syft follows one whose
target stays inside the tree, so the pattern also hid the files syft reaches
through such a link, ignored or not. A directory holding one is now written as
its ignored files, one by one.

``grep_ignore_names`` passed a bare ``--exclude`` name unless a component of the
target's spelled (absolute) path had it; semgrep matches the name at every depth
of the real path below the git work tree's root, so a name equal to a component
of the target's real path (reached through a link) excluded the whole target, and
the scan reported a clean ignore-paths-only result. Both spellings are guarded.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils.link_exclusions import (
    grep_ignore_names,
    inside_tree_directory_links,
    syft_excludes,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="these exclusion values are POSIX-only"
    ),
]


def _ignore(*paths: str):
    return [SimpleNamespace(path=path) for path in paths]


def _tree(tmp_path):
    tree = Path(os.path.realpath(tmp_path))
    target = tree / "proj"
    (target / "dir").mkdir(parents=True)
    (target / "dir" / "a.txt").write_text("ignored\n", encoding="utf-8")
    (target / "other").mkdir()
    (target / "other" / "b.txt").write_text("scanned\n", encoding="utf-8")
    return tree, target


def test_a_whole_ignored_directory_holding_an_inside_tree_link_is_not_hidden_whole(
    tmp_path,
):
    tree, target = _tree(tmp_path)
    (target / "dir" / "link").symlink_to(target / "other")

    assert inside_tree_directory_links(target) == ["dir/link"]
    values = syft_excludes(target, target, _ignore("dir/a.txt"))

    assert values == ["./dir/a.txt"]


def test_control_without_the_link_the_directory_is_hidden_whole(tmp_path):
    tree, target = _tree(tmp_path)

    assert inside_tree_directory_links(target) == []
    assert syft_excludes(target, target, _ignore("dir/a.txt")) == ["./dir/**"]


def test_control_a_directory_link_leaving_the_tree_changes_nothing(tmp_path):
    tree, target = _tree(tmp_path)
    (tree / "outside").mkdir()
    (target / "dir" / "away").symlink_to(tree / "outside")

    assert inside_tree_directory_links(target) == []
    assert syft_excludes(target, target, _ignore("dir/a.txt")) == ["./dir/**"]


def _aliased(tmp_path, ignored_name: str):
    """A target reached through ``alias``, really at ``real/proj``, holding one
    ignored file named *ignored_name* at its root and one scanned file."""
    tree = Path(os.path.realpath(tmp_path))
    real = tree / "real" / "proj"
    real.mkdir(parents=True)
    (real / ignored_name).write_text("ignored\n", encoding="utf-8")
    (real / "keep.txt").write_text("scanned\n", encoding="utf-8")
    alias = tree / "alias"
    alias.symlink_to(real)
    return alias


def test_a_name_that_is_a_component_of_the_targets_real_path_is_not_passed(tmp_path):
    alias = _aliased(tmp_path, "proj")

    assert grep_ignore_names(alias, alias, _ignore("proj")) == []


def test_control_a_name_that_is_a_component_of_the_spelled_path_is_not_passed(
    tmp_path,
):
    alias = _aliased(tmp_path, "alias")

    assert grep_ignore_names(alias, alias, _ignore("alias")) == []


def test_control_a_name_free_of_both_spellings_is_passed(tmp_path):
    alias = _aliased(tmp_path, "secret.env")

    assert grep_ignore_names(alias, alias, _ignore("secret.env")) == ["secret.env"]
