# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sweep passes over the directories a plan names, and nothing else.

A backend gives a tool that must write a cache a private directory under the
results directory (backends._private_caches) and removes it whole in its own
cleanup step. uv fills its cache with links, so a sweep that walked that directory
counted ASH's own links as entries the scanner had left. The sweep runs first, as
the stream-log write needs, and is told the plan's private directories: each is
passed over by the name the backend made it under, a link a scanner planted at that
name is removed like any other, and a sibling or a path outside the root names
nothing. The os.walk fallback makes the same decisions.
"""

import os
import sys

import pytest

from automated_security_helper.utils.sandbox import fs_guard

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks"),
]


def _tree(tmp_path):
    """A results directory with a link the scanner left and a private cache
    whose entry is a link uv made."""
    root = tmp_path / "results"
    private = root / ".sandbox-cache-abc"
    (private / "uv_cache_dir").mkdir(parents=True)
    (private / "uv_cache_dir" / "entry").symlink_to(tmp_path)
    (root / "escape").symlink_to(tmp_path)
    return root, private


def test_a_named_directory_is_passed_over_and_the_rest_is_swept(tmp_path):
    root, private = _tree(tmp_path)

    removed = fs_guard.sweep_writable([root], skip=[private])

    assert removed == 1
    assert not os.path.lexists(root / "escape")
    assert os.path.lexists(private / "uv_cache_dir" / "entry"), (
        "the backend's own cleanup removes the private cache, not the sweep"
    )


def test_without_a_skip_the_same_tree_counts_both_links(tmp_path):
    """The control for the case above: the skip is what keeps the count at one."""
    root, private = _tree(tmp_path)

    assert fs_guard.sweep_writable([root]) == 2
    assert not os.path.lexists(private / "uv_cache_dir" / "entry")


def test_a_link_planted_at_the_named_directorys_name_is_removed(tmp_path):
    """The match is by name and never follows a link: a scanner that replaced
    the private directory with a link gets it removed and counted."""
    root = tmp_path / "results"
    root.mkdir()
    planted = root / ".sandbox-cache-abc"
    planted.symlink_to(tmp_path)

    assert fs_guard.sweep_writable([root], skip=[planted]) == 1
    assert not os.path.lexists(planted)


def test_a_sibling_the_root_and_a_path_outside_name_nothing(tmp_path):
    root, private = _tree(tmp_path)
    sibling = root / ".sandbox-cache-other"
    outside = tmp_path / ".sandbox-cache-abc"

    removed = fs_guard.sweep_writable([root], skip=[sibling, outside, root])

    assert removed == 2, "nothing in the tree was named, so nothing is passed over"
    assert not os.path.lexists(private / "uv_cache_dir" / "entry")


def test_a_nested_named_directory_is_passed_over(tmp_path):
    root = tmp_path / "results"
    deep = root / "a" / "b"
    deep.mkdir(parents=True)
    (deep / "kept").symlink_to(tmp_path)
    (root / "a" / "swept").symlink_to(tmp_path)

    assert fs_guard.sweep_writable([root], skip=[deep]) == 1
    assert os.path.lexists(deep / "kept")
    assert not os.path.lexists(root / "a" / "swept")


@pytest.mark.skipif(not hasattr(os, "fwalk"), reason="the os.walk branch is taken")
def test_the_os_walk_fallback_passes_over_the_same_directory(tmp_path, monkeypatch):
    monkeypatch.delattr(os, "fwalk")
    root, private = _tree(tmp_path)

    removed = fs_guard.sweep_writable([root], skip=[private])

    assert removed == 1
    assert not os.path.lexists(root / "escape")
    assert os.path.lexists(private / "uv_cache_dir" / "entry")


def test_the_relative_form_matches_the_walks(tmp_path):
    root = tmp_path / "results"
    skips = fs_guard._relative_skips(
        root,
        [root / "a" / "b", root / "top", root, tmp_path / "beside", root / "x" / ".."],
    )

    assert skips == frozenset({"a/b", "top"})
