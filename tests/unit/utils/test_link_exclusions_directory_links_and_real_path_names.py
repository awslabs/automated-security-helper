# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two exclusion values that would have hidden files the scan should read.

``syft_excludes`` wrote ``./<dir>/**`` for a directory whose every walked file is
ignored. The walk never enters a link to a directory, but syft follows one whose
target stays inside the tree, so the pattern also hid the files syft reaches
through such a link, ignored or not. A directory holding a link to scanned files
is now written as its ignored files, one by one. A link leading to a directory
whose files are all ignored (pnpm's ``node_modules/foo`` into
``node_modules/.pnpm``) is written as ``./<link>/**`` itself where no directory
holding it is: without it syft cataloged the ignored packages under the link's
name, in an SBOM nothing filters.

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
    _LINK_HOPS,
    _ignore_entries,
    grep_ignore_names,
    ignored_entries,
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

    assert inside_tree_directory_links(target) == {"dir/link": "other"}
    values = syft_excludes(target, target, _ignore("dir/a.txt"))

    assert values == ["./dir/a.txt"]


def test_control_without_the_link_the_directory_is_hidden_whole(tmp_path):
    tree, target = _tree(tmp_path)

    assert inside_tree_directory_links(target) == {}
    assert syft_excludes(target, target, _ignore("dir/a.txt")) == ["./dir/**"]


def test_control_a_directory_link_leaving_the_tree_changes_nothing(tmp_path):
    tree, target = _tree(tmp_path)
    (tree / "outside").mkdir()
    (target / "dir" / "away").symlink_to(tree / "outside")

    assert inside_tree_directory_links(target) == {}
    assert syft_excludes(target, target, _ignore("dir/a.txt")) == ["./dir/**"]


def _pnpm_tree(tmp_path):
    """pnpm's layout: ``node_modules/foo`` is a link into ``node_modules/.pnpm``,
    where the package's files really are; one scanned file beside them."""
    tree = Path(os.path.realpath(tmp_path))
    target = tree / "proj"
    store = target / "node_modules" / ".pnpm" / "foo@1.0.0" / "node_modules" / "foo"
    store.mkdir(parents=True)
    (store / "package.json").write_text("{}\n", encoding="utf-8")
    (target / "node_modules" / "foo").symlink_to(store, target_is_directory=True)
    (target / "app.py").write_text("x = 1\n", encoding="utf-8")
    return target


def test_a_link_into_an_ignored_directory_keeps_the_directory_hidden_whole(tmp_path):
    target = _pnpm_tree(tmp_path)

    assert inside_tree_directory_links(target) == {
        "node_modules/foo": "node_modules/.pnpm/foo@1.0.0/node_modules/foo"
    }
    assert syft_excludes(target, target, _ignore("node_modules/")) == [
        "./node_modules/**"
    ]


def test_a_link_to_an_ignored_directory_from_a_scanned_one_is_hidden_itself(tmp_path):
    tree = Path(os.path.realpath(tmp_path))
    target = tree / "proj"
    (target / "third_party" / "lib").mkdir(parents=True)
    (target / "third_party" / "lib" / "vendored.py").write_text("", encoding="utf-8")
    (target / "src").mkdir()
    (target / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (target / "src" / "vendored").symlink_to(
        target / "third_party" / "lib", target_is_directory=True
    )

    values = syft_excludes(target, target, _ignore("third_party/"))

    assert values == ["./src/vendored/**", "./third_party/**"]


def test_a_link_to_a_directory_the_walk_found_no_file_in_is_not_hidden(tmp_path):
    """``third_party/hub`` holds no file of its own, only a link on to scanned
    files; a link to it proves nothing ignored and must not be written as
    ``./src/vendored/**``, which would hide those files from syft."""
    tree = Path(os.path.realpath(tmp_path))
    target = tree / "proj"
    (target / "third_party" / "hub").mkdir(parents=True)
    (target / "third_party" / "vendor.py").write_text("", encoding="utf-8")
    (target / "other" / "lib").mkdir(parents=True)
    (target / "other" / "lib" / "x.py").write_text("x = 1\n", encoding="utf-8")
    (target / "third_party" / "hub" / "lib").symlink_to(
        target / "other" / "lib", target_is_directory=True
    )
    (target / "src").mkdir()
    (target / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (target / "src" / "vendored").symlink_to(
        target / "third_party" / "hub", target_is_directory=True
    )

    values = syft_excludes(target, target, _ignore("third_party/"))

    assert values == ["./third_party/vendor.py"]


def test_a_link_to_an_ignored_directory_holding_a_link_to_scanned_files_is_not_hidden(
    tmp_path,
):
    """``src/vendored`` leads to ``third_party/lib``, whose own files are all
    ignored, but that directory holds a further link to scanned files, which syft
    reaches through ``src/vendored`` too. Written as ``./src/vendored/**``, the
    exclusion hid those scanned files; the link's target must be a directory that
    is hidden whole in its own right before the link is. Not hiding the link whole
    does not leave its ignored file readable: syft reaches ``vendored.py`` as
    ``src/vendored/vendored.py`` too, so that name is excluded as well."""
    tree = Path(os.path.realpath(tmp_path))
    target = tree / "proj"
    (target / "third_party" / "lib").mkdir(parents=True)
    (target / "third_party" / "lib" / "vendored.py").write_text("", encoding="utf-8")
    (target / "other").mkdir()
    (target / "other" / "b.py").write_text("x = 1\n", encoding="utf-8")
    (target / "third_party" / "lib" / "inner").symlink_to(
        target / "other", target_is_directory=True
    )
    (target / "src").mkdir()
    (target / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (target / "src" / "vendored").symlink_to(
        target / "third_party" / "lib", target_is_directory=True
    )

    values = syft_excludes(target, target, _ignore("third_party/"))

    assert values == [
        "./src/vendored/vendored.py",
        "./third_party/lib/vendored.py",
    ]


def test_an_ignored_directory_behind_a_link_is_excluded_under_the_links_name(
    tmp_path,
):
    """A directory inside ``third_party/lib`` whose every file is ignored is hidden
    whole under its own name; ``src/vendored`` leads to ``lib``, which cannot be
    hidden whole (it holds a link to scanned files), so syft reads that directory
    as ``src/vendored/gen`` too and the whole directory is excluded there as well."""
    tree = Path(os.path.realpath(tmp_path))
    target = tree / "proj"
    (target / "third_party" / "lib" / "gen").mkdir(parents=True)
    (target / "third_party" / "lib" / "gen" / "a.py").write_text("", encoding="utf-8")
    (target / "third_party" / "lib" / "gen" / "b.py").write_text("", encoding="utf-8")
    (target / "other").mkdir()
    (target / "other" / "c.py").write_text("x = 1\n", encoding="utf-8")
    (target / "third_party" / "lib" / "inner").symlink_to(
        target / "other", target_is_directory=True
    )
    (target / "src").mkdir()
    (target / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (target / "src" / "vendored").symlink_to(
        target / "third_party" / "lib", target_is_directory=True
    )

    values = syft_excludes(target, target, _ignore("third_party/"))

    assert values == ["./src/vendored/gen/**", "./third_party/lib/gen/**"]


def test_a_link_that_leads_back_into_itself_is_followed_a_bounded_number_of_times():
    files = ["a/ignored.txt", "a/keep.txt"]

    # The default ``matches`` is ``ignore_path_matches``, which the tests above use
    # with an exact file pattern; the link leads to its own parent.
    entries = ignored_entries(
        Path("/does/not/matter"),
        Path("/does/not/matter"),
        _ignore("a/ignored.txt"),
        files,
        directory_links={"a/loop": "a"},
    )

    assert entries == ["a/ignored.txt"] + [
        "a/" + "loop/" * hops + "ignored.txt" for hops in range(1, _LINK_HOPS + 1)
    ]


def test_a_chain_of_links_to_scanned_files_is_followed_back_to_the_first_link(
    tmp_path,
):
    """Three hops: ``src/vendored`` leads to ``third_party/lib``, whose own files
    are all ignored but which holds ``bridge`` to ``third_party/hub``, whose own
    files are all ignored but which holds ``inner`` to scanned files. One pass
    judged ``bridge`` by ``hub``'s own counts (all ignored) and left ``lib`` whole,
    so ``./src/vendored/**`` hid the scanned files reached through all three."""
    tree = Path(os.path.realpath(tmp_path))
    target = tree / "proj"
    (target / "third_party" / "lib").mkdir(parents=True)
    (target / "third_party" / "lib" / "vendored.py").write_text("", encoding="utf-8")
    (target / "third_party" / "hub").mkdir()
    (target / "third_party" / "hub" / "vendor.py").write_text("", encoding="utf-8")
    (target / "other").mkdir()
    (target / "other" / "b.py").write_text("x = 1\n", encoding="utf-8")
    (target / "third_party" / "hub" / "inner").symlink_to(
        target / "other", target_is_directory=True
    )
    (target / "third_party" / "lib" / "bridge").symlink_to(
        target / "third_party" / "hub", target_is_directory=True
    )
    (target / "src").mkdir()
    (target / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (target / "src" / "vendored").symlink_to(
        target / "third_party" / "lib", target_is_directory=True
    )

    values = syft_excludes(target, target, _ignore("third_party/"))

    # The ignored files, each under every name the links give it: ``bridge``
    # leads to ``hub`` from inside ``lib``, and ``src/vendored`` leads to ``lib``,
    # so ``hub/vendor.py`` is also read as ``lib/bridge/vendor.py`` and as
    # ``src/vendored/bridge/vendor.py``.
    assert values == [
        "./src/vendored/bridge/vendor.py",
        "./src/vendored/vendored.py",
        "./third_party/hub/vendor.py",
        "./third_party/lib/bridge/vendor.py",
        "./third_party/lib/vendored.py",
    ]


@pytest.mark.parametrize("function", [ignored_entries, _ignore_entries])
def test_the_directory_links_default_is_not_a_shared_mapping(function):
    """The default is ``None``, resolved inside the call, not a ``{}`` literal that
    every call would share (``test_mutable_defaults_fix`` reads the whole package
    for that shape)."""
    import inspect

    assert inspect.signature(function).parameters["directory_links"].default is None


def test_omitting_the_directory_links_reads_as_no_link(tmp_path):
    """A caller with no links to report (checkov, ferret-scan) gets the answer an
    empty mapping gives: the whole ignored directory, hidden whole."""
    tree, target = _tree(tmp_path)
    files = ["dir/a.txt", "other/b.txt"]

    omitted = ignored_entries(target, target, _ignore("dir/"), files)
    empty = ignored_entries(target, target, _ignore("dir/"), files, directory_links={})

    assert omitted == empty == ["dir/"]


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
