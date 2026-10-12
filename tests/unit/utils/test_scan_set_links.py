# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A file link whose target leaves the scanned tree is not in the scan set.

``os.walk`` lists a link to a file among the files, and every scanner that reads
the scan set opens it by name, which reads the file it points at. A link committed
to the repository points wherever its author chose. So the scan-set walk, and the
filter that turns walked files into the scan set, keep a link only when its target,
every link resolved, is inside the scan root. Each one left out is listed with the
reason ``link leaves the scanned tree``.

Kept as before: a regular file, a link to a file inside the tree (whatever path
the link takes to get there), and a scan root that is itself reached through a
link, since the root is the operator's choice. A link to a directory is still not
descended. The fixtures hold a ``.py``, a ``.tf`` and a ``package.json``, each
linked from the tree to a file outside it.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils.get_scan_set import (
    get_ash_ignorespec_with_attribution,
    get_files_not_matching_spec,
    scan_set,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)

#: In every file outside the tree, so a test can tell whether any of it was read.
OUTSIDE_MARKER = "OUTSIDE-ONLY-CONTENT-5b2e"

LEAVES = "link leaves the scanned tree"


def _tree(tmp_path: Path) -> SimpleNamespace:
    """A tree with links out and links in, and a directory outside it.

    The outside directory sits beside the tree, so a relative link reaches it with
    ``../``. Paths in ``out`` and ``kept`` are relative to the tree.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text(f"KEY = '{OUTSIDE_MARKER}'\n", encoding="utf-8")
    (outside / "main.tf").write_text(
        f'resource "aws_s3_bucket" "b" {{ bucket = "{OUTSIDE_MARKER}" }}\n',
        encoding="utf-8",
    )
    (outside / "package.json").write_text(
        json.dumps({"name": "outside", "description": OUTSIDE_MARKER}),
        encoding="utf-8",
    )

    tree = tmp_path / "tree"
    (tree / "real").mkdir(parents=True)
    (tree / "app.py").write_text("print('app')\n", encoding="utf-8")
    (tree / "real" / "inside.py").write_text("print('inside')\n", encoding="utf-8")
    (tree / "infra.tf").write_text('variable "v" {}\n', encoding="utf-8")
    (tree / "app_pkg").mkdir()
    (tree / "app_pkg" / "package.json").write_text('{"name": "app"}', encoding="utf-8")

    # Links that leave the tree: absolute, relative, a chain through an in-tree
    # link, and one through an in-tree link to a directory outside.
    (tree / "link_out.py").symlink_to(outside / "secret.py")
    (tree / "link_out.tf").symlink_to(outside / "main.tf")
    (tree / "pkg_out").mkdir()
    (tree / "pkg_out" / "package.json").symlink_to(outside / "package.json")
    (tree / "rel_out.py").symlink_to(Path("..") / "outside" / "secret.py")
    (tree / "chain.py").symlink_to("link_out.py")
    (tree / "dir_out").symlink_to(outside, target_is_directory=True)
    (tree / "via_dir.py").symlink_to(Path("dir_out") / "secret.py")

    # Links that stay inside: to a file, and relative from a subdirectory.
    (tree / "link_in.py").symlink_to(tree / "real" / "inside.py")
    (tree / "real" / "up.py").symlink_to(Path("..") / "app.py")

    return SimpleNamespace(
        tree=tree,
        outside=outside,
        out=sorted(
            [
                "chain.py",
                "link_out.py",
                "link_out.tf",
                "pkg_out/package.json",
                "rel_out.py",
                "via_dir.py",
            ]
        ),
        kept=sorted(
            [
                "app.py",
                "app_pkg/package.json",
                "infra.tf",
                "link_in.py",
                "real/inside.py",
                "real/up.py",
            ]
        ),
    )


def _relative(paths, root: Path) -> list[str]:
    return sorted(Path(os.path.relpath(p, root)).as_posix() for p in paths)


@pytest.fixture
def fixture_tree(tmp_path):
    return _tree(tmp_path)


class TestTheScanSet:
    def test_holds_no_link_that_leaves_the_tree(self, fixture_tree, tmp_path):
        files = scan_set(source=str(fixture_tree.tree), output=str(tmp_path / "out"))

        assert _relative(files, fixture_tree.tree) == fixture_tree.kept

    def test_keeps_in_tree_links_when_the_root_is_reached_through_a_link(
        self, fixture_tree, tmp_path
    ):
        """The root is the operator's: a link to it does not make the tree outside."""
        root_link = tmp_path / "root-link"
        root_link.symlink_to(fixture_tree.tree, target_is_directory=True)

        files = scan_set(source=str(root_link), output=str(tmp_path / "out"))

        assert _relative(files, root_link) == fixture_tree.kept

    def test_lists_each_link_left_out_with_the_reason(self, fixture_tree, tmp_path):
        not_scanned: list[dict[str, str]] = []

        scan_set(
            source=str(fixture_tree.tree),
            output=str(tmp_path / "out"),
            links_not_scanned=not_scanned,
        )

        assert not_scanned == [{"path": p, "reason": LEAVES} for p in fixture_tree.out]

    def test_warns_once_per_link_naming_it_and_not_its_target(
        self, fixture_tree, tmp_path, caplog
    ):
        with caplog.at_level(logging.WARNING):
            scan_set(source=str(fixture_tree.tree), output=str(tmp_path / "out"))

        warned = [r.getMessage() for r in caplog.records if LEAVES in r.getMessage()]
        assert sorted(warned) == [
            f"Not scanning {p!r}: {LEAVES}" for p in fixture_tree.out
        ]
        # Where a link points is the repository's to choose and outside the tree;
        # the warning names only the link.
        assert not any(str(fixture_tree.outside) in w for w in warned)

    def test_the_written_list_matches_and_reuse_keeps_it(self, fixture_tree, tmp_path):
        out = tmp_path / "out"
        first = scan_set(source=str(fixture_tree.tree), output=str(out))
        written = (out / "ash-scan-set-files-list.txt").read_text(encoding="utf-8")

        again = scan_set(source=str(fixture_tree.tree), output=str(out))

        assert _relative(written.splitlines(), fixture_tree.tree) == fixture_tree.kept
        assert again == first

    def test_left_out_links_are_not_counted_as_removed_by_an_ignore_file(
        self, fixture_tree, tmp_path
    ):
        """No ignore file is involved, so the ignore-file count stays 0.

        Holds before and after the change; it fails if the walk keeps the links and
        only the filter drops them, which would count each one as removed by an
        ignore file.
        """
        exclusions: dict = {}

        scan_set(
            source=str(fixture_tree.tree),
            output=str(tmp_path / "out"),
            exclusions=exclusions,
        )

        assert exclusions["excluded_file_count"] == 0


class TestTheFilter:
    def test_its_own_walk_drops_links_that_leave_the_tree(self, fixture_tree):
        spec, _ = get_ash_ignorespec_with_attribution([], str(fixture_tree.tree))

        files = get_files_not_matching_spec(str(fixture_tree.tree), spec)

        assert _relative(files, fixture_tree.tree) == fixture_tree.kept

    def test_a_given_file_list_is_filtered_too(self, fixture_tree):
        """A caller's own list goes through the same check as the walk's."""
        spec, _ = get_ash_ignorespec_with_attribution([], str(fixture_tree.tree))
        given = [
            str(fixture_tree.tree / p) for p in fixture_tree.kept + fixture_tree.out
        ]

        files = get_files_not_matching_spec(
            str(fixture_tree.tree), spec, _all_files=given
        )

        assert _relative(files, fixture_tree.tree) == fixture_tree.kept
