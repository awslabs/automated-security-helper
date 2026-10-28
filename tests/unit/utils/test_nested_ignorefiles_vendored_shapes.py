# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Pins #501's anchoring for the two shapes a nested ignore file is most often written with.

A vendored directory commonly carries its own ignore file with one of two
contents: ``*`` (ignore everything beside me) or ``lib/`` (ignore my ``lib``
directory). Git anchors each rule to the directory its ignore file sits in, so
neither may reach outside that directory. A scan root that has an ``app.py`` and
a ``lib/keep.py`` of its own must keep both, whatever the vendored trees say.

These tests are green at main by construction: the cure for #501 ("fix(scan-set):
apply nested ignore files to the subtree they sit in", b9ee7a30ba3) is already on
main, and ``test_nested_ignorefiles.py`` covers the ``*.tmp`` shape. This module
adds the whole-directory shapes. Their red side is v3.4.0 behavior, which no CI
venue runs, so no venue shows them red.

The ignore files themselves are not asserted on: whether ``.gitignore`` appears in
the scan set is outside what these tests pin, as in ``test_nested_ignorefiles.py``.
"""

from pathlib import Path

import pytest

from automated_security_helper.utils.get_scan_set import scan_set


def _relative_posix_names(scan_root: Path, files: list[str]) -> set[str]:
    """Scan-set paths as ``/``-separated paths relative to *scan_root*."""
    return {Path(f).relative_to(scan_root).as_posix() for f in files}


def _scan(scan_root: Path) -> set[str]:
    """The scan set of *scan_root*, as relative POSIX names."""
    return _relative_posix_names(scan_root, scan_set(source=str(scan_root)))


def _build_vendored_tree(tmp_path: Path, root_ignore: str | None = None) -> Path:
    """A scan root with two vendored directories, each carrying its own ignore file.

    Structure::

        src/
        |-- app.py
        |-- lib/
        |   `-- keep.py          the scan root's own lib, not vendor/b's
        `-- vendor/
            |-- a/
            |   |-- .gitignore   (*)
            |   `-- dropped.py   excluded by vendor/a/.gitignore
            `-- b/
                |-- .gitignore   (lib/)
                |-- kept.py      beside the ignore file, not under lib/
                `-- lib/
                    `-- dropped.py   excluded by vendor/b/.gitignore

    *root_ignore*, when given, becomes the content of ``src/.gitignore``.
    """
    root = tmp_path / "src"
    root.mkdir()
    if root_ignore is not None:
        (root / ".gitignore").write_text(root_ignore)
    (root / "app.py").write_text("x = 1\n")

    lib = root / "lib"
    lib.mkdir()
    (lib / "keep.py").write_text("y = 2\n")

    vendor_a = root / "vendor" / "a"
    vendor_a.mkdir(parents=True)
    (vendor_a / ".gitignore").write_text("*\n")
    (vendor_a / "dropped.py").write_text("a = 1\n")

    vendor_b = root / "vendor" / "b"
    vendor_b.mkdir(parents=True)
    (vendor_b / ".gitignore").write_text("lib/\n")
    (vendor_b / "kept.py").write_text("b = 1\n")
    vendor_b_lib = vendor_b / "lib"
    vendor_b_lib.mkdir()
    (vendor_b_lib / "dropped.py").write_text("b = 2\n")

    return root


@pytest.fixture
def vendored_tree(tmp_path):
    """The tree with no root ignore file: only the two vendored ones apply."""
    return _build_vendored_tree(tmp_path)


@pytest.fixture
def vendored_tree_with_root_star(tmp_path):
    """The same tree with ``*`` in the ROOT ignore file (the must-flag control)."""
    return _build_vendored_tree(tmp_path, root_ignore="*\n")


class TestVendoredIgnoreFileShapes:
    """A nested ``*`` or ``lib/`` applies inside its own directory and nowhere else."""

    def test_nested_star_excludes_files_beside_it(self, vendored_tree):
        found = _scan(vendored_tree)

        assert "vendor/a/dropped.py" not in found, (
            f"'*' in vendor/a/.gitignore did not exclude vendor/a/dropped.py; "
            f"scan set: {sorted(found)}"
        )

    def test_nested_directory_rule_excludes_that_directory(self, vendored_tree):
        found = _scan(vendored_tree)

        assert "vendor/b/lib/dropped.py" not in found, (
            f"'lib/' in vendor/b/.gitignore did not exclude vendor/b/lib/dropped.py; "
            f"scan set: {sorted(found)}"
        )

    def test_nested_rules_do_not_reach_the_scan_roots_own_files(self, vendored_tree):
        """The over-broad failure: a nested rule widened to the whole tree.

        In a security scanner that silently drops the project's own code from
        the scan set, so it is asserted apart from the exclusions above.
        """
        found = _scan(vendored_tree)

        assert {"app.py", "lib/keep.py"} <= found, (
            f"a nested ignore file ('*' in vendor/a or 'lib/' in vendor/b) leaked "
            f"out of its directory; scan set: {sorted(found)}"
        )

    def test_nested_directory_rule_keeps_files_beside_the_ignore_file(
        self, vendored_tree
    ):
        found = _scan(vendored_tree)

        assert "vendor/b/kept.py" in found, (
            f"'lib/' in vendor/b/.gitignore excluded vendor/b/kept.py, which is not "
            f"under lib/; scan set: {sorted(found)}"
        )

    def test_same_star_in_the_root_ignore_file_excludes_the_root_files(
        self, vendored_tree_with_root_star
    ):
        """Must-flag control: the same ``*`` at the root does exclude ``app.py``.

        A rule anchors to the directory of the ignore file that holds it, so at
        the root it covers the whole tree. If this stopped excluding ``app.py``,
        the nested assertions above could be passing for the wrong reason.
        """
        found = _scan(vendored_tree_with_root_star)

        assert "app.py" not in found, (
            f"'*' in the root .gitignore did not exclude app.py; "
            f"scan set: {sorted(found)}"
        )
