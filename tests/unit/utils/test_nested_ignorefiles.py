# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests that a nested ignore file excludes files inside its own subtree.

A user who drops a ``sub/.gitignore`` into a project expects the matching files
under ``sub/`` to stop being scanned. They did not: ``get_ash_ignorespec``
received only the collected marker lines, so it had no access to the real scan
root and rebuilt each rule's base from a synthetic ``"/"`` prefix. A rule from
``sub/.gitignore`` therefore compiled against ``/sub`` while the files it was
matched against live under the scan root, and it matched nothing. Rules from the
*root* ignore file worked by accident: the base ``"/"`` compiles to
``//**/<pattern>``, whose leading ``**`` swallows any prefix.

The nested-rule assertions here fail against that synthetic base and pass once
the base is derived from the scan root, which is why they are behavior tests
through ``scan_set`` rather than assertions about compiled rule strings.
"""

from pathlib import Path

import pytest

from automated_security_helper.utils.get_scan_set import (
    get_ash_ignorespec,
    scan_set,
)


def _relative_posix_names(scan_root: Path, files: list[str]) -> set[str]:
    """Scan-set paths as ``/``-separated paths relative to *scan_root*.

    Keeps the assertions readable and identical on every platform without
    building any path literal by hand.
    """
    return {Path(f).relative_to(scan_root).as_posix() for f in files}


@pytest.fixture
def nested_ignore_tree(tmp_path):
    """A scan root carrying both a root and a nested ignore file.

    Structure::

        src/
        |-- .gitignore      (*.log)
        |-- keep.py
        |-- drop.log        excluded by the root ignore file
        |-- keep.tmp        NOT excluded: the *.tmp rule belongs to sub/
        `-- sub/
            |-- .gitignore  (*.tmp)
            |-- keep_sub.py
            `-- drop.tmp    excluded by the nested ignore file
    """
    root = tmp_path / "src"
    root.mkdir()
    (root / ".gitignore").write_text("*.log\n")
    (root / "keep.py").write_text("x = 1\n")
    (root / "drop.log").write_text("log output\n")
    (root / "keep.tmp").write_text("scratch\n")

    sub = root / "sub"
    sub.mkdir()
    (sub / ".gitignore").write_text("*.tmp\n")
    (sub / "keep_sub.py").write_text("y = 2\n")
    (sub / "drop.tmp").write_text("scratch\n")

    return root


class TestNestedIgnoreFileScoping:
    """scan_set must honor a nested ignore file, and only within its subtree."""

    def test_root_ignore_file_excludes_matching_file(self, nested_ignore_tree):
        """Baseline behavior, correct before the fix -- kept as a control."""
        found = _relative_posix_names(
            nested_ignore_tree, scan_set(source=str(nested_ignore_tree))
        )

        assert "drop.log" not in found, (
            f"root .gitignore rule '*.log' did not exclude drop.log; scan set: {sorted(found)}"
        )

    def test_nested_ignore_file_excludes_matching_file_in_its_subtree(
        self, nested_ignore_tree
    ):
        """The defect: sub/.gitignore was collected, compiled, and matched nothing."""
        found = _relative_posix_names(
            nested_ignore_tree, scan_set(source=str(nested_ignore_tree))
        )

        assert "sub/drop.tmp" not in found, (
            f"sub/.gitignore rule '*.tmp' did not exclude sub/drop.tmp; scan set: {sorted(found)}"
        )

    def test_nested_rule_does_not_leak_outside_its_directory(self, nested_ignore_tree):
        """Scoping the nested rule to the scan root would also 'fix' the test above.

        It would be the wrong fix: a rule from ``sub/.gitignore`` must not reach
        ``keep.tmp`` at the root. In a security scanner an over-broad ignore rule
        silently drops files from the scan set, so this is asserted separately
        from the exclusion itself.
        """
        found = _relative_posix_names(
            nested_ignore_tree, scan_set(source=str(nested_ignore_tree))
        )

        assert "keep.tmp" in found, (
            f"sub/.gitignore rule '*.tmp' leaked out of sub/ and excluded keep.tmp; "
            f"scan set: {sorted(found)}"
        )

    def test_unmatched_files_are_still_scanned(self, nested_ignore_tree):
        """Neither ignore file touches these, at either level."""
        found = _relative_posix_names(
            nested_ignore_tree, scan_set(source=str(nested_ignore_tree))
        )

        assert {"keep.py", "sub/keep_sub.py"} <= found, (
            f"expected keep.py and sub/keep_sub.py in the scan set, got: {sorted(found)}"
        )


@pytest.fixture
def layered_ignore_tree(tmp_path):
    """Two ignore files at different depths, the deeper one re-including a file.

    Structure::

        src/
        |-- app.py
        `-- sub/
            |-- .gitignore      (*.tmp)
            |-- a.tmp           excluded by sub/.gitignore
            `-- deep/
                |-- .gitignore  (!keep.tmp)
                |-- keep.tmp    re-included by the deeper ignore file
                `-- other.tmp   still excluded by sub/.gitignore
    """
    root = tmp_path / "src"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n")

    sub = root / "sub"
    sub.mkdir()
    (sub / ".gitignore").write_text("*.tmp\n")
    (sub / "a.tmp").write_text("scratch\n")

    deep = sub / "deep"
    deep.mkdir()
    (deep / ".gitignore").write_text("!keep.tmp\n")
    (deep / "keep.tmp").write_text("wanted\n")
    (deep / "other.tmp").write_text("scratch\n")

    return root


class TestIgnoreFilePrecedenceByDepth:
    """The ignore file closest to a file decides its fate, as git resolves it.

    Rules reach the parser in the order their ignore files are read and the last
    matching rule wins, so read order *is* precedence. That order used to come
    from iterating a set of path strings, and string hashing is randomized per
    process: the same tree scanned twice could put ``sub/deep/.gitignore`` before
    or after ``sub/.gitignore``, so a re-include in the deeper file won on some
    runs and was silently dropped from the scan set on others. Only observable
    once a nested ignore file applied at all.
    """

    def test_deeper_reinclude_overrides_a_shallower_exclude(self, layered_ignore_tree):
        found = _relative_posix_names(
            layered_ignore_tree, scan_set(source=str(layered_ignore_tree))
        )

        assert "sub/deep/keep.tmp" in found, (
            f"'!keep.tmp' in sub/deep/.gitignore lost to '*.tmp' in sub/.gitignore; "
            f"scan set: {sorted(found)}"
        )

    def test_the_shallower_exclude_still_applies_where_not_overridden(
        self, layered_ignore_tree
    ):
        """The deeper file overrides one path, it does not replace the rule."""
        found = _relative_posix_names(
            layered_ignore_tree, scan_set(source=str(layered_ignore_tree))
        )

        assert {"sub/a.tmp", "sub/deep/other.tmp"}.isdisjoint(found), (
            f"'*.tmp' from sub/.gitignore stopped excluding files the deeper "
            f"ignore file never named; scan set: {sorted(found)}"
        )


class TestMarkerCarryingRealPath:
    """A marker can name a real path instead of the ``${SOURCE_DIR}`` token.

    ``_source_dir_marker`` emits the token only for an ignore file under the scan
    root as the caller spelled it. An absolute ``--ignorefile`` gets its real path
    instead, including when that path is *inside* the tree -- which is what a
    relative ``--source`` produces. A persisted ``ash-ignore-report.txt`` written
    before the substitution worked on Windows carries real paths for every ignore
    file, and replaying such a report has to keep working.

    Such a marker still has to scope its rules to that file's own directory;
    falling back to the scan root would widen every nested rule to the whole tree.
    """

    def test_absolute_marker_scopes_rules_to_its_own_directory(
        self, nested_ignore_tree
    ):
        sub = nested_ignore_tree / "sub"
        lines = [
            f"######### START CONTENTS: {(sub / '.gitignore').as_posix()} #########",
            "*.tmp",
            f"######### END CONTENTS: {(sub / '.gitignore').as_posix()} #########",
        ]

        spec = get_ash_ignorespec(lines, nested_ignore_tree)

        assert spec.match(sub / "drop.tmp"), (
            "a marker carrying the ignore file's real path did not scope its rule to that directory"
        )
        assert not spec.match(nested_ignore_tree / "keep.tmp"), (
            "a marker carrying the ignore file's real path widened its rule to the scan root"
        )
