# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests that a rule's derived base path cannot leave the scan root.

``get_ash_ignorespec`` derives each rule's base from a section marker, and two of
those derivations could produce a directory outside the tree being scanned:
``root_base_path / parent_dir`` when the marker carries a ``..``, and
``marker_path.parent`` when the marker names an absolute path elsewhere on the
host. Neither escape was visible, because igittigitt normalizes a base through
``os.path.abspath`` when it compiles the rule, so ``<root>/../elsewhere`` simply
became ``<parent>/elsewhere`` with no complaint.

Both directions do damage. A base that escapes sideways matches nothing in the
tree, so the ignore file the user explicitly passed with ``--ignorefile`` becomes
a silent no-op. A base that escapes upward to an ancestor compiles to
``<ancestor>/**/<pattern>``, which reaches every file in the tree and applies the
file's rules from the wrong anchor.

The reachable route to both is ``--ignorefile``:
``_collect_ignorefiles_and_all_files`` joins the value onto the scan root, and
``os.path.join`` discards the root for an absolute value, so the marker ends up
naming a path outside the tree either way.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils.get_scan_set import (
    get_ash_ignorespec,
    scan_set,
)
from automated_security_helper.utils.log import ASH_LOGGER


def _relative_posix_names(scan_root: Path, files: list[str]) -> set[str]:
    """Scan-set paths as ``/``-separated paths relative to *scan_root*."""
    return {Path(f).relative_to(scan_root).as_posix() for f in files}


def _marker_block(marker: str, *rules: str) -> list[str]:
    """The ignorespec lines for one ignore file, as ``get_ash_ignorespec`` reads them."""
    return [
        f"######### START CONTENTS: {marker} #########",
        *rules,
        f"######### END CONTENTS: {marker} #########",
    ]


@pytest.fixture
def scan_root(tmp_path):
    """A scan root with a sibling directory outside it, and no ignore files.

    ``tmp_path/src`` is the root; ``tmp_path/shared`` and ``tmp_path`` itself are
    the two places a base can escape to.
    """
    root = tmp_path / "src"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n")
    (root / "a.tmp").write_text("scratch\n")
    (tmp_path / "shared").mkdir()
    return root


class TestDerivedBaseStaysInsideTheScanRoot:
    """Asserted through matching behavior rather than compiled rule strings, so
    the tests do not depend on igittigitt's internal rule representation."""

    def test_sideways_escape_is_scoped_back_to_the_scan_root(self, scan_root):
        """A ``..`` in the marker used to put the base in a sibling directory,
        where it matched nothing at all."""
        lines = _marker_block("${SOURCE_DIR}/../shared/.gitignore", "**/*.tmp")

        spec = get_ash_ignorespec(lines, scan_root)

        assert spec.match(scan_root / "a.tmp"), (
            "a rule from a marker outside the scan root matched nothing inside it, "
            "so the ignore file was silently discarded"
        )

    def test_upward_escape_is_scoped_back_to_the_scan_root(self, scan_root):
        """A base one level up still reaches the tree through a leading ``**``, so
        the anchored form is what distinguishes the two anchors.

        ``/a.tmp`` compiles to ``<base>/a.tmp``: from the ancestor that is
        ``<parent>/a.tmp`` and misses, from the scan root it is ``<root>/a.tmp``
        and hits.
        """
        lines = _marker_block("${SOURCE_DIR}/../.gitignore", "/a.tmp")

        spec = get_ash_ignorespec(lines, scan_root)

        assert spec.match(scan_root / "a.tmp"), (
            "an anchored rule was compiled against the scan root's parent, so it "
            "applied to a path that does not exist instead of the one that does"
        )

    def test_absolute_marker_outside_the_scan_root_is_scoped_back_to_it(
        self, scan_root, tmp_path
    ):
        """The other derivation: ``marker_path.parent`` for an absolute marker."""
        outside = tmp_path / "shared" / "extra.ignore"
        lines = _marker_block(outside.as_posix(), "**/*.tmp")

        spec = get_ash_ignorespec(lines, scan_root)

        assert spec.match(scan_root / "a.tmp"), (
            "an absolute marker naming a directory outside the tree kept that "
            "directory as its base, so its rules could never match"
        )

    def test_an_escaping_base_is_warned_about(self, scan_root):
        """Falling back silently would leave a user with an ignore file that did
        something other than what they wrote, and no way to find out."""
        lines = _marker_block("${SOURCE_DIR}/../shared/.gitignore", "**/*.tmp")

        mock_warning = MagicMock()
        with patch.object(ASH_LOGGER, "warning", mock_warning):
            get_ash_ignorespec(lines, scan_root)

        messages = [str(call) for call in mock_warning.call_args_list]
        assert any("outside the scan root" in message for message in messages), (
            f"no warning named the escaping base; warnings: {messages}"
        )

    def test_a_marker_inside_the_scan_root_is_not_warned_about(self, scan_root):
        """On Windows every marker carries an absolute path, because
        ``get_ash_ignorespec_lines`` matches the posix form of the scan root
        against a path ``os.walk`` built with ``\\``. Those markers are all inside
        the tree, and warning on each of them would bury the real case.
        """
        sub = scan_root / "sub"
        sub.mkdir()
        lines = _marker_block((sub / ".gitignore").as_posix(), "*.tmp")

        mock_warning = MagicMock()
        with patch.object(ASH_LOGGER, "warning", mock_warning):
            spec = get_ash_ignorespec(lines, scan_root)

        assert mock_warning.call_args_list == [], (
            f"a marker inside the scan root was reported as escaping: "
            f"{[str(call) for call in mock_warning.call_args_list]}"
        )
        assert not spec.match(scan_root / "a.tmp"), (
            "the containment check widened a nested rule to the scan root"
        )


class TestExplicitIgnorefileOutsideTheTree:
    """``--ignorefile`` is explicit user configuration; it has to do something."""

    @pytest.fixture
    def project_and_shared_ignorefile(self, tmp_path):
        """A scan root plus a shared ignore file that sits outside it."""
        root = tmp_path / "src"
        root.mkdir()
        (root / "app.py").write_text("x = 1\n")
        (root / "a.secret").write_text("not a real credential\n")

        shared = tmp_path / "shared"
        shared.mkdir()
        ignorefile = shared / "extra.ignore"
        ignorefile.write_text("*.secret\n")

        return root, ignorefile

    def test_an_absolute_ignorefile_applies(self, project_and_shared_ignorefile):
        """``os.path.join`` drops the scan root for an absolute value, so the
        marker named ``<shared>`` and the rules were scoped there."""
        root, ignorefile = project_and_shared_ignorefile

        found = _relative_posix_names(
            root, scan_set(source=str(root), ignorefile=[str(ignorefile)])
        )

        assert "a.secret" not in found, (
            f"'*.secret' from an absolute --ignorefile did not exclude anything; "
            f"scan set: {sorted(found)}"
        )
        assert "app.py" in found, (
            f"the shared ignore file excluded more than it named; scan set: {sorted(found)}"
        )

    def test_a_parent_relative_ignorefile_applies(self, project_and_shared_ignorefile):
        """Same file reached by a relative path, which keeps the scan root and then
        walks back out of it."""
        root, _ignorefile = project_and_shared_ignorefile

        found = _relative_posix_names(
            root,
            scan_set(source=str(root), ignorefile=["../shared/extra.ignore"]),
        )

        assert "a.secret" not in found, (
            f"'*.secret' from a '../' --ignorefile did not exclude anything; "
            f"scan set: {sorted(found)}"
        )
        assert "app.py" in found, (
            f"the shared ignore file excluded more than it named; scan set: {sorted(found)}"
        )

    def test_an_ignorefile_inside_the_tree_is_unaffected(self, tmp_path):
        """Control: the ordinary case, where the value names a file in the tree."""
        root = tmp_path / "src"
        root.mkdir()
        (root / "app.py").write_text("x = 1\n")
        (root / "a.secret").write_text("not a real credential\n")
        (root / "extra.ignore").write_text("*.secret\n")

        found = _relative_posix_names(
            root, scan_set(source=str(root), ignorefile=["extra.ignore"])
        )

        assert "a.secret" not in found, (
            f"an in-tree --ignorefile stopped working; scan set: {sorted(found)}"
        )
        assert "app.py" in found, (
            f"an in-tree --ignorefile excluded more than it named; scan set: {sorted(found)}"
        )
