# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

r"""Tests that an ignore file is named relative to the scan root on every platform.

``get_ash_ignorespec_lines`` labels each block of ignore rules with a marker naming
the file the rules came from, using a ``${SOURCE_DIR}`` token in place of the scan
root. The token is what makes the marker mean anything to a second reader:
``get_ash_ignorespec`` reads it back to derive the rule's base path, and the
per-ignore-file exclusion report prints it verbatim as the label a user is meant to
act on.

The derivation compared ``Path(source_dir).as_posix()`` against a path ``os.walk``
had joined with ``os.sep``. Those are the same string on POSIX and different on
Windows, so the substitution never fired there: every marker carried an absolute
host path, the report labelled a temp directory instead of an ignore file, and the
artifact could not be replayed against another checkout.

A test that only builds paths the way the host does cannot catch that, which is why
the derivation takes its separator set as an argument -- passing the Windows set is
what makes the Windows answer measurable from a POSIX host. Windows paths here are
built with ``ntpath`` rather than written out, so they are the strings Windows
would produce rather than a guess at them.

The POSIX-preservation controls are as load-bearing as the Windows cases. ``\`` is
a legal character in a POSIX filename, so a fix that rewrote it unconditionally
would misname a directory that really contains one.
"""

import ntpath
import posixpath
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.get_scan_set import (
    _PATH_SEPARATORS,
    _collect_ignorefiles_and_all_files,
    _source_dir_marker,
    get_ash_ignorespec_lines,
    scan_set,
)

WINDOWS_SEPARATORS = "\\/"
POSIX_SEPARATORS = "/"

WINDOWS_ROOT = "C:" + ntpath.sep + ntpath.join("proj", "src")
POSIX_ROOT = posixpath.join(posixpath.sep, "proj", "src")


def _marker_lines(lines: list[str]) -> list[str]:
    """The paths named by the ``START CONTENTS`` markers in *lines*."""
    return [
        line.split("START CONTENTS:")[1].strip().rstrip("#").strip()
        for line in lines
        if line.startswith("#########") and "START CONTENTS:" in line
    ]


class TestMarkerNamesTheIgnoreFileRelativeToTheScanRoot:
    def test_a_windows_walked_path_carries_the_token(self):
        """The reported failure: an absolute host path where the token belonged."""
        walked = ntpath.join(WINDOWS_ROOT, "vendor", ".gitignore")

        marker = _source_dir_marker(WINDOWS_ROOT, walked, separators=WINDOWS_SEPARATORS)

        assert marker == "${SOURCE_DIR}/vendor/.gitignore", (
            f"a Windows-shaped walked path was not named relative to the scan "
            f"root; got {marker!r} from root {WINDOWS_ROOT!r} and {walked!r}"
        )

    def test_a_windows_root_level_ignore_file_keeps_its_leading_dot(self):
        """The corruption the rejected fix produced, asserted against directly.

        Stripping a prefix that ends where the filename's own ``.`` begins yields
        ``${SOURCE_DIR}gitignore`` -- a marker that names no file, reads back as a
        relative path, and silently scopes the root ignore file's rules wrong.
        """
        walked = ntpath.join(WINDOWS_ROOT, ".gitignore")

        marker = _source_dir_marker(WINDOWS_ROOT, walked, separators=WINDOWS_SEPARATORS)

        assert marker == "${SOURCE_DIR}/.gitignore", (
            f"the root ignore file's marker lost its separator or its dot; "
            f"got {marker!r}"
        )
        assert "${SOURCE_DIR}gitignore" not in marker, (
            f"the separator between token and filename was consumed; got {marker!r}"
        )

    def test_a_posix_walked_path_is_unchanged(self):
        """Control: the platform that already worked has to keep its answer."""
        walked = posixpath.join(POSIX_ROOT, "vendor", ".gitignore")

        marker = _source_dir_marker(POSIX_ROOT, walked, separators=POSIX_SEPARATORS)

        assert marker == "${SOURCE_DIR}/vendor/.gitignore", (
            f"the POSIX marker moved; got {marker!r}"
        )

    @pytest.mark.parametrize(
        ("root", "walked", "expected"),
        [
            (".", "./.gitignore", "${SOURCE_DIR}/.gitignore"),
            (".", "./sub/.gitignore", "${SOURCE_DIR}/sub/.gitignore"),
            ("sub", "sub/.gitignore", "${SOURCE_DIR}/.gitignore"),
            ("sub", "sub/deep/.gitignore", "${SOURCE_DIR}/deep/.gitignore"),
        ],
    )
    def test_a_relative_scan_root_keeps_the_token(self, root, walked, expected):
        """The failure mode of the fix that was tried and reverted.

        Posix-ifying the subject drops its leading ``./``, at which point the
        anchor no longer matches and the placeholder is lost outright. Comparing
        the prefix raw cannot lose it: the subject was built by joining onto the
        root, so whatever shape the root has, the subject starts with it.
        """
        marker = _source_dir_marker(root, walked, separators=POSIX_SEPARATORS)

        assert marker == expected, (
            f"a relative scan root lost the token; root {root!r} and {walked!r} "
            f"gave {marker!r}"
        )

    def test_a_trailing_separator_on_the_scan_root_is_tolerated(self):
        """``--source /proj/`` is as valid as ``--source /proj``, and the remainder
        then starts at a name rather than at a separator."""
        root = POSIX_ROOT + posixpath.sep
        walked = posixpath.join(POSIX_ROOT, "vendor", ".gitignore")

        marker = _source_dir_marker(root, walked, separators=POSIX_SEPARATORS)

        assert marker == "${SOURCE_DIR}/vendor/.gitignore", (
            f"a trailing separator on the scan root broke the marker; got {marker!r}"
        )

    def test_a_sibling_directory_sharing_a_prefix_is_named_by_its_own_path(self):
        """A prefix test alone is not containment.

        ``/proj/src`` is a prefix of the *string* ``/proj/srcbak/.gitignore``
        without containing the file, and rewriting on that basis produced
        ``${SOURCE_DIR}bak/.gitignore`` -- a marker naming a directory that does
        not exist. An absolute ``--ignorefile`` naming a sibling reaches this.
        """
        outside = posixpath.join(POSIX_ROOT + "bak", ".gitignore")

        marker = _source_dir_marker(POSIX_ROOT, outside, separators=POSIX_SEPARATORS)

        assert marker == outside, (
            f"a sibling directory sharing a prefix was rewritten as though it were "
            f"inside the scan root; got {marker!r}"
        )

    def test_a_path_outside_the_scan_root_keeps_its_own_name(self):
        """An out-of-tree ``--ignorefile`` has to stay recognizable, because
        :func:`get_ash_ignorespec` routes it through the absolute-marker branch and
        warns about it there."""
        outside = posixpath.join(posixpath.sep, "shared", "extra.ignore")

        marker = _source_dir_marker(POSIX_ROOT, outside, separators=POSIX_SEPARATORS)

        assert marker == outside, (
            f"an out-of-tree ignore file was named as though it were inside the "
            f"scan root; got {marker!r}"
        )

    def test_the_host_separator_default_matches_the_platform(self):
        r"""The default is derived from ``os``, not hardcoded to both separators.

        Hardcoding both would treat a POSIX filename containing ``\`` as a nested
        path, so this asserts the concrete per-platform value rather than restating
        the expression that produces it.
        """
        if sys.platform == "win32":
            assert set(_PATH_SEPARATORS) == {"\\", "/"}, (
                f"Windows must treat both separators as separators; got "
                f"{_PATH_SEPARATORS!r}"
            )
        else:
            assert set(_PATH_SEPARATORS) == {"/"}, (
                f"POSIX must treat only '/' as a separator, or a filename "
                f"containing a backslash is silently split; got {_PATH_SEPARATORS!r}"
            )


class TestARelativeScanRootDrivesTheRealCode:
    """The cases above pin the derivation; these pin the wiring.

    Run against a real tree with ``source`` given relatively, because that is the
    shape under which the reverted fix broke. It is not enough for the marker to be
    right: the spec has to read it back, and the nested ignore file has to still
    apply afterwards.
    """

    @pytest.fixture
    def nested_tree(self, tmp_path, monkeypatch):
        """A tree with ``tmp_path`` as the cwd, so ``source="."`` is meaningful.

        Structure::

            .gitignore        (*.log)
            app.py
            root.log          excluded by the root ignore file
            vendor/
            |-- .gitignore    (lib/)
            `-- lib/
                `-- dep.py    excluded by the nested ignore file
        """
        (tmp_path / ".gitignore").write_text("*.log\n")
        (tmp_path / "app.py").write_text("x = 1\n")
        (tmp_path / "root.log").write_text("noise\n")
        vendor = tmp_path / "vendor"
        vendor.mkdir()
        (vendor / ".gitignore").write_text("lib/\n")
        (vendor / "lib").mkdir()
        (vendor / "lib" / "dep.py").write_text("y = 2\n")
        monkeypatch.chdir(tmp_path)
        return tmp_path

    def test_every_marker_carries_the_token(self, nested_tree):
        discovered, _all_files = _collect_ignorefiles_and_all_files(".")
        lines = get_ash_ignorespec_lines(".", [], _discovered_ignore_files=discovered)

        markers = [
            marker for marker in _marker_lines(lines) if marker != "ASH_INCLUSIONS"
        ]

        assert markers, "no ignore files were found, so nothing was asserted"
        assert all(marker.startswith("${SOURCE_DIR}/") for marker in markers), (
            f"a relative scan root produced a marker without the token: {markers}"
        )

    def test_no_marker_is_corrupted(self, nested_tree):
        """``${SOURCE_DIR}gitignore`` is the specific shape a lost separator takes,
        and it has to appear nowhere -- not only in the markers."""
        discovered, _all_files = _collect_ignorefiles_and_all_files(".")
        lines = get_ash_ignorespec_lines(".", [], _discovered_ignore_files=discovered)

        assert not any("${SOURCE_DIR}gitignore" in line for line in lines), (
            "a marker lost the separator between token and filename; lines: "
            f"{[line for line in lines if 'SOURCE_DIR' in line]}"
        )

    def test_a_nested_ignore_file_still_applies(self, nested_tree):
        """The marker is only useful if the spec can read it back.

        A marker that survived but resolved to the wrong base would leave the
        nested exclusion inert while every assertion about the marker text passed.
        """
        found = {Path(entry).as_posix() for entry in scan_set(source=".")}

        assert "vendor/lib/dep.py" not in found, (
            f"the nested ignore file did not apply under a relative scan root; "
            f"scan set: {sorted(found)}"
        )
        assert "root.log" not in found, (
            f"the root ignore file did not apply under a relative scan root; "
            f"scan set: {sorted(found)}"
        )
        assert {"app.py", "vendor/.gitignore"} <= found, (
            f"a relative scan root dropped files no ignore file named; "
            f"scan set: {sorted(found)}"
        )
