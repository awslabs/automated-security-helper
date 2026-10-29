# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan-set walk's boundaries: what it enters, what it tolerates, what it keeps.

Why this exists
---------------
Each test here pins one way the walk in ``get_scan_set`` either left the scan
root, aborted the whole scan on one bad entry, or dropped files the ignore rules
meant to keep:

- a Windows junction (seen through a stand-in ``os.path.isjunction`` on every
  host) was listed as a file by ``file_links_leaving_tree`` and descended by the
  walk on interpreters whose ``os.walk`` follows junctions (3.10 and 3.11);
- a directory the root ``.gitignore`` matches that the scanning user cannot
  search raised ``PermissionError`` out of ``_is_cdk_cloud_assembly`` and aborted
  the scan on 3.10 to 3.12;
- an ignore file in the tree that cannot be opened, and a pattern the parser
  refuses, each raised out of the full ignore spec and aborted the scan, while
  the pruning pre-pass tolerated the same errors;
- a negation in the root ``.ignore`` that re-includes a directory the root
  ``.gitignore`` excludes never took effect, because only the ``.gitignore``
  pruned the walk.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import pytest
from igittigitt import IgnoreParser

from automated_security_helper.utils import get_scan_set as gss
from automated_security_helper.utils.get_scan_set import (
    file_links_leaving_tree,
    scan_set,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit


@pytest.fixture
def ash_warnings(caplog):
    """Read back ASH's own WARNING records, which plain ``caplog`` cannot see:
    ``utils.log`` sets ``ASH_LOGGER.propagate = False`` (the shape
    ``tests/unit/utils/test_changed_files.py`` uses). Returns a callable, so the
    records are read after the call under test."""
    saved_handlers = ASH_LOGGER.handlers
    saved_propagate = ASH_LOGGER.propagate
    saved_disabled = ASH_LOGGER.disabled
    ASH_LOGGER.handlers = [*saved_handlers, caplog.handler]
    ASH_LOGGER.propagate = False
    ASH_LOGGER.disabled = False
    caplog.set_level(logging.WARNING, logger=ASH_LOGGER.name)
    try:
        yield lambda: [
            record.getMessage()
            for record in caplog.records
            if record.levelno >= logging.WARNING
        ]
    finally:
        ASH_LOGGER.handlers = saved_handlers
        ASH_LOGGER.propagate = saved_propagate
        ASH_LOGGER.disabled = saved_disabled


def _write(root: Path, relative: str, text: str = "x = 1\n") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _names(root: Path, files) -> set[str]:
    return {Path(f).relative_to(root).as_posix() for f in files}


def _junction_stand_in(monkeypatch, junction: Path) -> None:
    """Make ``os.path.isjunction`` report *junction* as one, on every host.

    ``_is_link_to_directory`` reads the function off ``os.path`` when it is
    called, so the stand-in is seen whether or not the platform has one.
    """
    target = os.path.abspath(junction)

    def isjunction(path) -> bool:
        return os.path.abspath(os.fspath(path)) == target

    monkeypatch.setattr(os.path, "isjunction", isjunction, raising=False)


class TestJunctions:
    def test_a_junction_is_not_listed_as_a_file_by_the_link_walk(
        self, tmp_path, monkeypatch
    ):
        root = tmp_path / "tree"
        _write(root, "app.py")
        _write(root, "junction/inside.py")
        _junction_stand_in(monkeypatch, root / "junction")

        all_files: list[str] = []
        file_links_leaving_tree(root, all_files=all_files)

        assert "app.py" in all_files
        assert "junction" not in all_files
        assert "junction/inside.py" not in all_files

    def test_a_junction_leaving_the_tree_is_recorded_as_a_directory_link(
        self, tmp_path, monkeypatch
    ):
        root = tmp_path / "tree"
        _write(root, "app.py")
        _write(root, "junction/inside.py")
        _junction_stand_in(monkeypatch, root / "junction")
        monkeypatch.setattr(
            gss, "resolves_inside", lambda path, _root: "junction" not in str(path)
        )

        directory_links: list[str] = []
        file_links_leaving_tree(root, directory_links=directory_links)

        assert directory_links == ["junction"]

    def test_the_scan_set_walk_does_not_descend_a_junction(self, tmp_path, monkeypatch):
        """``os.walk`` followed a junction on 3.10 and 3.11; the walk prunes it itself."""
        root = tmp_path / "tree"
        _write(root, "app.py")
        _write(root, "junction/inside.py")
        _junction_stand_in(monkeypatch, root / "junction")

        found = _names(root, scan_set(source=str(root)))

        assert "app.py" in found
        assert "junction/inside.py" not in found


class TestOneBadEntryDoesNotAbortTheScan:
    def test_an_unsearchable_ignored_directory_is_not_a_cloud_assembly(self, tmp_path):
        """``Path.is_file`` raises PermissionError on 3.10 to 3.12 for a child of
        a directory the user cannot search; the question is answered, not raised."""

        class Refusing(type(Path())):
            def is_file(self) -> bool:
                raise PermissionError(13, "Permission denied", str(self))

        assert gss._is_cdk_cloud_assembly(Refusing(tmp_path / "build")) is False

    @pytest.mark.skipif(
        sys.platform == "win32" or os.geteuid() == 0,
        reason="file modes do not refuse the owner on Windows or root",
    )
    def test_an_ignore_file_that_cannot_be_opened_is_skipped_and_said(
        self, tmp_path, ash_warnings
    ):
        root = tmp_path / "tree"
        _write(root, "app.py")
        _write(root, "sub/kept.py")
        unreadable = _write(root, "sub/.gitignore", "kept.py\n")
        unreadable.chmod(0o000)
        try:
            found = _names(root, scan_set(source=str(root)))
        finally:
            unreadable.chmod(0o644)

        assert {"app.py", "sub/kept.py"} <= found
        assert any("Skipped ignore file" in message for message in ash_warnings()), (
            ash_warnings()
        )

    def test_a_pattern_the_parser_refuses_is_skipped_and_said(
        self, tmp_path, monkeypatch, ash_warnings
    ):
        """The pre-pass tolerated it and the full spec raised: now both tolerate."""
        root = tmp_path / "tree"
        _write(root, "app.py")
        _write(root, "sub/.gitignore", "bad-pattern\n*.log\n")
        _write(root, "sub/trace.log")
        _write(root, "sub/kept.py")
        real_add_rule = IgnoreParser.add_rule

        def refusing_add_rule(self, pattern, base_path):
            if pattern.endswith("bad-pattern"):
                raise ValueError("refused by the parser")
            return real_add_rule(self, pattern, base_path)

        monkeypatch.setattr(IgnoreParser, "add_rule", refusing_add_rule)

        found = _names(root, scan_set(source=str(root)))

        assert {"app.py", "sub/kept.py"} <= found
        assert "sub/trace.log" not in found
        assert any("bad-pattern" in message for message in ash_warnings()), (
            ash_warnings()
        )


class TestWhatThePrunedWalkKeeps:
    def test_a_root_ignore_negation_brings_a_pruned_directory_back(self, tmp_path):
        """The root ``.ignore`` is compiled after the root ``.gitignore``, so its
        negation wins in the full spec; the pruning pre-pass has to see it too."""
        root = tmp_path / "tree"
        _write(root, ".gitignore", "vendor/\n")
        _write(root, ".ignore", "!vendor/\n")
        _write(root, "app.py")
        _write(root, "vendor/keep.js")

        found = _names(root, scan_set(source=str(root)))

        assert {"app.py", "vendor/keep.js"} <= found

    def test_a_root_ignore_rule_still_excludes(self, tmp_path):
        """The control: a positive rule in the root ``.ignore`` removes its files."""
        root = tmp_path / "tree"
        _write(root, ".ignore", "vendor/\n")
        _write(root, "app.py")
        _write(root, "vendor/dropped.js")

        found = _names(root, scan_set(source=str(root)))

        assert "app.py" in found
        assert "vendor/dropped.js" not in found

    def test_a_caller_named_ignore_file_negation_brings_a_pruned_directory_back(
        self, tmp_path
    ):
        """An ``--ignorefile`` compiles after the root files in the full spec too."""
        root = tmp_path / "tree"
        _write(root, ".gitignore", "vendor/\n")
        _write(root, "app.py")
        _write(root, "vendor/keep.js")
        extra = tmp_path / "extra.ignore"
        extra.write_text("!vendor/\n", encoding="utf-8")

        found = _names(
            root, scan_set(source=str(root), ignorefile=[os.path.relpath(extra, root)])
        )

        assert {"app.py", "vendor/keep.js"} <= found
