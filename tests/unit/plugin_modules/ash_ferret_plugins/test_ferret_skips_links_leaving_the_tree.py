# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ferret-scan is told to skip every link to a file whose target leaves its target.

ferret-scan walks the directory it is given, and how it treats links was not
measured. So each such link (``get_scan_set.file_links_leaving_tree``) goes into its
``--exclude`` value, comma-joined with the configured patterns, as the link's full
path with its glob characters escaped (``scan_output_dirs.escape_for_pattern``), the
form ASH's output directories take there. ``--exclude`` splits on commas, so a path
with a comma cannot be carried, and ferret-scan 2.4.x also leaves out every path a
pattern is a substring of (DEVELOPMENT.md section 9), so a link whose path another
file's path holds cannot be left out alone: then ferret-scan is not started and the
scan of that target fails, naming the path.
"""

from __future__ import annotations

import fnmatch
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScannerConfig,
    FerretScannerConfigOptions,
    FerretScanScanner,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
]


def _scan(scanner, target: Path):
    """Run scan() as far as starting ferret-scan; return the argv, or None."""
    started: list[list[str]] = []

    def _run(command, **kwargs):
        started.append(list(command))
        return {"returncode": 0, "stdout": "", "stderr": ""}

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=_run),
        patch.object(scanner, "_plugin_log"),
    ):
        scanner.scan(target=target, target_type="source")
    return started[0] if started else None


def _excludes(argv: list[str]) -> list[str]:
    index = argv.index("--exclude")
    return argv[index + 1].split(",")


@pytest.fixture
def target(mock_plugin_context, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("outside\n", encoding="utf-8")
    root = mock_plugin_context.source_dir
    (root / "real.txt").write_text("in the tree\n", encoding="utf-8")
    (root / "docs").mkdir()
    (root / "docs" / "notes.txt").symlink_to(outside / "secret.txt")
    (root / "in_tree.txt").symlink_to(root / "real.txt")
    return root, outside


def _scanner(context, **options) -> FerretScanScanner:
    scanner = FerretScanScanner(
        context=context,
        config=FerretScannerConfig(options=FerretScannerConfigOptions(**options)),
    )
    scanner.dependencies_satisfied = True
    return scanner


def test_each_link_leaving_the_target_is_excluded(mock_plugin_context, target):
    root, _ = target
    scanner = _scanner(mock_plugin_context, exclude_patterns=["*.log"])

    argv = _scan(scanner, root)

    assert _excludes(argv) == ["*.log", os.fspath(root / "docs" / "notes.txt")]
    # The configured patterns are left as they were.
    assert scanner.config.options.exclude_patterns == ["*.log"]


def test_a_same_named_file_inside_the_tree_is_not_excluded(mock_plugin_context, target):
    """The pattern is the link's full path, so it names that file and no other:
    ferret-scan matches it as a glob against the whole path."""
    root, _ = target
    (root / "other").mkdir()
    (root / "other" / "notes.txt").write_text("in the tree\n", encoding="utf-8")
    scanner = _scanner(mock_plugin_context)

    (pattern,) = _excludes(_scan(scanner, root))

    assert fnmatch.fnmatchcase(os.fspath(root / "docs" / "notes.txt"), pattern)
    assert not fnmatch.fnmatchcase(os.fspath(root / "other" / "notes.txt"), pattern)
    # 2.4.x's substring test does not reach it either.
    assert pattern not in os.fspath(root / "other" / "notes.txt")
    assert pattern not in os.fspath(root / "real.txt")


def test_without_links_nothing_is_added(mock_plugin_context, tmp_path):
    root = mock_plugin_context.source_dir
    (root / "real.txt").write_text("in the tree\n", encoding="utf-8")
    scanner = _scanner(mock_plugin_context)

    argv = _scan(scanner, root)

    assert "--exclude" not in argv


@pytest.mark.parametrize(
    "name, escaped",
    [
        ("a*b.txt", "a[*]b.txt"),
        ("a?b.txt", "a[?]b.txt"),
        ("a[1].txt", "a[[]1].txt"),
        ("a{b}.txt", "a[{]b}.txt"),
        ("a\\b.txt", "a\\\\b.txt"),
    ],
)
def test_a_link_with_a_glob_character_is_excluded_escaped(
    mock_plugin_context, target, name, escaped
):
    root, outside = target
    (root / name).symlink_to(outside / "secret.txt")
    scanner = _scanner(mock_plugin_context)

    argv = _scan(scanner, root)

    assert os.fspath(root / escaped) in _excludes(argv)


def test_a_link_the_exclude_value_cannot_carry_refuses_the_target(
    mock_plugin_context, target
):
    root, outside = target
    (root / "a,b.txt").symlink_to(outside / "secret.txt")
    scanner = _scanner(mock_plugin_context)

    with pytest.raises(ScannerError) as refused:
        _scan(scanner, root)

    assert repr("a,b.txt") in str(refused.value)
    assert "link leaves the scanned tree" in str(refused.value)


@pytest.mark.parametrize(
    "other", ["conf.txt.bak", "conf.txt.d/x.txt"], ids=["longer-name", "below-a-dir"]
)
def test_a_link_whose_path_another_file_holds_refuses_the_target(
    mock_plugin_context, target, other
):
    """ferret-scan 2.4.x leaves out every path a pattern is a substring of, so the
    link's pattern would also leave out that in-tree file."""
    root, outside = target
    (root / "conf.txt").symlink_to(outside / "secret.txt")
    (root / other).parent.mkdir(parents=True, exist_ok=True)
    (root / other).write_text("in the tree\n", encoding="utf-8")
    scanner = _scanner(mock_plugin_context)

    with pytest.raises(ScannerError) as refused:
        _scan(scanner, root)

    assert repr("conf.txt") in str(refused.value)
    assert "link leaves the scanned tree" in str(refused.value)
