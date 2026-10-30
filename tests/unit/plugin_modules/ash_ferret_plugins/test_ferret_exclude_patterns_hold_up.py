# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ferret-scan ``--exclude`` value is built for every tree, and left as configured.

Four shapes the value's construction used to fail on:

- A file name that is not UTF-8 (listed with a surrogate escape) made the byte
  budget's strict encode raise, which failed the whole ferret-scan target. The
  budget now counts the name's on-disk bytes (``os.fsencode``).
- A link to a directory whose target leaves the tree got no ``--exclude``, while a
  link to a file did, although the plugin states ferret-scan's link handling was
  never measured. The directory link is now excluded, itself and everything below.
- A link whose path is a prefix of another file's path refused the whole run on
  every ferret-scan line, although only 2.4.x matches a pattern as a substring.
  From 2.5.0 on the pattern is used; an unknown version keeps the refusal.
- The configured ``exclude_patterns`` were swapped for the run's absolute list and
  not swapped back when resolving the arguments raised, so the next target of the
  same instance inherited them. The swap is now undone in a ``finally``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScannerConfig,
    FerretScannerConfigOptions,
    FerretScanScanner,
    _ignore_exclude_patterns,
)
from automated_security_helper.utils.link_exclusions import walked_files

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32",
        reason="the patterns are POSIX paths and symlinks need privileges on Windows",
    ),
]


def _scanner(context, **options) -> FerretScanScanner:
    scanner = FerretScanScanner(
        context=context,
        config=FerretScannerConfig(options=FerretScannerConfigOptions(**options)),
    )
    scanner.dependencies_satisfied = True
    return scanner


def _scan(scanner, target: Path):
    """Run scan() as far as starting ferret-scan; return the argv, or None."""
    started: list[list[str]] = []

    def _run(command, **kwargs):
        started.append(list(command))
        # A completed run carries its exit code; a response without one is a
        # tool that never ran, which the scanner refuses before grading.
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


def test_an_ignored_file_whose_name_is_not_utf8_gets_a_pattern(mock_plugin_context):
    root = mock_plugin_context.source_dir
    (root / "kept.txt").write_text("kept\n", encoding="utf-8")
    undecodable = root / os.fsdecode(b"ignored-\xff.txt")
    undecodable.write_bytes(b"ignored\n")

    patterns, left_out = _ignore_exclude_patterns(
        root,
        root,
        [IgnorePathWithReason(path="ignored-*", reason="test")],
        walked_files(root),
        [],
    )

    assert left_out == []
    assert patterns == [os.fspath(undecodable)]


def test_a_link_to_a_directory_leaving_the_tree_is_excluded_with_its_contents(
    mock_plugin_context, tmp_path
):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "creds").write_text("outside\n", encoding="utf-8")
    root = mock_plugin_context.source_dir
    (root / "real.txt").write_text("in the tree\n", encoding="utf-8")
    (root / "shared").symlink_to(outside, target_is_directory=True)
    scanner = _scanner(mock_plugin_context)

    argv = _scan(scanner, root)

    assert argv is not None
    link = os.fspath(root / "shared")
    assert _excludes(argv) == [link, link + os.sep + "*"]


@pytest.fixture
def prefix_link(mock_plugin_context, tmp_path):
    """A link leaving the tree whose path is a prefix of another file's path."""
    outside = tmp_path / "outside.py"
    outside.write_text("outside\n", encoding="utf-8")
    root = mock_plugin_context.source_dir
    (root / "conf.py").symlink_to(outside)
    (root / "conf.py.bak").write_text("in the tree\n", encoding="utf-8")
    return root


def test_on_the_glob_only_line_a_prefix_link_is_excluded_not_refused(
    mock_plugin_context, prefix_link
):
    """ferret-scan 2.5.x matches a pattern as a glob only, so ``conf.py`` leaves
    out ``conf.py`` and not ``conf.py.bak``: the run goes ahead."""
    scanner = _scanner(mock_plugin_context)
    scanner.tool_version = "2.5.3"

    argv = _scan(scanner, prefix_link)

    assert argv is not None
    assert _excludes(argv) == [os.fspath(prefix_link / "conf.py")]


@pytest.mark.parametrize("version", ["2.4.5", None], ids=["2.4.x", "unknown"])
def test_on_the_substring_line_a_prefix_link_still_refuses_the_run(
    mock_plugin_context, prefix_link, version
):
    """Control: 2.4.x would leave out ``conf.py.bak`` too, so the run is refused,
    and an unknown version is read as the stricter line."""
    scanner = _scanner(mock_plugin_context)
    scanner.tool_version = version

    with pytest.raises(ScannerError, match="another file's path holds its path"):
        _scan(scanner, prefix_link)


def test_the_configured_patterns_are_restored_when_resolving_raises(
    mock_plugin_context,
):
    root = mock_plugin_context.source_dir
    (root / "real.txt").write_text("in the tree\n", encoding="utf-8")
    scanner = _scanner(mock_plugin_context, exclude_patterns=["*.log"])

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_plugin_log"),
        patch.object(
            scanner, "_resolve_arguments", side_effect=RuntimeError("resolving broke")
        ),
        pytest.raises(ScannerError, match="resolving broke"),
    ):
        scanner.scan(target=root, target_type="source")

    assert scanner.config.options.exclude_patterns == ["*.log"]
