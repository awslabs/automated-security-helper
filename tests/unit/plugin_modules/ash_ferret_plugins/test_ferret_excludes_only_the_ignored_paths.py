# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ferret-scan is told to skip the files the global ignore paths ignore, and no others.

The plugin passes ``--exclude`` the paths ASH ignores, not the ignore paths as
written. ferret-scan 2.4.x tests a pattern as a substring of the full path
(``isExcluded`` in its ``cmd/main.go``; DEVELOPMENT.md section 9), so an ignore
path passed as written, such as ``.`` or ``api``, would leave out nearly every
file. The paths come from ``ignored_entries``, which matches each ignore path
as ASH does when it drops findings: a file is its full path with its glob characters
escaped, and a fully ignored directory is that path followed by the separator and
``*``, the form ASH's output directories take there.

The cells read the ``--exclude`` value through models of the two supported lines:
2.4.x tests a pattern as a Go glob against the full path and the base name and as a
substring of the full path; 2.5.x as a glob against the full path, the base name and
each segment, with a relative pattern holding ``/`` resolved against the scan root. A
walked directory that is excluded is skipped with everything below it.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_ferret_plugins import (
    ferret_scanner,
)
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScannerConfig,
    FerretScannerConfigOptions,
    FerretScanScanner,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(sys.platform == "win32", reason="the patterns are POSIX paths"),
]

FILES = ["api/a.js", "api/sub/b.js", "apix/a.js", "src/a.js", "src/api.js"]


def _go_match(pattern: str, name: str) -> bool:
    """Go's ``filepath.Match`` on a ``/`` path: ``*`` and ``?`` stop at ``/``,
    ``[...]`` is a class (``^`` negates it), and ``\\`` escapes the next character."""
    regex, index = "", 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            regex += re.escape(pattern[index + 1])
            index += 2
            continue
        if char == "*":
            regex += "[^/]*"
        elif char == "?":
            regex += "[^/]"
        elif char == "[":
            end = pattern.find("]", index + 2)
            if end == -1:
                return False
            body = pattern[index + 1 : end]
            negated = body.startswith("^")
            body = body[1:] if negated else body
            regex += "[" + ("^" if negated else "") + re.escape(body) + "]"
            index = end + 1
            continue
        else:
            regex += re.escape(char)
        index += 1
    return re.fullmatch(regex, name) is not None


def _excluded_by(path: str, pattern: str, version: str, root: Path) -> bool:
    base = path.rsplit("/", 1)[-1]
    if _go_match(pattern, path) or _go_match(pattern, base):
        return True
    if version == "2.4":
        return pattern in path
    if "/" in pattern and not pattern.startswith("/"):
        relative = pattern.removeprefix("./")
        if _go_match(f"{os.fspath(root)}/{relative}", path):
            return True
    return any(_go_match(pattern, segment) for segment in path.split("/") if segment)


def _skipped(root: Path, relative: str, patterns: list[str], version: str) -> bool:
    """Whether ferret-scan leaves ``relative`` out: it, or a directory above it
    below ``root``, matches a pattern."""
    parts = relative.split("/")
    candidates = [
        os.fspath(root.joinpath(*parts[:depth])) for depth in range(1, len(parts) + 1)
    ]
    return any(
        _excluded_by(candidate, pattern, version, root)
        for candidate in candidates
        for pattern in patterns
    )


def _tree(root: Path, files: list[str]) -> Path:
    for relative in files:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x = 1\n", encoding="utf-8")
    return root


def _scanner(context) -> FerretScanScanner:
    scanner = FerretScanScanner(
        context=context,
        config=FerretScannerConfig(options=FerretScannerConfigOptions()),
    )
    scanner.dependencies_satisfied = True
    return scanner


def _excludes(scanner, target: Path, *ignore_paths: str) -> list[str]:
    """Run scan() as far as starting ferret-scan; return its --exclude patterns."""
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
        scanner.scan(
            target=target,
            target_type="source",
            global_ignore_paths=[
                IgnorePathWithReason(path=path, reason="ignored")
                for path in ignore_paths
            ],
        )
    (argv,) = started
    if "--exclude" not in argv:
        return []
    return argv[argv.index("--exclude") + 1].split(",")


@pytest.mark.parametrize("ignore_path", [".", "api", "./api"])
def test_an_ignore_path_ash_matches_to_nothing_leaves_every_file_scanned(
    mock_plugin_context, ignore_path
):
    """ASH matches these to no file, so it drops no finding for them, and ferret-scan
    is given nothing to leave out: 2.4.x read ``.`` and ``api`` as substrings."""
    root = _tree(mock_plugin_context.source_dir, FILES)

    patterns = _excludes(_scanner(mock_plugin_context), root, ignore_path)

    assert ignore_path not in patterns, patterns
    for version in ("2.4", "2.5"):
        for relative in FILES:
            assert not _skipped(root, relative, patterns, version), (version, relative)


@pytest.mark.parametrize("ignore_path", ["api/", "api/**"])
def test_a_directory_ignore_path_skips_only_the_files_below_it(
    mock_plugin_context, ignore_path
):
    root = _tree(mock_plugin_context.source_dir, FILES)

    patterns = _excludes(_scanner(mock_plugin_context), root, ignore_path)

    assert patterns == [os.fspath(root / "api") + os.sep + "*"], patterns
    for version in ("2.4", "2.5"):
        assert _skipped(root, "api/a.js", patterns, version)
        assert _skipped(root, "api/sub/b.js", patterns, version)
        for kept in ("apix/a.js", "src/a.js", "src/api.js"):
            assert not _skipped(root, kept, patterns, version), (version, kept)


def test_a_file_ignore_path_skips_that_file_alone(mock_plugin_context):
    root = _tree(mock_plugin_context.source_dir, FILES)

    patterns = _excludes(_scanner(mock_plugin_context), root, "src/a.js")

    assert patterns == [os.fspath(root / "src" / "a.js")], patterns
    for version in ("2.4", "2.5"):
        assert _skipped(root, "src/a.js", patterns, version)
        for kept in ("api/a.js", "apix/a.js", "src/api.js"):
            assert not _skipped(root, kept, patterns, version), (version, kept)


def test_a_pattern_another_kept_file_holds_is_left_out(mock_plugin_context):
    """2.4.x would also leave out ``conf.txt.bak``, which nothing ignores, so
    ``conf.txt`` is not excluded: ferret-scan reads it, and ASH drops its findings."""
    root = _tree(mock_plugin_context.source_dir, ["conf.txt", "conf.txt.bak", "a.txt"])

    patterns = _excludes(_scanner(mock_plugin_context), root, "conf.txt")

    assert patterns == [], patterns
    assert not _skipped(root, "conf.txt.bak", patterns, "2.4")


def test_a_path_the_exclude_value_cannot_carry_is_left_out(mock_plugin_context):
    """``--exclude`` splits on commas; the scan still runs, without that pattern."""
    root = _tree(mock_plugin_context.source_dir, ["a,b/x.js", "src/a.js", "c.js"])

    patterns = _excludes(_scanner(mock_plugin_context), root, "a,b/", "c.js")

    assert patterns == [os.fspath(root / "c.js")], patterns


def test_the_value_stays_within_its_budget(mock_plugin_context, monkeypatch):
    """One argument holds every pattern, and Linux refuses a single argument over
    128 KiB, so ignore patterns that do not fit are left out: ferret-scan reads
    those files, and ASH drops their findings."""
    files = [f"d{index}/ignored.min.js" for index in range(6)]
    files += [f"d{index}/kept.js" for index in range(6)]
    root = _tree(mock_plugin_context.source_dir, files)
    budget = len(",".join(os.fspath(root / f) for f in files[:3]).encode())
    monkeypatch.setattr(ferret_scanner, "_EXCLUDE_VALUE_BUDGET", budget, raising=False)

    patterns = _excludes(_scanner(mock_plugin_context), root, "*.min.js")

    assert len(",".join(patterns).encode()) <= budget
    assert patterns == [os.fspath(root / f) for f in files[:3]], patterns


def test_a_target_outside_the_source_directory_gets_no_ignore_patterns(
    mock_plugin_context,
):
    """The ignore paths name paths below the source directory; a converted file's
    path in the work directory is not one, so ASH drops those findings after."""
    work = _tree(mock_plugin_context.work_dir / "converted", ["api/a.js", "b.js"])

    patterns = _excludes(_scanner(mock_plugin_context), work, "api/")

    assert patterns == [], patterns
