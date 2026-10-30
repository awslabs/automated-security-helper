# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A client bandit ``excluded_paths`` entry hides, after the scan, what bandit skipped.

The post-scan matcher used the retired unanchored ``**/<path>/**`` against the
finding's absolute path, while the scanner passes bandit anchored globs
(``bandit_excluded_path_globs``). So an entry naming any directory above the
scan root (``home`` for a tree under ``/home/...``) suppressed every bandit
finding, a file entry (``app.py``) suppressed nothing although bandit skips that
file, and ``.`` or an empty entry became ``**/**`` and suppressed everything.
The matcher now asks the scanner's own builder for the globs bandit was given,
anchored at the root read off the finding's paths, and matches them as bandit
does: ``fnmatch`` or a plain substring.
"""

from __future__ import annotations

import fnmatch
import os

import pytest

from automated_security_helper.config.client_scanner_exclusions import (
    ClientScannerExclusion,
    bandit_would_skip,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    bandit_excluded_path_globs,
)

pytestmark = pytest.mark.unit

ROOT = "/home/user/proj"


def _exclusion(pattern: str) -> ClientScannerExclusion:
    return ClientScannerExclusion(
        scanner="bandit",
        option="excluded_paths",
        kind="bandit",
        pattern=pattern,
        reason="client's reason",
    )


def _hides(pattern: str, relative: str) -> bool:
    return _exclusion(pattern).hides(
        relative=relative, absolute=f"{ROOT}/{relative}", rule_id="B101"
    )


@pytest.mark.parametrize(
    ("pattern", "relative", "hidden"),
    [
        # A directory above the scan root is not below it: bandit skipped nothing.
        ("home", "src/app.py", False),
        ("user", "src/app.py", False),
        ("proj", "src/app.py", False),
        # A file entry skips that file, at the top or below any directory.
        ("app.py", "app.py", True),
        ("app.py", "src/app.py", True),
        ("app.py", "src/app.pyx", False),
        ("app.py", "src/app.py.d/x.py", False),
        # A directory entry skips what is under it, wherever it sits.
        ("vendor", "vendor/a.py", True),
        ("vendor", "src/vendor/a.py", True),
        ("vendor/", "src/vendor/a.py", True),
        ("vendor", "vendors/a.py", False),
        # A glob is read as bandit reads it.
        ("*.pyc", "build/x.pyc", True),
        ("tests/*", "tests/test_x.py", True),
        # '.', '' and './' name the target itself, which bandit never skips for.
        (".", "app.py", False),
        ("", "app.py", False),
        ("./", "app.py", False),
        # A comma or a line break has no bandit form, so bandit skipped nothing.
        ("a,b", "a,b/x.py", False),
        ("ven\ndor", "ven\ndor/x.py", False),
    ],
)
def test_the_matcher_hides_what_bandit_skipped(pattern, relative, hidden):
    assert _hides(pattern, relative) is hidden


@pytest.mark.parametrize(
    ("pattern", "relative"),
    [
        ("vendor", "vendor/a.py"),
        ("vendor", "src/x/vendor/a.py"),
        ("app.py", "deep/app.py"),
        ("*.pyc", "a/b/c.pyc"),
        ("home", "src/app.py"),
        ("", "app.py"),
    ],
)
def test_the_matcher_and_the_argument_agree(pattern, relative):
    """One builder: what the matcher hides is what the globs bandit got match."""
    absolute = f"{ROOT}/{relative}"
    globs = bandit_excluded_path_globs(ROOT, pattern)
    bandit_skips = any(
        fnmatch.fnmatchcase(absolute, entry) or entry in absolute for entry in globs
    )
    assert bandit_would_skip(pattern, relative=relative, absolute=absolute) is (
        bandit_skips
    )


def test_a_finding_whose_root_cannot_be_read_is_not_hidden():
    """An absolute URI the SARIF step could not make relative names no root."""
    assert (
        _exclusion("vendor").hides(
            relative="/elsewhere/vendor/a.py",
            absolute="/elsewhere/vendor/a.py",
            rule_id=None,
        )
        is False
    )


@pytest.mark.skipif(os.sep != "\\", reason="a backslash separates segments on Windows")
def test_a_windows_spelled_relative_path_is_read():
    assert (
        bandit_would_skip(
            "vendor", relative="src\\vendor\\a.py", absolute=f"{ROOT}/src/vendor/a.py"
        )
        is True
    )


@pytest.mark.skipif(os.sep != "/", reason="a backslash is a separator on Windows")
def test_a_posix_backslash_is_part_of_the_file_name():
    """bandit matched its globs against ``vendor\\x.py`` as walked, and did not
    skip it for an entry naming ``vendor/x.py``; the matcher rewrote the
    backslash to ``/`` on every platform and hid the finding."""
    assert (
        bandit_would_skip(
            "vendor/x.py", relative="vendor\\x.py", absolute=f"{ROOT}/vendor\\x.py"
        )
        is False
    )
    assert (
        bandit_would_skip(
            "vendor/x.py", relative="vendor/x.py", absolute=f"{ROOT}/vendor/x.py"
        )
        is True
    )
