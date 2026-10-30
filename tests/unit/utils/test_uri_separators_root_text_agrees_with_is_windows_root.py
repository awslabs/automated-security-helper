# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""root_text and is_windows_root (utils/uri_separators.py) read the same roots.

A UNC root spelled with leading forward slashes and backslash separators,
``//server/share\\ws``, was a Windows root to is_windows_root, so every URI under
it had its backslashes made ``/``, while root_text converted the drive form only
and kept the root's own backslash, so nothing under it matched the root.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils.uri_separators import (
    is_windows_root,
    root_text,
    sanitized_uri_text,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("root", "expected"),
    [
        ("//server/share\\ws", "//server/share/ws"),
        ("/\\server/share\\ws\\api", "//server/share/ws/api"),
        ("\\\\server\\share\\ws", "//server/share/ws"),
        ("C:\\ws\\api", "C:/ws/api"),
    ],
)
def test_a_root_is_windows_root_reads_as_windows_is_spelled_with_slashes(
    root, expected
):
    assert is_windows_root(root), "the control: is_windows_root reads it as Windows"
    assert root_text(root) == expected
    assert sanitized_uri_text("src\\a.py", root) == "src/a.py"


@pytest.mark.parametrize("root", ["/ws/a\\b", "/server/share\\x", "///x/y\\z"])
def test_a_posix_root_keeps_its_backslash_in_both_readings(root):
    assert not is_windows_root(root)
    assert root_text(root) == root
