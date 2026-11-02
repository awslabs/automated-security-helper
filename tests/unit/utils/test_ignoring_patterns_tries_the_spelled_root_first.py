# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ignoring_patterns`` matches a path below the source directory as spelled first.

The source directory is tried as spelled and with its links resolved. The two were
a set, iterated in hash order, so a path below both (here the source directory
spelled through a link to its own parent) was matched by one relative path in one
process and by the other in the next, and whether an ignore path ignored it varied
run to run. The spelling the scan set uses is tried first now, every time.

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils.link_exclusions import ignoring_patterns

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
]


def _ignore(*patterns: str):
    return [SimpleNamespace(path=pattern) for pattern in patterns]


def test_a_path_below_both_spellings_is_matched_below_the_spelled_root(tmp_path):
    real = Path(os.path.realpath(tmp_path)) / "repo"
    real.mkdir()
    (real / "self").symlink_to(".", target_is_directory=True)
    source = real / "self"
    path = source / "x.js"
    path.write_text("", encoding="utf-8")

    for _ in range(20):
        ignored = ignoring_patterns([str(path)], source, _ignore("self/x.js", "x.js"))

        assert ignored == {str(path): "x.js"}


def test_control_a_path_below_the_real_root_only_is_still_matched(tmp_path):
    real = Path(os.path.realpath(tmp_path)) / "repo"
    (real / "sub").mkdir(parents=True)
    (tmp_path / "alias").symlink_to(real, target_is_directory=True)
    path = real / "sub" / "x.js"

    ignored = ignoring_patterns([str(path)], tmp_path / "alias", _ignore("sub/x.js"))

    assert ignored == {str(path): "sub/x.js"}
