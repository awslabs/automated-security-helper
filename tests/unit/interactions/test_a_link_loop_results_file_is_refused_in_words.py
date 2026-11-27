# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A symbolic link loop named as ``existing_results`` is a worded refusal.

``Path.resolve()`` raises ``RuntimeError`` for a loop before Python 3.13; both
comparisons use ``os.path.realpath``, which answers the unresolved path, so the
loop is "not the output directory's own file" and a nix run refuses it with exit 3
rather than a traceback.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions import run_ash_scan as ras

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks"),
]


def _opts(tmp_path, existing):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return ras.ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=out,
        mode=RunMode.nix,
        existing_results=str(existing),
        progress=False,
        show_summary=False,
    )


def _loop(tmp_path):
    first = tmp_path / "loop-a.json"
    second = tmp_path / "loop-b.json"
    os.symlink(second, first)
    os.symlink(first, second)
    return first


def test_a_looping_link_is_refused_with_exit_3(tmp_path):
    opts = _opts(tmp_path, _loop(tmp_path))

    with pytest.raises(SystemExit) as refused:
        ras._refuse_a_results_file_the_shell_cannot_be_handed(opts, MagicMock())

    assert refused.value.code == 3


def test_a_looping_link_is_not_the_output_directorys_own_file(tmp_path):
    opts = _opts(tmp_path, _loop(tmp_path))

    assert ras._names_the_output_directorys_own_results(opts) is False


def test_the_output_directorys_own_file_is_still_accepted(tmp_path):
    # Control: the same call with the file --use-existing reads does not refuse.
    out = tmp_path / "out"
    out.mkdir()
    opts = _opts(tmp_path, out / "ash_aggregated_results.json")

    ras._refuse_a_results_file_the_shell_cannot_be_handed(opts, MagicMock())
    assert ras._names_the_output_directorys_own_results(opts) is True
