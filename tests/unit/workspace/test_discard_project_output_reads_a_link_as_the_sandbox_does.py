# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An abandoned project's output is discarded reading links as the sandbox reads them.

``_discard_project_output`` removes the results file and the reports directory
under ``projects/<key>/``, and unlinks a link at either name without following
it. It asked ``Path.is_symlink()``, which is False for a Windows junction, so a
junction at ``reports`` was taken for the directory it points at and removed
through, deleting what is in the target. It now reads each entry with
``os.lstat`` and the sandbox's ``_is_link_stat``, which names a junction.
"""

from __future__ import annotations

import os
import stat
import subprocess

import pytest

from automated_security_helper.utils import scanned_tree
from automated_security_helper.workspace.execution import (
    RESULTS_FILENAME,
    _discard_project_output,
)

pytestmark = pytest.mark.unit


def test_each_scan_output_entry_is_read_with_the_sandbox_link_reader(
    tmp_path, monkeypatch
):
    output = tmp_path / "out"
    (output / "reports").mkdir(parents=True)
    (output / "reports" / "ash.sarif").write_text("{}", encoding="utf-8")
    (output / RESULTS_FILENAME).write_text("{}", encoding="utf-8")
    (output / "scanners").mkdir()
    (output / "scanners" / "raw.json").write_text("{}", encoding="utf-8")
    seen = []
    real = scanned_tree._is_link_stat

    def recording(info):
        seen.append(stat.S_ISDIR(info.st_mode))
        return real(info)

    monkeypatch.setattr(scanned_tree, "_is_link_stat", recording)

    _discard_project_output(output)

    # RED at the base: the entries were asked Path.is_symlink() and the reader
    # was never consulted.
    assert sorted(seen) == [False, True]
    assert not (output / RESULTS_FILENAME).exists()
    assert not (output / "reports").exists()
    # Not one of the two names: left as it was.
    assert (output / "scanners" / "raw.json").is_file()


def test_a_symlink_at_a_scan_output_name_goes_and_its_target_stays(tmp_path):
    """Control, green on both sides: a link is unlinked and never followed."""
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "keep.txt").write_text("kept", encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    try:
        (output / "reports").symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this host cannot make a symlink")

    _discard_project_output(output)

    assert not (output / "reports").is_symlink()
    assert (target / "keep.txt").read_text(encoding="utf-8") == "kept"


@pytest.mark.skipif(os.name != "nt", reason="a junction is a Windows reparse point")
def test_a_junction_at_a_scan_output_name_goes_and_its_target_stays(tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "keep.txt").write_text("kept", encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(output / "reports"), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if made.returncode != 0:
        pytest.skip(f"this host cannot make a junction: {made.stdout}{made.stderr}")

    _discard_project_output(output)

    assert not (output / "reports").exists()
    assert (target / "keep.txt").read_text(encoding="utf-8") == "kept"
