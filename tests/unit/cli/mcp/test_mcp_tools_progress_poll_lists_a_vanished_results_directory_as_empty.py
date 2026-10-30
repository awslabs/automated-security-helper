# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A progress poll lists a results directory that vanished as empty, not as an error.

``get_scan_progress`` lists ``scanners/<scanner>/<target>/`` under the output
directory of a scan that is running, or whose previous results are being set
aside: a directory that passed the check a moment ago can be renamed aside or
removed before it is listed, and ``iterdir`` then raised ``FileNotFoundError``,
which turned the poll into an unexpected-error reply. A directory that is gone
holds no results file to check, so it lists as empty and the poll goes on.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit


def test_a_scanners_directory_removed_after_its_check_lists_as_empty(
    tmp_path, monkeypatch
) -> None:
    from automated_security_helper.cli import mcp_tools

    output_dir = tmp_path / "ash_output"
    output_dir.mkdir()
    # The check passed a moment ago; the directory is gone by the time it is
    # listed (the scan renamed it aside).
    monkeypatch.setattr(
        mcp_tools, "resolves_to_directory_inside", lambda directory, output: True
    )

    files = mcp_tools._result_files_in(output_dir)

    assert files == [output_dir / "ash_aggregated_results.json"], files


def test_a_scanner_directory_removed_after_its_check_lists_as_empty(
    tmp_path, monkeypatch
) -> None:
    from automated_security_helper.cli import mcp_tools

    output_dir = tmp_path / "ash_output"
    scanners = output_dir / "scanners"
    (scanners / "bandit" / "source").mkdir(parents=True)
    gone = scanners / "semgrep"
    # Listed as an entry of scanners/, checked, and gone before its own listing.
    real = mcp_tools.resolves_to_directory_inside

    def checks_pass_for_the_vanished_one(directory, output):
        if directory == gone:
            return True
        return real(directory, output)

    monkeypatch.setattr(
        mcp_tools, "resolves_to_directory_inside", checks_pass_for_the_vanished_one
    )
    gone.mkdir()
    real_iterdir = type(gone).iterdir

    def iterdir_after_a_rename(self):
        if self == gone:
            gone.rmdir()
        return real_iterdir(self)

    monkeypatch.setattr(type(gone), "iterdir", iterdir_after_a_rename)

    files = mcp_tools._result_files_in(output_dir)

    assert files == [
        output_dir / "ash_aggregated_results.json",
        scanners / "bandit" / "source" / "ASH.ScanResults.json",
    ], files
