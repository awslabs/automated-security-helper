# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""On macOS and Windows a results path is matched without regard to case.

A scan clears ``reports/`` and the other working directories with
``shutil.rmtree`` when it starts. The default filesystems of macOS (APFS, HFS+)
and Windows (NTFS) compare names without case, so a committed
``.ash/ash_output/Reports/x.md`` is inside the directory that rmtree removes. Were
the check that refuses a scan over committed files to compare git's names with
``reports`` exactly, that file would not be counted, and the scan would delete it.

The names are compared casefolded on macOS and Windows. Linux compares names
exactly, and there ``Reports`` is a directory of its own that a scan never
touches, so it is not counted. The same rule applies to what is counted on disk
when git cannot say what is committed.

The comparison depends on the names and ``sys.platform`` alone, so these tests
run on any platform with ``sys.platform`` set.
"""

from __future__ import annotations

import sys

import pytest

from automated_security_helper.core.exceptions import CommittedOutputFilesError
from automated_security_helper.utils.scan_output_dirs import (
    committed_files_at_results_paths,
)
from tests.unit.test_committed_output_refused_at_entry_points import _repo
from tests.unit.workspace.test_execution import _git

#: Committed with a case the scan's own names do not have.
OTHER_CASE = {
    "Reports/x.md": "committed report\n",
    "ASH_Aggregated_Results.json": "{}\n",
    "Scanners/Bandit/out.sarif": "{}\n",
}


@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_a_committed_name_in_another_case_is_counted_on_macos_and_windows(
    tmp_path, monkeypatch, platform
):
    source, output = _repo(tmp_path, monkeypatch, committed=OTHER_CASE)
    monkeypatch.setattr(sys, "platform", platform)

    found = committed_files_at_results_paths(output)

    assert [p.relative_to(output).as_posix() for p in found] == sorted(OTHER_CASE)


def test_a_committed_name_in_another_case_is_not_counted_on_linux(
    tmp_path, monkeypatch
):
    source, output = _repo(tmp_path, monkeypatch, committed=OTHER_CASE)
    monkeypatch.setattr(sys, "platform", "linux")

    assert committed_files_at_results_paths(output) == []


@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_a_scoped_check_keeps_a_name_in_another_case(tmp_path, monkeypatch, platform):
    """A report over existing results is checked only where it writes; ``Reports/``
    is where it writes on these platforms."""
    from automated_security_helper.core.committed_output import (
        committed_entries_in_the_way,
    )

    source, output = _repo(tmp_path, monkeypatch, committed=OTHER_CASE)
    monkeypatch.setattr(sys, "platform", platform)

    found = committed_entries_in_the_way(
        output, files=("ash_aggregated_results.json",), directories=("reports",)
    )

    assert [p.relative_to(output).as_posix() for p in found] == [
        "ASH_Aggregated_Results.json",
        "Reports/x.md",
    ]


@pytest.mark.parametrize(
    ("platform", "counted"), [("darwin", True), ("win32", True), ("linux", False)]
)
def test_the_workspace_spool_is_matched_the_same_way(
    tmp_path, monkeypatch, platform, counted
):
    """A workspace scan removes its spool with shutil.rmtree too."""
    from automated_security_helper.core.committed_output import (
        WORKSPACE_SPOOL_DIR_NAME,
        committed_entries_under,
    )

    source, output = _repo(
        tmp_path, monkeypatch, committed={".Workspace-Spool/api.run.json": "{}\n"}
    )
    monkeypatch.setattr(sys, "platform", platform)

    found = committed_entries_under(output, (WORKSPACE_SPOOL_DIR_NAME,))

    assert [p.relative_to(output).as_posix() for p in found] == (
        [".Workspace-Spool/api.run.json"] if counted else []
    )


@pytest.mark.parametrize(
    ("platform", "refused"), [("darwin", True), ("win32", True), ("linux", False)]
)
def test_the_on_disk_count_compares_names_the_same_way(
    tmp_path, monkeypatch, platform, refused
):
    """When git cannot answer, what is on disk is counted, by the same rule."""
    from automated_security_helper.core.committed_output import (
        committed_entries_in_the_way,
    )

    source, output = _repo(tmp_path, monkeypatch, committed={"keep.txt": "kept\n"})
    (output / "Reports").mkdir()
    (output / "Reports" / "old.md").write_text("old\n", encoding="utf-8")
    assert _git(source, "config", "core.repositoryformatversion", "99").returncode == 0
    monkeypatch.setattr(sys, "platform", platform)

    if refused:
        with pytest.raises(CommittedOutputFilesError) as refusal:
            committed_entries_in_the_way(output)
        assert "Reports/old.md" in str(refusal.value)
    else:
        assert committed_entries_in_the_way(output) == []
