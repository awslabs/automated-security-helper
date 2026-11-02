# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A committed link at the workspace's ``projects`` directory refuses the scan.

The workspace check looked inside each project's output directory, at the root
results file and ``reports/``, and under the spool, but never at ``projects``
itself. git tracks a directory name only as a link, so a committed link there
let a workspace scan clear and write every project's output through it. The
check now asks git about that one entry. git is not run here: the index answer
is the fake, the one shape ``git_index_below`` returns.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.core import committed_output as committed_output_module
from automated_security_helper.core.committed_output import (
    WORKSPACE_PROJECTS_DIR_NAME,
    committed_entries_in_a_workspace_output,
)
from automated_security_helper.utils.scan_output_dirs import GitIndexAnswer

pytestmark = pytest.mark.unit


def _fake_git(monkeypatch, output: Path, names: list[str]) -> None:
    monkeypatch.setattr(
        committed_output_module,
        "git_index_below",
        lambda directory, **_kw: GitIndexAnswer(
            base=Path(directory).resolve(), names=list(names), repository=output
        ),
    )


def test_a_tracked_projects_entry_is_a_committed_entry(tmp_path, monkeypatch):
    output = (tmp_path / "out").resolve()
    output.mkdir()
    _fake_git(monkeypatch, output, [WORKSPACE_PROJECTS_DIR_NAME])

    found = committed_entries_in_a_workspace_output(
        output, [output / WORKSPACE_PROJECTS_DIR_NAME / "api"]
    )

    # Red at the base: nothing looked at the entry itself, so [].
    assert found == [output / WORKSPACE_PROJECTS_DIR_NAME]


def test_a_tracked_file_under_projects_is_not_the_entry_itself(tmp_path, monkeypatch):
    """The control: a file under projects/ is a project's own check, not this one."""
    output = (tmp_path / "out").resolve()
    output.mkdir()
    _fake_git(monkeypatch, output, [f"{WORKSPACE_PROJECTS_DIR_NAME}/api/README.md"])

    found = committed_entries_in_a_workspace_output(
        output, [output / WORKSPACE_PROJECTS_DIR_NAME / "api"]
    )

    assert found == []


def test_the_projects_name_agrees_with_the_workspace_modules():
    from automated_security_helper.workspace import execution, reporting

    assert WORKSPACE_PROJECTS_DIR_NAME == execution.PROJECTS_DIR_NAME
    assert WORKSPACE_PROJECTS_DIR_NAME == reporting.PROJECTS_DIR_NAME
