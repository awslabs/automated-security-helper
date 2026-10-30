# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The masking pass over a project's output never writes through a linked directory.

Why this file exists
--------------------
``_mask_project_output`` walks ``projects/<key>/`` with ``rglob`` and rewrites
every report that carries a value another project exposed. A directory link
under that tree points outside it; a rewrite of a file reached through the link
would land in whatever the link reaches. pathlib's ``**`` does not descend into
a linked directory, and the pass also refuses a file whose ancestor is a link
(a directory replaced by a link between the walk and the read), as defence in
depth. The existing masking tests replace the pass wholesale, so neither
property was measured: this one builds a real linked directory and reads both
sides after the pass.
"""

from __future__ import annotations

import sys

import pytest

from automated_security_helper.workspace.execution import _mask_project_output

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
]


def test_a_report_behind_a_linked_directory_is_left_as_it_was(tmp_path):
    project_output = tmp_path / "out" / "projects" / "api"
    (project_output / "reports").mkdir(parents=True)
    inside = project_output / "reports" / "ash.summary.txt"
    inside.write_text("token=hunter2\n", encoding="utf-8")
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    reached = outside / "notes.txt"
    reached.write_text("token=hunter2\n", encoding="utf-8")
    (project_output / "linked").symlink_to(outside, target_is_directory=True)

    _mask_project_output(project_output, {"hunter2"}, [])

    # The report inside the tree is masked; the file behind the link is not
    # touched, and the link itself still points where it did.
    assert "hunter2" not in inside.read_text(encoding="utf-8")
    assert reached.read_text(encoding="utf-8") == "token=hunter2\n"
    assert (project_output / "linked").is_symlink()
    assert (project_output / "linked").resolve() == outside.resolve()
