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
sides after the pass, and drives the second check by making the walk yield a
file below the link, since the ordinary walk never reaches it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from automated_security_helper.workspace.execution import _mask_project_output

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
]


#: A value of the shape the masking propagates to other files: at least
#: ``MIN_PROPAGATED_VALUE_LENGTH`` characters, not letters alone, not repetitive
#: (``secret_masking._propagates``). A short word-like value such as ``hunter2``
#: is below that floor and is left where it stands, so a test that plants one
#: measures the floor, not the walk.
VALUE = "zzReportValue0071Kq"


def test_a_report_behind_a_linked_directory_is_left_as_it_was(tmp_path):
    project_output = tmp_path / "out" / "projects" / "api"
    (project_output / "reports").mkdir(parents=True)
    inside = project_output / "reports" / "ash.summary.txt"
    inside.write_text(f"token={VALUE}\n", encoding="utf-8")
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    reached = outside / "notes.txt"
    reached.write_text(f"token={VALUE}\n", encoding="utf-8")
    (project_output / "linked").symlink_to(outside, target_is_directory=True)

    _mask_project_output(project_output, {VALUE}, [])

    # The report inside the tree is masked; the file behind the link is not
    # touched, and the link itself still points where it did.
    assert VALUE not in inside.read_text(encoding="utf-8")
    assert reached.read_text(encoding="utf-8") == f"token={VALUE}\n"
    assert (project_output / "linked").is_symlink()
    assert (project_output / "linked").resolve() == outside.resolve()


def test_a_file_whose_ancestor_became_a_link_is_refused_by_the_second_check(
    tmp_path, monkeypatch
):
    """The defence in depth, driven: the walk is made to yield a file below the
    link (a directory replaced by a link between the walk and the read), and the
    ancestor-is-a-link check refuses it. The case above never reaches this check,
    because ``rglob`` does not descend into the link, so deleting the check left
    that case green; this one goes red without it."""
    project_output = tmp_path / "out" / "projects" / "api"
    (project_output / "reports").mkdir(parents=True)
    inside = project_output / "reports" / "ash.summary.txt"
    inside.write_text(f"token={VALUE}\n", encoding="utf-8")
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    reached = outside / "notes.txt"
    reached.write_text(f"token={VALUE}\n", encoding="utf-8")
    (project_output / "linked").symlink_to(outside, target_is_directory=True)
    below_the_link = project_output / "linked" / "notes.txt"
    real_rglob = Path.rglob

    def rglob_through_the_link(self, pattern, *args, **kwargs):
        yield from real_rglob(self, pattern, *args, **kwargs)
        if self == project_output:
            yield below_the_link

    monkeypatch.setattr(Path, "rglob", rglob_through_the_link)

    _mask_project_output(project_output, {VALUE}, [])

    assert VALUE not in inside.read_text(encoding="utf-8")
    assert reached.read_text(encoding="utf-8") == f"token={VALUE}\n", (
        "the file below the link was rewritten through it"
    )


def test_a_value_below_the_propagation_floor_is_left_in_the_report(tmp_path):
    """Must-not-flag control: the walk reaches the file, the floor keeps the value."""
    project_output = tmp_path / "out" / "projects" / "api"
    (project_output / "reports").mkdir(parents=True)
    inside = project_output / "reports" / "ash.summary.txt"
    inside.write_text("token=hunter2\n", encoding="utf-8")

    _mask_project_output(project_output, {"hunter2"}, [])

    assert inside.read_text(encoding="utf-8") == "token=hunter2\n"
