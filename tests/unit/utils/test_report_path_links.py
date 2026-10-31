# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ``utils/report_path_links.py`` examines, and what it leaves alone."""

from __future__ import annotations

import sys

import pytest

from automated_security_helper.utils.report_path_links import (
    ReportPathLinkRefused,
    is_report_file_name,
    linked_report_path,
    refuse_linked_report_paths,
)

pytestmark = pytest.mark.unit

#: Only the tests that make a symlink need this; the file-name tests below are
#: about text, and on Windows, where the name matters most, they must run.
needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


@pytest.mark.parametrize("name", ["ash.sarif", "ash.summary.md", ".hidden", "a..b"])
def test_a_single_component_is_a_report_file_name(name):
    assert is_report_file_name(name)


@pytest.mark.parametrize(
    "name", ["", ".", "..", "../x", "sub/x", "sub\\x", "x\x00", None, 3]
)
def test_anything_else_is_not(name):
    assert not is_report_file_name(name)


@pytest.mark.parametrize("name", ["ash.sarif:stream", "ash.sarif::$DATA", ":"])
def test_a_colon_names_an_ntfs_stream_of_another_file_and_is_refused(name):
    """``report.json:stream`` is the file ``report.json`` on NTFS, so a name with a
    colon passed the pre-run refusals while naming another reporter's report."""
    assert not is_report_file_name(name)


@pytest.mark.parametrize("name", ["C:report.md", "c:ash.sarif"])
def test_a_drive_prefix_is_refused_as_a_name_that_is_not_below_the_directory(name):
    """``C:report.md`` is not a stream: Windows reads it as ``report.md`` in the
    current directory of drive C, which joined under the reports directory does not
    stay in it. The colon rule refuses it too, for that reason."""
    assert not is_report_file_name(name)


@needs_symlinks
def test_a_dangling_link_is_a_link(tmp_path):
    (tmp_path / "ash.sarif").symlink_to(tmp_path / "missing")

    assert linked_report_path(tmp_path, ["ash.sarif"]) == (
        f"{(tmp_path / 'ash.sarif').as_posix()} is a symlink"
    )


@needs_symlinks
def test_a_link_to_a_file_inside_the_directory_is_a_link_too(tmp_path):
    (tmp_path / "ash.html").write_text("x", encoding="utf-8")
    (tmp_path / "ash.sarif").symlink_to(tmp_path / "ash.html")

    assert linked_report_path(tmp_path, ["ash.html", "ash.sarif"]) is not None


@needs_symlinks
def test_a_name_with_a_separator_is_not_examined(tmp_path):
    """ASH does not write such a name, so a link it would reach is no matter."""
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "x").symlink_to(tmp_path / "missing")
    (tmp_path / "x").symlink_to(tmp_path / "missing")

    assert linked_report_path(tmp_path / "sub", ["../x"]) is None


@needs_symlinks
def test_the_directory_is_examined_only_when_a_file_is_written_there(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "reports").symlink_to(tmp_path / "real", target_is_directory=True)

    assert linked_report_path(tmp_path / "reports", []) is None
    assert linked_report_path(tmp_path / "reports", ["../x"]) is None
    assert linked_report_path(tmp_path / "reports", ["ash.sarif"]) == (
        f"the reports directory {(tmp_path / 'reports').as_posix()} is a symlink"
    )


@needs_symlinks
def test_the_refusal_names_the_link_and_the_remedy(tmp_path):
    (tmp_path / "ash.sarif").symlink_to(tmp_path / "missing")

    with pytest.raises(ReportPathLinkRefused) as refused:
        refuse_linked_report_paths(tmp_path, ["ash.csv", "ash.sarif"])

    assert refused.value.found == f"{(tmp_path / 'ash.sarif').as_posix()} is a symlink"
    assert str(refused.value) == (
        f"{(tmp_path / 'ash.sarif').as_posix()} is a symlink. ASH does not write a "
        "report through a link. Remove the link and run ASH again."
    )


def test_nothing_is_refused_without_a_link(tmp_path):
    (tmp_path / "ash.sarif").write_text("x", encoding="utf-8")

    refuse_linked_report_paths(tmp_path, ["ash.sarif", "ash.csv"])
