# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Five readings of ``scan_output_dirs`` about which paths a scan deletes or excludes.

- ``.ash_previous_results.restoring``, which ``core/previous_results.py`` moves
  and deletes, was absent from the names the committed-output refusal and the
  output-directory exclusions cover, so tracked files there were removed without
  the refusal; it is one of :func:`ash_own_dir_names` now.
- ``_strictly_inside`` compared paths as text, so on macOS and Windows an output
  directory spelled in another case than the source read as outside the tree;
  it compares each name as the filesystem does (``output_name_key``).
- Inside the container, the host output directory's path relative to the host's
  source was joined onto the scan root; in a workspace scan that root is one
  project's directory below the ``/src`` mount, so a directory inside the project
  was named as this run's output and the real one was missed. It is joined onto
  the mount.
- ``output_dirs_to_exclude`` worked from the outermost named directories only, so
  this run's output directory nested inside an earlier run's ``.ash/ash_output``
  that holds a committed file was never excluded, and every directory-walking
  tool read ASH's in-progress output; each named directory is now excluded on
  its own.
- ``_result_paths`` asked ``Path.exists`` about the still-encoded URI, which
  raises on CPython 3.10-3.12 for a component longer than NAME_MAX, ending the
  scanner's result handling; the question now answers False.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.core.previous_results import RESTORING_DIR_NAME
from automated_security_helper.utils import scan_output_dirs
from automated_security_helper.utils.scan_output_dirs import (
    GitIndexAnswer,
    _host_output_dir_in_the_tree,
    _result_paths,
    _strictly_inside,
    ash_own_dir_names,
    entries_at_results_paths,
    output_dirs_to_exclude,
    results_path_names,
)

pytestmark = pytest.mark.unit


def test_the_restore_staging_directory_is_among_the_names_a_scan_deletes():
    assert RESTORING_DIR_NAME in ash_own_dir_names()
    assert RESTORING_DIR_NAME in results_path_names()[1]


def test_a_committed_file_under_the_restore_staging_directory_is_at_a_results_path(
    tmp_path,
):
    found = entries_at_results_paths(
        tmp_path, [f"{RESTORING_DIR_NAME}/ash_aggregated_results.json", "README.md"]
    )

    assert found == [tmp_path / RESTORING_DIR_NAME / "ash_aggregated_results.json"]


@pytest.mark.parametrize(
    "platform, inside",
    [("darwin", True), ("win32", True), ("linux", False)],
)
def test_strictly_inside_compares_names_as_the_filesystem_does(
    monkeypatch, platform, inside
):
    monkeypatch.setattr(sys, "platform", platform)

    assert _strictly_inside(Path("/a/Out/x"), Path("/a/out")) is inside
    assert _strictly_inside(Path("/a/out/x"), Path("/a/out"))
    assert not _strictly_inside(Path("/a/out"), Path("/a/out"))
    assert not _strictly_inside(Path("/a/outer/x"), Path("/a/out"))


@pytest.mark.skipif(sys.platform == "win32", reason="the container mount is POSIX")
def test_the_host_output_dir_is_joined_onto_the_mount_not_the_project(monkeypatch):
    monkeypatch.setenv("ASH_ACTUAL_SOURCE_DIR", "/home/user/workspace")
    monkeypatch.setenv("ASH_ACTUAL_OUTPUT_DIR", "/home/user/workspace/out")

    assert _host_output_dir_in_the_tree(Path("/src/projects/api")) == Path("/src/out")
    assert _host_output_dir_in_the_tree(Path("/src")) == Path("/src/out")
    assert _host_output_dir_in_the_tree(Path("/other")) == Path("/other/out")


def test_a_named_dir_nested_in_one_holding_a_committed_file_is_excluded_whole(
    tmp_path, monkeypatch
):
    source = Path(os.path.realpath(tmp_path)) / "src"
    earlier = source / ".ash" / "ash_output"
    this_run = earlier / "run2"
    (this_run / "reports").mkdir(parents=True)
    (earlier / "README.md").write_text("committed\n", encoding="utf-8")
    (this_run / "reports" / "ash.sarif").write_text("{}", encoding="utf-8")
    monkeypatch.chdir(source)
    asked = []

    # The stand-in answers for the directory it is asked about: only the earlier
    # run's directory holds a committed file. One answer for every directory told
    # the code run2/README.md was committed too, which the fixture does not have,
    # so the assertion could not tell "excluded as this run's output" from
    # "excluded as a directory holding a committed file".
    def git_index_below(directory, **_):
        base = Path(os.path.abspath(directory))
        asked.append(base)
        names = ["README.md"] if base == earlier else []
        return GitIndexAnswer(base, names=names, repository=source)

    monkeypatch.setattr(scan_output_dirs, "git_index_below", git_index_below)

    excluded = output_dirs_to_exclude(
        source, output_dir=this_run, scanned_files=[earlier / "README.md"]
    )

    assert earlier in asked
    assert this_run in excluded
    assert earlier not in excluded
    assert earlier / "analysis" in excluded


def _located(uri: str) -> SimpleNamespace:
    return SimpleNamespace(
        locations=[
            SimpleNamespace(
                physicalLocation=SimpleNamespace(
                    root=SimpleNamespace(artifactLocation=SimpleNamespace(uri=uri))
                )
            )
        ]
    )


def test_an_encoded_name_longer_than_the_filesystem_allows_names_no_file(tmp_path):
    """The encoded spelling (900 characters) is what ``Path.exists`` raised on; it
    names no file, so the decoded name is resolved and yielded as the one path, as
    it is for any decoded name that is not on disk."""
    encoded = "%41" * 300 + ".py"

    paths = list(_result_paths(_located(encoded), tmp_path))

    assert paths == [Path(os.path.realpath(tmp_path)) / ("A" * 300 + ".py")]


def test_control_an_encoded_name_that_decodes_to_a_file_is_resolved(tmp_path):
    (tmp_path / "out(1)").mkdir()
    (tmp_path / "out(1)" / "x.tf").write_text("", encoding="utf-8")

    paths = list(_result_paths(_located("out%281%29/x.tf"), tmp_path))

    assert paths == [Path(os.path.realpath(tmp_path / "out(1)" / "x.tf"))]
