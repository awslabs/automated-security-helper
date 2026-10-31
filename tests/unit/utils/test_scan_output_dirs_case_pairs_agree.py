# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every pairing of a name-key comparison with a text one in ``scan_output_dirs``.

``_strictly_inside`` compares each name as the filesystem does (``output_name_key``),
so on macOS and Windows ``Repo/out`` is inside ``repo``. The code that then took
the path apart used ``relative_to`` and ``is_relative_to``, which compare by
text: for exactly the inputs where the two comparisons differ, ``relative_to``
raised ``ValueError`` out of ``output_dirs_inside`` and ``_spelled_under`` (the
latter inside ``_classified_output_dirs``, which ``scan_set_of`` turns into a
refusal), and ``is_relative_to`` quietly skipped the link check of a candidate
the key comparison had placed inside. Each pairing now goes through
``_parts_below``, which agrees with ``_strictly_inside`` by construction, and a
candidate spelled under the root in another case is spelled under the root.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.scan_output_dirs import (
    _parts_below,
    _reached_through_a_link,
    _repository_root_of,
    _spelled_under,
    classified_output_dirs,
    entries_at_results_paths,
    output_dirs_inside,
)
from tests.utils.scan_output_support import needs_symlinks

pytestmark = pytest.mark.unit


@pytest.fixture
def folding(tmp_path, monkeypatch):
    """A platform whose filesystem compares names without case, with no git.

    ``sys.platform`` is patched for the whole process, so anything that starts a
    program while a test runs sees a macOS platform, and a test that reached git
    ran the real one against whatever repository sits above the temporary
    directory (the developer's checkout, under ``--basetemp`` inside it). The
    test directory is therefore a ceiling for the search for a repository, and a
    spawn is recorded and refused: the code under test turns a refused spawn into
    "git could not be run", so the record is what fails the test. A test that
    needs git answers sets its own stand-in over this one."""
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", os.path.realpath(tmp_path))
    started: list = []

    def refused(argv, **_kwargs):
        started.append(list(argv))
        raise AssertionError(f"git was started: {argv}")

    monkeypatch.setattr(subprocess_utils, "spawn_run", refused)
    yield
    assert started == []


def test_the_folding_platform_searches_for_no_repository_above_the_test_directory(
    folding, tmp_path
):
    tree = Path(os.path.realpath(tmp_path))
    (tree / ".git").mkdir()
    (tree / "src").mkdir()

    assert _repository_root_of(tree / "src") is None


def test_parts_below_agrees_with_the_name_key_comparison(folding):
    assert _parts_below(Path("/a/Repo/out/x"), Path("/a/repo")) == ("out", "x")
    assert _parts_below(Path("/a/repo"), Path("/a/Repo")) == ()
    assert _parts_below(Path("/a/other/x"), Path("/a/repo")) is None


def test_control_on_linux_another_case_is_another_directory(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")

    assert _parts_below(Path("/a/Repo/out"), Path("/a/repo")) is None
    assert _parts_below(Path("/a/repo/out"), Path("/a/repo")) == ("out",)


def test_output_dirs_inside_does_not_raise_for_a_directory_in_another_case(folding):
    # Spelled from the host's own root: output_dirs_inside makes the target
    # absolute with os.path.abspath, which on Windows adds the drive, so a
    # drive-less literal on the other side compared unequal before any name
    # was read and the directory read as outside.
    base = Path(os.path.abspath("/a"))

    inside = output_dirs_inside(
        [base / "Repo" / "out", base / "elsewhere"], base / "repo"
    )

    assert inside == [Path("out")]


def test_a_candidate_in_another_case_is_spelled_under_the_root(folding):
    root = Path("/a/Repo")

    assert _spelled_under(Path("/a/repo/out"), root, root) == Path("/a/Repo/out")


def test_a_resolved_candidate_in_another_case_is_spelled_under_the_root(
    folding, tmp_path
):
    tree = Path(os.path.realpath(tmp_path))
    root = tree / "Repo"
    root.mkdir()

    spelled = _spelled_under(tree / "repo" / "out", root, root)

    assert spelled == root / "out"


def test_two_spellings_of_one_named_directory_leave_one_named(
    folding, tmp_path, monkeypatch
):
    """On a filesystem that compares names without case, this run's output
    directory spelled ``.ASH/ash_output`` and the earlier run's ``.ash/ash_output``
    on disk are one directory. Each read as "below" the other by name key, so the
    reduction to the outermost directories dropped both and no output directory
    was named: nothing was excluded and ASH's own output was scanned."""
    root = Path(os.path.realpath(tmp_path)) / "repo"
    (root / ".git").mkdir(parents=True)
    (root / ".ash" / "ash_output").mkdir(parents=True)
    monkeypatch.setattr(
        subprocess_utils,
        "spawn_run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
    )
    monkeypatch.chdir(root)

    named, scanned = classified_output_dirs(
        root, output_dir=root / ".ASH" / "ash_output"
    )

    assert len(named) == 1
    assert named[0].parts[-2:] in ((".ASH", "ash_output"), (".ash", "ash_output"))
    assert scanned == []


@needs_symlinks
def test_reached_through_a_link_walks_from_a_base_in_another_case(folding, tmp_path):
    tree = Path(os.path.realpath(tmp_path))
    (tree / "Repo" / ".ash").mkdir(parents=True)
    (tree / "elsewhere").mkdir()
    (tree / "Repo" / ".ash" / "ash_output").symlink_to(
        tree / "elsewhere", target_is_directory=True
    )

    assert _reached_through_a_link(tree / "repo" / ".ash" / "ash_output", tree / "Repo")
    assert not _reached_through_a_link(tree / "other" / "x", tree / "Repo")


def test_entries_at_results_paths_take_names_apart_by_key(folding):
    found = entries_at_results_paths(
        Path("/a/repo"), ["ash_aggregated_results.json", "Reports/x.json", "src/a.py"]
    )

    # pathlib orders paths by its own platform rule (case-exact on POSIX, folded
    # on Windows), so the expectation is sorted the same way the function sorts.
    assert found == sorted(
        [
            Path("/a/repo/Reports/x.json"),
            Path("/a/repo/ash_aggregated_results.json"),
        ]
    )


def test_classified_output_dirs_names_a_directory_given_in_another_case(
    folding, tmp_path
):
    tree = Path(os.path.realpath(tmp_path))
    root = tree / "Repo"
    (root / "out").mkdir(parents=True)

    named, scanned = classified_output_dirs(root, tree / "repo" / "out")

    assert named == [root / "out"]
    assert scanned == []
