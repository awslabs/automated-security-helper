# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Where two spellings name one output directory, the one on disk is kept.

On macOS and Windows names compare without regard to case, so this run's output
directory spelled ``.ASH/ash_output`` and an earlier run's ``.ash/ash_output``,
which is what the file system holds, are one directory. ``_one_spelling_each``
keeps one of the two, and the scanners' exclusions are built from it. It kept the
first in sorted order, which puts ``.ASH`` before ``.ash``: tools that match an
exclusion case-exactly against the names on disk (syft, grype, trivy) then missed
ASH's own reports. The spelling the file system holds is kept; with neither on
disk, or both, the first in sorted order as before.

The fixtures are real directories made in the case this host accepts, and the
platform is patched after they exist, so a case-sensitive file system lists only
the spelling that was made, as a case-insensitive one lists the spelling it
stores.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils import scan_output_dirs
from automated_security_helper.utils.scan_output_dirs import _one_spelling_each

pytestmark = pytest.mark.unit


class _FoldedPath(type(Path())):
    """A path that compares and hashes without regard to case, as pathlib's
    Windows paths do, so a set or a dict keyed by them holds one entry for two
    spellings of a directory on any host. Equality under it says nothing about
    which spelling was kept, so the tests compare ``str``."""

    def __eq__(self, other):
        return str(self).casefold() == str(other).casefold()

    def __hash__(self):
        return hash(str(self).casefold())


def _tree(tmp_path) -> Path:
    base = Path(os.path.realpath(tmp_path))
    (base / ".ash" / "ash_output").mkdir(parents=True)
    return base


def _texts(paths) -> list:
    return sorted(str(path) for path in paths)


@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_the_spelling_on_disk_is_kept_over_one_that_sorts_first(
    tmp_path, monkeypatch, platform
):
    base = _tree(tmp_path)
    this_run = base / ".ASH" / "ash_output"
    earlier = base / ".ash" / "ash_output"
    monkeypatch.setattr(sys, "platform", platform)

    kept = _one_spelling_each([this_run, earlier])

    # Compared as text: where pathlib folds case, ``{earlier}`` equals
    # ``{this_run}`` and a set comparison would pass whichever was kept.
    assert _texts(kept) == [str(earlier)]


@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_the_answer_does_not_depend_on_the_order_the_spellings_arrive_in(
    tmp_path, monkeypatch, platform
):
    base = _tree(tmp_path)
    on_disk = base / ".ash" / "ash_output"
    sorts_first = base / ".asH" / "ash_output"
    monkeypatch.setattr(sys, "platform", platform)

    # ``.asH`` sorts before ``.ash`` (H is below h) whichever way round the two
    # reach the function.
    assert _texts(_one_spelling_each([sorts_first, on_disk])) == [str(on_disk)]
    assert _texts(_one_spelling_each([on_disk, sorts_first])) == [str(on_disk)]


@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_control_with_neither_spelling_on_disk_the_first_in_sorted_order_is_kept(
    tmp_path, monkeypatch, platform
):
    base = Path(os.path.realpath(tmp_path))
    first = base / ".ASH" / "ash_output"
    second = base / ".ash" / "ash_output"
    monkeypatch.setattr(sys, "platform", platform)

    assert _texts(_one_spelling_each([first, second])) == [str(first)]


def test_control_on_linux_two_spellings_are_two_directories(tmp_path, monkeypatch):
    base = _tree(tmp_path)
    this_run = base / ".ASH" / "ash_output"
    earlier = base / ".ash" / "ash_output"
    monkeypatch.setattr(sys, "platform", "linux")

    kept = _one_spelling_each([this_run, earlier])

    assert _texts(kept) == _texts([this_run, earlier])


@pytest.mark.parametrize("owned", [True, False], ids=["named", "scanned"])
def test_both_spellings_reach_the_choice_where_paths_compare_without_case(
    tmp_path, monkeypatch, owned
):
    base = _tree(tmp_path)
    root = _FoldedPath(base)
    this_run = root / ".ASH" / "ash_output"
    earlier = root / ".ash" / "ash_output"
    # The fixture folds as pathlib does on Windows: a set holds one of the two.
    assert this_run == earlier
    assert len({this_run, earlier}) == 1
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(
        scan_output_dirs,
        "_output_dir_candidates_with_owner",
        lambda *args: [(this_run, owned), (earlier, owned)],
    )
    monkeypatch.setattr(
        scan_output_dirs, "_spelled_under", lambda candidate, *rest: candidate
    )
    monkeypatch.setattr(
        scan_output_dirs, "_an_enclosing_repository_lists", lambda directory: False
    )

    named, scanned = scan_output_dirs._classified_output_dirs(base, this_run)

    # The earlier run's ``.ash`` is what the file system holds and the tools
    # match exclusions against: it is the spelling kept, in whichever list the
    # directory belongs to, and the other list holds nothing.
    kept, other = (named, scanned) if owned else (scanned, named)
    assert _texts(kept) == [str(earlier)]
    assert _texts(other) == []


def test_a_component_that_cannot_be_listed_is_not_on_disk(tmp_path, monkeypatch):
    base = _tree(tmp_path)

    def refused(path):
        raise PermissionError(13, "Permission denied", os.fspath(path))

    monkeypatch.setattr(scan_output_dirs.os, "listdir", refused)

    assert not scan_output_dirs._spelled_as_on_disk(base / ".ash" / "ash_output")
