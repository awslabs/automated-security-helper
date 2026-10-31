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


def _tree(tmp_path) -> Path:
    base = Path(os.path.realpath(tmp_path))
    (base / ".ash" / "ash_output").mkdir(parents=True)
    return base


@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_the_spelling_on_disk_is_kept_over_one_that_sorts_first(
    tmp_path, monkeypatch, platform
):
    base = _tree(tmp_path)
    this_run = base / ".ASH" / "ash_output"
    earlier = base / ".ash" / "ash_output"
    monkeypatch.setattr(sys, "platform", platform)

    kept = _one_spelling_each({this_run, earlier})

    assert kept == {earlier}


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
    assert _one_spelling_each({sorts_first, on_disk}) == {on_disk}
    assert _one_spelling_each({on_disk, sorts_first}) == {on_disk}


@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_control_with_neither_spelling_on_disk_the_first_in_sorted_order_is_kept(
    tmp_path, monkeypatch, platform
):
    base = Path(os.path.realpath(tmp_path))
    first = base / ".ASH" / "ash_output"
    second = base / ".ash" / "ash_output"
    monkeypatch.setattr(sys, "platform", platform)

    assert _one_spelling_each({first, second}) == {first}


def test_control_on_linux_two_spellings_are_two_directories(tmp_path, monkeypatch):
    base = _tree(tmp_path)
    this_run = base / ".ASH" / "ash_output"
    earlier = base / ".ash" / "ash_output"
    monkeypatch.setattr(sys, "platform", "linux")

    assert _one_spelling_each({this_run, earlier}) == {this_run, earlier}


def test_a_component_that_cannot_be_listed_is_not_on_disk(tmp_path, monkeypatch):
    base = _tree(tmp_path)

    def refused(path):
        raise PermissionError(13, "Permission denied", os.fspath(path))

    monkeypatch.setattr(scan_output_dirs.os, "listdir", refused)

    assert not scan_output_dirs._spelled_as_on_disk(base / ".ash" / "ash_output")
