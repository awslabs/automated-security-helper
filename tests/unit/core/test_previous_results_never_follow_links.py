# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Setting the previous results aside, dropping them and putting them back follow no link.

A scanned repository controls what sits in its own ``.ash/ash_output``, so any
entry the previous-results moves touch may be a symlink a repository planted:
the ``reports`` directory, the held set itself, an entry inside the held set, or
the staging directory. core/previous_results.py moves and removes each of them
as a link, never through it. Nothing tested that, so a change to ``_remove`` or
``_holding`` that followed a link would have passed. Each way of planting a link
is tried here with the scan finishing (the held set dropped) and failing (the
held set put back), and the data the link points at must be untouched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.core.previous_results import (
    HELD_DIR_NAME,
    RESTORED_MARKER_NAME,
    PreviousResults,
)

PLANTS = [
    "top_reports_link",
    "held_dir_link",
    "link_inside_held",
    "partial_link",
    "link_inside_partial",
]


def _outside(tmp_path: Path) -> Path:
    outside = tmp_path / "outside"
    (outside / "reports").mkdir(parents=True)
    (outside / "keep.txt").write_text("outside data", encoding="utf-8")
    (outside / "reports" / "keep2.txt").write_text("outside data 2", encoding="utf-8")
    return outside


def _plant(output: Path, outside: Path, plant: str) -> None:
    if plant == "top_reports_link":
        (output / "reports").symlink_to(outside, target_is_directory=True)
    elif plant == "held_dir_link":
        (output / HELD_DIR_NAME).symlink_to(outside, target_is_directory=True)
    elif plant == "link_inside_held":
        (output / HELD_DIR_NAME).mkdir()
        (output / HELD_DIR_NAME / "reports").symlink_to(
            outside, target_is_directory=True
        )
    elif plant == "link_inside_partial":
        # A staging directory is put back by the next set_aside: the link in it
        # is moved as a link, and the new scan's reports are not written there.
        (output / (HELD_DIR_NAME + ".partial")).mkdir()
        (output / (HELD_DIR_NAME + ".partial") / "reports").symlink_to(
            outside, target_is_directory=True
        )
    else:
        (output / (HELD_DIR_NAME + ".partial")).symlink_to(
            outside, target_is_directory=True
        )
        (output / "scanners").mkdir()


def _intact(outside: Path) -> None:
    assert (outside / "keep.txt").read_text(encoding="utf-8") == "outside data"
    assert (outside / "reports" / "keep2.txt").read_text(encoding="utf-8") == (
        "outside data 2"
    )
    assert sorted(p.name for p in outside.iterdir()) == ["keep.txt", "reports"]


@pytest.mark.parametrize("plant", PLANTS)
@pytest.mark.parametrize("ending", ["finished", "failed"])
def test_no_move_or_removal_goes_through_a_planted_link(tmp_path, plant, ending):
    outside = _outside(tmp_path)
    output = tmp_path / "out"
    output.mkdir()
    _plant(output, outside, plant)

    previous = PreviousResults(output)
    previous.set_aside()
    # The new scan writes its own reports.
    (output / "reports").mkdir(exist_ok=True)
    (output / "reports" / "new.sarif").write_text("{}", encoding="utf-8")
    if ending == "finished":
        previous.discard()
    else:
        previous.restore()

    _intact(outside)


@pytest.mark.parametrize("ending", ["finished", "failed"])
def test_an_output_directory_that_is_a_link_is_left_alone(tmp_path, ending):
    """The output directory itself is the link: nothing moves into or out of it.

    A workspace scan's project output is ``projects/<key>`` under a tree the
    scanned repository controls, so it can be a link to any directory.
    """
    outside = _outside(tmp_path)
    output = tmp_path / "out"
    output.symlink_to(outside, target_is_directory=True)

    previous = PreviousResults(output)
    previous.set_aside()
    if ending == "finished":
        previous.discard()
    else:
        previous.restore()

    _intact(outside)


@pytest.mark.parametrize("plant", PLANTS)
def test_a_held_set_a_cli_scan_removes_is_removed_as_links(tmp_path, plant):
    """What a scan that does not keep the previous results does with a kept set."""
    outside = _outside(tmp_path)
    output = tmp_path / "out"
    output.mkdir()
    _plant(output, outside, plant)
    (output / RESTORED_MARKER_NAME).symlink_to(outside / "keep.txt")

    PreviousResults(output).discard()

    _intact(outside)
    assert not (output / RESTORED_MARKER_NAME).is_symlink()
    assert not (output / HELD_DIR_NAME).is_symlink()
