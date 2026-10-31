# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A discard works around a leftover it cannot remove, and a half-deleted held
set is never taken for the last complete results.

Why these tests exist
---------------------
``PreviousResults.discard`` moves the held set to ``DISCARDING_DIR_NAME`` before
it deletes it, so that a delete that stops partway leaves no half-deleted set at
the held name. Two things went wrong around a leftover at that name that could
not be removed:

* the rename onto the leftover was refused, the held set was deleted in place,
  and the final sweep removed the leftover with no guard, so the leftover's
  refusal raised from the discard and skipped the staging directory's removal
  and the restore marker's. A leftover of an earlier discard is not this
  discard's failure;
* when every rename was refused, the in-place delete could end partway and leave
  a half-deleted set at the held name, which the next set aside took for the last
  complete results and used to remove the newer scan's output.

The refusals are planted by patching the module's ``_remove`` and ``Path.rename``.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.core import previous_results as previous_results_module
from automated_security_helper.core.previous_results import (
    DISCARDING_DIR_NAME,
    HELD_DIR_NAME,
    RESTORED_MARKER_NAME,
    STAGING_DIR_NAME,
    PreviousResults,
)

pytestmark = pytest.mark.unit

RESULTS = "ash_aggregated_results.json"
PREVIOUS = {
    "reports/ash.sarif": '{"previous": "sarif"}',
    "scanners/bandit/ASH.ScanResults.json": '{"status": "PASSED"}',
    RESULTS: '{"previous": "results"}',
    "ash-scan-set-files-list.txt": "previous/file.py\n",
}


def _with_previous(tmp_path: Path) -> Path:
    output = tmp_path / "out"
    for rel, text in PREVIOUS.items():
        path = output / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return output


def test_an_unremovable_leftover_does_not_skip_the_staging_and_marker_removal(
    tmp_path, monkeypatch
):
    output = _with_previous(tmp_path)
    PreviousResults(output).set_aside()
    held = output / HELD_DIR_NAME
    leftover = output / DISCARDING_DIR_NAME
    leftover.mkdir()
    (leftover / "stuck").write_text("x", encoding="utf-8")
    staging = output / STAGING_DIR_NAME
    staging.mkdir()
    (staging / "partial").write_text("x", encoding="utf-8")
    marker = output / RESTORED_MARKER_NAME
    marker.write_text("restored\n", encoding="utf-8")
    real_remove = previous_results_module._remove

    def remove(path: Path) -> None:
        if Path(path) == leftover:
            raise PermissionError(13, "Permission denied", str(path))
        real_remove(path)

    monkeypatch.setattr(previous_results_module, "_remove", remove)

    # Red at the base: PermissionError from the leftover's removal.
    PreviousResults(output).discard()

    assert not held.exists()
    assert not staging.exists()
    assert not marker.exists()
    assert leftover.is_dir()


def test_a_discard_whose_own_delete_is_refused_still_raises(tmp_path, monkeypatch):
    """The control: the set this discard is deleting is its own failure."""
    output = _with_previous(tmp_path)
    PreviousResults(output).set_aside()
    real_remove = previous_results_module._remove

    def remove(path: Path) -> None:
        if Path(path) == output / DISCARDING_DIR_NAME:
            raise PermissionError(13, "Permission denied", str(path))
        real_remove(path)

    monkeypatch.setattr(previous_results_module, "_remove", remove)

    with pytest.raises(PermissionError):
        PreviousResults(output).discard()


def test_a_half_deleted_held_set_is_not_taken_for_the_last_complete_results(
    tmp_path, monkeypatch
):
    output = _with_previous(tmp_path)
    previous = PreviousResults(output)
    previous.set_aside()
    held = output / HELD_DIR_NAME
    real_rename = Path.rename
    real_remove = previous_results_module._remove

    def rename(self: Path, target):
        if self.name == HELD_DIR_NAME and Path(target).name.startswith(
            DISCARDING_DIR_NAME
        ):
            raise PermissionError(13, "Permission denied", str(self))
        return real_rename(self, target)

    def remove(path: Path) -> None:
        if Path(path) == held:
            # Stops partway: one entry goes, then the delete is refused.
            real_remove(sorted(held.iterdir())[0])
            raise PermissionError(13, "Permission denied", str(path))
        real_remove(path)

    monkeypatch.setattr(Path, "rename", rename)
    monkeypatch.setattr(previous_results_module, "_remove", remove)
    with pytest.raises(PermissionError):
        previous.discard()
    assert held.is_dir()
    monkeypatch.undo()

    # The next scan wrote its results at the top level and sets the previous ones
    # aside again.
    (output / RESULTS).write_text("new", encoding="utf-8")
    PreviousResults(output).set_aside()

    # Red at the base: the half set was trusted, the new results were removed as
    # an interrupted scan's leftovers, and the held file still read "previous".
    assert (held / RESULTS).read_text(encoding="utf-8") == "new"
    assert not (held / "scanners").exists()
    assert not (output / RESULTS).exists()
