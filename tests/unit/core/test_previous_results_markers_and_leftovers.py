# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The previous-results moves leave the directory readable after any stop.

Six defects of ``PreviousResults``, each pinned by a test red on the tree that
carried it:

* A restore wrote its marker only after the last move, so a restore stopped by
  a refused rename left previous results at the top level with no marker, and
  an MCP reader presented them as the failed scan's.
* A set aside removed the marker before the renames that can raise, so a failed
  set aside left put-back results on disk with no marker.
* A ``.restoring`` directory that outlived a completed scan was finished by the
  next set aside, which renamed its older entries over the newer results.
* A ``.restoring`` directory already present was adopted as an interrupted
  restore, and every entry of any name in it was moved to the top level.
* A discard that failed partway left a half-deleted held set that the next set
  aside trusted as the last complete results.
* A restore resumed a leftover ``.restoring`` without clearing the top level,
  so a later scan's output and the older set were merged into one tree.

Rename is refused by patching ``Path.rename``, as the resume tests do; the
delete by patching ``shutil.rmtree`` in the module.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict

import pytest

from automated_security_helper.core import previous_results as previous_results_module
from automated_security_helper.core.previous_results import (
    DISCARDING_DIR_NAME,
    HELD_DIR_NAME,
    RESTORED_MARKER_NAME,
    RESTORING_DIR_NAME,
    PreviousResults,
    holds_restored_results,
)

pytestmark = pytest.mark.unit

PREVIOUS = {
    "reports/ash.sarif": '{"previous": "sarif"}',
    "scanners/bandit/ASH.ScanResults.json": '{"status": "PASSED"}',
    "ash_aggregated_results.json": '{"previous": "results"}',
    "ash-scan-set-files-list.txt": "previous/file.py\n",
}
RESULTS = "ash_aggregated_results.json"


def _with_previous(tmp_path: Path) -> Path:
    output = tmp_path / "out"
    for rel, text in PREVIOUS.items():
        path = output / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return output


def _refuse_rename_on_call(monkeypatch, number: int) -> Dict[str, int]:
    calls = {"n": 0}
    real_rename = Path.rename

    def rename(self: Path, target):
        calls["n"] += 1
        if calls["n"] == number:
            raise PermissionError(13, "Permission denied", str(self))
        return real_rename(self, target)

    monkeypatch.setattr(Path, "rename", rename)
    return calls


class TestTheMarkerSaysWhatIsAtTheTopLevel:
    def test_a_restore_stopped_by_a_refused_rename_leaves_the_marker(
        self, tmp_path, monkeypatch
    ):
        output = _with_previous(tmp_path)
        previous = PreviousResults(output)
        previous.set_aside()
        (output / RESULTS).write_text('{"new": "scan"}', encoding="utf-8")

        # Rename 1 is held -> restoring; rename 2 is the first entry back.
        _refuse_rename_on_call(monkeypatch, 2)
        with pytest.raises(OSError):
            previous.restore()

        # Red at the base: the marker came only after the last move.
        assert holds_restored_results(output)

    def test_a_set_aside_stopped_by_a_refused_rename_keeps_the_marker(
        self, tmp_path, monkeypatch
    ):
        output = _with_previous(tmp_path)
        previous = PreviousResults(output)
        previous.set_aside()
        previous.restore()
        assert holds_restored_results(output)

        _refuse_rename_on_call(monkeypatch, 1)
        with pytest.raises(OSError):
            PreviousResults(output).set_aside()

        # Red at the base: the marker was removed before the renames.
        assert holds_restored_results(output)


class TestALeftoverRestoringDirectoryIsNotTrusted:
    def test_a_set_aside_keeps_the_newer_top_level_entry(self, tmp_path):
        output = tmp_path / "out"
        (output / RESTORING_DIR_NAME).mkdir(parents=True)
        (output / RESTORING_DIR_NAME / RESULTS).write_text("old", encoding="utf-8")
        (output / RESULTS).write_text("new", encoding="utf-8")

        PreviousResults(output).set_aside()

        # Red at the base: the older entry was renamed over the newer one.
        assert (output / HELD_DIR_NAME / RESULTS).read_text(encoding="utf-8") == "new"
        assert not (output / RESTORING_DIR_NAME).exists()

    def test_an_entry_that_is_not_a_result_entry_is_not_moved_to_the_top(
        self, tmp_path
    ):
        output = tmp_path / "out"
        (output / RESTORING_DIR_NAME).mkdir(parents=True)
        (output / RESTORING_DIR_NAME / "planted.txt").write_text("x", encoding="utf-8")

        PreviousResults(output).set_aside()

        # Red at the base: every entry of any name was renamed to the top level.
        assert not (output / "planted.txt").exists()
        assert not (output / RESTORING_DIR_NAME).exists()

    def test_a_leftover_without_a_marker_does_not_merge_with_a_later_scan(
        self, tmp_path
    ):
        output = tmp_path / "out"
        (output / RESTORING_DIR_NAME).mkdir(parents=True)
        (output / RESTORING_DIR_NAME / RESULTS).write_text("old", encoding="utf-8")
        # A later scan's output at the top level, with an entry the old set lacks.
        (output / RESULTS).write_text("new", encoding="utf-8")
        (output / "scanners" / "semgrep").mkdir(parents=True)
        (output / "scanners" / "semgrep" / "ASH.ScanResults.json").write_text(
            "{}", encoding="utf-8"
        )

        PreviousResults(output).restore()

        # Red at the base: the top level was not cleared, so the later scan's
        # scanners/ survived beside the older results file.
        assert not (output / "scanners").exists()
        assert (output / RESULTS).read_text(encoding="utf-8") == "old"
        assert holds_restored_results(output)


class TestAFailedDiscardLeavesNoHeldSetToTrust:
    def test_the_half_deleted_set_is_not_at_the_held_name(self, tmp_path, monkeypatch):
        output = _with_previous(tmp_path)
        previous = PreviousResults(output)
        previous.set_aside()
        assert (output / HELD_DIR_NAME).is_dir()

        def refuse(path, *args, **kwargs):
            raise PermissionError(13, "Permission denied", str(path))

        monkeypatch.setattr(previous_results_module.shutil, "rmtree", refuse)
        with pytest.raises(OSError):
            previous.discard()

        # Red at the base: the set stayed at the held name, half-deleted or not.
        assert not (output / HELD_DIR_NAME).exists()
        assert (output / DISCARDING_DIR_NAME).is_dir()

        # The next scan's set aside removes the leftover and holds the new
        # results, not the stale set.
        monkeypatch.undo()
        (output / RESULTS).write_text("new", encoding="utf-8")
        PreviousResults(output).set_aside()
        assert not (output / DISCARDING_DIR_NAME).exists()
        assert (output / HELD_DIR_NAME / RESULTS).read_text(encoding="utf-8") == "new"
        assert not (output / RESTORED_MARKER_NAME).exists()
