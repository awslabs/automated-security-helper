# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Setting the previous results aside, or putting them back, survives a refused move.

Both are a series of renames, and a rename can be refused (a file held open on
Windows, a permission changed underneath, a full disk on a cross-device move). A
refused rename raises, and without recovery the next call would lose an entry:

- restore removes what the new scan wrote at the top of the output directory,
  then moves the held entries back one by one. Refused at the second, the first
  is already back at the top, so a second restore that cleared the top again
  would remove it with the new scan's files, and then write the marker that
  says the results were put back.
- set_aside moves the entries into a staging directory and renames that to the
  held set. Refused at the second, the first is already staged, and a next
  set_aside that took the staging directory for a leftover would delete it,
  and the entry in it.

A set_aside that fails moves what it had staged back before it raises, and
a restore renames the held set to a ``.restoring`` directory once the top level
is clear, so a second restore resumes the moves instead of clearing the top
level again. The marker is written right after that rename, before the first
move back, so a restore that stops on a refused move already says that what is
at the top level was put back; a restore that stops before the rename (the top
level could not be cleared, or the held set could not be renamed) leaves no
marker, because nothing was put back yet.

A set_aside can also stop on something other than a refused rename (an
interrupt, any other error), and its process can be killed between two renames.
Either way the staging directory holds part of the previous results: the first
puts back what it had staged whatever stopped it, and the next set_aside puts
back what a killed one left staged before it moves anything.

Rename is refused here by patching ``Path.rename`` to raise on its second call.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core.previous_results import (
    HELD_DIR_NAME,
    RESTORED_MARKER_NAME,
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


def _with_previous(tmp_path: Path) -> Path:
    output = tmp_path / "out"
    for rel, text in PREVIOUS.items():
        path = output / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return output


def _contents(output: Path) -> Dict[str, str]:
    return {
        p.relative_to(output).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted(output.rglob("*"))
        if p.is_file() and p.name != RESTORED_MARKER_NAME
    }


STAGING = HELD_DIR_NAME + ".partial"


def _held() -> Dict[str, str]:
    """PREVIOUS as the held set holds it."""
    return {f"{HELD_DIR_NAME}/{rel}": text for rel, text in PREVIOUS.items()}


def _second_rename_raises(monkeypatch, error: BaseException):
    """arm/disarm: the second Path.rename after arm() raises ``error``, once."""
    real = Path.rename
    calls = {"n": 0}

    def rename(self, target):
        calls["n"] += 1
        if calls["n"] == 2:
            raise error
        return real(self, target)

    def arm() -> None:
        calls["n"] = 0
        monkeypatch.setattr(Path, "rename", rename)

    def disarm() -> None:
        monkeypatch.setattr(Path, "rename", real)

    return arm, disarm


@pytest.fixture
def refuse_second_rename(monkeypatch):
    """Make the second Path.rename after this point raise PermissionError, once."""
    real = Path.rename
    calls = {"n": 0}

    def rename(self, target):
        calls["n"] += 1
        if calls["n"] == 2:
            raise PermissionError(13, "Permission denied", str(self))
        return real(self, target)

    def arm() -> None:
        calls["n"] = 0
        monkeypatch.setattr(Path, "rename", rename)

    def disarm() -> None:
        monkeypatch.setattr(Path, "rename", real)

    return arm, disarm


def test_a_restore_refused_halfway_then_retried_puts_every_entry_back(
    tmp_path, refuse_second_rename
):
    arm, disarm = refuse_second_rename
    output = _with_previous(tmp_path)
    previous = PreviousResults(output)
    previous.set_aside()
    # The new scan writes its own results, then ends without finishing.
    (output / "reports").mkdir()
    (output / "reports" / "ash.sarif").write_text('{"new": 1}', encoding="utf-8")
    (output / "ash_aggregated_results.json").write_text('{"new": 1}', encoding="utf-8")

    arm()
    with pytest.raises(PermissionError):
        previous.restore()
    disarm()
    # The marker is written before the first move: a restore that stopped on a
    # refused rename left previous results at the top level, and a report must
    # not present them as the new scan's from that moment on.
    assert holds_restored_results(output), (
        "a restore that stopped halfway put previous results back and does not say so"
    )

    previous.restore()

    assert _contents(output) == PREVIOUS
    assert holds_restored_results(output)
    assert not (output / HELD_DIR_NAME).exists()
    assert not (output / (HELD_DIR_NAME + ".restoring")).exists()


def _new_scan_wrote_results(output: Path) -> None:
    """The new scan writes its own results, then ends without finishing."""
    (output / "reports").mkdir()
    (output / "reports" / "ash.sarif").write_text('{"new": 1}', encoding="utf-8")
    (output / "ash_aggregated_results.json").write_text('{"new": 1}', encoding="utf-8")


def test_a_restore_refused_at_the_held_sets_rename_leaves_no_marker(
    tmp_path, monkeypatch
):
    """Control for the marker's place: the first rename of a restore is the held
    set to RESTORING_DIR_NAME, and nothing was put back when it is refused, so no
    marker is written, the held set is intact, and a retry restores everything."""
    output = _with_previous(tmp_path)
    previous = PreviousResults(output)
    previous.set_aside()
    _new_scan_wrote_results(output)
    real = Path.rename

    def refuse_the_first_rename(self, target):
        monkeypatch.setattr(Path, "rename", real)
        raise PermissionError(13, "Permission denied", str(self))

    monkeypatch.setattr(Path, "rename", refuse_the_first_rename)
    with pytest.raises(PermissionError):
        previous.restore()

    assert not holds_restored_results(output), (
        "a restore that never moved an entry back says the directory holds put-back results"
    )
    assert (output / HELD_DIR_NAME).is_dir()
    assert not (output / (HELD_DIR_NAME + ".restoring")).exists()
    # The top level was cleared before the rename; the held set is whole.
    assert _contents(output) == _held()

    previous.restore()
    assert _contents(output) == PREVIOUS
    assert holds_restored_results(output)


def test_a_restore_refused_clearing_the_top_level_leaves_no_marker(
    tmp_path, monkeypatch
):
    """Control for the marker's place: a top-level entry of the new scan that
    cannot be removed stops the restore before anything moves, so no marker is
    written, the held set is intact, and a retry restores everything."""
    from automated_security_helper.core import previous_results

    output = _with_previous(tmp_path)
    previous = PreviousResults(output)
    previous.set_aside()
    _new_scan_wrote_results(output)
    real_remove = previous_results._remove

    def refuse_the_results_file(path: Path) -> None:
        if path.name == "ash_aggregated_results.json":
            raise PermissionError(13, "Permission denied", str(path))
        real_remove(path)

    monkeypatch.setattr(previous_results, "_remove", refuse_the_results_file)
    with pytest.raises(PermissionError):
        previous.restore()
    monkeypatch.setattr(previous_results, "_remove", real_remove)

    assert not holds_restored_results(output), (
        "a restore that never moved an entry back says the directory holds put-back results"
    )
    assert (output / HELD_DIR_NAME).is_dir()
    assert not (output / (HELD_DIR_NAME + ".restoring")).exists()
    contents = _contents(output)
    assert all(contents.get(rel) == text for rel, text in _held().items()), (
        "the held set was touched before the top level was clear"
    )
    assert contents["ash_aggregated_results.json"] == '{"new": 1}'

    previous.restore()
    assert _contents(output) == PREVIOUS
    assert holds_restored_results(output)


def test_a_set_aside_refused_halfway_then_retried_keeps_every_entry(
    tmp_path, refuse_second_rename
):
    arm, disarm = refuse_second_rename
    output = _with_previous(tmp_path)
    previous = PreviousResults(output)

    arm()
    with pytest.raises(PermissionError):
        previous.set_aside()
    disarm()
    assert _contents(output) == PREVIOUS, (
        "a set_aside that stopped halfway left the previous results split"
    )

    previous.set_aside()
    assert _contents(output) == {
        f"{HELD_DIR_NAME}/{rel}": text for rel, text in PREVIOUS.items()
    }
    previous.restore()

    assert _contents(output) == PREVIOUS


def test_a_new_scan_finishes_an_interrupted_restore_before_setting_aside(
    tmp_path, refuse_second_rename
):
    """The restore stopped halfway and the next scan starts: nothing is lost.

    set_aside resumes the restore first, so what it sets aside is the whole
    previous set, and the marker is gone because a scan is starting.
    """
    arm, disarm = refuse_second_rename
    output = _with_previous(tmp_path)
    previous = PreviousResults(output)
    previous.set_aside()

    arm()
    with pytest.raises(PermissionError):
        previous.restore()
    disarm()

    PreviousResults(output).set_aside()

    assert _contents(output) == {
        f"{HELD_DIR_NAME}/{rel}": text for rel, text in PREVIOUS.items()
    }
    assert not holds_restored_results(output)
    PreviousResults(output).restore()
    assert _contents(output) == PREVIOUS


def test_a_restoring_directory_that_is_a_link_is_removed_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("outside data", encoding="utf-8")
    output = _with_previous(tmp_path)
    (output / (HELD_DIR_NAME + ".restoring")).symlink_to(
        outside, target_is_directory=True
    )

    PreviousResults(output).restore()
    PreviousResults(output).set_aside()
    PreviousResults(output).discard()

    assert sorted(p.name for p in outside.iterdir()) == ["keep.txt"]
    assert (outside / "keep.txt").read_text(encoding="utf-8") == "outside data"
    assert not (output / (HELD_DIR_NAME + ".restoring")).exists()


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(RuntimeError("stopped halfway"), id="an-error"),
        pytest.param(KeyboardInterrupt(), id="an-interrupt"),
        # Already put back before: the control that the cell sees a put-back.
        pytest.param(PermissionError(13, "Permission denied"), id="a-refused-move"),
    ],
)
def test_a_set_aside_stopped_by_anything_puts_back_what_it_had_staged(
    tmp_path, monkeypatch, error
):
    arm, disarm = _second_rename_raises(monkeypatch, error)
    output = _with_previous(tmp_path)
    previous = PreviousResults(output)

    arm()
    with pytest.raises(type(error)):
        previous.set_aside()
    disarm()

    assert _contents(output) == PREVIOUS, (
        "a set_aside stopped halfway left the previous results split"
    )
    assert not (output / STAGING).exists(), "the staging directory is still there"
    previous.set_aside()
    assert _contents(output) == _held()
    previous.restore()
    assert _contents(output) == PREVIOUS


def _killed_while_staging(output: Path, staged: str) -> None:
    """What a set_aside killed between two renames leaves: some entries in the
    staging directory, the rest at the top, and no held set."""
    names = sorted({rel.split("/")[0] for rel in PREVIOUS})
    moved = names[:1] if staged == "one-entry-staged" else names
    (output / STAGING).mkdir()
    for name in moved:
        (output / name).rename(output / STAGING / name)


@pytest.mark.parametrize("staged", ["one-entry-staged", "every-entry-staged"])
def test_what_a_killed_set_aside_left_staged_is_put_back_by_the_next(tmp_path, staged):
    output = _with_previous(tmp_path)
    _killed_while_staging(output, staged)
    if _contents(output) == PREVIOUS or not (output / STAGING).is_dir():
        raise RuntimeError("control: nothing was left staged")

    previous = PreviousResults(output)
    previous.set_aside()

    assert _contents(output) == _held(), (
        "the next set_aside lost what a killed one had staged"
    )
    assert not (output / STAGING).exists()
    previous.restore()
    assert _contents(output) == PREVIOUS


def test_an_interrupt_after_the_rename_to_the_held_set_reports_nothing_lost(
    tmp_path, monkeypatch
):
    """The interrupt lands once the staging directory is already the held set:
    the set stays held for the caller's restore, and no error says the staged
    results could not be moved back."""
    from automated_security_helper.core import previous_results

    output = _with_previous(tmp_path)
    real = Path.rename

    def rename(self, target):
        real(self, target)
        if self.name == STAGING:
            raise KeyboardInterrupt

    logger = MagicMock()
    monkeypatch.setattr(previous_results, "ASH_LOGGER", logger)
    monkeypatch.setattr(Path, "rename", rename)
    with pytest.raises(KeyboardInterrupt):
        PreviousResults(output).set_aside()
    monkeypatch.setattr(Path, "rename", real)

    assert _contents(output) == _held()
    assert not logger.error.called, logger.error.call_args_list
    PreviousResults(output).restore()
    assert _contents(output) == PREVIOUS


def test_a_refused_put_back_of_a_stage_keeps_the_restored_marker(
    tmp_path, refuse_second_rename
):
    """No scan starts when what a killed set_aside staged cannot all be moved
    back: the set aside raises, the put-back results are at the top level, and
    the marker that says the directory holds put-back results stays until a
    set aside completes its moves. Removing it before the renames left them
    there as if they were the next scan's."""
    arm, disarm = refuse_second_rename
    output = _with_previous(tmp_path)
    _killed_while_staging(output, "every-entry-staged")
    (output / RESTORED_MARKER_NAME).write_text("restored\n", encoding="utf-8")

    arm()
    with pytest.raises(PermissionError):
        PreviousResults(output).set_aside()
    disarm()

    assert holds_restored_results(output)
    assert (output / STAGING).is_dir(), "what was not moved back was not kept staged"
    PreviousResults(output).set_aside()
    assert not holds_restored_results(output), (
        "the completed set aside keeps the marker"
    )
    assert _contents(output) == _held()


@pytest.mark.parametrize(
    "staged",
    ["reports/ash.sarif", "ash_aggregated_results.json"],
    ids=["a-dir", "a-file"],
)
def test_a_staged_entry_never_replaces_one_at_the_top_level(tmp_path, staged):
    """Control: an entry of the same name at the top level stays what it is. A
    file renamed over a file replaces it without an error, a directory over a
    directory does not, so both are tried."""
    output = _with_previous(tmp_path)
    (output / STAGING / staged).parent.mkdir(parents=True, exist_ok=True)
    (output / STAGING / staged).write_text("staged", encoding="utf-8")

    PreviousResults(output).set_aside()

    assert _contents(output) == _held()
    assert not (output / STAGING).exists()


def test_a_staged_name_that_is_no_result_entry_is_not_put_back(tmp_path):
    """Control: only what a set_aside moves comes back out of the staging
    directory; anything else there goes with it."""
    output = _with_previous(tmp_path)
    (output / STAGING).mkdir()
    (output / STAGING / "not-a-result.txt").write_text("x", encoding="utf-8")

    PreviousResults(output).set_aside()

    assert _contents(output) == _held()
    assert not (output / STAGING).exists()
