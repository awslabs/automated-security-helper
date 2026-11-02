# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``.discarding`` leftover that cannot be removed does not stop the moves.

``set_aside`` and ``discard`` each began by removing the half-deleted set a
discard that stopped partway leaves (DISCARDING_DIR_NAME), with no guard: a
persistent refusal there (a permission, a lock another process holds on a file
in it) made every later set aside in the directory raise before it moved
anything, which turned keep-previous-results off for that directory for good,
and left the previous results at the top level for every scan after. The
removal is now best effort: refused, it is logged and the moves go on.

The refusal is planted by patching the module's ``_remove`` for that one path;
every other removal runs as it does.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from automated_security_helper.core import previous_results as previous_results_module
from automated_security_helper.core.previous_results import (
    DISCARDING_DIR_NAME,
    HELD_DIR_NAME,
    PreviousResults,
)

pytestmark = pytest.mark.unit

RESULTS = "ash_aggregated_results.json"


def _refuse_removing(monkeypatch, refused: Path) -> list[Path]:
    real_remove = previous_results_module._remove
    attempts: list[Path] = []

    def remove(path: Path) -> None:
        if Path(path) == refused:
            attempts.append(Path(path))
            raise PermissionError(13, "Permission denied", str(path))
        real_remove(path)

    monkeypatch.setattr(previous_results_module, "_remove", remove)
    return attempts


def test_a_set_aside_goes_on_past_a_leftover_it_cannot_remove(
    tmp_path, monkeypatch, caplog
):
    output = tmp_path / "out"
    output.mkdir()
    (output / RESULTS).write_text("previous", encoding="utf-8")
    leftover = output / DISCARDING_DIR_NAME
    leftover.mkdir()
    (leftover / "stuck").write_text("x", encoding="utf-8")
    attempts = _refuse_removing(monkeypatch, leftover)

    with caplog.at_level(logging.WARNING):
        PreviousResults(output).set_aside()

    # Red at the previous tip: PermissionError escaped from the first line of
    # set_aside, nothing was moved, and the previous results stayed at the top.
    assert attempts == [leftover]
    assert (output / HELD_DIR_NAME / RESULTS).read_text(encoding="utf-8") == "previous"
    assert not (output / RESULTS).exists()
    assert leftover.is_dir()
    assert any(DISCARDING_DIR_NAME in m for m in caplog.messages), caplog.messages


def test_a_discard_goes_on_past_a_leftover_it_cannot_remove(tmp_path, monkeypatch):
    output = tmp_path / "out"
    output.mkdir()
    held = output / HELD_DIR_NAME
    held.mkdir()
    (held / RESULTS).write_text("previous", encoding="utf-8")
    leftover = output / DISCARDING_DIR_NAME
    leftover.mkdir()
    (leftover / "stuck").write_text("x", encoding="utf-8")
    attempts = _refuse_removing(monkeypatch, leftover)

    # The held set cannot be renamed over the leftover, so it is moved to the
    # next free name and deleted from there. The leftover is an earlier
    # discard's, not this one's: its refusal is logged and is not this
    # discard's failure, so nothing is raised.
    PreviousResults(output).discard()

    assert attempts == [leftover]
    assert not held.exists()
    assert leftover.is_dir()
    assert not (output / f"{DISCARDING_DIR_NAME}.2").exists()


def test_the_control_removes_a_removable_leftover(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / RESULTS).write_text("previous", encoding="utf-8")
    leftover = output / DISCARDING_DIR_NAME
    leftover.mkdir()

    PreviousResults(output).set_aside()

    assert not leftover.exists()
    assert (output / HELD_DIR_NAME / RESULTS).read_text(encoding="utf-8") == "previous"
