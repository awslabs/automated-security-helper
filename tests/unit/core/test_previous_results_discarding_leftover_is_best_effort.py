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


@pytest.mark.parametrize(
    "renders", [True, False], ids=["the-text-renders", "the-text-cannot-be-rendered"]
)
def test_a_leftover_refusal_is_logged_in_its_own_words_or_by_its_type(
    tmp_path, monkeypatch, caplog, renders
):
    # Red before the fix: with the text that cannot be rendered, the leftover's
    # refusal was formatted with a plain f-string, and an OSError built from one
    # argument renders that argument with its __str__, which raises here, so
    # set_aside raised it from its first step, the one this best-effort removal
    # exists to keep from stopping the set aside.
    asked = []

    class _TextThatCannotBeRendered:
        def __str__(self) -> str:
            asked.append(self)
            raise ValueError("a planted failure making the text")

    planted = _TextThatCannotBeRendered()
    output = tmp_path / "out"
    output.mkdir()
    (output / RESULTS).write_text("previous", encoding="utf-8")
    leftover = output / DISCARDING_DIR_NAME
    leftover.mkdir()
    (leftover / "stuck").write_text("x", encoding="utf-8")
    real_remove = previous_results_module._remove
    attempts = []

    def remove(path: Path) -> None:
        if Path(path) == leftover:
            attempts.append(Path(path))
            raise OSError("held open" if renders else planted)
        real_remove(path)

    monkeypatch.setattr(previous_results_module, "_remove", remove)
    with caplog.at_level(logging.WARNING, logger="ash"):
        PreviousResults(output).set_aside()

    assert attempts == [leftover], attempts
    assert asked == ([] if renders else [planted]), asked
    assert (output / HELD_DIR_NAME / RESULTS).read_text(encoding="utf-8") == "previous"
    assert leftover.is_dir()
    shown = "held open" if renders else "<OSError: its message could not be rendered>"
    expected = (
        f"Could not remove {leftover}, left by a discard that stopped partway: "
        f"{shown}; it is left in place"
    )
    said = [message for message in caplog.messages if DISCARDING_DIR_NAME in message]
    assert said == [expected], said


class _AnOSErrorWithItsOwnText(OSError):
    """An OSError whose own ``__str__`` returns its one argument as it is."""

    def __str__(self) -> str:
        return self.args[0]


def _a_text_of_a_str_subclass(method: str, asked: list, text: str) -> str:
    """*text*, as an instance of a str subclass whose own ``method`` records each
    call in ``asked``: its ``__format__`` gives other words, its ``__str__``
    raises."""

    class _Text(str):
        __slots__ = ()

    def other_words(self: str, spec: str) -> str:
        asked.append(method)
        return "other words"

    def refuse(self: str) -> str:
        asked.append(method)
        raise ValueError(f"a planted {method}")

    setattr(_Text, method, other_words if method == "__format__" else refuse)
    return _Text(text)


@pytest.mark.parametrize(
    "method",
    [
        pytest.param(None, id="an-exact-str"),
        pytest.param("__format__", id="a-subclass-whose-format-says-other-words"),
        pytest.param("__str__", id="a-subclass-whose-str-raises"),
    ],
)
def test_a_leftover_refusal_whose_text_is_a_str_subclass_is_logged_as_its_characters(
    tmp_path, monkeypatch, caplog, method
):
    # Red before the fix: the leftover's refusal was formatted with
    # own_error_text(e) in an f-string, and own_error_text returned what the
    # error's __str__ returned, here an instance of a str subclass. An f-string
    # formats a str subclass through its own __format__, and str.__format__ with
    # an empty spec calls its own __str__ (an exact str is used as is), so the
    # warning said other words or set_aside raised from its first step.
    asked: list = []
    text = "held open"
    if method is not None:
        text = _a_text_of_a_str_subclass(method, asked, text)
    output = tmp_path / "out"
    output.mkdir()
    (output / RESULTS).write_text("previous", encoding="utf-8")
    leftover = output / DISCARDING_DIR_NAME
    leftover.mkdir()
    real_remove = previous_results_module._remove

    def remove(path: Path) -> None:
        if Path(path) == leftover:
            raise _AnOSErrorWithItsOwnText(text)
        real_remove(path)

    monkeypatch.setattr(previous_results_module, "_remove", remove)
    with caplog.at_level(logging.WARNING, logger="ash"):
        PreviousResults(output).set_aside()

    expected = (
        f"Could not remove {leftover}, left by a discard that stopped partway: "
        "held open; it is left in place"
    )
    said = [message for message in caplog.messages if DISCARDING_DIR_NAME in message]
    assert said == [expected], said
    assert asked == [], asked
    assert (output / HELD_DIR_NAME / RESULTS).read_text(encoding="utf-8") == "previous"
