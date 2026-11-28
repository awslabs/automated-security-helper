# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A restore that cannot write its marker leaves something to resume from.

``_finish_restore`` removed the restoring directory and only then wrote the
marker, and wrote it by removing the marker the caller had already written and
creating it again. A write that failed left put-back results with no marker and
no restoring directory, so no later restore or set-aside could tell they were
put back. The marker is now written before the directory goes, and not again
when there is one.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from automated_security_helper.core import previous_results as previous_results_module
from automated_security_helper.core.previous_results import (
    RESTORED_MARKER_NAME,
    RESTORING_DIR_NAME,
    RESULT_ENTRIES,
    PreviousResults,
)

pytestmark = pytest.mark.unit

ENTRY = RESULT_ENTRIES[0]


def _refused(self):
    raise OSError("the marker cannot be written")


def _output_with_a_restore_under_way(tmp_path):
    restoring = tmp_path / RESTORING_DIR_NAME
    restoring.mkdir()
    (restoring / ENTRY).write_text("previous")
    return restoring


def test_a_marker_that_cannot_be_written_leaves_the_restoring_directory(
    tmp_path, monkeypatch
):
    restoring = _output_with_a_restore_under_way(tmp_path)
    results = PreviousResults(tmp_path)
    monkeypatch.setattr(PreviousResults, "_mark_restored", _refused)

    with pytest.raises(OSError, match="marker cannot be written"):
        results._finish_restore(replace_existing=True, mark=True)

    # Red at the base: the directory was removed before the marker was tried, so
    # nothing was left for a later call to finish from.
    assert restoring.is_dir()
    assert (tmp_path / ENTRY).read_text() == "previous"


def test_an_existing_marker_is_kept_not_written_again(tmp_path, monkeypatch):
    restoring = _output_with_a_restore_under_way(tmp_path)
    marker = tmp_path / RESTORED_MARKER_NAME
    marker.write_text("written before the first move")
    results = PreviousResults(tmp_path)
    monkeypatch.setattr(PreviousResults, "_mark_restored", _refused)

    # Red at the base: the marker was removed and written again, and the write
    # raised.
    results._finish_restore(replace_existing=True, mark=True)

    assert marker.read_text() == "written before the first move"
    assert not restoring.exists()
    assert (tmp_path / ENTRY).read_text() == "previous"


def test_a_restore_still_leaves_the_marker_beside_what_it_put_back(tmp_path):
    """The control: the whole restore, with a held set, still marks and clears."""
    held = tmp_path / ".ash_previous_results"
    held.mkdir()
    (held / ENTRY).write_text("previous")
    (tmp_path / ENTRY).write_text("failed scan")

    PreviousResults(tmp_path).restore()

    assert (tmp_path / ENTRY).read_text() == "previous"
    assert (tmp_path / RESTORED_MARKER_NAME).exists()
    assert not (tmp_path / RESTORING_DIR_NAME).exists()


@pytest.mark.parametrize(
    "renders", [True, False], ids=["the-text-renders", "the-text-cannot-be-rendered"]
)
def test_a_marker_that_cannot_be_removed_is_logged_and_never_raised(
    tmp_path, monkeypatch, renders
):
    # Red before the fix: with the text that cannot be rendered,
    # forget_restored_marker formatted the refusal with a plain f-string, and an
    # OSError built from one argument renders that argument with its __str__,
    # which raises here, so the method raised it, though it is documented never
    # to raise and the orchestrator calls it from its handler for a set aside
    # that failed.
    asked = []

    class _TextThatCannotBeRendered:
        def __str__(self) -> str:
            asked.append(self)
            raise ValueError("a planted failure making the text")

    planted = _TextThatCannotBeRendered()
    results = PreviousResults(tmp_path)
    attempts = []

    def refuse(self):
        attempts.append(self)
        raise OSError("held open" if renders else planted)

    logger = MagicMock()
    monkeypatch.setattr(PreviousResults, "_remove_marker", refuse)
    monkeypatch.setattr(previous_results_module, "ASH_LOGGER", logger)

    results.forget_restored_marker()

    assert attempts == [results], attempts
    assert asked == ([] if renders else [planted]), asked
    shown = "held open" if renders else "<OSError: its message could not be rendered>"
    logger.warning.assert_called_once_with(
        f"Could not remove the restore marker {tmp_path / RESTORED_MARKER_NAME}: "
        f"{shown}; a reader of holds_restored_results may take this scan's results "
        "for put-back ones until the next scan removes it"
    )


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
def test_a_marker_refusal_whose_text_is_a_str_subclass_is_logged_as_its_characters(
    tmp_path, monkeypatch, method
):
    # Red before the fix: forget_restored_marker formatted own_error_text(e) in
    # an f-string, and own_error_text returned what the error's __str__ returned,
    # here an instance of a str subclass. An f-string formats a str subclass
    # through its own __format__, and str.__format__ with an empty spec calls its
    # own __str__ (an exact str is used as is), so the warning said other words
    # or the method raised, though it is documented never to raise.
    asked: list = []
    text = "held open"
    if method is not None:
        text = _a_text_of_a_str_subclass(method, asked, text)

    def refuse(self):
        raise _AnOSErrorWithItsOwnText(text)

    logger = MagicMock()
    monkeypatch.setattr(PreviousResults, "_remove_marker", refuse)
    monkeypatch.setattr(previous_results_module, "ASH_LOGGER", logger)

    PreviousResults(tmp_path).forget_restored_marker()

    logger.warning.assert_called_once_with(
        f"Could not remove the restore marker {tmp_path / RESTORED_MARKER_NAME}: "
        "held open; a reader of holds_restored_results may take this scan's results "
        "for put-back ones until the next scan removes it"
    )
    assert asked == [], asked
