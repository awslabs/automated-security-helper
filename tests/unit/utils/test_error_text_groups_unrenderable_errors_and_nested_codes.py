# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""error_text's chain walk, its own robustness, and its escape-code removal.

Three readings of utils/error_text.py went wrong. An exception group's members
were not part of the chain, so a ValidationError inside one was printed by
traceback_text and log_unexpected_error with its refused inputs. An error whose
own ``__str__`` raises made error_text raise, replacing the error being
reported. And escape codes were removed in a single pass, so removing an inner
sequence could join the bytes around it into a complete sequence that stayed in
the text saved to results and reports.
"""

from __future__ import annotations

import logging
import sys
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel

from automated_security_helper.utils.error_text import (
    ESCAPE_CODES,
    error_text,
    log_unexpected_error,
    redact_then_split,
    shown_tool_stderr,
    traceback_text,
    validation_errors_in,
)

pytestmark = pytest.mark.unit

ESC = chr(0x1B)
#: A refused input that no text printed about the error may hold. A
#: placeholder, not a credential.
REFUSED = "placeholder-refused-input"


class _Counted(BaseModel):
    count: int


def _validation_error():
    with pytest.raises(Exception) as caught:
        _Counted(count=REFUSED)
    return caught.value


@pytest.mark.skipif(sys.version_info < (3, 11), reason="exception groups")
def test_a_validation_error_inside_a_group_is_found_and_described():
    inner = _validation_error()
    group = ExceptionGroup("several things failed", [ValueError("x"), inner])  # noqa: F821

    assert inner in validation_errors_in(group)
    assert REFUSED not in traceback_text(group)
    assert REFUSED not in error_text(group)


@pytest.mark.skipif(sys.version_info < (3, 11), reason="exception groups")
def test_an_unexpected_group_is_logged_without_its_members_inputs():
    inner = _validation_error()
    group = ExceptionGroup("several things failed", [inner])  # noqa: F821
    logger = MagicMock()

    log_unexpected_error(logger, group)

    # The control: both lines were logged, so the loop below has calls to read.
    assert logger.error.called and logger.debug.called
    # Every call on the logger, whatever method it used, not only error and debug.
    for call in logger.mock_calls:
        assert REFUSED not in str(call), call


@pytest.mark.skipif(sys.version_info < (3, 11), reason="exception groups")
def test_a_validation_error_member_is_described_after_the_groups_own_text():
    inner = _validation_error()
    group = ExceptionGroup("several things failed", [ValueError("x"), inner])  # noqa: F821

    text = error_text(group)

    # A group's own text counts its members and names none.
    assert text.startswith("several things failed (2 sub-exceptions)"), text
    assert "1 validation error for _Counted" in text, text
    assert "count" in text and REFUSED not in text, text


@pytest.mark.skipif(sys.version_info < (3, 11), reason="exception groups")
def test_a_member_the_groups_own_text_quotes_is_described_once():
    inner = _validation_error()

    class _QuotingGroup(ExceptionGroup):  # noqa: F821
        def __str__(self) -> str:
            return f"failed: {inner}"

    text = error_text(_QuotingGroup("several things failed", [inner]))

    assert text.count("1 validation error for _Counted") == 1, text
    assert REFUSED not in text, text


def test_a_validation_error_that_is_a_cause_is_not_added_to_an_unrelated_text():
    inner = _validation_error()
    try:
        try:
            raise inner
        except Exception as e:
            raise RuntimeError("the run could not continue") from e
    except RuntimeError as caught:
        error = caught

    assert error_text(error) == "the run could not continue"


@pytest.mark.skipif(sys.version_info < (3, 11), reason="exception groups")
def test_an_unexpected_groups_debug_line_holds_its_members_frames():
    inner = _validation_error()
    group = ExceptionGroup("several things failed", [inner])  # noqa: F821
    logger = MagicMock()

    log_unexpected_error(logger, group)

    (frames,), _ = logger.debug.call_args
    assert "ValidationError, a member of the group:" in frames, frames
    assert "_validation_error" in frames, frames
    assert REFUSED not in frames, frames


class _Unrenderable(RuntimeError):
    def __str__(self) -> str:
        raise ValueError("no text for this error")


def test_an_error_whose_text_cannot_be_rendered_is_still_reported():
    error = _Unrenderable()

    text = error_text(error)

    assert "_Unrenderable" in text
    assert "could not be rendered" in text


def test_an_unexpected_unrenderable_error_is_logged_as_text():
    error = _Unrenderable()
    logger = MagicMock()

    log_unexpected_error(logger, error, context="Error in a tool")

    (message,), _kwargs = logger.error.call_args
    assert isinstance(message, str)
    assert message.startswith("Error in a tool: <_Unrenderable")
    # The record's own formatting renders what it was given: text, not the error.
    assert logging.LogRecord("ash", 40, "f", 1, message, (), None).getMessage()


def _nested(depth: int) -> str:
    """An inner sequence whose removal joins its neighbors into "ESC [ m", ``depth``
    levels deep: two needs two passes of a remover, three needs three."""
    return (ESC + "[") * (depth - 1) + ESC + "[2K" + "m" * (depth - 1)


DEPTHS = pytest.mark.parametrize("depth", [2, 3, 4])


@DEPTHS
def test_an_escape_code_joined_by_removing_an_inner_one_is_removed_too(depth):
    text = error_text(RuntimeError("a" + _nested(depth) + "b"))

    assert ESCAPE_CODES.search(text) is None, repr(text)
    assert text == "ab"


@DEPTHS
def test_every_remover_reaches_a_fixed_point(depth):
    nested = _nested(depth)
    assert shown_tool_stderr("x" + nested + "y", ()) == "xy"
    assert redact_then_split("x" + nested + "y\nz", ()) == ["xy", "z"]
    try:
        raise RuntimeError("t" + nested + "u")
    except RuntimeError as caught:
        text = traceback_text(caught)
    assert ESCAPE_CODES.search(text) is None, repr(text)
