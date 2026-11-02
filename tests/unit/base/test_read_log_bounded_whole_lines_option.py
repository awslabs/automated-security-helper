# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``read_log_bounded(whole_lines=True)`` ends a cut read at its last line break.

The bounded log read stops at its byte bound wherever that falls. A caller that
hands the text to a hook hiding strings the read-edge trim does not know needs
the text to hold only lines that were read to their end, because a hidden
string that crosses the bound is not whole in what the hook sees. The option
makes that cut once, in the reader, so no caller keeps a copy of it. Without
the option the reader is as it was, and a read the bound did not cut is whole
either way.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_base import read_log_bounded

pytestmark = pytest.mark.unit

#: A value that appears nowhere in these logs, so the read-edge trim has nothing
#: to take and the text is the read as it came.
VALUES = ("NOT-IN-THE-LOG-7",)
WHOLE_LINES = "alpha\nbeta\n"
PARTIAL_LINE = "g" * 40
BOUND = len(WHOLE_LINES) + 10


def _log(tmp_path, text: str):
    path = tmp_path / "tool.stderr.log"
    # Bytes, so no platform rewrites the line breaks the tests count on.
    path.write_bytes(text.encode("utf-8"))
    return path


def test_a_cut_read_ends_at_its_last_line_break(tmp_path):
    log = _log(tmp_path, WHOLE_LINES + PARTIAL_LINE)

    text, cut = read_log_bounded(log, BOUND, VALUES, whole_lines=True)

    assert (text, cut) == (WHOLE_LINES, True)


def test_without_the_option_a_cut_read_keeps_the_partial_line(tmp_path):
    """The control: the reader is as it was for a caller that does not ask."""
    log = _log(tmp_path, WHOLE_LINES + PARTIAL_LINE)

    text, cut = read_log_bounded(log, BOUND, VALUES)

    assert (text, cut) == (WHOLE_LINES + "g" * 10, True)


@pytest.mark.parametrize(
    "frames",
    ["frame one\rframe two\r", "frame one\r\nframe two\r\n"],
    ids=["carriage return", "carriage return and line feed"],
)
def test_a_carriage_return_ends_a_line_too(tmp_path, frames):
    """A tool that redraws a progress line ends each frame with a carriage
    return and no line feed, so its frames before the cut are whole lines."""
    log = _log(tmp_path, frames + PARTIAL_LINE)

    text, cut = read_log_bounded(log, len(frames) + 10, VALUES, whole_lines=True)

    assert (text, cut) == (frames, True)


def test_a_cut_read_with_no_line_break_is_empty(tmp_path):
    log = _log(tmp_path, "g" * 100)

    text, cut = read_log_bounded(log, 50, VALUES, whole_lines=True)

    assert (text, cut) == ("", True)


@pytest.mark.parametrize("whole_lines", [False, True])
@pytest.mark.parametrize(
    "log_text",
    ["first line\nlast line, no final line break", "first line\nlast line\n"],
    ids=["no final line break", "final line break"],
)
def test_a_read_the_bound_did_not_cut_is_whole(tmp_path, log_text, whole_lines):
    log = _log(tmp_path, log_text)

    text, cut = read_log_bounded(log, 1000, VALUES, whole_lines=whole_lines)

    assert (text, cut) == (log_text, False)
