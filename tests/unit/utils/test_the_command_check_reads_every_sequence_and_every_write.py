# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The command check reads the sequences error_text strips, every write shape of
a stream, and one long line in time linear in its length.

CommandSafeStream breaks a line a CI runner would read as a workflow command.
Four properties of it that nothing else pinned:

- the terminal sequences it skips before a line-start "::", and allows inside
  "##name[", are the set utils/error_text.py strips (ESCAPE_CODES): a colon-form
  SGR ("\\x1b[38:5:196m") or an OSC hyperlink before the "::" hid the command
  from the check while the runner, which drops both, read it;
- the "##name[" scan is bounded by the line's length: a line holding a long run
  of backslashes and no command was scanned once per backslash, each scan walking
  the rest of the run, so one such line stalled every write to the wrap;
- writelines() goes through the check and moves the line state as write() does,
  instead of reaching the target's own writelines past both;
- a target lookup that returns None (sys.stdout is None under pythonw, or in a
  service with its descriptors closed) discards the write, as Rich's Console
  does, instead of raising AttributeError from None.

Each test drives the real wrap over an in-memory stream, which is no terminal,
so the check applies whatever the environment says about the runner.
"""

from __future__ import annotations

import io
import time

import pytest

from automated_security_helper.utils import error_text
from automated_security_helper.utils.command_safe_stream import CommandSafeStream

pytestmark = pytest.mark.unit

#: A colon-form SGR, as a 256-color terminal writes it.
COLON_SGR = "\x1b[38:5:196m"
#: An OSC 8 hyperlink opener, ended by ESC-backslash.
HYPERLINK = "\x1b]8;;https://example.invalid/\x1b\\"
#: A plain SGR, which the check always read: the control.
PLAIN_SGR = "\x1b[32m"


def _wrapped() -> tuple[CommandSafeStream, io.StringIO]:
    sink = io.StringIO()
    return CommandSafeStream(lambda: sink), sink


@pytest.mark.parametrize(
    "sequence",
    [COLON_SGR, HYPERLINK, PLAIN_SGR],
    ids=["colon-form-sgr", "osc-hyperlink", "plain-sgr"],
)
def test_a_line_start_command_behind_a_stripped_sequence_is_broken(sequence):
    # The control: error_text strips this very sequence before a reader sees it.
    assert error_text.ESCAPE_CODES.fullmatch(sequence) is not None
    stream, sink = _wrapped()
    stream.write(f"{sequence}::add-mask::value\n")
    assert sink.getvalue() == f"{sequence}\\x3a:add-mask::value\n"


def test_a_named_hash_command_colored_with_a_colon_form_sgr_is_broken():
    stream, sink = _wrapped()
    stream.write(f"text ##vso{COLON_SGR}[task.setvariable variable=x]y\n")
    assert (
        sink.getvalue() == f"text \\x23#vso{COLON_SGR}[task.setvariable variable=x]y\n"
    )


def _best_write_time(run_length: int) -> float:
    """The fastest of three writes of one line holding ``run_length`` backslashes
    and no command, with the check's output compared with the line."""
    line = "\\" * run_length + " and no command\n"
    best = float("inf")
    for _attempt in range(3):
        stream, sink = _wrapped()
        started = time.perf_counter()
        stream.write(line)
        best = min(best, time.perf_counter() - started)
        assert sink.getvalue() == line
    return best


def test_a_long_run_of_backslashes_is_scanned_once():
    """Eight times the run takes about eight times as long when each backslash is
    scanned once, and sixty-four times as long when each scan walks the rest of the
    run. The bound sits between: a fixed wall-clock limit passed or failed on the
    host's load as much as on the scan, and the best of three runs cancels a
    scheduling stall in either measurement."""
    small = _best_write_time(10_000)
    large = _best_write_time(80_000)
    # The floor keeps a very fast small run from turning timer noise into a ratio.
    assert large < 24 * max(small, 1e-3), (
        f"8x the backslashes took {large / max(small, 1e-3):.0f}x as long to check"
    )


def test_the_backslashes_before_a_named_hash_command_are_still_doubled():
    stream, sink = _wrapped()
    stream.write("\\" * 2 + "##vso[x]\n")
    assert sink.getvalue() == "\\" * 4 + "\\x23#vso[x]\n"


def test_writelines_goes_through_the_check():
    stream, sink = _wrapped()
    stream.writelines(["::warning::first\n", "::error::second\n"])
    assert sink.getvalue() == "\\x3a:warning::first\n\\x3a:error::second\n"


def test_writelines_moves_the_line_state():
    stream, sink = _wrapped()
    stream.writelines(["mid-line text"])
    stream.write("::no command mid-line\n")
    assert sink.getvalue() == "mid-line text::no command mid-line\n"


def test_a_write_to_a_missing_standard_stream_is_discarded():
    stream = CommandSafeStream(lambda: None)
    text = "::warning::x\n"
    assert stream.write(text) == len(text)
    stream.writelines(["a\n"])
    stream.flush()
    assert stream.isatty() is False
    assert stream.encoding == "utf-8"
