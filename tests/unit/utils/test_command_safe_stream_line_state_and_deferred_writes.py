# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The command-safe stream keeps one line model and loses no deferred write.

Properties of ``utils/command_safe_stream.py`` that nothing else pins:

- the pass-as-is paths (a terminal, no command-reading runner) leave the line
  state the checked model would have left, so a later checked write of the same
  wrap does not start mid-line by mistake, and a pass-through byte write lands
  after the tail an earlier checked byte write left held;
- a text write deferred during a byte write lands after that write's held tail;
- a write deferred after a drain's last empty check lands before the next
  write's text, not after it;
- a KeyboardInterrupt while a deferred item lands strands nothing after it;
- ``copy.copy`` of a wrap or of its checked view does not recurse;
- the checked byte view hands out no ``raw`` writer.

Every cell drives the real wrap over in-memory streams; the deferral cells set
the wrap's own state where a signal handler would, so they run on every platform.
"""

from __future__ import annotations

import copy
import io

import pytest

from automated_security_helper.utils import command_safe_stream as css

pytestmark = pytest.mark.unit


class _Terminal(io.StringIO):
    """A text stream that answers isatty, so the wrap passes text as is."""

    def isatty(self) -> bool:
        return True


class _TerminalText(io.TextIOWrapper):
    """A text layer over bytes that answers isatty, so bytes pass as is."""

    def isatty(self) -> bool:
        return True


@pytest.fixture(autouse=True)
def _no_command_reading_runner(monkeypatch):
    for name in css.COMMAND_READING_RUNNERS:
        monkeypatch.delenv(name, raising=False)


def test_the_pass_as_is_text_path_keeps_the_checked_line_model():
    """Whitespace after a line break still starts the line: a checked write that
    follows a pass-as-is write of a newline and spaces breaks its command form."""
    targets: list = [_Terminal()]
    wrap = css.CommandSafeStream(lambda: targets[0])
    wrap.write("\n  ")
    checked = io.StringIO()
    targets[0] = checked
    wrap.write("::warning::x")
    assert checked.getvalue() == "\\x3a:warning::x", checked.getvalue()


def test_a_pass_through_byte_write_lands_after_the_held_tail():
    """The start of a character an earlier checked byte write held lands first,
    as its own bytes, when the next byte write passes as is."""
    raw = io.BytesIO()
    checked_target = io.TextIOWrapper(raw, encoding="utf-8", write_through=True)
    targets: list = [checked_target]
    wrap = css.CommandSafeStream(lambda: targets[0], check_buffer=True)
    wrap.buffer.write(b"caf\xc3")
    assert raw.getvalue() == b"caf", raw.getvalue()
    terminal_raw = io.BytesIO()
    targets[0] = _TerminalText(terminal_raw, encoding="utf-8", write_through=True)
    wrap.buffer.write(b"\xa9\n")
    assert terminal_raw.getvalue() == b"\xc3\xa9\n", terminal_raw.getvalue()


def test_a_deferred_text_write_lands_after_the_held_tail():
    """A text write deferred during a byte write that left a tail held lands
    after that tail, not ahead of it."""
    raw = io.BytesIO()
    target = io.TextIOWrapper(raw, encoding="utf-8", write_through=True)
    wrap = css.CommandSafeStream(lambda: target, check_buffer=True)
    wrap.buffer.write(b"caf\xc3")
    # What a signal handler's write inside that byte write does: deferred.
    wrap._mid_write = True
    wrap.write("X\n")
    wrap._end_write(failed=False)
    wrap.buffer.write(b"\xa9\n")
    assert raw.getvalue() == b"caf\xc3X\n\xa9\n", raw.getvalue()


def test_a_write_stranded_after_a_drain_lands_before_the_next_text():
    target = io.StringIO()
    wrap = css.CommandSafeStream(lambda: target)
    # A write made between the drain's last empty check and the clearing of
    # _mid_write: deferred with no drain left to land it.
    wrap._mid_write = True
    wrap.write("late\n")
    wrap._mid_write = False
    wrap.write("next\n")
    assert target.getvalue() == "late\nnext\n", target.getvalue()


def test_a_flush_lands_a_stranded_write():
    target = io.StringIO()
    wrap = css.CommandSafeStream(lambda: target)
    wrap._mid_write = True
    wrap.write("late\n")
    wrap._mid_write = False
    wrap.flush()
    assert target.getvalue() == "late\n", target.getvalue()


def test_a_keyboard_interrupt_in_a_deferred_write_strands_nothing_after_it():
    class Interrupting(io.StringIO):
        def write(self, text: str) -> int:
            if text == "a\n":
                raise KeyboardInterrupt
            return super().write(text)

    target = Interrupting()
    wrap = css.CommandSafeStream(lambda: target)
    wrap._mid_write = True
    wrap._pending = ["a\n", "b\n"]
    with pytest.raises(KeyboardInterrupt):
        wrap._end_write(failed=False)
    assert target.getvalue() == "b\n", target.getvalue()
    assert wrap._pending == []
    assert wrap._mid_write is False


def test_copy_copy_of_the_wrap_does_not_recurse():
    target = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    wrap = css.CommandSafeStream(lambda: target, check_buffer=True)
    assert isinstance(copy.copy(wrap), css.CommandSafeStream)


@pytest.mark.parametrize("cls", [css.CommandSafeStream, css.CommandSafeBuffer])
def test_an_attribute_read_on_an_uninitialized_instance_is_an_attribute_error(cls):
    """What copy.copy does before it fills the new instance's __dict__ in: a
    lookup there must raise AttributeError, never recurse through ``target``.

    Made the way copy.copy makes it, ``cls.__new__(cls)``: ``object.__new__`` on
    a subclass of an ``_io`` type raises TypeError on CPython 3.10 and 3.11
    (those types have a ``__new__`` of their own), so the earlier shape errored
    on those interpreters before the lookup under test ran.
    """
    half_made = cls.__new__(cls)
    with pytest.raises(AttributeError):
        half_made.anything


@pytest.mark.parametrize("at_line_start", [True, False])
@pytest.mark.parametrize(
    "text",
    [
        "",
        "plain",
        "plain\n",
        "\n",
        "\r\n  ",
        "  \x1b[31m",
        "  \x1b[31mx",
        "::set-output name=x::y",
        "##vso[task.setvariable]x",
        "a\r##[group]b",
        "\n::x\n",
        "\udc80\udcff",
        "tail\rhead",
    ],
    ids=[
        "empty",
        "word",
        "word-break",
        "break",
        "crlf-spaces",
        "lead-only",
        "lead-then-text",
        "colon-command",
        "hash-command",
        "break-then-hash",
        "break-colon-break",
        "escaped-bytes",
        "cr-head",
    ],
)
def test_the_line_state_read_alone_is_the_checked_models(text, at_line_start):
    """The pass-as-is write reads the line state without building the checked
    text; its answer is the second value ``_safe`` returns, for every shape of
    break, lead and command the check knows."""
    target = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    wrap = css.CommandSafeStream(lambda: target, check_buffer=True)
    assert (
        wrap._line_state_after(text, at_line_start)
        == wrap._safe(text, at_line_start)[1]
    )


def test_the_checked_view_hands_out_no_raw_writer():
    raw = io.BufferedWriter(io.BytesIO())
    target = io.TextIOWrapper(raw, encoding="utf-8")
    wrap = css.CommandSafeStream(lambda: target, check_buffer=True)
    # The control: the real buffer does carry a raw writer.
    assert target.buffer.raw is not None
    with pytest.raises(AttributeError):
        wrap.buffer.raw
