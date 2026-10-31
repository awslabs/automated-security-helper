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
  write's text, not after it, on a flush, and on the old target when the wrap is
  retargeted; its error, when it raises, follows the next write's text instead
  of replacing it;
- the held tail lands once, ahead of every deferred item, byte items included;
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
    # newline="\n": the deferred text lands through this text layer, whose
    # default newline mode writes os.linesep (\r\n on Windows), while the byte
    # writes reach raw as they are; the test compares raw bytes.
    target = io.TextIOWrapper(raw, encoding="utf-8", newline="\n", write_through=True)
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


def test_retargeting_lands_a_stranded_write_on_the_old_target():
    """A write stranded in _pending goes to the target it was written to before
    the replacement, as a flush lands it; left in the old wrap, it went with it."""
    old = io.StringIO()
    wrap = css.CommandSafeStream(lambda: old)
    wrap._mid_write = True
    wrap.write("late\n")
    wrap._mid_write = False
    new = io.StringIO()
    wrap.retargeted(lambda _target: new)
    assert old.getvalue() == "late\n", old.getvalue()
    assert new.getvalue() == ""


def test_a_stranded_writes_error_does_not_lose_the_callers_text():
    """A stranded item whose write raises is drained ahead of a new write; its
    error is raised after the new write's own text has landed, not instead of it."""

    class Refusing(io.StringIO):
        def write(self, text: str) -> int:
            if text == "bad\n":
                raise OSError("refused")
            return super().write(text)

    target = Refusing()
    wrap = css.CommandSafeStream(lambda: target)
    wrap._pending = ["bad\n"]
    with pytest.raises(OSError, match="refused"):
        wrap.write("mine\n")
    assert target.getvalue() == "mine\n", target.getvalue()
    assert wrap._pending == []
    assert wrap._mid_write is False


def test_a_stranded_writes_error_does_not_lose_the_callers_text_on_a_checked_wrap():
    """The same as above on a wrap that checks its bytes, the shape of
    sys.stderr in MCP server mode: the bytes a buffer write left held were landed
    first, outside the held-error scheme, and a stranded item's error came out of
    that step before the caller's text was written."""

    class Refusing(io.StringIO):
        def write(self, text: str) -> int:
            if text == "bad\n":
                raise OSError("refused")
            return super().write(text)

    target = Refusing()
    wrap = css.CommandSafeStream(lambda: target, check_buffer=True)
    wrap._pending = ["bad\n"]
    with pytest.raises(OSError, match="refused"):
        wrap.write("mine\n")
    assert target.getvalue() == "mine\n", target.getvalue()
    assert wrap._pending == []
    assert wrap._mid_write is False


class _Buffer:
    """A byte buffer whose next write can be made to refuse."""

    def __init__(self) -> None:
        self.writes: list[bytes] = []
        self.refuse_next = False

    def write(self, data: bytes) -> int:
        if self.refuse_next:
            self.refuse_next = False
            raise OSError("tail refused")
        self.writes.append(data)
        return len(data)

    def flush(self) -> None:
        return None


class _TextWithBuffer:
    """A text target that is not a terminal and has a byte buffer of its own."""

    def __init__(self) -> None:
        self.texts: list[str] = []
        self.buffer = _Buffer()

    def write(self, text: str) -> int:
        self.texts.append(text)
        return len(text)

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        return False


def test_a_failing_tail_write_does_not_strand_the_deferred_items():
    """The held tail is emitted ahead of the first deferred text item; that write
    raising used to leave the drain before its loop, so every pending item stayed
    stranded. The error is held like an item's: the items land, then it is raised."""
    target = _TextWithBuffer()
    wrap = css.CommandSafeStream(lambda: target, check_buffer=True)
    wrap.buffer.write(b"caf\xc3")
    assert target.buffer.writes == [b"caf"], target.buffer.writes
    target.buffer.refuse_next = True
    # A signal handler's text write inside a byte write: deferred.
    wrap._mid_write = True
    wrap.write("T\n")
    with pytest.raises(OSError, match="tail refused"):
        wrap._end_write(failed=False)
    assert target.texts == ["T\n"], target.texts
    assert wrap._pending == []
    assert wrap._mid_write is False


def test_the_held_tail_lands_ahead_of_every_deferred_item():
    """Bytes a byte write left held (an incomplete character's start) land once,
    before the deferred items, byte items included: emitted only before the first
    deferred text item, the tail landed after the deferred bytes before it."""
    raw = io.BytesIO()
    # newline="\n" for the same reason as in the deferred-text test above.
    target = io.TextIOWrapper(raw, encoding="utf-8", newline="\n", write_through=True)
    wrap = css.CommandSafeStream(lambda: target, check_buffer=True)
    wrap.buffer.write(b"caf\xc3")
    # A signal handler's byte write and text write inside that byte write.
    wrap._mid_write = True
    wrap.buffer.write(b"B2")
    wrap.write("T\n")
    wrap._end_write(failed=False)
    assert raw.getvalue() == b"caf\xc3B2T\n", raw.getvalue()


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


def test_copy_copy_of_the_wrap_is_a_fresh_wrap_of_the_same_target():
    """The copy shares the target and the buffer rule, and nothing of this wrap's
    state: a shallow copy shared the lock, the deferred-write list and the checked
    view (still owned by the original), so the two wraps kept two line models over
    one stream and drained each other's deferred writes."""
    target = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", write_through=True)
    wrap = css.CommandSafeStream(lambda: target, check_buffer=True)
    wrap._mid_write = True
    wrap.write("deferred\n")
    duplicate = copy.copy(wrap)
    assert duplicate.target is wrap.target
    assert duplicate._pending == [] and duplicate._pending is not wrap._pending
    assert duplicate._lock is not wrap._lock
    assert duplicate.buffer is not wrap.buffer
    assert duplicate.buffer._owner is duplicate
    plain = copy.copy(css.CommandSafeStream(lambda: target))
    assert plain._checked_buffer is None


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
        # A terminal sequence whose intermediate bytes are "##" and final byte
        # "[": lead unbroken, text once the check escapes its first "#".
        "\x1b[##[",
        "\n\x1b[##[",
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
        "csi-hash-intermediates",
        "break-then-csi-hash-intermediates",
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
