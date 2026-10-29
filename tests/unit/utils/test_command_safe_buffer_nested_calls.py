"""The checked byte view under a nested call from a signal handler.

Two properties of CommandSafeBuffer that nothing else pins:

- a flush made from a signal handler inside a byte write leaves the held
  tail held: emitted there, the incomplete character's first bytes would land
  ahead of the text they belong after, and the character's rest, written
  next, would be orphaned;
- a byte write made from a signal handler inside another write answers the
  count of bytes it took, as io.BufferedIOBase.write must, wherever the
  wrap's design lands the bytes themselves.

Each cell drives the real wrap over an in-memory stream, with the nested
call raised from the module's own line scan, the way the stderr suite's
signal cells do.
"""

import io
import signal
import sys

import pytest

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(not hasattr(signal, "SIGUSR1"), reason="no SIGUSR1 here"),
]


def _checked_stderr(monkeypatch):
    """sys.stderr replaced by an in-memory stream under the command check,
    returning the raw buffer the target writes into."""
    import automated_security_helper.utils.command_safe_stream  # noqa: F401
    from automated_security_helper.utils.log import check_commands_of_stderr

    raw = io.BytesIO()
    monkeypatch.setattr(
        sys,
        "stderr",
        io.TextIOWrapper(raw, encoding="utf-8", write_through=True),
    )
    check_commands_of_stderr()
    return raw


def _armed_line_break(monkeypatch):
    """The module's line scan, raising SIGUSR1 once when armed, so a handler
    runs at the exact point a write of the wrap is under way."""
    import automated_security_helper.utils.command_safe_stream as css

    line_break = css._LINE_BREAK

    class SplitThatSignals:
        armed = False

        def split(self, text):
            if SplitThatSignals.armed:
                SplitThatSignals.armed = False
                signal.raise_signal(signal.SIGUSR1)
            return line_break.split(text)

    monkeypatch.setattr(css, "_LINE_BREAK", SplitThatSignals())
    return SplitThatSignals


def test_a_handlers_flush_inside_a_byte_write_leaves_the_held_tail_held(
    monkeypatch,
):
    """The byte write holds an incomplete character's start; a flush raised
    from a signal handler while that write is still being checked emits
    nothing: the character's bytes land together once its rest arrives."""
    raw = _checked_stderr(monkeypatch)
    arm = _armed_line_break(monkeypatch)
    flushed: list = []

    def handler(signum, frame):
        sys.stderr.buffer.flush()
        flushed.append(True)

    previous = signal.signal(signal.SIGUSR1, handler)
    try:
        arm.armed = True
        sys.stderr.buffer.write(b"hello\xc3")
        sys.stderr.buffer.write(b"\xa9\n")
        sys.stderr.flush()
    finally:
        signal.signal(signal.SIGUSR1, previous)

    # The control: the handler's flush ran inside the first write.
    assert flushed == [True]
    assert raw.getvalue() == b"hello\xc3\xa9\n", raw.getvalue()


def test_a_nested_byte_write_answers_the_count_of_bytes_it_took(monkeypatch):
    """A byte write made from a signal handler inside a text write answers
    len(data), as io.BufferedIOBase.write must: a caller that loops on short
    writes would otherwise re-send bytes the wrap already took. Where the
    bytes land is the wrap's own design; the count is not."""
    raw = _checked_stderr(monkeypatch)
    arm = _armed_line_break(monkeypatch)
    counts: list = []

    def handler(signum, frame):
        counts.append(sys.stderr.buffer.write(b"note\n"))

    previous = signal.signal(signal.SIGUSR1, handler)
    try:
        arm.armed = True
        sys.stderr.write("hello\n")
        sys.stderr.flush()
    finally:
        signal.signal(signal.SIGUSR1, previous)

    # The controls: the nested write ran, and its bytes landed whole.
    assert len(counts) == 1, counts
    written = raw.getvalue()
    assert b"note\n" in written, written
    assert b"hello\n" in written, written
    assert counts == [5], counts
