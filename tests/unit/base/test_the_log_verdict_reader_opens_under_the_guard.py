"""``log_says`` opens the stderr log under fs_guard's open semantics.

``_carry_stderr_log``'s docstring names the threat: a process the sandboxed
scanner left running may replace the log between the guarded bounded read and
this verdict read. The verdict-only reasoning in the bounded-reads guard
covers what the reader can LEAK, not how it opens -- a FIFO left at the name
must fail fast instead of blocking the scan forever, and a symlink at the
name must not be followed, exactly as ``fs_guard.read_bytes_at_most``
refuses both.
"""

import os
import threading

import pytest

from automated_security_helper.base.plugin_base import log_says

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(os.name == "nt", reason="POSIX file semantics"),
]


def test_a_fifo_at_the_log_name_fails_fast_instead_of_blocking(tmp_path):
    """A FIFO with no writer blocks a plain open() forever; the guarded open
    must refuse it quickly instead."""
    fifo = tmp_path / "Scanner.stderr.log"
    os.mkfifo(fifo)
    outcome = {}

    def probe():
        try:
            outcome["value"] = log_says(fifo, "anything")
        except OSError as error:
            outcome["error"] = error

    thread = threading.Thread(target=probe, daemon=True)
    thread.start()
    thread.join(2.0)
    if thread.is_alive():
        # Unblock the open so the probe thread does not outlive the test;
        # opening the write side completes the blocked read-side open.
        try:
            unblock = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
            os.close(unblock)
        except OSError:
            pass
        pytest.fail("log_says blocked on a FIFO at the log's name")
    assert "error" in outcome, outcome


def test_a_symlink_at_the_log_name_is_not_followed(tmp_path):
    real = tmp_path / "elsewhere.log"
    real.write_text("No solution found when resolving\n", encoding="utf-8")
    link = tmp_path / "Scanner.stderr.log"
    link.symlink_to(real)

    with pytest.raises(OSError):
        log_says(link, "No solution found")


def test_a_regular_log_still_answers_the_phrase(tmp_path):
    log = tmp_path / "Scanner.stderr.log"
    log.write_text(
        "earlier output\nNo solution\x1b[K found when resolving\n", encoding="utf-8"
    )
    assert log_says(log, "No solution found when resolving")
    assert not log_says(log, "a phrase the log does not hold")


def test_a_phrase_split_across_the_chunk_boundary_is_still_seen(tmp_path):
    """The byte-chunked guarded read must keep the overlap semantics: a phrase
    (and a multi-byte character) straddling a chunk edge still matches."""
    log = tmp_path / "Scanner.stderr.log"
    filler = "x" * (65536 - 10)
    log.write_text(filler + "No solution found when resolving é\n", encoding="utf-8")
    assert log_says(log, "No solution found when resolving é")


PHRASE = "No solution found when resolving"

# The carried-tail overlap must also survive an escape code or a whitespace
# run sitting ON the chunk edge inside the phrase: both are folded away
# before the match, and a reader that drops the carry sees neither half.
CHUNK_EDGE_SHAPES = {
    "code-inside-the-phrase": (
        "x" * (65536 - 13),
        "No solution\x1b[31m found when resolving",
    ),
    "whitespace-run-inside-the-phrase": (
        "x" * (65536 - 14),
        "No solution   \n   found when resolving",
    ),
}


@pytest.mark.parametrize("shape", sorted(CHUNK_EDGE_SHAPES))
def test_a_folded_phrase_split_across_the_chunk_boundary_is_still_seen(tmp_path, shape):
    head, spelled = CHUNK_EDGE_SHAPES[shape]
    log = tmp_path / "Scanner.stderr.log"
    log.write_text(head + spelled + " and then more\n", encoding="utf-8")
    assert len(head) < 65536 < len(head) + len(spelled), "the cell shows nothing"
    assert log_says(log, PHRASE) is True


def test_the_bound_counts_bytes_as_the_docstring_says(tmp_path):
    """ "First *bound* bytes" means bytes: 600 two-byte characters are 1200
    bytes, so a 1000-byte bound stops before the phrase behind them, and a
    bound past them reads it. A character-counting reader would read past the
    byte bound and answer True at 1000."""
    log = tmp_path / "Scanner.stderr.log"
    log.write_text("é" * 600 + PHRASE + "\n", encoding="utf-8")
    assert len(("é" * 600).encode("utf-8")) == 1200
    assert log_says(log, PHRASE, bound=1000) is False
    assert log_says(log, PHRASE, bound=1300) is True
