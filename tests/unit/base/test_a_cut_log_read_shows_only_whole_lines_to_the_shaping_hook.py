# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A log read that the bound cut shows the shaping hook whole lines only.

The failure message quotes the tool's stderr log through a bounded read, and
the plugin's text-shaping hook hides what the tool echoes back from its own
input. The read stops at its bound wherever that falls. A string the hook hides
that crosses the bound is not whole in the text the hook sees, so the hook
leaves the piece of it that was read, and the excerpt quoted that piece at its
tail, where the message keeps the end of the text. The read now ends at its last
line break when the bound cut it, so the hook sees only lines that were read to
their end. A read the bound did not cut keeps its last line, with or without a
final line break.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.scanner_plugin import _STDERR_EXCERPT_LIMIT
from tests.unit.base.scanner_support import build_scanner

pytestmark = pytest.mark.unit

PLANTED = "hunter2-planted-password"
#: What of the planted string the read keeps when the bound lands inside it.
KEPT = PLANTED[:8]
BOUND = _STDERR_EXCERPT_LIMIT * 32
MARKER = "the log continues beyond this excerpt"


def _results_file(tmp_path, log_text):
    results = tmp_path / "scanners" / "stub" / "results.json"
    results.parent.mkdir(parents=True)
    (results.parent / "StubScanner.stderr.log").write_text(log_text, encoding="utf-8")
    return results


def _hiding_the_planted(scanner, monkeypatch):
    monkeypatch.setattr(
        type(scanner),
        "_tool_text_for_records",
        lambda self, text, stream: text.replace(PLANTED, "[removed]"),
    )


def _log_whose_last_line_crosses_the_bound() -> str:
    """Whole lines, then a last line holding the planted string with the bound
    landing after its first eight characters."""
    whole = ("a" * 99 + "\n") * ((BOUND - 40) // 100)
    pad = BOUND - len(whole) - len(KEPT)
    assert pad >= 0
    return whole + "z" * pad + PLANTED + " rest of the line\nlater line\n"


def test_a_hidden_string_crossing_the_read_bound_is_not_quoted_in_part(
    plugin_context, tmp_path, monkeypatch
):
    scanner = build_scanner(plugin_context)
    _hiding_the_planted(scanner, monkeypatch)
    results = _results_file(tmp_path, _log_whose_last_line_crosses_the_bound())

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert KEPT not in detail, detail[-400:]
    assert PLANTED not in detail, detail[-400:]
    # The lines read to their end are still shown, and the message still says
    # the log goes on and names it.
    assert "a" * 50 in detail, detail[-400:]
    assert MARKER in detail, detail[-400:]
    assert "StubScanner.stderr.log" in detail, detail[-400:]


def test_a_cut_read_with_no_line_break_shows_the_marker_alone(
    plugin_context, tmp_path, monkeypatch
):
    scanner = build_scanner(plugin_context)
    _hiding_the_planted(scanner, monkeypatch)
    pad = BOUND - len(KEPT)
    results = _results_file(tmp_path, "z" * pad + PLANTED + " and more after it")

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert KEPT not in detail, detail[-400:]
    assert "zzzz" not in detail, detail[-400:]
    assert MARKER in detail, detail[-400:]
    assert "No stderr captured" not in detail, detail[-400:]


def _results_file_bytes(tmp_path, log_bytes):
    """As :func:`_results_file`, written as bytes: a platform that rewrites
    line feeds on a text write cannot change which line breaks the log holds."""
    results = tmp_path / "scanners" / "stub" / "results.json"
    results.parent.mkdir(parents=True)
    (results.parent / "StubScanner.stderr.log").write_bytes(log_bytes)
    return results


def _progress_frames_whose_last_crosses_the_bound() -> bytes:
    """Frames separated only by carriage returns (a tool redrawing a progress
    line), the last one holding the planted string with the bound landing
    after its first eight characters; no line feed anywhere in the read."""
    whole = ("f" * 99 + "\r") * ((BOUND - 40) // 100)
    pad = BOUND - len(whole) - len(KEPT)
    assert pad >= 0
    tail = "z" * pad + PLANTED + " rest of the frame\rlater frame\r"
    return (whole + tail).encode("utf-8")


def test_a_cut_read_of_carriage_return_frames_keeps_the_earlier_frames(
    plugin_context, tmp_path, monkeypatch
):
    """The whole-line cut treats a carriage return as a line break: the frames
    read to their end are shown, and the frame the bound landed in is dropped
    with the piece of the hidden string it held. Under a line-feed-only cut
    this read holds no line feed at all, so the cut kept nothing and the
    message named the log alone."""
    scanner = build_scanner(plugin_context)
    _hiding_the_planted(scanner, monkeypatch)
    results = _results_file_bytes(
        tmp_path, _progress_frames_whose_last_crosses_the_bound()
    )

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert KEPT not in detail, detail[-400:]
    assert PLANTED not in detail, detail[-400:]
    # The frame the bound landed in is dropped whole.
    assert "zzzz" not in detail, detail[-400:]
    # The earlier frames are kept, and the message still says the log
    # continues and names it.
    assert "f" * 50 in detail, detail[-400:]
    assert MARKER in detail, detail[-400:]
    assert "StubScanner.stderr.log" in detail, detail[-400:]


@pytest.mark.parametrize(
    "log_text",
    ["first line\nlast line, no final line break", "first line\nlast line\n"],
    ids=["no final line break", "final line break"],
)
def test_a_read_the_bound_did_not_cut_keeps_its_last_line(
    plugin_context, tmp_path, monkeypatch, log_text
):
    """The control: only a cut read loses its last piece."""
    scanner = build_scanner(plugin_context)
    _hiding_the_planted(scanner, monkeypatch)
    results = _results_file(tmp_path, log_text)

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert "first line" in detail, detail
    assert "last line" in detail, detail
    assert MARKER not in detail, detail
