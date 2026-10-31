# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The read-edge trim's long-code fallback is anchored at the last ESC.

``trimmed_at_read_edge`` strips junk a bound-cut read can leave at a tail. When
the windowed search finds none, it looks once more for a single code longer than
the window, starting at the text's last ESC. That search was unanchored: the
pattern was tried at every position between the ESC and the end, and its
replacement-run alternative scanned to the end from each of them, so a long run
of U+FFFD behind the last ESC that did not reach the end cost a quadratic walk
inside a scan's failure handling. Anchored at the ESC, the fallback is one
attempt, and the text it keeps is the same.
"""

from __future__ import annotations

import time

import pytest

from automated_security_helper.base.plugin_base import trimmed_at_read_edge

pytestmark = pytest.mark.unit


def test_a_replacement_run_behind_the_last_escape_is_trimmed_quickly():
    """The run does not reach the end ("x" does), so the windowed search finds
    nothing and the fallback runs. At the base its unanchored search took over
    a second at 20,000 characters on the host that measured it; the fix answers
    in milliseconds. The bound is loose so a loaded runner passes."""
    # Named by its code point, so a tool that rewrites the file cannot swap the
    # character for a look-alike and leave the run unexercised.
    replacement = chr(0xFFFD)
    assert replacement.encode("utf-8") == b"\xef\xbf\xbd"
    text = "kept line\n\x1b" + replacement * 60000 + "x"

    started = time.perf_counter()
    trimmed = trimmed_at_read_edge(text, ())
    elapsed = time.perf_counter() - started

    assert elapsed < 2.0, elapsed
    # Nothing at the end is junk, so nothing is cut.
    assert trimmed == text


def test_an_over_long_cut_off_code_at_the_end_is_still_trimmed():
    """The case the fallback exists for: a CSI longer than the window, cut
    before its final byte, is removed whole."""
    text = "kept line\n" + "\x1b[" + "1;" * 200

    assert trimmed_at_read_edge(text, ()) == "kept line\n"


def test_a_complete_over_long_osc_at_the_end_is_still_trimmed():
    text = "kept line\n" + "\x1b]8;;" + "a" * 300 + "\x1b\\"

    assert trimmed_at_read_edge(text, ()) == "kept line\n"
