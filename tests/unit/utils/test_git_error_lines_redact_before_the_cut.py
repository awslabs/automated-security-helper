# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Git stderr excerpts are redacted whole before any line cut.

Both sites quote git's stderr in a problem clause after cutting it: the first
line (``get_scan_set._rev_parse_toplevel``), or the first non-empty lines
stripped and joined with one space (``scan_output_dirs._first_lines``). A value
holding a line break that spans the cut would leave a fragment ("its first
line", or the halves re-joined with a space) that the downstream whole-value
redaction cannot match. Redacting the whole text first and cutting the
redacted lines (``redact_then_split``) means no clause can hold a piece of a
value. Whether an environment-read value can reach these texts is unverified;
the sites take ``values`` from their callers, which today pass an explicit
empty tuple.
"""

import subprocess
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import get_scan_set, scan_output_dirs

pytestmark = pytest.mark.unit

FIRST = "wq2v-first-piece-k8d3"
SECOND = "wq2v-second-piece-m5f1"

_CASES = [
    pytest.param(FIRST + SECOND, id="single-line"),
    pytest.param(FIRST + "\n" + SECOND, id="multi-line-spanning-the-cut"),
]


@pytest.mark.parametrize("value", _CASES)
def test_rev_parse_problem_clause_holds_no_piece_of_a_value(
    monkeypatch, tmp_path, value
):
    """The problem clause quotes git's first stderr line; the cut runs on the
    redacted text, so neither the value nor a line of it survives."""

    def fake_run(*args, **kwargs):
        return SimpleNamespace(
            returncode=128,
            stdout=b"",
            stderr=(
                f"fatal: unsafe repository ('{value}' is owned by someone else)\n"
            ).encode(),
        )

    monkeypatch.setattr(
        get_scan_set,
        "subprocess",
        SimpleNamespace(
            run=fake_run,
            DEVNULL=subprocess.DEVNULL,
            TimeoutExpired=subprocess.TimeoutExpired,
        ),
    )
    root, problem = get_scan_set._rev_parse_toplevel(tmp_path, values=(value,))
    assert root is None
    assert "unsafe repository" in (problem or ""), problem
    assert FIRST not in (problem or "") and SECOND not in (problem or ""), problem


@pytest.mark.parametrize("value", _CASES)
def test_first_lines_hold_no_piece_of_a_value(value):
    """The joined excerpt strips and re-joins stderr lines with one space; the
    join runs on the redacted lines, so a value spanning two lines never comes
    back as the one-space spelling the downstream redaction cannot match."""
    said = scan_output_dirs._first_lines(
        f"fatal: '{value}/out' is outside repository\n".encode(), values=(value,)
    )
    assert "outside repository" in said, said
    assert FIRST not in said and SECOND not in said, said
