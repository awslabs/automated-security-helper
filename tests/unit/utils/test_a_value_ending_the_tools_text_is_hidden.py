# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value whose last character ends the tool's whole text is still hidden.

The pre-installed verdicts strip uv's text before the one redaction. A
whole-text strip removes a trailing whitespace-class character, and an
env-read value can END in one (a form feed, a line feed) while sitting at
the very end of uv's output: the stripped text then holds the value minus
its last character, no whole spelling matches, and the fragment prints in
the verdict detail the reports carry. The strip belongs AFTER the
redaction, where there is no value left for it to respell.

Two routes own such a strip here: the ``--version`` probe's excerpt and the
dry-run detail (which feeds both the unverifiable arm and the cause
extraction). Each cell plants the value at the text's end and reads the
verdict's detail; the control plants it mid-text, where no strip reaches
it, so the redaction's own coverage is pinned apart from the fix.
"""

from __future__ import annotations

import subprocess

import pytest

from automated_security_helper.utils import pre_installed_tool

#: The value's visible core: this spelling surviving anywhere is the leak.
_CORE = "ops-canary-kq81"

_ENDINGS = [
    pytest.param("\x0c", id="form-feed"),
    pytest.param("\n", id="line-feed"),
]


def _answers(monkeypatch, returncode: int, stderr: str) -> None:
    completed = subprocess.CompletedProcess(
        args=["irrelevant"], returncode=returncode, stdout="", stderr=stderr
    )
    monkeypatch.setattr(pre_installed_tool, "_run", lambda command, timeout: completed)


@pytest.mark.parametrize("ending", _ENDINGS)
def test_the_failed_probes_excerpt_hides_a_value_ending_the_text(monkeypatch, ending):
    value = _CORE + ending
    _answers(monkeypatch, 3, f"error: cannot start near {value}")
    verdict = pre_installed_tool._verify(
        "/fake/copy", "faketool", [], None, "faketool", "/fake/uv", values=(value,)
    )
    # The carrier first: a route that discarded the probe's text would pass
    # the leak assertion with nothing shown at all.
    assert "cannot start near" in verdict.detail
    assert _CORE not in verdict.detail, (
        "the probe's text ends in the value, and the excerpt printed it "
        "minus its last character"
    )


@pytest.mark.parametrize("ending", _ENDINGS)
def test_the_dry_run_detail_hides_a_value_ending_the_text(monkeypatch, ending):
    value = _CORE + ending
    # No unsatisfiable marker and a non-zero exit: the unverifiable arm,
    # whose detail is uv's own output.
    _answers(monkeypatch, 2, f"error: resolver crashed near {value}")
    verdict = pre_installed_tool._judge(
        "/fake/copy",
        "faketool",
        [],
        None,
        "faketool",
        "/fake/uv",
        "/fake/python",
        None,
        "its environment (/fake/python)",
        values=(value,),
    )
    assert verdict.status == "unverifiable"
    # The carrier first: a route that discarded uv's text would pass the
    # leak assertion with nothing shown at all.
    assert "resolver crashed" in verdict.detail
    assert _CORE not in verdict.detail, (
        "uv's text ends in the value, and the detail printed it minus its "
        "last character"
    )


@pytest.mark.parametrize("ending", _ENDINGS)
def test_the_cause_hides_a_value_ending_the_text(monkeypatch, ending):
    value = _CORE + ending
    # An unsatisfiable marker: the cause route, through _first_cause.
    _answers(
        monkeypatch,
        1,
        "No solution found when resolving dependencies:\n"
        f"  Because faketool depends on {value}",
    )
    verdict = pre_installed_tool._judge(
        "/fake/copy",
        "faketool",
        [],
        None,
        "faketool",
        "/fake/uv",
        "/fake/python",
        None,
        "its environment (/fake/python)",
        values=(value,),
    )
    assert verdict.status == "unsatisfied"
    # The carrier first: a cause extraction that fell back to its value-free
    # sentence would pass the leak assertion with the clause discarded.
    assert "depends on" in verdict.detail
    assert _CORE not in verdict.detail, (
        "uv's cause ends in the value, and the extracted cause printed it "
        "minus its last character"
    )


def test_a_value_inside_the_text_stays_hidden(monkeypatch):
    """The control: mid-text, no whole-text strip reaches the value."""
    value = _CORE + "\x0c"
    _answers(monkeypatch, 2, f"error: crashed near {value} and then stopped")
    verdict = pre_installed_tool._judge(
        "/fake/copy",
        "faketool",
        [],
        None,
        "faketool",
        "/fake/uv",
        "/fake/python",
        None,
        "its environment (/fake/python)",
        values=(value,),
    )
    assert "and then stopped" in verdict.detail
    assert _CORE not in verdict.detail
