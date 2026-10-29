# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value a tool printed with an escape code inside it stays hidden.

Redaction matches a value's printed spellings, and a complete CSI or OSC
sequence inside the value splits the contiguous match: a terminal, a viewer
or a log sink that drops or obeys the code then shows the value whole around
it. The report-line layers strip every such code before matching
(error_text.ESCAPE_CODES), so the match sees the value as a reader would.

The record cells run a real child (the venv's own interpreter) through
``PluginBase._run_subprocess`` and read the recorded lines the way a report
does; the cdk-nag cells run the real worker protocol with only the child's
bootstrap replaced.
"""

from __future__ import annotations

import sys

import pytest

from automated_security_helper.core.phases.scanner_executor import _tool_lines
from automated_security_helper.utils import cdk_nag_worker
from automated_security_helper.utils.error_text import (
    carry_environment_values,
    config_environment_values,
    error_text,
    text_without_values,
)
from tests.unit.base.test_failure_lines_carry_no_environment_value import _context
from tests.unit.base.test_scanner_plugin_coverage import _scanner

HEAD = "ASH_CANARY_Zq7Kx9LmHead"
TAIL = "ASH_CANARY_Pw4Nv2RtTail"

#: One complete escape sequence of each kind the strip has to take: a color
#: (SGR), a non-color CSI (erase to end of line), and an OSC hyperlink.
CODES = [
    pytest.param("\x1b[1m", id="sgr"),
    pytest.param("\x1b[K", id="csi-erase"),
    pytest.param("\x1b]8;;https://h.example\x1b\\", id="osc-link"),
]


def _child(text, stream="stdout"):
    """argv of a child that writes *text* (as UTF-8 bytes) to *stream*."""
    data = text.encode("utf-8").hex()
    code = (
        "import sys; "
        f"sys.{stream}.buffer.write(bytes.fromhex('{data}')); "
        f"sys.{stream}.buffer.flush()"
    )
    return [sys.executable, "-c", code]


def _recorded(scanner, context, lines):
    return [
        str(line)
        for line in [
            *lines,
            *_tool_lines(lines, config_environment_values(context.config)),
        ]
    ]


@pytest.mark.parametrize("code", CODES)
@pytest.mark.unit
def test_text_without_values_hides_a_value_split_by_a_code(code):
    value = f"{HEAD}{TAIL}"
    shown = text_without_values(f"tool saw {HEAD}{code}{TAIL} here", [value])
    assert "tool saw" in shown, repr(shown)
    assert HEAD not in shown and TAIL not in shown, repr(shown)


@pytest.mark.unit
def test_text_without_values_without_values_changes_nothing():
    """With nothing to redact there is nothing a code could split, so the
    text passes through as it is, codes included."""
    text = "tool saw \x1b[1mbold\x1b[0m here"
    assert text_without_values(text, []) == text


@pytest.mark.parametrize("code", CODES)
@pytest.mark.unit
def test_an_errors_text_hides_a_value_split_by_a_code(code):
    value = f"{HEAD}{TAIL}"
    error = RuntimeError(f"tool saw {HEAD}{code}{TAIL} here")
    carry_environment_values(error, [value])
    shown = error_text(error)
    assert "tool saw" in shown, repr(shown)
    assert HEAD not in shown and TAIL not in shown, repr(shown)


@pytest.mark.parametrize("code", CODES)
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
@pytest.mark.integration
def test_the_record_of_a_real_child_hides_a_value_split_by_a_code(
    tmp_path, stream, code
):
    value = f"{HEAD}{TAIL}"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    scanner.use_uv_tool = False
    scanner._run_subprocess(
        command=_child(f"tool saw {HEAD}{code}{TAIL} here\n", stream),
        results_dir=tmp_path / "results",
        stdout_preference="return",
        stderr_preference="return",
    )
    lines = scanner.output if stream == "stdout" else scanner.errors
    joined = " | ".join(_recorded(scanner, context, lines))
    assert "tool saw" in joined, repr(joined)
    assert not (HEAD in joined and TAIL in joined), repr(joined)


@pytest.mark.parametrize("code", CODES)
@pytest.mark.unit
def test_a_value_that_itself_holds_a_code_is_hidden_in_its_stripped_spelling(code):
    """The shown layers strip every complete escape sequence from a tool's
    text before matching, so a value that itself holds such a code appears
    there in its stripped spelling; the value's printed forms carry it, or
    the strip re-splits the match it exists to protect."""
    value = f"{HEAD}{code}{TAIL}"
    shown = text_without_values(f"tool saw {value} here", [value])
    assert "tool saw" in shown, repr(shown)
    assert HEAD not in shown and TAIL not in shown, repr(shown)


@pytest.mark.parametrize("code", CODES)
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
@pytest.mark.integration
def test_the_record_hides_a_value_that_itself_holds_a_code(tmp_path, stream, code):
    value = f"{HEAD}{code}{TAIL}"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    scanner.use_uv_tool = False
    scanner._run_subprocess(
        command=_child(f"tool saw {value} here\n", stream),
        results_dir=tmp_path / "results",
        stdout_preference="return",
        stderr_preference="return",
    )
    lines = scanner.output if stream == "stdout" else scanner.errors
    joined = " | ".join(_recorded(scanner, context, lines))
    assert "tool saw" in joined, repr(joined)
    assert not (HEAD in joined and TAIL in joined), repr(joined)


def _bootstrap_writing(text):
    data = text.encode("utf-8").hex()
    return (
        "import sys; "
        f"sys.stderr.buffer.write(bytes.fromhex('{data}')); "
        "sys.stderr.buffer.flush(); sys.exit(2)"
    )


@pytest.mark.parametrize("code", CODES)
@pytest.mark.integration
def test_the_cdk_nag_workers_reason_hides_a_value_split_by_a_code(
    tmp_path, monkeypatch, code
):
    """The worker's reason is built from a real child's stderr; its strip
    takes every escape the package strips, not only colors."""
    value = f"{HEAD}{TAIL}"
    monkeypatch.setattr(
        cdk_nag_worker,
        "_CHILD_BOOTSTRAP",
        _bootstrap_writing(f"node crashed reading {HEAD}{code}{TAIL} here\n"),
    )
    answers, reason, timed_out, _response = cdk_nag_worker._run_child(
        ["t.yaml"], {}, tmp_path / "work", tmp_path, 60, (value,)
    )
    assert answers == [] and timed_out is False, (answers, reason)
    assert "exited 2" in reason and "node crashed" in reason, reason
    assert HEAD not in reason and TAIL not in reason, repr(reason)
