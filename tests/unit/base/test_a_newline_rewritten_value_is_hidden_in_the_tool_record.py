# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tool's record hides a value whose newlines the child's pipe respelled.

Every cell runs a real child (the venv's own interpreter) through
``PluginBase._run_subprocess``, then reads the plugin's recorded lines and
the results layer (``scanner_executor._tool_lines``) the way a report does.
The planted values are canaries holding a line separator.

Why the separator matters: the finished-run path reads the child in text
mode, and universal newlines rewrite the value's "\\r\\n" and "\\r" to
"\\n" before redaction ever sees the text. The value's printable spellings
(config_validator._printed_forms) have to cover that rewritten spelling,
or the record keeps the value readable with only its separator changed.
The other separators pass the pipe unchanged and match the value as is.
"""

from __future__ import annotations

import sys

import pytest

from automated_security_helper.core.phases.scanner_executor import _tool_lines
from automated_security_helper.utils.error_text import config_environment_values
from automated_security_helper.utils.subprocess_utils import (
    run_command_with_output_handling,
)
from tests.unit.base.test_failure_lines_carry_no_environment_value import _context
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.integration

HEAD = "ASH_CANARY_Zq7Kx9LmHead"
TAIL = "ASH_CANARY_Pw4Nv2RtTail"


def _child(text, stream="stdout", sleep=0):
    """argv of a child that writes *text* (as UTF-8 bytes) to *stream*."""
    data = text.encode("utf-8").hex()
    code = (
        "import sys, time; "
        f"sys.{stream}.buffer.write(bytes.fromhex('{data}')); "
        f"sys.{stream}.buffer.flush(); time.sleep({sleep})"
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


SEPARATORS = [
    pytest.param("\n", id="lf"),
    pytest.param("\r\n", id="crlf"),
    pytest.param("\r", id="lone-cr"),
    pytest.param("\x85", id="nel"),
    pytest.param(chr(0x2028), id="line-sep"),
    pytest.param("\x0c", id="ff"),
    pytest.param("\x0b", id="vt"),
    pytest.param("\x1e", id="rs"),
]


@pytest.mark.parametrize("sep", ["\r\n", "\r"], ids=["crlf", "lone-cr"])
def test_the_premise_a_text_mode_child_rewrites_the_values_separator(sep):
    """The branch the record cells guard: a finished text-mode run hands ASH
    the value with LF where the value itself holds CR or CRLF."""
    value = f"{HEAD}{sep}{TAIL}"
    response = run_command_with_output_handling(
        command=_child(f"tool saw {value} end\n"),
        stdout_preference="return",
        stderr_preference="return",
        encoding="utf-8",
        errors="replace",
    )
    out = response.get("stdout") or ""
    assert value not in out, repr(out)
    assert f"{HEAD}\n{TAIL}" in out, repr(out)


@pytest.mark.parametrize("sep", SEPARATORS)
def test_the_stdout_record_of_a_real_child_hides_the_value(tmp_path, sep):
    value = f"{HEAD}{sep}{TAIL}"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    scanner.use_uv_tool = False
    response = scanner._run_subprocess(
        command=_child(f"tool saw {value} in its config\nand went on\n"),
        results_dir=tmp_path / "results",
        stdout_preference="return",
        stderr_preference="return",
    )
    assert response.get("returncode") == 0, response
    joined = " | ".join(_recorded(scanner, context, scanner.output))
    assert "tool saw" in joined and "and went on" in joined, repr(joined)
    assert HEAD not in joined, repr(joined)
    assert TAIL not in joined, repr(joined)


@pytest.mark.parametrize("sep", SEPARATORS)
def test_the_stderr_record_of_a_real_child_hides_the_value(tmp_path, sep):
    value = f"{HEAD}{sep}{TAIL}"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    scanner.use_uv_tool = False
    response = scanner._run_subprocess(
        command=_child(f"tool saw {value} in its config\nand went on\n", "stderr"),
        results_dir=tmp_path / "results",
        stdout_preference="return",
        stderr_preference="return",
    )
    assert response.get("returncode") == 0, response
    joined = " | ".join(_recorded(scanner, context, scanner.errors))
    assert "tool saw" in joined and "and went on" in joined, repr(joined)
    assert HEAD not in joined, repr(joined)
    assert TAIL not in joined, repr(joined)


def test_a_timed_out_runs_partial_stdout_hides_a_crlf_value(tmp_path):
    """The partial output of a timed-out run is decoded from the exception's
    bytes with no newline translation, so a CRLF value keeps its own spelling
    there and has to stay hidden in that spelling too."""
    value = f"{HEAD}\r\n{TAIL}"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    scanner.use_uv_tool = False
    response = scanner._run_subprocess(
        command=_child(f"tool saw {value} then hung\n", sleep=30),
        results_dir=tmp_path / "results",
        stdout_preference="return",
        stderr_preference="return",
        timeout=2,
    )
    assert response.get("timed_out") is True, response
    assert value in (response.get("stdout") or ""), repr(response.get("stdout"))
    joined = " | ".join(_recorded(scanner, context, scanner.output))
    assert "tool saw" in joined, repr(joined)
    assert HEAD not in joined and TAIL not in joined, repr(joined)
