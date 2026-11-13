# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tool's report lines hold no escape codes, whether or not values are hidden.

``text_without_values`` strips escape codes only when there are values to
hide, since a code inside a value splits the match. The plugin's stdout record
path went through it alone, so the same tool output kept its colors in the
reports of a run whose config read no environment values and lost them in a
run whose config did. The record path strips the codes itself when there are
no values, and hands the text as written to the redaction when there are. The response's own text, which the stream log is written
from, is left as the tool printed it.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
)

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

_VALUE = "tool-qz4b9secret"
_STDOUT = "\x1b[31mred line\x1b[0m\nplain line\n\x1b]8;;https://x.test\x1b\\link\x1b]8;;\x1b\\\n"
_STDERR = "\x1b[33myellow\x1b[0m\n"


@pytest.fixture
def make_scanner(tmp_path):
    def build():
        source = tmp_path / "src"
        source.mkdir(exist_ok=True)
        output = tmp_path / "out"
        output.mkdir(exist_ok=True)
        context = PluginContext(
            source_dir=source, output_dir=output, config=AshConfig()
        )
        scanner = CheckovScanner(context=context, config=CheckovScannerConfig())
        scanner.use_uv_tool = False
        return scanner

    return build


def _record(make_scanner, values, stdout=_STDOUT, stderr=_STDERR):
    scanner = make_scanner()
    response = {"stdout": stdout, "stderr": stderr, "returncode": 0}
    with patch.object(CheckovScanner, "_values_to_redact", lambda _self: values):
        scanner._process_command_response(response)
    return scanner, response


def test_stdout_report_lines_are_the_same_with_and_without_values(make_scanner):
    without, _ = _record(make_scanner, ())
    with_values, _ = _record(make_scanner, (_VALUE,))

    assert list(without.output) == list(with_values.output)
    assert not any("\x1b" in line for line in without.output), without.output


def test_stderr_report_lines_are_the_same_with_and_without_values(make_scanner):
    """The control: the stderr path already strips unconditionally."""
    without, _ = _record(make_scanner, ())
    with_values, _ = _record(make_scanner, (_VALUE,))

    assert list(without.errors) == list(with_values.errors)
    assert without.errors, "no stderr line was recorded, so the cell shows nothing"
    assert not any("\x1b" in line for line in without.errors), without.errors


def test_a_value_inside_a_code_is_still_hidden(make_scanner):
    """The control: stripping first does not weaken the redaction. A value
    split by a code is joined, then hidden."""
    split = f"seen {_VALUE[:6]}\x1b[K{_VALUE[6:]} here"
    scanner, _ = _record(make_scanner, (_VALUE,), stdout=split)

    assert scanner.output, "no line was recorded, so the cell shows nothing"
    assert _VALUE not in "\n".join(scanner.output), scanner.output
    assert not any("\x1b" in line for line in scanner.output), scanner.output


def test_a_short_value_holding_a_code_is_hidden_where_it_is_glued_to_a_word(
    make_scanner,
):
    """The value carries a complete code, so its as-written spelling is long
    enough to be matched anywhere while its stripped spelling (7 word
    characters) is matched as a word only. Stripping the codes out of the
    line first would leave the glued occurrence to the word band, which
    misses it. The recorded line also holds no code."""
    value = "qz4\x1b[31mb9se"
    line = f"token x{value} end"
    scanner, _ = _record(make_scanner, (value,), stdout=f"{line}\n")

    assert scanner.output, "no line was recorded, so the cell shows nothing"
    joined = "\n".join(scanner.output)
    assert "qz4b9se" not in joined, scanner.output
    assert value not in joined, scanner.output
    assert not any("\x1b" in text for text in scanner.output), scanner.output


@pytest.mark.parametrize("values", [(), (_VALUE,)], ids=["no-values", "values"])
def test_a_line_without_codes_is_recorded_as_the_tool_printed_it(make_scanner, values):
    """The control: a line holding no escape code comes out unchanged."""
    scanner, _ = _record(
        make_scanner, values, stdout="plain line\nsecond line: a[0m b\n"
    )

    assert list(scanner.output) == ["plain line", "second line: a[0m b"]


@pytest.mark.parametrize("values", [(), (_VALUE,)], ids=["no-values", "values"])
def test_the_response_text_keeps_the_codes_the_tool_printed(make_scanner, values):
    """The control: the stream log is written from the response's text, which
    recording the report lines does not change."""
    _, response = _record(make_scanner, values)

    assert response["stdout"] == _STDOUT
    assert response["stderr"] == _STDERR
