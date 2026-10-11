# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Member and archive names the scanned tree chose are shown as inert text.

The refusal summaries print names straight from the archive. In ``ash.summary.md``,
which is often posted to a pull request, a name such as ``@someone`` or
``https://example.invalid/x`` became a mention or a link even with markdown
punctuation escaped. In the text summary and on the console, a name holding an
escape sequence or another control character was written to the reader's terminal
as is. Each name is now inside a code span in markdown, and every control or
bidirectional-formatting character is written as an escape everywhere else.
"""

from __future__ import annotations

import re
from pathlib import Path

from rich.console import Console

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.metrics_table import print_converter_refusals
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
    RefusedInputInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)

ESCAPE = "\x1b[31mred\x1b[0m.zip"
REVERSED = "invoice\u202egpj.zip"
MENTION = "@someone/pkg.zip"
LINK = "https://example.invalid/pkg.zip"
TICKS = "a``b.zip"


def model() -> AshAggregatedResults:
    results = AshAggregatedResults(ash_config=get_default_config())
    results.converter_results["archive"] = ConverterStatusInfo(
        converted_paths=[],
        refused_inputs=[
            RefusedInputInfo(path="outer.zip", member=name, reason="nested")
            for name in (ESCAPE, REVERSED, MENTION, LINK, TICKS)
        ],
    )
    return results


def context() -> PluginContext:
    return PluginContext(
        source_dir=Path("."), output_dir=Path("."), config=get_default_config()
    )


def refusal_lines(report: str):
    return [line for line in report.splitlines() if "was not scanned" in line]


def test_the_markdown_summary_puts_each_refusal_in_a_code_span():
    lines = refusal_lines(MarkdownReporter(context=context()).report(model()))

    assert len(lines) == 5, lines
    for line in lines:
        match = re.fullmatch(r"- (?:\*\*scan incomplete\*\*: )?(`+) (.*) \1", line)
        assert match, line
        assert "`" * len(match.group(1)) not in match.group(2), line
    joined = "\n".join(lines)
    assert MENTION in joined and LINK in joined
    assert "\x1b" not in joined and "\u202e" not in joined


def test_the_text_summary_escapes_control_and_bidirectional_characters():
    report = TextReporter(context=context()).report(model())

    lines = refusal_lines(report)
    assert "\x1b" not in report and "\u202e" not in report
    assert any("\\x1b[31mred\\x1b[0m.zip" in line for line in lines), lines
    assert any("invoice\\u202egpj.zip" in line for line in lines), lines


def test_the_console_escapes_control_and_bidirectional_characters():
    console = Console(record=True, width=400, color_system=None)

    print_converter_refusals(model(), console)

    text = console.export_text()
    assert "\x1b" not in text and "\u202e" not in text
    assert "\\x1b[31mred\\x1b[0m.zip" in text
    assert "invoice\\u202egpj.zip" in text
