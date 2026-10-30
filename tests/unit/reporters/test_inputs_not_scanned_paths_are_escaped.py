# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A path in "Inputs not scanned" is shown as written, and cannot change the summary.

The path is the repository-relative path of a lockfile, so the scanned repository names
it. ``ash.summary.md`` wrote it inside single backticks without escaping, so a directory
name holding a backtick ended the code span, and one holding a newline started a line of
its own, a heading for instance. The text summary and the console printed control
characters as they were, a terminal escape sequence included.

Each renderer now shows the path with its control characters escaped, and the markdown
summary fences it with more backticks than it holds.
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from automated_security_helper.core.metrics_table import print_inputs_not_scanned
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

HOSTILE = "web`x\n## injected heading\x1b[31m/package-lock.json"


def _model() -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.additional_reports = {
        "npm-audit": {
            "source": {
                "scanner_name": "npm-audit",
                "target_type": "source",
                "status": "MISSING",
                "inputs_not_scanned": [{"path": HOSTILE, "reason": "not audited"}],
            }
        }
    }
    return model


def _lines_with(text: str, needle: str) -> list:
    return [line for line in text.splitlines() if needle in line]


def test_the_markdown_summary_keeps_the_path_on_its_line_in_a_code_span(
    test_plugin_context,
):
    from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
        MarkdownReporter,
    )

    out = MarkdownReporter(context=test_plugin_context).report(_model())

    assert not [line for line in out.splitlines() if line.startswith("## injected")]
    assert "\x1b" not in out
    (item,) = _lines_with(out, "package-lock.json")
    assert "``web`x\\n## injected heading\\x1b[31m/package-lock.json``" in item, item


def test_the_text_summary_keeps_the_path_on_its_line(test_plugin_context):
    from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
        TextReporter,
    )

    out = TextReporter(context=test_plugin_context).report(_model())

    assert not [line for line in out.splitlines() if line.startswith("## injected")]
    assert "\x1b" not in out
    (item,) = _lines_with(out, "package-lock.json")
    assert "web`x\\n## injected heading\\x1b[31m/package-lock.json" in item, item


def test_the_console_line_escapes_control_characters():
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, width=400)

    print_inputs_not_scanned(_model(), console)

    out = buffer.getvalue()
    assert "\x1b" not in out
    assert len(_lines_with(out, "Not scanned:")) == 1
    # The console writes the newline as terminal_text does (``\x0a``); the
    # markdown and text summaries above keep display_text's named ``\n``.
    assert "\\x0a## injected heading" in out, out


def test_control_an_ordinary_path_is_unchanged(test_plugin_context):
    from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
        MarkdownReporter,
    )

    model = _model()
    model.additional_reports["npm-audit"]["source"]["inputs_not_scanned"] = [
        {"path": "web/package-lock.json", "reason": "not audited"}
    ]

    out = MarkdownReporter(context=test_plugin_context).report(model)

    assert "`web/package-lock.json`" in out
