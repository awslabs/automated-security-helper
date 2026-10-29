# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report`` writes the document, and nothing else, to stdout.

Two behaviors the CLI keeps whatever reaches stdout:

- ASH's log lines go to stderr. With ``--log-level INFO``, ``ash report --format
  sarif > x.sarif`` writes exactly the SARIF document to the file, and the same
  document to a pipe, with no log line ahead of it.
- Off an interactive terminal, and on one with ``--no-color``, the report is the
  reporter's text as written, not Markdown rendered by rich: rendering re-wraps
  long lines and turns the reporter's own text into formatting.

The command runs in this process with ``sys.stdout`` a regular file, a pipe, or a
stream that says it is a terminal, as each is when ``ash report`` runs from a shell.
"""

from __future__ import annotations

import io
import os
import sys
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.cli.main import app
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

#: Longer than any console, with rich markup and Markdown in it: rendering would
#: wrap the long line and read the markup, the emphasis and the heading as formatting.
MARKDOWN_TEXT = (
    "# A heading\n\n"
    "first line [red]not markup[/red] *not emphasis* " + "x" * 300 + " end\n"
    "second line with ünïcode and a [bold]tag[/bold]\n"
)


@pytest.fixture
def results_dir(tmp_path, monkeypatch) -> Path:
    output = tmp_path / "out"
    output.mkdir()
    model = AshAggregatedResults(ash_config=get_default_config())
    (output / "ash_aggregated_results.json").write_text(
        model.model_dump_json(by_alias=True), encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    return output


def _report(stdout, results_dir: Path, fmt: str, monkeypatch, *extra: str) -> None:
    with monkeypatch.context() as patched:
        patched.setattr(sys, "stdout", stdout)
        exit_code = app(
            [
                "report",
                "--format",
                fmt,
                "--output-dir",
                results_dir.as_posix(),
                *extra,
            ],
            standalone_mode=False,
        )
    assert exit_code in (None, 0)


def _to_a_file(tmp_path: Path, results_dir, fmt, monkeypatch, *extra) -> str:
    path = tmp_path / "stdout"
    with open(path, "w", encoding="utf-8") as stdout:
        _report(stdout, results_dir, fmt, monkeypatch, *extra)
    return path.read_bytes().decode("utf-8")


def _through_a_pipe(results_dir, fmt, monkeypatch, *extra) -> str:
    read_end, write_end = os.pipe()
    chunks: list = []
    with open(read_end, "rb") as reader:
        drain = threading.Thread(target=lambda: chunks.append(reader.read()))
        drain.start()
        with open(write_end, "w", encoding="utf-8") as stdout:
            _report(stdout, results_dir, fmt, monkeypatch, *extra)
        drain.join(timeout=60)
    return b"".join(chunks).decode("utf-8")


class _Terminal(io.StringIO):
    def isatty(self):
        return True


def _sarif_document(results_dir: Path) -> str:
    """What SarifReporter returns for the saved results: the document."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
        SarifReporter,
    )

    model = AshAggregatedResults.model_validate_json(
        (results_dir / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    return SarifReporter(
        context=PluginContext(source_dir=results_dir, output_dir=results_dir)
    ).report(model)


@pytest.mark.parametrize("route", ["file", "pipe"])
def test_stdout_is_the_sarif_document_with_the_log_at_info(
    results_dir, tmp_path, monkeypatch, route
):
    """``--log-level INFO`` logs while the report runs; none of it reaches stdout."""
    expected = _sarif_document(results_dir).replace("\n", os.linesep)

    if route == "file":
        out = _to_a_file(
            tmp_path, results_dir, "sarif", monkeypatch, "--log-level", "INFO"
        )
    else:
        out = _through_a_pipe(results_dir, "sarif", monkeypatch, "--log-level", "INFO")

    assert out == expected, out[:2000]


@pytest.mark.parametrize("route", ["file", "pipe"])
def test_the_info_log_is_written_to_stderr(
    results_dir, tmp_path, monkeypatch, capsys, route
):
    """The control for the cell above: at INFO the report does log, to stderr."""
    if route == "file":
        _to_a_file(tmp_path, results_dir, "sarif", monkeypatch, "--log-level", "INFO")
    else:
        _through_a_pipe(results_dir, "sarif", monkeypatch, "--log-level", "INFO")

    assert "Found reporter plugin" in capsys.readouterr().err


@pytest.mark.parametrize(
    "route, extra",
    [
        ("pipe", ()),
        ("pipe", ("--no-color",)),
        ("file", ("--no-color",)),
        ("terminal", ("--no-color",)),
    ],
    ids=["pipe", "pipe-no-color", "file-no-color", "terminal-no-color"],
)
def test_markdown_is_written_as_the_reporter_wrote_it(
    results_dir, tmp_path, monkeypatch, route, extra
):
    target = (
        "automated_security_helper.plugin_modules.ash_builtin.reporters."
        "MarkdownReporter.report"
    )
    with patch(target, return_value=MARKDOWN_TEXT):
        if route == "file":
            out = _to_a_file(tmp_path, results_dir, "markdown", monkeypatch, *extra)
        elif route == "pipe":
            out = _through_a_pipe(results_dir, "markdown", monkeypatch, *extra)
        else:
            terminal = _Terminal()
            _report(terminal, results_dir, "markdown", monkeypatch, *extra)
            out = terminal.getvalue()

    expected = (
        MARKDOWN_TEXT.replace("\n", os.linesep) if route == "file" else MARKDOWN_TEXT
    )
    assert out == expected, out[:2000]
