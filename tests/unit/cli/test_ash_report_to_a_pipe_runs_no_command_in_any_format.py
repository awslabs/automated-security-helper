# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report`` to a pipe writes no line a CI runner reads as a command.

Why this exists
---------------
A CI step's stdout is a pipe, and a runner reads a line of it that starts, after
its indentation, with ``::`` as a workflow command (``::add-mask::``,
``::warning::``). A scanned file's name is the tree's to choose: one holding a
line feed and ``::add-mask::x`` is written by each text reporter on a line of its
own. The JSON and YAML reporters write the line feed as an escape
(utils/report_yaml.py for YAML), so theirs hold no command line to break. Every
format written to a stdout that is not a regular file goes through the command
breaker; one written to a regular file (``ash report --format F > report``) is the
bytes the report phase writes to reports/.

A "##" with a name and "[" after it is a command anywhere in a line (Azure
Pipelines' "##vso[", the runner's legacy "##[cmd]"), so a name holding one is
broken on a pipe too, and a JSON report broken that way is still the same
document. Under an entry point that already writes stdout through the command
check, each command is broken once, not twice.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
from pathlib import Path

import pytest
import rich
from rich.console import Console

from automated_security_helper.cli.main import app
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Result,
)

#: A scanned file's name with a line feed and a workflow command after it.
NAME = "notes\n::add-mask::x.txt"
#: The same, the command indented.
INDENTED = "notes\n    ::add-mask::y.txt"
#: A name holding a command that is one anywhere in a line.
HASH_NAME = "a##vso[task.setvariable variable=x]y.txt"
#: Names holding the "##name[" commands a runner reads anywhere in a line: Azure
#: Pipelines' ``##[`` and ``##vso[``, and TeamCity's ``##teamcity[``.
HASH_NAMES = (
    "a ##[warning]b.txt",
    "a ##vso[task.setvariable variable=x]y.txt",
    "a ##teamcity[message text='x']z.txt",
)
#: A "##" with a name and "[" after it, anywhere in a line.
HASH_COMMAND = re.compile(r"##[A-Za-z]*\[")

FORMATS = ["yaml", "flat-json", "sarif", "markdown", "html", "text", "csv"]
JSON_FORMATS = ("flat-json", "sarif")
#: The formats that write a value's line feed as an escape, so a name's command
#: never starts a line of theirs.
LINE_FEED_ESCAPED = (*JSON_FORMATS, "yaml")
#: The human reports, which show a scanned name rather than write it: on one
#: line, with each CI command form broken (shown_on_one_line and
#: shown_not_obeyed), so their own text already holds no line-start command and
#: no "##name[" form for the stream to break.
SHOWN = ("markdown", "html", "text")


def _finding(path: str) -> Result:
    return Result(
        ruleId="SECRET-PROBE",
        message=Message(root=Message1(text=f"Secret detected in file '{path}'")),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri=path),
                        region=Region(startLine=1, endLine=1),
                    )
                )
            )
        ],
        properties=PropertyBag.model_validate(
            {"scanner_name": "detect-secrets", "issue_severity": "CRITICAL"}
        ),
    )


def _saved_results(tmp_path: Path, monkeypatch, *paths: str) -> Path:
    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif.runs[0].results = [_finding(path) for path in paths]
    output = tmp_path / "ash_output"
    populate_metrics_from_unified_source(model).save_model(output)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        rich,
        "_console",
        Console(
            width=80,
            color_system=None,
            force_terminal=False,
            legacy_windows=False,
            _environ={},
        ),
    )
    return output


@pytest.fixture
def results_dir(tmp_path, monkeypatch) -> Path:
    return _saved_results(tmp_path, monkeypatch, NAME, INDENTED)


@pytest.fixture
def results_dir_with_hash_names(tmp_path, monkeypatch) -> Path:
    """The names in ``results_dir``, and one holding each "##name[" command."""
    return _saved_results(tmp_path, monkeypatch, NAME, INDENTED, *HASH_NAMES)


def _commands_in(text: str) -> list:
    return [
        line for line in re.split(r"\r\n|\r|\n", text) if line.lstrip().startswith("::")
    ]


def _hash_commands_in(text: str) -> list:
    return [line for line in re.split(r"\r\n|\r|\n", text) if HASH_COMMAND.search(line)]


def _report(stdout, results_dir: Path, report_format: str, monkeypatch) -> None:
    with monkeypatch.context() as patched:
        patched.setattr(sys, "stdout", stdout)
        exit_code = app(
            [
                "report",
                "--format",
                report_format,
                "--output-dir",
                results_dir.as_posix(),
                "--log-level",
                "ERROR",
            ],
            standalone_mode=False,
        )
    assert exit_code in (None, 0)


def _through_a_pipe(
    results_dir: Path, report_format: str, monkeypatch, *, wrap=lambda stream: stream
) -> str:
    read_end, write_end = os.pipe()
    chunks: list = []
    with open(read_end, "rb") as reader:
        drain = threading.Thread(target=lambda: chunks.append(reader.read()))
        drain.start()
        with open(write_end, "w", encoding="utf-8") as stdout:
            _report(wrap(stdout), results_dir, report_format, monkeypatch)
        drain.join(timeout=60)
    return b"".join(chunks).decode("utf-8")


@pytest.mark.parametrize("report_format", FORMATS)
def test_a_report_to_a_pipe_runs_no_command(
    results_dir_with_hash_names, monkeypatch, report_format
) -> None:
    out = _through_a_pipe(results_dir_with_hash_names, report_format, monkeypatch)

    # The control: the report holds the names, so it had the lines to write.
    assert "add-mask" in out, out[:2000]
    assert "teamcity" in out and "vso" in out, out[:2000]
    assert _commands_in(out) == [], _commands_in(out)
    assert _hash_commands_in(out) == [], _hash_commands_in(out)


@pytest.mark.parametrize("report_format", FORMATS)
def test_a_report_to_a_regular_file_is_the_report_phases_bytes(
    results_dir_with_hash_names, tmp_path, monkeypatch, report_format
) -> None:
    from automated_security_helper.cli import report as report_module
    from automated_security_helper.utils.atomic_write import write_text_atomically

    written: list = []
    original = report_module._write_report

    def recording(content: str, fmt: str, **kwargs) -> None:
        written.append(content)
        original(content, fmt, **kwargs)

    monkeypatch.setattr(report_module, "_write_report", recording)
    path = tmp_path / "stdout"
    with open(path, "w", encoding="utf-8") as stdout:
        _report(stdout, results_dir_with_hash_names, report_format, monkeypatch)

    expected = tmp_path / "written-report"
    write_text_atomically(expected, written[0])
    assert path.read_bytes() == expected.read_bytes()
    raw = path.read_text(encoding="utf-8")
    assert "::add-mask::" in raw
    if report_format in SHOWN:
        # A human report shows each name: no command on a line of its own, and
        # every "##name[" form broken, as the reporter wrote it.
        assert not _commands_in(raw), _commands_in(raw)
        assert not _hash_commands_in(raw), _hash_commands_in(raw)
        return
    # Every other format, the JSON ones included, writes the "##name[" forms as
    # the names hold them.
    assert _hash_commands_in(raw), raw[:2000]
    # The control for the pipe cells: as the reporter writes it, every such format
    # but the JSON and YAML ones, which escape the line feed, has the command on a
    # line of its own.
    if report_format not in LINE_FEED_ESCAPED:
        assert _commands_in(raw), raw[:2000]
    else:
        assert not _commands_in(raw), _commands_in(raw)


#: The escapes a broken command holds: a line start's first colon, and a
#: "##name[" form's first "#".
BREAKS = ("\\x3a", "\\x23")


@pytest.mark.parametrize("report_format", FORMATS)
def test_a_report_to_a_pipe_under_a_command_safe_stdout_is_broken_once(
    results_dir_with_hash_names, monkeypatch, report_format
) -> None:
    """An entry point that writes stdout through the command check already: each
    command is broken by one escape, as on a plain pipe, and no escape is broken
    again."""
    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    plain = _through_a_pipe(results_dir_with_hash_names, report_format, monkeypatch)
    wrapped = _through_a_pipe(
        results_dir_with_hash_names,
        report_format,
        monkeypatch,
        wrap=lambda stream: CommandSafeStream(lambda: stream),
    )

    assert _commands_in(wrapped) == [], _commands_in(wrapped)
    assert _hash_commands_in(wrapped) == [], _hash_commands_in(wrapped)
    if report_format not in JSON_FORMATS:
        # The control: the plain pipe holds broken escapes, so there was
        # something to break twice. The "##name[" names put one in every
        # format but the JSON ones, which break with JSON's own escape: by the
        # stream for a line-start command or a "##name[" form, or by a human
        # report that showed the name and broke its "##name[" form itself.
        assert sum(plain.count(form) for form in BREAKS) > 0, plain[:2000]
    for form in BREAKS:
        assert wrapped.count(form) == plain.count(form), (form, wrapped[:2000])
        # No escape is broken again: none is doubled, on either pipe. The
        # Markdown report is the exception, compared with the plain pipe
        # instead: it writes a shown escape's backslash as Markdown's own "\\",
        # which a second break would add to.
        doubled = "\\" + form
        if report_format == "markdown":
            assert wrapped.count(doubled) == plain.count(doubled), (
                doubled,
                wrapped[:2000],
            )
        else:
            assert plain.count(doubled) == 0, (doubled, plain[:2000])
            assert wrapped.count(doubled) == 0, (doubled, wrapped[:2000])


@pytest.mark.parametrize("report_format", FORMATS)
def test_a_named_hash_command_is_broken_on_a_pipe(
    tmp_path, monkeypatch, report_format
) -> None:
    results = _saved_results(tmp_path, monkeypatch, HASH_NAME)

    out = _through_a_pipe(results, report_format, monkeypatch)

    # The control: the name is in the report.
    assert "task.setvariable" in out, out[:2000]
    assert "##vso[" not in out, out[:2000]
    if report_format in JSON_FORMATS:
        # Broken with JSON's own escape, so the document still parses, and to the
        # name the scan found.
        assert HASH_NAME in json.dumps(json.loads(out)), out[:2000]
