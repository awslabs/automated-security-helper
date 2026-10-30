# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash report` writes where the scan wrote, names the file it refuses, and keeps going.

The reporters' companion files and the link checks follow the results that
were found, not --output-dir as given; a deleted working directory and a
path the user cannot search are refusals, not tracebacks; the config file is
read once; the OSError and parse refusals name a file, never "None"; the
ASH_CONFIG file is held with the --config file; a reporter is found by the
name it declares and one that cannot be built is a failed run, not a
mistyped --format; a closed stdout pipe is not a render error; the writer
keeps a CRLF line end, writes a JSON-format reporter's non-JSON text as
text, and knows unused-suppressions as a JSON format.
"""

from __future__ import annotations

import io
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import report as report_module
from automated_security_helper.cli.main import app
from automated_security_helper.cli.report import (
    JSON_STDOUT_FORMATS,
    _exists,
    _is_json_document,
    _named_config_files,
    _refused_config_name,
    _write_report,
    _write_report_data,
)
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit


class _Terminal(io.StringIO):
    def isatty(self):
        return True


def _write_results(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    results = directory / "ash_aggregated_results.json"
    results.write_text(
        AshAggregatedResults().model_dump_json(by_alias=True), encoding="utf-8"
    )
    return results


def _report(*args):
    return CliRunner().invoke(app, ["report", "--log-level", "ERROR", *args])


@pytest.fixture(autouse=True)
def _own_environment(monkeypatch, tmp_path):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_OUTPUT_DIR", raising=False)
    monkeypatch.chdir(tmp_path)


# --- the writer ---


def test_a_crlf_line_end_stays_one_line_end(monkeypatch):
    """Replacing the line feed alone made CR CR LF of a CSV row's CRLF on Windows."""
    monkeypatch.setattr(report_module.os, "linesep", "\r\n")
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")

    _write_report_data("a,b\r\nc,d\n", stream)

    assert stream.buffer.getvalue() == b"a,b\r\nc,d\r\n"


def test_a_crlf_line_end_is_kept_where_the_line_separator_is_a_line_feed(monkeypatch):
    """Folding CRLF to LF before writing os.linesep rewrote a CSV row's CRLF as LF
    on Linux and macOS; only a line feed with no carriage return before it is the
    writer's to replace, and a quoted field's CRLF is content."""
    monkeypatch.setattr(report_module.os, "linesep", "\n")
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")

    _write_report_data('a,b\r\n"x\r\ny",d\nlast', stream)

    assert stream.buffer.getvalue() == b'a,b\r\n"x\r\ny",d\nlast'


def test_non_json_text_from_a_json_format_reporter_is_written_on_a_terminal():
    """json.loads ran only on a terminal, so the same reporter output passed
    to a pipe and failed a terminal with 'Expecting value'."""
    stream = _Terminal()

    _write_report("not a document\n", "sarif", pretty=True, stream=stream)

    assert "not a document" in stream.getvalue()


def test_unused_suppressions_is_a_json_format_whose_markdown_is_written_as_text():
    assert "unused-suppressions" in JSON_STDOUT_FORMATS
    stream = io.StringIO()

    _write_report(
        "# Unused\n\n##name[x]\n", "unused-suppressions", pretty=False, stream=stream
    )

    written = stream.getvalue()
    assert "\\u0023" not in written, written  # not JSON's escape
    assert "Unused" in written


def test_a_json_document_under_the_format_keeps_jsons_escape():
    stream = io.StringIO()

    _write_report(
        '{"a": "##name[x]"}\n', "unused-suppressions", pretty=False, stream=stream
    )

    assert "\\u0023" in stream.getvalue()


@pytest.mark.parametrize(
    "content, expected",
    [("{}", True), ("  [1]\n", True), ("# md", False), ("", False), ("text", False)],
)
def test_a_json_document_is_known_by_its_first_character(content, expected):
    assert _is_json_document(content) is expected


# --- paths and names ---


@pytest.mark.skipif(os.name == "nt", reason="directory modes are POSIX")
@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root searches any directory"
)
def test_a_path_the_user_cannot_search_reads_as_present(tmp_path):
    """Read as absent, the open that would have named the real cause never ran:
    a --config there was "not found" and a results file there was skipped."""
    locked = tmp_path / "locked"
    locked.mkdir()
    probe = locked / "ash.yaml"
    locked.chmod(0o000)
    try:
        assert _exists(probe) is True
    finally:
        locked.chmod(0o700)


@pytest.mark.skipif(os.name == "nt", reason="directory modes are POSIX")
@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root searches any directory"
)
def test_a_locked_path_is_present_whatever_path_exists_answers(tmp_path, monkeypatch):
    """From Python 3.14 on, ``Path.exists`` answers False for a path the user
    cannot reach instead of raising, so a check built on it read the path as
    absent there and kept the two wrong answers; the check reads the path with
    ``os.stat``. ``Path.exists`` is pinned to the 3.14 answer so the test holds on
    every version."""
    locked = tmp_path / "locked"
    locked.mkdir()
    probe = locked / "ash.yaml"
    monkeypatch.setattr(Path, "exists", lambda self, **kwargs: False)
    locked.chmod(0o000)
    try:
        assert _exists(probe) is True
    finally:
        locked.chmod(0o700)


def test_a_path_with_a_null_byte_reads_as_absent():
    """``Path.exists`` answered False for a name with a null byte; ``os.stat``
    raises ValueError for it, which the check reading the path with ``os.stat``
    let escape. A ``--cli-json-input`` document can name such a path."""
    assert _exists(Path("a\0b")) is False


@pytest.mark.skipif(os.name == "nt", reason="directory modes are POSIX")
@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root searches any directory"
)
def test_a_config_the_user_cannot_reach_is_refused_with_the_real_cause(tmp_path):
    """It was refused as "Configuration file not found"; the file is there."""
    results = _write_results(tmp_path / "out")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "ash.yaml").write_text("project_name: fixture\n", encoding="utf-8")
    locked.chmod(0o000)
    try:
        result = _report(
            "--format",
            "text",
            "--config",
            str(locked / "ash.yaml"),
            "--output-dir",
            str(results.parent),
        )
    finally:
        locked.chmod(0o700)

    assert result.exit_code == 3, result.output
    # The loader stats the named file before it opens it and refuses an
    # unreadable one by the errno's code ("Config file cannot be read (EACCES)");
    # "could not read" is the open-failure text, which this path never reaches.
    assert "cannot be read" in result.output, result.output
    assert "not found" not in result.output, result.output


@pytest.mark.skipif(os.name == "nt", reason="directory modes are POSIX")
@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root searches any directory"
)
def test_a_results_file_the_user_cannot_reach_is_refused_not_skipped(tmp_path):
    """The search skipped it as absent and said none of the places exists; the
    file is there and the refusal names why it cannot be read."""
    results = _write_results(tmp_path / "out" / ".ash" / "ash_output")
    locked = results.parent
    locked.chmod(0o000)
    try:
        result = _report("--format", "text", "--output-dir", str(tmp_path / "out"))
    finally:
        locked.chmod(0o700)

    assert result.exit_code == 1, result.output
    assert "Could not read the scan results" in result.output, result.output
    assert "No scan results found" not in result.output, result.output


def test_the_refused_name_is_never_none(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    assert _refused_config_name("a.yaml") == "a.yaml"
    assert _refused_config_name(None) == "the configuration file"
    monkeypatch.setenv("ASH_CONFIG", "env.yaml")
    assert _refused_config_name(None) == "env.yaml"


def test_both_named_files_are_held(monkeypatch):
    monkeypatch.setenv("ASH_CONFIG", "base.yaml")
    assert _named_config_files("a.yaml") == ["a.yaml", "base.yaml"]
    assert _named_config_files("base.yaml") == ["base.yaml"]
    assert _named_config_files(None) == ["base.yaml"]
    monkeypatch.delenv("ASH_CONFIG")
    assert _named_config_files(None) == []


def test_the_ash_config_file_is_confined_with_the_config_file(tmp_path, monkeypatch):
    """With both given, only the --config file was held to the off-host rules."""
    results = _write_results(tmp_path / "out")
    base = tmp_path / "base.yaml"
    base.write_text("project_name: base\n", encoding="utf-8")
    named = tmp_path / "named.yaml"
    named.write_text("project_name: named\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(base))
    held: list = []
    real = report_module.confine_off_host_reporters_to_overrides

    def recording(config, files, overrides, source):
        held.append(list(files))
        return real(config, files, overrides, source)

    monkeypatch.setattr(
        report_module, "confine_off_host_reporters_to_overrides", recording
    )

    result = _report(
        "--format", "text", "--output-dir", str(results.parent), "--config", str(named)
    )

    assert result.exit_code == 0, result.output
    assert held == [[named, base]], held


# --- the command ---


def test_a_deleted_working_directory_is_the_usage_refusal(tmp_path):
    gone = tmp_path / "gone"
    gone.mkdir()
    before = os.getcwd()
    os.chdir(gone)
    try:
        gone.rmdir()
        result = _report("--format", "text")
    finally:
        os.chdir(before)

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "deleted or unmounted" in result.output, result.output


def test_companion_files_follow_the_results_that_were_found(tmp_path, monkeypatch):
    """--output-dir named the project; the results were found under its
    .ash/ash_output, and the reporters wrote into <project>/reports."""
    project = tmp_path / "project"
    results = _write_results(project / ".ash" / "ash_output")
    seen: list = []
    real = report_module.PluginContext

    def recording(**kwargs):
        seen.append(kwargs["output_dir"])
        return real(**kwargs)

    monkeypatch.setattr(report_module, "PluginContext", recording)

    result = _report("--format", "text", "--output-dir", str(project))

    assert result.exit_code == 0, result.output
    assert seen == [results.parent], seen
    assert not (project / "reports").exists()


def test_a_reporter_that_cannot_be_built_is_a_failed_run_not_a_mistyped_format(
    tmp_path, monkeypatch
):
    from automated_security_helper.plugin_modules.ash_builtin.reporters import (
        text_reporter,
    )

    results = _write_results(tmp_path / "out")

    def refusing(self, *args, **kwargs):
        raise RuntimeError("the client library is missing")

    monkeypatch.setattr(text_reporter.TextReporter, "__init__", refusing)

    result = _report("--format", "text", "--output-dir", str(results.parent))

    assert result.exit_code == 1, result.output
    assert "not found" not in result.output, result.output
    assert "could not be built" in result.output, result.output
    assert "the client library is missing" in result.output, result.output


def test_a_reporter_is_built_once_from_its_section(tmp_path, monkeypatch):
    """The reporter was built twice, first from its defaults before the results
    were read, so a reporter whose default build raises but whose configured
    build works failed the run with "could not be built"; it is built once, from
    the section the configuration has for it."""
    from automated_security_helper.plugin_modules.ash_builtin.reporters import (
        text_reporter,
    )

    results = _write_results(tmp_path / "out")
    config = tmp_path / "ash.yaml"
    config.write_text(
        "project_name: fixture\nreporters:\n  text:\n    enabled: true\n",
        encoding="utf-8",
    )
    original = text_reporter.TextReporter.__init__
    builds: list[bool] = []

    def from_its_section_only(self, *args, **kwargs):
        builds.append(kwargs.get("config") is not None)
        if kwargs.get("config") is None:
            raise RuntimeError("the defaults are not a configuration")
        original(self, *args, **kwargs)

    monkeypatch.setattr(text_reporter.TextReporter, "__init__", from_its_section_only)

    result = _report(
        "--format",
        "text",
        "--config",
        str(config),
        "--output-dir",
        str(results.parent),
    )

    assert result.exit_code == 0, result.output
    assert builds == [True], builds


def test_a_closed_stdout_pipe_is_not_a_render_error(tmp_path, monkeypatch):
    results = _write_results(tmp_path / "out")

    def closed(*args, **kwargs):
        raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setattr(report_module, "_write_report", closed)

    result = _report("--format", "text", "--output-dir", str(results.parent))

    assert result.exit_code == 1, result.output
    assert "Error generating report" not in result.output, result.output


def test_a_broken_pipe_inside_the_reporter_is_a_failed_run(tmp_path, monkeypatch):
    """The closed-stdout handler wrapped the reporter too, so a BrokenPipeError
    raised inside a reporter (a subprocess pipe, a socket the remote end closed)
    exited 1 in silence, as if the reader had closed stdout; it is a failed run,
    with its cause on stderr."""
    from automated_security_helper.plugin_modules.ash_builtin.reporters import (
        text_reporter,
    )

    results = _write_results(tmp_path / "out")

    def closed(self, model):
        raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setattr(text_reporter.TextReporter, "report", closed)

    result = _report("--format", "text", "--output-dir", str(results.parent))

    assert result.exit_code == 1, result.output
    assert "Error generating report" in result.output, result.output
