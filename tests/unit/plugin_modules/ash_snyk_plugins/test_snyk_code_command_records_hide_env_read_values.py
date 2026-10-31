# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""snyk code's recorded command line hides a value its configuration read from the environment.

``project_name`` written ``!ENV ${VAR}`` in the configuration file is part of the
configuration's redaction set, and the scanned directory, an argument of the
command, carries that name. The command is recorded in a verbose log record, in the
SARIF invocation fields and in the scanner details attached to the results; the
value shows as ``<value>`` in each. A name written out literally is operator text
and is recorded whole.

snyk-code's own options put no value of their own on the command line:
``severity_threshold`` is applied by ASH after the scan and is not passed as
``--severity-threshold`` (test_snyk_code_scanner_behavior.py), so the directory
name is the value that reaches the command line here.
"""

import json
import logging
import shlex
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config import resolve_config as resolve_config_module
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_snyk_plugins import snyk_code_scanner
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()
AshConfig.model_rebuild()

MARKED_DIRECTORY = "marker-directory-value"
# Holds a single quote: shlex.join writes it as several quoted segments.
DIRECTORY_WITH_QUOTE = "marker-quote'marked-value"
SARIF_OUTPUT_FLAG = "--sarif-file-output="
EMPTY_SARIF = json.dumps(
    {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "SnykCode", "semanticVersion": "1.0.0"}},
                "results": [],
            }
        ],
    }
)


class _CapturedRecords(logging.Handler):
    def __init__(self):
        super().__init__(level=1)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


@pytest.fixture
def snyk_on_path(monkeypatch, tmp_path):
    """Report a snyk binary without installing Node or the CLI."""
    fake_binary = tmp_path / "bin" / "snyk"
    fake_binary.parent.mkdir(parents=True, exist_ok=True)
    fake_binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setattr(
        snyk_code_scanner, "find_executable", lambda name: str(fake_binary)
    )
    monkeypatch.setenv("SNYK_TOKEN", "placeholder-token")
    return fake_binary


def _scan(
    tmp_path,
    monkeypatch,
    *,
    directory_name=None,
    directory_is_environment_value=True,
    values_hook=None,
    output_under_directory=False,
    threshold_from_environment=None,
):
    """Scan with a fake snyk.

    With ``threshold_from_environment``, ``severity_threshold`` is written
    ``!ENV ${ASH_TEST_SNYK_THRESHOLD}`` and that variable holds the value.

    With ``directory_name``, the scanned directory sits in a directory of that
    name, which is an argument of the command. ``project_name`` reads the name
    from the environment, so the name is in the redaction set, unless
    ``directory_is_environment_value`` is false. ``values_hook`` replaces the
    scanner's ``_values_to_redact`` for the scan. With ``output_under_directory``
    the output directory sits under the named directory too, so the name reaches
    the command that runs (its ``--sarif-file-output`` argument), not only the
    recorded one.
    """
    monkeypatch.setenv("ASH_TEST_SNYK_DIRECTORY", directory_name or "unused")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config_file = tmp_path / "operator" / ".ash.yaml"
    config_file.parent.mkdir()
    if threshold_from_environment is not None:
        monkeypatch.setenv("ASH_TEST_SNYK_THRESHOLD", threshold_from_environment)
        threshold = "!ENV ${ASH_TEST_SNYK_THRESHOLD}"
    else:
        threshold = "MEDIUM"
    project_name = (
        "!ENV ${ASH_TEST_SNYK_DIRECTORY}"
        if directory_name and directory_is_environment_value
        else "command-record-project"
    )
    config_file.write_text(
        f"project_name: {project_name}\n"
        "scanners:\n"
        "  snyk-code:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      severity_threshold: {threshold}\n",
        encoding="utf-8",
    )
    _, config = resolve_config_module.load_config_file_for_run(config_file)
    source = tmp_path / (directory_name or ".") / "src"
    source.mkdir(parents=True)
    (source / "app.js").write_text("const token = 'placeholder';\n", encoding="utf-8")
    output_parent = (
        tmp_path / (directory_name or ".") if output_under_directory else tmp_path
    )
    output = output_parent / "out"
    output.mkdir()
    scanner = SnykCodeScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=tmp_path / "work",
            config=config,
        ),
        config=config.get_plugin_config(plugin_type="scanner", plugin_name="snyk-code"),
    )
    argv = []

    def fake_run(self, command, **kwargs):
        argv[:] = [str(a) for a in command]
        destination = next(
            arg.split("=", 1)[1] for arg in command if arg.startswith(SARIF_OUTPUT_FLAG)
        )
        Path(destination).write_text(EMPTY_SARIF, encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": 0}

    capture = _CapturedRecords()
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(capture)
    ASH_LOGGER.setLevel(1)
    try:
        with (
            patch.object(
                SnykCodeScanner, "_run_subprocess", autospec=True, side_effect=fake_run
            ),
            patch.object(SnykCodeScanner, "_values_to_redact", values_hook)
            if values_hook is not None
            else nullcontext(),
        ):
            report = scanner.scan(target=source, target_type="source")
    finally:
        ASH_LOGGER.removeHandler(capture)
        ASH_LOGGER.setLevel(previous_level)
    running = [m for m in capture.messages if "Running command" in m]
    return report, running, argv


def test_a_directory_name_read_from_the_environment_is_hidden_in_command_records(
    tmp_path, monkeypatch, snyk_on_path
):
    report, running, argv = _scan(
        tmp_path, monkeypatch, directory_name=MARKED_DIRECTORY
    )

    # The command is the bare name the scanner builds: the spawn layer, faked here,
    # is what resolves it, so the fake binary's path is not in the argument list.
    # The scan ran on a copy of the scan set: the directory argument is a temporary
    # directory, not the scanned one. The records name the scanned directory.
    assert argv[0] == "snyk", argv
    source = tmp_path / MARKED_DIRECTORY / "src"
    # The argv element as the command spelled it (as_posix), kept as a string for
    # the record check below: str(Path(...)) re-spells it with backslashes on
    # Windows, where the log line carries the forward slashes the command did.
    copy_argument = next(a for a in argv[3:] if not a.startswith("--"))
    copy = Path(copy_argument)
    assert copy.resolve() != source.resolve(), copy
    # tmp_path sits under the temporary directory by default, so "somewhere under
    # the temporary directory" holds for the source, the output and the work
    # directory too. The copy is the scanner's own: named with its prefix, and in
    # none of the directories this test made.
    assert copy.name.startswith(snyk_code_scanner._COPY_PREFIX), copy
    assert not copy.resolve().is_relative_to(tmp_path.resolve()), copy
    assert running, "the scan did not reach the Running command log call"
    invocation = report.runs[0].invocations[0]
    assert MARKED_DIRECTORY not in invocation.commandLine, invocation.commandLine
    assert "<value>" in invocation.commandLine, invocation.commandLine
    assert not any(MARKED_DIRECTORY in a for a in invocation.arguments)
    # The verbose log record names the command that ran: the copy snyk was given,
    # whose temporary name carries no value, so this record holds nothing to
    # redact (the redaction of that record is measured below, with a value that
    # does reach the command). The SARIF's own location fields still name the
    # scanned directory: redaction covers the command records, not where the
    # findings are.
    assert MARKED_DIRECTORY not in copy_argument, copy_argument
    assert any(copy_argument in message for message in running), running
    assert all(MARKED_DIRECTORY not in message for message in running), running


def test_an_environment_value_in_the_output_path_is_hidden_in_the_log_record(
    tmp_path, monkeypatch, snyk_on_path
):
    """The log record is redacted too, measured with a value the command carries.

    The scanned directory is swapped for a copy before the command runs, so the
    directory name never reaches the verbose "Running command" record; the output
    path does. With the output directory under the environment-named directory,
    the record carries the value's marker and not the value.
    """
    report, running, argv = _scan(
        tmp_path,
        monkeypatch,
        directory_name=MARKED_DIRECTORY,
        output_under_directory=True,
    )

    # The control: the value reaches the command that ran.
    assert any(MARKED_DIRECTORY in a for a in argv), argv
    assert running, "the scan did not reach the Running command log call"
    assert all(MARKED_DIRECTORY not in message for message in running), running
    assert any("<value>" in message for message in running), running
    invocation = report.runs[0].invocations[0]
    assert MARKED_DIRECTORY not in invocation.commandLine, invocation.commandLine


def test_a_threshold_read_from_the_environment_is_nowhere_in_the_scan(
    tmp_path, monkeypatch, snyk_on_path
):
    """``severity_threshold`` written ``!ENV`` is applied by ASH after the scan.

    It is not a snyk argument, so the command, the verbose records and the report
    are the places the value could still appear (ASH's own logs and the scanner
    details are new ones since the threshold moved out of the command). The scan
    has no results, so a severity word cannot match by being a finding's.
    """
    report, running, argv = _scan(
        tmp_path, monkeypatch, threshold_from_environment="CRITICAL"
    )

    assert argv, "the fake snyk was not run"
    assert running, "the scan did not reach the Running command log call"
    assert not any("critical" in a.lower() for a in argv), argv
    assert not any("severity-threshold" in a for a in argv), argv
    assert not any("critical" in message.lower() for message in running), running
    assert "critical" not in report.model_dump_json().lower()


def test_a_directory_name_written_out_is_recorded_whole(
    tmp_path, monkeypatch, snyk_on_path
):
    report, running, _ = _scan(
        tmp_path,
        monkeypatch,
        directory_name=MARKED_DIRECTORY,
        directory_is_environment_value=False,
    )

    source = tmp_path / MARKED_DIRECTORY / "src"
    assert running, "the scan did not reach the Running command log call"
    invocation = report.runs[0].invocations[0]
    assert source.as_posix() in invocation.commandLine
    assert source.as_posix() in invocation.arguments
    assert "<value>" not in invocation.commandLine


def test_a_quote_holding_environment_value_is_hidden_in_the_command_line(
    tmp_path, monkeypatch, snyk_on_path
):
    report, _, _ = _scan(tmp_path, monkeypatch, directory_name=DIRECTORY_WITH_QUOTE)

    invocation = report.runs[0].invocations[0]
    assert "marker-quote" not in invocation.commandLine, invocation.commandLine
    assert "marked-value" not in invocation.commandLine, invocation.commandLine
    assert "snyk code test" in invocation.commandLine


def test_a_quote_holding_directory_name_not_in_the_set_is_recorded_in_its_quoted_form(
    tmp_path, monkeypatch, snyk_on_path
):
    report, _, _ = _scan(
        tmp_path,
        monkeypatch,
        directory_name=DIRECTORY_WITH_QUOTE,
        directory_is_environment_value=False,
    )

    source = tmp_path / DIRECTORY_WITH_QUOTE / "src"
    invocation = report.runs[0].invocations[0]
    assert shlex.quote(source.as_posix()) in invocation.commandLine
    assert source.as_posix() in invocation.arguments


#: The two subcommands, which are two arguments of the command.
SPLIT_ACROSS_ARGUMENTS = "code test"


def test_a_value_split_across_two_arguments_leaves_no_piece_in_either_record(
    tmp_path, monkeypatch, snyk_on_path
):
    report, running, argv = _scan(
        tmp_path, monkeypatch, values_hook=lambda _self: (SPLIT_ACROSS_ARGUMENTS,)
    )

    assert argv[1:3] == ["code", "test"], argv
    invocation = report.runs[0].invocations[0]
    details = report.runs[0].tool.driver.properties.scanner_details["tool_invocation"]
    pieces = set(SPLIT_ACROSS_ARGUMENTS.split())
    for arguments in (invocation.arguments, details["arguments"]):
        assert not pieces.intersection(arguments), arguments
        assert len(arguments) == len(argv) - 1
    for command_line in (invocation.commandLine, details["command_line"]):
        assert not pieces.intersection(command_line.split()), command_line
        assert "<value>" in command_line, command_line
    assert not any(SPLIT_ACROSS_ARGUMENTS in m for m in running), running


def test_a_unique_token_split_across_two_arguments_is_absent_from_both_records(
    tmp_path, monkeypatch, snyk_on_path
):
    token = f"{tmp_path.as_posix()}/src"
    value = f"test {token}"
    report, _, argv = _scan(tmp_path, monkeypatch, values_hook=lambda _self: (value,))

    # The command runs on a staged copy; the records name the scanned directory
    # in its place, right after the subcommands.
    assert "test" in argv, argv
    invocation = report.runs[0].invocations[0]
    details = report.runs[0].tool.driver.properties.scanner_details["tool_invocation"]
    for arguments in (invocation.arguments, details["arguments"]):
        assert "test" not in arguments, arguments
        assert not any(token in a for a in arguments), arguments
    for command_line in (invocation.commandLine, details["command_line"]):
        assert "test" not in command_line.split(), command_line
        assert token not in command_line, command_line


def _raising_hook(_self):
    raise RuntimeError("the values hook broke")


def _none_hook(_self):
    return None


@pytest.mark.parametrize(
    "hook", [_raising_hook, _none_hook], ids=["raises", "answers-none"]
)
def test_a_failing_values_hook_leaves_the_command_records_holding_only_the_command(
    tmp_path, monkeypatch, snyk_on_path, hook
):
    report, running, argv = _scan(tmp_path, monkeypatch, values_hook=hook)

    assert hasattr(report, "runs"), type(report)
    command = argv[0]
    invocation = report.runs[0].invocations[0]
    details = report.runs[0].tool.driver.properties.scanner_details["tool_invocation"]
    assert invocation.commandLine == command, invocation.commandLine
    assert invocation.arguments == []
    assert details["command_line"] == command, details["command_line"]
    assert details["arguments"] == []
    assert running, "the scan did not reach the Running command log call"
    assert not any("code test" in m for m in running), running
    assert all(command in m for m in running), running


def test_a_values_answer_that_hides_nothing_keeps_the_whole_command_records(
    tmp_path, monkeypatch, snyk_on_path
):
    report, running, _ = _scan(tmp_path, monkeypatch, values_hook=lambda _self: ())

    invocation = report.runs[0].invocations[0]
    assert "snyk code test" in invocation.commandLine
    assert any("snyk code test" in m for m in running), running
