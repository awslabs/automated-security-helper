# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""snyk code's recorded command line hides a value its option read from the environment.

``severity_threshold`` written ``${VAR}`` in the configuration file is part of
the configuration's redaction set, and snyk is given it as ``--severity-threshold
<lower case value>``. The command is recorded in a verbose log record, in the
SARIF invocation fields and in the scanner details attached to the results; the
value shows as ``<value>`` in each. A threshold written out literally is operator
text and is recorded whole.
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

PluginContext.model_rebuild()
AshConfig.model_rebuild()

# Holds a single quote: shlex.join writes it as several quoted segments.
DIRECTORY_WITH_QUOTE = "marker-quote'carrier-value"
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
    threshold_line,
    *,
    directory_name=None,
    directory_is_environment_value=True,
    values_hook=None,
):
    """Scan with a fake snyk, ``severity_threshold`` written as ``threshold_line``.

    With ``directory_name``, the scanned directory sits in a directory of that
    name, which is an argument of the command. ``project_name`` reads the name
    from the environment, so the name is in the redaction set, unless
    ``directory_is_environment_value`` is false. ``values_hook`` replaces the
    scanner's ``_values_to_redact`` for the scan.
    """
    monkeypatch.setenv("ASH_TEST_SNYK_THRESHOLD", "MEDIUM")
    monkeypatch.setenv("ASH_TEST_SNYK_DIRECTORY", directory_name or "unused")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config_file = tmp_path / "operator" / ".ash.yaml"
    config_file.parent.mkdir()
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
        f"      severity_threshold: {threshold_line}\n",
        encoding="utf-8",
    )
    _, config = resolve_config_module.load_config_file_for_run(config_file)
    source = tmp_path / (directory_name or ".") / "src"
    source.mkdir(parents=True)
    (source / "app.js").write_text("const token = 'placeholder';\n", encoding="utf-8")
    output = tmp_path / "out"
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


def test_a_threshold_read_from_the_environment_is_hidden_in_command_records(
    tmp_path, monkeypatch, snyk_on_path
):
    report, running, argv = _scan(
        tmp_path, monkeypatch, "!ENV ${ASH_TEST_SNYK_THRESHOLD}"
    )

    assert argv[argv.index("--severity-threshold") + 1] == "medium", argv
    assert running, "the scan did not reach the Running command log call"
    assert not any("medium" in m.lower() for m in running), running
    assert "medium" not in report.model_dump_json().lower()


def test_a_threshold_written_out_is_recorded_whole(tmp_path, monkeypatch, snyk_on_path):
    report, running, argv = _scan(tmp_path, monkeypatch, "HIGH")

    assert argv[argv.index("--severity-threshold") + 1] == "high", argv
    assert running, "the scan did not reach the Running command log call"
    assert any("--severity-threshold high" in m for m in running), running
    invocation = report.runs[0].invocations[0]
    assert "--severity-threshold high" in invocation.commandLine
    assert "high" in invocation.arguments


def test_a_quote_holding_environment_value_is_hidden_in_the_command_line(
    tmp_path, monkeypatch, snyk_on_path
):
    report, _, _ = _scan(
        tmp_path, monkeypatch, "HIGH", directory_name=DIRECTORY_WITH_QUOTE
    )

    invocation = report.runs[0].invocations[0]
    assert "marker-quote" not in invocation.commandLine, invocation.commandLine
    assert "carrier-value" not in invocation.commandLine, invocation.commandLine
    assert "--severity-threshold high" in invocation.commandLine


def test_a_quote_holding_directory_name_not_in_the_set_is_recorded_in_its_quoted_form(
    tmp_path, monkeypatch, snyk_on_path
):
    report, _, _ = _scan(
        tmp_path,
        monkeypatch,
        "HIGH",
        directory_name=DIRECTORY_WITH_QUOTE,
        directory_is_environment_value=False,
    )

    source = tmp_path / DIRECTORY_WITH_QUOTE / "src"
    invocation = report.runs[0].invocations[0]
    assert shlex.quote(source.as_posix()) in invocation.commandLine
    assert source.as_posix() in invocation.arguments


SPLIT_ACROSS_ARGUMENTS = "--severity-threshold high"


def test_a_value_split_across_two_arguments_leaves_no_piece_in_either_record(
    tmp_path, monkeypatch, snyk_on_path
):
    report, running, argv = _scan(
        tmp_path,
        monkeypatch,
        "HIGH",
        values_hook=lambda _self: (SPLIT_ACROSS_ARGUMENTS,),
    )

    position = argv.index("high")
    assert argv[position - 1] == "--severity-threshold", argv
    invocation = report.runs[0].invocations[0]
    details = report.runs[0].tool.driver.properties.scanner_details["tool_invocation"]
    pieces = set(SPLIT_ACROSS_ARGUMENTS.split())
    for arguments in (invocation.arguments, details["arguments"]):
        assert not pieces.intersection(arguments), arguments
        assert len(arguments) == len(argv) - 1
    for command_line in (invocation.commandLine, details["command_line"]):
        assert not pieces.intersection(command_line.split()), command_line
        assert "<value>" in command_line, command_line
    assert not any("--severity-threshold" in m for m in running), running


def test_a_unique_token_split_across_two_arguments_is_absent_from_both_records(
    tmp_path, monkeypatch, snyk_on_path
):
    token = f"{tmp_path.as_posix()}/src"
    value = f"high {token}"
    report, _, argv = _scan(
        tmp_path, monkeypatch, "HIGH", values_hook=lambda _self: (value,)
    )

    # The command runs on a staged copy; the records name the scanned directory
    # in its place, right after the threshold.
    assert "high" in argv, argv
    invocation = report.runs[0].invocations[0]
    details = report.runs[0].tool.driver.properties.scanner_details["tool_invocation"]
    for arguments in (invocation.arguments, details["arguments"]):
        assert "high" not in arguments, arguments
        assert not any(token in a for a in arguments), arguments
    for command_line in (invocation.commandLine, details["command_line"]):
        assert "high" not in command_line.split(), command_line
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
    report, running, argv = _scan(tmp_path, monkeypatch, "HIGH", values_hook=hook)

    assert hasattr(report, "runs"), type(report)
    command = argv[0]
    invocation = report.runs[0].invocations[0]
    details = report.runs[0].tool.driver.properties.scanner_details["tool_invocation"]
    assert invocation.commandLine == command, invocation.commandLine
    assert invocation.arguments == []
    assert details["command_line"] == command, details["command_line"]
    assert details["arguments"] == []
    assert running, "the scan did not reach the Running command log call"
    assert not any("--severity-threshold" in m for m in running), running
    assert all(command in m for m in running), running


def test_a_values_answer_that_hides_nothing_keeps_the_whole_command_records(
    tmp_path, monkeypatch, snyk_on_path
):
    report, running, _ = _scan(
        tmp_path, monkeypatch, "HIGH", values_hook=lambda _self: ()
    )

    invocation = report.runs[0].invocations[0]
    assert "--severity-threshold high" in invocation.commandLine
    assert any("--severity-threshold high" in m for m in running), running
