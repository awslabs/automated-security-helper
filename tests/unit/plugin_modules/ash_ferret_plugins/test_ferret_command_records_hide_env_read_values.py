# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ferret-scan's recorded command line hides a value its option read from the environment.

The option is written ``${VAR}`` in the configuration file, so its value is part
of the configuration's redaction set. The command ferret-scan ran is recorded in
a debug log record, in the SARIF invocation fields and in the scanner details
attached to the results; each shows the option as ``<value>``. An option written
out literally is operator text and is recorded whole.
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
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScanScanner,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()
AshConfig.model_rebuild()

PROFILE_FROM_ENVIRONMENT = "marker-secret-profile-value"
PROFILE_WRITTEN_OUT = "marker-literal-profile-value"
# Holds a single quote: shlex.join writes it as several quoted segments.
PROFILE_WITH_QUOTE = "marker-quote'carrier-value"

EMPTY_SARIF = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [
        {
            "tool": {
                "driver": {"name": "ferret-scan", "version": "2.5.3", "rules": []}
            },
            "results": [],
        }
    ],
}


class _CapturedRecords(logging.Handler):
    def __init__(self):
        super().__init__(level=1)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def _scan(
    tmp_path,
    monkeypatch,
    profile_line,
    environment_value=PROFILE_FROM_ENVIRONMENT,
    values_hook=None,
):
    """Scan with a fake ferret-scan, the profile option written as ``profile_line``.

    ``values_hook`` replaces the scanner's ``_values_to_redact`` for the scan.
    """
    monkeypatch.setenv("ASH_TEST_FERRET_PROFILE", environment_value)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config_file = tmp_path / "operator" / ".ash.yaml"
    config_file.parent.mkdir()
    config_file.write_text(
        "project_name: command-record-project\n"
        "scanners:\n"
        "  ferret-scan:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      profile: {profile_line}\n",
        encoding="utf-8",
    )
    _, config = resolve_config_module.load_config_file_for_run(config_file)
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "out"
    output.mkdir()
    scanner = FerretScanScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=config),
        config=config.get_plugin_config(
            plugin_type="scanner", plugin_name="ferret-scan"
        ),
    )
    scanner.dependencies_satisfied = True
    argv = []

    def fake_run(*, command, results_dir, **kwargs):
        argv[:] = [str(a) for a in command]
        Path(results_dir, "ferret-scan.sarif").write_text(json.dumps(EMPTY_SARIF))
        return {"returncode": 0}

    capture = _CapturedRecords()
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(capture)
    ASH_LOGGER.setLevel(1)
    try:
        with (
            patch.object(scanner, "_pre_scan", return_value=True),
            patch.object(scanner, "_run_subprocess", side_effect=fake_run),
            patch.object(FerretScanScanner, "_values_to_redact", values_hook)
            if values_hook is not None
            else nullcontext(),
        ):
            report = scanner.scan(target=source, target_type="source")
    finally:
        ASH_LOGGER.removeHandler(capture)
        ASH_LOGGER.setLevel(previous_level)
    running = [m for m in capture.messages if "Running command" in m]
    return report, running, argv


def test_a_profile_read_from_the_environment_is_hidden_in_command_records(
    tmp_path, monkeypatch
):
    report, running, argv = _scan(
        tmp_path, monkeypatch, "!ENV ${ASH_TEST_FERRET_PROFILE}"
    )

    assert PROFILE_FROM_ENVIRONMENT in argv, argv
    assert running, "the scan did not reach the Running command log call"
    assert not any(PROFILE_FROM_ENVIRONMENT in m for m in running), running
    assert PROFILE_FROM_ENVIRONMENT not in report.model_dump_json()


def test_a_profile_written_out_is_recorded_whole(tmp_path, monkeypatch):
    report, running, argv = _scan(tmp_path, monkeypatch, PROFILE_WRITTEN_OUT)

    assert PROFILE_WRITTEN_OUT in argv, argv
    assert running, "the scan did not reach the Running command log call"
    assert any(PROFILE_WRITTEN_OUT in m for m in running), running
    invocation = report.runs[0].invocations[0]
    assert PROFILE_WRITTEN_OUT in invocation.commandLine
    assert PROFILE_WRITTEN_OUT in invocation.arguments


def test_the_invocation_keeps_the_flag_beside_a_hidden_profile(tmp_path, monkeypatch):
    report, _, _ = _scan(tmp_path, monkeypatch, "!ENV ${ASH_TEST_FERRET_PROFILE}")

    invocation = report.runs[0].invocations[0]
    assert "--profile" in invocation.arguments
    assert "--profile" in invocation.commandLine


def test_a_quote_holding_profile_from_the_environment_is_hidden_in_the_command_line(
    tmp_path, monkeypatch
):
    report, _, argv = _scan(
        tmp_path,
        monkeypatch,
        "!ENV ${ASH_TEST_FERRET_PROFILE}",
        environment_value=PROFILE_WITH_QUOTE,
    )

    assert PROFILE_WITH_QUOTE in argv, argv
    invocation = report.runs[0].invocations[0]
    assert "marker-quote" not in invocation.commandLine, invocation.commandLine
    assert "carrier-value" not in invocation.commandLine, invocation.commandLine
    assert "--profile" in invocation.commandLine


def test_a_quote_holding_profile_written_out_is_recorded_in_its_quoted_form(
    tmp_path, monkeypatch
):
    report, _, argv = _scan(tmp_path, monkeypatch, f'"{PROFILE_WITH_QUOTE}"')

    assert PROFILE_WITH_QUOTE in argv, argv
    invocation = report.runs[0].invocations[0]
    assert shlex.quote(PROFILE_WITH_QUOTE) in invocation.commandLine
    assert PROFILE_WITH_QUOTE in invocation.arguments


SPLIT_ACROSS_ARGUMENTS = f"--profile {PROFILE_WRITTEN_OUT}"


def test_a_value_split_across_two_arguments_leaves_no_piece_in_either_record(
    tmp_path, monkeypatch
):
    report, running, argv = _scan(
        tmp_path,
        monkeypatch,
        PROFILE_WRITTEN_OUT,
        values_hook=lambda _self: (SPLIT_ACROSS_ARGUMENTS,),
    )

    position = argv.index(PROFILE_WRITTEN_OUT)
    assert argv[position - 1] == "--profile", argv
    invocation = report.runs[0].invocations[0]
    details = report.runs[0].tool.driver.properties.scanner_details["tool_invocation"]
    pieces = set(SPLIT_ACROSS_ARGUMENTS.split())
    for arguments in (invocation.arguments, details["arguments"]):
        assert not pieces.intersection(arguments), arguments
        assert len(arguments) == len(argv) - 1
    for command_line in (invocation.commandLine, details["command_line"]):
        assert not pieces.intersection(command_line.split()), command_line
        assert PROFILE_WRITTEN_OUT not in command_line, command_line
        assert "<value>" in command_line, command_line
    assert not any(PROFILE_WRITTEN_OUT in m for m in running), running


def _raising_hook(_self):
    raise RuntimeError("the values hook broke")


def _none_hook(_self):
    return None


def _assert_command_only(report, running, argv):
    """The scan finished with a report; the log line and both SARIF records
    name the command and none of the arguments the tool was given."""
    assert hasattr(report, "runs"), type(report)
    command = argv[0]
    invocation = report.runs[0].invocations[0]
    details = report.runs[0].tool.driver.properties.scanner_details["tool_invocation"]
    assert invocation.commandLine == command, invocation.commandLine
    assert invocation.arguments == []
    assert details["command_line"] == command, details["command_line"]
    assert details["arguments"] == []
    assert running, "the scan did not reach the Running command log call"
    assert not any("--profile" in m or PROFILE_WRITTEN_OUT in m for m in running)
    assert all(command in m for m in running), running


@pytest.mark.parametrize(
    "hook", [_raising_hook, _none_hook], ids=["raises", "answers-none"]
)
def test_a_failing_values_hook_leaves_the_command_records_holding_only_the_command(
    tmp_path, monkeypatch, hook
):
    report, running, argv = _scan(
        tmp_path, monkeypatch, PROFILE_WRITTEN_OUT, values_hook=hook
    )

    assert PROFILE_WRITTEN_OUT in argv, argv
    _assert_command_only(report, running, argv)


def test_a_values_answer_that_hides_nothing_keeps_the_whole_command_records(
    tmp_path, monkeypatch
):
    report, running, argv = _scan(
        tmp_path, monkeypatch, PROFILE_WRITTEN_OUT, values_hook=lambda _self: ()
    )

    invocation = report.runs[0].invocations[0]
    assert invocation.commandLine == shlex.join(argv), invocation.commandLine
    assert PROFILE_WRITTEN_OUT in invocation.arguments
    assert any(PROFILE_WRITTEN_OUT in m for m in running), running


CONFIG_FILE_MARKER = "marker-ferret-config-value"
CONFIG_FILE_VARIABLE = "ASH_MARKER_FERRET_CONFIG"
NOT_FOUND_TEXT = "Specified config file not found"
NOT_FOUND_ACTION = "Ferret-scan will run with the empty config file ASH writes"


def _config_file_warnings(tmp_path, monkeypatch, written_value, *, from_environment):
    """The warning records made for a ``config_file`` option naming a file that does
    not exist, read through the loader every scan uses."""
    missing = tmp_path / CONFIG_FILE_MARKER / "ferret.yaml"
    if from_environment:
        monkeypatch.setenv(CONFIG_FILE_VARIABLE, str(missing))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config_file = tmp_path / "operator" / ".ash.yaml"
    config_file.parent.mkdir()
    config_file.write_text(
        "project_name: config-file-warning-project\n"
        "scanners:\n"
        "  ferret-scan:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      config_file: {written_value.replace('@@', str(missing))}\n",
        encoding="utf-8",
    )
    _, config = resolve_config_module.load_config_file_for_run(config_file)
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()

    records = []

    class _Warnings(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Warnings(level=logging.WARNING)
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        scanner = FerretScanScanner(
            context=PluginContext(source_dir=source, output_dir=output, config=config),
            config=config.get_plugin_config(
                plugin_type="scanner", plugin_name="ferret-scan"
            ),
        )
        assert str(scanner.config.options.config_file) == str(missing)
        scanner._process_config_options()
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous_level)
    return [r.getMessage() for r in records if NOT_FOUND_TEXT in r.getMessage()]


@pytest.mark.parametrize(
    "written",
    ["${" + CONFIG_FILE_VARIABLE + "}", "!ENV ${" + CONFIG_FILE_VARIABLE + "}"],
    ids=["plain-reference", "tagged-reference"],
)
def test_a_missing_config_file_read_from_the_environment_is_hidden_in_the_warning(
    tmp_path, monkeypatch, written
):
    messages = _config_file_warnings(
        tmp_path, monkeypatch, written, from_environment=True
    )

    assert messages, "the not-found branch did not log"
    for message in messages:
        assert CONFIG_FILE_MARKER not in message, message
        assert NOT_FOUND_ACTION in message, message


def test_a_missing_config_file_written_out_is_shown_in_the_warning(
    tmp_path, monkeypatch
):
    messages = _config_file_warnings(
        tmp_path, monkeypatch, "'@@'", from_environment=False
    )

    assert messages, "the not-found branch did not log"
    for message in messages:
        assert CONFIG_FILE_MARKER in message, message
        assert NOT_FOUND_ACTION in message, message
