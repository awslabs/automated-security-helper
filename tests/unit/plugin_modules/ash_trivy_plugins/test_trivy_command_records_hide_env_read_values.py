# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""trivy's recorded command line hides a value the configuration read from the environment.

The command trivy ran is recorded in the SARIF invocation (``commandLine`` and
``arguments``). A value the configuration read from the environment is part of
the configuration's redaction set and shows as ``<value>``. The scanned
directory's name is one such value here: it is an argument of the command, so
the record holds it wherever the command does. A value that holds a single
quote must be hidden too, though the quoted command line spells it as several
quoted segments. A directory whose name is not in the set is recorded whole.
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
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()
AshConfig.model_rebuild()

# Holds a single quote: shlex.join writes it as several quoted segments.
DIRECTORY_WITH_QUOTE = "marker-quote'carrier-value"

EMPTY_SARIF = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [
        {
            "tool": {"driver": {"name": "Trivy", "version": "0.1.0", "rules": []}},
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


def _scan(tmp_path, monkeypatch, *, directory_is_environment_value, values_hook=None):
    """Scan a directory named ``DIRECTORY_WITH_QUOTE`` with a fake trivy.

    ``values_hook`` replaces the scanner's ``_values_to_redact`` for the scan.

    The configuration's ``project_name`` is read from the environment and holds
    the directory's name when ``directory_is_environment_value``, so the name is
    in the redaction set; otherwise ``project_name`` is written out.
    """
    monkeypatch.setenv("ASH_TEST_TRIVY_DIRECTORY", DIRECTORY_WITH_QUOTE)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    project_name = (
        "!ENV ${ASH_TEST_TRIVY_DIRECTORY}"
        if directory_is_environment_value
        else "command-record-project"
    )
    config_file = tmp_path / "operator" / ".ash.yaml"
    config_file.parent.mkdir()
    config_file.write_text(
        f"project_name: {project_name}\nscanners:\n  trivy-repo:\n    enabled: true\n",
        encoding="utf-8",
    )
    _, config = resolve_config_module.load_config_file_for_run(config_file)
    source = tmp_path / DIRECTORY_WITH_QUOTE / "src"
    source.mkdir(parents=True)
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "out"
    output.mkdir()
    scanner = TrivyRepoScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=config),
        config=config.get_plugin_config(
            plugin_type="scanner", plugin_name="trivy-repo"
        ),
    )
    scanner.dependencies_satisfied = True
    argv = []

    def fake_run(*, command, results_dir, **kwargs):
        argv[:] = [str(a) for a in command]
        Path(results_dir, "results_sarif.sarif").write_text(json.dumps(EMPTY_SARIF))
        return {"stdout": "", "stderr": "", "returncode": 0}

    capture = _CapturedRecords()
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(capture)
    ASH_LOGGER.setLevel(1)
    try:
        with (
            patch.object(scanner, "_pre_scan", return_value=True),
            patch.object(scanner, "_run_subprocess", side_effect=fake_run),
            patch.object(TrivyRepoScanner, "_values_to_redact", values_hook)
            if values_hook is not None
            else nullcontext(),
        ):
            report = scanner.scan(target=source, target_type="source")
    finally:
        ASH_LOGGER.removeHandler(capture)
        ASH_LOGGER.setLevel(previous_level)
    running = [m for m in capture.messages if "Running command" in m]
    return report, argv, source, running


def test_a_quote_holding_environment_value_is_hidden_in_the_recorded_command_line(
    tmp_path, monkeypatch
):
    report, argv, source, _ = _scan(
        tmp_path, monkeypatch, directory_is_environment_value=True
    )

    assert source.as_posix() in argv, argv
    invocation = report.runs[0].invocations[0]
    assert "marker-quote" not in invocation.commandLine, invocation.commandLine
    assert "carrier-value" not in invocation.commandLine, invocation.commandLine
    assert not any("carrier-value" in a for a in invocation.arguments)


def test_a_quote_holding_directory_name_not_in_the_set_is_recorded_in_its_quoted_form(
    tmp_path, monkeypatch
):
    report, argv, source, _ = _scan(
        tmp_path, monkeypatch, directory_is_environment_value=False
    )

    assert source.as_posix() in argv, argv
    invocation = report.runs[0].invocations[0]
    assert shlex.quote(source.as_posix()) in invocation.commandLine
    assert source.as_posix() in invocation.arguments


SPLIT_ACROSS_ARGUMENTS = "--format sarif"


def test_a_value_split_across_two_arguments_leaves_no_piece_in_either_record(
    tmp_path, monkeypatch
):
    report, argv, _, running = _scan(
        tmp_path,
        monkeypatch,
        directory_is_environment_value=False,
        values_hook=lambda _self: (SPLIT_ACROSS_ARGUMENTS,),
    )

    position = argv.index("--format")
    assert argv[position + 1] == "sarif", argv
    invocation = report.runs[0].invocations[0]
    details = report.runs[0].tool.driver.properties.scanner_details["tool_invocation"]
    pieces = set(SPLIT_ACROSS_ARGUMENTS.split())
    for arguments in (invocation.arguments, details["arguments"]):
        assert not pieces.intersection(arguments), arguments
        assert len(arguments) == len(argv) - 1
    for command_line in (invocation.commandLine, details["command_line"]):
        assert not pieces.intersection(command_line.split()), command_line
        assert "<value>" in command_line, command_line
    assert not any("--format" in m for m in running), running


def test_a_unique_token_split_across_two_arguments_is_absent_from_both_records(
    tmp_path, monkeypatch
):
    token = (
        tmp_path / "out" / "scanners" / "trivy-repo" / "source" / "results_sarif.sarif"
    ).as_posix()
    value = f"--output {token}"
    report, argv, _, _ = _scan(
        tmp_path,
        monkeypatch,
        directory_is_environment_value=False,
        values_hook=lambda _self: (value,),
    )

    position = argv.index("--output")
    assert argv[position + 1] == token, argv
    invocation = report.runs[0].invocations[0]
    details = report.runs[0].tool.driver.properties.scanner_details["tool_invocation"]
    for arguments in (invocation.arguments, details["arguments"]):
        assert "--output" not in arguments, arguments
        assert not any(token in a for a in arguments), arguments
    for command_line in (invocation.commandLine, details["command_line"]):
        assert "--output" not in command_line.split(), command_line
        assert token not in command_line, command_line


def _raising_hook(_self):
    raise RuntimeError("the values hook broke")


def _none_hook(_self):
    return None


@pytest.mark.parametrize(
    "hook", [_raising_hook, _none_hook], ids=["raises", "answers-none"]
)
def test_a_failing_values_hook_leaves_the_command_records_holding_only_the_command(
    tmp_path, monkeypatch, hook
):
    report, argv, _, running = _scan(
        tmp_path,
        monkeypatch,
        directory_is_environment_value=False,
        values_hook=hook,
    )

    assert hasattr(report, "runs"), type(report)
    assert any(a.startswith("--scanners") for a in argv), argv
    command = argv[0]
    invocation = report.runs[0].invocations[0]
    details = report.runs[0].tool.driver.properties.scanner_details["tool_invocation"]
    assert invocation.commandLine == command, invocation.commandLine
    assert invocation.arguments == []
    assert details["command_line"] == command, details["command_line"]
    assert details["arguments"] == []
    assert running, "the scan did not reach the Running command log call"
    assert not any("--scanners" in m for m in running), running
    assert all(command in m for m in running), running


def test_a_values_answer_that_hides_nothing_keeps_the_whole_command_records(
    tmp_path, monkeypatch
):
    report, argv, _, running = _scan(
        tmp_path,
        monkeypatch,
        directory_is_environment_value=False,
        values_hook=lambda _self: (),
    )

    invocation = report.runs[0].invocations[0]
    assert invocation.commandLine == shlex.join(argv), invocation.commandLine
    assert any("--scanners" in m for m in running), running
