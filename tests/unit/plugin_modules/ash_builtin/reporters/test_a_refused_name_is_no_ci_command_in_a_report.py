# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refused input's name is no CI command in any record or report that carries it.

A converter keeps each input it refused in its results row (RefusedInputInfo:
path, member, reason), with the name as it was read, so a name can hold a newline,
and a line of it can start with a CI command: "::" (GitHub Actions) or "##" (its
legacy "##[", Azure Pipelines' "##vso[", TeamCity's "##teamcity["). Every file or
reply that carries the row must write such a name so that no line of it starts
with one when it is printed to a CI log: escaped in the text, or encoded by the
format, as JSON writes a newline as \\n.

PyYAML writes a value holding a newline as a block of lines, the next one
starting with what followed the newline, and folds a long value at a space, so
ash.yaml, the S3 reporter's YAML and ``ash report --format yaml`` quote any
value that could start a line with a CI command. The JSON writers encode the
newline; their cells show it.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.cli.main import app
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
    RefusedInputInfo,
)

pytestmark = pytest.mark.unit

#: Names a refusal record can hold, each with a line that is a workflow command
#: unless the writer escapes or encodes it.
NAMES = {
    "newline-then-command": "x\n::add-mask::secret-a",
    "command-first": "::warning::secret-b.js",
    "folded-at-a-space": "a" * 70 + " ::add-mask::secret-c",
    "newline-then-legacy-command": "x\n##[group]secret-d",
    "azure-command-first": "##vso[task.setvariable variable=a]secret-e",
    "folded-teamcity-command": "a" * 70 + " ##teamcity[message text='secret-f']",
    "newline-then-upper-case-name": "x\n##VSO[task.complete]secret-g",
}


def _model() -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.converter_results = {
        "archive": ConverterStatusInfo(
            refused_inputs=[
                RefusedInputInfo(path=f"lib/{name}", member=name, reason=f"for {name}")
                for name in NAMES.values()
            ]
        )
    }
    return model


def _command_lines(text: str) -> list[str]:
    """The lines that start, after whitespace, with "::" or "##"."""
    return [
        line for line in text.splitlines() if line.lstrip().startswith(("::", "##"))
    ]


def _members(refused: list[dict]) -> list[str]:
    return [entry["member"] for entry in refused]


def _assert_carried_without_a_command(text: str, refused: list[dict]) -> None:
    assert _command_lines(text) == [], _command_lines(text)
    assert _members(refused) == list(NAMES.values())


def _context(tmp_path: Path) -> PluginContext:
    return PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
    )


def test_a_value_without_a_command_at_a_line_start_is_written_as_before():
    """A tag's "::" inside a word is no command at a line start, and a text with
    a line break and no mark at all keeps PyYAML's own style too: a "::" value is
    quoted only when it could start a line. A "##name[" form is a command wherever
    it sits in a line (the runners that read it match it anywhere), so one inside
    a word is written broken, which
    tests/unit/utils/test_report_yaml_breaks_named_hash_commands_anywhere.py pins."""
    from automated_security_helper.utils.report_yaml import report_yaml

    data = {
        "tag": "tool_name::bandit",
        "no-mark": "no findings\nin the scan",
    }

    assert report_yaml(data) == yaml.dump(data)


def test_a_markdown_heading_is_written_double_quoted_and_reads_back():
    """Any "##" first or after whitespace is quoted, a Markdown heading's
    included. Quoting changes no value."""
    from automated_security_helper.utils.report_yaml import report_yaml

    data = {"heading": "## Summary\n\nno findings"}

    text = report_yaml(data)

    assert '"## Summary\\n\\nno findings"' in text, text
    assert _command_lines(text) == [], text
    assert yaml.safe_load(text) == data


def test_ash_yaml_holds_no_command(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.reporters.yaml_reporter import (
        YamlReporter,
    )

    text = YamlReporter(context=_context(tmp_path)).report(_model())

    refused = yaml.safe_load(text)["converter_results"]["archive"]["refused_inputs"]
    _assert_carried_without_a_command(text, refused)


@pytest.mark.parametrize("file_format", ["yaml", "json"])
@patch("automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter.boto3")
def test_the_s3_report_holds_no_command(mock_boto3, tmp_path, file_format):
    from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
        S3Reporter,
        S3ReporterConfig,
        S3ReporterConfigOptions,
    )

    s3_client = MagicMock()
    mock_boto3.Session.return_value.client.return_value = s3_client
    reporter = S3Reporter(
        context=_context(tmp_path),
        config=S3ReporterConfig(
            options=S3ReporterConfigOptions(
                aws_region="us-west-2", bucket_name="a-bucket", file_format=file_format
            )
        ),
    )

    reporter.report(_model())

    body = s3_client.put_object.call_args.kwargs["Body"]
    text = body.decode("utf-8") if isinstance(body, bytes) else body
    loaded = yaml.safe_load(text) if file_format == "yaml" else json.loads(text)
    refused = loaded["converter_results"]["archive"]["refused_inputs"]
    _assert_carried_without_a_command(text, refused)


def test_the_results_file_holds_no_command():
    text = _model().model_dump_json(indent=2, by_alias=True)

    refused = json.loads(text)["converter_results"]["archive"]["refused_inputs"]
    _assert_carried_without_a_command(text, refused)


@patch(
    "automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter.boto3"
)
def test_the_cloudwatch_event_holds_no_command(mock_boto3, tmp_path):
    from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
        CloudWatchLogsReporter,
        CloudWatchLogsReporterConfig,
        CloudWatchLogsReporterConfigOptions,
    )

    logs_client = MagicMock()
    mock_boto3.client.return_value = logs_client
    reporter = CloudWatchLogsReporter(
        context=_context(tmp_path),
        config=CloudWatchLogsReporterConfig(
            options=CloudWatchLogsReporterConfigOptions(
                aws_region="us-west-2", log_group_name="a-group"
            )
        ),
    )

    receipt = reporter.report(_model())

    (event,) = logs_client.put_log_events.call_args.kwargs["logEvents"]
    for text in (event["message"], receipt):
        loaded = json.loads(text)
        loaded = loaded.get("message", loaded)
        refused = loaded["converter_results"]["archive"]["refused_inputs"]
        _assert_carried_without_a_command(text, refused)


def test_the_mcp_scan_results_hold_no_command(tmp_path):
    from automated_security_helper.core.resource_management.scan_tracking import (
        get_scan_results,
    )

    output_dir = tmp_path / "out"
    output_dir.mkdir()
    (output_dir / "ash_aggregated_results.json").write_text(
        _model().model_dump_json(by_alias=True), encoding="utf-8"
    )

    reply = json.dumps(get_scan_results(output_dir=output_dir), indent=2)

    raw = json.loads(reply)["raw_results"]
    refused = raw["converter_results"]["archive"]["refused_inputs"]
    _assert_carried_without_a_command(reply, refused)


def test_ash_report_yaml_prints_no_command(tmp_path):
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    (output_dir / "ash_aggregated_results.json").write_text(
        _model().model_dump_json(by_alias=True), encoding="utf-8"
    )

    result = CliRunner().invoke(
        app,
        [
            "report",
            "--format",
            "yaml",
            "--output-dir",
            str(output_dir),
            "--log-level",
            "ERROR",
        ],
    )

    assert result.exit_code == 0, result.output
    report = result.stdout[result.stdout.index("converter_results") :]
    assert _command_lines(result.stdout) == [], _command_lines(result.stdout)
    refused = yaml.safe_load("converter_results" + report[len("converter_results") :])
    assert _members(refused["converter_results"]["archive"]["refused_inputs"]) == list(
        NAMES.values()
    )


#: The probe matrix: every CI command form, after each separator, behind every
#: prefix length up to past the width. PyYAML splits a long double-quoted value
#: once its column passes the width, and the split can fall right after an escape
#: (\n, \t, \a, \", \x85), not only at a space; the next line then starts with
#: whatever follows, as is.
_FORMS = (
    "::add-mask::secret-h",
    "##[group]secret-i",
    "##vso[task.setvariable variable=a]secret-j",
    "##teamcity[message text='secret-k']",
)
_SEPARATORS = {
    "space": " ",
    "newline": "\n",
    "indented": "\n  ",
    "tab": "\t",
    "bell": "\a",
    "quote": '"',
    "next-line": "\x85",
}
_PREFIX_LENGTHS = range(130)


def _yaml_writers():
    from automated_security_helper.cli.mcp_tools import _block_yaml_one_line_per_key
    from automated_security_helper.utils.report_yaml import report_yaml

    return {
        "ash.yaml": lambda data: report_yaml(data, indent=2),
        "s3": lambda data: report_yaml(data, default_flow_style=False),
        "mcp-suppression": _block_yaml_one_line_per_key,
    }


@pytest.mark.parametrize("writer", ["ash.yaml", "s3", "mcp-suppression"])
@pytest.mark.parametrize("separator", sorted(_SEPARATORS))
@pytest.mark.parametrize("form", _FORMS, ids=lambda form: form.split("[")[0][:8])
def test_no_split_puts_a_command_at_a_line_start(writer, separator, form):
    """Each value is written in a results row, then read back: it must read back
    as it was, and no line of the output may start with a command form."""
    write = _yaml_writers()[writer]
    failures = []
    for length in _PREFIX_LENGTHS:
        value = "A" * length + _SEPARATORS[separator] + form
        data = {
            "converter_results": {
                "archive": {
                    "refused_inputs": [
                        {"path": "lib/b.tar", "member": value, "reason": "a link"}
                    ]
                }
            }
        }
        text = write(data)
        lines = _command_lines(text)
        if lines or yaml.safe_load(text) != data:
            failures.append((length, lines))

    assert failures == [], f"{len(failures)} of {len(_PREFIX_LENGTHS)}: {failures[:3]}"
