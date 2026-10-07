# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for ``ash report``: reporter config and stdout format routing.

Two defects in ``report_command``, both reproduced end to end through the CLI
rather than with the plugin manager mocked, because the mocked tests in
``test_report.py`` replace exactly the objects these bugs live in:

* The reporter's config section was assigned to ``reporter.config`` as the plain
  dict ``get_plugin_config`` returns. Every reporter reads it by attribute, so
  ``ash report --format junitxml`` on a scan with any finding exited 1 with
  ``'dict' object has no attribute 'options'``.
* The list of formats printed with ``print_json`` named reporters that do not
  exist (asff, security-hub, security-lake, opensearch), missed JSON reporters
  that do, and the Markdown list spelled ``bedrock-summary`` where the reporter
  is ``bedrock-summary-reporter``.
"""

import importlib
import json
import pkgutil
import re
import pytest
from defusedxml import ElementTree as ET
from typer.testing import CliRunner

from automated_security_helper.base.reporter_plugin import ReporterPluginConfigBase
from automated_security_helper.cli.main import app
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.cli.report import (
    JSON_STDOUT_FORMATS,
    MARKDOWN_STDOUT_FORMATS,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    Message1,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

ANSI = re.compile(r"\x1b\[[0-9;]*m")

# Reporters that need AWS credentials to produce anything; their routing is
# checked by name only.
AWS_FORMATS = {"aws-security-hub", "cloudwatch-logs", "s3", "bedrock-summary-reporter"}


def _all_reporter_names() -> set:
    """Every reporter config name ASH ships, builtin and AWS."""
    for package_name in (
        "automated_security_helper.plugin_modules.ash_builtin.reporters",
        "automated_security_helper.plugin_modules.ash_aws_plugins",
    ):
        package = importlib.import_module(package_name)
        for module in pkgutil.iter_modules(package.__path__):
            importlib.import_module(f"{package_name}.{module.name}")

    names = set()
    pending = list(ReporterPluginConfigBase.__subclasses__())
    while pending:
        cls = pending.pop()
        pending.extend(cls.__subclasses__())
        field = cls.model_fields.get("name")
        if field is not None and isinstance(field.default, str):
            names.add(field.default)
    return names


def _model_with_one_low_finding() -> AshAggregatedResults:
    props = PropertyBag(tags=["tool_name::bandit"])
    props.__pydantic_extra__ = {"scanner_name": "bandit", "issue_severity": "LOW"}
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.sarif = SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit")),
                results=[
                    Result(
                        ruleId="B101",
                        level="note",
                        message=Message(root=Message1(text="assert used")),
                        properties=props,
                    )
                ],
            )
        ]
    )
    return model


def _write_results(output_dir, model=None):
    model = model or _model_with_one_low_finding()
    (output_dir / "ash_aggregated_results.json").write_text(
        model.model_dump_json(by_alias=True), encoding="utf-8"
    )


def _report(output_dir, fmt, *extra):
    return CliRunner().invoke(
        app,
        [
            "report",
            "--format",
            fmt,
            "--output-dir",
            str(output_dir),
            "--log-level",
            "ERROR",
            *extra,
        ],
    )


def _stdout(result) -> str:
    """The report itself: stdout without ANSI codes and without log lines.

    ASH's log handler writes to stdout as well, so anything logged at ERROR
    precedes the report. The report starts at the first line that opens a JSON
    or XML document.
    """
    lines = ANSI.sub("", result.stdout).splitlines()
    for index, line in enumerate(lines):
        if line.startswith(("{", "[", "<")):
            return "\n".join(lines[index:])
    return ""


@pytest.mark.parametrize("name", sorted(JSON_STDOUT_FORMATS | MARKDOWN_STDOUT_FORMATS))
def test_every_routed_format_is_a_real_reporter(name):
    assert name in _all_reporter_names(), (
        f"{name!r} is routed in report_command but no reporter is named that"
    )


@pytest.mark.parametrize(
    "name", sorted(JSON_STDOUT_FORMATS - AWS_FORMATS), ids=lambda n: n
)
def test_json_formats_print_parseable_json(tmp_path, name):
    _write_results(tmp_path)
    result = _report(tmp_path, name)
    assert result.exit_code == 0, result.output
    json.loads(_stdout(result))


def test_junitxml_with_a_finding_exits_zero(tmp_path):
    """Before the fix: exit 1, "'dict' object has no attribute 'options'"."""
    _write_results(tmp_path)
    result = _report(tmp_path, "junitxml")
    assert result.exit_code == 0, result.output
    root = ET.fromstring(_stdout(result).strip())
    assert root.findall(".//testcase"), "the finding did not reach the report"


def test_junitxml_honors_its_configured_options(tmp_path):
    """The config section reaches the reporter as its own config model.

    A LOW finding under the default MEDIUM threshold is skipped when
    respect_severity_threshold is true (the default) and an error when false,
    so the rendered XML shows which value the reporter actually read.
    """
    _write_results(tmp_path)
    config = tmp_path / "ash-config.yaml"
    config.write_text(
        "project_name: fixture\n"
        "reporters:\n"
        "  junitxml:\n"
        "    options:\n"
        "      respect_severity_threshold: false\n",
        encoding="utf-8",
    )
    result = _report(tmp_path, "junitxml", "--config", str(config))
    assert result.exit_code == 0, result.output
    root = ET.fromstring(_stdout(result).strip())
    assert root.findall(".//error"), (
        "respect_severity_threshold: false did not reach the reporter"
    )
    assert not root.findall(".//skipped")
