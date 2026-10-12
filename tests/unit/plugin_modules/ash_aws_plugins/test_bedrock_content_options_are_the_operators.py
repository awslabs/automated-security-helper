# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the Bedrock reporter sends to the model is decided by the operator's config.

The reporter's options that choose which findings are sent (``exclude_scanner_types``,
``actionable_only``, ``max_findings_*``, ``summarize_findings``,
``batch_processing``), what text goes with them (``industry_context``,
``compliance_frameworks``, ``custom_context``, ``custom_prompt``,
``include_code_snippets``), which model receives them
(``enable_fallback_models``) and which of the reporter's calls are made
(``add_section_headers``, ``output_markdown``, ``include_sections``,
``exclude_sections``, ``group_by_severity``) are the operator's
(config/reporter_trust.py). These
tests take the path a scan takes: the config is resolved from a file inside the
scanned tree, the reporter is built from the section ``get_plugin_config``
returns, as ``ReportPhase`` builds it, and its ``converse`` calls are captured.
A repository's value never reaches them; the same value from the operator's
config does, which shows the capture would see it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import yaml

from automated_security_helper.config.reporter_trust import (
    REPORTER_DESTINATION_OPTIONS,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
    BedrockSummaryReporterConfig,
    BedrockSummaryReporterConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

MODULE = (
    "automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter"
)
REPORTER = "bedrock-summary-reporter"

AshAggregatedResults.model_rebuild()
BedrockSummaryReporterConfig.model_rebuild()
BedrockSummaryReporter.model_rebuild()

#: The options this ruling makes the operator's, with a value other than the
#: default. Text values are markers the captured calls are searched for.
CONTENT: Dict[str, Any] = {
    "exclude_scanner_types": [],
    "actionable_only": False,
    "max_findings_to_analyze": 999,
    "max_findings_per_severity": 999,
    "summarize_findings": True,
    "batch_processing": True,
    "industry_context": "INDUSTRY-MARKER",
    "compliance_frameworks": ["FRAMEWORK-MARKER"],
    "custom_context": "CONTEXT-MARKER",
    "enable_fallback_models": False,
    "include_code_snippets": True,
    "custom_prompt": "PROMPT-MARKER",
}

#: What only a repository's value would put in a call: the marker texts, a
#: secret finding's message (``exclude_scanner_types: []``) and a suppressed
#: finding's (``actionable_only: false``).
MARKERS = (
    "INDUSTRY-MARKER",
    "FRAMEWORK-MARKER",
    "CONTEXT-MARKER",
    "PROMPT-MARKER",
    "SECRET-FINDING-MARKER",
    "SUPPRESSED-FINDING-MARKER",
)

#: The options that decide which of the reporter's model calls are made, each
#: sending findings: the simple report or the sectioned one
#: (``add_section_headers``), the files written with their own calls
#: (``output_markdown``), the sections asked for (``include_sections``,
#: ``exclude_sections``) and one call per severity (``group_by_severity``).
#: Values other than the defaults, which make fewer calls.
SHAPE: Dict[str, Any] = {
    "add_section_headers": False,
    "output_markdown": False,
    "include_sections": ["executive_summary"],
    "exclude_sections": ["technical_analysis"],
    "group_by_severity": False,
}

#: Written with the content options, so the reporter writes no files and builds a
#: simple report where the config they are in applies.
SHARED = {"output_markdown": False, "add_section_headers": False}


class RuntimeDouble:
    """A bedrock-runtime client that records each converse() call."""

    def __init__(self):
        self.calls: List[Dict[str, Any]] = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "output": {"message": {"role": "assistant", "content": [{"text": "ok"}]}}
        }


class SessionDouble:
    def __init__(self, runtime):
        self._runtime = runtime

    def client(self, service, **kwargs):
        return self._runtime


def _finding(rule_id: str, text: str, scanner_type: str = "SAST", **extra) -> Result:
    return Result.model_validate(
        {
            "ruleId": rule_id,
            "level": "error",
            "message": {"text": text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/app.py"},
                        "region": {"startLine": 1, "endLine": 2},
                    }
                }
            ],
            "properties": {"scanner_type": scanner_type},
            **extra,
        }
    )


def _results() -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="ASH")),
                results=[
                    _finding("R1", "an ordinary finding"),
                    _finding("R2", "SECRET-FINDING-MARKER", scanner_type="SECRET"),
                    _finding(
                        "R3",
                        "SUPPRESSED-FINDING-MARKER",
                        suppressions=[{"kind": "external"}],
                    ),
                ],
            )
        ],
    )
    model.scanner_results = {}
    return model


def _write(path: Path, options: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {"reporters": {REPORTER: {"options": {**SHARED, **options}}}}
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _report(config, test_plugin_context, monkeypatch) -> tuple:
    runtime = RuntimeDouble()
    monkeypatch.setattr(f"{MODULE}.boto3.Session", lambda **kw: SessionDouble(runtime))
    reporter = BedrockSummaryReporter(
        context=test_plugin_context,
        config=config.get_plugin_config("reporter", REPORTER),
    )
    reporter.report(_results())
    return reporter, json.dumps(runtime.calls, default=str)


def test_every_option_here_is_the_operators():
    """The lists above are the ruling's, and each one is in the table."""
    assert set(CONTENT) | set(SHAPE) <= set(REPORTER_DESTINATION_OPTIONS[REPORTER])


def _calls(config, test_plugin_context, monkeypatch) -> List[str]:
    """The system prompt of each model call, in order."""
    runtime = RuntimeDouble()
    monkeypatch.setattr(f"{MODULE}.boto3.Session", lambda **kw: SessionDouble(runtime))
    BedrockSummaryReporter(
        context=test_plugin_context,
        config=config.get_plugin_config("reporter", REPORTER),
    ).report(_results())
    return [json.dumps(call.get("system"), default=str) for call in runtime.calls]


def _shape_only(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump({"reporters": {REPORTER: {"options": SHAPE}}}), encoding="utf-8"
    )
    return path


def test_a_repository_does_not_choose_which_calls_are_made(
    tmp_path, test_plugin_context, monkeypatch
):
    source = tmp_path / "repo"
    source.mkdir()
    unconfigured = _calls(
        resolve_config(source_dir=source), test_plugin_context, monkeypatch
    )
    _shape_only(source / ".ash" / ".ash.yaml")

    config = resolve_config(source_dir=source)
    calls = _calls(config, test_plugin_context, monkeypatch)

    options = config.get_plugin_config("reporter", REPORTER)["options"]
    assert not set(SHAPE) & set(options), options
    assert calls == unconfigured


def test_the_operator_chooses_which_calls_are_made(
    tmp_path, test_plugin_context, monkeypatch
):
    """Positive control: the operator's values change the calls."""
    source = tmp_path / "repo"
    source.mkdir()
    unconfigured = _calls(
        resolve_config(source_dir=source), test_plugin_context, monkeypatch
    )
    operator = _shape_only(tmp_path / "operator" / "ash.yaml")

    calls = _calls(
        resolve_config(config_path=operator, source_dir=source),
        test_plugin_context,
        monkeypatch,
    )

    assert calls and calls != unconfigured
    assert len(calls) < len(unconfigured)


def test_a_repository_value_never_reaches_the_model_call(
    tmp_path, test_plugin_context, monkeypatch
):
    source = tmp_path / "repo"
    _write(source / ".ash" / ".ash.yaml", CONTENT)

    config = resolve_config(source_dir=source)
    reporter, sent = _report(config, test_plugin_context, monkeypatch)

    defaults = BedrockSummaryReporterConfigOptions()
    for name in CONTENT:
        assert getattr(reporter.config.options, name) == getattr(defaults, name), name
    assert sent != "[]", "the reporter made no model call"
    for marker in MARKERS:
        assert marker not in sent, marker


def test_a_hyphenated_repository_value_never_reaches_it_either(
    tmp_path, test_plugin_context, monkeypatch
):
    source = tmp_path / "repo"
    _write(
        source / ".ash" / ".ash.yaml",
        {name.replace("_", "-"): value for name, value in CONTENT.items()},
    )

    config = resolve_config(source_dir=source)
    _, sent = _report(config, test_plugin_context, monkeypatch)

    for marker in MARKERS:
        assert marker not in sent, marker


def test_the_operators_value_reaches_it(tmp_path, test_plugin_context, monkeypatch):
    """Positive control: the capture sees every marker when the operator sets it."""
    source = tmp_path / "repo"
    source.mkdir()
    operator = _write(tmp_path / "operator" / "ash.yaml", CONTENT)

    config = resolve_config(config_path=operator, source_dir=source)
    reporter, sent = _report(config, test_plugin_context, monkeypatch)

    for name, value in CONTENT.items():
        assert getattr(reporter.config.options, name) == value, name
    for marker in MARKERS:
        assert marker in sent, marker


def test_a_repository_repeating_the_operators_value_keeps_it(
    tmp_path, test_plugin_context, monkeypatch
):
    source = tmp_path / "repo"
    project = _write(source / ".ash" / ".ash.yaml", CONTENT)
    operator = _write(tmp_path / "operator" / "ash.yaml", CONTENT)

    config = resolve_config(
        config_path=project, source_dir=source, trusted_config_path=operator
    )
    reporter, sent = _report(config, test_plugin_context, monkeypatch)

    for name, value in CONTENT.items():
        assert getattr(reporter.config.options, name) == value, name
    assert "CONTEXT-MARKER" in sent
