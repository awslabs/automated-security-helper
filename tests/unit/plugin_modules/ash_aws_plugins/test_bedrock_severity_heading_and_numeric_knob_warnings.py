# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Two small report-path rules of the Bedrock summary reporter.

* With the default ``group_by_severity`` a scan that has nothing to analyze (a
  secrets-only scan, whose findings have their own section) wrote the heading
  "Findings by severity" and nothing under it. The flat layout already says
  there is nothing to analyze; the grouped layout now does too, without asking
  the model.
* A numeric environment knob (ASH_BEDROCK_TEMPERATURE, ASH_BEDROCK_MAX_TOKENS)
  holding a bad value takes its default with a warning. The options model is
  built several times per scan, and each build logged the same warning; one
  refused value is now one warning.

No test here calls AWS: the model runtime answers by plan.
"""

import logging

import pytest

from automated_security_helper.base.options import (
    reset_refused_tool_version_warnings,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_pipeline import (
    BedrockPromptBuilder,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporterConfigOptions,
)
from tests.unit.plugin_modules.ash_aws_plugins.bedrock_reporter_doubles import (
    make_reporter,
    plugin_context_in,
)

pytestmark = pytest.mark.unit

NOTHING = "No actionable findings to analyze for this section."


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_refused_tool_version_warnings()
    yield
    reset_refused_tool_version_warnings()


class Runtime:
    """A bedrock-runtime client answering ``plan`` in order and recording requests."""

    def __init__(self, *plan):
        self.plan = list(plan)
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        step = self.plan.pop(0) if self.plan else "answer"
        return {
            "output": {"message": {"role": "assistant", "content": [{"text": step}]}}
        }


def _finding(rule_id, severity):
    return {
        "ruleId": rule_id,
        "level": "error",
        "severity": severity,
        "message": {"text": f"{rule_id} happened"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/a.py"}}}],
    }


def _grouped(reporter, findings, runtime, included=None):
    return reporter._render_by_severity(
        findings,
        BedrockPromptBuilder(),
        reporter._make_model_client(runtime),
        reporter.config.options,
        included,
    )


def test_a_grouped_layout_with_nothing_to_analyze_says_so(tmp_path):
    reporter = make_reporter(
        plugin_context_in(tmp_path), group_by_severity=True, enable_caching=False
    )
    runtime = Runtime()

    out = _grouped(reporter, [], runtime)

    assert out == NOTHING + "\n\n", out
    assert runtime.calls == []


def test_a_grouped_layout_points_at_the_secret_findings_section(tmp_path, monkeypatch):
    reporter = make_reporter(
        plugin_context_in(tmp_path), group_by_severity=True, enable_caching=False
    )
    monkeypatch.setattr(reporter, "_secret_findings_exist", True)

    out = _grouped(reporter, [], Runtime(), included={"secret_findings"})
    without_section = _grouped(reporter, [], Runtime(), included={"executive_summary"})

    assert "The secret findings are reported in their own section." in out, out
    assert "own section" not in without_section, without_section


def test_a_grouped_layout_with_findings_is_still_one_group_per_severity(tmp_path):
    """The control: the new branch is only for an empty list."""
    reporter = make_reporter(
        plugin_context_in(tmp_path), group_by_severity=True, enable_caching=False
    )
    runtime = Runtime("analysis of the high findings")

    out = _grouped(reporter, [_finding("R1", "HIGH")], runtime)

    assert "### High findings" in out, out
    assert "analysis of the high findings" in out, out
    assert NOTHING not in out, out
    assert len(runtime.calls) == 1


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]


def test_a_bad_numeric_knob_is_warned_about_once_over_repeated_builds(
    monkeypatch, caplog
):
    monkeypatch.setenv("ASH_BEDROCK_TEMPERATURE", "warm")
    monkeypatch.delenv("ASH_BEDROCK_MAX_TOKENS", raising=False)

    with caplog.at_level(logging.WARNING):
        for _ in range(3):
            options = BedrockSummaryReporterConfigOptions()

    assert options.temperature == 0.5
    warnings = _warnings(caplog)
    assert len(warnings) == 1, warnings
    assert "ASH_BEDROCK_TEMPERATURE" in warnings[0], warnings
    assert "warm" not in warnings[0], warnings


def test_each_bad_knob_is_warned_about_once_and_by_name(monkeypatch, caplog):
    monkeypatch.setenv("ASH_BEDROCK_TEMPERATURE", "9")
    monkeypatch.setenv("ASH_BEDROCK_MAX_TOKENS", "lots")

    with caplog.at_level(logging.WARNING):
        for _ in range(2):
            BedrockSummaryReporterConfigOptions()

    warnings = _warnings(caplog)
    assert len(warnings) == 2, warnings
    assert sum("ASH_BEDROCK_TEMPERATURE" in w for w in warnings) == 1, warnings
    assert sum("ASH_BEDROCK_MAX_TOKENS" in w for w in warnings) == 1, warnings


def test_a_different_bad_value_of_the_same_knob_is_warned_about_again(
    monkeypatch, caplog
):
    with caplog.at_level(logging.WARNING):
        monkeypatch.setenv("ASH_BEDROCK_TEMPERATURE", "warm")
        BedrockSummaryReporterConfigOptions()
        monkeypatch.setenv("ASH_BEDROCK_TEMPERATURE", "hot")
        BedrockSummaryReporterConfigOptions()

    assert len(_warnings(caplog)) == 2, _warnings(caplog)


def test_a_good_knob_warns_about_nothing(monkeypatch, caplog):
    """The control."""
    monkeypatch.setenv("ASH_BEDROCK_TEMPERATURE", "0.25")
    monkeypatch.setenv("ASH_BEDROCK_MAX_TOKENS", "77")

    with caplog.at_level(logging.WARNING):
        options = BedrockSummaryReporterConfigOptions()

    assert (options.temperature, options.max_tokens) == (0.25, 77)
    assert _warnings(caplog) == []
