# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Bedrock's ``actionable_only`` sends the findings the gate counts, and no others.

Why this exists
---------------
``actionable_only`` is described as "not suppressed, above severity threshold",
and the reporter judges the threshold by the finding's severity, not by a
``properties.below_threshold`` flag that nothing in ASH sets: a finding is sent
when it is not suppressed and its severity (the gate's ``result_severity``) fails
the threshold of the scanner that reported it, which is the exit-code gate's
definition of actionable. The LOW and INFO findings a MEDIUM gate ignores are not
sent.

No test here calls Bedrock: only the finding extraction runs. The AWS environment
is pointed at nothing and botocore sends are refused regardless.
"""

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
    BedrockSummaryReporterConfig,
    BedrockSummaryReporterConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

AshAggregatedResults.model_rebuild()
BedrockSummaryReporterConfig.model_rebuild()
BedrockSummaryReporter.model_rebuild()


@pytest.fixture(autouse=True)
def no_aws(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")  # pragma: allowlist secret
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-aws-creds"))

    def refuse(*args, **kwargs):
        raise AssertionError("a botocore request was attempted")

    monkeypatch.setattr("botocore.endpoint.Endpoint._send", refuse)


def _model(scanner_threshold=None) -> AshAggregatedResults:
    results = []
    for rule, level, severity, suppressed in [
        ("R-HIGH", "error", "HIGH", False),
        ("R-MEDIUM", "warning", None, False),
        ("R-LOW", "note", None, False),
        ("R-INFO", "none", None, False),
        ("R-HIGH-SUPPRESSED", "error", "HIGH", True),
    ]:
        properties = {"scanner_name": "bandit", "tags": []}
        if severity:
            properties["issue_severity"] = severity
        entry = {
            "ruleId": rule,
            "level": level,
            "message": {"text": rule},
            "properties": properties,
        }
        if suppressed:
            entry["suppressions"] = [{"kind": "external", "justification": "x"}]
        results.append(entry)
    model = AshAggregatedResults()
    config = {"project_name": "p", "global_settings": {"severity_threshold": "MEDIUM"}}
    if scanner_threshold:
        config["scanners"] = {
            "bandit": {"options": {"severity_threshold": scanner_threshold}}
        }
    model.ash_config = AshConfig.model_validate(config)
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "bandit"}}, "results": results}],
        }
    )
    return model


def _reporter(context, actionable_only=True) -> BedrockSummaryReporter:
    options = BedrockSummaryReporterConfigOptions(
        aws_region="us-east-1",
        model_id="test-vendor.test-model-v1:0",
        actionable_only=actionable_only,
    )
    return BedrockSummaryReporter(
        context=context, config=BedrockSummaryReporterConfig(options=options)
    )


def _sent(reporter, model):
    findings, secrets, _ = reporter._extract_findings(model)
    return sorted(f["ruleId"] for f in findings + secrets)


def test_findings_below_the_threshold_are_not_sent(test_plugin_context):
    assert _sent(_reporter(test_plugin_context), _model()) == ["R-HIGH", "R-MEDIUM"]


def test_a_scanners_own_threshold_decides_for_its_findings(test_plugin_context):
    assert _sent(_reporter(test_plugin_context), _model(scanner_threshold="LOW")) == [
        "R-HIGH",
        "R-LOW",
        "R-MEDIUM",
    ]


def test_without_the_option_everything_is_sent(test_plugin_context):
    assert _sent(_reporter(test_plugin_context, actionable_only=False), _model()) == [
        "R-HIGH",
        "R-HIGH-SUPPRESSED",
        "R-INFO",
        "R-LOW",
        "R-MEDIUM",
    ]
