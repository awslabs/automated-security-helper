# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Bedrock's ``actionable_only`` does not send a result whose kind states no finding.

``actionable_only`` sends the findings the exit-code gate counts, and the gate no
longer counts a result of kind ``pass``, ``notApplicable`` or ``informational``
(``sarif_utils.NON_FINDING_KINDS``). SARIF gives such a result level ``none``, which
ASH grades INFO, and a threshold of ``ALL`` fails INFO, so the reporter sent the note a
scanner records for a rule it did not evaluate to the model as a finding to analyze.
The findings details name why each result was left out, and a result that is not a
finding is not "below threshold".

Every test with a non-finding kind has a control that changes the kind and nothing
else. With ``actionable_only`` off every result is sent, as the option says.

No test here calls Bedrock: only the finding extraction runs. The AWS environment
is pointed at nothing and botocore sends are refused regardless.
"""

from __future__ import annotations

from typing import Any

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
    BedrockSummaryReporterConfig,
    BedrockSummaryReporterConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sarif_utils import NON_FINDING_KINDS

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()
BedrockSummaryReporterConfig.model_rebuild()
BedrockSummaryReporter.model_rebuild()

# Sorted, so every pytest-xdist worker collects the same ids in the same order.
NON_FINDING = sorted(NON_FINDING_KINDS)
# The kinds that assert a finding. A result that states no kind is a failing one.
FINDING = ["fail", "open", "review"]
ANY_FINDING = [pytest.param(None, id="absent"), *FINDING]


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


def _model(kind: str | None, *, suppressed: bool = False) -> AshAggregatedResults:
    """A HIGH finding and a note of *kind*, under a gate of ALL."""
    high: dict[str, Any] = {
        "ruleId": "R-HIGH",
        "level": "error",
        "message": {"text": "R-HIGH"},
        "properties": {
            "scanner_name": "bandit",
            "tags": [],
            "issue_severity": "HIGH",
        },
    }
    note: dict[str, Any] = {
        "ruleId": "R-NOTE",
        "level": "none",
        "message": {"text": "R-NOTE"},
        "properties": {"scanner_name": "bandit", "tags": []},
    }
    if kind is not None:
        note["kind"] = kind
    if suppressed:
        note["suppressions"] = [{"kind": "external", "justification": "x"}]
    model = AshAggregatedResults()
    model.ash_config = AshConfig.model_validate(
        {"project_name": "p", "global_settings": {"severity_threshold": "ALL"}}
    )
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "bandit"}}, "results": [high, note]}],
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


def _left_out(reporter, model):
    _, _, indexed = reporter._extract_findings(model)
    return {entry["rule_id"]: entry["left_out"] for entry in indexed}


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_result_that_states_no_finding_is_not_sent(test_plugin_context, kind):
    assert _sent(_reporter(test_plugin_context), _model(kind)) == ["R-HIGH"]


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_same_result_that_asserts_a_finding_is_sent(test_plugin_context, kind):
    assert _sent(_reporter(test_plugin_context), _model(kind)) == [
        "R-HIGH",
        "R-NOTE",
    ]


@pytest.mark.parametrize("kind", NON_FINDING)
def test_without_the_option_a_result_that_states_no_finding_is_sent_too(
    test_plugin_context, kind
):
    """Must-not-regress control: off, the option sends every result, as it says."""
    reporter = _reporter(test_plugin_context, actionable_only=False)

    assert _sent(reporter, _model(kind)) == ["R-HIGH", "R-NOTE"]


@pytest.mark.parametrize("kind", NON_FINDING)
def test_the_findings_details_say_such_a_result_is_not_a_finding(
    test_plugin_context, kind
):
    left_out = _left_out(_reporter(test_plugin_context), _model(kind))

    assert left_out == {"R-HIGH": None, "R-NOTE": "not a finding"}


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_findings_details_leave_out_nothing_that_asserts_a_finding(
    test_plugin_context, kind
):
    left_out = _left_out(_reporter(test_plugin_context), _model(kind))

    assert left_out == {"R-HIGH": None, "R-NOTE": None}


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_suppressed_result_that_states_no_finding_is_left_out_as_suppressed(
    test_plugin_context, kind
):
    """Must-not-regress control: a suppression in effect is the reason that is given.

    Green at the base too.
    """
    left_out = _left_out(_reporter(test_plugin_context), _model(kind, suppressed=True))

    assert left_out == {"R-HIGH": None, "R-NOTE": "suppressed"}
