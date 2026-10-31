# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the model client repairs and what the prompt builders send.

Four defects of ``bedrock_pipeline``, each pinned by the test that failed at
the base: a model that takes temperature or top_p but not both refused every
call and the walk switched models; the risk and compliance prompts carried five
sample findings whatever ``max_findings_to_analyze`` said; a ``custom_context``
configured alone never reached the model; and a finding that stands for several
(a summarized rule) counted as one in every total the model was told.

No test here calls AWS: the runtime is a MagicMock that answers by plan.
"""

import logging
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

from automated_security_helper.utils.log import ASH_LOGGER, VERBOSE_LEVEL
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_pipeline import (
    BedrockModelClient,
    BedrockPromptBuilder,
)

pytestmark = pytest.mark.unit


def _finding(rule_id="RULE-1", severity="HIGH", summarized_count=None):
    finding = {
        "ruleId": rule_id,
        "level": "error",
        "severity": severity,
        "message": {"text": f"{rule_id} happened"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": f"src/{rule_id}.py"}}}
        ],
    }
    if summarized_count is not None:
        finding["properties"] = {
            "summarized": True,
            "original_count": summarized_count,
        }
    return finding


def _ok(text="answer"):
    return {"output": {"message": {"role": "assistant", "content": [{"text": text}]}}}


def _validation_error(message):
    return botocore.exceptions.ClientError(
        {"Error": {"Code": "ValidationException", "Message": message}}, "Converse"
    )


# ---------------------------------------------------------------------------
# temperature and top_p cannot both be specified
# ---------------------------------------------------------------------------


def test_a_model_that_refuses_temperature_with_top_p_is_called_again_without_top_p():
    """Bedrock names the pair it refuses; the client drops the second-named
    parameter and retries, as it already did for a parameter named deprecated,
    so the call answers on this model instead of failing it."""
    runtime = MagicMock()
    runtime.converse.side_effect = [
        _validation_error(
            "The model returned the following errors: `temperature` and `top_p` "
            "cannot both be specified for this model. Please use only one."
        ),
        _ok("the answer"),
    ]
    client = BedrockModelClient(runtime, "anthropic.claude-next", 0.5, 100, 0.9)

    outcome = client.call("prompt", "system")

    assert outcome.ok is True and outcome.text == "the answer", outcome
    assert runtime.converse.call_count == 2
    first, second = (call.kwargs for call in runtime.converse.call_args_list)
    assert first["inferenceConfig"] == {
        "temperature": 0.5,
        "maxTokens": 100,
        "topP": 0.9,
    }
    assert second["inferenceConfig"] == {"temperature": 0.5, "maxTokens": 100}


def test_a_refusal_that_names_no_sent_parameter_is_not_retried():
    """The control: a pair the request does not carry cannot be repaired, so the
    refusal comes back as the failure it is, after one call."""
    runtime = MagicMock()
    runtime.converse.side_effect = _validation_error(
        "`alpha` and `beta` cannot both be specified for this model."
    )
    client = BedrockModelClient(runtime, "anthropic.claude-next", 0.5, 100, 0.9)

    outcome = client.call("prompt", "system")

    assert outcome.ok is False and "Validation error" in outcome.text, outcome
    assert runtime.converse.call_count == 1


def test_a_refused_pair_is_dropped_from_the_clients_later_calls(caplog):
    """The repair is paid once per client: the second call sends the request
    without the refused parameter from the start (three Converse requests for
    two calls, not four), and the repaired refusal is said at verbose, not as a
    "Bedrock API error" warning, because the call then answered."""
    runtime = MagicMock()
    runtime.converse.side_effect = [
        _validation_error(
            "`temperature` and `top_p` cannot both be specified for this model."
        ),
        _ok("first"),
        _ok("second"),
    ]
    client = BedrockModelClient(runtime, "anthropic.claude-next", 0.5, 100, 0.9)

    # Captured on the pipeline's own logger at VERBOSE, so the repair line is
    # seen to be there: an empty warning list then means the refusal was not
    # warned about, not that caplog received nothing.
    with caplog.at_level(VERBOSE_LEVEL, logger=ASH_LOGGER.name):
        first = client.call("prompt", "system")
        second = client.call("again", "system")

    assert (first.text, second.text) == ("first", "second"), (first, second)
    assert runtime.converse.call_count == 3
    third = runtime.converse.call_args_list[2].kwargs
    assert third["inferenceConfig"] == {"temperature": 0.5, "maxTokens": 100}
    repairs = [
        r.getMessage()
        for r in caplog.records
        if r.levelno == VERBOSE_LEVEL and "retrying without 'top_p'" in r.getMessage()
    ]
    assert len(repairs) == 1, [r.getMessage() for r in caplog.records]
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings == [], warnings


# ---------------------------------------------------------------------------
# max_findings_to_analyze governs the risk and compliance prompts too
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("asked", [2, 7])
def test_the_risk_assessment_carries_as_many_sample_findings_as_asked(asked):
    builder = BedrockPromptBuilder()
    findings = [_finding(f"RULE-{i}") for i in range(10)]

    prompt = builder.risk_assessment(findings, [], max_findings=asked)

    assert prompt.count("\nFINDING ") == asked, prompt


@pytest.mark.parametrize("asked", [2, 7])
def test_the_compliance_impact_carries_as_many_sample_findings_as_asked(asked):
    builder = BedrockPromptBuilder()
    findings = [_finding(f"RULE-{i}") for i in range(10)]

    prompt = builder.compliance_impact(findings, ["SOC 2"], None, max_findings=asked)

    assert prompt.count("\nFINDING ") == asked, prompt


# ---------------------------------------------------------------------------
# custom_context alone
# ---------------------------------------------------------------------------


def test_a_custom_context_configured_alone_reaches_the_model():
    builder = BedrockPromptBuilder()

    prompt = builder.prepare_prompt(
        "the message",
        custom_prompt=None,
        industry_context=None,
        compliance_frameworks=[],
        custom_context="PCI scope applies to the payments service.",
    )

    assert "ADDITIONAL CONTEXT:" in prompt, prompt
    assert "PCI scope applies to the payments service." in prompt, prompt


# ---------------------------------------------------------------------------
# A summarized finding counts for every instance it stands for
# ---------------------------------------------------------------------------


def test_totals_count_every_instance_a_summarized_finding_stands_for():
    """With summarize_findings on, the reporter hands the builders one finding
    per rule carrying original_count. The totals and severity counts the model
    is told are the instances, not the rule groups."""
    builder = BedrockPromptBuilder()
    findings = [
        _finding("RULE-A", "CRITICAL", summarized_count=4),
        _finding("RULE-B", "LOW"),
    ]

    executive = builder.executive_summary(findings, [], ["bandit"])
    legacy = builder.legacy_summary(findings, [], ["bandit"], max_findings=10)
    risk = builder.risk_assessment(findings, [])
    recommendations = builder.recommendations(findings, max_findings=10)

    assert "Total actionable findings: 5" in executive, executive
    assert "critical: 4, low: 1" in executive, executive
    assert "Total actionable findings: 5" in legacy, legacy
    assert "critical: 4, low: 1" in risk, risk
    assert "critical: 4, low: 1" in recommendations, recommendations


def test_a_plain_finding_still_counts_once():
    """The control: no original_count, no summarized flag, one each."""
    builder = BedrockPromptBuilder()
    findings = [_finding("RULE-A", "CRITICAL"), _finding("RULE-B", "CRITICAL")]

    executive = builder.executive_summary(findings, [], ["bandit"])

    assert "Total actionable findings: 2" in executive, executive
    assert "critical: 2" in executive, executive
