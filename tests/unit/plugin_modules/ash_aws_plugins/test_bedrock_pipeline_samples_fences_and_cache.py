# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Which findings a prompt samples, how a snippet is fenced, and what the
report pipeline caches.

Each test here failed at the base. The builders cut their sample findings in
scan order, so a critical finding late in the scan was left out while low ones
went; ``recommendations`` sent a finding-less template for an empty list where
its siblings answered no prompt; a snippet holding a fence of its own closed
the prompt's fence early; and the report pipeline keyed its cache by section
name alone, replaying the earlier answer for a different prompt and a transient
failure's text alike, and never applied a section's ``max_tokens``.

No test here calls AWS: the runtime is a MagicMock that answers by plan.
"""

from unittest.mock import MagicMock

import botocore.exceptions
import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_pipeline import (
    BedrockModelClient,
    BedrockPromptBuilder,
    BedrockReportPipeline,
    ReportSection,
)

pytestmark = pytest.mark.unit


def _finding(rule_id, severity, snippet=None):
    region = {}
    if snippet is not None:
        region["snippet"] = {"text": snippet}
    return {
        "ruleId": rule_id,
        "level": "error",
        "severity": severity,
        "message": {"text": f"{rule_id} happened"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"src/{rule_id}.py"},
                    "region": region,
                }
            }
        ],
    }


#: Two low findings first in scan order, then the critical one.
SCAN_ORDER = [
    _finding("LOW-1", "LOW"),
    _finding("LOW-2", "LOW"),
    _finding("CRIT-1", "CRITICAL"),
]


def _ok(text="answer"):
    return {"output": {"message": {"role": "assistant", "content": [{"text": text}]}}}


def _throttle():
    return botocore.exceptions.ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "slow down"}}, "Converse"
    )


# ---------------------------------------------------------------------------
# A sample holds the most severe findings
# ---------------------------------------------------------------------------


def _sample(builder, name):
    if name == "technical_analysis":
        return builder.technical_analysis(SCAN_ORDER, 1, include_code_snippets=False)
    if name == "risk_assessment":
        return builder.risk_assessment(SCAN_ORDER, [], max_findings=1)
    if name == "compliance_impact":
        return builder.compliance_impact(SCAN_ORDER, ["SOC 2"], None, max_findings=1)
    if name == "recommendations":
        return builder.recommendations(SCAN_ORDER, max_findings=1)
    return builder.legacy_summary(SCAN_ORDER, [], ["bandit"], max_findings=1)


@pytest.mark.parametrize(
    "name",
    [
        "technical_analysis",
        "risk_assessment",
        "compliance_impact",
        "recommendations",
        "legacy_summary",
    ],
)
def test_a_sample_of_one_is_the_most_severe_finding(name):
    """With room for one sample finding the critical one goes, not the low
    one the scan reported first."""
    prompt = _sample(BedrockPromptBuilder(), name)

    assert prompt.count("\nFINDING ") == 1, prompt
    assert "CRIT-1" in prompt, prompt
    assert "LOW-1" not in prompt, prompt


def test_the_sort_is_stable_within_a_severity():
    """The control: two findings of one severity keep their scan order, so a
    sample of two from the same severity is the first two."""
    builder = BedrockPromptBuilder()

    ordered = builder.most_severe_first(SCAN_ORDER)

    assert [f["ruleId"] for f in ordered] == ["CRIT-1", "LOW-1", "LOW-2"]


# ---------------------------------------------------------------------------
# An empty list is no prompt
# ---------------------------------------------------------------------------


def test_recommendations_for_no_findings_is_no_prompt():
    """Its siblings already answered no prompt for nothing to analyze; the
    recommendations builder sent a finding-less template to the model."""
    assert BedrockPromptBuilder().recommendations([], max_findings=10) == ""


def test_recommendations_for_findings_is_a_prompt():
    """The control."""
    prompt = BedrockPromptBuilder().recommendations(SCAN_ORDER, max_findings=10)

    assert prompt.count("\nFINDING ") == 3, prompt


# ---------------------------------------------------------------------------
# A snippet that holds a fence stays fenced
# ---------------------------------------------------------------------------


def test_a_snippet_holding_a_fence_is_fenced_with_a_longer_one():
    """A three-backtick line inside the snippet would close a three-backtick
    fence; the prompt's fence is one backtick longer than the snippet's."""
    snippet = "print('a')\n```\nprint('b')"
    prompt = BedrockPromptBuilder().technical_analysis(
        [_finding("R1", "HIGH", snippet=snippet)], 5, include_code_snippets=True
    )

    assert f"- Code Snippet:\n````\n{snippet}\n````\n" in prompt, prompt


def test_a_snippet_with_no_fence_keeps_the_three_backtick_fence():
    """The control."""
    prompt = BedrockPromptBuilder().technical_analysis(
        [_finding("R1", "HIGH", snippet="print('a')")], 5, include_code_snippets=True
    )

    assert "- Code Snippet:\n```\nprint('a')\n```\n" in prompt, prompt


# ---------------------------------------------------------------------------
# The report pipeline's cache
# ---------------------------------------------------------------------------


def _pipeline(runtime, sections, cache, enable_caching=True):
    client = BedrockModelClient(runtime, "test-vendor.test-model-v1:0", 0.5, 100, 0.9)
    builder = BedrockPromptBuilder()
    return BedrockReportPipeline(client, builder, sections, cache, enable_caching)


def test_a_different_prompt_for_the_same_section_is_generated():
    """The cache is keyed by the prompt sent as well as the section, so a
    second run with another prompt is not served the first run's answer."""
    runtime = MagicMock()
    runtime.converse.side_effect = [_ok("first"), _ok("second")]
    section = ReportSection(title="A", cache_key="a", system_prompt="sys")
    pipeline = _pipeline(runtime, [section], {})

    first = pipeline.run({"a": "prompt one"})
    second = pipeline.run({"a": "prompt two"})

    assert first == {"a": "first"} and second == {"a": "second"}, (first, second)
    assert runtime.converse.call_count == 2


def test_the_same_prompt_is_served_from_the_cache():
    """The control."""
    runtime = MagicMock()
    runtime.converse.side_effect = [_ok("first"), _ok("second")]
    section = ReportSection(title="A", cache_key="a", system_prompt="sys")
    pipeline = _pipeline(runtime, [section], {})

    first = pipeline.run({"a": "prompt one"})
    second = pipeline.run({"a": "prompt one"})

    assert first == second == {"a": "first"}, (first, second)
    assert runtime.converse.call_count == 1


def test_a_failed_call_is_not_cached():
    """A throttled call's "*Error ...*" text is this run's section content and
    is asked again on the next run, not replayed as the answer."""
    runtime = MagicMock()
    runtime.converse.side_effect = [_throttle(), _ok("recovered")]
    section = ReportSection(title="A", cache_key="a", system_prompt="sys")
    pipeline = _pipeline(runtime, [section], {})

    first = pipeline.run({"a": "prompt"})
    second = pipeline.run({"a": "prompt"})

    assert first["a"].startswith("*Error"), first
    assert second == {"a": "recovered"}, second


def test_a_sections_max_tokens_bounds_its_call():
    """A section with a limit of its own is generated under it, not the
    client's global limit."""
    runtime = MagicMock()
    runtime.converse.return_value = _ok()
    sections = [
        ReportSection(title="A", cache_key="a", system_prompt="sys", max_tokens=50),
        ReportSection(title="B", cache_key="b", system_prompt="sys"),
    ]
    pipeline = _pipeline(runtime, sections, {}, enable_caching=False)

    pipeline.run({"a": "pa", "b": "pb"})

    first, second = (call.kwargs for call in runtime.converse.call_args_list)
    assert first["inferenceConfig"]["maxTokens"] == 50, first
    assert second["inferenceConfig"]["maxTokens"] == 100, second
