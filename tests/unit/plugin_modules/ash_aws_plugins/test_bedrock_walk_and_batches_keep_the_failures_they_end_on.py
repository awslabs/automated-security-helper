# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""What the Bedrock walk and the batch path say when they end on a failure.

* The fallback walk ends early on a failure no other model answers (no
  credentials, no connection). Its text used to be that failure alone, so an
  operator whose configured model was denied and whose fallback then lost its
  connection saw only the connection error; the exhaustion text keeps the
  configured model's error, and the early return now does too. A resumed walk
  keeps the run's fallback model's error as well.
* When every batch of a large scan fails, the section is the first failure's
  text, each batch was called once, and no synthesis is asked for.

No test here calls AWS: the model runtime answers by plan and the control
plane is a MagicMock.
"""

import json
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_pipeline import (
    CallOutcome,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
)
from tests.unit.plugin_modules.ash_aws_plugins.bedrock_reporter_doubles import (
    FALLBACK_ONE,
    FALLBACK_TWO,
    MODULE,
    PRIMARY_MODEL,
    make_reporter,
    plugin_context_in,
)

pytestmark = pytest.mark.unit

NO_CONNECTION = (
    "*Error generating content with model x: EndpointConnectionError: no route*"
)


class Runtime:
    """A bedrock-runtime client: converse() answers ``plan`` in order (a text or
    an exception) and records every request."""

    def __init__(self, *plan):
        self.plan = list(plan)
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        step = self.plan.pop(0) if self.plan else "answer"
        if isinstance(step, BaseException):
            raise step
        return {
            "output": {"message": {"role": "assistant", "content": [{"text": step}]}}
        }


def _chain(monkeypatch):
    monkeypatch.setattr(
        f"{MODULE}.get_fallback_model",
        {PRIMARY_MODEL: FALLBACK_ONE, FALLBACK_ONE: FALLBACK_TWO}.get,
    )
    monkeypatch.setattr(
        f"{MODULE}.validate_bedrock_model", lambda *a, **k: (True, None)
    )


def _no_connection(called):
    def call_model(model):
        called.append(model)
        return CallOutcome(NO_CONNECTION, ok=False, model_specific=False)

    return call_model


def test_the_early_return_keeps_the_configured_models_error(tmp_path, monkeypatch):
    reporter = make_reporter(plugin_context_in(tmp_path), enable_caching=False)
    _chain(monkeypatch)
    called = []

    out = reporter._walk_fallbacks(
        MagicMock(),
        PRIMARY_MODEL,
        _no_connection(called),
        primary_error="*Error: AccessDeniedException: configured model denied*",
    )

    assert called == [FALLBACK_ONE], called
    assert "EndpointConnectionError" in out, out
    assert "AccessDeniedException: configured model denied" in out, out
    assert "configured model's error" in out, out
    assert "No suitable fallback model found" not in out, out
    assert out.startswith("*") and out.endswith("*"), out


def test_the_early_return_of_a_resumed_walk_keeps_both_earlier_errors(
    tmp_path, monkeypatch
):
    reporter = make_reporter(plugin_context_in(tmp_path), enable_caching=False)
    _chain(monkeypatch)
    called = []

    out = reporter._walk_fallbacks(
        MagicMock(),
        PRIMARY_MODEL,
        _no_connection(called),
        primary_error="*Error: AccessDeniedException: configured model denied*",
        resume_after=FALLBACK_ONE,
        resume_error="*Error: ThrottlingException: run model throttled*",
    )

    assert called == [FALLBACK_TWO], called
    assert "EndpointConnectionError" in out, out
    assert "configured model denied" in out, out
    assert f"The run's fallback model {FALLBACK_ONE} then failed" in out, out
    assert "run model throttled" in out, out


def test_with_no_earlier_error_the_early_return_is_the_failure_as_it_was(
    tmp_path, monkeypatch
):
    """The control: nothing is added when no earlier error is known."""
    reporter = make_reporter(plugin_context_in(tmp_path), enable_caching=False)
    _chain(monkeypatch)

    out = reporter._walk_fallbacks(
        MagicMock(), PRIMARY_MODEL, _no_connection([]), primary_error=None
    )

    assert out == NO_CONNECTION


def test_the_added_text_is_redacted_like_the_rest(tmp_path, monkeypatch):
    reporter = make_reporter(plugin_context_in(tmp_path), enable_caching=False)
    _chain(monkeypatch)
    monkeypatch.setattr(
        BedrockSummaryReporter,
        "_redaction_values",
        lambda self: ("canary-value-1",),
    )

    out = reporter._walk_fallbacks(
        MagicMock(),
        PRIMARY_MODEL,
        _no_connection([]),
        primary_error="*Error: AccessDeniedException: canary-value-1 was denied*",
    )

    assert "canary-value-1" not in out, out
    assert "AccessDeniedException" in out, out


def _instance(rule_id, uri):
    return {
        "ruleId": rule_id,
        "level": "error",
        "severity": "HIGH",
        "message": {"text": f"{rule_id} happened"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
    }


def test_when_every_batch_fails_the_section_is_the_first_failure(tmp_path):
    reporter = make_reporter(
        plugin_context_in(tmp_path),
        batch_processing=True,
        max_findings_to_analyze=1,
        enable_fallback_models=False,
        enable_caching=False,
    )
    runtime = Runtime(
        botocore.exceptions.ClientError(
            {"Error": {"Code": "ValidationException", "Message": "batch one refused"}},
            "Converse",
        ),
        botocore.exceptions.ClientError(
            {"Error": {"Code": "ValidationException", "Message": "batch two refused"}},
            "Converse",
        ),
    )
    findings = [_instance("R1", "src/a.py"), _instance("R2", "src/b.py")]

    out = reporter._process_findings_by_batch(runtime, None, findings)

    # One call per batch, and no synthesis request after them.
    assert len(runtime.calls) == 2, runtime.calls
    for call in runtime.calls:
        assert "Synthesize the following" not in json.dumps(call, default=str)
    assert "batch one refused" in out, out
    assert "batch two refused" not in out, out
