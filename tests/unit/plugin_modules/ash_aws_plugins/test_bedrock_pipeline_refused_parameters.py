# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which inference parameter the model client drops, and for how long.

* A model that takes ``temperature`` or ``top_p`` but not both names the pair in
  its refusal. The client keeps the operator's temperature and drops ``top_p``
  whichever way the message orders the two.
* A parameter a model refused is left out of every later request to that model
  from any client derived from the one that saw the refusal (a fallback model's
  client, a client for a section with a token limit of its own), so the refusal
  and its retry are paid once per model and not once per report section. A
  parameter one model refused is still sent to another.

No test here calls AWS: the runtime is a MagicMock that answers by plan.
"""

from unittest.mock import MagicMock

import botocore.exceptions
import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_pipeline import (
    BedrockModelClient,
)

pytestmark = pytest.mark.unit

MODEL_A = "test-vendor.model-a-v1:0"
MODEL_B = "test-vendor.model-b-v1:0"
MODEL_C = "test-vendor.model-c-v1:0"

BOTH = {"temperature": 0.5, "maxTokens": 100, "topP": 0.9}
WITHOUT_TOP_P = {"temperature": 0.5, "maxTokens": 100}


def _ok(text="answer"):
    return {"output": {"message": {"role": "assistant", "content": [{"text": text}]}}}


def _refusal(message):
    return botocore.exceptions.ClientError(
        {"Error": {"Code": "ValidationException", "Message": message}}, "Converse"
    )


#: The pair, in the two orders a model may name it.
TEMPERATURE_FIRST = (
    "The model returned the following errors: `temperature` and `top_p` cannot "
    "both be specified for this model. Please use only one."
)
TOP_P_FIRST = (
    "The model returned the following errors: `top_p` and `temperature` cannot "
    "both be specified for this model. Please use only one."
)


def _client(runtime, model_id=MODEL_A):
    return BedrockModelClient(runtime, model_id, 0.5, 100, 0.9)


@pytest.mark.parametrize(
    "message",
    [TEMPERATURE_FIRST, TOP_P_FIRST],
    ids=["temperature-first", "top_p-first"],
)
def test_top_p_is_dropped_whichever_order_the_refusal_names_the_pair(message):
    """The reversed wording used to drop the operator's temperature and keep
    top_p."""
    runtime = MagicMock()
    runtime.converse.side_effect = [_refusal(message), _ok("the answer")]

    outcome = _client(runtime).call("prompt", "system")

    assert outcome.ok is True and outcome.text == "the answer", outcome
    first, second = (call.kwargs for call in runtime.converse.call_args_list)
    assert first["inferenceConfig"] == BOTH
    assert second["inferenceConfig"] == WITHOUT_TOP_P


def test_a_pair_that_does_not_hold_top_p_drops_the_second_named():
    """The control: another pair keeps the first-named parameter, as before."""
    runtime = MagicMock()
    runtime.converse.side_effect = [
        _refusal("`temperature` and `maxTokens` cannot both be specified."),
        _ok(),
    ]

    outcome = _client(runtime).call("prompt", "system")

    assert outcome.ok is True, outcome
    second = runtime.converse.call_args_list[1].kwargs
    assert second["inferenceConfig"] == {"temperature": 0.5, "topP": 0.9}


def test_a_fallback_models_client_keeps_what_the_model_refused():
    """The walk calls a fallback through ``with_model`` for every report
    section; the second section's request leaves the refused parameter out from
    the start, and a different model is still sent it."""
    runtime = MagicMock()
    runtime.converse.side_effect = [
        _refusal(TEMPERATURE_FIRST),
        _ok("first"),
        _ok("second"),
        _ok("third"),
    ]
    root = _client(runtime)

    first = root.with_model(MODEL_B).call("one", "system")
    second = root.with_model(MODEL_B).call("two", "system")
    third = root.with_model(MODEL_C).call("three", "system")

    assert [o.text for o in (first, second, third)] == ["first", "second", "third"]
    calls = [call.kwargs for call in runtime.converse.call_args_list]
    assert len(calls) == 4, calls
    assert calls[2]["modelId"] == MODEL_B
    assert calls[2]["inferenceConfig"] == WITHOUT_TOP_P
    # The control: the refusal was about MODEL_B, not about the parameter.
    assert calls[3]["modelId"] == MODEL_C
    assert calls[3]["inferenceConfig"] == BOTH


def test_a_client_for_a_section_with_a_token_limit_keeps_what_the_model_refused():
    runtime = MagicMock()
    runtime.converse.side_effect = [
        _refusal(TEMPERATURE_FIRST),
        _ok("first"),
        _ok("second"),
    ]
    root = _client(runtime)

    root.call("one", "system")
    root.with_max_tokens(50).call("two", "system")

    third = runtime.converse.call_args_list[2].kwargs
    assert third["inferenceConfig"] == {"temperature": 0.5, "maxTokens": 50}
