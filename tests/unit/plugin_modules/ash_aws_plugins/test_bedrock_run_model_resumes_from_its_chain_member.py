# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A walk resumed after the run's model failed continues from the chain.

The fallback walk calls a chain member by the spelling the listing gives it,
which can differ from the chain's (a region's geography, a different case), and
that spelling is the run's model from then on. When the run's model fails in
turn, the walk resumes after it. It used to ask for the model after the
listing's spelling, which the chain does not hold, so a double that answers from
the chain gave up with candidates left, and the real function could start the
chain again. The walk now resumes from the chain member the run's model was
called for.

No test here calls AWS: the control plane and the runtime are doubles.
"""

from unittest.mock import MagicMock

import botocore.exceptions
import pytest

from tests.unit.plugin_modules.ash_aws_plugins.bedrock_reporter_doubles import (
    FALLBACK_ONE,
    FALLBACK_TWO,
    MODULE,
    PRIMARY_MODEL,
    make_reporter,
    plugin_context_in,
)

pytestmark = pytest.mark.unit

#: FALLBACK_ONE as the listing spells it: the check matches it case-insensitively
#: and the run calls the listing's spelling.
LISTED_ONE = "Test-Vendor.test-model-fallback-1-v1:0"


def _denied():
    return botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "Converse"
    )


def _summary(model_id):
    return {
        "modelId": model_id,
        "modelName": "placeholder",
        "modelArn": f"arn:test:model/{model_id}",
        "providerName": "placeholder",
        "modelLifecycle": {"status": "ACTIVE"},
        "inputModalities": ["TEXT"],
        "outputModalities": ["TEXT"],
        "inferenceTypesSupported": ["ON_DEMAND"],
    }


def _control_plane():
    control = MagicMock()
    control.list_inference_profiles.return_value = {"inferenceProfileSummaries": []}
    control.list_foundation_models.return_value = {
        "modelSummaries": [_summary(LISTED_ONE), _summary(FALLBACK_TWO)]
    }
    return control


class _Runtime:
    """A bedrock-runtime double: each model answers from its list of steps, an
    exception to raise or None to answer; a model with no steps left answers."""

    def __init__(self, plan):
        self.plan = {model: list(steps) for model, steps in plan.items()}
        self.models = []

    def converse(self, **kwargs):
        model = kwargs["modelId"]
        self.models.append(model)
        steps = self.plan.get(model, [])
        step = steps.pop(0) if steps else None
        if isinstance(step, BaseException):
            raise step
        return {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": f"answer from {model}"}],
                }
            }
        }


def test_a_walk_resumed_after_the_run_model_failed_goes_on_from_its_chain_member(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        f"{MODULE}.get_fallback_model",
        {PRIMARY_MODEL: FALLBACK_ONE, FALLBACK_ONE: FALLBACK_TWO}.get,
    )
    reporter = make_reporter(plugin_context_in(tmp_path), enable_caching=False)
    reporter._control_client = _control_plane()
    runtime = _Runtime({PRIMARY_MODEL: [_denied()], LISTED_ONE: [None, _denied()]})
    client = reporter._make_model_client(runtime)

    first = reporter._outcome_with_fallback(client, "one", "system")
    second = reporter._outcome_with_fallback(client, "two", "system")

    assert first.ok and first.text == f"answer from {LISTED_ONE}", first
    assert second.ok and second.text == f"answer from {FALLBACK_TWO}", second
    # The listing's spelling was called twice (the second call is the run's
    # model failing in turn) and never again; the chain went on to its next
    # member.
    assert runtime.models == [PRIMARY_MODEL, LISTED_ONE, LISTED_ONE, FALLBACK_TWO]
    assert reporter._run_model == FALLBACK_TWO
    assert reporter._run_model_member == FALLBACK_TWO
