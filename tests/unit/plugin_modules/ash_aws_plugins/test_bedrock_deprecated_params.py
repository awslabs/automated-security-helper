# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Newer Anthropic models reject inference parameters that older ones require.

Why this file exists
--------------------
Configuring a recent model made the reporter fall back to Nova Pro, which
defeats the point of naming a model. Bedrock rejected the request:

    ValidationException: The model returned the following errors:
    `temperature` is deprecated for this model.

and once temperature was removed by hand, the next call failed the same way on
``top_k``. BedrockModelClient sent both unconditionally: temperature in
inferenceConfig, and top_k in additionalModelRequestFields for any model id
containing "claude".

Why strip-and-retry rather than a model table
---------------------------------------------
The obvious alternative is a lookup of which models deprecate which parameters.
That table is wrong the day a model ships, and the failure it produces is the one
already reported: a silent fallback to a different model. Bedrock names the
offending parameter in the error, so the request can be repaired from the
response instead of from a list somebody has to maintain.

That also means a parameter deprecated in future needs no code change here.

What is deliberately not retried
--------------------------------
Only ValidationExceptions that name a deprecated parameter. Access denied, model
not found and throttling are unchanged, and a ValidationException about anything
else still returns immediately rather than retrying a request that cannot
succeed.
"""

import botocore.exceptions
import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_pipeline import (
    BedrockModelClient,
)


def _validation_error(message: str) -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError(
        {"Error": {"Code": "ValidationException", "Message": message}},
        "Converse",
    )


def _deprecated(param: str) -> botocore.exceptions.ClientError:
    """The wording Bedrock actually returns, quoted from the issue."""
    return _validation_error(
        f"The model returned the following errors: `{param}` is deprecated for this model."
    )


def _ok_response(text: str = "summary text"):
    return {"output": {"message": {"content": [{"text": text}]}}}


class _FakeRuntime:
    """Rejects named parameters the way Bedrock does, then succeeds."""

    def __init__(self, reject: list[str]):
        self._reject = list(reject)
        self.calls: list[dict] = []

    def converse(self, **kwargs):
        self.calls.append(
            {
                "inferenceConfig": dict(kwargs.get("inferenceConfig") or {}),
                "additionalModelRequestFields": dict(
                    kwargs.get("additionalModelRequestFields") or {}
                ),
            }
        )
        sent = {
            **(kwargs.get("inferenceConfig") or {}),
            **(kwargs.get("additionalModelRequestFields") or {}),
        }
        normalized = {k.replace("_", "").lower() for k in sent}
        for param in self._reject:
            if param.replace("_", "").lower() in normalized:
                raise _deprecated(param)
        return _ok_response()


def _client(runtime, model_id="global.anthropic.claude-opus-4-7"):
    return BedrockModelClient(
        bedrock_runtime=runtime,
        model_id=model_id,
        temperature=0.5,
        max_tokens=4096,
        top_p=0.9,
    )


class TestDeprecatedParametersAreDropped:
    def test_temperature_is_dropped_and_the_call_succeeds(self):
        runtime = _FakeRuntime(reject=["temperature"])

        result = _client(runtime).try_call("prompt", "system")

        assert result == "summary text"
        assert "temperature" in runtime.calls[0]["inferenceConfig"]
        assert "temperature" not in runtime.calls[-1]["inferenceConfig"]

    def test_both_reported_parameters_are_dropped_in_turn(self):
        """The reported sequence: temperature first, then top_k on the next call."""
        runtime = _FakeRuntime(reject=["temperature", "top_k"])

        result = _client(runtime).try_call("prompt", "system")

        assert result == "summary text"
        final = runtime.calls[-1]
        assert "temperature" not in final["inferenceConfig"]
        assert "top_k" not in final["additionalModelRequestFields"]
        # One call per rejection, plus the one that succeeds.
        assert len(runtime.calls) == 3

    def test_surviving_parameters_are_kept(self):
        """Only what Bedrock objected to is removed.

        Stripping the whole inferenceConfig would work around the error while
        silently discarding maxTokens, which changes the output rather than
        fixing the request.
        """
        runtime = _FakeRuntime(reject=["temperature"])

        _client(runtime).try_call("prompt", "system")

        final = runtime.calls[-1]["inferenceConfig"]
        assert final.get("maxTokens") == 4096
        assert final.get("topP") == 0.9

    def test_underscore_and_camel_spellings_both_match(self):
        """Bedrock names top_k with an underscore and topP in camelCase.

        A literal key comparison would fail to find one of them, and the retry
        would resend the same request until the bound gave up.
        """
        runtime = _FakeRuntime(reject=["top_p"])

        result = _client(runtime).try_call("prompt", "system")

        assert result == "summary text"
        assert "topP" not in runtime.calls[-1]["inferenceConfig"]


class TestOtherErrorsAreUnchanged:
    @pytest.mark.parametrize(
        "code,expected",
        [
            ("AccessDeniedException", "Access denied"),
            ("ResourceNotFoundException", "not found"),
            ("ThrottlingException", "Rate limit exceeded"),
        ],
    )
    def test_non_validation_errors_return_immediately(self, code, expected):
        class _Runtime:
            calls = 0

            def converse(self, **kwargs):
                type(self).calls += 1
                raise botocore.exceptions.ClientError(
                    {"Error": {"Code": code, "Message": "nope"}}, "Converse"
                )

        runtime = _Runtime()
        result = _client(runtime).try_call("prompt", "system")

        assert expected in result
        assert _Runtime.calls == 1

    def test_unrelated_validation_error_is_not_retried(self):
        """Retrying a request that cannot succeed just multiplies the latency."""

        class _Runtime:
            calls = 0

            def converse(self, **kwargs):
                type(self).calls += 1
                raise _validation_error("Input is too long for requested model.")

        runtime = _Runtime()
        result = _client(runtime).try_call("prompt", "system")

        assert "Validation error" in result
        assert _Runtime.calls == 1

    def test_retry_is_bounded_when_stripping_never_helps(self):
        """A model that keeps naming a parameter already gone must not loop.

        Guards the retry loop itself: if the strip cannot find the named key, the
        next request is byte-identical and would fail the same way forever.
        """

        class _Runtime:
            calls = 0

            def converse(self, **kwargs):
                type(self).calls += 1
                raise _deprecated("somethingNotSent")

        runtime = _Runtime()
        result = _client(runtime).try_call("prompt", "system")

        assert "Error" in result
        assert _Runtime.calls == 1
