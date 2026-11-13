# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which failures walk to the next fallback model, one case per class.

A failure another model could answer (``bedrock_pipeline._MODEL_SPECIFIC_ERRORS``,
a read that timed out or a connection closed after the request reached the
service, an empty response) walks to the next model in the chain. A failure of
the credentials, the connection or the service comes back as it is: no model
switch fixes it. Each class is its own case, through the report path
(``_run_simple_report``), with botocore's own exception classes.
"""

from __future__ import annotations

import botocore.exceptions
import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins import bedrock_pipeline
from tests.unit.plugin_modules.ash_aws_plugins.bedrock_reporter_doubles import (
    FALLBACK_ONE,
    MODULE,
    PRIMARY_MODEL,
    ControlPlaneSessions,
    client_error,
    default_session_client,
    make_reporter,
    sarif_model,
)

pytestmark = pytest.mark.unit

URL = "https://bedrock-runtime.invalid/model/x/converse"
OK = {
    "output": {
        "message": {"role": "assistant", "content": [{"text": "fallback content"}]}
    }
}

#: Written out, not read from the module: a code dropped from the set must
#: fail these cells, not shrink them.
MODEL_SPECIFIC_CODES = [
    "AccessDeniedException",
    "ModelErrorException",
    "ModelNotReadyException",
    "ModelTimeoutException",
    "ResourceNotFoundException",
    "ThrottlingException",
    "TooManyRequestsException",
    "ValidationException",
]
OTHER_CODES = [
    "InternalServerException",
    "ServiceUnavailableException",
    "ExpiredTokenException",
    "UnrecognizedClientException",
    "InvalidSignatureException",
    "ModelStreamErrorException",
]
#: The codes above that a later try can pass: the model client's retries repeat
#: the call on the same model before the failure comes back as it is. The rest
#: of OTHER_CODES are asked once here because these answers are built without
#: an HTTP status; one sent with a 5xx status is retried whatever its code.
RETRIED_CODES = ["InternalServerException"]
AFTER_CONNECTING = ["ReadTimeoutError", "ConnectionClosedError"]
#: The classes in BEFORE_CONNECTING that the retry list reaches through the
#: botocore classes it names (ConnectionError, HTTPClientError): the model
#: client's retries repeat the call on the same model, as they do for
#: AFTER_CONNECTING. The credential classes are no connection failure and are
#: asked once.
RETRIED_BEFORE_CONNECTING = [
    "EndpointConnectionError",
    "ConnectTimeoutError",
    "ProxyConnectionError",
    "SSLError",
    "ConnectionError",
    "HTTPClientError",
    "ResponseStreamingError",
]
BEFORE_CONNECTING = [
    "EndpointConnectionError",
    "ConnectTimeoutError",
    "ProxyConnectionError",
    "SSLError",
    "ConnectionError",
    "HTTPClientError",
    "ResponseStreamingError",
    "NoCredentialsError",
    "PartialCredentialsError",
    "CredentialRetrievalError",
]
#: Every keyword the classes above format their messages with.
_KW = {
    "endpoint_url": URL,
    "proxy_url": URL,
    "error": "it failed",
    "provider": "p",
    "cred_var": "v",
    "error_msg": "m",
}


class _Runtime:
    """converse(): raises or answers per model, from ``plan`` (model -> an
    exception, a response dict, or a list of those taken in turn)."""

    def __init__(self, plan, default=OK):
        self.plan = plan
        self.default = default
        self.models: list = []
        self.calls: list = []

    def converse(self, **kwargs):
        model = kwargs["modelId"]
        self.models.append(model)
        self.calls.append(kwargs)
        step = self.plan.get(model, self.default)
        if isinstance(step, list):
            step = step.pop(0) if len(step) > 1 else step[0]
        if isinstance(step, BaseException):
            raise step
        return step


def _walk_setup(context, monkeypatch, **options):  # noqa: F811
    reporter = make_reporter(context, **options)
    monkeypatch.setattr(
        f"{MODULE}.get_fallback_model",
        lambda m: {PRIMARY_MODEL: FALLBACK_ONE}.get(m),
    )
    monkeypatch.setattr(
        f"{MODULE}.validate_bedrock_model",
        lambda client, model, values=(): (model == FALLBACK_ONE, "unavailable"),
    )
    monkeypatch.setattr(f"{MODULE}.boto3.Session", ControlPlaneSessions())
    monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)
    return reporter


def test_the_model_specific_codes_are_these_eight():
    assert sorted(bedrock_pipeline._MODEL_SPECIFIC_ERRORS) == MODEL_SPECIFIC_CODES


@pytest.mark.parametrize("code", MODEL_SPECIFIC_CODES)
def test_a_model_specific_code_walks_to_the_next_model(context, monkeypatch, code):  # noqa: F811
    # No retries: the two throttle codes are also RETRYABLE_EXCEPTIONS, so
    # with retries the configured model is repeated before the walk (the
    # retried shape is test_a_failure_after_connecting_walks_to_the_next_model's).
    reporter = _walk_setup(context, monkeypatch, max_retries=0)
    runtime = _Runtime({PRIMARY_MODEL: client_error(code, "it failed")})
    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])
    assert (out, runtime.models) == (
        "fallback content",
        [PRIMARY_MODEL, FALLBACK_ONE],
    )


@pytest.mark.parametrize("code", OTHER_CODES)
def test_another_code_comes_back_as_it_is(context, monkeypatch, code):  # noqa: F811
    # Two retries with no delay: a retried code is called three times in all.
    reporter = _walk_setup(
        context, monkeypatch, max_retries=2, base_delay=0.0, max_delay=0.0
    )
    runtime = _Runtime({PRIMARY_MODEL: client_error(code, "it failed")})
    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])
    calls = 3 if code in RETRIED_CODES else 1
    assert (out, runtime.models) == ("*Error: it failed*", [PRIMARY_MODEL] * calls)


@pytest.mark.parametrize("name", AFTER_CONNECTING)
def test_a_failure_after_connecting_walks_to_the_next_model(context, monkeypatch, name):  # noqa: F811
    # Two retries with no delay: the failure is repeated on the configured
    # model (three calls in all) before the walk moves on.
    reporter = _walk_setup(
        context, monkeypatch, max_retries=2, base_delay=0.0, max_delay=0.0
    )
    runtime = _Runtime({PRIMARY_MODEL: getattr(botocore.exceptions, name)(**_KW)})
    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])
    assert (out, runtime.models) == (
        "fallback content",
        [PRIMARY_MODEL] * 3 + [FALLBACK_ONE],
    )


@pytest.mark.parametrize("name", BEFORE_CONNECTING)
def test_another_client_side_failure_comes_back_as_it_is(context, monkeypatch, name):  # noqa: F811
    reporter = _walk_setup(
        context, monkeypatch, max_retries=2, base_delay=0.0, max_delay=0.0
    )
    error = getattr(botocore.exceptions, name)(**_KW)
    runtime = _Runtime({PRIMARY_MODEL: error})
    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])
    calls = 3 if name in RETRIED_BEFORE_CONNECTING else 1
    assert runtime.models == [PRIMARY_MODEL] * calls
    assert out == (
        f"*Error generating content with model {PRIMARY_MODEL}: {name}: {error}*"
    )


def test_no_installed_subclass_widens_the_after_connecting_classes():
    """The installed botocore defines no subclass of either class, so the walk
    takes those two failures and nothing else: a connect timeout is not one."""

    def subclasses(cls):
        found = set()
        for sub in cls.__subclasses__():
            found |= {sub} | subclasses(sub)
        return found

    widened = set()
    for cls in bedrock_pipeline._AFTER_CONNECTING:
        widened |= subclasses(cls)
    assert widened == set()
    assert not issubclass(
        botocore.exceptions.ConnectTimeoutError, bedrock_pipeline._AFTER_CONNECTING
    )


def test_an_empty_response_walks_to_the_next_model(context, monkeypatch):  # noqa: F811
    reporter = _walk_setup(context, monkeypatch)
    runtime = _Runtime({PRIMARY_MODEL: {"output": {"message": {"content": []}}}})
    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])
    assert (out, runtime.models) == (
        "fallback content",
        [PRIMARY_MODEL, FALLBACK_ONE],
    )


def test_every_parameter_refused_in_turn_walks_to_the_next_model(context, monkeypatch):  # noqa: F811
    """Each refusal that names a parameter sent drops it and retries, the last
    retry with none left; that one's refusal names nothing left to drop, so its
    validation error walks to the next model."""
    reporter = _walk_setup(context, monkeypatch)
    refusals = [
        client_error("ValidationException", f"`{name}` is deprecated")
        for name in ("temperature", "maxTokens", "topP")
    ]
    runtime = _Runtime({PRIMARY_MODEL: refusals + [refusals[-1]]})
    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])
    assert out == "fallback content", out
    assert runtime.models == [PRIMARY_MODEL] * 4 + [FALLBACK_ONE]
    # The fourth request carried no inference parameter at all.
    assert not runtime.calls[3].get("inferenceConfig"), runtime.calls[3]


def test_a_named_parameter_is_retried_without_walking(context, monkeypatch):  # noqa: F811
    reporter = _walk_setup(context, monkeypatch)
    runtime = _Runtime(
        {
            PRIMARY_MODEL: [
                client_error("ValidationException", "`temperature` is deprecated"),
                OK,
            ]
        }
    )
    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])
    assert (out, runtime.models) == ("fallback content", [PRIMARY_MODEL, PRIMARY_MODEL])
    assert "temperature" not in runtime.calls[1]["inferenceConfig"]


def test_an_answer_that_starts_like_an_error_is_the_answer(context, monkeypatch):  # noqa: F811
    reporter = _walk_setup(context, monkeypatch)
    answer = {
        "output": {"message": {"content": [{"text": "*Error handling is fine*"}]}}
    }
    runtime = _Runtime({PRIMARY_MODEL: answer})
    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])
    assert (out, runtime.models) == ("*Error handling is fine*", [PRIMARY_MODEL])
