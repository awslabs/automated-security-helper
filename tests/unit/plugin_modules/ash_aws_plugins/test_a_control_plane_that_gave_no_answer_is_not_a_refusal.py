# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What a refusal from the Bedrock control plane means.

``validate_bedrock_model`` answers False both for a model the listing does not
name and, because ``get_available_models`` turns a throttled or failed listing
into an empty list, for a control plane that gave no usable answer. The first
is about the model. The second says nothing about it, so the fallback walk names
that model as not checked, not as unavailable. The kind is data on the answer
(``ModelCheck.transient``, ``AvailableModels.failed``), set where the check
knows it and never read back from the reason, which a caller redacts and a
maintainer rewords.

No cell calls AWS: the control plane is a recorded double that throttles or
lists by plan, the real ``validate_bedrock_model`` reads it, and the model
runtime is a double.
"""

import copy
import pickle  # nosec B403

import botocore.config
import botocore.exceptions
import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins import aws_utils
from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
    ListingsOnce,
    check_is_transient,
    validate_bedrock_model,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_pipeline import (
    BedrockModelClient,
)
from tests.unit.plugin_modules.ash_aws_plugins.bedrock_reporter_doubles import (
    FALLBACK_ONE,
    FALLBACK_TWO,
    MODULE,
    PRIMARY_MODEL,
    client_error,
    default_session_client,
    make_reporter,
    sarif_model,
)

pytestmark = pytest.mark.unit

OK = {
    "output": {
        "message": {"role": "assistant", "content": [{"text": "fallback content"}]}
    }
}


def _error(code, message="it failed", operation="ListInferenceProfiles"):
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": message}}, operation
    )


class ControlPlane:
    """A bedrock control-plane client: both listings are throttled while
    ``throttled`` is set (or for its first ``throttle_first`` profile listings),
    refuse with ``listing_error`` when that is set, raise ``error`` when one is
    given, and the model listing names ``listed`` otherwise. A control plane
    that throttles or refuses one listing does so for the other, and
    ``get_available_models`` asks the two apart (a failed profile listing alone
    leaves the on-demand models listed), so a failure here is the whole
    listing's. ``profile_error`` is the one exception: it refuses the profile
    listing ALONE, with that code, while the model listing answers, which is
    the shape a caller allowed ListFoundationModels but not
    ListInferenceProfiles sees. ``listings`` counts the profile listings and
    ``model_listings`` the model listings: the control-plane calls a walk
    makes."""

    def __init__(
        self,
        listed,
        throttled=False,
        listing_error=None,
        throttle_first=0,
        error=None,
        profile_error=None,
        profile_only=(),
    ):
        self.listed = list(listed)
        self.profile_only = list(profile_only)
        self.throttled = throttled
        self.listing_error = listing_error
        self.throttle_first = throttle_first
        self.error = error
        self.profile_error = profile_error
        self.listings = 0
        self.model_listings = 0

    def _failure(self, operation):
        """The failure both listings share, or None when they answer, built for
        the *operation* that is failing (a new error per call, naming the call
        that was made, as botocore's does); ``error`` is the one instance a
        caller gave, raised as it is.

        ``throttle_first`` counts profile listings, so a model listing made
        before any (the dependency check's reachability probe) is not throttled
        by it; one made alongside the k-th profile listing shares its fate."""
        if self.throttled or 0 < self.listings <= self.throttle_first:
            return _error("ThrottlingException", "Rate exceeded", operation)
        if self.listing_error is not None:
            return _error(self.listing_error, "the listing was refused", operation)
        return self.error

    def list_inference_profiles(self):
        self.listings += 1
        failure = self._failure("ListInferenceProfiles")
        if failure is not None:
            raise failure
        if self.profile_error is not None:
            raise _error(self.profile_error, "the listing was refused")
        return {"inferenceProfileSummaries": []}

    def list_foundation_models(self):
        self.model_listings += 1
        failure = self._failure("ListFoundationModels")
        if failure is not None:
            raise failure
        return {
            "modelSummaries": [
                {
                    "modelId": model,
                    "modelName": "placeholder",
                    "modelArn": f"placeholder-arn-{model}",
                    "providerName": "placeholder",
                    "modelLifecycle": {"status": "ACTIVE"},
                    "inputModalities": ["TEXT"],
                    "outputModalities": ["TEXT"],
                    "inferenceTypesSupported": ["ON_DEMAND"],
                }
                for model in self.listed
            ]
            # A model only an inference profile routes: the foundation-model
            # listing names it, and no profile listing is needed to know a
            # profile could carry it.
            + [
                {
                    "modelId": model,
                    "modelName": "placeholder",
                    "modelArn": f"placeholder-arn-{model}",
                    "providerName": "placeholder",
                    "modelLifecycle": {"status": "ACTIVE"},
                    "inputModalities": ["TEXT"],
                    "outputModalities": ["TEXT"],
                    "inferenceTypesSupported": ["INFERENCE_PROFILE"],
                }
                for model in self.profile_only
            ]
        }


class Runtime:
    """converse() raises or answers per model, from ``plan`` (model -> an
    exception or a response); a model the plan does not name answers OK."""

    def __init__(self, plan):
        self.plan = plan
        self.models: list = []

    def converse(self, **kwargs):
        model = kwargs["modelId"]
        self.models.append(model)
        step = self.plan.get(model, OK)
        if isinstance(step, BaseException):
            raise step
        return step


class Sessions:
    """A boto3.Session stand-in whose control-plane ("bedrock") client is the
    one given. No other client is built from a session."""

    def __init__(self, control_plane):
        self.control_plane = control_plane

    def __call__(self, **kwargs):
        return self

    def client(self, service, **kwargs):
        assert service == "bedrock", service
        return self.control_plane


def _walk_setup(context, monkeypatch, control_plane, links):  # noqa: F811
    """A reporter whose fallback chain is ``links`` (model -> its fallback) and
    whose control plane is the double; the real ``validate_bedrock_model``
    reads it. Caching is off: the report path caches the exhaustion text it
    returns, so a second call would not walk again."""
    reporter = make_reporter(context, enable_caching=False)
    monkeypatch.setattr(f"{MODULE}.get_fallback_model", links.get)
    monkeypatch.setattr(f"{MODULE}.boto3.Session", Sessions(control_plane))
    monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)
    return reporter


def _exhausted_text(unavailable=None, not_checked=None):
    groups = [f"called: {PRIMARY_MODEL}"]
    if unavailable:
        groups.append(f"unavailable: {unavailable}")
    if not_checked:
        groups.append(f"not checked: {not_checked}")
    return (
        f"*Error: No suitable fallback model found for {PRIMARY_MODEL} "
        f"({'; '.join(groups)})"
    )


def test_a_throttled_listing_is_a_refusal_that_says_nothing_about_the_model():
    """A throttled listing and a listing without the model both come back False.
    The check says which is which as data on its answer, not in its reason."""
    throttled = validate_bedrock_model(
        ControlPlane([FALLBACK_ONE], throttled=True), FALLBACK_ONE
    )
    not_listed = validate_bedrock_model(ControlPlane([PRIMARY_MODEL]), FALLBACK_ONE)
    listed = validate_bedrock_model(ControlPlane([FALLBACK_ONE]), FALLBACK_ONE)

    assert (throttled[0], not_listed[0], listed[0]) == (False, False, True)
    assert check_is_transient(throttled), throttled
    assert not check_is_transient(not_listed), not_listed
    assert listed[1] is None
    assert not check_is_transient(listed)


def test_an_answer_without_a_kind_is_about_the_model_whatever_its_reason_says():
    """The kind is never read from the reason: a pair a caller built, whose
    reason is worded like a control-plane blip, is a refusal about the model."""
    assert not check_is_transient(
        (False, "No available models found in the current region")
    )
    assert not check_is_transient(
        (False, "Error validating model " + FALLBACK_ONE + ": it failed")
    )
    assert not check_is_transient(None)


def test_a_failed_listing_is_told_apart_from_a_region_with_no_models():
    """Both lists are empty. Only the listing that failed is flagged, and only
    its refusal is transient: a region the control plane lists no model in is
    about the model."""
    throttled_models = aws_utils.get_available_models(
        ControlPlane([FALLBACK_ONE], throttled=True)
    )
    empty_models = aws_utils.get_available_models(ControlPlane([]))
    listed_models = aws_utils.get_available_models(ControlPlane([FALLBACK_ONE]))

    assert isinstance(throttled_models, list)
    assert throttled_models == [] and empty_models == []
    assert throttled_models.failed is True
    assert empty_models.failed is False
    assert listed_models.failed is False and len(listed_models) == 1
    assert check_is_transient(
        validate_bedrock_model(
            ControlPlane([FALLBACK_ONE], throttled=True), FALLBACK_ONE
        )
    )
    assert not check_is_transient(
        validate_bedrock_model(ControlPlane([]), FALLBACK_ONE)
    )


def test_a_check_that_failed_is_transient_after_its_reason_is_redacted(monkeypatch):
    """The reason of a failed check is redacted with the caller's values. A
    value equal to the words the reason starts with takes them out of it; the
    refusal stays transient, because the kind is not read from the reason."""

    def _fails(client, values=()):
        raise _error("InternalServerException")

    monkeypatch.setattr(aws_utils, "get_available_models", _fails)
    value = "Error validating model"

    check = validate_bedrock_model(object(), FALLBACK_ONE, values=[value])

    assert check[0] is False
    assert value not in check[1], check[1]
    assert check_is_transient(check), check


def test_a_check_that_raised_something_unexpected_is_not_transient(monkeypatch):
    """An error that is not a throttle, a service fault or a connection failure
    is not one a later check is known to pass, so it is reported with its error
    and the model is not named as not checked."""

    def _fails(client, values=()):
        raise RuntimeError("it failed")

    monkeypatch.setattr(aws_utils, "get_available_models", _fails)

    check = validate_bedrock_model(object(), FALLBACK_ONE)

    assert check[0] is False
    assert not check_is_transient(check), check


_URL = "https://placeholder.invalid"
CONNECTION_ERRORS = [
    botocore.exceptions.EndpointConnectionError(endpoint_url=_URL),
    botocore.exceptions.ConnectTimeoutError(endpoint_url=_URL),
    botocore.exceptions.ReadTimeoutError(endpoint_url=_URL),
    botocore.exceptions.ConnectionClosedError(endpoint_url=_URL),
]
#: Client-side failures that are no connection failure: no response and no
#: class the retry list names.
OTHER_CLIENT_SIDE_ERRORS = [
    botocore.exceptions.NoCredentialsError(),
    botocore.exceptions.NoRegionError(),
    botocore.exceptions.ParamValidationError(report="a parameter was refused"),
]


@pytest.mark.parametrize(
    "error", CONNECTION_ERRORS, ids=lambda error: type(error).__name__
)
def test_a_check_that_lost_its_connection_is_transient(monkeypatch, error):
    """A timeout or a refused connection says nothing about the model: the same
    classification that retries a throttle calls it transient."""

    def _fails(client, values=()):
        raise error

    monkeypatch.setattr(aws_utils, "get_available_models", _fails)

    check = validate_bedrock_model(object(), FALLBACK_ONE)

    assert check[0] is False
    assert check_is_transient(check), check


@pytest.mark.parametrize(
    "code",
    [
        "AccessDeniedException",
        "AccessDenied",
        "ResourceNotFoundException",
        "ExpiredTokenException",
        "ExpiredToken",
        "UnrecognizedClientException",
        "InvalidSignatureException",
        "InvalidClientTokenId",
    ],
)
def test_a_listing_the_control_plane_refused_is_not_a_retry_that_may_help(code):
    """The listing is where a denial or a bad credential shows: the control
    plane answers the call with a ClientError, which ``get_available_models``
    turns into an empty, failed list. A denied or credential code says the
    caller's access is the reason, so the refusal is not transient, its reason
    names the code, and it does not say the region has no models."""
    control = ControlPlane([FALLBACK_ONE], listing_error=code)

    models = aws_utils.get_available_models(control)
    check = validate_bedrock_model(control, FALLBACK_ONE)

    assert models.failed is True and models.failure_code == code, models
    assert check[0] is False
    assert not check_is_transient(check), (code, check)
    assert check[1] == f"the model listing failed: {code}", check
    assert "No available models" not in check[1], check


def test_a_throttled_listing_is_transient_and_names_its_code():
    """The control: throttling is a refusal a later check can pass, and it is
    told apart from a denial by the code, not by the reason's wording."""
    control = ControlPlane([FALLBACK_ONE], throttled=True)

    models = aws_utils.get_available_models(control)
    check = validate_bedrock_model(control, FALLBACK_ONE)

    assert models.failed is True and models.failure_code == "ThrottlingException"
    assert check_is_transient(check), check
    assert check[1] == "the model listing failed: ThrottlingException", check


def test_a_listing_that_raised_something_unexpected_is_not_transient_and_has_no_code():
    """An error that is neither a service answer nor a connection failure is
    the documented non-transient case: it is reported as the listing's failure
    and the models are not called not checked."""

    class Broken(ControlPlane):
        def __init__(self, listed):
            super().__init__(listed, error=RuntimeError("it failed"))

    models = aws_utils.get_available_models(Broken([FALLBACK_ONE]))
    check = validate_bedrock_model(Broken([FALLBACK_ONE]), FALLBACK_ONE)

    assert models.failed is True and models.failure_code is None, models
    assert not check_is_transient(check), check
    assert check[1] == "the model listing failed: unexpected error", check


@pytest.mark.parametrize(
    "error", CONNECTION_ERRORS, ids=lambda error: type(error).__name__
)
def test_a_listing_that_lost_its_connection_is_transient_and_has_no_code(error):
    """The connection failures are the transient errors that are not service
    answers, so they carry no code and are still told apart from the rest."""

    class Dropped(ControlPlane):
        def __init__(self, listed):
            super().__init__(listed, error=error)

    models = aws_utils.get_available_models(Dropped([FALLBACK_ONE]))
    check = validate_bedrock_model(Dropped([FALLBACK_ONE]), FALLBACK_ONE)

    assert models.failed is True and models.failure_code is None, models
    assert check_is_transient(check), check


@pytest.mark.parametrize(
    "code",
    [
        "ValidationException",
        "IncompleteSignatureException",
        "MissingAuthenticationTokenException",
        "RequestExpired",
        "OptInRequired",
        "AnErrorCodeNoOneListed",
    ],
)
def test_a_code_that_is_not_throttling_or_a_service_fault_is_not_transient(code):
    """The classification is an allowlist: throttling, service faults and
    connection failures are transient and every other code, a listed refusal or
    one nobody listed, is not. A code the list does not name is reported as
    the listing's failure, never as a check that may pass."""
    control = ControlPlane([FALLBACK_ONE], listing_error=code)

    models = aws_utils.get_available_models(control)
    check = validate_bedrock_model(control, FALLBACK_ONE)

    assert models.failed is True and models.failure_code == code, models
    assert not check_is_transient(check), (code, check)
    assert check[1] == f"the model listing failed: {code}", check
    assert aws_utils.failure_is_transient(code) is False


def test_a_listing_with_a_code_that_is_not_transient_is_asked_once():
    """``ValidationException`` is a refusal of the call: asking again cannot
    change it, so a walk reads the one answer for every candidate."""
    control = ControlPlane([FALLBACK_ONE], listing_error="ValidationException")
    wrapped = ListingsOnce(control)

    checks = [validate_bedrock_model(wrapped, model) for model in CHAIN]

    assert control.listings == 1, control.listings
    assert not any(check_is_transient(check) for check in checks), checks


def test_a_service_fault_from_the_listing_is_transient():
    """The control: ``InternalServerException`` is the code the control plane
    answers a 500 with, and the same list the retry decorator reads names it."""
    control = ControlPlane([FALLBACK_ONE], listing_error="InternalServerException")

    check = validate_bedrock_model(control, FALLBACK_ONE)

    assert check_is_transient(check), check
    assert "InternalServerException" in aws_utils.RETRYABLE_EXCEPTIONS


def test_one_list_decides_what_is_transient_for_a_check_and_for_a_retry():
    """The check and ``retry_with_backoff`` read one list: a code the list names
    is transient for both, and a code it does not name is neither. The kind of a
    check is never decided by a second list of its own."""
    probes = [
        *aws_utils.RETRYABLE_EXCEPTIONS,
        "ValidationException",
        "AccessDeniedException",
        "AnErrorCodeNoOneListed",
    ]

    for code in probes:
        calls = []

        @aws_utils.retry_with_backoff(max_retries=1, base_delay=0.0, max_delay=0.0)
        def _call():
            calls.append(code)
            raise _error(code)

        with pytest.raises(botocore.exceptions.ClientError):
            _call()

        retried = len(calls) == 2
        assert retried is aws_utils.failure_is_transient(code), (code, calls)
        assert retried is (code in aws_utils.RETRYABLE_EXCEPTIONS), (code, calls)

    # The same holds for a failure that is no service answer: botocore's
    # connection failures carry no code, and the check reads the classes they
    # derive from, so the decorator has to as well.
    for error in [*CONNECTION_ERRORS, *OTHER_CLIENT_SIDE_ERRORS, RuntimeError("no")]:
        assert _attempts(error, max_retries=1) == (
            2 if aws_utils.failure_is_transient(None, error) else 1
        ), error


def _attempts(error, max_retries=2, **options):
    """How many times ``retry_with_backoff`` calls a function that always raises
    ``error``, with no delay between the calls."""
    calls = []

    @aws_utils.retry_with_backoff(
        max_retries=max_retries, base_delay=0.0, max_delay=0.0, **options
    )
    def _call():
        calls.append(error)
        raise error

    with pytest.raises(type(error)):
        _call()
    return len(calls)


@pytest.mark.parametrize(
    "error", CONNECTION_ERRORS, ids=lambda error: type(error).__name__
)
def test_a_connection_failure_is_retried_by_the_default_list(error):
    """botocore's connection failures have no response and no ``code``, and
    their class names are not in the list: ``EndpointConnectionError`` derives
    from the ``ConnectionError`` the list names, ``ReadTimeoutError`` from the
    ``HTTPClientError`` it names. The check calls them transient, so the
    decorator that reads the same list retries them: the first call and the
    two retries."""
    assert aws_utils.failure_is_transient(None, error) is True
    assert _attempts(error) == 3


@pytest.mark.parametrize(
    "error", OTHER_CLIENT_SIDE_ERRORS, ids=lambda error: type(error).__name__
)
def test_a_client_side_failure_that_is_no_connection_failure_is_asked_once(error):
    """The control: a missing credential, a missing region and a parameter the
    client refused are not connection failures, so neither the check nor the
    decorator repeats them."""
    assert aws_utils.failure_is_transient(None, error) is False
    assert _attempts(error) == 1


def test_a_list_of_its_own_is_matched_by_class_name_and_code():
    """A caller that gives the decorator a list of its own (the Security Hub
    reporter) keeps the match it had: the exception's class name, or the code of
    its answer. A connection failure that list does not name is asked once, and
    one it names by class is retried."""
    dropped = botocore.exceptions.EndpointConnectionError(endpoint_url=_URL)

    assert _attempts(dropped, retryable_exceptions=["ThrottlingException"]) == 1
    assert _attempts(dropped, retryable_exceptions=["EndpointConnectionError"]) == 3
    assert _attempts(_error("ThrottlingException"), retryable_exceptions=["Other"]) == 1
    assert (
        _attempts(
            _error("ThrottlingException"), retryable_exceptions=["ThrottlingException"]
        )
        == 3
    )


@pytest.mark.parametrize(
    "error", CONNECTION_ERRORS, ids=lambda error: type(error).__name__
)
def test_a_model_call_that_lost_its_connection_is_repeated_on_the_same_model(error):
    """The model client's retries are ``retry_with_backoff``'s: a call that lost
    its connection once is repeated on the same model and answers, where it
    came back as an error before."""

    class Flaky:
        def __init__(self):
            self.calls = 0

        def converse(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise error
            return OK

    runtime = Flaky()
    client = BedrockModelClient(
        bedrock_runtime=runtime,
        model_id=PRIMARY_MODEL,
        temperature=0.5,
        max_tokens=64,
        top_p=0.9,
        max_retries=2,
        base_delay=0.0,
        max_delay=0.0,
    )

    outcome = client.call("a prompt", "a system prompt")

    assert outcome.ok is True and outcome.text == "fallback content", outcome
    assert runtime.calls == 2, runtime.calls


def test_a_region_with_no_models_keeps_its_own_reason():
    """The control: a listing that succeeded and named nothing is about the
    model, with the wording it always had."""
    check = validate_bedrock_model(ControlPlane([]), FALLBACK_ONE)

    assert check[1] == "No available models found in the current region", check
    assert not check_is_transient(check)


def test_a_failed_listing_reason_is_redacted_with_the_callers_values():
    check = validate_bedrock_model(
        ControlPlane([FALLBACK_ONE], listing_error="AccessDeniedException"),
        FALLBACK_ONE,
        values=["AccessDeniedException"],
    )

    assert "AccessDeniedException" not in check[1], check
    assert not check_is_transient(check)


@pytest.mark.parametrize("code", ["AccessDeniedException", "ResourceNotFoundException"])
def test_a_check_that_raised_a_refusal_about_the_model_is_not_transient(
    monkeypatch, code
):
    """The branch that catches a ClientError raised out of the listing reads the
    same classification as the failed listing does: only the codes the retry
    list names (throttling, service faults) are transient."""

    def _refused(client, values=()):
        raise _error(code, "no")

    monkeypatch.setattr(aws_utils, "get_available_models", _refused)

    check = validate_bedrock_model(object(), FALLBACK_ONE)

    assert check[0] is False, code
    assert not check_is_transient(check), (code, check)
    assert aws_utils.failure_is_transient(code) is False
    assert aws_utils.failure_is_transient("ThrottlingException") is True
    assert aws_utils.failure_is_transient("InternalServerException") is True
    assert aws_utils.failure_is_transient("ValidationException") is False
    assert aws_utils.failure_is_transient(None) is False


def test_a_model_whose_check_got_no_answer_is_named_as_not_checked(
    context,  # noqa: F811
    monkeypatch,
):
    """The configured model is not found and the control plane throttles the
    listing: the fallback is not known to be gone, and the exhaustion text does
    not say it is."""
    reporter = _walk_setup(
        context,
        monkeypatch,
        ControlPlane([FALLBACK_ONE], throttled=True),
        {PRIMARY_MODEL: FALLBACK_ONE},
    )
    runtime = Runtime({PRIMARY_MODEL: client_error("ResourceNotFoundException")})

    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

    assert out.startswith(_exhausted_text(not_checked=FALLBACK_ONE)), out
    assert runtime.models == [PRIMARY_MODEL], runtime.models


def test_a_model_the_listing_does_not_name_is_named_as_unavailable(
    context,  # noqa: F811
    monkeypatch,
):
    """The control: the listing succeeds and does not name the fallback."""
    reporter = _walk_setup(
        context,
        monkeypatch,
        ControlPlane([PRIMARY_MODEL]),
        {PRIMARY_MODEL: FALLBACK_ONE},
    )
    runtime = Runtime({PRIMARY_MODEL: client_error("ResourceNotFoundException")})

    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

    assert out.startswith(_exhausted_text(unavailable=FALLBACK_ONE)), out
    assert runtime.models == [PRIMARY_MODEL], runtime.models


def _listing_group(label, models):
    """The exhaustion text's group for models a refused listing left unchecked."""
    return f"not checked, {label}: {models}"


@pytest.mark.parametrize(
    "code",
    [
        "AccessDeniedException",
        "ExpiredTokenException",
        "UnrecognizedClientException",
        "ValidationException",
    ],
)
def test_a_walk_names_a_refused_listing_by_its_code_not_as_unavailable(
    context,  # noqa: F811
    monkeypatch,
    code,
):
    """The configured model is not found and the control plane refuses the
    listing (a denied call, an expired credential, a request it will not take).
    Nothing says the fallback is gone, so the exhaustion text must not word it
    as ``unavailable``, the text for a region that does not list the model: it
    names the code, which sends the operator to access and not to availability."""
    control = ControlPlane([FALLBACK_ONE], listing_error=code)
    reporter = _walk_setup(context, monkeypatch, control, {PRIMARY_MODEL: FALLBACK_ONE})
    runtime = Runtime({PRIMARY_MODEL: client_error("ResourceNotFoundException")})

    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

    group = _listing_group(f"listing refused ({code})", FALLBACK_ONE)
    assert out.startswith(
        f"*Error: No suitable fallback model found for {PRIMARY_MODEL} "
        f"(called: {PRIMARY_MODEL}; {group})"
    ), out
    assert "unavailable" not in out.split(". The configured model's error")[0], out
    assert runtime.models == [PRIMARY_MODEL], runtime.models
    assert control.listings == 1, control.listings


def test_a_walk_with_only_the_profile_listing_refused_still_calls_on_demand_models(
    context,  # noqa: F811
    monkeypatch,
):
    """ListInferenceProfiles is denied while ListFoundationModels answers: a
    fallback the on-demand list names is checked and called, and a fallback
    only a profile could route is "not checked, listing refused (code)", never
    "unavailable", because nobody could list the profiles that would name it."""
    control = ControlPlane(
        [FALLBACK_TWO],
        profile_error="AccessDeniedException",
        profile_only=[FALLBACK_ONE],
    )
    reporter = _walk_setup(
        context,
        monkeypatch,
        control,
        {PRIMARY_MODEL: FALLBACK_ONE, FALLBACK_ONE: FALLBACK_TWO},
    )
    runtime = Runtime(
        {
            PRIMARY_MODEL: client_error("ResourceNotFoundException"),
            FALLBACK_TWO: client_error("ValidationException"),
        }
    )

    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

    # The group names the call that was refused: it is the inference profile
    # listing, not the foundation-model listing, that the principal may not make.
    group = _listing_group(
        "profile listing refused (AccessDeniedException)", FALLBACK_ONE
    )
    assert out.startswith(
        f"*Error: No suitable fallback model found for {PRIMARY_MODEL} "
        f"(called: {PRIMARY_MODEL}, {FALLBACK_TWO}; {group})"
    ), out
    assert "unavailable" not in out.split(". The configured model's error")[0], out
    # The on-demand fallback was called; the profile-only one never was.
    assert runtime.models == [PRIMARY_MODEL, FALLBACK_TWO], runtime.models
    # One listing pair serves the whole walk, and the model listing answered.
    assert (control.listings, control.model_listings) == (1, 1)


def test_a_walk_names_every_candidate_a_refused_listing_left_unchecked(
    context,  # noqa: F811
    monkeypatch,
):
    """One refused listing is read by every candidate, so one group names the
    code once and all four models after it."""
    control = ControlPlane(CHAIN, listing_error="AccessDeniedException")
    reporter = _walk_setup(context, monkeypatch, control, _chain_links())
    runtime = Runtime({PRIMARY_MODEL: client_error("ResourceNotFoundException")})

    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

    group = _listing_group("listing refused (AccessDeniedException)", ", ".join(CHAIN))
    assert out.startswith(
        f"*Error: No suitable fallback model found for {PRIMARY_MODEL} "
        f"(called: {PRIMARY_MODEL}; {group})"
    ), out
    # Both listings are asked once: the profile listing's refusal alone no longer
    # stands for the model listing's, so the model listing is asked (and refused).
    assert (control.listings, control.model_listings) == (1, 1)
    assert runtime.models == [PRIMARY_MODEL], runtime.models


def test_a_walk_names_a_listing_that_failed_without_a_code(
    context,  # noqa: F811
    monkeypatch,
):
    """An error that is not a service answer and not a connection failure has no
    code to name. The group says the listing failed and how little is known."""

    class Broken(ControlPlane):
        def __init__(self, listed):
            super().__init__(listed, error=RuntimeError("it failed"))

    reporter = _walk_setup(
        context, monkeypatch, Broken([FALLBACK_ONE]), {PRIMARY_MODEL: FALLBACK_ONE}
    )
    runtime = Runtime({PRIMARY_MODEL: client_error("ResourceNotFoundException")})

    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

    group = _listing_group("listing failed (unexpected error)", FALLBACK_ONE)
    assert out.startswith(
        f"*Error: No suitable fallback model found for {PRIMARY_MODEL} "
        f"(called: {PRIMARY_MODEL}; {group})"
    ), out


#: Failures of botocore itself, before or around the call: no service answer,
#: so no code, and not a connection failure either.
BOTOCORE_ERRORS = [
    botocore.exceptions.NoCredentialsError(),
    botocore.exceptions.NoRegionError(),
    botocore.exceptions.ParamValidationError(report="a parameter was refused"),
    botocore.exceptions.TokenRetrievalError(provider="sso", error_msg="no token"),
    botocore.exceptions.UnauthorizedSSOTokenError(),
]


class Failing(ControlPlane):
    """A control plane whose listing calls raise ``error``."""

    def __init__(self, listed, error):
        super().__init__(listed, error=error)


@pytest.mark.parametrize(
    "error", BOTOCORE_ERRORS, ids=lambda error: type(error).__name__
)
def test_a_listing_botocore_failed_names_the_error_class(error):
    """A client-side failure (a missing credential, a missing region, a refused
    parameter, an expired SSO token) is not "unexpected": botocore raised it, and
    its class name says what it is. It has no service code, and it is not a
    failure a later try passes."""
    name = type(error).__name__
    control = Failing([FALLBACK_ONE], error)

    models = aws_utils.get_available_models(control)
    check = validate_bedrock_model(Failing([FALLBACK_ONE], error), FALLBACK_ONE)

    assert models.failed is True and models.failure_code is None, models
    assert check[1] == f"the model listing failed: {name}", check
    assert aws_utils.check_listing_failure(check) == name
    assert not check_is_transient(check), check


@pytest.mark.parametrize(
    "error", CONNECTION_ERRORS, ids=lambda error: type(error).__name__
)
def test_a_listing_that_lost_its_connection_names_the_error_class(error):
    """The connection failures are botocore's too: they have no code, are
    transient, and are named by their class."""
    name = type(error).__name__

    check = validate_bedrock_model(Failing([FALLBACK_ONE], error), FALLBACK_ONE)

    assert check[1] == f"the model listing failed: {name}", check
    assert aws_utils.check_listing_failure(check) == name
    assert check_is_transient(check), check


@pytest.mark.parametrize(
    "error", BOTOCORE_ERRORS, ids=lambda error: type(error).__name__
)
def test_a_repeated_botocore_failure_keeps_its_class_name_for_every_candidate(error):
    """The candidates after the first read the kept failure, which names the
    class as the first did, and the listing is asked once."""
    name = type(error).__name__
    control = Failing(CHAIN, error)
    wrapped = ListingsOnce(control)

    checks = [validate_bedrock_model(wrapped, model) for model in CHAIN]

    assert {aws_utils.check_listing_failure(check) for check in checks} == {name}
    assert control.listings == 1, control.listings


@pytest.mark.parametrize(
    "error", BOTOCORE_ERRORS, ids=lambda error: type(error).__name__
)
def test_a_check_says_that_botocore_failed_the_listing_before_any_answer(error):
    """The check carries, as data, that the listing failed on the client side
    and no service answered, so the exhaustion text does not call it a refusal.
    A service's own answer (a denied call) does not carry the flag."""
    failed = validate_bedrock_model(Failing([FALLBACK_ONE], error), FALLBACK_ONE)
    denied = validate_bedrock_model(
        ControlPlane([FALLBACK_ONE], listing_error="AccessDeniedException"),
        FALLBACK_ONE,
    )

    assert aws_utils.check_listing_client_side(failed) is True
    assert aws_utils.check_listing_client_side(denied) is False
    assert (
        aws_utils.check_listing_client_side((False, "a pair a caller built")) is False
    )


@pytest.mark.parametrize(
    "error", BOTOCORE_ERRORS, ids=lambda error: type(error).__name__
)
def test_a_walk_names_a_botocore_failure_by_its_class(
    context,  # noqa: F811
    monkeypatch,
    error,
):
    """The exhaustion text puts the models a botocore failure left unchecked in
    a group that names the class, not "unexpected error". No service answered,
    so the group says the listing failed. A listing the service refused is
    worded as refused (the tests above)."""
    name = type(error).__name__
    reporter = _walk_setup(
        context,
        monkeypatch,
        Failing([FALLBACK_ONE], error),
        {PRIMARY_MODEL: FALLBACK_ONE},
    )
    runtime = Runtime({PRIMARY_MODEL: client_error("ResourceNotFoundException")})

    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

    group = _listing_group(f"listing failed ({name})", FALLBACK_ONE)
    assert out.startswith(
        f"*Error: No suitable fallback model found for {PRIMARY_MODEL} "
        f"(called: {PRIMARY_MODEL}; {group})"
    ), out
    assert "unexpected error" not in out, out
    assert "refused" not in out.split(". The configured model's error")[0], out


def test_the_shim_names_its_primary_with_the_fallbacks_a_refused_listing_left_unchecked(
    context,  # noqa: F811
    monkeypatch,
):
    """The shim checks the configured model first. A refused listing left it
    unchecked, as it left the fallbacks, so one group names all of them and the
    code; the primary is not "unavailable" while the fallbacks are "not
    checked". The refused listing is requested once for the whole call."""
    control = ControlPlane([FALLBACK_ONE], listing_error="AccessDeniedException")
    reporter = _walk_setup(context, monkeypatch, control, {PRIMARY_MODEL: FALLBACK_ONE})

    out = reporter._call_bedrock(Runtime({}), "findings", "system")

    group = _listing_group(
        "listing refused (AccessDeniedException)", f"{PRIMARY_MODEL}, {FALLBACK_ONE}"
    )
    assert out.startswith(
        f"*Error: No suitable fallback model found for {PRIMARY_MODEL} ({group})"
    ), out
    assert "unavailable" not in out.split(". The configured model's error")[0], out
    assert control.listings == 1, control.listings


def test_the_shim_names_its_primary_not_checked_when_the_listing_was_throttled(
    context,  # noqa: F811
    monkeypatch,
):
    """A throttled listing says nothing about the configured model either: it
    is named as not checked with the fallbacks, and the listing is asked
    once."""
    control = ControlPlane([FALLBACK_ONE], throttled=True)
    reporter = _walk_setup(context, monkeypatch, control, {PRIMARY_MODEL: FALLBACK_ONE})

    out = reporter._call_bedrock(Runtime({}), "findings", "system")

    assert out.startswith(
        f"*Error: No suitable fallback model found for {PRIMARY_MODEL} "
        f"(not checked: {PRIMARY_MODEL}, {FALLBACK_ONE})"
    ), out
    assert control.listings == 1, control.listings


def test_the_shim_names_a_primary_the_listing_does_not_name_as_unavailable(
    context,  # noqa: F811
    monkeypatch,
):
    """The control: a listing that succeeded and does not name the configured
    model makes it unavailable, as before, and the fallback it names is called.
    The one listing answers the primary's check and the fallback's."""
    control = ControlPlane([FALLBACK_ONE])
    reporter = _walk_setup(context, monkeypatch, control, {PRIMARY_MODEL: FALLBACK_ONE})
    runtime = Runtime({FALLBACK_ONE: client_error("ResourceNotFoundException")})

    out = reporter._call_bedrock(runtime, "findings", "system")

    assert out.startswith(
        f"*Error: No suitable fallback model found for {PRIMARY_MODEL} "
        f"(called: {FALLBACK_ONE}; unavailable: {PRIMARY_MODEL})"
    ), out
    assert runtime.models == [FALLBACK_ONE], runtime.models
    assert (control.listings, control.model_listings) == (1, 1)


def test_a_refused_listing_does_not_send_a_cyclic_chain_around_again(
    context,  # noqa: F811
    monkeypatch,
):
    """``get_fallback_model`` ends a chain by returning to a model already
    visited. The models a refused listing left unchecked count as visited: the
    walk ends at the repeat, as it does for a model that was unavailable, and
    does not walk the cycle again. The chain is read through a counter that
    fails after twenty questions, so a walk that does not end fails here."""
    control = ControlPlane(CHAIN, listing_error="AccessDeniedException")
    reporter = _walk_setup(context, monkeypatch, control, {})
    links = {PRIMARY_MODEL: CHAIN[0], CHAIN[0]: CHAIN[1], CHAIN[1]: CHAIN[0]}
    asked = []

    def _next_in_chain(model):
        asked.append(model)
        assert len(asked) < 20, asked
        return links.get(model)

    monkeypatch.setattr(f"{MODULE}.get_fallback_model", _next_in_chain)
    runtime = Runtime({PRIMARY_MODEL: client_error("ResourceNotFoundException")})

    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

    group = _listing_group(
        "listing refused (AccessDeniedException)", f"{CHAIN[0]}, {CHAIN[1]}"
    )
    assert out.startswith(
        f"*Error: No suitable fallback model found for {PRIMARY_MODEL} "
        f"(called: {PRIMARY_MODEL}; {group})"
    ), out
    assert asked == [PRIMARY_MODEL, CHAIN[0], CHAIN[1]], asked
    assert control.listings == 1, control.listings


def test_a_check_names_how_its_listing_failed():
    """The walk reads how a listing failed from data on the check, as it reads
    whether the failure was transient: never from the reason's wording."""
    denied = validate_bedrock_model(
        ControlPlane([FALLBACK_ONE], listing_error="AccessDeniedException"),
        FALLBACK_ONE,
    )
    throttled = validate_bedrock_model(
        ControlPlane([FALLBACK_ONE], throttled=True), FALLBACK_ONE
    )
    not_listed = validate_bedrock_model(ControlPlane([PRIMARY_MODEL]), FALLBACK_ONE)
    listed = validate_bedrock_model(ControlPlane([FALLBACK_ONE]), FALLBACK_ONE)

    assert aws_utils.check_listing_failure(denied) == "AccessDeniedException"
    assert aws_utils.check_listing_failure(throttled) == "ThrottlingException"
    assert aws_utils.check_listing_failure(not_listed) is None
    assert aws_utils.check_listing_failure(listed) is None
    assert (
        aws_utils.check_listing_failure((False, "the model listing failed: x")) is None
    )
    assert aws_utils.check_listing_failure(None) is None


def test_a_model_the_listing_names_is_called(context, monkeypatch):  # noqa: F811
    """The control: the listing names the fallback, so it answers."""
    reporter = _walk_setup(
        context,
        monkeypatch,
        ControlPlane([FALLBACK_ONE]),
        {PRIMARY_MODEL: FALLBACK_ONE},
    )
    runtime = Runtime({PRIMARY_MODEL: client_error("ResourceNotFoundException")})

    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

    assert out == "fallback content", out
    assert runtime.models == [PRIMARY_MODEL, FALLBACK_ONE], runtime.models


# A fallback chain of four models after the configured one.
CHAIN = [
    "test-vendor.test-chain-a-v1:0",
    "test-vendor.test-chain-b-v1:0",
    "test-vendor.test-chain-c-v1:0",
    "test-vendor.test-chain-d-v1:0",
]


def _chain_links():
    return dict(zip([PRIMARY_MODEL, *CHAIN], CHAIN))


def test_a_wrapped_control_plane_answers_each_listing_once():
    """``ListingsOnce`` gives every check of a walk the first listing's answer,
    an error included, and the next wrapper asks the control plane again. The
    wrapper makes one call for a listing, a throttled one included: retries
    belong to the client, so every check after reads the kept answer."""
    control = ControlPlane([FALLBACK_ONE], throttled=True)
    wrapped = ListingsOnce(control)

    checks = [
        validate_bedrock_model(wrapped, model)
        for model in (FALLBACK_ONE, PRIMARY_MODEL)
    ]

    assert control.listings == 1, control.listings
    assert all(check_is_transient(check) for check in checks), checks
    validate_bedrock_model(ListingsOnce(control), FALLBACK_ONE)
    assert control.listings == 2, control.listings
    assert ListingsOnce(control).throttled is True


def test_a_listing_throttled_once_is_not_asked_again_by_the_wrapper():
    """The control plane throttles the first call only. The wrapper does not ask
    again: botocore's own retries ran inside the client call that failed, and a
    second round by the wrapper would send the whole sequence into the
    control plane again, once for each walk."""
    control = ControlPlane([FALLBACK_ONE], throttle_first=1)
    wrapped = ListingsOnce(control)

    checks = [
        validate_bedrock_model(wrapped, model)
        for model in (FALLBACK_ONE, PRIMARY_MODEL)
    ]

    assert all(check_is_transient(check) for check in checks), checks
    assert (control.listings, control.model_listings) == (1, 1)


def test_a_listing_throttled_for_good_is_kept_after_one_call():
    control = ControlPlane([FALLBACK_ONE], throttle_first=5)
    wrapped = ListingsOnce(control)

    checks = [validate_bedrock_model(wrapped, model) for model in CHAIN]

    assert control.listings == 1, control.listings
    assert all(check_is_transient(check) for check in checks), checks


def test_the_wrapper_never_sleeps(monkeypatch):
    """No wait sits in the wrapper: a walk over a throttled control plane
    returns at once, and there is no delay attribute to patch."""

    def _sleeps(seconds):
        raise AssertionError(f"the wrapper slept {seconds}s")

    monkeypatch.setattr(aws_utils.time, "sleep", _sleeps)
    control = ControlPlane([FALLBACK_ONE], throttled=True)
    wrapped = ListingsOnce(control)

    for model in CHAIN:
        validate_bedrock_model(wrapped, model)

    assert control.listings == 1, control.listings
    assert not hasattr(ListingsOnce, "RETRY_DELAY_SECONDS")


@pytest.mark.parametrize("code", ["AccessDeniedException", "ExpiredTokenException"])
def test_a_denied_listing_is_not_asked_again(code):
    """A denial or a bad credential is not a rate limit: asking again waits for
    nothing, so the wrapper keeps the first answer."""
    control = ControlPlane([FALLBACK_ONE], listing_error=code)
    wrapped = ListingsOnce(control)

    for model in CHAIN:
        validate_bedrock_model(wrapped, model)

    assert control.listings == 1, control.listings


@pytest.mark.parametrize("code", ["AccessDeniedException", "ThrottlingException"])
def test_a_failed_listing_is_logged_once_for_a_whole_walk(monkeypatch, code):
    """Four candidates read one failure. One warning names it, written when it
    first came: the first candidate's check does not warn a second time about
    the failure the listing just reported, and the others read the kept one."""
    warnings = []
    monkeypatch.setattr(
        aws_utils.ASH_LOGGER, "warning", lambda text, *a, **k: warnings.append(text)
    )
    wrapped = ListingsOnce(ControlPlane([], listing_error=code))

    for model in CHAIN:
        validate_bedrock_model(wrapped, model)

    assert len(warnings) == 1, warnings
    assert code in warnings[0], warnings


def test_a_wrapped_listing_is_kept_per_call_arguments():
    """A listing asked with other arguments is another listing: the answer is
    kept per name, positional arguments and keyword arguments, and the same call
    again gets the kept answer."""
    calls = []

    class Client:
        def list_foundation_models(self, **kwargs):
            calls.append(kwargs)
            return {"modelSummaries": [], "seen": len(calls)}

    wrapped = ListingsOnce(Client())

    first = wrapped.list_foundation_models(byProvider="a")
    again = wrapped.list_foundation_models(byProvider="a")
    other = wrapped.list_foundation_models(byProvider="b")
    reordered = wrapped.list_foundation_models(x=1, byProvider="b")
    reordered_again = wrapped.list_foundation_models(byProvider="b", x=1)

    assert again is first
    assert other is not first and other["seen"] == 2
    assert reordered_again is reordered
    assert len(calls) == 3, calls


def test_a_wrapper_built_without_init_refuses_its_own_names_and_does_not_recurse():
    """``__getattr__`` reads ``self._client``. On an instance whose ``__init__``
    never ran (a copy rebuilt by ``copy``, say) that read re-enters
    ``__getattr__`` forever unless the wrapper's own names and the dunders are
    refused. Any other private name is the client's and raises on its own."""
    bare = ListingsOnce.__new__(ListingsOnce)

    with pytest.raises(AttributeError):
        bare.list_inference_profiles
    for name in ("_client", "_answers", "_reported", "__setstate__", "__deepcopy__"):
        with pytest.raises(AttributeError):
            getattr(bare, name)
    # A private name that is not the wrapper's own reads as the client's, even
    # on a wrapper whose __init__ never ran: that read raises, it does not loop.
    with pytest.raises(AttributeError):
        bare._endpoint

    control = ControlPlane([FALLBACK_ONE])
    duplicate = copy.copy(ListingsOnce(control))
    assert duplicate.throttled is False


def test_a_wrapper_gives_the_clients_private_names_as_they_are():
    """The wrapper keeps three names of its own and the dunders. Any other name,
    a private one included, is the client's: botocore keeps its endpoint and
    service model under such names, and a caller that reads them through the
    wrapper gets the client's value, not an AttributeError."""

    class Client(ControlPlane):
        _endpoint = "https://placeholder.invalid"
        _service_model = object()

    client = Client([FALLBACK_ONE])
    wrapped = ListingsOnce(client)

    assert wrapped._endpoint == "https://placeholder.invalid"
    assert wrapped._service_model is client._service_model
    with pytest.raises(AttributeError):
        wrapped._missing_everywhere


def test_a_kept_failure_is_the_clients_error_with_its_response():
    """The first caller sees the error the client raised. A later one sees an
    error of the same class family with the same response, so a caller that
    handles ``ClientError`` handles it the same way, and it says it was already
    reported."""
    control = ControlPlane([FALLBACK_ONE], listing_error="AccessDeniedException")
    wrapped = ListingsOnce(control)

    with pytest.raises(botocore.exceptions.ClientError) as first:
        wrapped.list_inference_profiles()
    with pytest.raises(botocore.exceptions.ClientError) as again:
        wrapped.list_inference_profiles()

    kept = again.value
    assert isinstance(kept, aws_utils.KeptListingFailure), kept
    assert not isinstance(first.value, aws_utils.KeptListingFailure), first.value
    assert kept.response == first.value.response
    assert kept.operation_name == first.value.operation_name
    assert kept.original is first.value
    assert kept.failure_code == "AccessDeniedException"
    assert kept.transient is False
    assert control.listings == 1


def test_a_kept_failure_without_a_service_answer_still_reads_as_aclient_error():
    """A listing that failed without a service answer (a refused connection) has
    no response of its own. The kept failure is still a ``ClientError``, keeps
    the original, and is classified from it: a connection failure is transient
    and a failure that is neither a service answer nor a connection failure is
    not."""

    class Dropped(ControlPlane):
        def __init__(self, listed):
            super().__init__(
                listed,
                error=botocore.exceptions.EndpointConnectionError(endpoint_url=_URL),
            )

    class Broken(ControlPlane):
        def __init__(self, listed):
            super().__init__(listed, error=RuntimeError("it failed"))

    for control, transient in ((Dropped([]), True), (Broken([]), False)):
        wrapped = ListingsOnce(control)
        with pytest.raises(Exception) as first:
            wrapped.list_inference_profiles()
        with pytest.raises(botocore.exceptions.ClientError) as again:
            wrapped.list_inference_profiles()

        assert not isinstance(first.value, botocore.exceptions.ClientError)
        assert again.value.original is first.value
        assert again.value.failure_code is None
        assert again.value.transient is transient, type(first.value)


def test_a_repeated_failure_keeps_the_kind_of_the_first_for_every_candidate():
    """The walk's candidates after the first read the kept failure. It tells a
    connection failure from the rest as the first did, so a candidate is named
    as not checked when the first was."""

    class Dropped(ControlPlane):
        def __init__(self, listed):
            super().__init__(
                listed, error=botocore.exceptions.ReadTimeoutError(endpoint_url=_URL)
            )

    wrapped = ListingsOnce(Dropped([FALLBACK_ONE]))

    checks = [validate_bedrock_model(wrapped, model) for model in CHAIN]

    assert all(check_is_transient(check) for check in checks), checks


def test_a_model_check_survives_copy_deepcopy_and_pickle():
    """``ModelCheck`` is a tuple subclass built from three values. The tuple's
    own rebuild passes the pair as one argument, which makes the copy
    ``((False, "x"), None)``: truthy, and a refusal read as an answer."""
    refused = aws_utils.ModelCheck(
        False,
        "the reason",
        transient=True,
        listing_failure="AccessDeniedException",
        listing_client_side=True,
    )
    accepted = aws_utils.ModelCheck(True)

    for make in (
        copy.copy,
        copy.deepcopy,
        lambda value: pickle.loads(pickle.dumps(value)),  # nosec B301
    ):
        refused_copy = make(refused)
        accepted_copy = make(accepted)
        assert isinstance(refused_copy, aws_utils.ModelCheck)
        assert tuple(refused_copy) == (False, "the reason"), refused_copy
        assert refused_copy[0] is False
        assert refused_copy.transient is True
        assert refused_copy.listing_failure == "AccessDeniedException"
        assert refused_copy.listing_client_side is True
        assert tuple(accepted_copy) == (True, None), accepted_copy
        assert accepted_copy.transient is False
        assert accepted_copy.listing_failure is None
        assert accepted_copy.listing_client_side is False


def _kept_failure(original):
    """The ``KeptListingFailure`` a second caller of a listing that raised
    ``original`` is given."""

    wrapped = ListingsOnce(Failing([FALLBACK_ONE], original))
    with pytest.raises(type(original)):
        wrapped.list_inference_profiles()
    with pytest.raises(aws_utils.KeptListingFailure) as again:
        wrapped.list_inference_profiles()
    return again.value


@pytest.mark.parametrize(
    "original",
    [
        _error("AccessDeniedException"),
        _error("ThrottlingException"),
        botocore.exceptions.EndpointConnectionError(endpoint_url=_URL),
        RuntimeError("it failed"),
    ],
    ids=lambda original: type(original).__name__,
)
def test_a_kept_failure_survives_copy_deepcopy_and_pickle(original):
    """``ClientError.__reduce__`` rebuilds a ``ClientError`` from the response,
    so a copy of a kept failure was a plain ``ClientError``: it lost the
    original error and the kind, and an ``except KeptListingFailure`` no longer
    caught it. The copy is a kept failure with the same original and the same
    kind."""
    kept = _kept_failure(original)

    for make in (
        copy.copy,
        copy.deepcopy,
        lambda value: pickle.loads(pickle.dumps(value)),  # nosec B301
    ):
        rebuilt = make(kept)
        assert type(rebuilt) is aws_utils.KeptListingFailure, type(rebuilt)
        assert type(rebuilt.original) is type(original), rebuilt.original
        assert rebuilt.failure_code == kept.failure_code
        assert rebuilt.transient is kept.transient
        assert rebuilt.response == kept.response
        assert rebuilt.operation_name == kept.operation_name


@pytest.mark.parametrize(
    "error", CONNECTION_ERRORS, ids=lambda error: type(error).__name__
)
def test_a_kept_connection_failure_is_transient_to_the_plain_check(error):
    """A connection failure has no service answer, so the kept failure of a
    listing that lost its connection names the original's class as its code. A
    check that read only that code and the kept failure's own classes called it
    not transient, where the first caller's error was transient. The kept
    failure carries its own answer and the plain check honors it, so a later
    caller and the retry decorator tell it as the first caller was told."""
    kept = _kept_failure(error)
    code = kept.response["Error"]["Code"]

    assert code == type(error).__name__
    assert kept.transient is True
    assert aws_utils.failure_is_transient(code, kept) is True
    assert aws_utils.failure_is_transient(None, kept) is True
    assert _attempts(kept) == 3


@pytest.mark.parametrize(
    "original",
    [
        _error("AccessDeniedException"),
        RuntimeError("it failed"),
        botocore.exceptions.NoCredentialsError(),
    ],
    ids=lambda original: type(original).__name__,
)
def test_a_kept_failure_that_is_not_transient_is_asked_once(original):
    """The control: a kept failure of a denial, a missing credential or an
    unexpected error says so to the plain check as well, and is not repeated."""
    kept = _kept_failure(original)

    assert kept.transient is False
    assert aws_utils.failure_is_transient(kept.response["Error"]["Code"], kept) is False
    assert _attempts(kept) == 1


def test_a_kept_throttle_is_transient_to_the_plain_check():
    """The control: a kept failure of a throttle was transient by its code and
    still is."""
    kept = _kept_failure(_error("ThrottlingException"))

    assert kept.transient is True
    assert aws_utils.failure_is_transient("ThrottlingException", kept) is True
    assert _attempts(kept) == 3


class _Flagged(Exception):
    """An error that says for itself whether a later try may pass."""

    def __init__(self, transient):
        super().__init__("flagged")
        self.transient = transient


def test_an_errors_own_transient_flag_decides_the_check():
    """An error that carries a ``transient`` flag of its own is told by it, ahead
    of the class and the code, and so is the retry that reads the check. A list
    the caller passes still matches by class name and code only."""
    assert aws_utils.failure_is_transient(None, _Flagged(True)) is True
    assert aws_utils.failure_is_transient(None, _Flagged(False)) is False
    assert (
        aws_utils.failure_is_transient("ThrottlingException", _Flagged(False)) is False
    )
    assert _attempts(_Flagged(True)) == 3
    assert _attempts(_Flagged(False)) == 1
    assert _attempts(_Flagged(True), retryable_exceptions=["Other"]) == 1


def test_a_transient_attribute_that_is_not_a_flag_is_ignored():
    """The control: only a true or false value is an answer. Anything else on
    the attribute leaves the class and the code to decide."""
    dropped = botocore.exceptions.EndpointConnectionError(endpoint_url=_URL)
    dropped.transient = "yes"
    refused = _error("AccessDeniedException")
    refused.transient = None

    assert aws_utils.failure_is_transient(None, dropped) is True
    assert aws_utils.failure_is_transient("AccessDeniedException", refused) is False


def _status_error(code, status, operation="Converse"):
    """A service answer with the HTTP status the service sent with it."""
    return botocore.exceptions.ClientError(
        {
            "Error": {"Code": code, "Message": "it failed"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        operation,
    )


SERVER_FAULTS = [
    pytest.param("ServiceUnavailableException", 503, id="service-unavailable-503"),
    pytest.param("AnUnlistedServerFault", 500, id="unlisted-500"),
    pytest.param("AnotherUnlistedCode", 599, id="unlisted-599"),
]


@pytest.mark.parametrize("code, status", SERVER_FAULTS)
def test_an_answer_with_a_server_status_is_transient_whatever_its_code(code, status):
    """A service that answers with a 5xx status has failed on its side, and a
    later try may pass, whichever code it chose. ``ServiceUnavailableException``
    is no entry of the list and is such an answer: Bedrock sends it with 503."""
    error = _status_error(code, status)

    assert code not in aws_utils.RETRYABLE_EXCEPTIONS
    assert aws_utils.failure_is_transient(code, error) is True
    assert aws_utils.failure_is_transient(None, error) is True
    assert _attempts(error) == 3


@pytest.mark.parametrize(
    "code, status",
    [
        ("ValidationException", 400),
        ("AccessDeniedException", 403),
        ("ModelErrorException", 424),
        ("AnUnlistedClientFault", 499),
    ],
)
def test_an_answer_with_a_client_status_and_an_unlisted_code_is_not_transient(
    code, status
):
    """The control: a status below 500 says the request was refused, and a code
    the list does not name is asked once."""
    error = _status_error(code, status)

    assert aws_utils.failure_is_transient(code, error) is False
    assert _attempts(error) == 1


def test_an_answer_without_a_usable_status_is_judged_by_its_code():
    """The control: no status, an empty metadata block and a status that is not
    a number leave the code to decide, so the code that was asked once without
    a status is still asked once."""
    bare = _error("ServiceUnavailableException")
    empty = botocore.exceptions.ClientError(
        {
            "Error": {"Code": "ServiceUnavailableException", "Message": "it failed"},
            "ResponseMetadata": {},
        },
        "Converse",
    )
    text = _status_error("ServiceUnavailableException", "503")

    for error in (bare, empty, text):
        assert aws_utils.failure_is_transient("ServiceUnavailableException", error) is (
            False
        )
        assert _attempts(error) == 1


def test_a_list_of_its_own_ignores_the_status():
    """A caller that passes a list of its own keeps the match it had: class name
    and code, whatever the status says."""
    error = _status_error("AnUnlistedServerFault", 503)

    assert _attempts(error, retryable_exceptions=["Other"]) == 1
    assert _attempts(error, retryable_exceptions=["AnUnlistedServerFault"]) == 3


def test_a_listing_a_server_error_refused_is_transient_and_names_its_code():
    """The listing's check reads the same status: a control plane that failed on
    its side says nothing about the model, so the model is not checked, and the
    failure is named by the code it carried. A later caller of the walk's one
    listing reads the same."""
    error = _status_error("AnUnlistedServerFault", 503, "ListInferenceProfiles")

    models = aws_utils.get_available_models(Failing([FALLBACK_ONE], error))
    check = validate_bedrock_model(Failing([FALLBACK_ONE], error), FALLBACK_ONE)

    assert models.failed is True and models.failure_code == "AnUnlistedServerFault"
    assert models.transient is True, models
    assert check_is_transient(check), check
    assert _kept_failure(error).transient is True


def _server_error_client(error, failures):
    """A model client over a runtime that raises ``error`` for its first
    ``failures`` calls and answers after that."""

    class Flaky:
        def __init__(self):
            self.calls = 0

        def converse(self, **kwargs):
            self.calls += 1
            if self.calls <= failures:
                raise error
            return OK

    runtime = Flaky()
    client = BedrockModelClient(
        bedrock_runtime=runtime,
        model_id=PRIMARY_MODEL,
        temperature=0.5,
        max_tokens=64,
        top_p=0.9,
        max_retries=2,
        base_delay=0.0,
        max_delay=0.0,
    )
    return client, runtime


@pytest.mark.parametrize("code, status", SERVER_FAULTS)
def test_a_model_call_that_got_a_server_error_is_repeated_on_the_same_model(
    code, status
):
    """A model call that failed with a 5xx once is repeated on the same model and
    answers."""
    client, runtime = _server_error_client(_status_error(code, status), failures=1)

    outcome = client.call("a prompt", "a system prompt")

    assert outcome.ok is True and outcome.text == "fallback content", outcome
    assert runtime.calls == 2, runtime.calls


def test_a_model_call_that_keeps_getting_a_server_error_comes_back_as_it_is():
    """The first call and the two retries, then the failure as it is: not a
    reason to try another model."""
    client, runtime = _server_error_client(
        _status_error("ServiceUnavailableException", 503), failures=99
    )

    outcome = client.call("a prompt", "a system prompt")

    assert outcome.ok is False and outcome.model_specific is False, outcome
    assert outcome.text == "*Error: it failed*", outcome
    assert runtime.calls == 3, runtime.calls


def test_a_wrapped_control_plane_gives_a_successful_listing_again():
    """The control: a listing that succeeded is given to every later check, and
    each check still reads it for its own model."""
    control = ControlPlane([FALLBACK_ONE])
    wrapped = ListingsOnce(control)

    checks = [
        validate_bedrock_model(wrapped, model)
        for model in (FALLBACK_ONE, PRIMARY_MODEL)
    ]

    assert [check[0] for check in checks] == [True, False], checks
    assert (control.listings, control.model_listings) == (1, 1)


def test_a_throttled_control_plane_is_asked_once_per_walk_not_once_per_model(
    context,  # noqa: F811
    monkeypatch,
):
    """The configured model is not found and the control plane throttles every
    listing. Each walk makes one listing call, however many models the chain
    has (a retry is the client's, set by its config); the models it could not
    check are named as not checked, not as unavailable; and the next call walks
    the chain again."""
    control = ControlPlane(CHAIN, throttled=True)
    reporter = _walk_setup(context, monkeypatch, control, _chain_links())
    runtime = Runtime({PRIMARY_MODEL: client_error("ResourceNotFoundException")})
    expected = _exhausted_text(not_checked=", ".join(CHAIN))

    first = reporter._run_simple_report(runtime, sarif_model([]), [], [])
    assert control.listings == 1, control.listings
    second = reporter._run_simple_report(runtime, sarif_model([]), [], [])

    assert first.startswith(expected), first
    assert second.startswith(expected), second
    assert control.listings == 2, control.listings
    assert runtime.models == [PRIMARY_MODEL, PRIMARY_MODEL], runtime.models


def test_a_listing_throttled_once_leaves_the_fallback_unchecked_not_gone(
    context,  # noqa: F811
    monkeypatch,
):
    """The control plane throttles the first listing call. The wrapper does not
    ask again (the client's retries have already run), so the fallback is named
    as not checked, one listing call was made, and the primary was called once."""
    control = ControlPlane([FALLBACK_ONE], throttle_first=1)
    reporter = _walk_setup(context, monkeypatch, control, {PRIMARY_MODEL: FALLBACK_ONE})
    runtime = Runtime({PRIMARY_MODEL: client_error("ResourceNotFoundException")})

    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

    assert out.startswith(_exhausted_text(not_checked=FALLBACK_ONE)), out
    assert runtime.models == [PRIMARY_MODEL], runtime.models
    assert control.listings == 1, control.listings


def test_the_listing_is_read_once_for_every_model_a_walk_checks(
    context,  # noqa: F811
    monkeypatch,
):
    """The control: the listing succeeds and names none of the chain. One walk
    reads each listing once for its four candidates, and all four are
    unavailable."""
    control = ControlPlane([PRIMARY_MODEL])
    reporter = _walk_setup(context, monkeypatch, control, _chain_links())
    runtime = Runtime({PRIMARY_MODEL: client_error("ResourceNotFoundException")})

    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

    assert out.startswith(_exhausted_text(unavailable=", ".join(CHAIN))), out
    assert (control.listings, control.model_listings) == (1, 1)
    assert runtime.models == [PRIMARY_MODEL], runtime.models


def test_a_candidate_the_one_listing_names_is_called(
    context,  # noqa: F811
    monkeypatch,
):
    """The control: the one listing names the third model of the chain. The two
    before it are unavailable, the third answers, and the walk asked for the
    listing once."""
    control = ControlPlane([CHAIN[2]])
    reporter = _walk_setup(context, monkeypatch, control, _chain_links())
    third = {
        "output": {
            "message": {"role": "assistant", "content": [{"text": "third answer"}]}
        }
    }
    runtime = Runtime(
        {PRIMARY_MODEL: client_error("ResourceNotFoundException"), CHAIN[2]: third}
    )

    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

    assert out == "third answer", out
    assert runtime.models == [PRIMARY_MODEL, CHAIN[2]], runtime.models
    assert (control.listings, control.model_listings) == (1, 1)


# What a control-plane client retries is set where the client is built: botocore
# retries a throttle or a service fault inside the call, with its own backoff,
# so the wrapper does not ask a second time. The tests below read the config the
# reporter hands the session; none of them counts a call a retry made.
#: The config of a client built with no word from the operator.
RETRY_CONFIG = {"mode": "standard", "total_max_attempts": 3}


def retry_config_for(max_retries):
    """The config of a client built for a reporter whose ``max_retries`` option
    is ``max_retries``: botocore counts the first call, so one more attempt."""
    return {"mode": "standard", "total_max_attempts": max_retries + 1}


class ServiceSessions:
    """A boto3.Session stand-in that answers each service with the client given
    for it and records the service and keyword arguments of every client built."""

    def __init__(self, **clients):
        self.clients = clients
        self.built = []

    def __call__(self, **kwargs):
        return self

    def client(self, service, **kwargs):
        self.built.append((service, kwargs))
        return self.clients[service]


class Identity:
    def get_caller_identity(self):
        return {"Account": "placeholder"}


class Probe(ControlPlane):
    """The control plane as the reachability probe calls it, with a filter."""

    def list_foundation_models(self, **kwargs):
        return super().list_foundation_models()


def _recording_reporter(
    context,  # noqa: F811
    monkeypatch,
    reporter_options=None,
    **clients,
):
    sessions = ServiceSessions(**clients)
    reporter = make_reporter(context, enable_caching=False, **(reporter_options or {}))
    monkeypatch.setattr(
        f"{MODULE}.get_fallback_model", {PRIMARY_MODEL: FALLBACK_ONE}.get
    )
    monkeypatch.setattr(f"{MODULE}.boto3.Session", sessions)
    monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)
    return reporter, sessions


def _control_plane_configs(sessions):
    return [
        kwargs.get("config")
        for service, kwargs in sessions.built
        if service == "bedrock"
    ]


def test_the_control_plane_client_config_sets_the_retries():
    config = aws_utils.control_plane_client_config()

    assert isinstance(config, botocore.config.Config), config
    assert config.retries == RETRY_CONFIG, config.retries
    # A config of its own: changing one cannot change the next client's.
    assert config.retries is not aws_utils.CONTROL_PLANE_RETRIES


@pytest.mark.parametrize(
    "max_retries, attempts",
    [(0, 1), (1, 2), (3, 4), (10, 11), (11, 11), (500, 11), (-4, 1)],
)
def test_the_control_plane_client_config_follows_the_operators_max_retries(
    max_retries, attempts
):
    """The operator's ``max_retries`` is the count of retries, so the client
    makes that many more attempts than the first call, up to the most an option
    allows (``MAX_RETRIES``); a count below zero is no retry."""
    config = aws_utils.control_plane_client_config(max_retries)

    assert config.retries == {"mode": "standard", "total_max_attempts": attempts}
    assert aws_utils.MAX_RETRIES == 10


@pytest.mark.parametrize("max_retries", [0, 3, 10])
def test_the_walks_control_plane_client_is_built_with_the_retry_config(
    context,  # noqa: F811
    monkeypatch,
    max_retries,
):
    reporter, sessions = _recording_reporter(
        context,
        monkeypatch,
        {"max_retries": max_retries},
        bedrock=ControlPlane([FALLBACK_ONE]),
    )
    runtime = Runtime({PRIMARY_MODEL: client_error("ResourceNotFoundException")})

    reporter._run_simple_report(runtime, sarif_model([]), [], [])

    configs = _control_plane_configs(sessions)
    assert len(configs) == 1, sessions.built
    assert configs[0].retries == retry_config_for(max_retries), configs[0]


@pytest.mark.parametrize("max_retries", [0, 3, 10])
def test_the_shims_control_plane_client_is_built_with_the_retry_config(
    context,  # noqa: F811
    monkeypatch,
    max_retries,
):
    reporter, sessions = _recording_reporter(
        context,
        monkeypatch,
        {"max_retries": max_retries},
        bedrock=ControlPlane([PRIMARY_MODEL]),
    )

    reporter._call_bedrock(Runtime({}), "findings", "system")

    configs = _control_plane_configs(sessions)
    assert len(configs) == 1, sessions.built
    assert configs[0].retries == retry_config_for(max_retries), configs[0]


@pytest.mark.parametrize("max_retries", [0, 3, 10])
def test_the_dependency_checks_control_plane_client_is_built_with_the_retry_config(
    context,  # noqa: F811
    monkeypatch,
    max_retries,
):
    reporter, sessions = _recording_reporter(
        context,
        monkeypatch,
        {"max_retries": max_retries},
        sts=Identity(),
        bedrock=Probe([PRIMARY_MODEL]),
    )

    assert reporter.validate_plugin_dependencies() is True

    configs = _control_plane_configs(sessions)
    assert len(configs) == 1, sessions.built
    assert configs[0].retries == retry_config_for(max_retries), configs[0]


def test_a_reporter_built_with_default_options_makes_three_control_plane_attempts(
    context,  # noqa: F811
    monkeypatch,
):
    """The operator said nothing about ``max_retries``, so the control plane
    client has ``CONTROL_PLANE_RETRIES``: the first call and two retries. The
    option used to default to 3, which is three retries and four attempts."""
    reporter, sessions = _recording_reporter(
        context, monkeypatch, None, bedrock=ControlPlane([FALLBACK_ONE])
    )
    runtime = Runtime({PRIMARY_MODEL: client_error("ResourceNotFoundException")})

    reporter._run_simple_report(runtime, sarif_model([]), [], [])

    configs = _control_plane_configs(sessions)
    assert len(configs) == 1, sessions.built
    assert configs[0].retries == RETRY_CONFIG, configs[0]


class Throttled:
    """A bedrock-runtime client whose converse() is always throttled."""

    def __init__(self):
        self.calls = 0

    def converse(self, **kwargs):
        self.calls += 1
        raise _error("ThrottlingException", "Rate exceeded", "Converse")


def test_a_reporter_built_with_default_options_retries_a_model_call_three_times(
    context,  # noqa: F811
    monkeypatch,
):
    """The control: a model call is still repeated three times when the operator
    said nothing, which is the documented default of ``max_retries``."""
    monkeypatch.setattr(aws_utils.time, "sleep", lambda seconds: None)
    reporter = make_reporter(context, base_delay=0.0, max_delay=0.0)
    runtime = Throttled()

    outcome = reporter._make_model_client(runtime).call("a prompt", "a system prompt")

    assert outcome.ok is False, outcome
    assert runtime.calls == 4, runtime.calls
