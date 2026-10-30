# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The inference profile listing is asked apart from the foundation-model listing.

``get_available_models`` makes two control-plane calls. A failure of
``ListInferenceProfiles`` alone (a principal allowed ``ListFoundationModels`` but
not that call, a throttle on that call) used to discard the foundation-model
list with it, so every on-demand model the caller could list and invoke read as
"No available models found in the current region". The profile listing is also
read over every page, a model routed by two profiles is listed under each, and
an ARN the listing carries names a listed model, as Converse accepts it.

No test here calls AWS: the control plane is a MagicMock whose two listings
answer by plan.
"""

import logging
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
    ListingsOnce,
    check_is_transient,
    check_listing_failure,
    get_available_models,
    validate_bedrock_model,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

ON_DEMAND = "us.amazon.nova-pro-v1:0"
ON_DEMAND_ARN = "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-pro-v1:0"
PROFILED = "anthropic.claude-3-7-sonnet-20250219-v1:0"
PROFILED_ARN = (
    "arn:aws:bedrock:us-east-1::foundation-model/"
    "anthropic.claude-3-7-sonnet-20250219-v1:0"
)
US_PROFILE = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
US_PROFILE_ARN = (
    "arn:aws:bedrock:us-east-1:123456789012:inference-profile/"
    "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
)
GLOBAL_PROFILE = "global.anthropic.claude-3-7-sonnet-20250219-v1:0"
GLOBAL_PROFILE_ARN = (
    "arn:aws:bedrock:us-east-1:123456789012:inference-profile/"
    "global.anthropic.claude-3-7-sonnet-20250219-v1:0"
)


def _summary(model_id, arn, inference_types):
    return {
        "modelId": model_id,
        "modelName": "placeholder",
        "modelArn": arn,
        "providerName": "placeholder",
        "modelLifecycle": {"status": "ACTIVE"},
        "inputModalities": ["TEXT"],
        "outputModalities": ["TEXT"],
        "inferenceTypesSupported": inference_types,
    }


def _profile(profile_id, profile_arn, model_arn):
    return {
        "inferenceProfileId": profile_id,
        "inferenceProfileArn": profile_arn,
        "inferenceProfileName": "placeholder",
        "models": [{"modelArn": model_arn}],
    }


def _refused(code, operation="ListInferenceProfiles"):
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": "the listing was refused"}}, operation
    )


def _client(profiles=None, profile_error=None, models=None):
    client = MagicMock()
    if profile_error is not None:
        client.list_inference_profiles.side_effect = profile_error
    else:
        client.list_inference_profiles.return_value = {
            "inferenceProfileSummaries": list(profiles or [])
        }
    client.list_foundation_models.return_value = {
        "modelSummaries": list(
            models
            if models is not None
            else [
                _summary(ON_DEMAND, ON_DEMAND_ARN, ["ON_DEMAND"]),
                _summary(PROFILED, PROFILED_ARN, ["INFERENCE_PROFILE"]),
            ]
        )
    }
    return client


# ---------------------------------------------------------------------------
# A failed profile listing leaves the on-demand models listed
# ---------------------------------------------------------------------------


def test_on_demand_models_are_listed_when_the_profile_listing_is_refused():
    """A principal allowed ListFoundationModels but not ListInferenceProfiles
    can list and invoke the on-demand models, so they are listed and the
    profile listing's refusal is carried as data, not as the whole listing's
    failure."""
    client = _client(profile_error=_refused("AccessDeniedException"))

    models = get_available_models(client)

    assert [model["modelId"] for model in models] == [ON_DEMAND], models
    assert models.failed is False
    assert models.profile_listing_failure == "AccessDeniedException"
    assert models.profile_listing_transient is False
    client.list_foundation_models.assert_called_once()


def test_an_on_demand_model_is_valid_when_only_the_profile_listing_failed():
    client = _client(profile_error=_refused("AccessDeniedException"))

    check = validate_bedrock_model(client, ON_DEMAND)

    assert check[0] is True, check


def test_a_model_the_on_demand_list_lacks_is_unchecked_when_profiles_failed():
    """The model may be routed by a profile nobody could list: the check is a
    listing failure named by the profile listing's code, never "not found in
    available models", and a denial is not a retry that may help."""
    client = _client(profile_error=_refused("AccessDeniedException"))

    check = validate_bedrock_model(client, PROFILED)

    assert check[0] is False
    assert "not found in available models" not in check[1], check
    assert "inference profile listing failed: AccessDeniedException" in check[1]
    assert check_listing_failure(check) == "AccessDeniedException"
    assert not check_is_transient(check)


def test_one_failed_profile_listing_is_one_warning_over_a_walk(caplog):
    """A walk over a chain of profile models asks one listing (ListingsOnce) and
    checks each candidate against it. The listing's failure is logged once, at
    warning, when it comes; each candidate's "the profile listing failed" answer
    then names it at debug, so one denied ListInferenceProfiles is one warning in
    ash.log, not one per candidate."""
    listings = ListingsOnce(_client(profile_error=_refused("AccessDeniedException")))

    with caplog.at_level(logging.DEBUG, logger=ASH_LOGGER.name):
        first = validate_bedrock_model(listings, PROFILED)
        second = validate_bedrock_model(listings, US_PROFILE)

    assert first[0] is False and second[0] is False, (first, second)
    warnings = [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING
    ]
    assert len(warnings) == 1, warnings
    assert "AccessDeniedException" in warnings[0], warnings
    # The control: each candidate's answer still names the failure, quietly.
    # The filter is the candidate answer's own text: the second walk call also
    # re-describes the kept failure at debug ("the inference profile listing
    # failed, so models reachable only ..."), which is the listing's line, not
    # a candidate's, so a filter on "inference profile listing failed" alone
    # would count three records here.
    named = [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.DEBUG
        and "is not an on-demand model" in record.getMessage()
        and "AccessDeniedException" in record.getMessage()
    ]
    assert len(named) == 2, named


def test_a_throttled_profile_listing_leaves_the_missing_model_transient():
    client = _client(profile_error=_refused("ThrottlingException"))

    models = get_available_models(client)
    check = validate_bedrock_model(client, PROFILED)

    assert [model["modelId"] for model in models] == [ON_DEMAND], models
    assert models.profile_listing_transient is True
    assert check[0] is False and check_is_transient(check), check


def test_an_empty_on_demand_list_with_a_failed_profile_listing_is_unchecked():
    """No on-demand model and no profile listing: nothing says the region has
    no models, so the answer is the listing failure, not the region's."""
    client = _client(
        profile_error=_refused("AccessDeniedException"),
        models=[_summary(PROFILED, PROFILED_ARN, ["INFERENCE_PROFILE"])],
    )

    check = validate_bedrock_model(client, PROFILED)

    assert check[0] is False
    assert "No available models" not in check[1], check
    assert check_listing_failure(check) == "AccessDeniedException"


def test_both_listings_failing_is_the_whole_listings_failure():
    """The control: when the foundation-model listing fails too, the answer is
    the failed empty list it always was, reported once."""
    client = _client(profile_error=_refused("AccessDeniedException"))
    client.list_foundation_models.side_effect = _refused(
        "AccessDeniedException", "ListFoundationModels"
    )

    models = get_available_models(client)

    assert models == [] and models.failed is True
    assert models.failure_code == "AccessDeniedException"
    assert models.profile_listing_failure is None


def test_both_listings_failing_names_the_profile_failure_beside_the_warning(
    caplog,
):
    """One warning, the foundation listing's; the profile listing's failure,
    which the answer does not carry, is named at debug beside it rather than
    dropped, so ash.log says both calls failed and with what."""
    client = _client(profile_error=_refused("ThrottlingException"))
    client.list_foundation_models.side_effect = _refused(
        "AccessDeniedException", "ListFoundationModels"
    )

    with caplog.at_level(logging.DEBUG, logger=ASH_LOGGER.name):
        get_available_models(client)

    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1 and "AccessDeniedException" in warnings[0], warnings
    named = [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.DEBUG
        and "inference profile listing had failed too" in r.getMessage()
    ]
    assert len(named) == 1 and "ThrottlingException" in named[0], named


# ---------------------------------------------------------------------------
# Every page, every profile, every identifier
# ---------------------------------------------------------------------------


def test_the_profile_listing_is_read_over_every_page():
    """A model reachable only through a profile on a later page is listed."""
    client = _client()
    pages = [
        {
            "inferenceProfileSummaries": [
                _profile("other-profile", "arn:other", "arn:other-model")
            ],
            "nextToken": "page-two",
        },
        {
            "inferenceProfileSummaries": [
                _profile(US_PROFILE, US_PROFILE_ARN, PROFILED_ARN)
            ]
        },
    ]
    client.list_inference_profiles.side_effect = lambda **kwargs: pages.pop(0)

    models = get_available_models(client)

    assert [model["modelId"] for model in models] == [ON_DEMAND, US_PROFILE], models
    calls = client.list_inference_profiles.call_args_list
    assert [call.kwargs for call in calls] == [{}, {"nextToken": "page-two"}], calls


def test_the_pages_read_before_a_failed_page_are_kept(caplog):
    """A throttle on page two loses page two, not page one: the model page
    one's profile routes is listed and validates, the listing's failure is
    still carried (a profile on the pages never read may route the rest), and
    the warning says how far the listing got."""
    client = _client()

    def answer(**kwargs):
        if kwargs.get("nextToken") == "page-two":
            raise _refused("ThrottlingException")
        return {
            "inferenceProfileSummaries": [
                _profile(US_PROFILE, US_PROFILE_ARN, PROFILED_ARN)
            ],
            "nextToken": "page-two",
        }

    client.list_inference_profiles.side_effect = answer

    with caplog.at_level(logging.WARNING):
        models = get_available_models(client)

    assert [model["modelId"] for model in models] == [ON_DEMAND, US_PROFILE], models
    assert models.profile_listing_failure == "ThrottlingException"
    assert models.profile_listing_transient is True
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1 and "after 1 profile(s) were read" in warnings[0], (
        warnings
    )
    assert validate_bedrock_model(client, US_PROFILE)[0] is True
    # The control: a profile the unread pages would have carried is unchecked,
    # named by the listing's failure, never "not found".
    check = validate_bedrock_model(client, GLOBAL_PROFILE)
    assert check[0] is False and check_listing_failure(check) == "ThrottlingException"
    assert "not found in available models" not in check[1], check


def test_a_model_routed_by_two_profiles_is_listed_under_each():
    """A geographic profile and a global one route the same model; neither
    profile ID is reported as not found."""
    client = _client(
        profiles=[
            _profile(US_PROFILE, US_PROFILE_ARN, PROFILED_ARN),
            _profile(GLOBAL_PROFILE, GLOBAL_PROFILE_ARN, PROFILED_ARN),
        ]
    )

    models = get_available_models(client)

    profiled = [m for m in models if m["inferenceType"] == "INFERENCE_PROFILE"]
    assert [m["modelId"] for m in profiled] == [US_PROFILE, GLOBAL_PROFILE], models
    assert [m["inferenceProfileArn"] for m in profiled] == [
        US_PROFILE_ARN,
        GLOBAL_PROFILE_ARN,
    ]
    assert validate_bedrock_model(client, US_PROFILE)[0] is True
    assert validate_bedrock_model(client, GLOBAL_PROFILE)[0] is True


@pytest.mark.parametrize(
    "identifier", [ON_DEMAND_ARN, US_PROFILE_ARN], ids=["model-arn", "profile-arn"]
)
def test_an_arn_the_listing_carries_names_a_listed_model(identifier):
    """Converse takes a model ARN or an inference profile ARN as the model
    identifier, so a configured ARN is validated against the ARNs the listing
    carries, not only against the IDs."""
    client = _client(profiles=[_profile(US_PROFILE, US_PROFILE_ARN, PROFILED_ARN)])

    check = validate_bedrock_model(client, identifier)

    assert check[0] is True, check


def test_a_profile_only_models_foundation_arn_is_not_a_listed_identifier():
    """A model only a profile routes is listed under its profile, and that
    entry carries the model's own ARN too; Converse refuses that ARN as a model
    identifier ("with on-demand throughput isn't supported"), so the check must
    not say yes to it and send the first call into a ValidationException."""
    client = _client(profiles=[_profile(US_PROFILE, US_PROFILE_ARN, PROFILED_ARN)])

    check = validate_bedrock_model(client, PROFILED_ARN)

    assert check[0] is False, check
    # The controls: the two identifiers Converse does take still validate.
    assert validate_bedrock_model(client, US_PROFILE_ARN)[0] is True
    assert validate_bedrock_model(client, ON_DEMAND_ARN)[0] is True
