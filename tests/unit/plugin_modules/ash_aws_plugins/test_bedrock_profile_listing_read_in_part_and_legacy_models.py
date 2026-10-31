# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the model checks say when the inference profile listing is read in part,
and about a model Bedrock lists as LEGACY.

* A profile listing whose second page is throttled still lists the profiles on
  its first page. The failure belongs to the spelling that was not found, not to
  every spelling of the model, so the check goes on to the next spelling and the
  dependency check does not disable the reporter while a listed fallback exists.
* An id that no profile could carry (an on-demand id the foundation-model listing
  does not name as profile-routed) is not found when the profile listing failed;
  it is not "listing failed".
* A page token the listing hands back twice stops the listing with a recorded
  failure, in two calls.
* A fallback listed as LEGACY does not satisfy the dependency check: Bedrock may
  refuse a Legacy model to an account that has not used it recently
  (https://docs.aws.amazon.com/bedrock/latest/userguide/model-lifecycle.html).
  The configured model is the operator's choice and passes as before.
* A refused inference profile listing is named as such in the walk's text, apart
  from a refused foundation-model listing.

No test here calls AWS: the control plane is a stand-in that answers by plan.
"""

from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
    UNEXPECTED_LISTING_ERROR,
    ListingsOnce,
    check_is_legacy,
    check_is_spelling_specific,
    check_is_transient,
    check_listing_failure,
    get_available_models,
    validate_bedrock_model,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    _exhaustion_text,
)
from tests.unit.plugin_modules.ash_aws_plugins.bedrock_reporter_doubles import (
    make_reporter,
    plugin_context_in,
)

pytestmark = pytest.mark.unit

#: The model the fallback chain names after the configured one below.
CHAIN_MODEL = "anthropic.claude-3-5-sonnet-20240620-v1:0"
EU_PROFILE = f"eu.{CHAIN_MODEL}"
US_PROFILE = f"us.{CHAIN_MODEL}"
EU_CONFIGURED = "eu.anthropic.claude-3-7-sonnet-20250219-v1:0"

#: Opaque ids: the chain has no entry for this prefix, so its fallback is the
#: default chain head, FALLBACK.
CONFIGURED = "test-vendor.configured-model-v1:0"
FALLBACK = "us.amazon.nova-pro-v1:0"


def _model(model_id, *, types, status="ACTIVE"):
    return {
        "modelId": model_id,
        "modelName": "placeholder",
        "modelArn": f"arn:test:model/{model_id}",
        "providerName": "placeholder",
        "modelLifecycle": {"status": status},
        "inputModalities": ["TEXT"],
        "outputModalities": ["TEXT"],
        "inferenceTypesSupported": list(types),
    }


def _profile(profile_id, model_id):
    return {
        "inferenceProfileId": profile_id,
        "inferenceProfileArn": f"arn:test:profile/{profile_id}",
        "inferenceProfileName": "placeholder",
        "models": [{"modelArn": f"arn:test:model/{model_id}"}],
    }


def _refused(code, operation="ListInferenceProfiles"):
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": "the listing was refused"}}, operation
    )


def _control_plane(models, pages=()):
    """A control plane that lists ``models`` and answers the profile listing page
    by page: each item of ``pages`` is a list of profiles (a page that hands
    back the token of the next item, unless it is the last) or an exception
    (that page is refused)."""
    control = MagicMock()
    control.list_foundation_models.return_value = {"modelSummaries": list(models)}

    def answer(**kwargs):
        index = int(kwargs["nextToken"].split("-")[1]) if kwargs else 0
        page = pages[index]
        if isinstance(page, BaseException):
            raise page
        result = {"inferenceProfileSummaries": list(page)}
        if index + 1 < len(pages):
            result["nextToken"] = f"page-{index + 1}"
        return result

    control.list_inference_profiles.side_effect = answer
    return control


def _session(control):
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "placeholder"}
    clients = {"sts": sts, "bedrock": control}
    session = MagicMock()
    session.client.side_effect = lambda service, **kwargs: clients[service]
    return session


def _hidden_behind_a_throttled_page():
    """CHAIN_MODEL is profile-routed; the profile that names it is on page one,
    and page two, which may hold others, is throttled."""
    return _control_plane(
        [_model(CHAIN_MODEL, types=["INFERENCE_PROFILE"])],
        [[_profile(US_PROFILE, CHAIN_MODEL)], _refused("ThrottlingException")],
    )


# ---------------------------------------------------------------------------
# A profile listing read in part: the failure is about the spelling checked
# ---------------------------------------------------------------------------


def test_a_spelling_on_the_pages_read_is_found_after_one_the_failed_listing_hides(
    tmp_path,
):
    reporter = make_reporter(plugin_context_in(tmp_path), aws_region="eu-west-1")

    check, spelling = reporter._check_candidate(
        ListingsOnce(_hidden_behind_a_throttled_page()), EU_PROFILE, ()
    )

    assert check[0] is True, check
    assert spelling == US_PROFILE


def test_a_candidate_no_spelling_finds_stays_unchecked_while_the_listing_failed(
    tmp_path,
):
    """The control: with the first page throttled too, no spelling is listed, and
    the answer is the listing's transient failure for the last spelling tried."""
    control = _control_plane(
        [_model(CHAIN_MODEL, types=["INFERENCE_PROFILE"])],
        [_refused("ThrottlingException")],
    )
    reporter = make_reporter(plugin_context_in(tmp_path), aws_region="eu-west-1")

    check, spelling = reporter._check_candidate(ListingsOnce(control), EU_PROFILE, ())

    assert check[0] is False
    assert check_is_spelling_specific(check) and check_is_transient(check)
    assert spelling == US_PROFILE


@patch("boto3.Session")
def test_the_dependency_check_keeps_the_reporter_when_a_listed_fallback_hides(
    mock_session_cls, tmp_path
):
    """The configured model is not listed, its fallback is listed under the
    ``us.`` spelling on the first profile page, and page two is throttled: the
    reporter stays enabled."""
    mock_session_cls.return_value = _session(_hidden_behind_a_throttled_page())
    reporter = make_reporter(
        plugin_context_in(tmp_path),
        aws_region="eu-west-1",
        model_id=EU_CONFIGURED,
        enable_fallback_models=True,
    )

    assert reporter.validate_plugin_dependencies() is True, reporter.errors


# ---------------------------------------------------------------------------
# An id no profile could carry is not found
# ---------------------------------------------------------------------------


def test_an_on_demand_id_the_region_does_not_list_is_not_found_when_profiles_failed():
    control = _control_plane(
        [_model("amazon.titan-text-express-v1", types=["ON_DEMAND"])],
        [_refused("AccessDeniedException")],
    )

    check = validate_bedrock_model(control, "amazon.titan-text-lite-v1")

    assert check[0] is False
    assert "not found in available models" in check[1], check
    assert check_listing_failure(check) is None
    assert not check_is_transient(check)


@pytest.mark.parametrize(
    "model_id",
    ["eu.amazon.titan-text-lite-v1", "arn:test:profile/not-listed"],
    ids=["area-prefixed", "arn"],
)
def test_an_id_a_profile_could_carry_is_unchecked_when_profiles_failed(model_id):
    """The control: a profile id and an ARN may name a profile nobody could list."""
    control = _control_plane(
        [_model("amazon.titan-text-express-v1", types=["ON_DEMAND"])],
        [_refused("AccessDeniedException")],
    )

    check = validate_bedrock_model(control, model_id)

    assert check[0] is False
    assert check_listing_failure(check) == "AccessDeniedException"
    assert check_is_spelling_specific(check)


def test_a_raw_id_the_listing_names_as_profile_routed_is_unchecked_when_profiles_failed():
    """The control: the foundation-model listing says this id is reached through a
    profile, so the failed profile listing leaves it unchecked."""
    control = _control_plane(
        [_model("anthropic.test-model-v1:0", types=["INFERENCE_PROFILE"])],
        [_refused("AccessDeniedException")],
    )

    check = validate_bedrock_model(control, "anthropic.test-model-v1:0")

    assert check_listing_failure(check) == "AccessDeniedException"


# ---------------------------------------------------------------------------
# A page token handed back twice ends the listing with a failure
# ---------------------------------------------------------------------------


def test_a_page_token_given_twice_stops_the_listing_and_records_a_failure():
    control = MagicMock()
    control.list_foundation_models.return_value = {
        "modelSummaries": [_model(CHAIN_MODEL, types=["INFERENCE_PROFILE"])]
    }
    control.list_inference_profiles.return_value = {
        "inferenceProfileSummaries": [_profile(US_PROFILE, CHAIN_MODEL)],
        "nextToken": "again",
    }

    models = get_available_models(control)

    assert control.list_inference_profiles.call_count == 2
    assert models.profile_listing_failure == UNEXPECTED_LISTING_ERROR
    # The page was read once; the repeat was not read again.
    assert [model["modelId"] for model in models] == [US_PROFILE], models


def test_a_listing_that_answers_with_a_bare_mock_stops_in_two_calls():
    """A client double that returns one bare mock for every call hands back the
    same token each time; the listing must not wait for it to end."""
    control = MagicMock()

    get_available_models(control)

    assert control.list_inference_profiles.call_count == 2


# ---------------------------------------------------------------------------
# A LEGACY fallback is not counted as available
# ---------------------------------------------------------------------------


def _legacy_control(status):
    return _control_plane([_model(FALLBACK, types=["ON_DEMAND"], status=status)], [[]])


def _dependency_reporter(tmp_path):
    return make_reporter(
        plugin_context_in(tmp_path),
        aws_region="us-east-1",
        model_id=CONFIGURED,
        enable_fallback_models=True,
    )


@patch("boto3.Session")
def test_a_legacy_fallback_does_not_satisfy_the_dependency_check(
    mock_session_cls, tmp_path
):
    mock_session_cls.return_value = _session(_legacy_control("LEGACY"))
    reporter = _dependency_reporter(tmp_path)

    assert reporter.validate_plugin_dependencies() is False

    assert "is listed as Legacy" in "\n".join(reporter.errors), reporter.errors


@patch("boto3.Session")
def test_an_active_fallback_satisfies_the_dependency_check(mock_session_cls, tmp_path):
    """The control: the same listing with an ACTIVE model passes."""
    mock_session_cls.return_value = _session(_legacy_control("ACTIVE"))
    reporter = _dependency_reporter(tmp_path)

    assert reporter.validate_plugin_dependencies() is True, reporter.errors


@patch("boto3.Session")
def test_a_legacy_configured_model_satisfies_the_dependency_check(
    mock_session_cls, tmp_path
):
    """The configured model is the operator's choice: listed as LEGACY it is
    still the model the run calls first."""
    control = _control_plane(
        [_model(CONFIGURED, types=["ON_DEMAND"], status="LEGACY")], [[]]
    )
    mock_session_cls.return_value = _session(control)
    reporter = _dependency_reporter(tmp_path)

    assert reporter.validate_plugin_dependencies() is True, reporter.errors


def test_a_check_says_whether_the_model_it_found_is_legacy():
    legacy = validate_bedrock_model(_legacy_control("LEGACY"), FALLBACK)
    active = validate_bedrock_model(_legacy_control("ACTIVE"), FALLBACK)

    assert legacy[0] is True and check_is_legacy(legacy)
    assert active[0] is True and not check_is_legacy(active)


# ---------------------------------------------------------------------------
# The walk's text names the listing that was refused
# ---------------------------------------------------------------------------


def test_a_refused_profile_listing_is_named_apart_from_a_refused_model_listing():
    text = _exhaustion_text(
        "primary",
        ["primary"],
        [],
        None,
        listing_refused={"AccessDeniedException": ["first"]},
        profile_listing_refused={"AccessDeniedException": ["second"]},
    )

    assert "not checked, listing refused (AccessDeniedException): first" in text, text
    assert (
        "not checked, profile listing refused (AccessDeniedException): second" in text
    ), text
