# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""What the model listing keeps, which fallback a non-US model gets, and which
spelling a check hands its caller.

Three behaviors of ``aws_utils``, each pinned by a test that failed at the base:
a LEGACY foundation model, which Bedrock still serves, was dropped from the
listing as if it were gone; a model under a non-US inference-profile area fell
straight to the ``us.`` default model, which its region does not list; and a
case-insensitive match answered True without the spelling the listing carries,
so the caller kept calling Converse with its own.

No test here calls AWS: the control plane is a MagicMock that answers by plan.
"""

from unittest.mock import MagicMock

import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
    check_model_id,
    get_available_models,
    get_fallback_model,
    validate_bedrock_model,
)

pytestmark = pytest.mark.unit

LISTED = "test-vendor.test-model-v1:0"


def _summary(model_id, status):
    return {
        "modelId": model_id,
        "modelName": "a model",
        "modelArn": f"arn:aws:bedrock:eu-west-1::foundation-model/{model_id}",
        "providerName": "test-vendor",
        "modelLifecycle": {"status": status},
        "inputModalities": ["TEXT"],
        "outputModalities": ["TEXT"],
        "inferenceTypesSupported": ["ON_DEMAND"],
    }


def _control_plane(*summaries):
    client = MagicMock()
    client.list_inference_profiles.return_value = {"inferenceProfileSummaries": []}
    client.list_foundation_models.return_value = {"modelSummaries": list(summaries)}
    return client


# ---------------------------------------------------------------------------
# A LEGACY model is still served
# ---------------------------------------------------------------------------


def test_a_legacy_model_the_region_still_serves_is_listed():
    """Bedrock marks a model LEGACY while it is being retired and keeps
    answering Converse for it; the listing used to keep ACTIVE alone."""
    models = get_available_models(_control_plane(_summary(LISTED, "LEGACY")))

    assert [model["modelId"] for model in models] == [LISTED]


def test_an_active_model_is_listed_as_before():
    """The control."""
    models = get_available_models(_control_plane(_summary(LISTED, "ACTIVE")))

    assert [model["modelId"] for model in models] == [LISTED]


def test_a_model_with_another_lifecycle_is_not_listed():
    """The other control: a status that is neither is not served."""
    models = get_available_models(_control_plane(_summary(LISTED, "RETIRED")))

    assert list(models) == []


# ---------------------------------------------------------------------------
# A fallback follows the configured model's area
# ---------------------------------------------------------------------------


def test_a_fallback_for_a_non_us_profile_is_under_the_same_area():
    """The chains are written as ``us.`` profiles; a model under ``eu.`` gets
    the next model of its chain under ``eu.``, not the ``us.`` default."""
    fallback = get_fallback_model("eu.anthropic.claude-3-7-sonnet-20250219-v1:0")

    assert fallback == "eu.anthropic.claude-3-5-sonnet-20240620-v1:0", fallback


def test_the_default_fallback_is_under_the_configured_models_area():
    """A model of no known family under ``apac.`` falls to the default model
    under ``apac.``, which that region can route."""
    fallback = get_fallback_model("apac.test-vendor.test-model-v1:0")

    assert fallback == "apac.amazon.nova-pro-v1:0", fallback


def test_a_us_profile_keeps_its_chain():
    """The control: the ``us.`` chains answer as before."""
    assert get_fallback_model("us.amazon.nova-pro-v1:0") == "us.amazon.nova-lite-v1:0"


def test_a_model_with_no_area_keeps_the_us_default():
    """The other control: an id with no area prefix (an on-demand id, or an
    opaque one) is looked up as it is and falls to the ``us.`` default."""
    assert get_fallback_model("test-model-with-no-area") == "us.amazon.nova-pro-v1:0"
    assert get_fallback_model("amazon.titan-text-lite-v1") == "us.amazon.nova-pro-v1:0"


def test_an_area_with_no_mirrored_chain_keeps_the_us_candidates():
    """``global.``, ``jp.`` and the like have no inference profiles for the
    chain models, so a model under one is looked up by its family and gets the
    chain's ``us.`` spelling, which the US regions list. The configured
    model's area never becomes the candidates' area here."""
    fallback = get_fallback_model("global.anthropic.claude-sonnet-4-20250514-v1:0")

    assert fallback == "us.anthropic.claude-3-7-sonnet-20250219-v1:0", fallback
    assert get_fallback_model("jp.test-vendor.test-model-v1:0") == (
        "us.amazon.nova-pro-v1:0"
    )


def test_an_upper_cased_area_gets_lower_cased_candidates():
    """The area is read case-insensitively and the candidates carry the
    area's own spelling, never the operator's casing: Converse knows
    ``us.amazon.nova-pro-v1:0``, not ``US.amazon.nova-pro-v1:0``."""
    fallback = get_fallback_model("US.anthropic.claude-sonnet-4-20250514-v1:0")

    assert fallback == "us.anthropic.claude-3-7-sonnet-20250219-v1:0", fallback
    assert get_fallback_model("EU.test-vendor.test-model-v1:0") == (
        "eu.amazon.nova-pro-v1:0"
    )


# ---------------------------------------------------------------------------
# A check names the listed spelling
# ---------------------------------------------------------------------------


def test_a_case_insensitive_match_names_the_listed_spelling():
    """The listing spells the model one way and the config another, differing
    in case. The check is True, and its ``model_id`` is the listing's spelling:
    the one Converse knows."""
    check = validate_bedrock_model(
        _control_plane(_summary(LISTED, "ACTIVE")), LISTED.upper()
    )

    assert check[0] is True
    assert check_model_id(check) == LISTED


def test_an_exact_match_names_the_model_as_checked():
    """The control."""
    check = validate_bedrock_model(_control_plane(_summary(LISTED, "ACTIVE")), LISTED)

    assert check[0] is True
    assert check_model_id(check) == LISTED


def test_a_false_check_names_no_model():
    check = validate_bedrock_model(
        _control_plane(_summary(LISTED, "ACTIVE")), "test-vendor.other-model-v1:0"
    )

    assert check[0] is False
    assert check_model_id(check) is None
    assert check_model_id((False, "a pair a caller built")) is None
