# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The Bedrock reporter's top_p option has Converse's range, as temperature does.

Converse takes a topP of 0 to 1 (InferenceConfiguration: "Valid Range: Minimum
value of 0. Maximum value of 1."). A value outside it is copied to every fallback
candidate and refused by each, so the walk exhausts for nothing; it is a
configuration error instead, like a temperature outside its range.
"""

import pydantic
import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporterConfigOptions,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("value", [-0.1, 1.5, 5, float("nan"), float("inf")])
def test_a_top_p_outside_converses_range_is_refused(value):
    """RED at the base: any float was accepted."""
    with pytest.raises(pydantic.ValidationError):
        BedrockSummaryReporterConfigOptions(top_p=value)


@pytest.mark.parametrize("value", [0.0, 0.9, 1.0])
def test_a_top_p_in_converses_range_is_accepted(value):
    options = BedrockSummaryReporterConfigOptions(top_p=value)

    assert options.top_p == value


def test_the_default_top_p_is_unchanged():
    assert BedrockSummaryReporterConfigOptions().top_p == 0.9
