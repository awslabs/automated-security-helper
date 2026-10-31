# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A blank AWS_REGION or AWS_PROFILE is unset for the Bedrock reporter too.

The other three AWS reporters treat a blank environment value as unset (see
``test_a_blank_environment_value_is_unset_in_the_aws_reporter_defaults.py``).
The Bedrock options read the variables with ``os.environ.get(name, default)``,
which returns a blank value as it is: ``AWS_REGION=""`` reached the region
pattern as an empty name and refused the whole configuration (exit 3), and a
blank ``AWS_PROFILE`` reached botocore as a profile named by spaces.

Nothing here reaches AWS: the tests build the options model.
"""

import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporterConfigOptions,
)

pytestmark = pytest.mark.unit

BLANKS = ["", " ", "   ", "\t"]


@pytest.fixture(autouse=True)
def _no_aws_environment(monkeypatch):
    for name in ("AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("blank", BLANKS, ids=repr)
def test_a_blank_region_does_not_hide_the_default_region(monkeypatch, blank):
    monkeypatch.setenv("AWS_REGION", blank)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-2")

    assert BedrockSummaryReporterConfigOptions().aws_region == "eu-west-2"


@pytest.mark.parametrize("blank", BLANKS, ids=repr)
def test_a_blank_region_with_no_default_falls_back_to_the_built_in_region(
    monkeypatch, blank
):
    monkeypatch.setenv("AWS_REGION", blank)
    monkeypatch.setenv("AWS_DEFAULT_REGION", blank)

    assert BedrockSummaryReporterConfigOptions().aws_region == "us-east-1"


@pytest.mark.parametrize("blank", BLANKS, ids=repr)
def test_a_blank_profile_is_no_profile(monkeypatch, blank):
    monkeypatch.setenv("AWS_PROFILE", blank)

    assert BedrockSummaryReporterConfigOptions().aws_profile is None


def test_values_with_text_in_them_are_kept(monkeypatch):
    """The control: the change does not touch a real region or profile."""
    monkeypatch.setenv("AWS_REGION", "ap-south-1")
    monkeypatch.setenv("AWS_PROFILE", "reporting")

    options = BedrockSummaryReporterConfigOptions()

    assert options.aws_region == "ap-south-1"
    assert options.aws_profile == "reporting"


def test_with_nothing_set_the_region_is_the_built_in_one_and_no_profile():
    options = BedrockSummaryReporterConfigOptions()

    assert options.aws_region == "us-east-1"
    assert options.aws_profile is None
