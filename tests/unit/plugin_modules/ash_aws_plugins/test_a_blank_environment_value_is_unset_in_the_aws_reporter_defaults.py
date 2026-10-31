# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A blank environment value is unset, whether it is empty or only spaces.

The three AWS reporters read their region, profile and names from the
environment when the options are built. An empty value was already treated as
unset; a value of one space was not, so ``AWS_REGION=" "`` hid
``AWS_DEFAULT_REGION`` and a blank profile or name reached the AWS client as a
name of its own. The options model maps a blank value to None on every path
(the config file and ``--config-overrides`` already did), and the default
factories now do the same for the environment.

Nothing here reaches AWS: the tests build option models and read fields.
"""

import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
    CloudWatchLogsReporterConfigOptions,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3ReporterConfigOptions,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    SecurityHubReporterConfigOptions,
)

OPTION_MODELS = [
    S3ReporterConfigOptions,
    SecurityHubReporterConfigOptions,
    CloudWatchLogsReporterConfigOptions,
]
BLANKS = ["", " ", "   ", "\t"]


@pytest.fixture(autouse=True)
def _no_aws_environment(monkeypatch):
    for name in (
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_PROFILE",
        "ASH_S3_BUCKET_NAME",
        "ASH_CLOUDWATCH_LOG_GROUP_NAME",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.unit
@pytest.mark.parametrize("model", OPTION_MODELS, ids=lambda m: m.__name__)
@pytest.mark.parametrize("blank", BLANKS, ids=repr)
def test_a_blank_region_does_not_hide_the_default_region(monkeypatch, model, blank):
    monkeypatch.setenv("AWS_REGION", blank)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-2")

    assert model().aws_region == "eu-west-2"


@pytest.mark.unit
@pytest.mark.parametrize("model", OPTION_MODELS, ids=lambda m: m.__name__)
def test_a_blank_region_with_no_default_is_unset(monkeypatch, model):
    monkeypatch.setenv("AWS_REGION", " ")

    assert model().aws_region is None


@pytest.mark.unit
@pytest.mark.parametrize(
    "model", [S3ReporterConfigOptions, SecurityHubReporterConfigOptions]
)
@pytest.mark.parametrize("blank", BLANKS, ids=repr)
def test_a_blank_profile_is_no_profile(monkeypatch, model, blank):
    monkeypatch.setenv("AWS_PROFILE", blank)

    assert model().aws_profile is None


@pytest.mark.unit
@pytest.mark.parametrize("blank", BLANKS, ids=repr)
def test_a_blank_bucket_name_is_unset(monkeypatch, blank):
    monkeypatch.setenv("ASH_S3_BUCKET_NAME", blank)

    assert S3ReporterConfigOptions().bucket_name is None


@pytest.mark.unit
@pytest.mark.parametrize("blank", BLANKS, ids=repr)
def test_a_blank_log_group_name_is_unset(monkeypatch, blank):
    monkeypatch.setenv("ASH_CLOUDWATCH_LOG_GROUP_NAME", blank)

    assert CloudWatchLogsReporterConfigOptions().log_group_name is None


@pytest.mark.unit
def test_a_value_with_text_in_it_is_kept_as_written(monkeypatch):
    """The control: a value with text in it is not changed."""
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_PROFILE", "reporting")

    for model in (S3ReporterConfigOptions, SecurityHubReporterConfigOptions):
        options = model()
        assert options.aws_region == "us-east-1"
        assert options.aws_profile == "reporting"
