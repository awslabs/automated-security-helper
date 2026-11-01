# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A Bedrock model id a config file sets is read as the environment one is.

``ASH_BEDROCK_MODEL_ID`` is read without the whitespace around it, and a blank
value is the built-in model id (see
``test_a_blank_bedrock_model_id_is_unset_and_no_redaction_needle.py``). That read
sits in the option's default factory, which pydantic does not run for a value a
config file or ``--config-overrides`` sets. Such a value reached the options as
written: a blank ``model_id`` (or ``${ASH_BEDROCK_MODEL_ID}`` with the variable
blank) went to Converse as a model named by spaces, and a padded id kept its
padding where the same id from the environment lost it, so the two sources gave
different ids.

Nothing here reaches AWS: the tests build the options and the reporter config
from dicts, the shape a loaded config file hands them.
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporterConfig,
    BedrockSummaryReporterConfigOptions,
)

pytestmark = pytest.mark.unit

BLANKS = ["", " ", "   ", "\t"]
BUILT_IN_MODEL_ID = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
OTHER_MODEL_ID = "eu.example.model-v1:0"


@pytest.fixture(autouse=True)
def _no_bedrock_model_variable(monkeypatch):
    monkeypatch.delenv("ASH_BEDROCK_MODEL_ID", raising=False)


@pytest.mark.parametrize("blank", BLANKS, ids=repr)
def test_a_blank_model_id_in_the_options_is_the_built_in_model_id(blank):
    options = BedrockSummaryReporterConfigOptions.model_validate({"model_id": blank})

    assert options.model_id == BUILT_IN_MODEL_ID


@pytest.mark.parametrize("blank", BLANKS, ids=repr)
def test_a_blank_model_id_in_the_reporter_section_of_a_config_is_the_built_in(
    blank,
):
    config = BedrockSummaryReporterConfig.model_validate(
        {"options": {"model_id": blank}}
    )

    assert config.options.model_id == BUILT_IN_MODEL_ID


def test_a_padded_model_id_in_a_config_is_kept_without_the_padding():
    config = BedrockSummaryReporterConfig.model_validate(
        {"options": {"model_id": f"  {OTHER_MODEL_ID}\t"}}
    )

    assert config.options.model_id == OTHER_MODEL_ID


def test_the_config_file_and_the_environment_give_one_model_id(monkeypatch):
    padded = f" {OTHER_MODEL_ID} "
    monkeypatch.setenv("ASH_BEDROCK_MODEL_ID", padded)

    from_environment = BedrockSummaryReporterConfigOptions().model_id
    from_config = BedrockSummaryReporterConfigOptions.model_validate(
        {"model_id": padded}
    ).model_id

    assert from_environment == from_config == OTHER_MODEL_ID


def test_a_model_id_without_padding_is_kept_as_written():
    """The control: a plain id passes through unchanged."""
    options = BedrockSummaryReporterConfigOptions.model_validate(
        {"model_id": OTHER_MODEL_ID}
    )

    assert options.model_id == OTHER_MODEL_ID


def test_a_model_id_that_is_no_string_is_still_refused():
    """The control: only a string is cleaned up; any other type is the field's
    to refuse, as before."""
    with pytest.raises(ValidationError):
        BedrockSummaryReporterConfigOptions.model_validate({"model_id": 5})
