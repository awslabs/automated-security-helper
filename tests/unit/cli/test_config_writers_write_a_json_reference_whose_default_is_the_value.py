# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A JSON session config is written when a reference's own default is the value.

The writer refuses to write a config that would hold a value its files read from
the environment as text. In YAML a reference the record wrote is a typed string,
so the check skips it. A JSON record has no such type: each reference is a plain
string, and the check looked for the value inside every plain string at the
place of a reference. A reference whose default is the variable's value
(``${ASH_REGION:us-east-1}`` read as ``us-east-1``) holds the value in its own
text, so a correctly recorded config was refused. The check takes the reference
out of the string before it looks for the value, and still refuses a string that
holds the value beside the reference.

The config is built in memory, with the rewrite that records the reference.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_validator import EnvironmentRewrite
from automated_security_helper.config.config_writer import (
    _refuse_a_value_left_as_text,
    render_config_file_as_written,
)

pytestmark = pytest.mark.unit

VARIABLE = "ASH_TEST_SEVERITY_NAME"
LEVEL = "MEDIUM"
REFERENCE = "${" + VARIABLE + ":" + LEVEL + "}"


@pytest.fixture
def config() -> AshConfig:
    """A config whose project name is ``LEVEL``, which its file read from the
    environment as ``REFERENCE``."""
    built = AshConfig.model_validate({"project_name": LEVEL})
    rewrite = EnvironmentRewrite(
        "value", ("project_name",), LEVEL, REFERENCE, LEVEL, REFERENCE
    )
    built._written_references = [rewrite]
    return built


def test_a_json_config_holds_a_reference_whose_default_is_the_value(tmp_path, config):
    text = render_config_file_as_written(tmp_path / "session.json", config, [])

    assert json.loads(text)["project_name"] == REFERENCE, text


def test_a_string_that_holds_the_value_beside_the_reference_is_still_refused(config):
    with pytest.raises(RuntimeError, match="was not written"):
        _refuse_a_value_left_as_text({"project_name": REFERENCE + "/" + LEVEL}, config)


def test_a_string_that_is_the_value_alone_is_still_refused(config):
    with pytest.raises(RuntimeError, match="was not written"):
        _refuse_a_value_left_as_text({"project_name": LEVEL}, config)
