# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value left as text is found when it sits under a key read from the
environment.

The writer refuses to write a config that would hold a value its files read from
the environment as text. It finds each such value in the record by the path its
file's rewrite names, and a value under a key read from the environment is named
by that key's resolved text. The record renames the key to the reference its
file wrote after it records the values, so the lookup by the resolved text found
nothing and the value under the key was never checked. The lookup now follows
the rename.

The config is built in memory, with the rewrites that record the key and the
value. The variables are left unset, so a reference cannot be resolved back to
the text the config holds: the value stays text in the record.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_validator import EnvironmentRewrite
from automated_security_helper.config.config_writer import (
    render_config_file_as_written,
)

pytestmark = pytest.mark.unit

SECTION_VARIABLE = "ASH_TEST_SECTION_NAME"
OPTION_VARIABLE = "ASH_TEST_OPTION_NAME"
SECTION = "community-demo-scanner"
SECTION_REFERENCE = "${" + SECTION_VARIABLE + "}"
OPTION_REFERENCE = "${" + OPTION_VARIABLE + "}"
READ = "needle"


@pytest.fixture(autouse=True)
def _variables_unset(monkeypatch):
    monkeypatch.delenv(SECTION_VARIABLE, raising=False)
    monkeypatch.delenv(OPTION_VARIABLE, raising=False)


def _config_with_a_keyed_option(held: str) -> AshConfig:
    """A config with an undeclared scanner section whose option is ``held``. Its
    file read the section's name and the option's value ``READ`` from the
    environment."""
    config = AshConfig.model_validate(
        {
            "project_name": "t",
            "scanners": {SECTION: {"enabled": True, "options": {"mode": held}}},
        }
    )
    key = EnvironmentRewrite(
        "key", ("scanners",), SECTION, SECTION_REFERENCE, SECTION, SECTION_REFERENCE
    )
    value = EnvironmentRewrite(
        "value",
        ("scanners", SECTION, "options", "mode"),
        READ,
        OPTION_REFERENCE,
        READ,
        OPTION_REFERENCE,
    )
    config._written_references = [key, value]
    return config


def test_a_value_left_as_text_under_a_key_read_from_the_environment_is_refused(
    tmp_path,
):
    config = _config_with_a_keyed_option(READ + "-extra")

    with pytest.raises(RuntimeError, match="was not written"):
        render_config_file_as_written(tmp_path / "session.yaml", config, [])


def test_a_value_recorded_as_a_reference_under_such_a_key_is_written(tmp_path):
    config = _config_with_a_keyed_option(READ)

    text = render_config_file_as_written(tmp_path / "session.yaml", config, [])

    assert "mode: " + OPTION_REFERENCE in text, text
    assert SECTION_REFERENCE in text, text
    assert SECTION not in text, text


def test_a_value_left_as_text_under_a_plain_key_is_refused(tmp_path):
    config = AshConfig.model_validate({"project_name": READ + "-extra"})
    value = EnvironmentRewrite(
        "value", ("project_name",), READ, OPTION_REFERENCE, READ, OPTION_REFERENCE
    )
    config._written_references = [value]

    with pytest.raises(RuntimeError, match="was not written"):
        render_config_file_as_written(tmp_path / "session.yaml", config, [])
