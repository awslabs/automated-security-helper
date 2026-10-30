# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The configuration schema admits a file that reads a value from the environment.

A configuration file may write any scalar as a reference to the environment
(``${VAR}``, ``${VAR:default}``, a tagged ``!ENV ${VAR}``), and the loader
resolves it to the variable's value before the field is validated. The published
``AshConfig.json`` was pydantic's own schema, which lists a fixed-choice field's
choices alone and a boolean field's type alone, so an editor validating a file
against it (``config_writer.SCHEMA_COMMENT`` points every saved file at it) called
invalid a file ASH itself reads and writes. Each such field now admits the
reference beside its own schema; a non-reference value keeps its outcome, and
the workspace policy file, which resolves no reference, keeps pydantic's schema.
"""

from __future__ import annotations

import jsonschema
import pytest

from automated_security_helper.schemas.generate_schemas import generate_schemas

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def schemas() -> dict:
    return generate_schemas("dict")


@pytest.fixture(scope="module")
def config_validator(schemas) -> jsonschema.Validator:
    return jsonschema.Draft202012Validator(schemas["AshConfig"])


def _messages(validator: jsonschema.Validator, document: dict) -> list[str]:
    return sorted(error.message for error in validator.iter_errors(document))


@pytest.mark.parametrize(
    "reference",
    [
        "${ASH_SEVERITY_THRESHOLD}",
        "${ASH_SEVERITY_THRESHOLD:MEDIUM}",
        "!ENV ${ASH_SEVERITY_THRESHOLD}",
    ],
)
def test_a_reference_in_a_fixed_choice_field_is_valid(config_validator, reference):
    document = {
        "project_name": "x",
        "global_settings": {"severity_threshold": reference},
    }
    assert _messages(config_validator, document) == []


def test_a_reference_in_a_boolean_field_is_valid(config_validator):
    document = {"project_name": "x", "fail_on_findings": "${ASH_FAIL_ON_FINDINGS}"}
    assert _messages(config_validator, document) == []


def test_control_a_choice_and_a_non_choice_keep_their_outcomes(config_validator):
    choice = {"project_name": "x", "global_settings": {"severity_threshold": "MEDIUM"}}
    assert _messages(config_validator, choice) == []
    not_a_choice = {
        "project_name": "x",
        "global_settings": {"severity_threshold": "medium-ish"},
    }
    assert _messages(config_validator, not_a_choice) != []
    not_a_boolean = {"project_name": "x", "fail_on_findings": "yes"}
    assert _messages(config_validator, not_a_boolean) != []


def test_control_the_workspace_policy_schema_keeps_its_choices_alone(schemas):
    """The workspace policy file resolves no reference (``ash_workspace_config``),
    so a reference there stays invalid, as the loader reads it."""
    validator = jsonschema.Draft202012Validator(schemas["AshWorkspaceConfig"])
    assert validator.is_valid({"workspace": {"max_severity_threshold": "HIGH"}})
    assert not validator.is_valid(
        {"workspace": {"max_severity_threshold": "${ASH_MAX_SEVERITY}"}}
    )
