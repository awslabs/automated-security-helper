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

from decimal import Decimal

import jsonschema
import pytest
from pydantic import BaseModel, Field

from automated_security_helper.schemas.generate_schemas import (
    ConfigFileJsonSchema,
    generate_schemas,
)

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


class _Constrained(BaseModel):
    """One field of each string-like kind the config schema has to treat."""

    free: str = "x"
    patterned: str = Field("abc", pattern=r"^[a-z]+$")
    sized: str = Field("abc", min_length=2)
    amount: Decimal = Decimal("1.5")


@pytest.fixture(scope="module")
def constrained_validator() -> jsonschema.Validator:
    schema = _Constrained.model_json_schema(schema_generator=ConfigFileJsonSchema)
    return jsonschema.Draft202012Validator(schema)


@pytest.mark.parametrize("field", ["free", "patterned", "sized", "amount"])
def test_a_reference_in_a_constrained_or_decimal_field_is_valid(
    constrained_validator, field
):
    """The reference is not the value a pattern, a length or a number describes,
    but the loader resolves it before the field is validated."""
    assert constrained_validator.is_valid({field: "${ASH_VALUE:fallback}"})


@pytest.mark.parametrize(
    "document",
    [{"patterned": "ABC1"}, {"sized": "x"}, {"amount": "not a number"}],
    ids=["patterned", "sized", "amount"],
)
def test_control_a_constrained_value_that_is_not_a_reference_stays_invalid(
    constrained_validator, document
):
    assert not constrained_validator.is_valid(document)


def test_control_a_constrained_value_that_fits_stays_valid(constrained_validator):
    assert constrained_validator.is_valid(
        {"patterned": "abc", "sized": "ab", "amount": "2.5"}
    )


def test_a_reference_in_a_constrained_string_field_is_valid(config_validator):
    """A string field with a pattern (bandit's ``confidence_level``) described
    the pattern alone, so a reference the loader resolves read as invalid, the
    same defect as a fixed-choice field's. The reference is admitted beside the
    constrained string; a literal outside the pattern is still refused."""
    document = {
        "project_name": "x",
        "scanners": {
            "bandit": {"options": {"confidence_level": "${ASH_BANDIT_CONFIDENCE}"}}
        },
    }
    assert _messages(config_validator, document) == []
    literal = {
        "project_name": "x",
        "scanners": {"bandit": {"options": {"confidence_level": "high"}}},
    }
    assert _messages(config_validator, literal) == []
    outside = {
        "project_name": "x",
        "scanners": {"bandit": {"options": {"confidence_level": "bogus"}}},
    }
    assert _messages(config_validator, outside) != []


def _reference_branch(section: dict) -> dict:
    """The environment-reference branch of ``severity_threshold`` in a schema's
    global-settings section: the string branch with a pattern."""
    branches = section["properties"]["severity_threshold"]["anyOf"]
    (reference,) = [branch for branch in branches if "pattern" in branch]
    return reference


def test_the_reference_branch_says_the_loader_resolves_it(schemas):
    """The configuration file's branch describes what happens to a reference
    there: the loader resolves it. The results schema's branch says the field is
    read with its default, which is true of a stored results file and false of a
    configuration file, so the two schemas carry different descriptions. Read
    at the field, not as a phrase anywhere in the document, so a field
    description that happens to use the words changes nothing here."""
    from automated_security_helper.schemas.generate_schemas import (
        CONFIG_FILE_REFERENCE_JSON_SCHEMA,
        ENV_REFERENCE_JSON_SCHEMA,
    )

    in_config = _reference_branch(
        schemas["AshConfig"]["$defs"]["AshConfigGlobalSettingsSection"]
    )
    in_results = _reference_branch(
        schemas["AshAggregatedResults"]["$defs"]["AshConfigGlobalSettingsSection"]
    )
    assert in_config == CONFIG_FILE_REFERENCE_JSON_SCHEMA
    assert in_results == ENV_REFERENCE_JSON_SCHEMA
    assert in_config["pattern"] == in_results["pattern"]
    assert in_config["description"] != in_results["description"]
    assert "resolved to the variable's value" in in_config["description"]
    assert "read with its default" in in_results["description"]
