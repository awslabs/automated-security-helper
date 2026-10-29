# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The results schema admits a results file whose stored configuration keeps an
environment reference in a fixed-choice field.

A scan records its configuration in its results file with each value the
configuration's files read from the environment kept as the reference the file
wrote (``${VAR}``), never the value. A fixed-choice field such as
``global_settings.severity_threshold`` cannot hold a reference, so the load
reads the field with its default and warns (``AshAggregatedResults
.validate_ash_config``, ``config/recorded_config.py``). The results schema
listed the choices alone there, so it called invalid a file ASH itself writes
and reads. It now admits the reference beside the choices, for the
configuration's models only: a fixed-choice field elsewhere in the results
(the CycloneDX ``bomFormat``) keeps its choices alone, as the load does.
"""

from __future__ import annotations

import jsonschema
import pytest

from automated_security_helper.schemas.generate_schemas import (
    ENV_REFERENCE_JSON_SCHEMA,
    generate_schemas,
)

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def results_schema() -> dict:
    return generate_schemas("dict")["AshAggregatedResults"]


def _validator_for(results_schema: dict, definition: str) -> jsonschema.Validator:
    """A validator for one ``$defs`` entry, with the whole schema's definitions."""
    schema = {"$ref": f"#/$defs/{definition}", "$defs": results_schema["$defs"]}
    return jsonschema.Draft202012Validator(schema)


@pytest.mark.parametrize(
    "reference",
    [
        "${ASH_SEVERITY_THRESHOLD}",
        "${ASH_SEVERITY_THRESHOLD:MEDIUM}",
        "!ENV ${ASH_SEVERITY_THRESHOLD}",
    ],
)
def test_a_recorded_reference_in_severity_threshold_is_valid(results_schema, reference):
    validator = _validator_for(results_schema, "AshConfigGlobalSettingsSection")
    assert validator.is_valid({"severity_threshold": reference}), sorted(
        error.message
        for error in validator.iter_errors({"severity_threshold": reference})
    )


def test_control_a_choice_and_a_non_choice_keep_their_verdicts(results_schema):
    validator = _validator_for(results_schema, "AshConfigGlobalSettingsSection")
    assert validator.is_valid({"severity_threshold": "MEDIUM"})
    assert not validator.is_valid({"severity_threshold": "BOGUS"})
    assert not validator.is_valid({"severity_threshold": "$ASH_SEVERITY_THRESHOLD"})


def test_a_fixed_choice_field_outside_the_configuration_stays_strict(results_schema):
    validator = _validator_for(results_schema, "CycloneDXReport")
    assert validator.is_valid({"bomFormat": "CycloneDX", "specVersion": "1.6"})
    assert not validator.is_valid({"bomFormat": "${BOM_FORMAT}", "specVersion": "1.6"})


def test_the_reference_branch_is_the_shared_one(results_schema):
    section = results_schema["$defs"]["AshConfigGlobalSettingsSection"]
    branches = section["properties"]["severity_threshold"]["anyOf"]
    assert ENV_REFERENCE_JSON_SCHEMA in branches
    (choices,) = [branch for branch in branches if "enum" in branch]
    assert choices["enum"] == ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
