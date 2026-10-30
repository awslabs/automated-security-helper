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

import json
import re

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


def test_a_required_fixed_choice_field_does_not_admit_a_reference(results_schema):
    """A Literal with no default has no default to fall back to.

    The load drops a fixed-choice field that holds a reference and reads the
    model again; a required field then fails as missing and the whole results
    file is refused (recorded_config.without_unreadable_references), so the
    schema refuses it too.
    """
    validator = _validator_for(results_schema, "ContentDbStalenessOverride")
    entry = {
        "database": "trivy-db",
        "policy": "warn",
        "expiration": "2030-01-01",
        "reason": "upstream paused",
    }
    assert validator.is_valid(entry)
    assert not validator.is_valid({**entry, "policy": "${ASH_DB_POLICY}"})
    policy = results_schema["$defs"]["ContentDbStalenessOverride"]["properties"][
        "policy"
    ]
    assert "anyOf" not in policy, policy


def test_an_output_formats_entry_admits_a_reference(results_schema):
    """The load drops a whole fixed-choice list that holds a reference entry.

    ``output_formats`` entries are refused by their own validator, as a value
    error at the entry, and recorded_config._a_choice_refused admits exactly
    that location, so the list is read as its default. The schema admits the
    reference on each entry and on the single-value form, beside the enum.
    """
    validator = _validator_for(results_schema, "AshConfig")
    assert validator.is_valid({"output_formats": ["sarif", "${ASH_FORMAT}"]})
    assert validator.is_valid({"output_formats": "${ASH_FORMAT}"})
    assert validator.is_valid({"output_formats": ["sarif"]})
    assert not validator.is_valid({"output_formats": [5]})
    # The results schema is generated in serialization mode, where the entries
    # render as the strings a dump writes and the Enum has no definition of its
    # own; a definition it does have is left as pydantic emits it.
    enum = results_schema["$defs"].get("ExportFormat")
    assert enum is None or "anyOf" not in enum, enum


def test_control_a_true_false_field_keeps_refusing_a_reference(results_schema):
    """The record never writes a reference in a true/false field
    (config_validator.typed_from is never true for a bool, so the typed value is
    recorded), and the load refuses one as any other wrong value
    (recorded_config._a_choice_refused admits no bool refusal)."""
    validator = _validator_for(results_schema, "AshConfig")
    assert not validator.is_valid({"fail_on_findings": "${ASH_FAIL}"})
    assert validator.is_valid({"fail_on_findings": False})


def test_a_number_field_with_a_default_admits_a_reference(results_schema):
    """The record writes a reference in a number field's place
    (config_validator.record_of_config, typed_from: a timeout read from the
    environment is never written in clear), and the load reads such a field as
    its default (recorded_config._NUMBER_REFUSALS), so the schema admits it."""
    validator = _validator_for(results_schema, "BanditScannerConfigOptions")
    assert validator.is_valid({"install_timeout": "${ASH_INSTALL_TIMEOUT}"})
    assert validator.is_valid({"install_timeout": 600})
    assert not validator.is_valid({"install_timeout": "ten minutes"})


def test_the_shape_keeping_serializers_are_exactly_the_models_any_typed_ones():
    """The generator describes a field by its own schema only for the serializers
    named in SHAPE_KEEPING_SERIALIZERS. A serializer added to the results model
    with no return type, or ``Any``, must be listed there when it keeps the
    field's shape, or the field reads as "anything"; a reshaping one must not be.
    This test fails on either omission so the choice is made on purpose."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.schemas.generate_schemas import (
        SHAPE_KEEPING_SERIALIZERS,
        StoredResultsJsonSchema,
        _serializer_name,
    )

    any_typed: set[str] = set()

    class Recording(StoredResultsJsonSchema):
        def ser_schema(self, schema):
            if schema.get("type") in ("function-plain", "function-wrap"):
                name = _serializer_name(schema)
                return_schema = schema.get("return_schema")
                if name.startswith("AshAggregatedResults.") and (
                    return_schema is None or return_schema.get("type") == "any"
                ):
                    any_typed.add(name)
            return super().ser_schema(schema)

    AshAggregatedResults.model_json_schema(
        schema_generator=Recording, mode="serialization"
    )
    assert any_typed == set(SHAPE_KEEPING_SERIALIZERS)


@pytest.mark.parametrize(
    "text",
    ["${X}", "${X:default}", "!ENV ${X}", "${X:a}b}", "${long_name_1:}"],
)
def test_the_schema_pattern_and_the_loader_agree_on_a_reference(text):
    from automated_security_helper.config.recorded_config import _is_reference

    assert re.match(ENV_REFERENCE_JSON_SCHEMA["pattern"], text)
    assert _is_reference(text)


@pytest.mark.parametrize("text", ["BOGUS", "$X", "${}", "MEDIUM", ""])
def test_the_schema_pattern_and_the_loader_agree_on_a_non_reference(text):
    from automated_security_helper.config.recorded_config import _is_reference

    assert not re.match(ENV_REFERENCE_JSON_SCHEMA["pattern"], text)
    assert not _is_reference(text)


def test_the_schema_pattern_is_anchored_at_the_end():
    """The one place the two differ: the loader reads a reference as a prefix.

    ash_config.ENV_REFERENCE_PATTERN is matched with re.match and has no end
    anchor, so ``${X}BOGUS`` is a reference to the load. The schema's copy
    ends at the closing brace: the generated document never holds a reference
    with trailing text, and admitting one would admit any string that starts
    like a reference.
    """
    from automated_security_helper.config.recorded_config import _is_reference

    for text in ("${X}BOGUS", "${A B}"):
        assert not re.match(ENV_REFERENCE_JSON_SCHEMA["pattern"], text), text
        assert _is_reference(text), text


def test_the_stored_configuration_is_described_in_serialization_mode(results_schema):
    """The results schema names the configuration model it stores, and keeps
    the computed fields serialization mode exists for.

    ``ash_config`` is written through a wrap serializer annotated ``Any``; in
    serialization mode pydantic would describe the field by that annotation and
    the whole stored configuration, with every reference rule, would read as
    "anything".
    """
    ash_config = results_schema["properties"]["ash_config"]
    refs = {branch.get("$ref") for branch in ash_config.get("anyOf", [ash_config])}
    assert "#/$defs/AshConfig" in refs, ash_config
    assert "AshConfigGlobalSettingsSection" in results_schema["$defs"]
    assert "skipped_projects" in json.dumps(results_schema), (
        "the computed field serialization mode exists for is missing"
    )


def test_the_reference_branch_is_the_shared_one(results_schema):
    section = results_schema["$defs"]["AshConfigGlobalSettingsSection"]
    branches = section["properties"]["severity_threshold"]["anyOf"]
    assert ENV_REFERENCE_JSON_SCHEMA in branches
    (choices,) = [branch for branch in branches if "enum" in branch]
    assert choices["enum"] == ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
