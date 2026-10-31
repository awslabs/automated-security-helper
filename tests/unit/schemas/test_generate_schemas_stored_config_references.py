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
    assert validator.is_valid({"output_formats": "sarif"})
    assert not validator.is_valid({"output_formats": [5]})


def test_an_output_formats_entry_that_is_not_a_format_is_refused(results_schema):
    """The enum survives serialization mode. The field is dumped through a
    serializer typed ``List[str]``, and described by that return type alone every
    string was a valid format, where the load refuses a name that is not one
    (``ash_config._export_format_name``; recorded_config admits only a reference
    there). The serializer is named in SHAPE_KEEPING_SERIALIZERS, so the enum is
    what the schema says; a wrong name is refused in the list and single forms."""
    validator = _validator_for(results_schema, "AshConfig")
    assert not validator.is_valid({"output_formats": ["not-a-format"]})
    assert not validator.is_valid({"output_formats": "not-a-format"})
    assert not validator.is_valid({"output_formats": ["sarif", "not-a-format"]})
    # The reference sits beside the enum at the field, never in the shared
    # definition, which is left as pydantic emits it.
    enum = results_schema["$defs"]["ExportFormat"]
    assert "anyOf" not in enum, enum
    assert "sarif" in enum["enum"]


def test_an_enum_field_with_a_default_admits_a_reference_in_a_stored_model():
    """The same rule as a Literal's, for an Enum field used directly."""
    from enum import Enum

    from automated_security_helper.base.options import PluginOptionsBase
    from automated_security_helper.schemas.generate_schemas import (
        StoredResultsJsonSchema,
    )

    class _Level(str, Enum):
        low = "low"
        high = "high"

    class _Options(PluginOptionsBase):
        level: _Level = _Level.low
        pinned: _Level

    schema = _Options.model_json_schema(
        schema_generator=StoredResultsJsonSchema, mode="serialization"
    )
    validator = jsonschema.Draft202012Validator(schema)
    assert validator.is_valid({"pinned": "high", "level": "${ASH_LEVEL}"})
    assert validator.is_valid({"pinned": "high", "level": "low"})
    assert not validator.is_valid({"pinned": "high", "level": "medium"})
    assert not validator.is_valid({"pinned": "${ASH_LEVEL}", "level": "low"}), (
        "a required Enum field has no default to fall back to"
    )
    assert "anyOf" not in schema["$defs"]["_Level"]


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


#: Serializers anywhere in the results tree that are declared ``-> Any`` (or
#: untyped) AND reshape their field, so they must NOT be in
#: SHAPE_KEEPING_SERIALIZERS and are described as "anything" on purpose. None
#: today; a serializer added later lands in one list or the other, never in
#: neither, or the test below fails.
RESHAPING_ANY_TYPED_SERIALIZERS: frozenset[str] = frozenset()

#: Serializers in SHAPE_KEEPING_SERIALIZERS whose return type is not Any: listed
#: because the return type hides what the dump writes (the enum behind the
#: names), not because it says nothing.
TYPED_SHAPE_KEEPING_SERIALIZERS = frozenset({"AshConfig._output_format_values"})

#: The serializer pydantic itself attaches to every ``Path`` field. It has no
#: return schema, so it looks untyped to the recorder below, but it is not the
#: product's to classify: the generator falls back to the field's own schema for
#: it, which is the string the dump writes. Its presence proves the recorder's
#: package filter excludes something real.
PYDANTIC_PATH_SERIALIZER = "GenerateSchema._path_schema.<locals>.ser_path"


def _serializer_module(schema) -> str:
    """The module that defines a function serializer's function, or ``""``."""
    function = schema.get("function")
    if isinstance(function, dict):
        function = function.get("function")
    return getattr(function, "__module__", "") or ""


def test_every_any_typed_serializer_in_the_results_tree_is_classified():
    """The generator describes a field by its own schema only for the serializers
    named in SHAPE_KEEPING_SERIALIZERS. A serializer with no return type, or
    ``Any``, on ANY model the results file holds (AshConfig, WorkspaceResults, a
    scanner's options, a base class whose qualname differs from the model's)
    must be listed there when it keeps the field's shape, or that part of the
    schema reads as "anything"; one that reshapes its field is listed in
    RESHAPING_ANY_TYPED_SERIALIZERS instead. Every such serializer the PRODUCT
    defines and that is met during the whole generation is classified on
    purpose, and every listed name was met, so the lists cannot fall out of
    date. Serializers pydantic attaches on its own (the ``Path`` one) are
    pydantic's, not the product's: they are counted apart and never classified."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.schemas.generate_schemas import (
        SHAPE_KEEPING_SERIALIZERS,
        StoredResultsJsonSchema,
        _serializer_name,
    )

    any_typed: set[str] = set()
    seen: set[str] = set()
    pydantics_own: set[str] = set()

    class Recording(StoredResultsJsonSchema):
        def ser_schema(self, schema):
            if schema.get("type") in ("function-plain", "function-wrap"):
                name = _serializer_name(schema)
                if not _serializer_module(schema).startswith(
                    "automated_security_helper"
                ):
                    pydantics_own.add(name)
                    return super().ser_schema(schema)
                seen.add(name)
                return_schema = schema.get("return_schema")
                if return_schema is None or return_schema.get("type") == "any":
                    any_typed.add(name)
            return super().ser_schema(schema)

    AshAggregatedResults.model_json_schema(
        schema_generator=Recording, mode="serialization"
    )
    assert any_typed, "no serializer was met: the recorder read nothing"
    assert PYDANTIC_PATH_SERIALIZER in pydantics_own, (
        "the package filter excluded nothing: the results tree has Path fields, "
        "so pydantic's own Path serializer must have been met and set apart"
    )
    unclassified = (
        any_typed - set(SHAPE_KEEPING_SERIALIZERS) - RESHAPING_ANY_TYPED_SERIALIZERS
    )
    assert unclassified == set(), unclassified
    assert set(SHAPE_KEEPING_SERIALIZERS) & RESHAPING_ANY_TYPED_SERIALIZERS == set()
    stale = set(SHAPE_KEEPING_SERIALIZERS) - seen
    assert stale == set(), stale
    assert set(SHAPE_KEEPING_SERIALIZERS) - any_typed == TYPED_SHAPE_KEEPING_SERIALIZERS


def _the_schema_admits(text: str) -> bool:
    """Whether a JSON Schema validator admits ``text`` as a reference.

    The schema's pattern is applied the way a validator applies it: unanchored,
    a search (python-jsonschema uses re.search), so a missing ``^`` or ``$`` in
    the pattern is visible here where ``re.match`` would hide the former.
    """
    return jsonschema.Draft202012Validator(ENV_REFERENCE_JSON_SCHEMA).is_valid(text)


@pytest.mark.parametrize(
    "text",
    ["${X}", "${X:default}", "!ENV ${X}", "${X:a}b}", "${long_name_1:}"],
)
def test_the_schema_pattern_and_the_loader_agree_on_a_reference(text):
    from automated_security_helper.config.recorded_config import _is_reference

    assert _the_schema_admits(text)
    assert _is_reference(text)


@pytest.mark.parametrize(
    "text", ["BOGUS", "$X", "${}", "MEDIUM", "", "BOGUS${X}", "x !ENV ${X}"]
)
def test_the_schema_pattern_and_the_loader_agree_on_a_non_reference(text):
    """``BOGUS${X}`` holds a reference after position 0: a pattern without its
    start anchor would admit it under a validator's search, and the loader's
    re.match refuses it, so this is the case that pins the ``^``."""
    from automated_security_helper.config.recorded_config import _is_reference

    assert not _the_schema_admits(text)
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

    assert not _the_schema_admits("${X}BOGUS")
    assert _is_reference("${X}BOGUS")


def test_the_schema_refuses_a_variable_name_the_loader_accepts():
    """A second, separate difference: the schema's ``\\w+`` name admits word
    characters only, while the loader's pattern takes ``${A B}`` as a reference.
    The record never writes such a name (a configuration file's reference names
    an environment variable, and a shell variable name holds no blank), so the
    schema's stricter name costs nothing; this test keeps the difference named
    rather than letting it hide inside the trailing-text case above."""
    from automated_security_helper.config.recorded_config import _is_reference

    assert not _the_schema_admits("${A B}")
    assert _is_reference("${A B}")
    assert _the_schema_admits("${A_B}")


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
    workspace = results_schema["$defs"]["WorkspaceResults"]["properties"]
    assert "skipped_projects" in workspace, (
        "the computed field serialization mode exists for is missing"
    )


def test_the_reference_branch_is_the_shared_one(results_schema):
    section = results_schema["$defs"]["AshConfigGlobalSettingsSection"]
    branches = section["properties"]["severity_threshold"]["anyOf"]
    assert ENV_REFERENCE_JSON_SCHEMA in branches
    (choices,) = [branch for branch in branches if "enum" in branch]
    assert choices["enum"] == ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
