# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The results schema admits an aliased field under its Python name where the
load does.

Every CycloneDX model with an aliased field (``bom-ref``, ``mime-type``) loads
it by its Python name too (``validate_by_name``), because a results file
written before those models dumped by alias holds ``bom_ref`` and
``mime_type``. The results schema is generated in serialization mode, which
named the alias alone, and the models forbid unknown keys, so the schema
refused the very files the load keeps. The generator now describes the Python
name beside the alias with the same schema, and a required aliased field is
required under either name.
"""

from __future__ import annotations

import jsonschema
import pytest
from pydantic import BaseModel, ConfigDict, Field

from automated_security_helper.schemas.generate_schemas import (
    StoredResultsJsonSchema,
    generate_schemas,
)

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def results_schema() -> dict:
    return generate_schemas("dict")["AshAggregatedResults"]


def _validator_for(results_schema: dict, definition: str) -> jsonschema.Validator:
    schema = {"$ref": f"#/$defs/{definition}", "$defs": results_schema["$defs"]}
    return jsonschema.Draft202012Validator(schema)


def test_a_nested_bom_ref_under_its_python_name_is_valid(results_schema):
    validator = _validator_for(results_schema, "OrganizationalContact")
    assert validator.is_valid({"bom_ref": "contact-1", "name": "n"})
    assert validator.is_valid({"bom-ref": "contact-1", "name": "n"})


def test_control_an_unknown_key_is_still_refused(results_schema):
    validator = _validator_for(results_schema, "OrganizationalContact")
    assert not validator.is_valid({"bogus": "contact-1", "name": "n"})


def test_both_names_carry_the_same_schema(results_schema):
    properties = results_schema["$defs"]["Component"]["properties"]
    assert properties["bom_ref"] == properties["bom-ref"]
    assert properties["mime_type"] == properties["mime-type"]


def _cyclonedx_models() -> dict:
    """Every model the CycloneDX module defines, by class name."""
    import inspect

    import automated_security_helper.schemas.cyclonedx_bom_1_6_schema as module

    return {
        name: cls
        for name, cls in vars(module).items()
        if inspect.isclass(cls)
        and issubclass(cls, BaseModel)
        and cls.__module__ == module.__name__
    }


def _definition_properties(results_schema: dict, module_name: str, name: str) -> dict:
    """The properties of a model's definition in the results schema.

    A class name the SARIF models share (``Attachment``, ``Level``, ``State``,
    ``Tool``, ``Version``) is committed under the module-qualified key, so the
    plain class name alone finds nothing for those five. The qualified key is
    tried first, because a plain key then belongs to the other module's class."""
    qualified = f"{module_name.replace('.', '__')}__{name}"
    for key in (qualified, name):
        if key in results_schema["$defs"]:
            return results_schema["$defs"][key].get("properties", {})
    return {}


def test_every_cyclonedx_definition_key_names_a_class_of_the_module(results_schema):
    """A module-qualified definition whose class was renamed is no longer found
    by the lookup above, which would skip it silently; this fails instead."""
    import inspect

    import automated_security_helper.schemas.cyclonedx_bom_1_6_schema as module

    prefix = module.__name__.replace(".", "__") + "__"
    class_names = {
        name
        for name, cls in vars(module).items()
        if inspect.isclass(cls) and cls.__module__ == module.__name__
    }
    qualified = [key for key in results_schema["$defs"] if key.startswith(prefix)]
    assert len(qualified) >= 5, qualified
    for key in qualified:
        assert key[len(prefix) :] in class_names, key


def test_every_aliased_cyclonedx_model_is_described_as_its_load_reads_it(
    results_schema,
):
    """The Python name sits in a model's properties exactly when the model loads
    by it (``validate_by_name``): read per model and per aliased field from the
    models themselves, so a model that loads by alias only is described by the
    alias alone and one that loads by either name by both.

    The loop used to skip every definition that holds ``bom-ref``, which are the
    models it claimed to check, so nothing but the synthetic control below was
    tested. The count and the named pairs keep this loop from reading nothing.
    ``Level`` carries an aliased ``bom-ref`` and sits under the module-qualified
    key, so it is named too: a lookup by the plain class name skipped it."""
    checked: list = []
    for name, cls in _cyclonedx_models().items():
        properties = _definition_properties(results_schema, cls.__module__, name)
        loads_by_name = bool(cls.model_config.get("validate_by_name"))
        for field_name, info in cls.model_fields.items():
            alias = info.serialization_alias or info.alias
            if not alias or alias == field_name or alias not in properties:
                continue
            checked.append((name, field_name))
            assert (field_name in properties) == loads_by_name, (name, field_name)
    assert ("Component", "bom_ref") in checked, checked
    assert ("Component", "mime_type") in checked, checked
    assert ("Level", "bom_ref") in checked, checked
    assert len(checked) >= 6, checked


class _ByEitherName(BaseModel):
    model_config = ConfigDict(
        extra="forbid", serialize_by_alias=True, validate_by_name=True
    )

    bom_ref: str = Field(..., alias="bom-ref")
    kind: str = "x"


class _ByAliasOnly(BaseModel):
    model_config = ConfigDict(extra="forbid", serialize_by_alias=True)

    bom_ref: str = Field(..., alias="bom-ref")


def _schema(model: type) -> dict:
    return model.model_json_schema(
        schema_generator=StoredResultsJsonSchema, mode="serialization"
    )


def test_a_required_aliased_field_is_required_under_either_name():
    validator = jsonschema.Draft202012Validator(_schema(_ByEitherName))
    assert validator.is_valid({"bom-ref": "r"})
    assert validator.is_valid({"bom_ref": "r"})
    assert not validator.is_valid({"kind": "x"}), "neither name is present"
    assert not validator.is_valid({"bom_ref": 5})


def test_the_alias_stays_in_the_properties_the_dump_writes():
    schema = _schema(_ByEitherName)
    assert set(schema["properties"]) == {"bom-ref", "bom_ref", "kind"}
    assert "required" not in schema, "the requirement moved to either-name form"
    assert schema["allOf"] == [
        {"anyOf": [{"required": ["bom-ref"]}, {"required": ["bom_ref"]}]}
    ]


def test_control_a_model_that_loads_by_alias_only_is_unchanged():
    schema = _schema(_ByAliasOnly)
    assert set(schema["properties"]) == {"bom-ref"}
    assert schema["required"] == ["bom-ref"]
    assert "allOf" not in schema
    assert not jsonschema.Draft202012Validator(schema).is_valid({"bom_ref": "r"})
