# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The results schema describes the file ``model_dump_json`` writes.

``workspace.skipped_projects`` is a computed field: every workspace results file
carries it, for the downstream consumers that must see a project was dropped.
The results schema was generated in pydantic's default validation mode, where a
computed field is absent, so a validator given a real workspace results file
refused the key. The schema is generated in serialization mode now, which
carries every computed field and keeps the same required-ness for the rest.
"""

from __future__ import annotations

from typing import Callable, Optional

import jsonschema
import pydantic
import pytest
from pydantic import BaseModel, ConfigDict, Field, computed_field

from automated_security_helper.schemas.generate_schemas import (
    StoredResultsJsonSchema,
    generate_schemas,
)

pytestmark = pytest.mark.unit


class _Record(BaseModel):
    """A model with one field of each kind serialization mode treats specially."""

    model_config = ConfigDict(extra="forbid")

    kept: int = 1
    hidden: int = Field(0, exclude=True)
    secret: str = Field(..., exclude=True)
    # A runtime-only field of a kind pydantic cannot describe: generating its
    # schema raises, so the generator must never reach it.
    gate: Optional[Callable[[int], bool]] = Field(None, exclude=True)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def derived(self) -> int:
        return self.kept + 1


def _record_schema(**options) -> dict:
    return _Record.model_json_schema(mode="serialization", **options)


@pytest.fixture(scope="module")
def results_schema() -> dict:
    return generate_schemas("dict")["AshAggregatedResults"]


def test_the_workspace_results_carry_their_skipped_projects(results_schema):
    workspace = results_schema["$defs"]["WorkspaceResults"]["properties"]
    assert "skipped_projects" in workspace, sorted(workspace)
    assert workspace["skipped_projects"]["type"] == "array"
    assert workspace["skipped_projects"]["items"] == {"$ref": "#/$defs/SkippedProject"}


def test_control_a_stored_field_is_still_described(results_schema):
    workspace = results_schema["$defs"]["WorkspaceResults"]["properties"]
    assert "projects" in workspace
    assert "workspace_file" in workspace


def test_control_a_field_with_a_default_is_not_made_required(results_schema):
    """Serialization mode keeps pydantic's required-ness: a field with a default
    stays optional, so a results file written with ``exclude_none`` validates."""
    workspace = results_schema["$defs"]["WorkspaceResults"]
    assert "refusal_detail" in workspace["properties"]
    assert "refusal_detail" not in workspace.get("required", [])


# --- a computed field is described and never required --------------------------


def test_a_computed_field_is_described_and_not_required(results_schema):
    """A results file from a version that did not compute the field yet is a file
    this version loads, so the schema must not call it invalid."""
    workspace = results_schema["$defs"]["WorkspaceResults"]
    assert "skipped_projects" in workspace["properties"]
    assert "skipped_projects" not in workspace.get("required", [])


def test_a_workspace_block_written_before_skipped_projects_validates(results_schema):
    validator = jsonschema.Draft202012Validator(
        {"$ref": "#/$defs/WorkspaceResults", "$defs": results_schema["$defs"]}
    )
    older = {
        "workspace_file": "/w/workspace.yaml",
        "workspace_root": "/w",
        "exit_code": 0,
    }
    assert list(validator.iter_errors(older)) == []
    assert not validator.is_valid({"workspace_file": "/w/workspace.yaml"})


def test_no_computed_field_anywhere_in_the_results_schema_is_required(results_schema):
    """Pydantic marks a computed field ``readOnly``; none may be in ``required``."""
    computed = 0
    for name, definition in results_schema["$defs"].items():
        for prop, described in definition.get("properties", {}).items():
            if described.get("readOnly") is True:
                computed += 1
                assert prop not in definition.get("required", []), (name, prop)
    assert computed > 0, "no computed field found: the check above read nothing"


def test_the_generator_leaves_a_computed_field_out_of_required():
    schema = _record_schema(schema_generator=StoredResultsJsonSchema)
    assert "derived" in schema["properties"]
    assert "derived" not in schema.get("required", [])


def test_control_pydantics_own_serialization_schema_requires_it():
    """The must-flag control: without the override the field is required."""
    assert "derived" in _record_schema()["required"]


# --- an excluded field is left out, as pydantic leaves it out -------------------


def test_the_generator_leaves_an_excluded_field_out():
    """No results file carries a field its dump excludes (none of the product's
    excluded fields was ever written by a released version), and describing
    every excluded field published runtime-only fields as part of the contract."""
    schema = _record_schema(schema_generator=StoredResultsJsonSchema)
    assert "hidden" not in schema["properties"]
    assert "secret" not in schema["properties"]
    assert "gate" not in schema["properties"]
    assert {"hidden", "secret", "gate"}.isdisjoint(schema.get("required", []))


def test_an_excluded_field_pydantic_cannot_describe_does_not_fail_the_generation():
    """A model with an excluded callable field generates: the generator never asks
    pydantic for that field's schema. The control shows the ask would fail."""
    assert _record_schema(schema_generator=StoredResultsJsonSchema)

    class _Described(BaseModel):
        gate: Optional[Callable[[int], bool]] = None

    with pytest.raises(pydantic.errors.PydanticInvalidForJsonSchema):
        _Described.model_json_schema(mode="serialization")


def test_control_pydantics_own_serialization_schema_agrees():
    schema = _record_schema()
    assert "hidden" not in schema["properties"]
    assert "secret" not in schema["properties"]


def test_no_excluded_field_of_the_product_is_in_the_results_schema(results_schema):
    """The product's excluded fields, by model: none is described."""
    excluded = {
        "AshConfig": ("extends", "patch"),
        "WorkspaceProjectResult": ("scanner_reasons",),
    }
    for model, fields in excluded.items():
        properties = results_schema["$defs"][model]["properties"]
        for field in fields:
            assert field not in properties, (model, field)


def test_control_an_ordinary_field_keeps_its_requiredness():
    """Only computed and excluded fields change: a field with a default stays
    optional and is described."""
    schema = _record_schema(schema_generator=StoredResultsJsonSchema)
    assert "kept" in schema["properties"]
    assert "kept" not in schema.get("required", [])
