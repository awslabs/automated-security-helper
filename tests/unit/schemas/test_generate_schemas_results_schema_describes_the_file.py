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

import jsonschema
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


# --- an excluded field is described and never required -------------------------


def test_the_generator_describes_an_excluded_field_and_does_not_require_it():
    """A file written by a version that dumped the field still carries it, and a
    model that forbids unknown keys would refuse it if the schema left it out."""
    schema = _record_schema(schema_generator=StoredResultsJsonSchema)
    assert "hidden" in schema["properties"]
    assert "secret" in schema["properties"]
    assert {"hidden", "secret"}.isdisjoint(schema.get("required", []))


def test_control_pydantics_own_serialization_schema_drops_the_excluded_field():
    schema = _record_schema()
    assert "hidden" not in schema["properties"]
    assert "secret" not in schema["properties"]


def test_control_an_ordinary_field_keeps_its_requiredness():
    """Only computed and excluded fields change: a field with a default stays
    optional and is described."""
    schema = _record_schema(schema_generator=StoredResultsJsonSchema)
    assert "kept" in schema["properties"]
    assert "kept" not in schema.get("required", [])
