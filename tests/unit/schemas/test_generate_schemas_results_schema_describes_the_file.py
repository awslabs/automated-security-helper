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

import pytest

from automated_security_helper.schemas.generate_schemas import generate_schemas

pytestmark = pytest.mark.unit


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
