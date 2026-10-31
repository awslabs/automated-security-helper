# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The generated schemas keep the hints an editor checks a config against.

Admitting an environment reference beside a fixed-choice or constrained value
wraps that value's schema in ``anyOf``. pydantic writes a dict's ``propertyNames``
only for a plain constrained string or a definition reference, so the wrap made
it drop the key constraint of a dict keyed by a ``Literal`` (opengrep's
``sha256``, keyed by platform): the editor then accepted any key. The generators
now keep the wrapped key schema as ``propertyNames``. The list items of
``output_formats`` keep their enum through the same wrap, and are checked here
beside it.
"""

from __future__ import annotations

from typing import Annotated, Dict, Literal

import jsonschema
import pytest
from pydantic import BaseModel, Field

from automated_security_helper.schemas.generate_schemas import (
    ConfigFileJsonSchema,
    StoredResultsJsonSchema,
    generate_schemas,
)

pytestmark = pytest.mark.unit

DIGEST = "a" * 64


class _Platforms(BaseModel):
    sha256: Dict[
        Literal["linux/amd64", "darwin/arm64"],
        Annotated[str, Field(pattern=r"^[0-9a-fA-F]{64}$")],
    ] = {}


class _Free(BaseModel):
    labels: Dict[str, str] = {}


def _validator(schema: dict) -> jsonschema.Validator:
    return jsonschema.Draft202012Validator(schema)


@pytest.fixture(scope="module")
def config_schema() -> dict:
    return generate_schemas("dict")["AshConfig"]


def _defs_validator(schema: dict, definition: str) -> jsonschema.Validator:
    return _validator({"$ref": f"#/$defs/{definition}", "$defs": schema["$defs"]})


def test_a_dict_keyed_by_a_literal_keeps_its_key_constraint():
    schema = _Platforms.model_json_schema(schema_generator=ConfigFileJsonSchema)
    sha256 = schema["properties"]["sha256"]
    (choices,) = [b for b in sha256["propertyNames"]["anyOf"] if "enum" in b]
    assert choices["enum"] == ["linux/amd64", "darwin/arm64"]
    assert "title" not in sha256["propertyNames"]


def test_the_key_constraint_refuses_a_key_outside_the_choices():
    schema = _Platforms.model_json_schema(schema_generator=ConfigFileJsonSchema)
    validator = _validator(schema)

    assert validator.is_valid({"sha256": {"linux/amd64": DIGEST}})
    assert not validator.is_valid({"sha256": {"plan9/amd64": DIGEST}})
    # The loader resolves a reference before it validates, so the key may be one.
    assert validator.is_valid({"sha256": {"${ASH_PLATFORM}": DIGEST}})
    # The value constraint still applies beside the key constraint.
    assert not validator.is_valid({"sha256": {"linux/amd64": "short"}})


def test_control_a_dict_of_free_keys_gains_no_key_constraint():
    for generator in (ConfigFileJsonSchema, StoredResultsJsonSchema):
        labels = _Free.model_json_schema(schema_generator=generator)["properties"][
            "labels"
        ]
        assert "propertyNames" not in labels, labels


def test_the_published_opengrep_digests_are_keyed_by_platform(config_schema):
    validator = _defs_validator(config_schema, "OpengrepScannerConfigOptions")

    assert validator.is_valid({"sha256": {"linux/amd64": DIGEST}})
    assert not validator.is_valid({"sha256": {"linux/riscv": DIGEST}})


def test_the_results_schema_keeps_the_same_key_constraint():
    results = generate_schemas("dict")["AshAggregatedResults"]
    validator = _defs_validator(results, "OpengrepScannerConfigOptions")

    assert validator.is_valid({"sha256": {"linux/amd64": DIGEST}})
    assert not validator.is_valid({"sha256": {"linux/riscv": DIGEST}})


def test_output_formats_entries_keep_their_choices(config_schema):
    """An entry is checked against the report names, and a reference is admitted
    beside them; a name that is not one is refused."""
    validator = _defs_validator(config_schema, "AshConfig")

    assert validator.is_valid({"output_formats": ["sarif", "markdown"]})
    assert validator.is_valid({"output_formats": "sarif"})
    assert validator.is_valid({"output_formats": ["${ASH_FORMAT}"]})
    assert not validator.is_valid({"output_formats": ["not-a-report"]})
    (choices,) = [
        branch
        for branch in config_schema["$defs"]["ExportFormat"]["anyOf"]
        if "enum" in branch
    ]
    assert "sarif" in choices["enum"]
