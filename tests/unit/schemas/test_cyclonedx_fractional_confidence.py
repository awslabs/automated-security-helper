# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A fractional CycloneDX confidence or conformance score is a valid SBOM.

The CycloneDX 1.6 schema types ``ComponentIdentityEvidence.confidence``,
``Conformance.score``, ``Method.confidence`` and ``Confidence.score`` as numbers
between 0 and 1 inclusive. The generated model typed the first two as ``int``
with the same bounds, so the only values they accepted were 0 and 1 and a tool
writing 0.85 made the whole SBOM fail validation.

Typed ``float`` alone, a BOM's integer ``1`` was re-emitted as ``1.0``; each of
the four fields is a union of a bounded int and a bounded float, so each value
is kept as written.
"""

from __future__ import annotations

import json
import re

import pytest
from pydantic import ValidationError

from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    ComponentIdentityEvidence,
    Confidence,
    Conformance,
    FieldModel,
    Method,
    Technique,
)

pytestmark = pytest.mark.unit

#: Every 0 - 1 field of the module: the model, the field, and the other fields
#: the model requires to be built.
ZERO_TO_ONE_FIELDS = [
    pytest.param(
        ComponentIdentityEvidence,
        "confidence",
        {"field": FieldModel.purl},
        id="identity-evidence-confidence",
    ),
    pytest.param(Conformance, "score", {}, id="conformance-score"),
    pytest.param(
        Method,
        "confidence",
        {"technique": Technique.manifest_analysis},
        id="method-confidence",
    ),
    pytest.param(Confidence, "score", {}, id="confidence-score"),
]


@pytest.mark.parametrize("model, field, required", ZERO_TO_ONE_FIELDS)
@pytest.mark.parametrize("value", [0.0, 0.5, 0.85, 1.0, 1])
def test_a_zero_to_one_field_accepts_a_fractional_value(model, field, required, value):
    loaded = model.model_validate({**required, field: value})
    assert getattr(loaded, field) == pytest.approx(float(value))
    assert loaded.model_dump(mode="json", exclude_none=True)[field] == pytest.approx(
        float(value)
    )


@pytest.mark.parametrize("model, field, required", ZERO_TO_ONE_FIELDS)
@pytest.mark.parametrize("value", [-0.01, 1.01, 2])
def test_the_zero_to_one_bounds_still_hold(model, field, required, value):
    with pytest.raises(ValidationError):
        model.model_validate({**required, field: value})


@pytest.mark.parametrize("model, field, required", ZERO_TO_ONE_FIELDS)
def test_an_integer_value_is_kept_as_an_integer(model, field, required):
    """A BOM that writes ``1`` is re-emitted with ``1``, not ``1.0``."""
    loaded = model.model_validate({**required, field: 1})
    assert type(getattr(loaded, field)) is int
    # ``== 1`` and the substring ``"confidence":1`` are both true of ``1.0``, so
    # the type is what is compared, on the dumped value and on the JSON text.
    dumped = loaded.model_dump(mode="json", exclude_none=True)[field]
    assert type(dumped) is int and dumped == 1
    text = loaded.model_dump_json(exclude_none=True)
    written = json.loads(text)[field]
    assert type(written) is int and written == 1
    assert re.search(rf'"{field}":1(?![0-9.])', text), text
    reread = model.model_validate_json(text)
    assert type(getattr(reread, field)) is int


@pytest.mark.parametrize("model, field, required", ZERO_TO_ONE_FIELDS)
def test_a_fractional_value_is_kept_as_a_float(model, field, required):
    loaded = model.model_validate({**required, field: 0.85})
    assert type(getattr(loaded, field)) is float
    assert loaded.model_dump(mode="json", exclude_none=True)[field] == pytest.approx(
        0.85
    )
