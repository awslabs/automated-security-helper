# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A fractional CycloneDX confidence or conformance score is a valid SBOM.

The CycloneDX 1.6 schema types ``ComponentIdentityEvidence.confidence`` and
``Conformance.score`` as numbers between 0 and 1 inclusive. The generated model
typed both as ``int`` with the same bounds, so the only values they accepted
were 0 and 1 and a tool writing 0.85 made the whole SBOM fail validation. The
sibling ``Method.confidence`` was already a float, and is the control.

Typed ``float`` alone, a BOM's integer ``1`` was re-emitted as ``1.0``; the
field is a union of a bounded int and a bounded float now, so each value is
kept as written.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    ComponentIdentityEvidence,
    Conformance,
    FieldModel,
    Method,
    Technique,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("confidence", [0.0, 0.5, 0.85, 1.0, 1])
def test_identity_evidence_accepts_a_fractional_confidence(confidence):
    evidence = ComponentIdentityEvidence(field=FieldModel.purl, confidence=confidence)
    assert evidence.confidence == pytest.approx(float(confidence))
    assert evidence.model_dump(exclude_none=True)["confidence"] == pytest.approx(
        float(confidence)
    )


@pytest.mark.parametrize("score", [0.0, 0.25, 0.85, 1.0])
def test_conformance_accepts_a_fractional_score(score):
    assert Conformance(score=score).score == pytest.approx(score)


@pytest.mark.parametrize("value", [-0.01, 1.01, 2])
def test_the_zero_to_one_bounds_still_hold(value):
    with pytest.raises(ValidationError):
        ComponentIdentityEvidence(field=FieldModel.purl, confidence=value)
    with pytest.raises(ValidationError):
        Conformance(score=value)


def test_control_method_confidence_was_already_a_number():
    method = Method(technique=Technique.manifest_analysis, confidence=0.85)
    assert method.confidence == pytest.approx(0.85)


@pytest.mark.parametrize(
    "model, field", [(ComponentIdentityEvidence, "confidence"), (Conformance, "score")]
)
def test_an_integer_value_is_kept_as_an_integer(model, field):
    """A BOM that writes ``1`` is re-emitted with ``1``, not ``1.0``."""
    payload = {"field": "purl", field: 1} if field == "confidence" else {field: 1}
    loaded = model.model_validate(payload)
    assert type(getattr(loaded, field)) is int
    assert loaded.model_dump(mode="json", exclude_none=True)[field] == 1
    assert '"' + field + '":1' in loaded.model_dump_json(exclude_none=True)
    reread = model.model_validate_json(loaded.model_dump_json(exclude_none=True))
    assert type(getattr(reread, field)) is int


@pytest.mark.parametrize(
    "model, field", [(ComponentIdentityEvidence, "confidence"), (Conformance, "score")]
)
def test_a_fractional_value_is_kept_as_a_float(model, field):
    payload = {"field": "purl", field: 0.85} if field == "confidence" else {field: 0.85}
    loaded = model.model_validate(payload)
    assert type(getattr(loaded, field)) is float
    assert loaded.model_dump(mode="json", exclude_none=True)[field] == pytest.approx(
        0.85
    )
