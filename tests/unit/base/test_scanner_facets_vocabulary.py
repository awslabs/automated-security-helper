# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Vocabulary totality for the scanner facets register.

``ScannerFacets.model_fields`` must equal ``FACET_NAMES`` exactly and in
order, every field required and typed ``FacetDecl`` -- so the vocabulary tuple
(what docs generation and the conformance suite iterate) and the model (what
scanners declare against) cannot drift apart. Adding a facet to one without
the other fails here; adding it to both refuses every scanner that has not
classified it, which is the register's point: a new facet forces conscious
classifications, never silent defaults.

The rest of the module pins the fail-closed construction rules of the two
models, because each is what makes a register claim evidence rather than
prose: a MAPPED/DROPPED cell without its native field, a DROPPED/N-A cell
without its reason, a mapped resource_id without an example from a real read,
a missing or unknown facet, and mutation of a built declaration are all
refused.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from automated_security_helper.base.scanner_facets import (
    FACET_NAMES,
    FacetDecl,
    FacetState,
    ScannerFacets,
)

pytestmark = pytest.mark.unit


def _na(reason: str = "not in this scanner's output") -> FacetDecl:
    return FacetDecl(state=FacetState.NA, reason=reason)


def _full_kwargs() -> dict[str, FacetDecl]:
    """A complete, valid declaration: every facet n/a with a reason."""
    return {name: _na() for name in FACET_NAMES}


def test_model_fields_are_exactly_the_vocabulary_in_order() -> None:
    assert tuple(ScannerFacets.model_fields) == FACET_NAMES


def test_every_facet_field_is_required_and_a_facet_decl() -> None:
    for name, field in ScannerFacets.model_fields.items():
        assert field.is_required(), f"facet field {name!r} must be required"
        assert field.annotation is FacetDecl, (
            f"facet field {name!r} must be typed FacetDecl, not {field.annotation!r}"
        )


def test_a_missing_facet_is_refused() -> None:
    kwargs = _full_kwargs()
    del kwargs["tags"]
    with pytest.raises(ValidationError):
        ScannerFacets(**kwargs)


def test_an_unknown_facet_is_refused() -> None:
    kwargs = _full_kwargs()
    kwargs["made_up_facet"] = _na()
    with pytest.raises(ValidationError):
        ScannerFacets(**kwargs)


def test_a_complete_declaration_constructs() -> None:
    facets = ScannerFacets(**_full_kwargs())
    assert facets.rule_id.state is FacetState.NA


def test_mapped_requires_a_native_field() -> None:
    with pytest.raises(ValidationError):
        FacetDecl(state=FacetState.MAPPED)
    with pytest.raises(ValidationError):
        FacetDecl(state=FacetState.MAPPED, native_field="   ")
    decl = FacetDecl(state=FacetState.MAPPED, native_field="resource")
    assert decl.native_field == "resource"


def test_dropped_requires_native_field_and_reason() -> None:
    with pytest.raises(ValidationError):
        FacetDecl(state=FacetState.DROPPED, native_field="fix.state")
    with pytest.raises(ValidationError):
        FacetDecl(state=FacetState.DROPPED, reason="discarded today")
    decl = FacetDecl(
        state=FacetState.DROPPED,
        native_field="fix.state",
        reason="discarded today; roadmap record",
    )
    assert decl.state is FacetState.DROPPED


def test_na_requires_a_reason() -> None:
    with pytest.raises(ValidationError):
        FacetDecl(state=FacetState.NA)
    with pytest.raises(ValidationError):
        FacetDecl(state=FacetState.NA, reason="")
    decl = FacetDecl(
        state=FacetState.NA,
        reason="the tool's output carries no such field",
    )
    assert decl.state is FacetState.NA


def test_unconfirmed_is_its_own_state_and_requires_a_reason() -> None:
    assert FacetState.UNCONFIRMED is not FacetState.NA
    assert FacetState.UNCONFIRMED.value == "unconfirmed"
    with pytest.raises(ValidationError):
        FacetDecl(state=FacetState.UNCONFIRMED)
    with pytest.raises(ValidationError):
        FacetDecl(state=FacetState.UNCONFIRMED, reason="  ")
    decl = FacetDecl(
        state=FacetState.UNCONFIRMED,
        reason="output not read; a sample run would settle it",
    )
    assert decl.state is FacetState.UNCONFIRMED
    # Unlike MAPPED and DROPPED it names no native field: nothing was read.
    assert decl.native_field is None


def test_mapped_resource_id_requires_an_example() -> None:
    kwargs = _full_kwargs()
    kwargs["resource_id"] = FacetDecl(state=FacetState.MAPPED, native_field="resource")
    with pytest.raises(ValidationError):
        ScannerFacets(**kwargs)
    kwargs["resource_id"] = FacetDecl(
        state=FacetState.MAPPED,
        native_field="resource",
        example="AWS::S3::Bucket.S3Bucket3",
    )
    facets = ScannerFacets(**kwargs)
    assert facets.resource_id.example == "AWS::S3::Bucket.S3Bucket3"


def test_a_mapped_non_resource_facet_needs_no_example() -> None:
    kwargs = _full_kwargs()
    kwargs["rule_id"] = FacetDecl(state=FacetState.MAPPED, native_field="ruleName")
    facets = ScannerFacets(**kwargs)
    assert facets.rule_id.example is None


def test_declarations_are_frozen() -> None:
    decl = _na()
    with pytest.raises(ValidationError):
        decl.reason = "rewritten"  # type: ignore[misc]
    facets = ScannerFacets(**_full_kwargs())
    with pytest.raises(ValidationError):
        facets.rule_id = _na()  # type: ignore[misc]
