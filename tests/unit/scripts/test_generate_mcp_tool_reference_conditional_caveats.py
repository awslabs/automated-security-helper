# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/generate_mcp_tool_reference.py: a conditional caveat that names an
error type does not also call it untyped.

A caveat given as a dict with ``error_types`` prints the types the tool returns,
and adds its ``untyped`` sentence while none of ``untyped_unless`` is among them.
Without a contract (a tool the reader did not find) every type is named, and the
sentence used to be added as well, so the paragraph listed a type and then said
the failure carried none. Without a contract every type now counts as returned,
the way every response key does for ``returns_fields``.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

CAVEAT = {
    "lead": "On a refusal `error_type` is",
    "error_types": [("a_kind", ""), ("b_kind", "a note")],
    "untyped": "Other failures carry no type.",
    "untyped_unless": ["b_kind"],
}


@pytest.fixture
def conditional_caveat(script_loader):
    return script_loader("generate_mcp_tool_reference")._conditional_caveat


def test_without_a_contract_a_named_type_is_not_also_called_untyped(
    conditional_caveat,
):
    text = conditional_caveat(CAVEAT, set(), None)

    assert text == "On a refusal `error_type` is `a_kind`, or `b_kind` (a note)."


def test_without_a_contract_the_untyped_sentence_stays_when_nothing_gates_it(
    conditional_caveat,
):
    caveat = {key: value for key, value in CAVEAT.items() if key != "untyped_unless"}

    text = conditional_caveat(caveat, set(), None)

    assert text == (
        "On a refusal `error_type` is `a_kind`, or `b_kind` (a note). "
        "Other failures carry no type."
    )


def test_a_contract_without_the_gating_type_adds_the_untyped_sentence(
    conditional_caveat,
):
    text = conditional_caveat(CAVEAT, set(), {"a_kind"})

    assert (
        text == "On a refusal `error_type` is `a_kind`. Other failures carry no type."
    )


def test_a_contract_with_the_gating_type_names_it_and_drops_the_sentence(
    conditional_caveat,
):
    text = conditional_caveat(CAVEAT, set(), {"a_kind", "b_kind"})

    assert text == "On a refusal `error_type` is `a_kind`, or `b_kind` (a note)."
