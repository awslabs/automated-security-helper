# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The cell codecs in ``utils/frame_text.py`` agree with the expressions they replaced.

Each ``old_*`` function below is the inline expression a module carried before it
called the helper, kept verbatim as an oracle (the pattern of
``tests/unit/models/test_suppression_frame_equivalence.py``). The value spaces
are deliberately awkward: lone surrogates, non-strings, empty strings, huge and
negative ints.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from automated_security_helper.utils import frame_text
from automated_security_helper.utils.frame_text import (
    ranks,
    unwire,
    unwire_cell,
    wire,
    wire_cell,
)

pytestmark = pytest.mark.unit

#: Text that may hold a lone surrogate, which is what ``os.fsdecode`` of
#: undecodable bytes produces and a polars string column refuses.
TEXT = st.text(alphabet=st.characters(exclude_categories=()), max_size=12)


class WithStr:
    def __init__(self, text):
        self.text = text

    def __str__(self):
        return self.text


VALUES = st.one_of(
    st.none(),
    TEXT,
    st.integers(min_value=-(2**80), max_value=2**80),
    st.booleans(),
    TEXT.map(WithStr),
)


# --- the oracles: the expressions as they were written inline ---------------


def old_flat_frame_text(value):
    """models/flat_frame.py ``_text``, and finding_identity's nested ``text``."""
    return (
        None if value is None else wire(value if isinstance(value, str) else str(value))
    )


def old_csv_cell(value):
    """csv_reporter's inline, reached only for a value that is not a str."""
    return None if value is None else wire(str(value))


def old_wire_id(rule_id):
    """github_ghas_reporter ``_wire_id``."""
    return wire(str(rule_id)) if rule_id else None


def old_unwire_guard(cell):
    """The five ``unwire(x) if x is not None else None`` expressions."""
    return unwire(cell) if cell is not None else None


def old_line_ranks(values):
    """suppression_frame._line_ranks, byte for byte."""
    return {
        value: rank
        for rank, value in enumerate(sorted({v for v in values if v is not None}))
    }


# --- wire_cell ----------------------------------------------------------------


@given(VALUES)
def test_wire_cell_is_the_optional_coercing_wire(value):
    assert wire_cell(value) == old_flat_frame_text(value)


@given(VALUES.filter(lambda v: not isinstance(v, str)))
def test_wire_cell_is_the_csv_inline_for_a_value_that_is_not_text(value):
    assert wire_cell(value) == old_csv_cell(value)


@given(VALUES)
def test_wire_cell_over_falsy_to_none_is_the_ghas_rule_id_wrapper(value):
    assert wire_cell(value or None) == old_wire_id(value)


@given(TEXT)
def test_a_wired_cell_holds_no_surrogate(text):
    cell = wire_cell(text)
    assert cell is not None
    cell.encode("utf-8")


@given(st.one_of(TEXT, st.integers(), TEXT.map(WithStr)))
def test_wire_cell_round_trips_through_unwire_cell_to_the_text(value):
    assert unwire_cell(wire_cell(value)) == (
        value if isinstance(value, str) else str(value)
    )


def test_wire_cell_passes_none_and_the_empty_string():
    assert wire_cell(None) is None
    assert wire_cell("") == ""


def test_wire_cell_wires_a_lone_surrogate_as_wire_does():
    assert wire_cell("\udcff") == wire("\udcff")


# --- unwire_cell --------------------------------------------------------------


@given(st.one_of(st.none(), TEXT.map(wire)))
def test_unwire_cell_is_the_none_guarded_unwire(cell):
    assert unwire_cell(cell) == old_unwire_guard(cell)


@given(st.one_of(st.none(), TEXT))
def test_unwire_cell_reads_back_what_wire_made(text):
    assert unwire_cell(wire(text)) == text


def test_unwire_itself_still_refuses_none():
    with pytest.raises(AttributeError):
        unwire(None)  # type: ignore[arg-type]


# --- ranks (the one copy suppression_frame now calls) ------------------------


INTS = st.one_of(
    st.none(),
    st.integers(min_value=-(2**80), max_value=2**80),
    st.integers(min_value=-3, max_value=3),
)


@given(st.lists(INTS, max_size=30))
def test_ranks_is_the_deleted_line_ranks(values):
    assert ranks(values) == old_line_ranks(values)


@given(st.lists(INTS, max_size=30))
def test_ranks_accepts_any_iterable_the_callers_pass(values):
    assert ranks(iter(values)) == ranks(tuple(values)) == ranks(values)


def test_ranks_keeps_order_and_ties_whatever_the_size():
    assert ranks([2**70, -(2**70), 5, 5, None]) == {-(2**70): 0, 5: 1, 2**70: 2}


def test_frame_text_imports_no_polars():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(frame_text))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert "polars" not in imported
