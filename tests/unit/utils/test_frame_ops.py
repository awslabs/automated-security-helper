# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The frame operations in ``utils/frame_ops.py`` agree with a pure-Python oracle.

Each helper replaced a polars expression several modules spelled by hand. The
oracle for each is the Python the expression stands in for (``Counter``'s
first-seen order, ``list.sort``'s stability, a counter loop), run on awkward
inputs: duplicate keys, ties, interleaved groups, nulls, empty frames. The old
polars expressions are also kept here verbatim and compared where the helper
claims to be equal to them.
"""

from __future__ import annotations

import ast
import inspect
from collections import defaultdict
from typing import Dict

import polars as pl
import pytest
from hypothesis import given
from hypothesis import strategies as st

from automated_security_helper.utils import frame_ops
from automated_security_helper.utils.frame_ops import (
    ordered_counts,
    ordinal_over,
    stable_top,
)
from automated_security_helper.utils.frame_text import wire

pytestmark = pytest.mark.unit

KEYS = st.sampled_from(["a", "b", "c", "d", "\udcff", "ä", ""])
OPTIONAL_KEYS = st.one_of(st.none(), KEYS)


# --- ordered_counts -----------------------------------------------------------


def oracle_counts(keys, weights=None):
    counted: Dict = {}
    for index, key in enumerate(keys):
        counted[key] = counted.get(key, 0) + (1 if weights is None else weights[index])
    return list(counted.items())


@given(st.lists(KEYS, max_size=30))
def test_ordered_counts_is_a_first_seen_counter(keys):
    frame = pl.DataFrame({"k": [wire(k) for k in keys]}, schema={"k": pl.String})
    result = ordered_counts(frame, "k")
    assert list(result.iter_rows()) == [(wire(k), n) for k, n in oracle_counts(keys)]


@given(st.lists(st.tuples(KEYS, st.integers(0, 5)), max_size=30))
def test_ordered_counts_weight_sums_the_column_in_first_seen_order(rows):
    keys = [k for k, _ in rows]
    weights = [w for _, w in rows]
    frame = pl.DataFrame(
        {"k": [wire(k) for k in keys], "w": weights},
        schema={"k": pl.String, "w": pl.Int64},
    )
    result = ordered_counts(frame, "k", weight="w")
    assert list(result.iter_rows()) == [
        (wire(k), n) for k, n in oracle_counts(keys, weights)
    ]


@given(st.lists(st.tuples(KEYS, KEYS), max_size=30))
def test_ordered_counts_over_two_keys_groups_the_pair(rows):
    frame = pl.DataFrame(
        {"a": [wire(a) for a, _ in rows], "b": [wire(b) for _, b in rows]},
        schema={"a": pl.String, "b": pl.String},
    )
    result = ordered_counts(frame, ["a", "b"])
    assert result.columns == ["a", "b", "n"]
    assert [((a, b), n) for a, b, n in result.iter_rows()] == [
        ((wire(a), wire(b)), n) for (a, b), n in oracle_counts(rows)
    ]


@given(st.lists(KEYS, max_size=30))
def test_ordered_counts_equals_the_old_len_expression_modulo_dtype(keys):
    frame = pl.DataFrame({"k": [wire(k) for k in keys]}, schema={"k": pl.String})
    old = frame.group_by("k", maintain_order=True).agg(pl.len().alias("n"))
    new = ordered_counts(frame, "k")
    assert new.schema["n"] == pl.Int64
    assert old.cast({"n": pl.Int64}).equals(new)


def test_ordered_counts_of_an_empty_frame_is_empty_and_typed():
    frame = pl.DataFrame({"k": []}, schema={"k": pl.String})
    result = ordered_counts(frame, "k")
    assert result.height == 0
    assert result.schema == {"k": pl.String, "n": pl.Int64}


def test_ordered_counts_counts_null_as_a_key():
    frame = pl.DataFrame({"k": ["a", None, "a", None]}, schema={"k": pl.String})
    assert list(ordered_counts(frame, "k").iter_rows()) == [("a", 2), (None, 2)]


# --- stable_top ---------------------------------------------------------------


def oracle_top(values, limit, descending):
    ordered = sorted(
        enumerate(values), key=lambda pair: pair[1], reverse=descending
    )  # list.sort is stable, reverse included
    rows = [index for index, _ in ordered]
    if limit is None:
        return rows
    if limit <= 0:
        return []
    return rows[:limit]


LIMITS = st.one_of(st.none(), st.integers(-5, 40))


@given(st.lists(st.integers(0, 3), max_size=30), LIMITS, st.booleans())
def test_stable_top_is_pythons_stable_sort_sliced(values, limit, descending):
    frame = pl.DataFrame(
        {"i": list(range(len(values))), "v": values},
        schema={"i": pl.Int64, "v": pl.Int64},
    )
    result = stable_top(frame, "v", limit, descending=descending)
    assert result["i"].to_list() == oracle_top(values, limit, descending)


@given(
    st.lists(st.tuples(st.integers(0, 2), st.integers(0, 2)), max_size=30),
    LIMITS,
)
def test_stable_top_sorts_on_a_sequence_of_columns(pairs, limit):
    frame = pl.DataFrame(
        {
            "i": list(range(len(pairs))),
            "a": [a for a, _ in pairs],
            "b": [b for _, b in pairs],
        },
        schema={"i": pl.Int64, "a": pl.Int64, "b": pl.Int64},
    )
    result = stable_top(frame, ["a", "b"], limit)
    expected = [index for index, _ in sorted(enumerate(pairs), key=lambda p: p[1])]
    if limit is not None:
        expected = [] if limit <= 0 else expected[:limit]
    assert result["i"].to_list() == expected


def test_stable_top_keeps_input_order_among_ties():
    frame = pl.DataFrame(
        {"i": [0, 1, 2, 3, 4, 5], "v": [1, 2, 1, 2, 1, 2]},
        schema={"i": pl.Int64, "v": pl.Int64},
    )
    assert stable_top(frame, "v", None)["i"].to_list() == [0, 2, 4, 1, 3, 5]
    assert stable_top(frame, "v", 2, descending=True)["i"].to_list() == [1, 3]


@pytest.mark.parametrize("limit", [0, -1, -3, -100])
def test_stable_top_of_a_zero_or_negative_limit_is_empty_with_the_schema(limit):
    frame = pl.DataFrame({"i": [0, 1, 2], "v": [3, 2, 1]})
    result = stable_top(frame, "v", limit)
    assert result.height == 0
    assert result.schema == frame.schema


def test_control_polars_head_reads_a_negative_count_as_all_but_the_last():
    """The trap stable_top guards: this disagrees with the helper, so the
    oracle comparisons above can fail."""
    frame = pl.DataFrame({"i": [0, 1, 2, 3], "v": [4, 3, 2, 1]})
    unguarded = frame.sort("v", maintain_order=True).head(-1)
    assert unguarded.height == 3
    assert stable_top(frame, "v", -1).height == 0


def test_control_a_sort_that_ignores_input_order_disagrees_with_the_oracle():
    """A hand-written order the helper would be wrong to produce: reversing ties."""
    frame = pl.DataFrame({"i": [0, 1, 2], "v": [1, 1, 1]})
    reversed_ties = frame.sort(["v", "i"], descending=[False, True])["i"].to_list()
    assert reversed_ties != stable_top(frame, "v", None)["i"].to_list()


def test_stable_top_limit_larger_than_the_frame_returns_every_row():
    frame = pl.DataFrame({"i": [0, 1], "v": [2, 1]})
    assert stable_top(frame, "v", 99)["i"].to_list() == [1, 0]


# --- ordinal_over -------------------------------------------------------------


def oracle_ordinals(rows):
    seen: Dict = defaultdict(int)
    out = []
    for row in rows:
        out.append(seen[row])
        seen[row] += 1
    return out


@given(st.lists(KEYS, max_size=30))
def test_ordinal_over_numbers_each_occurrence_in_input_order(keys):
    frame = pl.DataFrame({"k": [wire(k) for k in keys]}, schema={"k": pl.String})
    result = frame.with_columns(ordinal_over("k").alias("o"))["o"].to_list()
    assert result == oracle_ordinals(keys)


@given(st.lists(st.tuples(OPTIONAL_KEYS, st.booleans()), max_size=30))
def test_ordinal_over_two_columns_counts_the_pair(rows):
    frame = pl.DataFrame(
        {
            "k": [None if k is None else wire(k) for k, _ in rows],
            "f": [f for _, f in rows],
        },
        schema={"k": pl.String, "f": pl.Boolean},
    )
    result = frame.with_columns(ordinal_over("k", "f").alias("o"))["o"].to_list()
    assert result == oracle_ordinals(rows)


def test_ordinal_over_interleaved_groups_would_fail_a_sorted_input_shortcut():
    frame = pl.DataFrame({"k": ["a", "b", "a", "b", "a"]})
    assert frame.with_columns(ordinal_over("k").alias("o"))["o"].to_list() == [
        0,
        0,
        1,
        1,
        2,
    ]


@given(st.lists(st.tuples(KEYS, KEYS), max_size=30))
def test_ordinal_over_equals_the_old_int_range_expression(rows):
    frame = pl.DataFrame(
        {"a": [wire(a) for a, _ in rows], "b": [wire(b) for _, b in rows]},
        schema={"a": pl.String, "b": pl.String},
    )
    old = frame.with_columns(pl.int_range(pl.len()).over(["a", "b"]).alias("o"))
    new = frame.with_columns(ordinal_over("a", "b").alias("o"))
    assert old.equals(new)
    assert new.schema["o"] == pl.Int64


def test_ordinal_over_composes_inside_a_when_otherwise():
    frame = pl.DataFrame({"k": ["a", None, "a", None]}, schema={"k": pl.String})
    result = frame.with_columns(
        pl.when(pl.col("k").is_not_null())
        .then(ordinal_over("k"))
        .otherwise(None)
        .alias("o")
    )["o"].to_list()
    assert result == [0, None, 1, None]


# --- import discipline --------------------------------------------------------


def test_frame_ops_imports_polars_only_inside_functions_and_for_annotations():
    tree = ast.parse(inspect.getsource(frame_ops))
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] + [getattr(node, "module", "") or ""]
            assert not any(n.split(".")[0] == "polars" for n in names)
