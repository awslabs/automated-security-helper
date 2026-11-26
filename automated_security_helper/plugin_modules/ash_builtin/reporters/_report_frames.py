# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The dataframe layer under ``report_content_emitter``.

The emitter's public methods keep their signatures and outputs; the counts,
group-bys and top-N selections they answer are computed here, on polars frames
built from the flattened findings. Each function is frame-in/frame-out, or takes
plain column lists and returns plain rows.

What stays row-wise Python in the emitter, and why: deciding whether one finding
is actionable (a per-(project, scanner) threshold lookup that reaches the
recorded configuration, plus a JSON read of the finding's property bag) is
imperative lookup against the model, not algebra over rows. The decisions are
made there, one per finding, and arrive here as boolean columns.

Ordering is part of the output. Every group-by and sort below keeps first-seen
order among ties (``maintain_order=True``), which is what ``Counter`` and the
stable ``list.sort`` the reports used to run gave.
"""

from __future__ import annotations

from typing import Any, Iterable, List, Sequence

import polars as pl

from automated_security_helper.utils.frame_ops import ordered_counts, stable_top
from automated_security_helper.utils.frame_text import ranks, unwire, wire


#: The graded frame's declared shape. The rows are per-finding gradings computed
#: on the host (no model to derive a spec from), so the one schema dict here is
#: the record, and the drift gate pins the frame against it. The columns of
#: :func:`graded_frame`, always all four, in this order.
#:
#: - ``level`` is the severity BUCKET (``_severity_level`` of the finding's
#:   severity, ``unknown`` for none), not ``FlatVulnerability.severity``.
#: - ``is_suppressed`` is ``FlatVulnerability.is_suppressed``, the name
#:   ``flat_frame`` gives it.
#: - ``left_out`` is the report's policy grading (``is_policy_not_gating``), not
#:   a model field.
#: - ``actionable`` is the report's threshold grading; null in each row the
#:   caller did not grade, so a null is "not decided", never "no", and a total
#:   over the column counts only the rows that were graded.
GRADED_SCHEMA: dict[str, Any] = {
    "level": pl.String,
    "is_suppressed": pl.Boolean,
    "left_out": pl.Boolean,
    "actionable": pl.Boolean,
}


def graded_frame(
    levels: Sequence[str],
    is_suppressed: Sequence[bool],
    left_out: Sequence[bool],
    actionable: Sequence[bool | None] | None = None,
) -> pl.DataFrame:
    """One row per finding: its severity bucket and its three yes/no gradings.

    ``is_suppressed`` bears the model field's name it carries
    (``FlatVulnerability.is_suppressed``). ``actionable`` is optional because
    deciding it costs a threshold lookup per finding, and a summary reads it for
    only some of its rows: a row given ``None`` (or every row, when the argument
    is left out) was not graded. The frame has the same four columns either way
    (:data:`GRADED_SCHEMA`); a row that was not graded has a null there.
    """
    rows = len(levels)
    return pl.DataFrame(
        {
            "level": list(levels),
            "is_suppressed": list(is_suppressed),
            "left_out": list(left_out),
            "actionable": list(actionable) if actionable is not None else [None] * rows,
        },
        schema=GRADED_SCHEMA,
    )


def flag_total(frame: pl.DataFrame, flag: str) -> int:
    """How many rows have *flag* set."""
    return int(frame[flag].sum())


def active_level_counts(frame: pl.DataFrame) -> List[tuple[str, int]]:
    """``(level, count)`` for the unsuppressed rows, levels in first-seen order."""
    counted = ordered_counts(frame.filter(~pl.col("is_suppressed")), "level")
    return [(level, int(count)) for level, count in counted.iter_rows()]


def top_locations(locations: Iterable[str], limit: int | None) -> List[tuple[str, int]]:
    """The *limit* most frequent locations with their counts.

    Most frequent first; locations with equal counts keep the order they were
    first seen in. A limit of 0 or less selects nothing (``head`` would read a
    negative one as "all but the last"); ``None`` selects every location.
    """
    if limit is not None and limit <= 0:
        return []
    found = pl.DataFrame(
        {"location": pl.Series([wire(item) for item in locations], dtype=pl.String)}
    )
    ranked = stable_top(ordered_counts(found, "location"), "n", limit, descending=True)
    return [(unwire(location), int(count)) for location, count in ranked.iter_rows()]


def severity_order(
    keys: Sequence[tuple[int, str, int, str]],
    suppressed: Sequence[bool] | None = None,
) -> List[int]:
    """The positions of *keys* in ascending order, ties in their given order.

    Each key is ``(severity place, file, line, rule)``. A file or rule may hold a
    lone surrogate and a line is an unbounded int, so text goes in as
    :func:`wire` and lines as their ranks. The ``line`` column is a dense rank of
    the lines given, not a line: only the order of lines is read here, and every
    line has a rank, where ``models.flat_frame`` holds the line and a null for
    one that does not fit 64 bits. Every line in a key is an int, never None: a
    rank map has no entry for None, so a caller whose rows may lack a line gives
    the line the Python sort it replaces read for it (0 for no line).

    *suppressed*, one flag per key, is a leading sort column: ``False`` rows come
    before ``True`` rows, as ``False < True`` does in a Python tuple compare, and
    each group keeps the ordering above. Each flag is read through ``bool()``, so
    a row whose flag is None sorts as live.
    """
    if not keys:
        return []
    if suppressed is not None and len(suppressed) != len(keys):
        raise ValueError("severity_order needs one suppression flag per key")
    line_rank = ranks(k[2] for k in keys)
    columns: dict[str, pl.Series] = {}
    if suppressed is not None:
        columns["suppressed"] = pl.Series(
            [bool(flag) for flag in suppressed], dtype=pl.Boolean
        )
    columns["place"] = pl.Series([k[0] for k in keys], dtype=pl.Int64)
    columns["file"] = pl.Series([wire(k[1]) for k in keys], dtype=pl.String)
    columns["line"] = pl.Series([line_rank[k[2]] for k in keys], dtype=pl.Int64)
    columns["rule"] = pl.Series([wire(k[3]) for k in keys], dtype=pl.String)
    ordered = (
        pl.DataFrame(columns)
        .with_row_index("position")
        .sort(list(columns), maintain_order=True)
    )
    return ordered["position"].to_list()
