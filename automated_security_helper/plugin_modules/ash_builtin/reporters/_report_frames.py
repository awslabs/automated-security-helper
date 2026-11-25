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

from automated_security_helper.utils.frame_text import ranks, unwire, wire


def graded_frame(
    levels: Sequence[str],
    is_suppressed: Sequence[bool],
    left_out: Sequence[bool],
    actionable: Sequence[bool] | None = None,
) -> pl.DataFrame:
    """One row per finding: its severity bucket and its three yes/no gradings.

    ``is_suppressed`` bears the model field's name it carries
    (``FlatVulnerability.is_suppressed``). ``actionable`` is optional because
    deciding it costs a threshold lookup per finding, and some summaries never
    need it.
    """
    columns: dict[str, Any] = {
        "level": pl.Series("level", list(levels), dtype=pl.String),
        "is_suppressed": pl.Series(
            "is_suppressed", list(is_suppressed), dtype=pl.Boolean
        ),
        "left_out": pl.Series("left_out", list(left_out), dtype=pl.Boolean),
    }
    if actionable is not None:
        columns["actionable"] = pl.Series(
            "actionable", list(actionable), dtype=pl.Boolean
        )
    return pl.DataFrame(columns)


def flag_total(frame: pl.DataFrame, flag: str) -> int:
    """How many rows have *flag* set."""
    return int(frame[flag].sum())


def active_level_counts(frame: pl.DataFrame) -> List[tuple[str, int]]:
    """``(level, count)`` for the unsuppressed rows, levels in first-seen order."""
    counted = (
        frame.filter(~pl.col("is_suppressed"))
        .group_by("level", maintain_order=True)
        .len()
    )
    return [(level, int(count)) for level, count in counted.iter_rows()]


def top_locations(locations: Iterable[str], limit: int | None) -> List[tuple[str, int]]:
    """The *limit* most frequent locations with their counts.

    Most frequent first; locations with equal counts keep the order they were
    first seen in. A limit of 0 or less selects nothing (``head`` would read a
    negative one as "all but the last"); ``None`` selects every location.
    """
    if limit is not None and limit <= 0:
        return []
    ranked = (
        pl.DataFrame(
            {"location": pl.Series([wire(item) for item in locations], dtype=pl.String)}
        )
        .group_by("location", maintain_order=True)
        .len()
        .sort("len", descending=True, maintain_order=True)
    )
    if limit is not None:
        ranked = ranked.head(limit)
    return [(unwire(location), int(count)) for location, count in ranked.iter_rows()]


def severity_order(keys: Sequence[tuple[int, str, int, str]]) -> List[int]:
    """The positions of *keys* in ascending order, ties in their given order.

    Each key is ``(severity place, file, line, rule)``. A file or rule may hold a
    lone surrogate and a line is an unbounded int, so text goes in as
    :func:`wire` and lines as their ranks.
    """
    if not keys:
        return []
    line_rank = ranks(k[2] for k in keys)
    ordered = (
        pl.DataFrame(
            {
                "place": pl.Series([k[0] for k in keys], dtype=pl.Int64),
                "file": pl.Series([wire(k[1]) for k in keys], dtype=pl.String),
                "line": pl.Series([line_rank[k[2]] for k in keys], dtype=pl.Int64),
                "rule": pl.Series([wire(k[3]) for k in keys], dtype=pl.String),
            }
        )
        .with_row_index("position")
        .sort(["place", "file", "line", "rule"], maintain_order=True)
    )
    return ordered["position"].to_list()
