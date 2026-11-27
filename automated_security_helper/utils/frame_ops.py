# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Operations on frames that several modules spell the same way.

``frame_text`` carries single cells, ``frame_model`` builds frames; this module
is the operations between them: an ordered count, a stable top-N, a
within-group occurrence number.

polars is imported inside each function, never at module scope, so importing
this module costs what importing ``frame_text`` does and a module on the models'
hot import path can import it freely. A caller that already holds polars passes
its frame in; the helpers hand frames and expressions back.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, Sequence, Union

if TYPE_CHECKING:
    import polars as pl


def ordered_counts(
    frame: "pl.DataFrame",
    key: Union[str, Sequence[str]],
    *,
    weight: Optional[str] = None,
) -> "pl.DataFrame":
    """The rows of *frame* counted by *key*, in the order each key first appears.

    The result has the *key* column(s) and an ``n`` column (Int64): the number of
    rows for that key, or, when *weight* names a column, the sum of that column.
    First-seen order is the order a ``Counter`` iterates in, which is what the
    callers' contracts quote.
    """
    import polars as pl

    count = pl.len() if weight is None else pl.col(weight).sum()
    return frame.group_by(key, maintain_order=True).agg(count.cast(pl.Int64).alias("n"))


def stable_top(
    frame: "pl.DataFrame",
    by: Union[str, Sequence[str]],
    limit: Optional[int],
    *,
    descending: bool = False,
) -> "pl.DataFrame":
    """The first *limit* rows of *frame* sorted by *by*, ties in input order.

    Two traps live here so a caller does not re-derive them. A sort without
    ``maintain_order=True`` loses the first-seen order among ties that
    ``Counter.most_common`` and ``list.sort`` kept. And ``head`` with a negative
    count reads as "all but the last", so a *limit* of zero or less returns no
    rows. A *limit* of None returns every row, sorted.
    """
    ordered = frame.sort(by, descending=descending, maintain_order=True)
    if limit is None:
        return ordered
    if limit <= 0:
        return ordered.clear()
    return ordered.head(limit)


def ordinal_over(*cols: str) -> "pl.Expr":
    """How many rows before this one have the same *cols*, as an Int64 expression.

    The first row of a group is 0, the next 1, and so on. "Before" means before
    in the frame's row order, so the number is the occurrence order of the input
    only while the frame has not been reordered since it was built; every caller
    builds the frame in input order and evaluates this straight after.
    """
    import polars as pl

    return pl.int_range(pl.len(), dtype=pl.Int64).over(list(cols))
