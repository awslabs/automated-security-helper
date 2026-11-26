# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One frame pipeline for the finding counts.

Three readers counted SARIF results by hand, each with its own loop: the statistics
calculator's per-scanner read (``extract_sarif_counts_for_scanner``), the
per-scanner metrics of a SARIF report (``get_severity_metrics_from_sarif``) and the
workspace aggregation's actionable count (``actionable_results_by_scanner``). Each
walked results, asked a predicate of each, and incremented a counter. The walk and
the predicates read the SARIF tree and stay on the host (the severity ladder, the
suppression state and the scanner attribution are the tree's, not a column's); what
they produce is one small row per result, and the counting is a group-by over those
rows:

* :func:`severity_frame` and :func:`tally_severities` for the severity counts. A
  row is ``(kind,)``: ``"suppressed"`` for a result with a suppression in effect,
  otherwise its resolved severity.
* :func:`actionable_frame` and :func:`actionable_by_name` for the actionable
  counts. A row is ``(name, actionable)``.

Text goes into a String column through :func:`~automated_security_helper.utils.
frame_text.wire`, so a scanner name or a severity with a lone surrogate is carried,
not refused, and comes back unchanged. Both group-bys keep the order each key was
first seen in, which is the order the loops they replace built their dicts in, and
the severity tally refuses a kind the counter does not know at the first one seen,
with the counter's own message, as the loop did at the first such result.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, Iterable, Tuple

from automated_security_helper.utils.frame_ops import ordered_counts
from automated_security_helper.utils.frame_text import unwire, wire

if TYPE_CHECKING:
    import polars as pl

    from automated_security_helper.models.asharp_model import ScannerSeverityCount

#: What a row of :func:`severity_frame` says when the result is suppressed.
SUPPRESSED = "suppressed"


def severity_frame(kinds: Iterable[str]) -> "pl.DataFrame":
    """One row per counted result: ``kind``, its resolved severity or ``"suppressed"``."""
    import polars as pl

    return pl.DataFrame(
        {"kind": [wire(kind) for kind in kinds]}, schema={"kind": pl.String}
    )


def tally_severities(
    frame: "pl.DataFrame", counts: "ScannerSeverityCount | None" = None
) -> "ScannerSeverityCount":
    """The counts of the kinds in *frame*, added to *counts* (a fresh one by default).

    A kind that is not a counter field raises ``ValueError("Invalid severity: ...")``
    as ``ScannerSeverityCount.increment`` does; the kinds are read in the order each
    was first seen, so it is the kind of the first such result that is named.
    """
    from automated_security_helper.models.asharp_model import (
        _VALID_INCREMENT_FIELDS,
        ScannerSeverityCount,
    )

    if counts is None:
        counts = ScannerSeverityCount()
    grouped = ordered_counts(frame, "kind")
    for wired, number in grouped.iter_rows():
        kind = unwire(wired)
        key = kind.lower()
        if key not in _VALID_INCREMENT_FIELDS:
            raise ValueError(f"Invalid severity: {kind!r}")
        setattr(counts, key, getattr(counts, key) + number)
    return counts


def actionable_frame(rows: Iterable[Tuple[str, bool]]) -> "pl.DataFrame":
    """One row per result: its scanner ``name`` and whether it is ``actionable``."""
    import polars as pl

    names, flags = [], []
    for name, actionable in rows:
        names.append(wire(name))
        flags.append(bool(actionable))
    return pl.DataFrame(
        {"name": names, "actionable": flags},
        schema={"name": pl.String, "actionable": pl.Boolean},
    )


def actionable_by_name(frame: "pl.DataFrame") -> Dict[str, int]:
    """The actionable results of each name in *frame*, every name a key, counted or
    not, in the order each was first seen."""
    grouped = ordered_counts(frame, "name", weight="actionable")
    return {unwire(name): number for name, number in grouped.iter_rows()}
