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
* :func:`severity_counts_by_name` for the severity counts of every scanner name at
  once, from one walk. A row is ``(name, kind)``.

Text goes into a String column through :func:`~automated_security_helper.utils.
frame_text.wire`, so a scanner name or a severity with a lone surrogate is carried,
not refused, and comes back unchanged. Both group-bys keep the order each key was
first seen in, which is the order the loops they replace built their dicts in, and
the severity tally refuses a kind the counter does not know at the first one seen,
with the counter's own message, as the loop did at the first such result.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, Iterable, List, Tuple

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
    from automated_security_helper.models.asharp_model import ScannerSeverityCount

    if counts is None:
        counts = ScannerSeverityCount()
    grouped = ordered_counts(frame, "kind")
    return _add_kind_counts(
        counts, ((unwire(wired), number) for wired, number in grouped.iter_rows())
    )


def _add_kind_counts(
    counts: "ScannerSeverityCount", pairs: Iterable[Tuple[str, int]]
) -> "ScannerSeverityCount":
    """Add each ``(kind, number)`` of *pairs* to the counter field the kind names.

    A kind that is not a counter field raises ``ValueError("Invalid severity: ...")``
    at the first such pair, as ``ScannerSeverityCount.increment`` does.
    """
    from automated_security_helper.models.asharp_model import _VALID_INCREMENT_FIELDS

    for kind, number in pairs:
        key = kind.lower()
        if key not in _VALID_INCREMENT_FIELDS:
            raise ValueError(f"Invalid severity: {kind!r}")
        setattr(counts, key, getattr(counts, key) + number)
    return counts


class SeverityCountsByName:
    """The severity counts of every scanner name one SARIF walk found.

    Built by :func:`severity_counts_by_name`. ``names`` lists each exact spelling
    once, in the order the walk first met it. :meth:`for_name` answers a scanner's
    counts the way a walk filtered to that name does: results match a name by its
    case-folded text, and a kind the counter does not know raises when its name
    is read, not when the walk is counted.
    """

    def __init__(
        self,
        names: List[str],
        kinds_by_name: Dict[str, List[Tuple[str, int]]],
    ) -> None:
        self.names = names
        self._kinds_by_name = kinds_by_name

    def for_name(self, scanner_name: str) -> "ScannerSeverityCount":
        """A fresh counter for *scanner_name*: zeros when no result names it."""
        from automated_security_helper.models.asharp_model import ScannerSeverityCount

        counts = ScannerSeverityCount()
        if not self.names:
            # No result named a scanner, so a per-name walk never folded the
            # name it was asked for either: a name that is not text fails only
            # where there is something to compare it with.
            return counts
        return _add_kind_counts(
            counts, self._kinds_by_name.get(scanner_name.lower(), ())
        )


def severity_counts_by_name(rows: Iterable[Tuple[str, str]]) -> SeverityCountsByName:
    """The counts of every scanner name in *rows*, one ordered count for all of them.

    A row is ``(scanner name, kind)``, the kind a resolved severity or
    :data:`SUPPRESSED`. Names are folded on the host before they are wired, so
    one scanner under two spellings is one key of the count, and the exact
    spellings are kept in first-seen order for the caller that lists them.
    """
    rows = list(rows)
    names = list(dict.fromkeys(name for name, _ in rows))
    frame = named_severity_frame(rows)
    kinds_by_name: Dict[str, List[Tuple[str, int]]] = {}
    for wired_name, wired_kind, number in ordered_counts(
        frame, ["name", "kind"]
    ).iter_rows():
        kinds_by_name.setdefault(unwire(wired_name), []).append(
            (unwire(wired_kind), number)
        )
    return SeverityCountsByName(names, kinds_by_name)


def named_severity_frame(rows: Iterable[Tuple[str, str]]) -> "pl.DataFrame":
    """One row per counted result: the case-folded scanner ``name`` and its ``kind``."""
    import polars as pl

    names, kinds = [], []
    for name, kind in rows:
        names.append(wire(name.lower()))
        kinds.append(wire(kind))
    return pl.DataFrame(
        {"name": names, "kind": kinds},
        schema={"name": pl.String, "kind": pl.String},
    )


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
