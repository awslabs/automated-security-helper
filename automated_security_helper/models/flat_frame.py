# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The flattened findings of a run as a polars frame.

``AshAggregatedResults.to_flat_vulnerabilities`` walks the runs and their results
and builds one :class:`FlatVulnerability` per result, with the extractors that
read the SARIF tree; the walk, the objects, the memo of them and the counts it
writes back to the model stay on the host. What every consumer that counts,
groups or joins findings needs is the rows as columns, which :func:`flat_frame`
projects, and the one aggregate the model's own flatten needs, each scanner's
suppressed count (:func:`suppressed_by_scanner`), is a group-by over it.

The frame has one row per finding, in the order of the list given, so ``i`` is
the finding's position in the host list: a consumer that needs a field the frame
does not carry reads ``findings[i]``.

========================  =========  =============================================
``i``                     Int64      position in the list
``id``                    String     the finding's id
``scanner``               String     the finding's scanner; null for none
``scanner_key``           String     the scanner lower-cased, ``""`` for none: the
                                     key the suppressed counts are taken by
``scanner_type``          String     the finding's scanner type
``rule_id``               String     the rule; null for none
``severity``              String     the severity as the finding holds it
``file_path``             String     the file as the finding holds it
``line_start``            Int64      the first line; null for none, or when it does
                                     not fit 64 bits (see ``line_overflow``)
``line_end``              Int64      the last line, as ``line_start``
``line_overflow``         Boolean    whether either line is a number a 64-bit
                                     column cannot hold
``is_suppressed``         Boolean    whether the finding is suppressed
``source_report``         String     the ``additional_reports`` key the row was read
                                     from; null for a SARIF row
``has_identity``          Boolean    whether the finding has an identity
``fingerprinted``         Boolean    whether its identity key is keyed by a
                                     fingerprint
``base``                  String     :func:`~automated_security_helper.utils.
                                     finding_identity.canonical` of the identity
                                     base; null without an identity
========================  =========  =============================================

Every String column holds text through :func:`~automated_security_helper.utils.
frame_text.wire`: a path can hold a lone surrogate and polars strings are UTF-8.
``wire`` is one-to-one, so two cells are equal exactly when the texts are and
sort as the texts' code points do; ``unwire`` gives the text back. A finding
holds its lines as unbounded Python ints; a frame column is 64-bit, so a line that
does not fit is null with ``line_overflow`` set, and the finding object, by ``i``,
has the number.

The frame is rebuilt from the list on every call and never cached: the findings
are mutable (a suppression is set on one in place) and the model's own memo of the
list has its own rules for when it is stale.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence, Tuple

from automated_security_helper.utils.finding_identity import canonical
from automated_security_helper.utils.frame_ops import ordered_counts
from automated_security_helper.utils.frame_text import unwire, wire, wire_cell

if TYPE_CHECKING:
    import polars as pl

    from automated_security_helper.models.flat_vulnerability import FlatVulnerability

_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1


def _line(value: Optional[int]) -> Tuple[Optional[int], bool]:
    """*value* as a 64-bit column holds it, and whether it did not fit."""
    if value is None:
        return None, False
    if _INT64_MIN <= value <= _INT64_MAX:
        return value, False
    return None, True


def flat_frame(findings: Sequence["FlatVulnerability"]) -> "pl.DataFrame":
    """*findings*, flattened findings of one run, as a frame (see the module
    docstring for the columns)."""
    import polars as pl

    columns: Dict[str, List[Any]] = {
        name: []
        for name in (
            "i",
            "id",
            "scanner",
            "scanner_key",
            "scanner_type",
            "rule_id",
            "severity",
            "file_path",
            "line_start",
            "line_end",
            "line_overflow",
            "is_suppressed",
            "source_report",
            "has_identity",
            "fingerprinted",
            "base",
        )
    }
    for index, finding in enumerate(findings):
        start, start_over = _line(finding.line_start)
        end, end_over = _line(finding.line_end)
        base = finding.identity_base
        row = (
            index,
            wire_cell(finding.id),
            wire_cell(finding.scanner),
            wire((finding.scanner or "").lower()),
            wire_cell(finding.scanner_type),
            wire_cell(finding.rule_id),
            wire_cell(finding.severity),
            wire_cell(finding.file_path),
            start,
            end,
            start_over or end_over,
            bool(finding.is_suppressed),
            wire_cell(finding.source_report),
            finding.identity is not None,
            finding.has_fingerprint_identity,
            None if base is None else wire(canonical(base)),
        )
        for name, value in zip(columns, row):
            columns[name].append(value)
    return pl.DataFrame(
        columns,
        schema={
            "i": pl.Int64,
            "id": pl.String,
            "scanner": pl.String,
            "scanner_key": pl.String,
            "scanner_type": pl.String,
            "rule_id": pl.String,
            "severity": pl.String,
            "file_path": pl.String,
            "line_start": pl.Int64,
            "line_end": pl.Int64,
            "line_overflow": pl.Boolean,
            "is_suppressed": pl.Boolean,
            "source_report": pl.String,
            "has_identity": pl.Boolean,
            "fingerprinted": pl.Boolean,
            "base": pl.String,
        },
    )


def suppressed_by_scanner(frame: "pl.DataFrame") -> Dict[str, int]:
    """The number of suppressed findings of each scanner in *frame*, keyed by the
    lower-cased scanner name, in the order each scanner's first suppressed finding
    appears. A scanner with none has no entry."""
    import polars as pl

    counted = ordered_counts(frame.filter(pl.col("is_suppressed")), "scanner_key")
    return {unwire(scanner): count for scanner, count in counted.iter_rows()}
