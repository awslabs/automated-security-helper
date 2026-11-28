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

The columns, their dtypes and their order are :data:`FLAT_SPEC`, derived from the
markers on :class:`FlatVulnerability`'s fields and the declared computed columns
below; ``frame_schema(FLAT_SPEC)`` is the schema. The columns that are not a
field projected as it is:

``i``
    the position in the list.
``scanner_key``
    the scanner lower-cased, ``""`` for none: the key the suppressed counts are
    taken by.
``line_overflow``
    whether either line is a number a 64-bit column cannot hold; the line
    columns are null for such a line.
``source_report``
    the ``additional_reports`` key the row was read from; null for a SARIF row.
``has_identity``
    whether the finding has an identity.
``fingerprinted``
    whether its identity key is keyed by a fingerprint.
``base``
    :func:`~automated_security_helper.utils.finding_identity.canonical` of the
    identity base; null without an identity.

Every String column holds text through :func:`~automated_security_helper.utils.
frame_text.wire`: a path can hold a lone surrogate and polars strings are UTF-8.
The one Enum column, ``severity``, holds the ladder's own ASCII words directly and
bypasses ``wire``; a value that is not one of them stops the build.
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

from typing import TYPE_CHECKING, Dict, Optional, Sequence

from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.models.frame_model import (
    Computed,
    FrameSpec,
    Position,
    to_frame,
)
from automated_security_helper.utils.finding_identity import canonical
from automated_security_helper.utils.frame_ops import ordered_counts
from automated_security_helper.utils.frame_text import unwire

if TYPE_CHECKING:
    import polars as pl


def _base(finding: FlatVulnerability) -> Optional[str]:
    base = finding.identity_base
    return None if base is None else canonical(base)


FLAT_SPEC = FrameSpec(
    FlatVulnerability,
    columns=(
        Position("i"),
        "id",
        "scanner",
        Computed(
            "scanner_key",
            "String",
            lambda finding: (finding.scanner or "").lower(),
            reads=("scanner",),
            nullable=False,
            note="the key the suppressed counts are taken by",
        ),
        "scanner_type",
        "rule_id",
        "severity",
        "file_path",
        "line_start",
        "line_end",
        "is_suppressed",
        Computed(
            "source_report",
            "String",
            lambda finding: finding.source_report,
            reads=("source_report",),
            note="a property over the private _source_report; model_fields "
            "cannot see it",
        ),
        Computed(
            "has_identity",
            "Boolean",
            lambda finding: finding.identity is not None,
            reads=("identity",),
            nullable=False,
        ),
        Computed(
            "fingerprinted",
            "Boolean",
            lambda finding: finding.has_fingerprint_identity,
            reads=("has_fingerprint_identity",),
            nullable=False,
        ),
        Computed("base", "String", _base, reads=("identity_base",)),
        # The cross-scanner correlation id: a nullable String column, so a
        # consumer can group the findings of a run that share an observation
        # without re-deriving the key (utils/finding_identity, "Correlation
        # ids"). Null for a finding that carries none.
        "correlation_id",
    ),
    waived={
        "_identity": "read through the identity and identity_base properties",
        "_assigned_identity_key": "read through has_fingerprint_identity and "
        "identity_base",
        "_identity_message": "the identity message is a join input of the diff "
        "side, not a column of the flat frame",
        "_secret_detection": "a baseline-gate policy flag, not a column of the "  # pragma: allowlist secret
        "flat frame",
        "_source_report": "read through the source_report property",
        "identity_message": "the identity message is a join input of the diff "
        "side, not a column of the flat frame",
        "location_display": "display text over file_path and the lines, which "
        "the frame carries as columns",
        "is_secret_detection": "a rule-classification flag the correlation "
        "registry reads on the host; the frame carries no column for it",
        "requires_exact_identity_match": "a baseline-gate policy flag, not a "
        "column of the flat frame",
        "_states_no_finding": "the verdict of the whole result, read through the "
        "is_finding property; the frame carries no column for it",
        "is_finding": "the verdict of the result the row was read from (a reading of "
        "_states_no_finding, else of result_kind and severity), which is not a "
        "frame column; a consumer that counts filters the host list before it "
        "builds a frame",
    },
)


def flat_frame(findings: Sequence[FlatVulnerability]) -> "pl.DataFrame":
    """*findings*, flattened findings of one run, as a frame (see the module
    docstring for the columns)."""
    return to_frame(findings, FLAT_SPEC)


def suppressed_by_scanner(frame: "pl.DataFrame") -> Dict[str, int]:
    """The number of suppressed findings of each scanner in *frame*, keyed by the
    lower-cased scanner name, in the order each scanner's first suppressed finding
    appears. A scanner with none has no entry."""
    import polars as pl

    counted = ordered_counts(frame.filter(pl.col("is_suppressed")), "scanner_key")
    return {unwire(scanner): count for scanner, count in counted.iter_rows()}
