# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The per-result projection of the JUnit XML report, on a polars frame.

The reporter reads each SARIF result once and lands one row per result here. The
frame then answers the two relational questions of the report: what each case
reports (the outcome cascade, a ``when/then`` chain over the row's yes/no
columns) and which suite each case belongs to (a group-by in first-seen order).

========================  =========  =============================================
``i``                     Int64      the result's position among the run's results
``suite``                 String     the suite name, through ``frame_text.wire``
``in_effect``             Boolean    a suppression in effect accepted the finding
``not_applicable``        Boolean    the rule was not evaluated
``policy_skip``           Boolean    a policy scanner's finding in a project whose
                                     policy gate is off
``actionable``            Boolean    the severity gate's verdict; null for a row
                                     decided by one of the three flags above
``kind_asserts``          Boolean    the result's kind asserts a finding
``kind_fail``             Boolean    the result's kind is ``fail``
``level_reports``         Boolean    the level is ``error`` or ``warning``
``level_type``            String     the ``type`` the level maps to; null for none
``outcome``               String     ``suppression``, ``not-evaluated``,
                                     ``policy-not-gating``, ``threshold``,
                                     ``error`` or ``pass`` (derived)
``error_type``            String     the ``<error>`` type of an ``error`` outcome
                                     (derived)
========================  =========  =============================================

What stays row-wise Python in the reporter, and why. Each of these reads one
result's own object graph, or looks a value up in the recorded configuration, and
none of them is algebra over rows:

* the scanner and project of a result (tag scans, pydantic extras, the shared
  ``extract_workspace_project``), the message, rule and metadata text, and the
  suppressions in effect: attribute reads on a SARIF object;
* the severity gate, which resolves a threshold from five sources (a property, two
  recorded per-project maps, a memoized per-scanner resolver that dumps the
  configuration, the scan default) and calls the shared ladder, which logs a
  warning for an unrecognised threshold. It runs only for a result no flag above
  decided, once each, so those warnings are what they were;
* building the ``junitparser`` elements and serializing them: formatting, and the
  skipped-project suites, which are one case each with nothing to group.

Text goes through ``frame_text.wire``: a scanner name or project can hold a lone
surrogate, which a polars string cannot. Only the suite name enters a String
column; the cases' own text stays in Python lists beside the frame and is read by
``i``, as the flat frame's consumers read the finding by ``i``.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Sequence, Tuple

import polars as pl

from automated_security_helper.utils.frame_text import unwire, wire


class CaseOutcome(str, Enum):
    """What a case reports: the frame's ``outcome`` column, and the ``type`` of the
    ``<skipped>`` element of every outcome but ``error`` and ``pass``.

    One definition for the writer (the cascade below) and the reader (the
    reporter's element builder), so a skip type a consumer selects on cannot
    drift from the outcome that produced it.
    """

    SUPPRESSION = "suppression"
    NOT_EVALUATED = "not-evaluated"
    POLICY_NOT_GATING = "policy-not-gating"
    THRESHOLD = "threshold"
    ERROR = "error"
    PASS = "pass"


_SCHEMA = {
    "i": pl.Int64,
    "suite": pl.String,
    "in_effect": pl.Boolean,
    "not_applicable": pl.Boolean,
    "policy_skip": pl.Boolean,
    "actionable": pl.Boolean,
    "kind_asserts": pl.Boolean,
    "kind_fail": pl.Boolean,
    "level_reports": pl.Boolean,
    "level_type": pl.String,
}


def cases_frame(
    suites: Sequence[str],
    in_effect: Sequence[bool],
    not_applicable: Sequence[bool],
    policy_skip: Sequence[bool],
    actionable: Sequence[bool | None],
    kind_asserts: Sequence[bool],
    kind_fail: Sequence[bool],
    level_reports: Sequence[bool],
    level_type: Sequence[str | None],
) -> pl.DataFrame:
    """One row per result, with its outcome and error type derived."""
    frame = pl.DataFrame(
        {
            "i": list(range(len(suites))),
            "suite": [wire(name) for name in suites],
            "in_effect": list(in_effect),
            "not_applicable": list(not_applicable),
            "policy_skip": list(policy_skip),
            "actionable": list(actionable),
            "kind_asserts": list(kind_asserts),
            "kind_fail": list(kind_fail),
            "level_reports": list(level_reports),
            "level_type": list(level_type),
        },
        schema=_SCHEMA,
    )
    # A kind that asserts a finding is always an <error>: the level's own type,
    # else `error` for `fail` and `note` for the others. Any other kind is one
    # only when the level itself says error or warning.
    error_type = (
        pl.when(pl.col("kind_asserts"))
        .then(
            pl.coalesce(
                pl.col("level_type"),
                pl.when(pl.col("kind_fail"))
                .then(pl.lit("error"))
                .otherwise(pl.lit("note")),
            )
        )
        .when(pl.col("level_reports"))
        .then(pl.col("level_type"))
        .otherwise(pl.lit(None, dtype=pl.String))
    )
    frame = frame.with_columns(error_type.alias("error_type"))
    outcome = (
        pl.when(pl.col("in_effect"))
        .then(pl.lit(CaseOutcome.SUPPRESSION.value))
        .when(pl.col("not_applicable"))
        .then(pl.lit(CaseOutcome.NOT_EVALUATED.value))
        .when(pl.col("policy_skip"))
        .then(pl.lit(CaseOutcome.POLICY_NOT_GATING.value))
        .when(pl.col("actionable").fill_null(False))
        .then(
            pl.when(pl.col("error_type").is_not_null())
            .then(pl.lit(CaseOutcome.ERROR.value))
            .otherwise(pl.lit(CaseOutcome.PASS.value))
        )
        .otherwise(pl.lit(CaseOutcome.THRESHOLD.value))
    )
    return frame.with_columns(outcome.alias("outcome"))


def suite_members(frame: pl.DataFrame) -> List[Tuple[str, List[int]]]:
    """``(suite name, result positions)`` for each suite, suites in the order their
    first result appears, positions in the order the results came."""
    grouped = frame.group_by("suite", maintain_order=True).agg(pl.col("i"))
    return [(unwire(suite), members) for suite, members in grouped.iter_rows()]
