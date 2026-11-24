# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The order in which a scanner's status is decided, written once.

``get_unified_scanner_metrics`` grades each scanner's row and
``ScannerStatisticsCalculator.get_summary_statistics`` counts the scanners in each
status; both ran their own copy of the same ordered case-when, kept equal by a
comment in each. The order is observable, not cosmetic:

1. ``error``, or counters that cannot be read: no usable results came back, the
   loudest thing that can be said about a scanner.
2. ``actionable > 0``: it produced findings. Ahead of the three did-not-run
   branches, which all resolve to a status for which ``passed`` is true, so a row
   reaching one of them with findings would show green while the exit code fails
   the build.
3. ``excluded``: the operator switched it off (SKIPPED).
4. ``dependencies_missing``: it could not run here (MISSING).
5. ``evaluated_nothing``: it ran and had no input (SKIPPED).

Anything else is ``None``: the caller decides from what the scanner's row records.
The statistics are read as each caller read them (``default_flags`` below: the unified
metrics index ``error`` and ``evaluated_nothing``, the summary reads them with a
default), and lazily, in the order above, so a row missing a key a branch it never
reaches would read is still graded.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Optional

ERROR = "ERROR"
FAILED = "FAILED"
SKIPPED = "SKIPPED"
MISSING = "MISSING"


def grade(
    stats: Mapping[str, Any],
    unusable_counters: Callable[[], bool] | bool,
    *,
    default_flags: bool,
) -> Optional[str]:
    """The status the first matching branch gives *stats*, or ``None``.

    *unusable_counters* is the answer, or a callable that gives it when the ``error``
    flag has not already decided (the summary reads the per-target counters only
    then). With *default_flags* a stats row from an older writer may carry neither
    ``error`` nor ``evaluated_nothing``, and absence is "no claim"; without it
    both keys are required, as the unified metrics index them.
    """

    def flag(key: str) -> Any:
        return stats.get(key, False) if default_flags else stats[key]

    if flag("error") or (
        unusable_counters() if callable(unusable_counters) else unusable_counters
    ):
        return ERROR
    if stats["actionable"] > 0:
        return FAILED
    if stats["excluded"]:
        return SKIPPED
    if stats["dependencies_missing"]:
        return MISSING
    if flag("evaluated_nothing"):
        return SKIPPED
    return None
