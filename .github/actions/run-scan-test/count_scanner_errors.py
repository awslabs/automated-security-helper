# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Count scanners that reported status ERROR in ash_aggregated_results.json.

Run with:
    python3 count_scanner_errors.py [RESULTS_JSON] [--count-only]

Why this exists
---------------
The "Validate No Plugin Errors" steps used to count plugin errors by grepping the
*text report* for the string "ERROR":

    ERROR_COUNT=$(echo "$REPORT_OUTPUT" | grep -c "ERROR" || true)
    if [ "$ERROR_COUNT" -gt 1 ]; then ...

That is wrong in two compounding ways, and the second one is why this file exists
rather than a smaller patch.

1. It counted a legend line. ``TextReporter`` emits
   ``"  - ERROR = Scanner execution error"`` whenever ``include_summary`` is true,
   which it is by default and explicitly in both configs CI uses. So the grep always
   matched at least once, and the threshold was ``-gt 1`` to skip that one line.
2. The offset made the check off by one in the dangerous direction. With the legend
   present a single real scanner ERROR gives a count of 2, which trips ``-gt 1`` --
   but only because the legend happens to be there. If the legend line ever changes
   wording or ``include_summary`` is turned off, the count for one real ERROR drops
   to 1, ``-gt 1`` is false, and the step passes. Exactly one real scanner error
   reads as clean.

Grepping rendered prose for a status also cannot distinguish the legend from a
finding from a scanner name that happens to contain the substring, and the Windows
leg used ``Select-String "ERROR"``, which is case-insensitive by default, so any
report line containing lower-case "error" inflated the count.

This script reads the machine-readable results instead, so no legend line exists to
skip and the threshold is a plain "more than zero".

A note on the old comment, for the record: it claimed the unguarded ``grep -c``
"failed this step in the good case". It did not. Because the legend line is always
present, the grep always matched and always exited 0. Run 34493384101 at head
518cc13 still carried the unguarded form at all three sites and the bash,
python-local and python-container cells all reported success. The ``|| true`` added
later was a no-op; the real defect was the direction of the failure, not the status.

What it reads
-------------
``AshAggregatedResults.scanner_results`` is a mapping of scanner name to status
record. The final populate in ``automated_security_helper/core/unified_metrics.py``
writes ``ScannerTargetStatusInfo``, which carries ``status`` at the top level. Some
other paths assign ``ScannerStatusInfo``, which nests ``source`` and ``converted``
sub-records each with their own ``status``. Both shapes are inspected, because a
counter that understood only one of them would silently under-count -- the same
class of failure this script replaces.

Status values are normalized before comparison: ``"ERROR"``, ``"error"`` and
``"ScannerStatus.ERROR"`` all count. That mirrors ``normalize_status`` in
``scripts/verify_external_target_scan.py``, and the reason is the same -- a change
in how the enum serializes must not silently turn every comparison false.

Refusing to inspect nothing
---------------------------
A missing file, a non-object payload, a missing ``scanner_results`` key or an empty
one all exit non-zero rather than reporting zero errors. A scan that recorded no
scanners at all has not demonstrated that no scanner failed, and "0 errors" from an
empty input is the silent pass this whole script exists to prevent.

Exit codes
----------
0   the results were readable and no scanner reported ERROR
1   at least one scanner reported ERROR, or the results could not be inspected

``--count-only`` prints the count and exits 0 whenever the results were readable,
whatever the count. It is for probing the counter itself; CI uses the default.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

DEFAULT_RESULTS_PATH = Path(".ash") / "ash_output" / "ash_aggregated_results.json"

STATUS_ERROR = "ERROR"

# Sub-records that carry their own status in the ScannerStatusInfo shape.
NESTED_TARGET_KEYS = ("source", "converted")


def normalize_status(raw: Any) -> str:
    """Return a bare uppercase status name.

    Tolerates ``"PASSED"`` and a stringified enum such as ``"ScannerStatus.PASSED"``
    alike, so a change in how the model serializes does not silently turn every
    status comparison false.
    """
    text = str(raw if raw is not None else "").strip()
    if "." in text:
        text = text.rsplit(".", 1)[-1]
    return text.upper()


def error_statuses_in(record: Mapping[str, Any]) -> list[str]:
    """Every place inside one scanner record that says ERROR.

    Returns labels such as ``"status"`` or ``"source.status"`` so the caller can
    report which field produced the verdict rather than just a count.
    """
    found: list[str] = []
    if normalize_status(record.get("status")) == STATUS_ERROR:
        found.append("status")
    for key in NESTED_TARGET_KEYS:
        nested = record.get(key)
        if (
            isinstance(nested, Mapping)
            and normalize_status(nested.get("status")) == STATUS_ERROR
        ):
            found.append(f"{key}.status")
    return found


def count_scanner_errors(results: Any) -> tuple[int, dict[str, list[str]], list[str]]:
    """Count scanners at ERROR.

    Returns ``(count, {scanner: [fields]}, problems)``. ``problems`` is non-empty
    when the input could not be inspected at all, which the caller must treat as a
    failure rather than as zero errors.
    """
    if not isinstance(results, Mapping):
        return (
            0,
            {},
            [
                (
                    f"results is not a JSON object (got {type(results).__name__}); "
                    "expected the parsed aggregated results"
                )
            ],
        )

    scanner_results = results.get("scanner_results")
    if not isinstance(scanner_results, Mapping):
        return (
            0,
            {},
            [
                (
                    "results has no 'scanner_results' object, so this check would "
                    "inspect nothing. Available top-level keys: "
                    f"{sorted(str(key) for key in results)}"
                )
            ],
        )
    if not scanner_results:
        return (
            0,
            {},
            ["'scanner_results' is empty -- the scan recorded no scanners at all"],
        )

    offenders: dict[str, list[str]] = {}
    for name, entry in scanner_results.items():
        if not isinstance(entry, Mapping):
            continue
        fields = error_statuses_in(entry)
        if fields:
            offenders[str(name)] = fields
    return len(offenders), offenders, []


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Count scanners reporting status ERROR in an ASH aggregated results "
            "file. Exits non-zero when any scanner errored, or when the file "
            "cannot be inspected."
        )
    )
    parser.add_argument(
        "results",
        nargs="?",
        default=str(DEFAULT_RESULTS_PATH),
        help=f"path to the results JSON (default: {DEFAULT_RESULTS_PATH})",
    )
    parser.add_argument(
        "--count-only",
        action="store_true",
        help=(
            "print the count and exit 0 whatever it is, as long as the results "
            "were readable. For probing this script; CI uses the default."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    path = Path(args.results)

    if not path.is_file():
        print(f"ERROR: no results file at '{path}'", file=sys.stderr)
        return 1
    try:
        results = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as bad_json:
        print(f"ERROR: '{path}' is not valid JSON: {bad_json}", file=sys.stderr)
        return 1

    count, offenders, problems = count_scanner_errors(results)

    if problems:
        for problem in problems:
            print(f"ERROR: {problem}", file=sys.stderr)
        return 1

    # Stdout carries the bare count so a caller can capture it; everything else is
    # commentary on stderr.
    print(count)

    if offenders:
        print(
            f"Found {count} scanner(s) reporting status ERROR:",
            file=sys.stderr,
        )
        for name in sorted(offenders):
            fields = ", ".join(offenders[name])
            print(f"  - {name} (via {fields})", file=sys.stderr)
        print(
            "A scanner at ERROR ran and broke. Check that scanner's "
            "subdirectory of the output dir, and the scan log above.",
            file=sys.stderr,
        )
    else:
        print("No scanner reported status ERROR.", file=sys.stderr)

    if args.count_only:
        return 0
    return 1 if count else 0


if __name__ == "__main__":
    raise SystemExit(main())
