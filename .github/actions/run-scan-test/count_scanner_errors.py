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

The same doctrine applies one level in, per entry, and it takes two checks rather
than one. An entry is unreadable if it is not a JSON object, and equally if it is an
object that declares no status anywhere this file knows to look. Either way its
status was never read, so it is reported as a problem instead of being skipped.

Both were holes in the first version. The container checks above catch a missing or
empty ``scanner_results``, so they do not fire when ``scanner_results`` is a perfectly
good non-empty mapping whose contents changed shape underneath it:

* Serialization changes from a mapping-of-records to, say, a list per scanner. Every
  entry fails the object check, every entry is skipped.
* A leaf field is renamed, or a scanner simply never set one, so every entry is still
  an object but ``record.get("status")`` is ``None`` everywhere. This one is nastier
  because nothing looks wrong: ``normalize_status(None)`` is ``""``, which compares
  unequal to ``"ERROR"``, so every entry reads as "not an error" and is cleared.

In both cases no offender is recorded, no problem is recorded, and the script prints 0
and exits 0 -- the identical silent pass, reached through the leaf instead of through
the container. The asymmetry between them is what gave the second one away: a record
of ``[]`` failed loudly while a record of ``{}`` passed silently, and both had
measured exactly nothing. Hence ``status_fields_in`` below, which asks whether a
status was found at all. ``error_statuses_in`` cannot answer that, because a record
with no status and a record with a status of PASSED both yield no ERROR fields.

Any unreadable entry is a problem, not just the all-unreadable case, and that is
deliberate. A threshold would reintroduce the defect this script replaced: the old
grep was wrong precisely because it carried an offset, and "fail only when all of
them are unreadable" is another offset, one that lets a partial serialization change
under-count silently. A scanner whose record could not be read has not demonstrated
that it did not error, which is the same sentence as the empty case above.

Why the readability check cannot fail a healthy scan, which is the thing to get right
given that five CI steps read this exit code. Both model shapes always carry a status
somewhere, including in the one case that looks risky. ``ScannerTargetStatusInfo``
declares ``status: ScannerStatus = ScannerStatus.PASSED``, so its top-level status is
never null. ``ScannerStatusInfo`` declares ``status: ScannerStatus | None = None``, so
its top-level status genuinely can be null -- but it also always carries ``source`` and
``converted`` sub-records, each a ``ScannerTargetStatusInfo`` whose own status defaults
to PASSED. Measured rather than inferred from the defaults: serializing a default
instance of each and running it through this function yields ``["status"]`` for the
first and ``["source.status", "converted.status"]`` for the second, and both produce no
problems. A real aggregated results file with ten scanners in it also comes back clean.

A note on an argument this file used to make and no longer relies on. It claimed a
rename of the leaf ``status`` field needed no guard here, because hundreds of ASH unit
tests read that field and would redden the suite first. That is an alibi located in
other files, and it fails in exactly the case that matters: a rename landed together
with a sweep updating those tests, which is how renames actually get done. The
readability check above covers the rename without special-casing it, so the argument
is no longer load bearing.

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


def status_fields_in(record: Mapping[str, Any]) -> list[str]:
    """Every place inside one scanner record that carries a status at all.

    Returns labels such as ``"status"`` or ``"source.status"``, whatever the value
    says. An empty result is the point of this function: it means the record declared
    no status anywhere this counter knows to look, so the record was never actually
    inspected and must not be read as a clean one. ``error_statuses_in`` below cannot
    answer that question, because a record with no status and a record with a status
    of PASSED both produce no ERROR fields.
    """
    found: list[str] = []
    if normalize_status(record.get("status")):
        found.append("status")
    for key in NESTED_TARGET_KEYS:
        nested = record.get(key)
        if isinstance(nested, Mapping) and normalize_status(nested.get("status")):
            found.append(f"{key}.status")
    return found


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

    Returns ``(count, {scanner: [fields]}, problems)``. ``problems`` is non-empty when
    any part of the input could not be inspected, which the caller must treat as a
    failure rather than as zero errors. That covers the whole payload, a missing or
    empty ``scanner_results``, and any individual entry inside it that is either not an
    object or declares no status -- an entry that was never read cannot be evidence
    that it did not error.

    Contract: whenever ``problems`` is non-empty, ``count`` is 0 and the offenders
    mapping is empty, uniformly across all four checks. A partial count would look
    authoritative to a caller while totalling only the entries that happened to be
    readable, so anything found is named in the ``problems`` strings instead.
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
    unreadable: list[str] = []
    for name, entry in scanner_results.items():
        if not isinstance(entry, Mapping):
            unreadable.append(f"{name} (not an object: {type(entry).__name__})")
            continue
        if not status_fields_in(entry):
            unreadable.append(f"{name} (an object, but it declares no status)")
            continue
        fields = error_statuses_in(entry)
        if fields:
            offenders[str(name)] = fields
    if unreadable:
        problems = [
            (
                "the status of these 'scanner_results' entries was never inspected, so "
                "they cannot have demonstrated that they did not error: "
                f"{sorted(unreadable)}"
            )
        ]
        if offenders:
            problems.append(
                "among the entries that could be read, these reported ERROR: "
                f"{sorted(offenders)}"
            )
        # Count 0 and no offenders, matching the three checks above: whenever
        # problems is non-empty the count is not a total of anything, and a caller
        # reading the tuple must not be handed a partial number that looks like one.
        # Everything found is named in the messages instead.
        return 0, {}, problems
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
