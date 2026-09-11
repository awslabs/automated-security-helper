# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fail a CI job when a scanner it was supposed to run did not complete.

Reads ``scanner_results[*].status`` out of ``ash_aggregated_results.json`` and
exits 1 when any scanner is ERROR (ran and failed) or MISSING (its dependencies
were unavailable, so it never ran). SKIPPED scanners are ones the run did not
select -- ``--exclude-scanners``, a config that disables them, or one shard of a
sharded run -- and are reported but do not fail the job.

Why this exists in this shape
-----------------------------
It replaces five separate in-line guards, four of which grepped the *prose* text
report for the substring "ERROR" and compared the line count against 1 to
discount the report's own legend line ("ERROR = Scanner execution error"). That
construction had three faults, and every one of them was measured on a real run
rather than reasoned about:

1. It could not see MISSING at all. A grep for ERROR does not match MISSING, so a
   cell where four of ten scanners never ran passed the guard. That is the whole
   defect this script exists to close: on one measured pull-request run, four
   green check runs each carried three or four MISSING scanners, each at under a
   millisecond, and in the cells where those scanners did run one of them
   reported 82 findings. The green cells were not clean, they were unmeasured.
2. The legend subtraction made the threshold depend on the report's formatting. A
   report rendered without the legend gives a genuine single ERROR a count of 1,
   which is not greater than 1, so it passed.
3. The grep matched anywhere in the report, so a finding message, rule id or file
   path containing the letters ERROR failed the job for no reason.

The fifth guard read JSON but at a path that does not exist -- ``scanners`` keyed
by ``result`` rather than ``scanner_results`` keyed by ``status``. In PowerShell's
default non-strict mode that resolves to $null, the loop body never ran, and the
step reported success unconditionally. A gate that cannot fail is worse than no
gate, because its green is read as evidence.

Reading the JSON status rather than the rendered report also means the guard and
ASH's own exit code answer from the same field, so they cannot disagree.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# The two statuses that mean "this scanner was selected and did not complete".
# Kept in step with automated_security_helper.interactions.run_ash_scan's
# _INCOMPLETE_SCANNER_STATUSES. Spelled as literals here rather than imported
# because this script runs before -- and independently of -- an importable ASH:
# the bash and PowerShell scan methods leave no ASH on the runner's PATH at all.
INCOMPLETE_STATUSES = ("ERROR", "MISSING")

DEFAULT_RESULTS = Path(".ash") / "ash_output" / "ash_aggregated_results.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "results",
        nargs="?",
        default=DEFAULT_RESULTS,
        type=Path,
        help=f"Path to ash_aggregated_results.json (default: {DEFAULT_RESULTS})",
    )
    args = parser.parse_args()

    if not args.results.is_file():
        print(f"::error::Scan results not found at {args.results}")
        return 1

    try:
        results = json.loads(args.results.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"::error::Could not read {args.results}: {exc}")
        return 1

    scanner_results = results.get("scanner_results")
    if not isinstance(scanner_results, dict) or not scanner_results:
        # No scanner reported at all. Treated as a failure rather than a vacuous
        # pass for the same reason the rest of this script exists: zero scanners
        # produce zero findings, which is indistinguishable from a clean scan if
        # you only look at the findings.
        print(
            f"::error::{args.results} reports no scanners. "
            "A scan that ran nothing has not shown the target to be clean."
        )
        return 1

    print(f"Scanner completion, read from {args.results}:")
    incomplete: list[tuple[str, str]] = []
    for name in sorted(scanner_results):
        entry = scanner_results[name] or {}
        status = entry.get("status") if isinstance(entry, dict) else None
        status = str(status) if status is not None else "UNKNOWN"
        print(f"  {name:<24} {status}")
        # UNKNOWN counts as incomplete. An entry whose status could not be read is
        # not evidence that the scanner ran.
        if status in INCOMPLETE_STATUSES or status == "UNKNOWN":
            incomplete.append((name, status))

    # Consistency check on the counters, cheap and worth having: every scanner
    # should land in exactly one outcome bucket. When they did not sum, the
    # missing one was ERROR -- it had no counter, so two scanners that ran and
    # failed were absent from every total while each total read clean.
    stats = results.get("metadata", {}).get("summary_stats", {})
    if isinstance(stats, dict):
        buckets = ("passed", "failed", "missing", "skipped", "error")
        if all(isinstance(stats.get(b), int) for b in buckets):
            accounted = sum(stats[b] for b in buckets)
            print(
                f"summary_stats accounts for {accounted} of "
                f"{len(scanner_results)} scanners "
                + ", ".join(f"{b}={stats[b]}" for b in buckets)
            )
            if accounted != len(scanner_results):
                print(
                    f"::warning::summary_stats accounts for {accounted} scanners "
                    f"but scanner_results holds {len(scanner_results)}. A counter "
                    "is missing a status, so any verdict keyed on these totals is "
                    "reading an incomplete tally."
                )

    if incomplete:
        for name, status in incomplete:
            print(f"::error::Scanner {name} did not complete: {status}")
        print(
            f"::error::{len(incomplete)} of {len(scanner_results)} scanners did not "
            "complete. ERROR means the scanner ran and failed; MISSING means its "
            "dependencies were unavailable so it never ran. Either install the "
            "tool on this platform or exclude the scanner explicitly, which "
            "records it as SKIPPED and says so in the report."
        )
        return 1

    print(f"All {len(scanner_results)} scanners accounted for; none incomplete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
