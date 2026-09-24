# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fail a CI job when a scanner it was supposed to run did not complete.

Reads ``scanner_results[*].status`` out of ``ash_aggregated_results.json`` and exits
1 unless every scanner is PASSED, FAILED or SKIPPED. Today that means it fails on
ERROR (ran and failed) and MISSING (its dependencies were unavailable, so it never
ran), and on any status it does not recognise. SKIPPED scanners are ones the run did
not select -- ``--exclude-scanners``, a config that disables them, or one shard of a
sharded run -- and are reported but do not fail the job.

Stated as what is accepted rather than what is rejected, deliberately: a results file
from a different ASH version can carry a status this script has never heard of, and a
rejected-list would let it through a gate whose whole job is to notice that a scanner
did not run.

It also exits 1 when *no* scanner executed, which is a separate assertion and not
implied by the first. Because SKIPPED has to be tolerated one entry at a time, a
file in which every entry is SKIPPED passes the per-scanner check while having
measured nothing at all.

And it exits 1 when a scanner ASH says it expected has no row at all, or when ASH
recorded a plugin module that failed to import. Both are assertions the per-scanner
loop structurally cannot make, because that loop builds its universe from the
``scanner_results`` dict it is handed. A scanner that never registered is absent
from the numerator and the denominator at once: eight rows of ten printed "All 8
scanners accounted for; none incomplete" and returned 0, and no arithmetic over
that dict could have noticed. ``metadata.expected_scanners`` is written by ASH from
the configuration's declared scanner roster rather than from the plugins that
resolved, so comparing against it is a genuinely different question from comparing
the rows to each other. Absent from a results file written by a version that did
not record it, in which case that comparison is skipped rather than failed.

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
ASH's own exit code answer from the same field, so they cannot disagree. Both
assertions above have a counterpart in ``run_ash_scan._compute_exit_code``:
``incomplete_scanners`` for the per-scanner one and ``no_scanner_ran`` for the
set-level one. The set-level pair was added later than this script, and until it
existed the two did disagree -- on a Windows run of this repository's own config,
``ash scan --scanners semgrep`` recorded ten SKIPPED and exited 0 while this script
exited 1 on the same file.

One difference remains, and it is why this script carries the gate rather than sharing
it: ASH puts both checks behind ``fail_on_incomplete_scanners``, while this script has
no equivalent and always fails. Both arms in ``run_ash_scan._compute_exit_code`` sit
inside that flag's ``if``, so anything that turns the flag off -- a
``--no-fail-on-incomplete-scanners`` added to a workflow, a scanned tree's own
``.ash.yaml`` -- takes both of ASH's checks with it and leaves nothing behind. This
script cannot be switched off that way, so it is what makes the assertion
unconditional in CI.

That is worth saying outright, because the paragraph above -- that the guard and the
exit code "answer from the same field, so they cannot disagree" -- is a claim about
the field they read, not about the verdict they return. The flag's default is now
True, so on an unconfigured run the two verdicts do agree; the point of keeping this
script is that they agree by policy rather than by construction.

Their overlap is deliberate and they fail for different reasons: ASH's exit code is
ASH judging its own run, and this is CI judging whether that judgement still happens.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# The statuses whose outcome is known, and the only ones that do not fail the job.
#
# An allowlist, not a denylist of the bad ones. This used to be
# ``INCOMPLETE_STATUSES = ("ERROR", "MISSING")`` tested with ``in``, so every status
# it did not name counted as complete -- including one this script has never heard
# of. A results file written by a different ASH version, or a future rename of
# ERROR, would then pass a gate whose entire purpose is to notice that a scanner did
# not run. The five predecessors this script replaced were each disarmed in some
# equally quiet way, so the default has to be "fail" rather than "pass".
#
# SKIPPED is tolerated because it means the scanner was not selected: one shard of a
# sharded run records the scanners the other shards own that way, and
# --exclude-scanners records an operator's choice that way. Whether the *whole set*
# being SKIPPED is acceptable is a separate question, answered below.
#
# Kept in step with automated_security_helper.interactions.run_ash_scan's
# _COMPLETE_SCANNER_STATUSES. Spelled as literals here rather than imported because
# this script runs before -- and independently of -- an importable ASH: the bash and
# PowerShell scan methods leave no ASH on the runner's PATH at all.
COMPLETE_STATUSES = ("PASSED", "FAILED", "SKIPPED")

# The statuses that mean "this scanner executed". Mirrors ScannerState.ran in
# scripts/verify_external_target_scan.py, which the sibling gate uses for the same
# assertion.
RAN_STATUSES = ("PASSED", "FAILED")

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
    observed: list[tuple[str, str]] = []
    for name in sorted(scanner_results):
        entry = scanner_results[name] or {}
        status = entry.get("status") if isinstance(entry, dict) else None
        status = str(status) if status is not None else "UNKNOWN"
        print(f"  {name:<24} {status}")
        observed.append((name, status))
        # Anything not on the allowlist counts as incomplete, which covers the
        # "UNKNOWN" this loop substitutes for an entry whose status could not be read
        # at all. An unreadable status is not evidence that the scanner ran.
        if status not in COMPLETE_STATUSES:
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

    failed = False

    if incomplete:
        for name, status in incomplete:
            print(f"::error::Scanner {name} did not complete: {status}")
        print(
            f"::error::{len(incomplete)} of {len(scanner_results)} scanners did not "
            "complete. ERROR means the scanner ran and failed; MISSING means its "
            "dependencies were unavailable so it never ran. Either install the "
            "tool on this platform or exclude the scanner explicitly, which "
            "records it as SKIPPED and says so in the report. Any other status is "
            "one this gate does not recognise -- most likely a results file from a "
            f"different ASH version; the ones it accepts are {', '.join(COMPLETE_STATUSES)}."
        )
        failed = True

    # Every scanner ASH expected has to be present, and the roster it is compared
    # against does not come from these rows.
    #
    # This is the assertion the loop above cannot make. It builds its universe from
    # the scanner_results dict, so a scanner that never registered is missing from
    # what is checked and from what it is checked against simultaneously -- and every
    # per-row verdict, every counter and the final summary line all read clean.
    #
    # Compared on a normalized key rather than literally. The roster is taken from
    # config field aliases and the rows from config.name on the instantiated plugin;
    # those agree today, and a literal comparison would turn any future divergence in
    # separator or case into ten false failures instead of the one real finding this
    # exists to report.
    #
    # Only the roster-minus-rows direction is a finding. A row not on the roster is a
    # plugin module an operator loaded without a matching config entry, which is a
    # supported arrangement.
    metadata = results.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}

    expected = metadata.get("expected_scanners")
    if isinstance(expected, list) and expected:
        present = {str(name).replace("-", "_").lower() for name in scanner_results}
        unaccounted = sorted(
            str(name)
            for name in expected
            if str(name).replace("-", "_").lower() not in present
        )
        if unaccounted:
            for name in unaccounted:
                print(f"::error::Scanner {name} was expected but has no result at all")
            print(
                f"::error::{len(unaccounted)} of {len(expected)} expected scanners "
                f"produced no result: {', '.join(unaccounted)}. A scanner with no row "
                "did not register, so it is absent from every status counter and from "
                "this gate's per-scanner check -- the run reported itself complete "
                "over the scanners that remained. Most likely a plugin module that "
                "failed to import, or a scanner whose constructor raised; check the "
                "run log for 'failed to import' and 'could not be constructed'."
            )
            failed = True

    load_errors = metadata.get("plugin_load_errors")
    if isinstance(load_errors, dict) and load_errors:
        for module_path, error in sorted(load_errors.items()):
            print(f"::error::Plugin module {module_path} failed to import: {error}")
        print(
            f"::error::{len(load_errors)} plugin module(s) failed to import, so this "
            "run is missing plugins ASH ships with. Each group is imported in "
            "isolation so one missing optional dependency costs one group rather than "
            "the rest of the set -- which makes the run degrade instead of crash, and "
            "is why it has to fail here instead."
        )
        failed = True

    # At least one scanner has to have executed.
    #
    # Every status above is judged on its own, and SKIPPED has to stay tolerated
    # there: it is how one shard of a sharded run records the scanners the other
    # shards own, and how --exclude-scanners records an operator's choice. So a
    # results file in which *every* scanner is SKIPPED passes the per-scanner loop
    # while having measured nothing, and that is reachable from a typo -- measured
    # on this tree, `ash scan --scanners detect_secrets` (the name is
    # detect-secrets) matched no scanner, recorded ten SKIPPED, and this script
    # returned 0.
    #
    # The assertion is therefore about the set rather than about any one entry,
    # which is the shape scripts/verify_external_target_scan.py's
    # check_some_scanner_ran already uses.
    if not any(status in RAN_STATUSES for _, status in observed):
        print(
            f"::error::None of the {len(scanner_results)} scanners in "
            f"{args.results} executed. Statuses: "
            + ", ".join(f"{name}={status}" for name, status in observed)
            + ". Every scanner being SKIPPED means the run selected nothing, so it "
            "has shown the target to be neither clean nor dirty -- most often a "
            "--scanners name that matches no scanner, or an allowlist wholly "
            "cancelled by --exclude-scanners."
        )
        failed = True

    if failed:
        return 1

    print(f"All {len(scanner_results)} scanners accounted for; none incomplete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
