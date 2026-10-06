#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Asserts that a scan actually found something, and that the right tool found it.

WHY THIS IS NOT `ashx scan && echo ok`
-------------------------------------
`ashx scan` exits 0 when it finds nothing and 2 when it finds something -- the
default `fail_on_findings` is true. So on a fixture that is supposed to carry a
finding, exit 0 is the FAILING outcome and exit 2 is the passing one. A check
written as "install the package, run a scan, require exit 0" would therefore be
satisfied by a scan that ran and found nothing, by a scan that selected no
scanners, and by a scan over an empty directory. That check passes forever and
measures the exit code of a program rather than whether the program worked.

This reads the SARIF report the scan wrote and requires a finding count above
zero.

WHY IT ALSO CHECKS WHICH SCANNER PRODUCED THE FINDING
-----------------------------------------------------
A bare count greater than zero is still weak. ASH aggregates every selected
scanner into one SARIF file, so a count can be satisfied by a finding from
something other than the scanner under test -- and what is being verified is that
the packaged install can drive a scanner end to end, not that the SARIF file is
non-empty. If the count came from, say, a configuration warning surfaced as a
result, the package could be broken and this would still be green.

WHERE THE ATTRIBUTION ACTUALLY LIVES, WHICH IS NOT WHERE IT LOOKS LIKE IT LIVES
-------------------------------------------------------------------------------
The two obvious places are both wrong, and this was measured on a real report
rather than reasoned about. In ASH's SARIF:

    runs[].tool.driver.name  == "AWS Labs - Automated Security Helper"
    runs[].results[].ruleId  == "SECRET-AWS-ACCESS-KEY"

The driver is ASH, because ASH is what wrote the file -- every run says that,
whichever scanner produced the finding. And the ruleId is ASH's own normalized
identifier, not the scanner's: detect-secrets calls that detector
`AWSKeyDetector`, and the string `detect-secrets` appears nowhere in either field.
A first attempt at this check required the substring "detect-secrets" in one of
those two, and it failed against a scan that had genuinely worked -- correctly, in
the sense that the check was measuring the wrong thing and said so.

The real field is per-result:

    runs[].results[].properties.scanner_name == "detect-secrets"

which is what ASH populates to record which scanner a finding came from. It is
matched EXACTLY rather than as a substring, because an exact match on the field
built for this purpose is the strongest available form.

There is deliberately NO FALLBACK to the looser predicates. If no result in the
document carries `properties.scanner_name`, that is reported as its own failure
rather than quietly answered by matching a rule id -- a check that silently
degrades to a weaker test when its evidence disappears is how a strong check
becomes a vacuous one without anybody editing it.

USAGE
-----
    packaging/assert-scan-findings.py /out/reports/ash.sarif \\
        --minimum 1 --require-scanner detect-secrets

    packaging/assert-scan-findings.py --self-test
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from typing import Any, TextIO


def collect_results(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Flattens every result across every run in a SARIF document."""
    results: list[dict[str, Any]] = []
    for run in document.get("runs") or []:
        for result in run.get("results") or []:
            # The tool that produced the run is not on the result, so it is copied
            # down here. Attribution is half of what this script checks, and
            # looking it up later would mean re-walking the runs.
            tool_name = ((run.get("tool") or {}).get("driver") or {}).get("name") or ""
            enriched = dict(result)
            enriched["_toolName"] = tool_name
            results.append(enriched)
    return results


def scanner_of(result: dict[str, Any]) -> str | None:
    """The scanner ASH recorded as the source of this result, if it recorded one."""
    properties = result.get("properties")
    if not isinstance(properties, dict):
        return None
    name = properties.get("scanner_name")
    return name if isinstance(name, str) and name else None


def describe(result: dict[str, Any]) -> str:
    """A short attribution string for one result, for use in failure messages."""
    return (
        f"{scanner_of(result) or '<no scanner_name>'}"
        f" via {result.get('_toolName') or '<no tool>'}"
        f" as {result.get('ruleId') or '<no ruleId>'}"
    )


def check_sarif(path: str, minimum: int, require_scanner: str | None) -> list[str]:
    """Returns a list of problems; empty means the scan is proven to have worked."""
    problems: list[str] = []

    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)

    # A SARIF file with no runs is not the same as a scan with no findings, and
    # conflating them is how "the scanner never ran" reads as "the code is clean".
    runs = document.get("runs")
    if not runs:
        problems.append(
            f"{path} contains no SARIF runs at all. That is not 'no findings' -- it "
            "means no scanner produced a run, so nothing was measured."
        )
        return problems

    results = collect_results(document)

    if len(results) < minimum:
        problems.append(
            f"{path} contains {len(results)} result(s), fewer than the required "
            f"minimum of {minimum}. The caller asked for at least {minimum} "
            "because the tree that was scanned is known to contain something to "
            "find, so a shortfall means the scan did not do what it was asked -- "
            "not that the tree is clean. Note that `ashx scan` exits 0 when it "
            "finds nothing, which is why the exit code is not what is checked."
        )

    # Attribution is only a question if there is anything to attribute. Asked
    # unconditionally, the `all(...)` below is vacuously true over an empty list, so
    # a scan that found nothing was reported BOTH as short of the minimum and as
    # having a changed report shape -- two complaints for one cause, the second of
    # them wrong. The count check above already owns the empty case.
    if require_scanner is not None and results:
        # The evidence has to be present before its absence can be distinguished
        # from a mismatch. If NO result carries properties.scanner_name, the report
        # shape has changed and this check no longer knows what it is reading --
        # which is a different failure from "the wrong scanner produced the
        # findings", and answering it by falling back to a rule-id substring is how
        # a check quietly stops testing what it claims to.
        if all(scanner_of(r) is None for r in results):
            problems.append(
                f"{path} has {len(results)} result(s), none of which carries "
                "properties.scanner_name. That field is where ASH records which "
                "scanner produced a finding, and it is the only place the scanner "
                "appears -- tool.driver.name is always ASH itself and ruleId is "
                "ASH's own normalized identifier. Its absence means the report "
                "shape changed; refusing to fall back to a looser match, because "
                "that would silently turn this into a weaker check."
            )
            return problems

        wanted = require_scanner.lower()
        attributed = [r for r in results if (scanner_of(r) or "").lower() == wanted]
        if not attributed:
            problems.append(
                f"{path} has {len(results)} result(s) but none has "
                f"properties.scanner_name == '{require_scanner}'. Attribution "
                f"seen: {sorted({describe(r) for r in results})}. A count "
                "satisfied by some other producer does not show that the scanner "
                "this package installed can run."
            )
        else:
            problems_note = (
                f"  {len(attributed)} of {len(results)} finding(s) attributed to "
                f"'{require_scanner}'\n"
            )
            sys.stdout.write(problems_note)

    return problems


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
# The real driver name ASH writes. Used in the fixtures rather than a placeholder
# so that a check accidentally rewritten to read tool.driver.name cannot pass the
# self-test: every fixture, good and bad, says ASH here, exactly as a real report
# does.
ASH_DRIVER = "AWS Labs - Automated Security Helper"


def sarif(results: list[dict[str, Any]], tool: str = ASH_DRIVER) -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool}}, "results": results}],
    }


def finding(rule: str, scanner: str | None) -> dict[str, Any]:
    result: dict[str, Any] = {"ruleId": rule}
    if scanner is not None:
        result["properties"] = {"scanner_name": scanner}
    return result


SELF_TEST_CASES = [
    # (label, document, minimum, require_scanner, must_fail)
    (
        (
            "the real report shape: ASH is the driver, the rule is ASH's own "
            "SECRET-* id, and the scanner is named only in properties"
        ),
        sarif([finding("SECRET-AWS-ACCESS-KEY", "detect-secrets")]),
        1,
        "detect-secrets",
        False,
    ),
    (
        "a scan that found nothing -- the case `ashx scan` exits 0 for",
        sarif([]),
        1,
        "detect-secrets",
        True,
    ),
    (
        "a SARIF file with no runs at all",
        {"version": "2.1.0", "runs": []},
        1,
        "detect-secrets",
        True,
    ),
    (
        "findings present but produced by a different scanner",
        sarif([finding("CKV_AWS_1", "checkov")]),
        1,
        "detect-secrets",
        True,
    ),
    (
        (
            "findings whose rule id merely MENTIONS the scanner, with no "
            "scanner_name -- the looser predicate this check refuses to fall back to"
        ),
        sarif([finding("detect-secrets.AWSKeyDetector", None)]),
        1,
        "detect-secrets",
        True,
    ),
    (
        "the count alone, with attribution not required",
        sarif([finding("SECRET-AWS-ACCESS-KEY", "detect-secrets")]),
        1,
        None,
        False,
    ),
    (
        "more findings required than are present",
        sarif([finding("SECRET-AWS-ACCESS-KEY", "detect-secrets")]),
        2,
        "detect-secrets",
        True,
    ),
]


def run_self_test(stream: TextIO) -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as workdir:
        for index, (label, document, minimum, rule, must_fail) in enumerate(
            SELF_TEST_CASES
        ):
            path = os.path.join(workdir, f"case-{index}.sarif")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(document, handle)
            problems = check_sarif(path, minimum, rule)
            if must_fail and not problems:
                failures.append(f"{label}: was ACCEPTED, but must be rejected")
            elif not must_fail and problems:
                failures.append(f"{label}: was REJECTED -- {problems}")
            else:
                verdict = "rejected" if must_fail else "accepted"
                stream.write(f"  {verdict} {label}\n")

    if failures:
        stream.write("\nself-test FAILED:\n")
        stream.writelines(f"  - {failure}\n" for failure in failures)
        return 1
    rejected = sum(1 for case in SELF_TEST_CASES if case[4])
    stream.write(
        f"self-test OK: all {len(SELF_TEST_CASES)} cases behave as required, "
        f"{rejected} of them by being rejected.\n"
        "Every case here is decided on the CONTENT of the report. Two of them -- "
        "the empty result set and the empty run list -- are the ones a scan that "
        "found nothing produces, and `ashx scan` exits 0 for both, so no check on "
        "the exit code can tell them from a scan that worked.\n"
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Assert a scan produced findings, and that a named scanner "
        "produced at least one of them.",
    )
    parser.add_argument("sarif", nargs="?", help="path to ash.sarif")
    parser.add_argument(
        "--minimum",
        type=int,
        default=1,
        help="minimum number of SARIF results required (default 1)",
    )
    parser.add_argument(
        "--require-scanner",
        default=None,
        help="the exact properties.scanner_name that at least one result must "
        "carry. Neither tool.driver.name nor ruleId identifies the scanner in "
        "ASH's SARIF; see the module docstring.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove the assertions can fail, using fixture SARIF documents",
    )
    args = parser.parse_args(argv[1:])

    if args.self_test:
        if args.sarif:
            parser.error("--self-test takes no SARIF path")
        return run_self_test(sys.stdout)

    if not args.sarif:
        sys.stderr.write(
            "scan-findings: no SARIF path given. Refusing to exit 0 having checked "
            "nothing.\n"
        )
        return 2

    if not os.path.isfile(args.sarif):
        sys.stderr.write(
            f"scan-findings: {args.sarif} is not a file. The scan was supposed to "
            "write it, so its absence is a failed scan rather than a clean one.\n"
        )
        return 2

    if args.minimum < 1:
        # A minimum of 0 is satisfied by an empty report, which is the whole
        # failure mode this script exists to prevent. Refused rather than honoured.
        sys.stderr.write(
            f"scan-findings: --minimum {args.minimum} would be satisfied by a scan "
            "that found nothing, which is what this script exists to catch.\n"
        )
        return 2

    try:
        problems = check_sarif(args.sarif, args.minimum, args.require_scanner)
    except (OSError, ValueError) as err:
        sys.stderr.write(f"scan-findings: could not read {args.sarif}: {err}\n")
        return 2

    if problems:
        sys.stderr.write("\nScan findings check FAILED:\n")
        for problem in problems:
            sys.stderr.write(f"  - {problem}\n")
        return 1

    with open(args.sarif, "r", encoding="utf-8") as handle:
        results = collect_results(json.load(handle))
    attribution = sorted({describe(r) for r in results})
    sys.stdout.write(
        f"scan findings OK: {len(results)} finding(s) in "
        f"{os.path.basename(args.sarif)}, at or above the required minimum of "
        f"{args.minimum}"
    )
    if args.require_scanner:
        sys.stdout.write(
            f", with at least one carrying scanner_name == '{args.require_scanner}'"
        )
    sys.stdout.write(".\n")
    for line in attribution:
        sys.stdout.write(f"  attribution: {line}\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - entry point
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:  # pragma: no cover
        sys.exit(130)
