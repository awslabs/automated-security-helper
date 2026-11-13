#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Check the scanner statuses a scan recorded against what the install provides.

    check-scanner-statuses.py <ash_aggregated_results.json> --may-be-missing a,b,c

Every scanner must have run: PASSED, FAILED or SKIPPED. A scanner named in
--may-be-missing may also be MISSING, because the install does not provide its
tool. Anything else fails the check, ERROR included: a scanner that crashed is not
a scanner that ran. Prints the MISSING scanners, space-separated, so the caller can
tell which exit status the scan's completeness gate should have given; exits 1 with
the offending scanners on stderr otherwise.

Used by homebrew.sh for its default-selection scan. Standard library only, so it
runs on whichever Python the runner has.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Dict, List, Set, Tuple

RAN = frozenset({"PASSED", "FAILED", "SKIPPED"})


def classify(
    statuses: Dict[str, str], may_be_missing: Set[str]
) -> Tuple[List[str], List[str]]:
    """(the MISSING scanners allowed to be, every scanner that broke the rule)."""
    missing = sorted(
        name
        for name, status in statuses.items()
        if status == "MISSING" and name in may_be_missing
    )
    wrong = sorted(
        f"{name}={status}"
        for name, status in statuses.items()
        if status not in RAN and not (status == "MISSING" and name in may_be_missing)
    )
    return missing, wrong


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("results")
    parser.add_argument("--may-be-missing", default="")
    args = parser.parse_args(argv)
    with open(args.results, encoding="utf-8") as handle:
        results = json.load(handle).get("scanner_results", {})
    statuses = {
        name: str(entry.get("status")) if isinstance(entry, dict) else "?"
        for name, entry in results.items()
    }
    if not statuses:
        print("no scanner results recorded", file=sys.stderr)
        return 1
    may_be_missing = {name for name in args.may_be_missing.split(",") if name}
    missing, wrong = classify(statuses, may_be_missing)
    if wrong:
        print(" ".join(wrong), file=sys.stderr)
        return 1
    print(" ".join(missing))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
