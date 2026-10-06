#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Assert that one opt-in scanner ran in a scan that selected it.

Opt-in scanners are left out of default scans entirely, so the default-scan
checks in this action say nothing about them. The step that calls this scans a
fixture with known findings and only the opt-in scanner selected; this reads the
aggregated results and fails unless the scanner is present, did not go MISSING
or ERROR, and reported at least the expected number of findings. The scan's own
exit status is checked too, so a click usage error (also exit 2) cannot pass
for a findings exit without the report agreeing.
"""

import argparse
import json
import sys
from pathlib import Path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    parser.add_argument("scanner")
    parser.add_argument("--exit-code", type=int, required=True)
    parser.add_argument("--expect-exit", type=int, required=True)
    parser.add_argument("--min-findings", type=int, default=1)
    args = parser.parse_args(argv)

    if args.exit_code != args.expect_exit:
        print(
            f"FAIL: the scan exited {args.exit_code}, expected {args.expect_exit}",
            file=sys.stderr,
        )
        return 1
    if not args.results.is_file():
        print(f"FAIL: no results at {args.results}", file=sys.stderr)
        return 1
    data = json.loads(args.results.read_text(encoding="utf-8"))
    row = (data.get("scanner_results") or {}).get(args.scanner)
    if not isinstance(row, dict):
        print(f"FAIL: {args.scanner} is absent from the report", file=sys.stderr)
        return 1
    status = str(row.get("status", "?")).upper()
    findings = row.get("finding_count") or 0
    print(f"{args.scanner}: {status} with {findings} finding(s)")
    if status in ("MISSING", "ERROR"):
        print(f"FAIL: {args.scanner} did not run ({status})", file=sys.stderr)
        return 1
    if findings < args.min_findings:
        print(
            f"FAIL: {args.scanner} reported {findings} finding(s) on a fixture with "
            f"at least {args.min_findings}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
