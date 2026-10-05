#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Runs one e2e case from tests/e2e/fixtures/cases.json with a local ASH executable.

For every channel that ends in an executable on the host (the wheel's venv, a
Homebrew keg, an MSIX or Chocolatey install, a Flatpak launcher), this does the part
that has to be identical across them:

1. copies the case's fixture into <work>/<case>/src, so the scan never writes into the
   checkout and never sees the repository's own .ash configuration;
2. runs `<cli> scan --source-dir <src> --output-dir <work>/<case>/out --no-progress
   --scanners <the case's scanners> <the case's args> [extra args]` with the case's
   environment applied on top of this process's environment. The case's args are part
   of the case: the incomplete case needs `--config-overrides
   scanners.opengrep.enabled=true` because opengrep is disabled by default on Windows,
   and a disabled scanner is SKIPPED instead of MISSING;
3. hands the exit code and output directory to assert_outcome.check_outcome.

It exits 0 when the outcome matches, 1 when it does not, and 3 on a usage error.

There is deliberately no way to override the case's expectations here. A negative
control either changes the scan (for example `-- --no-fail-on-findings` on the findings
case, which must then fail the exit-code check) or runs assert_outcome.py directly on a
real output with a wrong expectation.

Standard library only, like assert_outcome.py.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

import assert_outcome  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "e2e" / "fixtures"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--cli",
        required=True,
        help="the ASH executable to run (a path, or a name on PATH)",
    )
    parser.add_argument("--case", required=True, help="findings, clean or incomplete")
    parser.add_argument(
        "--work",
        required=True,
        type=Path,
        help="a scratch directory; <work>/<case> is replaced",
    )
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=FIXTURES,
        help=f"fixtures root (default: {FIXTURES})",
    )
    parser.add_argument(
        "--label", help="a name for this run in the output (default: the case name)"
    )
    parser.add_argument(
        "extra", nargs="*", help="extra arguments for `scan`, after a --"
    )
    args = parser.parse_args(argv)

    cases_path = args.fixtures / "cases.json"
    case = assert_outcome.load_case(cases_path, args.case)
    label = args.label or args.case

    cli = shutil.which(args.cli) or args.cli
    if not Path(cli).is_file():
        print(f"error: [{label}] no executable at {args.cli}", file=sys.stderr)
        return 3

    root = args.work / label
    if root.exists():
        shutil.rmtree(root)
    src = root / "src"
    out = root / "out"
    shutil.copytree(args.fixtures / case["source"], src)

    case_args = case.get("args") or []
    if not isinstance(case_args, list) or not all(
        isinstance(a, str) for a in case_args
    ):
        print(
            f"error: [{label}] the case's args must be a list of strings, not {case_args!r}",
            file=sys.stderr,
        )
        return 3

    env = dict(os.environ)
    env.update({str(k): str(v) for k, v in (case.get("env") or {}).items()})
    command = [
        cli,
        "scan",
        "--source-dir",
        str(src),
        "--output-dir",
        str(out),
        "--no-progress",
        "--scanners",
        ",".join(case["scanners"]),
        *case_args,
        *args.extra,
    ]
    log = root / "scan.log"
    print(f"[{label}] {' '.join(command)}")
    with open(log, "w", encoding="utf-8", errors="replace") as handle:
        rc = subprocess.run(
            command, env=env, stdout=handle, stderr=subprocess.STDOUT, check=False
        ).returncode  # noqa: S603
    print(f"[{label}] scan exit code {rc}; log at {log}")

    expected = assert_outcome.Expectation(
        expect_rc=int(case["expect_rc"]),
        findings=case.get("findings"),
        min_findings=case.get("min_findings"),
        require_scanner=case.get("require_scanner"),
        selected=list(case["scanners"]),
        incomplete_scanner=case.get("incomplete_scanner"),
    )
    usage = expected.usage_problems()
    if usage:
        for problem in usage:
            print(f"error: [{label}] {problem}", file=sys.stderr)
        return 3

    problems = assert_outcome.check_outcome(out, rc, expected)
    if problems:
        for problem in problems:
            print(f"::error::[{label}] {problem}")
        tail = log.read_text(encoding="utf-8", errors="replace").splitlines()[-25:]
        print(f"--- last {len(tail)} lines of {log}")
        print("\n".join(tail))
        print(f"FAIL: [{label}] {len(problems)} problem(s)")
        return 1
    summary = json.dumps({"case": args.case, "rc": rc, "findings": expected.findings})
    print(f"OK: [{label}] {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
