# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Prove every builtin scanner gives the same answer inside the sandbox as outside it.

Run with: python scripts/verify_sandbox_scanner_parity.py --sandbox bwrap

Why this exists
---------------
A sandbox that breaks a scanner fails in the quiet direction. A scanner that cannot
read its rule pack, its vulnerability database or its runtime usually does not crash;
it reports zero findings, which looks like a clean scan. So "every scanner PASSED
under --sandbox" proves nothing. What this script asserts is parity: the scan is run
twice over the same fixture, once with ``--sandbox off`` and once with the backend
under test, and for every scanner the status and the exact set of findings (rule,
file, line, message) must match. It also requires a minimum number of findings from
the unsandboxed run, so a fixture that stopped producing findings cannot make parity
pass trivially.

The fixture is the snapshot fixture (tests/test_data/snapshot_fixture/repo), plus a
CloudFormation template for cfn-nag and cdk-nag, a pinned old Python dependency for
grype, and an npm lockfile for npm-audit, so each builtin scanner has something to
find. Both runs use --offline as well, unless --online is passed, in which case the
pair is run online too, so the network-allowed scanners are exercised with and
without their network.

Exit status is 0 on parity and 1 otherwise. A JSON report goes to --report.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # nosec B404 - this script drives `ashx scan`
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Set, Tuple

from automated_security_helper.cli.deprecations import CANONICAL_CLI_NAME as CLI_NAME

REPO = Path(__file__).resolve().parents[1]
SNAPSHOT_REPO = REPO / "tests" / "test_data" / "snapshot_fixture" / "repo"
CFN_TEMPLATE = (
    REPO / "tests" / "test_data" / "scanners" / "cdk" / "insecure-s3-template.yaml"
)

PACKAGE_JSON = {
    "name": "parity-fixture",
    "version": "1.0.0",
    "dependencies": {"lodash": "4.17.15"},
}
PACKAGE_LOCK = {
    "name": "parity-fixture",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "requires": True,
    "packages": {
        "": {
            "name": "parity-fixture",
            "version": "1.0.0",
            "dependencies": {"lodash": "4.17.15"},
        },
        "node_modules/lodash": {
            "version": "4.17.15",
            "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
        },
    },
}

Finding = Tuple[str, str, str, int, str]


def build_fixture(root: Path) -> Path:
    source = root / "repo"
    shutil.copytree(SNAPSHOT_REPO, source)
    (source / "cfn").mkdir()
    shutil.copy(CFN_TEMPLATE, source / "cfn" / "template.yaml")
    (source / "requirements.txt").write_text("requests==2.19.0\nurllib3==1.24.1\n")
    (source / "web").mkdir()
    (source / "web" / "package.json").write_text(json.dumps(PACKAGE_JSON, indent=2))
    (source / "web" / "package-lock.json").write_text(
        json.dumps(PACKAGE_LOCK, indent=2)
    )
    return source


def run_scan(
    ash: List[str], source: Path, output: Path, mode: str, offline: bool
) -> int:
    command = [
        *ash,
        "scan",
        "--source-dir",
        str(source),
        "--output-dir",
        str(output),
        "--sandbox",
        mode,
        "--no-progress",
        "--no-fail-on-findings",
        "--no-fail-on-incomplete-scanners",
    ]
    if offline:
        command.append("--offline")
    print(f"$ {' '.join(command)}", flush=True)
    log = output.with_suffix(".log")
    with open(log, "w", encoding="utf-8") as handle:
        result = subprocess.run(  # nosec B603 - fixed argv
            command, stdout=handle, stderr=subprocess.STDOUT, check=False, timeout=3000
        )
    print(f"  exit {result.returncode}; log at {log}", flush=True)
    return result.returncode


def read_results(
    output: Path,
) -> Tuple[Dict[str, str], Dict[str, Set[Finding]], Dict[str, str]]:
    document = json.loads((output / "ash_aggregated_results.json").read_text())
    statuses = {
        name: str(info.get("status"))
        for name, info in document["scanner_results"].items()
    }
    findings: Dict[str, Set[Finding]] = {name: set() for name in statuses}
    for run in document["sarif"]["runs"]:
        for result in run.get("results") or []:
            props = result.get("properties") or {}
            scanner = props.get("scanner_name") or "?"
            location = ((result.get("locations") or [{}])[0] or {}).get(
                "physicalLocation"
            ) or {}
            uri = (location.get("artifactLocation") or {}).get("uri") or ""
            line = (location.get("region") or {}).get("startLine") or 0
            message = ((result.get("message") or {}).get("text") or "").strip()
            findings.setdefault(scanner, set()).add(
                (scanner, str(result.get("ruleId")), uri, int(line), message)
            )
    # The shape of what each scanner reports about its run, apart from values that
    # differ between any two runs. A sandbox must not change it: an earlier version
    # recorded the backend as container metadata, which made every sandboxed
    # scanner's tool_invocation gain exit_code and duration.
    shapes: Dict[str, str] = {}
    for run in document["sarif"]["runs"]:
        for result in run.get("results") or []:
            props = result.get("properties") or {}
            scanner = props.get("scanner_name") or "?"
            details = props.get("scanner_details") or {}
            invocation = details.get("tool_invocation") or {}
            shape = json.dumps(
                {"properties": sorted(props), "tool_invocation": sorted(invocation)}
            )
            shapes.setdefault(scanner, shape)
    return statuses, findings, shapes


def read_durations(output: Path) -> Dict[str, float]:
    """Seconds each scanner took, as ASH recorded it. Reported, not compared: a
    sandbox costs time, and how much is worth seeing per scanner."""
    document = json.loads((output / "ash_aggregated_results.json").read_text())
    return {
        name: float(info.get("duration") or 0.0)
        for name, info in document["scanner_results"].items()
    }


def compare(label: str, off: Path, boxed: Path) -> Tuple[List[dict], List[str]]:
    off_status, off_findings, off_shapes = read_results(off)
    box_status, box_findings, box_shapes = read_results(boxed)
    off_seconds, box_seconds = read_durations(off), read_durations(boxed)
    rows, problems = [], []
    for name in sorted(set(off_status) | set(box_status)):
        a, b = off_status.get(name), box_status.get(name)
        fa, fb = off_findings.get(name, set()), box_findings.get(name, set())
        row = {
            "run": label,
            "scanner": name,
            "status_off": a,
            "status_sandboxed": b,
            "findings_off": len(fa),
            "findings_sandboxed": len(fb),
            "identical": a == b and fa == fb,
            "seconds_off": round(off_seconds.get(name, 0.0), 2),
            "seconds_sandboxed": round(box_seconds.get(name, 0.0), 2),
        }
        rows.append(row)
        if a != b:
            problems.append(
                f"[{label}] {name}: status {a} unsandboxed but {b} sandboxed"
            )
        if fa != fb:
            only_off = sorted(fa - fb)[:5]
            only_box = sorted(fb - fa)[:5]
            problems.append(
                f"[{label}] {name}: findings differ; only unsandboxed {only_off}; "
                f"only sandboxed {only_box}"
            )
        if off_shapes.get(name) != box_shapes.get(name) and fa == fb and fa:
            problems.append(
                f"[{label}] {name}: result shape differs; unsandboxed "
                f"{off_shapes.get(name)} sandboxed {box_shapes.get(name)}"
            )
        if b in ("MISSING", "ERROR") and a not in ("MISSING", "ERROR"):
            problems.append(f"[{label}] {name}: ran unsandboxed but {b} sandboxed")
    return rows, problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--sandbox", default="bwrap")
    parser.add_argument(
        "--online", action="store_true", help="also compare an online pair"
    )
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument(
        "--require",
        default=os.environ.get("ASH_SANDBOX_PARITY_REQUIRE", ""),
        help="comma-separated scanners that must have run (not MISSING) unsandboxed",
    )
    parser.add_argument("--min-findings", type=int, default=10)
    parser.add_argument(
        "--ash",
        default=None,
        help=f"the ASH command, default: this interpreter's {CLI_NAME}",
    )
    args = parser.parse_args()

    ash = [args.ash] if args.ash else [str(Path(sys.executable).with_name(CLI_NAME))]
    work = Path(tempfile.mkdtemp(prefix="ash-sandbox-parity-"))
    source = build_fixture(work)
    rows: List[dict] = []
    problems: List[str] = []
    pairs = [("offline", True)] + ([("online", False)] if args.online else [])
    for label, offline in pairs:
        off = work / f"out-{label}-off"
        boxed = work / f"out-{label}-{args.sandbox}"
        run_scan(ash, source, off, "off", offline)
        run_scan(ash, source, boxed, args.sandbox, offline)
        pair_rows, pair_problems = compare(label, off, boxed)
        rows += pair_rows
        problems += pair_problems
        # Identical results prove nothing if the sandbox was never applied, and
        # since the backend no longer shows in the results, only the log can say.
        log_text = (boxed / "ash.log").read_text(encoding="utf-8", errors="replace")
        box_statuses, _, _ = read_results(boxed)
        if f"Scanner sandbox: using {args.sandbox}" not in log_text:
            problems.append(
                f"[{label}] the sandboxed run never selected {args.sandbox}"
            )
        for name, status in box_statuses.items():
            if status in ("SKIPPED", "MISSING"):
                continue
            if (
                f"Scanner sandbox: {name} on source runs under {args.sandbox}"
                not in log_text
            ):
                problems.append(f"[{label}] {name} ran but not under {args.sandbox}")
        statuses, findings, _ = read_results(off)
        total = sum(len(f) for f in findings.values())
        if total < args.min_findings:
            problems.append(
                f"[{label}] only {total} findings unsandboxed (need {args.min_findings}): "
                "the fixture is not exercising the scanners"
            )
        # Checked on the online pair when there is one: offline, semgrep and opengrep
        # need a seeded rule cache and npm-audit is skipped by design, so a scanner
        # can legitimately be MISSING in both offline runs. Parity still holds there.
        if args.online and label == "offline":
            continue
        for required in filter(None, (s.strip() for s in args.require.split(","))):
            if statuses.get(required) in (None, "MISSING", "ERROR", "SKIPPED"):
                problems.append(
                    f"[{label}] required scanner {required} did not run unsandboxed "
                    f"({statuses.get(required)})"
                )

    width = max(len(r["scanner"]) for r in rows)
    print(
        f"\n{'run':8} {'scanner':{width}}  off            {args.sandbox:14} identical"
        f"  seconds off/{args.sandbox}"
    )
    for r in rows:
        print(
            f"{r['run']:8} {r['scanner']:{width}}  "
            f"{str(r['status_off']):8}{r['findings_off']:>4}   "
            f"{str(r['status_sandboxed']):8}{r['findings_sandboxed']:>4}     "
            f"{'yes' if r['identical'] else 'NO ':9}"
            f"{r['seconds_off']:>7.2f} {r['seconds_sandboxed']:>7.2f}"
        )
    if args.report:
        args.report.write_text(
            json.dumps({"rows": rows, "problems": problems}, indent=2)
        )
    if problems:
        print("\nParity failures:")
        for p in problems:
            print(f"  - {p}")
        print(f"\nScan outputs kept under {work}")
        return 1
    print(f"\nParity holds for every scanner under --sandbox {args.sandbox}.")
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
