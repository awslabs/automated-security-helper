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
grype, an npm lockfile for npm-audit, the actionlint and zizmor fixture workflows,
the cfn-lint/cfn-guard insecure template, and the gitleaks fixture's fabricated
tokens (materialized under ``secrets/``, where its ``.gitleaks.toml`` is not the
root config), so each builtin scanner has something to find.
``--ash-plugin-modules`` loads community modules in both runs, and
``--config-override`` passes ``--config-overrides`` to both, for a scanner that is
off by default. Both runs use --offline as well, unless --online is passed, in which
case the pair is run online too, so the network-allowed scanners are exercised with
and without their network.

Exit status is 0 on parity and 1 otherwise. A JSON report goes to --report.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess  # nosec B404 - this script drives `ash scan`
import sys
import tempfile
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Dict, List, Optional, Set, Tuple

REPO = Path(__file__).resolve().parents[1]
SNAPSHOT_REPO = REPO / "tests" / "test_data" / "snapshot_fixture" / "repo"
SCANNER_DATA = REPO / "tests" / "test_data" / "scanners"
CFN_TEMPLATE = SCANNER_DATA / "cdk" / "insecure-s3-template.yaml"
WORKFLOWS = {
    "actionlint-vulnerable.yml": SCANNER_DATA
    / "actionlint"
    / "repo"
    / ".github"
    / "workflows"
    / "vulnerable.yml",
    "zizmor-vulnerable.yml": SCANNER_DATA
    / "zizmor"
    / "repo"
    / ".github"
    / "workflows"
    / "vulnerable.yml",
}
CFN_LINT_GUARD_TEMPLATE = (
    SCANNER_DATA / "cfn_lint_guard" / "repo" / "templates" / "insecure.yaml"
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

#: Wall-clock bound on one `ash scan`, in seconds.
SCAN_TIMEOUT_SECONDS = 3000


class ScanFailure(Exception):
    """A scan of one pair could not be judged: it timed out, or wrote no results.

    Raised instead of letting the underlying exception escape main, so the pair
    is recorded as a problem, the other pairs still run, and the report is
    written.
    """


def load_gitleaks_fixture() -> ModuleType:
    """``tests/utils/gitleaks_fixture.py`` of this repository, loaded by path.

    The module used to be imported as ``tests.utils.gitleaks_fixture`` after
    inserting the repository root on ``sys.path``; a regular ``tests`` package
    installed in the environment shadows that namespace package and the import
    then reads another project's file, or fails. The file is loaded from its
    known path instead.
    """
    path = REPO / "tests" / "utils" / "gitleaks_fixture.py"
    spec = importlib.util.spec_from_file_location("_ash_parity_gitleaks_fixture", path)
    if spec is None or spec.loader is None:
        raise ScanFailure(f"cannot load the gitleaks fixture module at {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    workflows = source / ".github" / "workflows"
    workflows.mkdir(parents=True)
    for name, origin in WORKFLOWS.items():
        shutil.copy(origin, workflows / name)
    shutil.copy(CFN_LINT_GUARD_TEMPLATE, source / "cfn" / "insecure.yaml")
    # The gitleaks fixture's tokens are fabricated but token-shaped, so the tree is
    # committed with markers and written out here (tests/utils/gitleaks_fixture.py).
    load_gitleaks_fixture().materialize(source / "secrets")
    return source


def _stop_process_tree(process: subprocess.Popen) -> None:
    """Stop ``process`` and, where the platform allows, every process it started.

    The scan is started in its own session, so on POSIX its scanners share its
    process group and one signal reaches them all; killing the direct child alone
    left bandit, semgrep and friends running after a timeout.
    """
    try:
        if hasattr(os, "killpg") and hasattr(os, "getpgid"):
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        else:  # pragma: no cover - Windows has no process groups of this kind
            process.kill()
    except (ProcessLookupError, PermissionError, OSError):
        process.kill()
    process.wait()


def run_scan(
    ash: List[str],
    source: Path,
    output: Path,
    mode: str,
    offline: bool,
    config: Optional[Path] = None,
    plugin_modules: List[str] = (),
    config_overrides: List[str] = (),
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
        # --fail-on-findings is an on/off flag. It was written here as
        # `--fail-on-findings false`, which `ash scan` accepted while it ignored
        # extra arguments, and which set the flag ON: the stray `false` was dropped.
        "--no-fail-on-findings",
        "--no-fail-on-incomplete-scanners",
    ]
    for module in plugin_modules:
        command += ["--ash-plugin-modules", module]
    for override in config_overrides:
        command += ["--config-overrides", override]
    if offline:
        command.append("--offline")
    if config is not None:
        command += ["--config", str(config)]
    print(f"$ {' '.join(command)}", flush=True)
    log = output.with_suffix(".log")
    with open(log, "w", encoding="utf-8") as handle:
        process = subprocess.Popen(  # nosec B603 - fixed argv
            command,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            returncode = process.wait(timeout=SCAN_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            _stop_process_tree(process)
            raise ScanFailure(
                f"ash scan --sandbox {mode} ran past {SCAN_TIMEOUT_SECONDS}s and was "
                f"stopped with its scanners; log at {log}"
            ) from None
    print(f"  exit {returncode}; log at {log}", flush=True)
    return returncode


def _load_document(output: Path) -> dict:
    """The aggregated results of one scan, or a ScanFailure naming what is missing.

    A scan that crashed writes no results file; reading it raised
    FileNotFoundError out of main, which lost the problems of the pairs before it
    and never wrote the report.
    """
    path = output / "ash_aggregated_results.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ScanFailure(
            f"the scan wrote no {path.name} under {output}; read {output.with_suffix('.log')}"
        ) from None
    except (json.JSONDecodeError, UnicodeDecodeError) as broken:
        raise ScanFailure(f"{path} is not readable JSON: {broken}") from None


def read_results(
    output: Path,
) -> Tuple[Dict[str, str], Dict[str, "Counter[Finding]"], Dict[str, Set[str]]]:
    document = _load_document(output)
    statuses = {
        name: str(info.get("status"))
        for name, info in document["scanner_results"].items()
    }
    # Findings are counted, not collected into a set: two identical findings on
    # one line (the same rule fired twice) collapsed to one, so a sandbox that
    # dropped one of them still read as parity.
    findings: Dict[str, Counter[Finding]] = {name: Counter() for name in statuses}
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
            findings.setdefault(scanner, Counter())[
                (scanner, str(result.get("ruleId")), uri, int(line), message)
            ] += 1
    # The shapes of what each scanner reports about its run, apart from values
    # that differ between any two runs. A sandbox must not change them: an earlier
    # version recorded the backend as container metadata, which made every
    # sandboxed scanner's tool_invocation gain exit_code and duration. Every
    # result's shape is kept, not the first one's: the first result read the same
    # while a later one gained a key.
    shapes: Dict[str, Set[str]] = {}
    for run in document["sarif"]["runs"]:
        for result in run.get("results") or []:
            props = result.get("properties") or {}
            scanner = props.get("scanner_name") or "?"
            details = props.get("scanner_details") or {}
            invocation = details.get("tool_invocation") or {}
            shape = json.dumps(
                {"properties": sorted(props), "tool_invocation": sorted(invocation)}
            )
            shapes.setdefault(scanner, set()).add(shape)
    return statuses, findings, shapes


def read_durations(output: Path) -> Dict[str, float]:
    """Seconds each scanner took, as ASH recorded it. Reported, not compared: a
    sandbox costs time, and how much is worth seeing per scanner."""
    document = _load_document(output)
    return {
        name: float(info.get("duration") or 0.0)
        for name, info in document["scanner_results"].items()
    }


_SELECTED_BACKEND = re.compile(r"Scanner sandbox: using (\S+) \(--sandbox (\S+)\)")


def selected_backend(log_text: str, requested: str) -> Optional[str]:
    """The backend ASH resolved for ``--sandbox <requested>``, read from ash.log.

    ASH logs the RESOLVED backend with the requested mode in parentheses, so
    ``--sandbox auto`` appears as ``Scanner sandbox: using bwrap (--sandbox
    auto)``. Matching the requested word against the backend name made every
    ``auto`` run read as "never selected" and the per-scanner lines, which also
    name the resolved backend, as "ran but not under auto". None when the log
    holds no selection line for the requested mode.
    """
    for match in _SELECTED_BACKEND.finditer(log_text):
        if match.group(2) == requested:
            return match.group(1)
    return None


def compare(
    label: str,
    off: Path,
    boxed: Path,
    exit_off: Optional[int] = None,
    exit_boxed: Optional[int] = None,
) -> Tuple[List[dict], List[str]]:
    off_status, off_findings, off_shapes = read_results(off)
    box_status, box_findings, box_shapes = read_results(boxed)
    off_seconds, box_seconds = read_durations(off), read_durations(boxed)
    rows, problems = [], []
    # ASH's exit status is part of its answer: a sandbox-only failure that the
    # scan reports through its exit code and nowhere in the results is parity
    # broken too. Both codes are given when the caller ran the scans.
    if exit_off is not None and exit_boxed is not None and exit_off != exit_boxed:
        problems.append(
            f"[{label}] ash exited {exit_off} unsandboxed but {exit_boxed} sandboxed"
        )
    # Every bucket findings were filed under, not only the scanners the rollup
    # names: a result whose scanner_name is absent from scanner_results (the "?"
    # fallback included) was never compared, so a sandbox that dropped or
    # renamed such a bucket passed parity.
    names = set(off_status) | set(box_status) | set(off_findings) | set(box_findings)
    for name in sorted(names):
        a, b = off_status.get(name), box_status.get(name)
        fa = off_findings.get(name, Counter())
        fb = box_findings.get(name, Counter())
        row = {
            "run": label,
            "scanner": name,
            "status_off": a,
            "status_sandboxed": b,
            "findings_off": sum(fa.values()),
            "findings_sandboxed": sum(fb.values()),
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
            # Counter subtraction keeps the findings one side has more of, so a
            # duplicate lost on one side shows up here.
            only_off = sorted(fa - fb)[:5]
            only_box = sorted(fb - fa)[:5]
            problems.append(
                f"[{label}] {name}: findings differ; only unsandboxed {only_off}; "
                f"only sandboxed {only_box}"
            )
        if off_shapes.get(name) != box_shapes.get(name) and fa == fb and fa:
            problems.append(
                f"[{label}] {name}: result shape differs; unsandboxed "
                f"{sorted(off_shapes.get(name, set()))} sandboxed "
                f"{sorted(box_shapes.get(name, set()))}"
            )
        if b in ("MISSING", "ERROR") and a not in ("MISSING", "ERROR"):
            problems.append(f"[{label}] {name}: ran unsandboxed but {b} sandboxed")
    return rows, problems


def summary_table(rows: List[dict], sandbox: str) -> str:
    """The per-scanner table, as text; a header alone when no scanner ran."""
    width = max((len(r["scanner"]) for r in rows), default=len("scanner"))
    header = (
        f"{'run':8} {'scanner':{width}}  off            {sandbox:14} identical"
        f"  seconds off/{sandbox}"
    )
    lines = [header]
    for r in rows:
        lines.append(
            f"{r['run']:8} {r['scanner']:{width}}  "
            f"{str(r['status_off']):8}{r['findings_off']:>4}   "
            f"{str(r['status_sandboxed']):8}{r['findings_sandboxed']:>4}     "
            f"{'yes' if r['identical'] else 'NO ':9}"
            f"{r['seconds_off']:>7.2f} {r['seconds_sandboxed']:>7.2f}"
        )
    return "\n".join(lines)


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
    parser.add_argument(
        "--require-offline",
        default="",
        help="comma-separated scanners that must also have run (not MISSING) "
        "unsandboxed in the offline pair, for a scanner whose offline run is the "
        "case under test",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="an ASH config file for every scan, to enable plugin scanners",
    )
    parser.add_argument("--min-findings", type=int, default=10)
    parser.add_argument(
        "--ash-plugin-modules",
        default="",
        help="comma-separated community plugin modules to load in both runs",
    )
    parser.add_argument(
        "--config-override",
        action="append",
        default=[],
        help="a --config-overrides value for both runs; repeatable",
    )
    parser.add_argument(
        "--ash", default=None, help="ash command, default: this interpreter's"
    )
    args = parser.parse_args()

    ash = [args.ash] if args.ash else [str(Path(sys.executable).with_name("ash"))]
    work = Path(tempfile.mkdtemp(prefix="ash-sandbox-parity-"))
    source = build_fixture(work)
    rows: List[dict] = []
    problems: List[str] = []
    pairs = [("offline", True)] + ([("online", False)] if args.online else [])
    modules = [m.strip() for m in args.ash_plugin_modules.split(",") if m.strip()]
    for label, offline in pairs:
        # One pair that cannot be judged (a timeout, a scan that wrote nothing) is
        # a problem of that pair; the other pairs still run and the report below
        # is still written, with every problem found so far.
        try:
            pair_rows, pair_problems = run_pair(
                label, offline, ash, source, work, args, modules
            )
        except ScanFailure as failure:
            pair_rows, pair_problems = [], [f"[{label}] {failure}"]
        rows += pair_rows
        problems += pair_problems

    print()
    print(summary_table(rows, args.sandbox))
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


def run_pair(
    label: str,
    offline: bool,
    ash: List[str],
    source: Path,
    work: Path,
    args: argparse.Namespace,
    modules: List[str],
) -> Tuple[List[dict], List[str]]:
    """Scan the fixture unsandboxed and sandboxed, and compare the two runs."""
    off = work / f"out-{label}-off"
    boxed = work / f"out-{label}-{args.sandbox}"
    exits: Dict[str, int] = {}
    for output, mode in ((off, "off"), (boxed, args.sandbox)):
        exits[mode] = run_scan(
            ash,
            source,
            output,
            mode,
            offline,
            args.config,
            modules,
            args.config_override,
        )
    rows, problems = compare(label, off, boxed, exits["off"], exits[args.sandbox])
    # Identical results prove nothing if the sandbox was never applied, and
    # since the backend no longer shows in the results, only the log can say.
    try:
        log_text = (boxed / "ash.log").read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        raise ScanFailure(
            f"the sandboxed scan wrote no ash.log under {boxed}"
        ) from None
    box_statuses, _, _ = read_results(boxed)
    # The log names the backend ASH resolved, so --sandbox auto reads as the
    # backend it chose; see selected_backend.
    backend = selected_backend(log_text, args.sandbox)
    if backend is None:
        problems.append(f"[{label}] the sandboxed run never selected {args.sandbox}")
    for name, status in box_statuses.items():
        if status in ("SKIPPED", "MISSING"):
            continue
        if (
            backend is None
            or f"Scanner sandbox: {name} on source runs under {backend}" not in log_text
        ):
            problems.append(
                f"[{label}] {name} ran but not under {backend or args.sandbox}"
            )
    statuses, findings, _ = read_results(off)
    total = sum(sum(f.values()) for f in findings.values())
    if total < args.min_findings:
        problems.append(
            f"[{label}] only {total} findings unsandboxed (need {args.min_findings}): "
            "the fixture is not exercising the scanners"
        )
    # --require is checked on the online pair when there is one: offline, semgrep
    # and opengrep need a seeded rule cache and npm-audit is skipped by design, so
    # a scanner can legitimately be MISSING in both offline runs. Parity still
    # holds there. --require-offline names the scanners whose offline run is
    # itself under test, and whose cache the job seeds first.
    required_here = args.require
    if args.online and label == "offline":
        required_here = args.require_offline
    elif label == "offline":
        required_here = f"{args.require},{args.require_offline}"
    for required in filter(None, (s.strip() for s in required_here.split(","))):
        if statuses.get(required) in (None, "MISSING", "ERROR", "SKIPPED"):
            problems.append(
                f"[{label}] required scanner {required} did not run unsandboxed "
                f"({statuses.get(required)})"
            )
    return rows, problems


if __name__ == "__main__":
    sys.exit(main())
