# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Prove ASH can scan a target directory that is not its own working directory.

Run with: python scripts/verify_external_target_scan.py

Why this exists
---------------
ASH scans the directory named by ``--source-dir``. Nothing in ``.github/`` has ever
passed that flag: CI runs ``./ash --build-target ci`` from the repository root, so
the process working directory and ``source_dir`` are always the same path. Two
production bugs hid inside that coincidence.

1. ``ScannerExecutor._extract_metrics_from_sarif`` returned a single pydantic model
   where the caller unpacked a 2-tuple. Pydantic models are iterable, so the unpack
   raised "too many values to unpack (expected 2)" at runtime only, and the error was
   swallowed into a scanner status. Every scanner reported ERROR with zero findings
   while 49,968 unit-test executions across 18 platform jobs stayed green.
2. checkov's config probe used ``Path(".ash/.checkov.yaml").exists()`` against the
   *process* working directory, while checkov's subprocess runs with
   ``cwd=source_dir``. Invoked from ASH's own checkout the probe matched ASH's
   committed config and handed checkov a path it could not open, so checkov reported
   ERROR. Invisible in CI, because there cwd and source_dir are the same directory.

Both are fixed. This script exists so neither class of bug can merge again: it scans
a throwaway directory built outside the repository, from a working directory that is
deliberately the repository root, and asserts both that no scanner broke *and* that
the findings the fixture is designed to produce actually came back.

Why the positive assertion matters
----------------------------------
"No scanner reported ERROR" alone is not enough -- that is exactly how the broken
build looked healthy, because a scanner that produces nothing also produces no
errors. So the gate also requires a non-zero finding count and requires that the
specific rules the fixture is built to trip appear in the aggregated SARIF.

Deliberate choices
------------------
* The fixture is generated at runtime under ``tempfile.mkdtemp()``. It is never
  committed: ASH scans its own repository in CI, so a committed fixture would be
  found by ASH's own self-scan and would fail the repository scan.
* The fixture trips bandit (Python AST rules) and checkov (Terraform policy rules)
  and deliberately does *not* plant a credential. A credential-shaped line would
  have to appear as a string literal in this file, and detect-secrets matches line
  by line with regexes rather than on an AST, so this file would itself become a
  finding in ASH's own repository scan. bandit and checkov are two independent
  scanner families, which is enough positive signal without that risk.
* Scanner status MISSING means the underlying tool is not installed on this runner.
  That is tolerated. ERROR means the scanner ran and broke, and fails the gate.
* The scan is invoked as ``<python> -m automated_security_helper.cli.main`` with
  ``cwd`` set to the repository root. ``-m`` prepends the working directory to
  ``sys.path``, so the gate always exercises the working tree rather than whatever
  copy happens to be pip-installed on the runner.

Known limitations
-----------------
* If neither bandit nor checkov can be installed on a runner, the gate fails rather
  than passing quietly. A gate that silently tests nothing is worse than a red one,
  so this is intentional -- but it does mean a broken tool install reads as a gate
  failure. The message names that cause explicitly.
* ``validation_checkpoints`` errors and discrepancies are reported as diagnostic
  context for a scanner at ERROR. They are not themselves a failure condition.
* The gate asserts rule *families* per scanner plus at least one concrete anchor
  rule ID. Requiring an exact rule-ID set would turn any upstream scanner release
  into a red branch, which has happened to this project before.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

RESULTS_FILENAME = "ash_aggregated_results.json"

# ScannerStatus values as they appear in ash_aggregated_results.json. FAILED means
# findings were found at or above the configured threshold -- a successful scan, not
# a gate failure.
STATUS_ERROR = "ERROR"
STATUS_MISSING = "MISSING"
STATUS_SKIPPED = "SKIPPED"

# 0 success, 1 scan errors / scanner failures, 2 actionable findings above
# threshold, 3 invalid config (see automated_security_helper.core.constants).
# The fixture is built to produce actionable findings, so 2 is the expected code and
# 0 is accepted in case a future default turns fail_on_findings off.
TOLERATED_EXIT_CODES = (0, 2)

# Log tail printed when something fails. Enough to see the scanner errors without
# dumping the whole Rich-rendered scan output into the job log.
LOG_TAIL_LINES = 60

# CSI, OSC and two-character escape sequences. The scan child renders a coloured
# Rich table; echoing the escapes verbatim into a CI log makes it unreadable.
_ANSI_ESCAPE = re.compile(
    r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])"
)


# ---------------------------------------------------------------------------
# Fixture content
#
# Written to disk at runtime, never committed. Every construct below is a known,
# stable finding for the scanner named in EXPECTED_PRODUCERS. These appear here as
# string literals; bandit, semgrep and opengrep all work on a parsed AST, so a
# string constant in this file is not itself a finding, and checkov only reads files
# whose name marks them as IaC.
# ---------------------------------------------------------------------------

FIXTURE_PYTHON = '''"""Deliberately insecure module. Scan fixture only -- never imported."""

import hashlib
import subprocess


def weak_digest(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def run_untrusted(command: str) -> int:
    return subprocess.call(command, shell=True)


def evaluate(expression: str):
    return eval(expression)
'''

FIXTURE_TERRAFORM = """resource "aws_s3_bucket" "gate_fixture" {
  bucket = "ash-external-target-gate-fixture"
}
"""

FIXTURE_FILES: Dict[str, str] = {
    "insecure_app.py": FIXTURE_PYTHON,
    "insecure_bucket.tf": FIXTURE_TERRAFORM,
}


@dataclass(frozen=True)
class ExpectedProducer:
    """A scanner the fixture is built to trip, and the evidence it must leave.

    ``rule_pattern`` is matched against rule IDs in the aggregated SARIF and is the
    hard requirement. ``anchor_rule_ids`` are concrete IDs observed from this
    fixture; at least one must be present. "At least one" rather than "all" keeps an
    upstream rule rename from reddening the branch while still pinning real IDs.
    """

    scanner: str
    fixture_file: str
    rule_pattern: str
    anchor_rule_ids: Tuple[str, ...]


EXPECTED_PRODUCERS: Tuple[ExpectedProducer, ...] = (
    # B307 eval, B324 insecure hash, B602 subprocess with shell=True.
    ExpectedProducer(
        scanner="bandit",
        fixture_file="insecure_app.py",
        rule_pattern=r"^B\d{3}$",
        anchor_rule_ids=("B307", "B324", "B602"),
    ),
    # A bare aws_s3_bucket trips seven CKV rules today. The exact set moves with
    # every checkov release, so the pattern is the requirement and the anchors are
    # a representative sample.
    ExpectedProducer(
        scanner="checkov",
        fixture_file="insecure_bucket.tf",
        rule_pattern=r"^CKV\d*_",
        anchor_rule_ids=(
            "CKV_AWS_18",
            "CKV_AWS_21",
            "CKV_AWS_144",
            "CKV_AWS_145",
            "CKV2_AWS_6",
        ),
    ),
)


@dataclass(frozen=True)
class ScannerState:
    """One entry of ``scanner_results``, normalized."""

    name: str
    status: str
    finding_count: int
    actionable_finding_count: int
    exit_code: int
    dependencies_satisfied: bool
    excluded: bool

    @property
    def ran(self) -> bool:
        """True when the scanner actually executed.

        A scanner at ERROR did run -- it ran and broke -- so it counts as having
        run. MISSING means the tool is not installed, SKIPPED means it was not
        invoked; neither produced a verdict.
        """
        if self.excluded:
            return False
        return self.status not in (STATUS_MISSING, STATUS_SKIPPED)


@dataclass
class GateOutcome:
    """What the gate concluded, so callers can report without re-deriving it."""

    violations: List[str] = field(default_factory=list)
    states: Tuple[ScannerState, ...] = ()
    rule_counts: Dict[str, int] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return not self.violations


# ---------------------------------------------------------------------------
# Pure assertion logic
#
# Everything below this point takes an already-parsed results dict (or data derived
# from one) and returns violation strings. No subprocesses, no filesystem, no
# global state -- so the checks are unit-testable without running a scan. That
# separation is the point: the bug this gate prevents lived in a seam between a
# producer and a consumer, and a seam only stays honest if both sides can be pinned
# independently.
# ---------------------------------------------------------------------------


def normalize_status(raw: Any) -> str:
    """Return a bare uppercase status name.

    Tolerates both ``"PASSED"`` and a stringified enum such as
    ``"ScannerStatus.PASSED"``, so a change in how the model serializes does not
    silently turn every status comparison false.
    """
    text = str(raw if raw is not None else "").strip()
    if "." in text:
        text = text.rsplit(".", 1)[-1]
    return text.upper()


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def check_results_shape(results: Any) -> List[str]:
    """Verify the keys every other check reads actually exist.

    Without this, renaming a key makes every downstream assertion vacuously true
    and the gate reports success while inspecting nothing. That failure mode is
    already live elsewhere in this repository, so it is not hypothetical.
    """
    if not isinstance(results, Mapping):
        return [
            (
                f"results is not a JSON object (got {type(results).__name__}); "
                f"expected the parsed contents of {RESULTS_FILENAME}"
            )
        ]

    violations: List[str] = []
    scanner_results = results.get("scanner_results")
    if not isinstance(scanner_results, Mapping):
        violations.append(
            "results has no 'scanner_results' object -- every scanner assertion "
            "below would inspect nothing. Available top-level keys: "
            f"{sorted(str(key) for key in results)}"
        )
    elif not scanner_results:
        violations.append(
            "'scanner_results' is empty -- the scan recorded no scanners at all"
        )

    if not isinstance(results.get("sarif"), Mapping):
        violations.append(
            "results has no top-level 'sarif' object -- the rule-ID assertions "
            "below would inspect nothing"
        )
    return violations


def parse_scanner_states(results: Mapping[str, Any]) -> Tuple[ScannerState, ...]:
    """Normalize ``scanner_results`` into a sorted tuple of ScannerState."""
    scanner_results = results.get("scanner_results") or {}
    states: List[ScannerState] = []
    for name, entry in scanner_results.items():
        record: Mapping[str, Any] = entry if isinstance(entry, Mapping) else {}
        states.append(
            ScannerState(
                name=str(name),
                status=normalize_status(record.get("status")),
                finding_count=_as_int(record.get("finding_count")),
                actionable_finding_count=_as_int(
                    record.get("actionable_finding_count")
                ),
                exit_code=_as_int(record.get("exit_code")),
                dependencies_satisfied=bool(record.get("dependencies_satisfied", True)),
                excluded=bool(record.get("excluded", False)),
            )
        )
    return tuple(sorted(states, key=lambda state: state.name))


def collect_rule_ids(results: Mapping[str, Any]) -> Dict[str, int]:
    """Count rule IDs across every run in the top-level aggregated SARIF."""
    counts: Dict[str, int] = {}
    sarif = results.get("sarif")
    if not isinstance(sarif, Mapping):
        return counts
    for run in sarif.get("runs") or []:
        if not isinstance(run, Mapping):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, Mapping):
                continue
            rule_id = result.get("ruleId")
            if rule_id is None:
                continue
            key = str(rule_id)
            counts[key] = counts.get(key, 0) + 1
    return counts


def collect_recorded_errors(
    results: Mapping[str, Any],
) -> Dict[str, Tuple[str, ...]]:
    """Gather whatever error detail the results file holds, keyed by scanner.

    ``ScannerTargetStatusInfo`` allows extra fields, so a scanner entry may carry
    error text under a name this script cannot know ahead of time; any key whose
    name mentions "error" is collected. ``validation_checkpoints`` entries that
    name the scanner are folded in as additional context.
    """
    scanner_results = results.get("scanner_results") or {}
    checkpoint_messages: List[str] = []
    for checkpoint in results.get("validation_checkpoints") or []:
        if not isinstance(checkpoint, Mapping):
            continue
        label = str(checkpoint.get("checkpoint_name") or "checkpoint")
        for key in ("errors", "discrepancies"):
            for entry in checkpoint.get(key) or []:
                checkpoint_messages.append(f"{label}.{key}: {entry}")

    collected: Dict[str, Tuple[str, ...]] = {}
    for name, entry in scanner_results.items():
        messages: List[str] = []
        if isinstance(entry, Mapping):
            for key, value in sorted(entry.items(), key=lambda item: str(item[0])):
                if "error" in str(key).lower() and value:
                    messages.append(f"{key}: {value}")
        lowered = str(name).lower()
        messages.extend(
            message for message in checkpoint_messages if lowered in message.lower()
        )
        collected[str(name)] = tuple(messages)
    return collected


def check_no_scanner_errors(
    states: Sequence[ScannerState],
    recorded_errors: Mapping[str, Sequence[str]] | None = None,
) -> List[str]:
    """Negative assertion: no scanner may report status ERROR.

    ERROR means the scanner was invoked and something went wrong inside it. That is
    the state every scanner was silently stuck in while CI stayed green.
    """
    recorded_errors = recorded_errors or {}
    violations: List[str] = []
    for state in states:
        if state.status != STATUS_ERROR:
            continue
        lines = [
            (
                f"scanner '{state.name}' reported status ERROR "
                f"(exit_code={state.exit_code}, finding_count={state.finding_count}, "
                f"dependencies_satisfied={state.dependencies_satisfied})"
            )
        ]
        detail = recorded_errors.get(state.name) or ()
        if detail:
            lines.extend(f"    {message}" for message in detail)
        else:
            lines.append(
                "    no error detail was recorded in the results file; see the scan "
                f"log above and the '{state.name}' subdirectory of the output dir"
            )
        violations.append("\n".join(lines))
    return violations


def check_some_scanner_ran(states: Sequence[ScannerState]) -> List[str]:
    """A gate where every scanner is MISSING has tested nothing, so it must fail."""
    if not states:
        return ["no scanners appear in scanner_results at all"]
    if any(state.ran for state in states):
        return []
    statuses = ", ".join(f"{state.name}={state.status}" for state in states)
    return [
        (
            "every scanner is MISSING, SKIPPED or excluded, so the scan exercised "
            f"nothing. Statuses: {statuses}"
        )
    ]


def check_findings_present(states: Sequence[ScannerState]) -> List[str]:
    """Positive assertion: the scanners that ran must have found something.

    Absence of errors is not evidence of a working scan. A scanner that cannot
    produce findings also cannot produce errors, which is precisely how the broken
    build passed CI.
    """
    ran = [state for state in states if state.ran]
    if not ran:
        # check_some_scanner_ran already reports this; do not double-count it.
        return []
    total = sum(state.finding_count for state in ran)
    if total > 0:
        return []
    names = ", ".join(state.name for state in ran)
    return [
        (
            f"the fixture produced zero findings across every scanner that ran "
            f"({names}). The fixture contains known insecure Python and a "
            "non-compliant aws_s3_bucket, so zero findings means scanning is "
            "broken, not that the target is clean"
        )
    ]


def check_expected_producers_available(
    states: Sequence[ScannerState],
) -> List[str]:
    """At least one scanner whose findings the gate asserts on must have run."""
    by_name = {state.name: state for state in states}
    available = [
        producer.scanner
        for producer in EXPECTED_PRODUCERS
        if producer.scanner in by_name and by_name[producer.scanner].ran
    ]
    if available:
        return []
    expected = ", ".join(producer.scanner for producer in EXPECTED_PRODUCERS)
    return [
        (
            f"none of the scanners this gate asserts on ({expected}) ran on this "
            "runner, so no finding could be verified. This usually means the tool "
            "install failed rather than that the product is broken -- check the "
            "scan log for dependency resolution errors"
        )
    ]


def check_expected_rules_present(
    states: Sequence[ScannerState],
    rule_counts: Mapping[str, int],
) -> List[str]:
    """Positive assertion: each available producer left its rules in the SARIF.

    Skips any producer whose scanner is MISSING, SKIPPED or excluded: the tool is
    not installed on this runner and requirement (e) says that must not fail.
    """
    by_name = {state.name: state for state in states}
    violations: List[str] = []
    for producer in EXPECTED_PRODUCERS:
        state = by_name.get(producer.scanner)
        if state is None or not state.ran:
            continue
        matched = sorted(
            rule_id
            for rule_id in rule_counts
            if re.match(producer.rule_pattern, rule_id)
        )
        if not matched:
            violations.append(
                f"scanner '{producer.scanner}' ran with status {state.status} but "
                f"no rule matching {producer.rule_pattern!r} appears in the "
                f"aggregated SARIF; '{producer.fixture_file}' should have produced "
                f"one. Rule IDs present: {sorted(rule_counts) or 'none'}"
            )
            continue
        if producer.anchor_rule_ids and not any(
            anchor in rule_counts for anchor in producer.anchor_rule_ids
        ):
            violations.append(
                f"scanner '{producer.scanner}' produced rules {matched} but none of "
                f"the expected anchors {list(producer.anchor_rule_ids)}. Either "
                f"'{producer.fixture_file}' no longer trips the rules it was "
                "written for, or the anchors need updating for a new scanner "
                "version"
            )
    return violations


def check_exit_code(exit_code: int) -> List[str]:
    """The scan process itself must not have failed or rejected its config."""
    if exit_code in TOLERATED_EXIT_CODES:
        return []
    return [
        (
            f"ash scan exited {exit_code}; expected one of "
            f"{list(TOLERATED_EXIT_CODES)} (0 success, 2 actionable findings). "
            "Exit 1 is a scan error and exit 3 is an invalid config"
        )
    ]


def check_paths_outside_repo(repo_root: Path, *paths: Path) -> List[str]:
    """The whole point of the gate is that the target is not the repository.

    Compares resolved ``Path`` objects rather than joined strings: ``str(Path)``
    uses backslashes on Windows, so any substring or ``endswith`` check on a
    slash-joined path is wrong there.
    """
    root = repo_root.resolve()
    violations: List[str] = []
    for path in paths:
        resolved = path.resolve()
        if resolved == root or resolved.is_relative_to(root):
            violations.append(
                f"'{resolved}' is inside the repository at '{root}'. The gate must "
                "scan a directory outside the repository, otherwise cwd and "
                "source_dir coincide and the bug class this gate exists for stays "
                "invisible"
            )
    return violations


def evaluate_results(results: Any, exit_code: int | None = None) -> GateOutcome:
    """Run every assertion against a parsed results dict.

    Shape violations short-circuit: if the keys are not where they should be, the
    remaining checks would pass by inspecting nothing, which is worse than failing.
    """
    outcome = GateOutcome()
    shape_violations = check_results_shape(results)
    if shape_violations:
        outcome.violations.extend(shape_violations)
        return outcome

    states = parse_scanner_states(results)
    rule_counts = collect_rule_ids(results)
    outcome.states = states
    outcome.rule_counts = rule_counts

    outcome.violations.extend(
        check_no_scanner_errors(states, collect_recorded_errors(results))
    )
    outcome.violations.extend(check_some_scanner_ran(states))
    outcome.violations.extend(check_findings_present(states))
    outcome.violations.extend(check_expected_producers_available(states))
    outcome.violations.extend(check_expected_rules_present(states, rule_counts))
    if exit_code is not None:
        outcome.violations.extend(check_exit_code(exit_code))
    return outcome


def format_summary_table(states: Sequence[ScannerState]) -> str:
    """A plain-ASCII table. Windows consoles cannot encode box-drawing or emoji."""
    headers = ("scanner", "status", "findings", "actionable", "exit")
    rows = [
        (
            state.name,
            state.status or "-",
            str(state.finding_count),
            str(state.actionable_finding_count),
            str(state.exit_code),
        )
        for state in states
    ]
    widths = [
        max(len(headers[column]), *(len(row[column]) for row in rows))
        if rows
        else len(headers[column])
        for column in range(len(headers))
    ]

    def render(values: Sequence[str]) -> str:
        cells = [values[0].ljust(widths[0]), values[1].ljust(widths[1])]
        cells.extend(
            values[column].rjust(widths[column]) for column in range(2, len(headers))
        )
        return "  ".join(cells).rstrip()

    lines = [render(headers), "  ".join("-" * width for width in widths)]
    lines.extend(render(row) for row in rows)
    return "\n".join(lines)


def format_rule_evidence(
    states: Sequence[ScannerState],
    rule_counts: Mapping[str, int],
) -> str:
    """Show which rules each asserted-on scanner actually produced."""
    by_name = {state.name: state for state in states}
    lines: List[str] = []
    for producer in EXPECTED_PRODUCERS:
        state = by_name.get(producer.scanner)
        if state is None:
            lines.append(f"{producer.scanner}: not present in scanner_results")
            continue
        if not state.ran:
            lines.append(
                f"{producer.scanner}: {state.status} (tool unavailable; not asserted)"
            )
            continue
        matched = sorted(
            rule_id
            for rule_id in rule_counts
            if re.match(producer.rule_pattern, rule_id)
        )
        anchors = [
            anchor for anchor in producer.anchor_rule_ids if anchor in rule_counts
        ]
        lines.append(
            f"{producer.scanner}: {len(matched)} rule(s) matching "
            f"{producer.rule_pattern} -- {matched}; anchors seen: {anchors}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Subprocess and temp-directory wrappers
#
# Thin shells around the pure logic above: build a fixture, run one scan, load one
# JSON file, hand it to evaluate_results.
# ---------------------------------------------------------------------------


def write_fixture(target_dir: Path) -> Tuple[Path, ...]:
    """Materialize FIXTURE_FILES under ``target_dir`` and return the paths.

    Always UTF-8: ``write_text`` defaults to the locale codepage on Windows.
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    for name, content in FIXTURE_FILES.items():
        path = target_dir / name
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return tuple(written)


def build_scan_command(source_dir: Path, output_dir: Path) -> List[str]:
    """The scan invocation, as a list -- never a shell string.

    ``--phases scan`` is enough to write the aggregated results file, and skipping
    the report phase keeps the gate fast.
    """
    return [
        sys.executable,
        "-m",
        "automated_security_helper.cli.main",
        "scan",
        "--source-dir",
        str(source_dir),
        "--output-dir",
        str(output_dir),
        "--phases",
        "scan",
        "--no-progress",
        "--simple",
    ]


def run_scan(
    repo_root: Path,
    source_dir: Path,
    output_dir: Path,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    """Run one scan of ``source_dir`` from a working directory that is not it.

    ``cwd=repo_root`` is the load-bearing part of this whole script. It is passed to
    the child rather than set with ``os.chdir``: this project deliberately removed
    process-wide cwd dependence, and reintroducing a global chdir previously took
    the unit suite from 2677 passed to 107 failed.
    """
    command = build_scan_command(source_dir, output_dir)
    env = dict(os.environ)
    # The child renders a Rich table. Force UTF-8 both ways so a cp1252 default on
    # Windows cannot turn a passing scan into an encoding traceback.
    env["PYTHONIOENCODING"] = "utf-8"
    env.setdefault("PYTHONUTF8", "1")
    return subprocess.run(  # nosec B603 -- list args, no shell, argv[0] is sys.executable
        command,
        cwd=str(repo_root),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def load_results(output_dir: Path) -> Any:
    """Read and parse the aggregated results file, explicitly as UTF-8."""
    results_path = output_dir / RESULTS_FILENAME
    if not results_path.exists():
        raise FileNotFoundError(str(results_path))
    return json.loads(results_path.read_text(encoding="utf-8"))


def sanitize_for_console(text: str) -> str:
    """Make captured child output safe to print on any console.

    Both reasons are Windows ones. The scan child renders a Rich table using
    box-drawing characters, and a default Windows console is cp1252, so echoing
    them raises UnicodeEncodeError -- the same failure mode that has already broken
    jobs in this repository. Stripping the ANSI escapes at the same time turns the
    failure output from a wall of colour codes into something readable in a CI log.

    Decoration is the only thing lost: scanner names, statuses and error text are
    all ASCII already.
    """
    plain = _ANSI_ESCAPE.sub("", text or "")
    return plain.encode("ascii", "replace").decode("ascii")


def _tail(text: str, limit: int = LOG_TAIL_LINES) -> str:
    lines = (text or "").splitlines()
    if len(lines) <= limit:
        return "\n".join(lines)
    return "\n".join(
        [f"... {len(lines) - limit} earlier line(s) omitted ..."] + lines[-limit:]
    )


def _print_block(title: str, body: str) -> None:
    """The single choke point for echoing captured child output."""
    if not body.strip():
        return
    print(f"--- {title} ---")
    print(sanitize_for_console(body))


def _remove_tree(path: Path) -> None:
    """Best-effort cleanup. Windows can hold locks on just-written files."""
    shutil.rmtree(path, ignore_errors=True)
    if path.exists():
        print(f"WARNING: could not fully remove temp directory '{path}'")


def _parse_args(argv: Iterable[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan a throwaway directory outside this repository and assert both "
            "that no scanner errored and that the expected findings came back."
        )
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1800.0,
        help="seconds to allow the scan subprocess (default: 1800)",
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="leave the fixture and output directories behind for inspection",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)

    # Derived from __file__, not from Path.cwd(): the gate must not depend on where
    # it was invoked from, since that dependence is the bug class under test.
    repo_root = Path(__file__).resolve().parents[1]

    temp_root = Path(tempfile.mkdtemp(prefix="ash-external-target-"))
    target_dir = temp_root / "target"
    output_dir = temp_root / "output"
    try:
        precondition_violations = check_paths_outside_repo(
            repo_root, target_dir, output_dir
        )
        if precondition_violations:
            print("FAIL: the gate's own preconditions are not met")
            for violation in precondition_violations:
                print(f"  - {violation}")
            return 1

        written = write_fixture(target_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        print("ASH external-target scan gate")
        print(f"  repository root (subprocess cwd): {repo_root}")
        print(f"  scan target (--source-dir):       {target_dir}")
        print(f"  scan output (--output-dir):       {output_dir}")
        print(f"  fixture files:                    {[p.name for p in written]}")
        print("  cwd != source_dir, which is the condition this gate exists for")
        print()

        try:
            completed = run_scan(repo_root, target_dir, output_dir, args.timeout)
        except subprocess.TimeoutExpired:
            print(f"FAIL: the scan did not finish within {args.timeout:g} seconds")
            return 1

        print(f"scan exited {completed.returncode}")

        try:
            results = load_results(output_dir)
        except FileNotFoundError as missing:
            print(f"FAIL: the scan wrote no results file at '{missing}'")
            _print_block("scan stdout (tail)", _tail(completed.stdout))
            _print_block("scan stderr (tail)", _tail(completed.stderr))
            return 1
        except json.JSONDecodeError as bad_json:
            print(f"FAIL: the results file is not valid JSON: {bad_json}")
            return 1

        outcome = evaluate_results(results, exit_code=completed.returncode)

        print()
        print(format_summary_table(outcome.states))
        print()
        print(format_rule_evidence(outcome.states, outcome.rule_counts))
        print()

        if outcome.passed:
            ran = [state for state in outcome.states if state.ran]
            total = sum(state.finding_count for state in ran)
            print(
                f"PASS: {len(ran)} scanner(s) ran, none errored, {total} finding(s) "
                "reported from a target outside the repository"
            )
            return 0

        print(f"FAIL: {len(outcome.violations)} problem(s) found")
        for violation in outcome.violations:
            print(f"  - {violation}")
        print()
        _print_block("scan stdout (tail)", _tail(completed.stdout))
        _print_block("scan stderr (tail)", _tail(completed.stderr))
        return 1
    finally:
        if args.keep_temp:
            print(f"temp directory kept at '{temp_root}'")
        else:
            _remove_tree(temp_root)


if __name__ == "__main__":
    raise SystemExit(main())
