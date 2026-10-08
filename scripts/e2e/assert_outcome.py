#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Asserts the outcome of one end-to-end `ashx scan` against an expected case.

Every e2e channel (wheel, container, deb/rpm, Homebrew, Flatpak, MSIX, Chocolatey,
winget, MCPB, the IDEs) runs the same three scans over the same fixtures and needs the
same verdict on each. This script is that verdict, so a channel cannot end up checking
less than its siblings by having written its own copy.

WHAT IT REQUIRES

- The exact exit code. ASH exits 0 (nothing actionable), 2 (actionable findings) and
  1 (the scan did not complete, or crashed). A leg that only checks "non-zero" cannot
  tell a scan that found the planted secret from one where a scanner never ran.
- reports/ash.sarif and ash_aggregated_results.json at exactly those paths under the
  output directory. There is no fallback to "any *.sarif": a report written somewhere
  else is a layout regression, and accepting it hides one.
- The actionable finding count from SARIF, exactly or as a minimum, and the same count
  in the aggregated results' summary_stats. The two files are written by different
  reporters; requiring them to agree catches one of them dropping results.
- When a scanner is named with --require-scanner, at least one SARIF result whose
  properties.scanner_name is that scanner. That field is where ASH records which
  scanner produced a result. The obvious fields are the wrong ones, as measured on a
  real report: runs[].tool.driver.name is ASH on every run, and ruleId is ASH's own
  normalized id (SECRET-AWS-ACCESS-KEY, not detect-secrets' AWSKeyDetector), so the
  string detect-secrets appears in neither.
- Every scanner listed with --selected to have actually been selected, meaning its
  status is not SKIPPED, so a --scanners argument that was dropped on the way into a
  channel (a wrapper, a shim, an MCP tool call) fails here rather than producing a scan
  of the wrong scanner set.
- For exit 1, the scanner named with --incomplete-scanner recorded as MISSING or ERROR,
  and no other scanner incomplete. Exit 1 also means "crashed", and only the aggregated
  results can tell the two apart, so an exit-1 case without a named scanner is refused
  as a usage error.
- For exit 0 and 2, no scanner incomplete at all.

The expectations can be given as flags or taken from tests/e2e/fixtures/cases.json
with --case. Flags given alongside --case override the case's values.

Pure standard library, Python 3.9+, so it runs in every distro image, on Windows
Python, and on a Flatpak host without installing anything.

--self-test builds planted outputs, one per rule, and requires each to be rejected for
its own reason, plus a well-formed output that must be accepted. A matcher that stopped
matching would otherwise pass every real run.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SARIF_RELATIVE = Path("reports") / "ash.sarif"
AGGREGATED_RELATIVE = Path("ash_aggregated_results.json")

# Statuses ASH writes for a scanner that was selected and did not produce a result.
INCOMPLETE_STATUSES = ("MISSING", "ERROR")
# Statuses for a scanner that executed. Mirrors .github/scripts/assert_scanners_completed.py.
RAN_STATUSES = ("PASSED", "FAILED")
KNOWN_STATUSES = RAN_STATUSES + INCOMPLETE_STATUSES + ("SKIPPED",)

DEFAULT_CASES = (
    Path(__file__).resolve().parents[2] / "tests" / "e2e" / "fixtures" / "cases.json"
)


def _norm(name: str) -> str:
    """Scanner names appear as detect-secrets and detect_secrets in different places."""
    return name.replace("_", "-").lower()


class Expectation:
    """What one scan must have produced."""

    def __init__(
        self,
        expect_rc: int,
        findings: Optional[int] = None,
        min_findings: Optional[int] = None,
        require_scanner: Optional[str] = None,
        selected: Optional[List[str]] = None,
        incomplete_scanner: Optional[str] = None,
        allow_unselected_missing: bool = False,
    ) -> None:
        self.expect_rc = expect_rc
        self.findings = findings
        self.min_findings = min_findings
        self.require_scanner = require_scanner
        self.selected = list(selected or [])
        self.incomplete_scanner = incomplete_scanner
        # For an N-1 that is a v3 release only (--allow-unselected-missing). v3 reports
        # every scanner whose tool is absent as MISSING, including scanners the scan
        # was not told to run; v4 reports those SKIPPED. A selected scanner that is
        # MISSING, and any ERROR, still fails.
        self.allow_unselected_missing = allow_unselected_missing

    def usage_problems(self) -> List[str]:
        """Expectations that cannot be asserted meaningfully, refused before any check."""
        problems: List[str] = []
        if self.expect_rc not in (0, 1, 2):
            problems.append(f"--expect-rc must be 0, 1 or 2, not {self.expect_rc}")
        if self.expect_rc == 1 and not self.incomplete_scanner:
            problems.append(
                "--expect-rc 1 needs --incomplete-scanner: exit 1 also means the scan "
                "crashed, and only a named incomplete scanner tells the two apart"
            )
        if self.expect_rc != 1 and self.incomplete_scanner:
            problems.append("--incomplete-scanner only applies to --expect-rc 1")
        if self.findings is None and self.min_findings is None:
            problems.append(
                "give --findings N or --min-findings N; a scan with no count check proves little"
            )
        if self.expect_rc == 2 and self.findings == 0:
            problems.append("--expect-rc 2 with --findings 0 contradicts itself")
        if (
            self.expect_rc == 2
            and self.findings is None
            and self.min_findings is not None
            and self.min_findings < 1
        ):
            problems.append(
                f"--expect-rc 2 with --min-findings {self.min_findings} checks no count; "
                "exit 2 means at least one actionable finding, so give --min-findings 1 or more"
            )
        if self.expect_rc == 0 and (self.findings or self.min_findings):
            problems.append(
                "--expect-rc 0 means nothing actionable; expect --findings 0"
            )
        if not self.selected:
            problems.append(
                "give --selected with the scanners the scan was told to run"
            )
        if self.incomplete_scanner and _norm(self.incomplete_scanner) not in {
            _norm(s) for s in self.selected
        }:
            problems.append(
                "--incomplete-scanner must be one of the --selected scanners"
            )
        return problems


def _actionable(result: Dict[str, Any]) -> bool:
    """A SARIF result counts unless it carries a suppression."""
    suppressions = result.get("suppressions")
    return not (isinstance(suppressions, list) and suppressions)


def check_outcome(output_dir: Path, rc: int, expected: Expectation) -> List[str]:
    """Returns every problem found; an empty list means the outcome matches."""
    problems: List[str] = []

    if rc != expected.expect_rc:
        meaning = {
            0: "nothing actionable",
            1: "scan incomplete or crashed",
            2: "actionable findings",
        }
        problems.append(
            f"exit code {rc} ({meaning.get(rc, 'not an ASH exit code')}), "
            f"expected exactly {expected.expect_rc} ({meaning[expected.expect_rc]})"
        )

    sarif_path = output_dir / SARIF_RELATIVE
    aggregated_path = output_dir / AGGREGATED_RELATIVE
    sarif: Optional[Dict[str, Any]] = None
    aggregated: Optional[Dict[str, Any]] = None
    for path, label in (
        (sarif_path, "SARIF report"),
        (aggregated_path, "aggregated results"),
    ):
        if not path.is_file():
            problems.append(f"no {label} at {path}")
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            problems.append(f"{label} at {path} is not readable JSON: {exc}")
            continue
        if not isinstance(document, dict):
            problems.append(f"{label} at {path} is not a JSON object")
            continue
        if label == "SARIF report":
            sarif = document
        else:
            aggregated = document

    sarif_actionable: Optional[int] = None
    if sarif is not None:
        runs = sarif.get("runs")
        if not isinstance(runs, list) or not runs:
            problems.append(
                f"{sarif_path} has no runs; that is a report nothing wrote into, not a clean scan"
            )
        else:
            results = [
                r
                for run in runs
                if isinstance(run, dict)
                for r in (run.get("results") or [])
                if isinstance(r, dict)
            ]
            actionable = [r for r in results if _actionable(r)]
            sarif_actionable = len(actionable)
            if expected.findings is not None and sarif_actionable != expected.findings:
                problems.append(
                    f"{sarif_actionable} actionable SARIF results, expected exactly {expected.findings}"
                )
            if (
                expected.min_findings is not None
                and sarif_actionable < expected.min_findings
            ):
                problems.append(
                    f"{sarif_actionable} actionable SARIF results, expected at least {expected.min_findings}"
                )
            if expected.require_scanner:
                want = _norm(expected.require_scanner)
                attributed = [
                    r
                    for r in actionable
                    if isinstance(r.get("properties"), dict)
                    and isinstance(r["properties"].get("scanner_name"), str)
                    and _norm(r["properties"]["scanner_name"]) == want
                ]
                if not attributed:
                    seen = sorted(
                        {
                            str(
                                (r.get("properties") or {}).get(
                                    "scanner_name", "<none>"
                                )
                            )
                            for r in actionable
                        }
                    )
                    problems.append(
                        f"no actionable SARIF result has properties.scanner_name == {expected.require_scanner!r}; "
                        f"scanners seen: {', '.join(seen) or 'none'}"
                    )

    if aggregated is not None:
        scanner_results = aggregated.get("scanner_results")
        if not isinstance(scanner_results, dict) or not scanner_results:
            problems.append(f"{aggregated_path} reports no scanners")
            scanner_results = {}
        statuses: Dict[str, str] = {}
        for name, entry in scanner_results.items():
            status = entry.get("status") if isinstance(entry, dict) else None
            statuses[_norm(str(name))] = (
                str(status) if status is not None else "UNKNOWN"
            )

        for name in expected.selected:
            status = statuses.get(_norm(name))
            if status is None:
                problems.append(
                    f"selected scanner {name} has no row in {aggregated_path}"
                )
            elif status == "SKIPPED":
                problems.append(
                    f"selected scanner {name} is SKIPPED, so the scanner selection did not reach the scan"
                )
        for name, status in sorted(statuses.items()):
            if status not in KNOWN_STATUSES:
                problems.append(
                    f"scanner {name} has status {status}, which this check does not recognize"
                )

        incomplete = {n: s for n, s in statuses.items() if s in INCOMPLETE_STATUSES}
        if expected.allow_unselected_missing:
            chosen = {_norm(s) for s in expected.selected}
            incomplete = {
                n: s
                for n, s in incomplete.items()
                if not (s == "MISSING" and _norm(n) not in chosen)
            }
        if expected.incomplete_scanner:
            want = _norm(expected.incomplete_scanner)
            got = statuses.get(want)
            if got not in INCOMPLETE_STATUSES:
                problems.append(
                    f"scanner {expected.incomplete_scanner} is {got or 'absent'}, expected MISSING or ERROR; "
                    "the incomplete trigger did not fire"
                )
            others = {n: s for n, s in incomplete.items() if n != want}
            if others:
                problems.append(
                    "scanners other than the trigger are incomplete: "
                    + ", ".join(f"{n}={s}" for n, s in sorted(others.items()))
                )
        elif incomplete:
            problems.append(
                "scanners did not complete: "
                + ", ".join(f"{n}={s}" for n, s in sorted(incomplete.items()))
            )
        if statuses and not any(s in RAN_STATUSES for s in statuses.values()):
            problems.append("no scanner executed (none is PASSED or FAILED)")

        stats = (aggregated.get("metadata") or {}).get("summary_stats")
        agg_actionable = stats.get("actionable") if isinstance(stats, dict) else None
        if not isinstance(agg_actionable, int):
            problems.append(
                f"{aggregated_path} has no integer metadata.summary_stats.actionable"
            )
        elif sarif_actionable is not None and agg_actionable != sarif_actionable:
            problems.append(
                f"the aggregated results count {agg_actionable} actionable findings and the SARIF "
                f"report {sarif_actionable}; one of the two reporters dropped results"
            )

    return problems


def load_case(cases_path: Path, case: str) -> Dict[str, Any]:
    document = json.loads(cases_path.read_text(encoding="utf-8"))
    cases = document.get("cases") if isinstance(document, dict) else None
    if not isinstance(cases, dict) or case not in cases:
        raise SystemExit(f"error: case {case!r} not found in {cases_path}")
    return dict(cases[case])


def expectation_from(args: argparse.Namespace) -> Expectation:
    base: Dict[str, Any] = {}
    if args.case:
        base = load_case(Path(args.cases), args.case)
    selected = args.selected.split(",") if args.selected else base.get("scanners", [])
    return Expectation(
        expect_rc=args.expect_rc
        if args.expect_rc is not None
        else int(base.get("expect_rc", -1)),
        findings=args.findings if args.findings is not None else base.get("findings"),
        min_findings=args.min_findings
        if args.min_findings is not None
        else base.get("min_findings"),
        require_scanner=args.require_scanner or base.get("require_scanner"),
        selected=[s for s in selected if s],
        incomplete_scanner=args.incomplete_scanner or base.get("incomplete_scanner"),
        allow_unselected_missing=args.allow_unselected_missing,
    )


# --------------------------------------------------------------------------
# Reporting a verdict
# --------------------------------------------------------------------------

# GitHub Actions turns a stdout line starting with this into an error annotation on the
# run summary.
ERROR_ANNOTATION = "::error::"
# What a rejection the caller asked for is printed with instead. Deliberately not an
# annotation: see report_problems.
EXPECTED_REJECTION = "expected rejection: "


def report_problems(label: str, problems: List[str], expect_reject: bool) -> None:
    """Prints why an outcome was rejected, one line per problem.

    A rejection nobody asked for is a real failure, so each problem is an error
    annotation and shows on the run summary. A negative control asks for its
    rejection with --expect-reject, and then the same problems print as plain lines.
    The reason is the reader: the e2e legs run several negative controls each, and
    when every one of them annotated, a green run's summary listed errors such as
    "[expect-rc 2] exit code 0 ..." on every channel. A summary that shows errors on
    a passing run trains whoever reads it to skip them, including on the run where one
    is real.

    The flag changes the printing and nothing else. The exit code still says whether
    the outcome matched, so the caller goes on judging the rejection itself: that it
    happened, and for the reason the control planted.
    """
    prefix = EXPECTED_REJECTION if expect_reject else ERROR_ANNOTATION
    for problem in problems:
        print(f"{prefix}[{label}] {problem}")


def report_unexpected_match(label: str) -> None:
    """The outcome matched although the caller expected a rejection.

    That is the negative control failing, so it is annotated: whatever the caller does
    with the exit code next, the summary shows that a control rejected nothing.
    """
    print(
        f"{ERROR_ANNOTATION}[{label}] --expect-reject was given and the outcome "
        "matched, so this negative control rejected nothing"
    )


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------


def _sarif_result(scanner: str, suppressed: bool = False) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ruleId": "SECRET-AWS-ACCESS-KEY",
        "properties": {"scanner_name": scanner},
    }
    if suppressed:
        result["suppressions"] = [{"kind": "external"}]
    return result


def _write_output(
    root: Path,
    results: List[Dict[str, Any]],
    statuses: Dict[str, str],
    actionable: Optional[int] = None,
    sarif_at: Path = SARIF_RELATIVE,
    write_aggregated: bool = True,
    no_runs: bool = False,
) -> Path:
    (root / sarif_at).parent.mkdir(parents=True, exist_ok=True)
    runs: List[Dict[str, Any]] = [] if no_runs else [{"results": results}]
    (root / sarif_at).write_text(
        json.dumps({"version": "2.1.0", "runs": runs}),
        encoding="utf-8",
    )
    if write_aggregated:
        count = (
            actionable
            if actionable is not None
            else sum(1 for r in results if _actionable(r))
        )
        (root / AGGREGATED_RELATIVE).write_text(
            json.dumps(
                {
                    "scanner_results": {n: {"status": s} for n, s in statuses.items()},
                    "metadata": {"summary_stats": {"actionable": count}},
                }
            ),
            encoding="utf-8",
        )
    return root


def self_test() -> int:
    three = [_sarif_result("detect-secrets") for _ in range(3)]
    findings = Expectation(
        2, findings=3, require_scanner="detect-secrets", selected=["detect-secrets"]
    )
    clean = Expectation(0, findings=0, selected=["detect-secrets"])
    incomplete = Expectation(
        1,
        findings=3,
        require_scanner="detect-secrets",
        selected=["detect-secrets", "opengrep"],
        incomplete_scanner="opengrep",
    )
    ok_findings = {
        "detect-secrets": "FAILED",  # pragma: allowlist secret
        "bandit": "SKIPPED",
    }
    ok_incomplete = {
        "detect-secrets": "FAILED",  # pragma: allowlist secret
        "opengrep": "MISSING",
    }

    # (name, results, statuses, rc, expectation, extra writer kwargs, problem substring or None)
    plans: List[Tuple[Any, ...]] = [
        ("findings outcome accepted", three, ok_findings, 2, findings, {}, None),
        (
            "clean outcome accepted",
            [],
            {"detect-secrets": "PASSED"},  # pragma: allowlist secret
            0,
            clean,
            {},
            None,
        ),
        ("incomplete outcome accepted", three, ok_incomplete, 1, incomplete, {}, None),
        (
            "ERROR also counts as incomplete",
            three,
            {
                "detect-secrets": "FAILED",  # pragma: allowlist secret
                "opengrep": "ERROR",
            },
            1,
            incomplete,
            {},
            None,
        ),
        (
            "suppressed results are not counted",
            three + [_sarif_result("detect-secrets", True)],
            ok_findings,
            2,
            findings,
            {},
            None,
        ),
        ("wrong exit code", three, ok_findings, 0, findings, {}, "exit code 0"),
        (
            "exit 2 where 1 was expected",
            three,
            ok_incomplete,
            2,
            incomplete,
            {},
            "expected exactly 1",
        ),
        (
            "SARIF somewhere other than reports/ash.sarif",
            three,
            ok_findings,
            2,
            findings,
            {"sarif_at": Path("other.sarif")},
            "no SARIF report at",
        ),
        (
            "aggregated results missing",
            three,
            ok_findings,
            2,
            findings,
            {"write_aggregated": False},
            "no aggregated results at",
        ),
        (
            "SARIF has no runs",
            [],
            {"detect-secrets": "PASSED"},  # pragma: allowlist secret
            0,
            clean,
            {"no_runs": True},
            "has no runs",
        ),
        (
            "finding count too low",
            three[:2],
            ok_findings,
            2,
            findings,
            {},
            "2 actionable SARIF results, expected exactly 3",
        ),
        (
            "finding count too high",
            three + three[:1],
            ok_findings,
            2,
            findings,
            {},
            "4 actionable SARIF results, expected exactly 3",
        ),
        (
            "findings from another scanner",
            [_sarif_result("bandit")] * 3,
            ok_findings,
            2,
            findings,
            {},
            "scanner_name == 'detect-secrets'",
        ),
        (
            "aggregated and SARIF disagree",
            three,
            ok_findings,
            2,
            findings,
            {"actionable": 5},
            "one of the two reporters dropped results",
        ),
        (
            "selected scanner was SKIPPED",
            three,
            {
                "detect-secrets": "FAILED",  # pragma: allowlist secret
                "opengrep": "SKIPPED",
            },
            1,
            incomplete,
            {},
            "selected scanner opengrep is SKIPPED",
        ),
        (
            "trigger scanner ran instead",
            three,
            {
                "detect-secrets": "FAILED",  # pragma: allowlist secret
                "opengrep": "PASSED",
            },
            1,
            incomplete,
            {},
            "the incomplete trigger did not fire",
        ),
        (
            "a second scanner is incomplete",
            three,
            {**ok_incomplete, "bandit": "MISSING"},
            1,
            incomplete,
            {},
            "other than the trigger",
        ),
        (
            "clean scan with an incomplete scanner",
            [],
            {"detect-secrets": "PASSED", "bandit": "ERROR"},  # pragma: allowlist secret
            0,
            clean,
            {},
            "scanners did not complete",
        ),
        (
            "unknown status",
            [],
            {"detect-secrets": "PASSED", "x": "RUNNING"},  # pragma: allowlist secret
            0,
            clean,
            {},
            "does not recognize",
        ),
        (
            "nothing executed",
            [],
            {"detect-secrets": "SKIPPED"},  # pragma: allowlist secret
            0,
            clean,
            {},
            "no scanner executed",
        ),
    ]

    failures = 0
    with tempfile.TemporaryDirectory(prefix="assert-outcome-self-test-") as tmp:
        for index, (
            name,
            results,
            statuses,
            rc,
            expectation,
            kwargs,
            needle,
        ) in enumerate(plans):
            root = _write_output(
                Path(tmp) / f"case{index}", results, statuses, **kwargs
            )
            problems = check_outcome(root, rc, expectation)
            if needle is None:
                passed = not problems
            else:
                passed = any(needle in p for p in problems)
            print(
                f"  {'ok' if passed else 'FAIL'}: {name}"
                + ("" if passed else f" -> {problems}")
            )
            failures += 0 if passed else 1

    usage = [
        (
            "exit 1 without a named scanner",
            Expectation(1, findings=0, selected=["a"]),
            "needs --incomplete-scanner",
        ),
        (
            "no count check",
            Expectation(0, selected=["a"]),
            "--findings N or --min-findings N",
        ),
        ("no selection", Expectation(0, findings=0), "--selected"),
        (
            "exit 2 with --min-findings 0",
            Expectation(2, min_findings=0, selected=["a"]),
            "checks no count",
        ),
    ]
    for name, expectation, needle in usage:
        passed = any(needle in p for p in expectation.usage_problems())
        print(f"  {'ok' if passed else 'FAIL'}: usage refused, {name}")
        failures += 0 if passed else 1

    total = len(plans) + len(usage)
    if failures:
        print(
            f"self-test FAILED: {failures} of {total} planted cases were judged wrongly"
        )
        return 1
    print(f"self-test passed: {total} planted cases judged as planted")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the planted-output self-test and exit",
    )
    parser.add_argument(
        "--output-dir", type=Path, help="the --output-dir the scan wrote to"
    )
    parser.add_argument("--rc", type=int, help="the exit code the scan returned")
    parser.add_argument(
        "--case", help="a case name from --cases (findings, clean, incomplete)"
    )
    parser.add_argument(
        "--cases",
        default=str(DEFAULT_CASES),
        help=f"cases file (default: {DEFAULT_CASES})",
    )
    parser.add_argument("--expect-rc", type=int, help="the exact exit code required")
    parser.add_argument(
        "--findings", type=int, help="the exact actionable finding count required"
    )
    parser.add_argument(
        "--min-findings", type=int, help="the minimum actionable finding count required"
    )
    parser.add_argument(
        "--require-scanner",
        help="a scanner that must have produced at least one finding",
    )
    parser.add_argument(
        "--selected", help="comma-separated scanners the scan was told to run"
    )
    parser.add_argument(
        "--incomplete-scanner",
        help="for exit 1: the scanner that must be MISSING or ERROR",
    )
    parser.add_argument(
        "--allow-unselected-missing",
        action="store_true",
        help=(
            "only for the scan of an N-1 that is a v3 release: a scanner the scan was "
            "not told to run, reported MISSING because its tool is absent, does not "
            "count as incomplete (v3 does this; v4 reports it SKIPPED)"
        ),
    )
    parser.add_argument(
        "--expect-reject",
        action="store_true",
        help=(
            "this run is a negative control that must be rejected: print the problems "
            "as plain lines rather than error annotations, and annotate a match "
            "instead. The exit code is unchanged (1 rejected, 0 matched)"
        ),
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.output_dir is None or args.rc is None:
        parser.error("--output-dir and --rc are required")

    expected = expectation_from(args)
    usage = expected.usage_problems()
    if usage:
        for problem in usage:
            print(f"error: {problem}", file=sys.stderr)
        return 3

    problems = check_outcome(args.output_dir, args.rc, expected)
    label = args.case or f"expect-rc {expected.expect_rc}"
    if problems:
        report_problems(label, problems, args.expect_reject)
        verdict = "REJECTED, as the caller expected" if args.expect_reject else "FAIL"
        print(
            f"{verdict}: {len(problems)} problem(s) with the {label} outcome in "
            f"{args.output_dir}"
        )
        return 1
    if args.expect_reject:
        report_unexpected_match(label)
    count = (
        expected.findings
        if expected.findings is not None
        else f">={expected.min_findings}"
    )
    print(
        f"OK: [{label}] rc={args.rc}, {count} actionable finding(s), reports at "
        f"{SARIF_RELATIVE.as_posix()} and {AGGREGATED_RELATIVE.as_posix()}"
        + (
            f", {expected.incomplete_scanner} incomplete as required"
            if expected.incomplete_scanner
            else ""
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
