#!/usr/bin/env python3
"""Assert one case of the ASH pull-request gate regression fixture.

WHY THIS IS NOT JUST A VERDICT COMPARISON
-----------------------------------------
On 2026-08-28 the gate reported "ASH scan passed" on a pull request carrying two
bandit HIGH findings, because in the Lambda environment no scanner ran and ASH
still exited 0. A checker that only compared the verdict would have called the
clean case correct on that same broken build -- right answer, no scanning. So
every case additionally asserts that the scanners it depends on actually ran.

A NOTE ON MISSING VERSUS SKIPPED
--------------------------------
`skipped` is deliberate non-selection and is how sharding excludes scanners; it
is always tolerated. `missing` (selected, dependencies absent) and `error` (ran,
failed) are faults. Conflating them would make this fixture fail every sharded
run, which is how it would get disabled and stop protecting anything.

FAIL-CLOSED
-----------
Absent evidence is a failure, never a pass. If `scanner_results` is missing, or a
required scanner has no entry, that is reported as a failure rather than skipped
over -- a checker that silently finds nothing to check is worse than no checker,
because it reports green.
"""

import argparse
import json
import pathlib
import sys

FAULT_STATUSES = {"MISSING", "ERROR"}


class Failures:
    def __init__(self):
        self.items = []
        # Signals worth printing but never worth failing on. Kept separate so an
        # unreliable field cannot silently become load-bearing: anything in here
        # is reported and then ignored when computing pass/fail.
        self.advisories = []

    def check(self, condition, message):
        if not condition:
            self.items.append(message)
        return condition

    def fail(self, message):
        self.items.append(message)


def load_json(path, failures, label):
    p = pathlib.Path(path)
    if not p.is_file():
        failures.fail(f"{label}: file not found at {path}")
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        failures.fail(f"{label}: not valid JSON ({exc})")
        return None


def derive_verdict(exit_code, mapping):
    """Mirror the gate's _verdict(), including its unknown-code fallback."""
    return mapping.get(str(exit_code), "errored")


def assert_integrity(agg, case, invariants, failures):
    """The assertions that distinguish 'nothing was wrong' from 'nothing ran'."""
    metadata = agg.get("metadata")
    if not isinstance(metadata, dict):
        failures.fail("integrity: aggregated results carry no 'metadata' object")
        metadata = {}

    stats = metadata.get("summary_stats")
    if not isinstance(stats, dict):
        failures.fail("integrity: metadata has no 'summary_stats' object")
    else:
        expected_missing = invariants["summary_stats_missing_must_equal"]
        if "missing" not in stats:
            failures.fail("integrity: summary_stats has no 'missing' field to check")
        else:
            failures.check(
                stats["missing"] == expected_missing,
                f"integrity: summary_stats.missing is {stats['missing']}, "
                f"expected {expected_missing} -- scanners were selected but could not run",
            )
        # Deliberately NOT asserted: stats['skipped']. See module docstring.

    # ADVISORY ONLY -- do not key a fix or a gate on this. MEASURED 2026-08-28 on a
    # run with four scanner tools absent: summary_stats reported missing=4 while
    # execution_completion_validation reported
    #   {expected_count: 1, completed_count: 1, missing_count: 0,
    #    completion_rate: 1.0, has_issues: False}
    # False, with four selected scanners that never ran. "expected" counts only
    # scanners actually DISPATCHED, so a MISSING scanner never enters the expected
    # set and therefore cannot register as missing from it. The field under-reports
    # exactly the condition it looks like it reports.
    #
    # It is still worth surfacing when it IS true -- that is real information -- so
    # it is reported as an advisory line and never as the reason a case fails.
    # summary_stats.missing and the per-scanner statuses below are the load-bearing
    # signals.
    validation = metadata.get("validation_summary")
    if isinstance(validation, dict):
        want = invariants["validation_summary_has_issues_must_be"]
        for section, body in validation.items():
            if isinstance(body, dict) and body.get("has_issues") != want:
                failures.advisories.append(
                    f"advisory: validation_summary.{section}.has_issues is "
                    f"{body.get('has_issues')} (missing_count="
                    f"{body.get('missing_count')}). Corroborating only; this field "
                    f"reads False on genuinely-missing scanners."
                )

    # Per-scanner. Read scanner_results, NOT additional_reports: the two disagree.
    # On the 2026-08-28 vulnerable run scanner_results.bandit.status was FAILED
    # while additional_reports.bandit.source.status was PASSED, so a checker
    # reading additional_reports would have accepted a failing scan as clean.
    results = agg.get("scanner_results")
    if not isinstance(results, dict):
        failures.fail("integrity: aggregated results carry no 'scanner_results' object")
        return

    required = case.get("required_scanners") or []
    if not required:
        failures.fail(f"integrity: case '{case['name']}' names no required_scanners")
    for name in required:
        entry = results.get(name)
        if not isinstance(entry, dict):
            failures.fail(
                f"integrity: required scanner '{name}' has no entry in scanner_results "
                f"(present: {sorted(results)})"
            )
            continue
        status = str(entry.get("status", "<absent>")).upper()
        failures.check(
            status not in FAULT_STATUSES,
            f"integrity: required scanner '{name}' status is {status} -- it did not run",
        )
        if invariants["required_scanner_dependencies_satisfied"]:
            failures.check(
                entry.get("dependencies_satisfied") is True,
                f"integrity: required scanner '{name}' reports "
                f"dependencies_satisfied={entry.get('dependencies_satisfied')!r}",
            )


def assert_bandit(agg, case, failures):
    expected = case.get("expected_bandit")
    if not expected:
        return
    entry = (agg.get("scanner_results") or {}).get("bandit")
    if not isinstance(entry, dict):
        failures.fail("bandit: no scanner_results.bandit entry to compare")
        return

    if "status" in expected:
        actual = str(entry.get("status", "<absent>")).upper()
        failures.check(
            actual == expected["status"].upper(),
            f"bandit: status is {actual}, expected {expected['status']}",
        )
    if "actionable_finding_count" in expected:
        actual = entry.get("actionable_finding_count")
        failures.check(
            actual == expected["actionable_finding_count"],
            f"bandit: actionable_finding_count is {actual}, "
            f"expected {expected['actionable_finding_count']}",
        )
    if "finding_count" in expected:
        actual = entry.get("finding_count")
        failures.check(
            actual == expected["finding_count"],
            f"bandit: finding_count is {actual}, expected {expected['finding_count']}",
        )
    for severity, want in (expected.get("severity_counts") or {}).items():
        actual = (entry.get("severity_counts") or {}).get(severity)
        failures.check(
            actual == want,
            f"bandit: severity_counts.{severity} is {actual}, expected {want}",
        )


def assert_sarif(sarif, case, failures):
    """Check the specific rules fired, so a coincidental count cannot satisfy us."""
    expected = case.get("expected_sarif_rule_ids") or {}
    expected = {k: v for k, v in expected.items() if not k.startswith("_")}
    if not expected:
        return
    if sarif is None:
        failures.fail("sarif: expected rule ids but the SARIF report was unreadable")
        return

    found = {}
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule = result.get("ruleId")
            if rule:
                found.setdefault(rule, set()).add(result.get("level"))

    for rule, want_level in expected.items():
        if rule not in found:
            failures.fail(
                f"sarif: expected rule {rule} did not fire (fired: {sorted(found)})"
            )
        else:
            failures.check(
                want_level in found[rule],
                f"sarif: rule {rule} fired at level(s) {sorted(found[rule])}, "
                f"expected {want_level}",
            )


def assert_verdict_integrity(verdict, scanner_statuses, invariant, failures):
    """A passing verdict is legitimate only if no scanner is MISSING or ERROR.

    This is the conjunction the gate violated, and it is evaluable against a
    recorded observation rather than a live scan -- which is what lets it run
    with no AWS, no Docker and no working scanner set.

    It also survives the fix: after the exit code learns to read scanner status,
    the same table must produce a non-passing verdict, and this invariant is then
    satisfied rather than obsolete.
    """
    faults = set(invariant["fault_statuses"])
    faulted = sorted(n for n, s in scanner_statuses.items() if str(s).upper() in faults)

    if not scanner_statuses:
        failures.fail(
            "verdict-integrity: no scanner statuses supplied; nothing to check"
        )
        return faulted

    if verdict in invariant["passing_verdicts"] and faulted:
        failures.fail(
            f"verdict-integrity: verdict is '{verdict}' but {len(faulted)} scanner(s) "
            f"did not run ({', '.join(faulted)}). A passing verdict requires zero "
            f"faulted scanners -- this claims green over work that never happened."
        )
    return faulted


def run_replay(args):
    """Replay a recorded (verdict, scanner-table) observation against the invariant."""
    failures = Failures()
    spec = load_json(args.expected, failures, "expected.json")
    observed = load_json(args.observed, failures, "observed record")
    if spec is None or observed is None:
        print("FAIL: cannot replay without both expected.json and the observed record")
        for item in failures.items:
            print(f"  - {item}")
        return 1

    invariant = spec["verdict_integrity_invariant"]
    known_defect = invariant["known_defect"]["expected_to_fail"]
    statuses = observed.get("scanner_statuses") or {}

    print(
        f"replay: {observed.get('date')} {observed.get('stack')} "
        f"(ash {observed.get('ash_version')})"
    )
    absent = observed.get("scanners_absent") or []
    if absent:
        print(
            f"  {len(statuses)} scanner(s) reported, {len(absent)} never appeared "
            f"of {observed.get('scanners_expected')} expected"
        )

    for obs in observed.get("observations", []):
        sub = Failures()
        verdict = obs.get("actual_verdict")
        faulted = assert_verdict_integrity(verdict, statuses, invariant, sub)
        label = f"  PR {obs.get('pull_request_id')} ({obs.get('case')}): verdict='{verdict}'"
        if sub.items:
            print(f"{label}  <- VIOLATION")
            for item in sub.items:
                print(f"      {item}")
            failures.items.extend(sub.items)
        else:
            print(f"{label}  ok ({len(faulted)} faulted scanner(s))")

        # The vulnerable case carries the second, independent violation: content
        # that should have blocked did not. Recorded separately so that fixing
        # only one of the two does not make this replay go quiet.
        if (
            obs.get("content_should_have_blocked")
            and verdict in invariant["passing_verdicts"]
        ):
            msg = (
                f"content-integrity: PR {obs.get('pull_request_id')} carried findings "
                f"that should have blocked, but the verdict was '{verdict}'"
            )
            print(f"      {msg}")
            failures.items.append(msg)

    if failures.items:
        expected_after = invariant["expected_verdict_after_fix"]
        print(
            f"  expected verdict for this scanner table after the fix: '{expected_after}'"
        )

    if failures.items:
        if known_defect:
            print(
                f"XFAIL ({len(failures.items)} violation(s)) -- expected until the "
                f"exit-code fix lands. This is the defect, pinned."
            )
            return 0
        print(f"FAIL ({len(failures.items)} violation(s))")
        return 1

    if known_defect:
        print("XPASS: the invariant now holds on the recorded observation.")
        print(
            "       The fix appears to have landed. Set known_defect.expected_to_fail"
        )
        print(
            "       to false in expected.json so this guards against a re-regression."
        )
        return 1
    print("PASS")
    return 0


def run(args):
    failures = Failures()
    spec = load_json(args.expected, failures, "expected.json")
    if spec is None:
        print("FAIL: cannot proceed without expected.json")
        for item in failures.items:
            print(f"  - {item}")
        return 1

    case = next((c for c in spec["cases"] if c["name"] == args.case), None)
    if case is None:
        print(f"FAIL: no case named '{args.case}' in {args.expected}")
        return 1

    agg = load_json(args.aggregated, failures, "aggregated results")
    sarif = None
    if args.sarif:
        sarif = (
            load_json(args.sarif, failures, "sarif")
            if pathlib.Path(args.sarif).is_file()
            else None
        )
        if sarif is None and (case.get("expected_sarif_rule_ids") or {}):
            failures.fail(
                f"sarif: expected findings but no readable SARIF at {args.sarif}"
            )

    # 1. Exit code, and 2. the verdict the gate would derive from it.
    failures.check(
        args.exit_code == case["expected_ash_exit_code"],
        f"exit code is {args.exit_code}, expected {case['expected_ash_exit_code']}",
    )
    verdict = derive_verdict(args.exit_code, spec["verdict_mapping"])
    failures.check(
        verdict == case["expected_verdict"],
        f"verdict is '{verdict}', expected '{case['expected_verdict']}'",
    )

    # 3. Did the scanners actually run? This is the assertion that has teeth.
    if agg is not None:
        assert_integrity(agg, case, spec["integrity_invariants"], failures)
        assert_bandit(agg, case, failures)
    assert_sarif(sarif, case, failures)

    print(f"case={args.case} exit_code={args.exit_code} verdict={verdict}")
    for note in failures.advisories:
        print(f"  {note}")
    if failures.items:
        print(f"FAIL ({len(failures.items)} problem(s)):")
        for item in failures.items:
            print(f"  - {item}")
        return 1
    print("PASS")
    return 0


def selftest():
    """Prove the checker rejects the state we actually observed as broken.

    Without this, a checker that silently asserts nothing would report PASS on
    every input and we would never know. This replays the 2026-08-28 Lambda
    payload -- exit 0, every scanner MISSING/ERROR -- and REQUIRES a rejection.
    It also replays a legitimately-sharded payload (scanners SKIPPED, not
    missing) and requires acceptance, so the checker cannot pass the first test
    by simply rejecting everything.
    """
    spec = json.loads((pathlib.Path(__file__).parent / "expected.json").read_text())
    invariants = spec["integrity_invariants"]
    clean_case = next(c for c in spec["cases"] if c["name"] == "clean")

    broken = {
        "scanner_results": {
            "bandit": {"status": "MISSING", "dependencies_satisfied": False},
            "detect-secrets": {"status": "ERROR", "dependencies_satisfied": True},
        },
        "metadata": {
            "summary_stats": {"passed": 0, "failed": 0, "missing": 5, "skipped": 0},
            "validation_summary": {
                "execution_completion_validation": {
                    "has_issues": True,
                    "missing_count": 5,
                }
            },
        },
    }
    f1 = Failures()
    assert_integrity(broken, clean_case, invariants, f1)
    if not f1.items:
        print("SELFTEST FAIL: checker accepted the observed-broken all-MISSING payload")
        return 1

    sharded = {
        "scanner_results": {
            "bandit": {"status": "PASSED", "dependencies_satisfied": True},
            "grype": {"status": "SKIPPED", "dependencies_satisfied": True},
        },
        "metadata": {
            "summary_stats": {"passed": 1, "failed": 0, "missing": 0, "skipped": 9},
            "validation_summary": {
                "execution_completion_validation": {
                    "has_issues": False,
                    "missing_count": 0,
                }
            },
        },
    }
    f2 = Failures()
    assert_integrity(sharded, clean_case, invariants, f2)
    if f2.items:
        print("SELFTEST FAIL: checker rejected a legitimately sharded payload:")
        for item in f2.items:
            print(f"  - {item}")
        return 1

    empty = {}
    f3 = Failures()
    assert_integrity(empty, clean_case, invariants, f3)
    if not f3.items:
        print("SELFTEST FAIL: checker accepted an empty payload with nothing to check")
        return 1

    # The case that catches a checker leaning on validation_summary.has_issues.
    # MEASURED shape, 2026-08-28: four scanner tools absent, summary_stats
    # missing=4, and execution_completion_validation nonetheless reporting
    # has_issues=False with missing_count=0 and completion_rate=1.0. A checker
    # keyed on has_issues accepts this and reports green over four scanners that
    # never ran.
    #
    # The earlier all-MISSING payload above cannot catch that, because it sets
    # has_issues=True and so both signals agree -- and a payload where two signals
    # agree cannot tell you whether the checker depends on the wrong one.
    understated = {
        "scanner_results": {
            "bandit": {"status": "MISSING", "dependencies_satisfied": False},
            "cfn-nag": {"status": "MISSING", "dependencies_satisfied": False},
        },
        "metadata": {
            "summary_stats": {
                "passed": 1,
                "failed": 0,
                "missing": 4,
                "skipped": 5,
                "actionable": 0,
                "total": 5,
            },
            "validation_summary": {
                "execution_completion_validation": {
                    "expected_count": 1,
                    "completed_count": 1,
                    "missing_count": 0,
                    "completion_rate": 1.0,
                    "has_issues": False,
                }
            },
        },
    }
    f4 = Failures()
    assert_integrity(understated, clean_case, invariants, f4)
    if not f4.items:
        print("SELFTEST FAIL: checker accepted a payload with missing=4 but")
        print("               has_issues=False. It is keyed on has_issues, which")
        print("               under-reports missing scanners. Key on")
        print("               summary_stats.missing and per-scanner status instead.")
        return 1
    if any("has_issues" in item for item in f4.items):
        print("SELFTEST FAIL: has_issues appeared as a FAILURE reason. It is")
        print("               advisory only -- it reads False on missing scanners.")
        return 1

    print("SELFTEST PASS")
    print("  rejects all-MISSING")
    print("  rejects empty (fail-closed)")
    print("  accepts sharded/SKIPPED (does not break sharding)")
    print("  rejects missing=4 with has_issues=False (not keyed on has_issues)")
    print(f"  primary rejection reason: {f4.items[0]}")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case")
    parser.add_argument("--aggregated")
    parser.add_argument("--sarif")
    parser.add_argument("--exit-code", type=int)
    parser.add_argument(
        "--expected", default=str(pathlib.Path(__file__).parent / "expected.json")
    )
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument(
        "--replay",
        action="store_true",
        help="replay a recorded (verdict, scanner-table) observation; needs no scan",
    )
    parser.add_argument(
        "--observed",
        default=str(
            pathlib.Path(__file__).parent
            / "cases"
            / "observed-2026-08-28"
            / "observed.json"
        ),
    )
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if args.replay:
        return run_replay(args)
    missing = [n for n in ("case", "aggregated") if getattr(args, n) is None]
    if missing or args.exit_code is None:
        parser.error("--case, --aggregated and --exit-code are required")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
