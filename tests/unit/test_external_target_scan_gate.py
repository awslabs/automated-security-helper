# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the assertion logic behind scripts/verify_external_target_scan.py.

The gate itself runs a real scan, which is too slow and too environment-dependent
for the unit suite. Its assertions are pure functions over a parsed
ash_aggregated_results.json, so they are pinned here without running anything.

What these tests are protecting
-------------------------------
The gate exists because a refactor left every scanner reporting status ERROR with
zero findings while the whole unit suite stayed green. A gate against that failure
mode is only worth having if it cannot itself degrade into a check that inspects
nothing -- which is why there are tests for the shape check and for the positive
finding assertion, not just for the ERROR check.
"""

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = REPO_ROOT / "scripts" / "verify_external_target_scan.py"


def _load_gate():
    """Import the gate by path.

    scripts/ is not a package and is not importable as one, and mutating sys.path
    at import time would leak into every other test in the worker.

    The sys.modules registration is required, not decorative: dataclasses resolves
    the gate's string annotations (it uses `from __future__ import annotations`) by
    looking the defining module up in sys.modules, and raises AttributeError on None
    if it is not there.
    """
    spec = importlib.util.spec_from_file_location(
        "ash_verify_external_target_scan", GATE_PATH
    )
    assert spec is not None and spec.loader is not None, GATE_PATH
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _scanner(status, findings=0, actionable=0, exit_code=0, **extra):
    record = {
        "status": status,
        "finding_count": findings,
        "actionable_finding_count": actionable,
        "suppressed_finding_count": 0,
        "severity_counts": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "suppressed": 0,
        },
        "dependencies_satisfied": True,
        "excluded": False,
        "exit_code": exit_code,
        "duration": 1.0,
    }
    record.update(extra)
    return record


BANDIT_FIXTURE = "insecure_app.py"
CHECKOV_FIXTURE = "insecure_bucket.tf"


def _sarif_result(rule_id, scanner, uri):
    """One SARIF result. ``scanner``/``uri`` of None omit that field entirely."""
    result = {"ruleId": rule_id}
    if scanner is not None:
        result["properties"] = {"scanner_name": scanner}
    if uri is not None:
        result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]
    return result


def _sarif(entries):
    """Build a SARIF dict from (rule_id, scanner_name, uri) triples.

    ASH merges every scanner into one run whose driver is the ASH name, so the shape
    here is one run with mixed attribution -- the same shape the real file has.
    """
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "AWS Labs - Automated Security Helper"}},
                "results": [_sarif_result(*entry) for entry in entries],
            }
        ],
    }


def _owner(rule_id):
    """The scanner that really produces a rule ID, for building healthy fixtures."""
    return "checkov" if rule_id.startswith("CKV") else "bandit"


def _fixture_for(scanner):
    return CHECKOV_FIXTURE if scanner == "checkov" else BANDIT_FIXTURE


def _results(scanners=None, rule_ids=None, checkpoints=None):
    """A results dict shaped like the real file, healthy unless overridden.

    Rule IDs are attributed to their real producer and located in that producer's
    fixture file, so the default dict passes the attribution and fixture-scoping
    checks as well as the older ones.
    """
    if scanners is None:
        scanners = {
            "bandit": _scanner("FAILED", findings=4, actionable=3),
            "checkov": _scanner("FAILED", findings=7, actionable=7),
            "cdk-nag": _scanner("MISSING"),
            "syft": _scanner("MISSING"),
        }
    if rule_ids is None:
        rule_ids = ["B307", "B324", "B602", "CKV_AWS_18", "CKV_AWS_21", "CKV2_AWS_6"]
    entries = [
        (rule_id, _owner(rule_id), _fixture_for(_owner(rule_id)))
        for rule_id in rule_ids
    ]
    return {
        "scanner_results": scanners,
        "sarif": _sarif(entries),
        "validation_checkpoints": checkpoints if checkpoints is not None else [],
        "metadata": {},
    }


class TestHealthyResults:
    def test_healthy_dict_has_no_violations(self):
        assert gate.evaluate_results(_results()).violations == []

    def test_healthy_dict_with_findings_exit_code_has_no_violations(self):
        """Exit 2 means actionable findings, which is a successful scan."""
        assert gate.evaluate_results(_results(), exit_code=2).violations == []

    def test_failed_status_is_not_a_gate_failure(self):
        """FAILED means findings at or above threshold, not a broken scanner."""
        states = gate.parse_scanner_states(_results())
        assert gate.check_no_scanner_errors(states) == []


class TestScannerAtError:
    def test_error_status_is_reported(self):
        results = _results(
            scanners={
                "bandit": _scanner("ERROR", exit_code=1),
                "checkov": _scanner("FAILED", findings=7, actionable=7),
            }
        )
        violations = gate.evaluate_results(results).violations
        assert any("bandit" in v and "ERROR" in v for v in violations), violations

    def test_every_erroring_scanner_is_reported(self):
        results = _results(
            scanners={
                "bandit": _scanner("ERROR"),
                "checkov": _scanner("ERROR"),
                "detect-secrets": _scanner("PASSED", findings=1),
            }
        )
        violations = gate.check_no_scanner_errors(
            gate.parse_scanner_states(results),
            gate.collect_recorded_errors(results),
        )
        assert len(violations) == 2, violations
        reported = "\n".join(violations)
        assert "bandit" in reported and "checkov" in reported, reported
        assert "detect-secrets" not in reported, reported

    def test_recorded_errors_are_included_in_the_message(self):
        results = _results(
            scanners={
                "bandit": _scanner("ERROR", errors=["boom while parsing SARIF"]),
                "checkov": _scanner("FAILED", findings=7, actionable=7),
            }
        )
        violations = gate.check_no_scanner_errors(
            gate.parse_scanner_states(results),
            gate.collect_recorded_errors(results),
        )
        assert len(violations) == 1
        assert "boom while parsing SARIF" in violations[0]

    def test_checkpoint_errors_are_folded_in_as_context(self):
        results = _results(
            scanners={
                "bandit": _scanner("ERROR"),
                "checkov": _scanner("FAILED", findings=7, actionable=7),
            },
            checkpoints=[
                {
                    "checkpoint_name": "execution_completion",
                    "errors": ["bandit produced no results file"],
                    "discrepancies": [],
                }
            ],
        )
        violations = gate.check_no_scanner_errors(
            gate.parse_scanner_states(results),
            gate.collect_recorded_errors(results),
        )
        assert "bandit produced no results file" in violations[0]

    def test_message_says_so_when_no_detail_was_recorded(self):
        results = _results(scanners={"bandit": _scanner("ERROR")})
        violations = gate.check_no_scanner_errors(
            gate.parse_scanner_states(results),
            gate.collect_recorded_errors(results),
        )
        assert "no error detail was recorded" in violations[0]

    @pytest.mark.parametrize("raw", ["ERROR", "error", "ScannerStatus.ERROR"])
    def test_status_spelling_variants_are_all_caught(self, raw):
        """A change in how the enum serializes must not silence the check."""
        states = gate.parse_scanner_states(_results(scanners={"bandit": _scanner(raw)}))
        assert gate.check_no_scanner_errors(states), raw


class TestAllScannersMissing:
    def test_all_missing_is_a_violation(self):
        """Otherwise the gate passes while having tested nothing."""
        results = _results(
            scanners={
                "bandit": _scanner("MISSING"),
                "checkov": _scanner("MISSING"),
                "syft": _scanner("MISSING"),
            },
            rule_ids=[],
        )
        violations = gate.evaluate_results(results).violations
        assert any("every scanner is MISSING" in v for v in violations), violations

    def test_all_excluded_is_a_violation(self):
        results = _results(
            scanners={
                "bandit": _scanner("PASSED", excluded=True),
                "checkov": _scanner("PASSED", excluded=True),
            },
            rule_ids=[],
        )
        assert gate.check_some_scanner_ran(gate.parse_scanner_states(results))

    def test_empty_scanner_results_is_a_violation(self):
        assert gate.check_some_scanner_ran(())

    def test_no_expected_producer_available_is_reported_separately(self):
        """bandit and checkov both absent means nothing could be verified."""
        results = _results(
            scanners={
                "bandit": _scanner("MISSING"),
                "checkov": _scanner("MISSING"),
                "npm-audit": _scanner("PASSED", findings=3),
            },
            rule_ids=[],
        )
        violations = gate.evaluate_results(results).violations
        assert any(
            "none of the scanners this gate asserts on" in v for v in violations
        ), violations


class TestMissingIsTolerated:
    def test_some_missing_others_passed_with_findings_is_clean(self):
        """MISSING means the tool is not installed; that must not fail the gate."""
        results = _results(
            scanners={
                "bandit": _scanner("PASSED", findings=4, actionable=0),
                "checkov": _scanner("MISSING"),
                "cdk-nag": _scanner("MISSING"),
                "grype": _scanner("MISSING"),
                "syft": _scanner("MISSING"),
            },
            rule_ids=["B307", "B324"],
        )
        assert gate.evaluate_results(results).violations == []

    def test_a_missing_producer_is_not_asserted_on(self):
        """checkov is MISSING, so no CKV rule is required."""
        results = _results(
            scanners={
                "bandit": _scanner("PASSED", findings=4),
                "checkov": _scanner("MISSING"),
            },
            rule_ids=["B307"],
        )
        states = gate.parse_scanner_states(results)
        evidence = gate.collect_sarif_evidence(results)
        assert gate.check_expected_rules_present(states, evidence) == []

    def test_skipped_is_treated_like_missing(self):
        results = _results(
            scanners={
                "bandit": _scanner("PASSED", findings=4),
                "checkov": _scanner("SKIPPED"),
            },
            rule_ids=["B307"],
        )
        assert gate.evaluate_results(results).violations == []

    def test_missing_scanner_is_not_counted_as_having_run(self):
        states = {
            state.name: state
            for state in gate.parse_scanner_states(
                _results(
                    scanners={
                        "bandit": _scanner("PASSED", findings=1),
                        "checkov": _scanner("MISSING"),
                    }
                )
            )
        }
        assert states["bandit"].ran is True
        assert states["checkov"].ran is False


class TestZeroFindings:
    def test_zero_findings_everywhere_is_a_violation(self):
        """No errors plus no findings is exactly how the broken build looked."""
        results = _results(
            scanners={
                "bandit": _scanner("PASSED", findings=0),
                "checkov": _scanner("PASSED", findings=0),
                "detect-secrets": _scanner("PASSED", findings=0),
            },
            rule_ids=[],
        )
        violations = gate.evaluate_results(results).violations
        assert any("zero findings" in v for v in violations), violations

    def test_findings_from_a_single_scanner_are_enough(self):
        results = _results(
            scanners={
                "bandit": _scanner("PASSED", findings=0),
                "checkov": _scanner("FAILED", findings=7, actionable=7),
            },
            rule_ids=["CKV_AWS_18"],
        )
        assert gate.check_findings_present(gate.parse_scanner_states(results)) == []

    def test_findings_on_a_missing_scanner_do_not_count(self):
        """A MISSING scanner reporting findings would be nonsense, not evidence."""
        results = _results(
            scanners={
                "bandit": _scanner("PASSED", findings=0),
                "checkov": _scanner("MISSING", findings=99),
            },
            rule_ids=[],
        )
        assert gate.check_findings_present(gate.parse_scanner_states(results))


class TestRuleAssertions:
    def test_missing_rule_family_is_a_violation(self):
        """bandit ran but left no B-rule, so the scan produced nothing real."""
        results = _results(rule_ids=["CKV_AWS_18", "CKV_AWS_21"])
        states = gate.parse_scanner_states(results)
        evidence = gate.collect_sarif_evidence(results)
        violations = gate.check_expected_rules_present(states, evidence)
        assert len(violations) == 1, violations
        assert "bandit" in violations[0]

    def test_family_present_but_no_anchor_is_a_violation(self):
        """Guards against the fixture drifting away from the rules it targets."""
        results = _results(rule_ids=["B999", "CKV_AWS_18"])
        states = gate.parse_scanner_states(results)
        evidence = gate.collect_sarif_evidence(results)
        violations = gate.check_expected_rules_present(states, evidence)
        assert len(violations) == 1, violations
        assert "anchors" in violations[0]

    def test_one_anchor_is_enough(self):
        """An upstream rule rename must not redden the branch on its own."""
        results = _results(rule_ids=["B307", "CKV2_AWS_6"])
        states = gate.parse_scanner_states(results)
        evidence = gate.collect_sarif_evidence(results)
        assert gate.check_expected_rules_present(states, evidence) == []

    def test_rule_ids_are_counted_across_runs(self):
        results = _results()
        results["sarif"]["runs"].append(
            {"results": [_sarif_result("B307", "bandit", BANDIT_FIXTURE)]}
        )
        evidence = gate.collect_sarif_evidence(results)
        assert evidence.rules_for("bandit")["B307"] == 2

    def test_results_without_a_rule_id_are_skipped(self):
        results = _results(rule_ids=[])
        results["sarif"]["runs"][0]["results"] = [{"message": {"text": "x"}}]
        assert gate.collect_sarif_evidence(results).all_rule_ids() == ()

    def test_every_expected_producer_pattern_matches_its_anchors(self):
        """A typo in a pattern would make the family check unsatisfiable."""
        for producer in gate.EXPECTED_PRODUCERS:
            for anchor in producer.anchor_rule_ids:
                assert re.match(producer.rule_pattern, anchor), (
                    producer.scanner,
                    producer.rule_pattern,
                    anchor,
                )


class TestRuleAttribution:
    """Rules must be credited to the scanner that produced them, not pooled.

    A flat global histogram would let an attribution regression pass: bandit and
    checkov would report zero findings in the summary table while the rule-evidence
    block printed rules for both. Every SARIF result carries
    properties.scanner_name, so the data to do this right is already there.
    """

    def test_a_rule_attributed_to_another_scanner_does_not_satisfy_a_producer(self):
        """B307 exists, but checkov produced it, so bandit is still empty."""
        results = _results(rule_ids=[])
        results["sarif"] = _sarif(
            [
                ("B307", "checkov", CHECKOV_FIXTURE),
                ("CKV_AWS_18", "checkov", CHECKOV_FIXTURE),
            ]
        )
        states = gate.parse_scanner_states(results)
        evidence = gate.collect_sarif_evidence(results)
        violations = gate.check_expected_rules_present(states, evidence)
        assert len(violations) == 1, violations
        assert "bandit" in violations[0]
        assert "attributed" in violations[0]

    def test_correct_attribution_passes(self):
        results = _results(rule_ids=[])
        results["sarif"] = _sarif(
            [
                ("B307", "bandit", BANDIT_FIXTURE),
                ("CKV_AWS_18", "checkov", CHECKOV_FIXTURE),
            ]
        )
        states = gate.parse_scanner_states(results)
        evidence = gate.collect_sarif_evidence(results)
        assert gate.check_expected_rules_present(states, evidence) == []

    def test_buckets_are_keyed_by_scanner(self):
        results = _results()
        evidence = gate.collect_sarif_evidence(results)
        assert sorted(evidence.by_scanner) == ["bandit", "checkov"]
        assert sorted(evidence.rules_for("bandit")) == ["B307", "B324", "B602"]
        assert "B307" not in evidence.rules_for("checkov")

    def test_no_attribution_anywhere_falls_back_to_the_union(self):
        """An older or future results file without the property must still work."""
        results = _results(rule_ids=[])
        results["sarif"] = _sarif(
            [
                ("B307", None, BANDIT_FIXTURE),
                ("CKV_AWS_18", None, CHECKOV_FIXTURE),
            ]
        )
        evidence = gate.collect_sarif_evidence(results)
        assert evidence.has_attribution is False
        assert sorted(evidence.rules_for("bandit")) == ["B307", "CKV_AWS_18"]
        states = gate.parse_scanner_states(results)
        assert gate.check_expected_rules_present(states, evidence) == []

    def test_partial_attribution_does_not_fall_back(self):
        """One named result means the buckets are authoritative for everyone."""
        results = _results(rule_ids=[])
        results["sarif"] = _sarif(
            [
                ("CKV_AWS_18", "checkov", CHECKOV_FIXTURE),
                ("B307", None, BANDIT_FIXTURE),
            ]
        )
        evidence = gate.collect_sarif_evidence(results)
        assert evidence.has_attribution is True
        assert evidence.rules_for("bandit") == {}
        assert gate.check_expected_rules_present(
            gate.parse_scanner_states(results), evidence
        )

    def test_all_rule_ids_spans_every_bucket(self):
        results = _results(rule_ids=[])
        results["sarif"] = _sarif(
            [
                ("B307", "bandit", BANDIT_FIXTURE),
                ("CKV_AWS_18", "checkov", CHECKOV_FIXTURE),
                ("X1", None, BANDIT_FIXTURE),
            ]
        )
        evidence = gate.collect_sarif_evidence(results)
        assert evidence.all_rule_ids() == ("B307", "CKV_AWS_18", "X1")

    def test_evidence_cannot_report_rules_a_producer_did_not_produce(self):
        """The printed evidence must agree with the assertion, always.

        This is the manufactured-evidence failure: the summary table showed zero
        findings for bandit while the block below it printed bandit's rules.
        """
        results = _results(rule_ids=[])
        results["sarif"] = _sarif([("B307", "checkov", CHECKOV_FIXTURE)])
        states = gate.parse_scanner_states(results)
        evidence = gate.collect_sarif_evidence(results)
        rendered = gate.format_rule_evidence(states, evidence)
        bandit_line = next(
            line for line in rendered.splitlines() if line.startswith("bandit:")
        )
        assert "0 rule(s)" in bandit_line, rendered
        assert "B307" not in bandit_line, rendered
        # And the assertion agrees with what was printed.
        assert gate.check_expected_rules_present(states, evidence), rendered


class TestFindingsComeFromTheFixture:
    """The property the job is named for, and the one that was unasserted.

    Without this, the inverse regression -- ASH ignoring --source-dir and scanning
    the process working directory -- passes every other check: the repository yields
    findings, ASH's own Python trips bandit, the anchors plausibly appear, the exit
    code is 0 or 2.
    """

    def test_fixture_relative_uris_pass(self):
        results = _results()
        evidence = gate.collect_sarif_evidence(results)
        assert gate.check_findings_are_from_the_fixture(evidence, REPO_ROOT) == []

    # The absolute cases deliberately do not spell "/tmp": bandit's B108
    # (hardcoded_tmp_directory) fires on a literal /tmp path at MEDIUM severity, and
    # ASH scans its own tests/, so writing the real temp prefix here would add an
    # actionable finding to the repository's own scan. Only absoluteness matters to
    # this check, not the directory name.
    @pytest.mark.parametrize(
        "uri",
        [
            "./insecure_app.py",
            "insecure_app.py",
            "sub/insecure_app.py",
            "C:/Temp/target/insecure_app.py",
            "C:\\Temp\\target\\insecure_app.py",
            "/scratch/ash-external-target-x/target/insecure_app.py",
            "scratch/ash-external-target-x/target/insecure_app.py",
            "../../../scratch/ash-external-target-x/target/insecure_app.py",
            "file:///scratch/ash-external-target-x/target/insecure_app.py",
        ],
    )
    def test_every_observed_uri_shape_for_a_fixture_file_passes(self, uri):
        """A healthy run really does produce all of these; see Known limitations.

        bandit emits an absolute path, checkov the same path with the leading
        separator stripped, detect-secrets a cwd-relative path with .. segments.
        Rejecting absolute URIs would fail every healthy run.
        """
        results = _results(rule_ids=[])
        results["sarif"] = _sarif([("B307", "bandit", uri)])
        evidence = gate.collect_sarif_evidence(results)
        assert gate.check_findings_are_from_the_fixture(evidence, REPO_ROOT) == [], uri

    def test_a_repository_file_fails(self):
        """The exact shape a scan of the working directory produces."""
        results = _results(rule_ids=[])
        results["sarif"] = _sarif(
            [
                (
                    "B307",
                    "bandit",
                    "automated_security_helper/core/phases/scanner_executor.py",
                )
            ]
        )
        evidence = gate.collect_sarif_evidence(results)
        violations = gate.check_findings_are_from_the_fixture(evidence, REPO_ROOT)
        assert violations, "a scan of the repository must not pass"
        assert any("scanner_executor.py" in v for v in violations), violations

    def test_a_repository_file_is_reported_as_inside_the_repository(self):
        """Both tests must fire, so the message names the real cause."""
        results = _results(rule_ids=[])
        results["sarif"] = _sarif([("B307", "bandit", "Dockerfile")])
        evidence = gate.collect_sarif_evidence(results)
        violations = gate.check_findings_are_from_the_fixture(evidence, REPO_ROOT)
        assert any("inside the repository" in v for v in violations), violations

    def test_an_absolute_path_to_a_repository_file_fails(self):
        """Caught by the basename test even though it is not repo-relative."""
        target = REPO_ROOT / "automated_security_helper" / "core" / "orchestrator.py"
        results = _results(rule_ids=[])
        results["sarif"] = _sarif([("B307", "bandit", target.as_posix())])
        evidence = gate.collect_sarif_evidence(results)
        assert gate.check_findings_are_from_the_fixture(evidence, REPO_ROOT)

    def test_a_non_fixture_basename_fails(self):
        results = _results(rule_ids=[])
        results["sarif"] = _sarif([("B307", "bandit", "/elsewhere/other_module.py")])
        evidence = gate.collect_sarif_evidence(results)
        violations = gate.check_findings_are_from_the_fixture(evidence, REPO_ROOT)
        assert any("not part of the fixture" in v for v in violations), violations

    def test_offending_uris_appear_in_the_message(self):
        results = _results(rule_ids=[])
        results["sarif"] = _sarif([("B307", "bandit", "/elsewhere/other_module.py")])
        evidence = gate.collect_sarif_evidence(results)
        violations = gate.check_findings_are_from_the_fixture(evidence, REPO_ROOT)
        assert any("/elsewhere/other_module.py" in v for v in violations), violations

    def test_a_result_without_a_location_neither_passes_nor_fails(self):
        """It cannot confirm or deny the target, so it must not decide either way."""
        results = _results(rule_ids=[])
        results["sarif"] = _sarif(
            [("B307", "bandit", None), ("B324", "bandit", BANDIT_FIXTURE)]
        )
        evidence = gate.collect_sarif_evidence(results)
        assert evidence.results_without_location == 1
        assert gate.check_findings_are_from_the_fixture(evidence, REPO_ROOT) == []

    def test_no_uris_at_all_is_reported(self):
        """Silence here means the location shape moved; do not pass quietly."""
        results = _results(rule_ids=[])
        results["sarif"] = _sarif([("B307", "bandit", None)])
        evidence = gate.collect_sarif_evidence(results)
        violations = gate.check_findings_are_from_the_fixture(evidence, REPO_ROOT)
        assert any("carry a location URI" in v for v in violations), violations

    def test_zero_findings_is_not_this_checks_verdict(self):
        """check_findings_present owns that; double-reporting is noise."""
        results = _results(rule_ids=[])
        evidence = gate.collect_sarif_evidence(results)
        assert gate.check_findings_are_from_the_fixture(evidence, REPO_ROOT) == []

    def test_the_check_runs_through_evaluate_results_when_repo_root_is_given(self):
        results = _results(rule_ids=[])
        results["sarif"] = _sarif([("B307", "bandit", "Dockerfile")])
        with_root = gate.evaluate_results(results, repo_root=REPO_ROOT).violations
        without_root = gate.evaluate_results(results).violations
        assert any("inside the repository" in v for v in with_root), with_root
        assert not any("inside the repository" in v for v in without_root)

    def test_a_healthy_dict_passes_with_repo_root(self):
        assert (
            gate.evaluate_results(
                _results(), exit_code=2, repo_root=REPO_ROOT
            ).violations
            == []
        )


class TestTimeoutBudget:
    def test_the_default_timeout_fits_inside_the_job_budget(self):
        """The job sets timeout-minutes: 25 (1500s).

        If the script's default exceeded that, GitHub would cancel the job first and
        the operator would get no summary table, no rule evidence and no log tail.
        """
        assert gate.JOB_TIMEOUT_BUDGET_SECONDS == 25 * 60
        assert gate.DEFAULT_SCAN_TIMEOUT_SECONDS < gate.JOB_TIMEOUT_BUDGET_SECONDS

    def test_the_workflow_timeout_matches_the_documented_budget(self):
        """Ties the two numbers together so they cannot drift apart silently."""
        import yaml

        workflow = yaml.safe_load(
            (REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml").read_text(
                encoding="utf-8"
            )
        )
        job = workflow["jobs"]["external-target-scan"]
        assert job["timeout-minutes"] * 60 == gate.JOB_TIMEOUT_BUDGET_SECONDS

    def test_the_argparse_default_is_the_module_constant(self):
        args = gate._parse_args([])
        assert args.timeout == gate.DEFAULT_SCAN_TIMEOUT_SECONDS


class TestCapturedStreamDecoding:
    """TimeoutExpired carries bytes even when subprocess.run was given text=True."""

    @pytest.mark.parametrize(
        "value,expected",
        [(None, ""), ("plain", "plain"), (b"bytes", "bytes")],
    )
    def test_streams_of_any_type_decode(self, value, expected):
        assert gate._as_text(value) == expected

    def test_undecodable_bytes_do_not_raise(self):
        assert gate._as_text(b"\xff\xfe ok").endswith("ok")


class TestResultsShape:
    def test_missing_scanner_results_short_circuits(self):
        """A renamed key must fail loudly, not make every check vacuous."""
        results = _results()
        del results["scanner_results"]
        violations = gate.evaluate_results(results).violations
        assert any("scanner_results" in v for v in violations), violations

    def test_empty_scanner_results_is_a_violation(self):
        violations = gate.evaluate_results(_results(scanners={})).violations
        assert any("empty" in v for v in violations), violations

    def test_missing_sarif_is_a_violation(self):
        results = _results()
        del results["sarif"]
        violations = gate.evaluate_results(results).violations
        assert any("sarif" in v for v in violations), violations

    def test_non_mapping_results_is_a_violation(self):
        assert gate.evaluate_results(["not", "a", "dict"]).violations

    def test_shape_violations_suppress_the_downstream_checks(self):
        """Otherwise a shape break produces a wall of unrelated noise."""
        outcome = gate.evaluate_results({})
        assert outcome.violations
        assert outcome.states == ()


class TestExitCode:
    @pytest.mark.parametrize("code", [0, 2])
    def test_tolerated_codes(self, code):
        assert gate.check_exit_code(code) == []

    @pytest.mark.parametrize("code", [1, 3, 127])
    def test_rejected_codes(self, code):
        assert gate.check_exit_code(code)

    def test_exit_code_violation_surfaces_through_evaluate_results(self):
        violations = gate.evaluate_results(_results(), exit_code=1).violations
        assert any("exited 1" in v for v in violations), violations


class TestTargetMustBeOutsideTheRepo:
    def test_a_path_inside_the_repo_is_rejected(self):
        assert gate.check_paths_outside_repo(REPO_ROOT, REPO_ROOT / "scripts")

    def test_the_repo_root_itself_is_rejected(self):
        assert gate.check_paths_outside_repo(REPO_ROOT, REPO_ROOT)

    def test_a_path_outside_the_repo_is_accepted(self, tmp_path):
        assert gate.check_paths_outside_repo(REPO_ROOT, tmp_path) == []

    def test_every_offending_path_is_reported(self):
        violations = gate.check_paths_outside_repo(
            REPO_ROOT, REPO_ROOT / "scripts", REPO_ROOT / "tests"
        )
        assert len(violations) == 2, violations


class TestFixtureHandling:
    def test_fixture_is_generated_not_committed(self):
        """A committed fixture would be found by ASH's own repository self-scan."""
        for name in gate.FIXTURE_FILES:
            matches = sorted(str(p) for p in REPO_ROOT.rglob(name))
            assert matches == [], matches

    def test_write_fixture_creates_every_file(self, tmp_path):
        target = tmp_path / "target"
        written = gate.write_fixture(target)
        assert sorted(p.name for p in written) == sorted(gate.FIXTURE_FILES)
        for path in written:
            assert path.read_text(encoding="utf-8") == gate.FIXTURE_FILES[path.name]

    def test_scan_command_names_the_source_dir_explicitly(self, tmp_path):
        command = gate.build_scan_command(tmp_path / "src", tmp_path / "out")
        assert isinstance(command, list), "a shell string would be an injection risk"
        assert "--source-dir" in command
        assert command[command.index("--source-dir") + 1] == str(tmp_path / "src")
        assert "--output-dir" in command
        assert command[command.index("--output-dir") + 1] == str(tmp_path / "out")


class TestOutputIsAscii:
    """Windows consoles default to cp1252 and cannot encode box-drawing or emoji."""

    def test_the_gate_source_is_pure_ascii(self):
        source = GATE_PATH.read_text(encoding="utf-8")
        offenders = sorted({char for char in source if ord(char) > 127})
        assert offenders == [], offenders

    def test_the_summary_table_is_pure_ascii(self):
        table = gate.format_summary_table(gate.parse_scanner_states(_results()))
        table.encode("cp1252")

    def test_the_summary_table_lists_every_scanner(self):
        results = _results()
        table = gate.format_summary_table(gate.parse_scanner_states(results))
        for name in results["scanner_results"]:
            assert name in table

    def test_the_rule_evidence_block_is_pure_ascii(self):
        results = _results()
        evidence = gate.format_rule_evidence(
            gate.parse_scanner_states(results),
            gate.collect_sarif_evidence(results),
        )
        evidence.encode("cp1252")

    def test_the_table_renders_with_no_scanners(self):
        assert gate.format_summary_table(()).splitlines()[0].startswith("scanner")


class TestSanitizeCapturedOutput:
    """The scan child prints a coloured Rich table; echoing it verbatim is a bug.

    A default Windows console is cp1252 and cannot encode box-drawing characters,
    so printing the captured output unchanged raises UnicodeEncodeError on exactly
    the platform where the gate is most likely to be reporting a real failure.
    """

    # Escapes rather than the literal glyphs, so this file stays pure ASCII too:
    # 250f/2513/2517/251b are the box corners, 2501 the heavy horizontal, 2503 the
    # heavy vertical. These are the exact characters ASH's Rich tables emit.
    RICH_TABLE = (
        "\x1b[1;36m=== ASH Scan Completed ===\x1b[0m\n"
        "\u250f\u2501\u2501\u2501\u2513\n"
        "\u2503 bandit \u2503\n"
        "\u2517\u2501\u2501\u2501\u251b\n"
    )

    def test_box_drawing_is_replaced(self):
        cleaned = gate.sanitize_for_console(self.RICH_TABLE)
        cleaned.encode("cp1252")
        assert all(ord(char) < 128 for char in cleaned), cleaned

    def test_ansi_escapes_are_stripped(self):
        cleaned = gate.sanitize_for_console(self.RICH_TABLE)
        assert "\x1b" not in cleaned
        assert "[1;36m" not in cleaned

    def test_the_message_text_survives(self):
        cleaned = gate.sanitize_for_console(self.RICH_TABLE)
        assert "=== ASH Scan Completed ===" in cleaned
        assert "bandit" in cleaned

    def test_scanner_error_text_survives_unchanged(self):
        """The whole reason the tail is printed at all."""
        line = "ERROR checkov: too many values to unpack (expected 2)"
        assert gate.sanitize_for_console(f"\x1b[31m{line}\x1b[0m") == line

    @pytest.mark.parametrize("value", ["", None])
    def test_empty_input_is_handled(self, value):
        assert gate.sanitize_for_console(value) == ""


class TestNormalizeStatus:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("PASSED", "PASSED"),
            ("passed", "PASSED"),
            ("ScannerStatus.MISSING", "MISSING"),
            (None, ""),
            ("", ""),
        ],
    )
    def test_normalization(self, raw, expected):
        assert gate.normalize_status(raw) == expected

    def test_a_non_integer_count_does_not_raise(self):
        states = gate.parse_scanner_states(
            {"scanner_results": {"bandit": {"status": "PASSED", "finding_count": None}}}
        )
        assert states[0].finding_count == 0

    def test_a_non_mapping_scanner_entry_does_not_raise(self):
        states = gate.parse_scanner_states({"scanner_results": {"bandit": "broken"}})
        assert states[0].name == "bandit"
        assert states[0].status == ""
