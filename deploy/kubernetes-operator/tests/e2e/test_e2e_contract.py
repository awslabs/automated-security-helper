"""The shared e2e cases, run through the operator and judged by the shared verdict.

The rest of this directory tests the operator's own contract: fan-out, refusals,
provenance. This file holds it to the one every v4 channel meets: the three cases in
``tests/e2e/fixtures/cases.json`` scanned as an ``AshScan``, the merged report copied
off the results volume, and ``scripts/e2e/assert_outcome.py --case <name>`` run on it
with the exit code ``ashx merge`` returned. That is exit 2 with exactly three
detect-secrets findings, exit 0 clean, and exit 1 with opengrep MISSING, each with
``reports/ash.sarif`` and ``ash_aggregated_results.json`` present.

The negative controls judge real outputs from this run against the wrong case and
require the verdict to reject them, so a verdict that accepted anything would fail
here.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from ash_operator.constants import ASH_CLI, PHASE_CLEAN, PHASE_FINDINGS, PHASE_INCOMPLETE
from tests.e2e.helpers import (
    ASH_IMAGE,
    NAMESPACE,
    apply_fixture_configmap,
    apply_scan,
    kubectl,
    run,
    scan_uid,
    shard_pods,
    wait_terminal,
)
from tests.e2e.shared_contract import (
    ENV_EQUIVALENTS,
    SHARED_FIXTURES,
    case_spec,
    judge,
    load_cases,
    read_merged_output,
)

pytestmark = pytest.mark.e2e

CASES = load_cases()
EXPECTED_PHASE = {"findings": PHASE_FINDINGS, "clean": PHASE_CLEAN, "incomplete": PHASE_INCOMPLETE}


@pytest.fixture(scope="module")
def outcomes(installed, tmp_path_factory) -> dict[str, dict]:
    """Scan every case once, then copy each merged report off the cluster."""
    for source in sorted({case["source"] for case in CASES.values()}):
        apply_fixture_configmap(f"shared-{source}", SHARED_FIXTURES / source)
    for name, case in CASES.items():
        apply_scan(
            f"contract-{name}",
            source_configmap=f"shared-{case['source']}",
            min_severity=None,
            config=None,
            extra_spec=case_spec(case),
        )
    root = tmp_path_factory.mktemp("contract")
    results = {}
    for name in CASES:
        status = wait_terminal(f"contract-{name}")
        output = read_merged_output(f"contract-{name}", status, root / name)
        results[name] = {"status": status, "output": output}
    return results


@pytest.mark.parametrize("case", sorted(CASES))
class TestSharedCase:
    def test_the_shared_verdict_accepts_it(self, outcomes, case):
        outcome = outcomes[case]
        verdict = judge(case, outcome["output"], int(outcome["status"]["merge"]["exitCode"]))
        assert verdict.returncode == 0, verdict.stdout + verdict.stderr

    def test_the_phase_and_both_exit_codes_agree_with_the_case(self, outcomes, case):
        status = outcomes[case]["status"]
        expect_rc = CASES[case]["expect_rc"]
        assert status["phase"] == EXPECTED_PHASE[case], json.dumps(status)[:1500]
        assert status["merge"]["exitCode"] == expect_rc, status["merge"]
        assert status["exitCode"] == expect_rc, status

    def test_the_status_count_matches_the_case(self, outcomes, case):
        # The verdict counted SARIF results; .status is what an adopter reads, so it
        # has to carry the same number.
        assert (
            int(outcomes[case]["status"]["findings"]["actionable"] or 0)
            == (CASES[case]["findings"])
        ), outcomes[case]["status"]["findings"]

    def test_the_shard_ran_the_case_arguments(self, outcomes, case):
        # The arguments have to reach `ashx scan`, or the incomplete case would be the
        # findings case with a different label.
        uid = scan_uid(f"contract-{case}")
        pods = shard_pods(uid)
        assert len(pods) == 1, [p["metadata"]["name"] for p in pods]
        logs = kubectl("-n", NAMESPACE, "logs", pods[0]["metadata"]["name"], check=False).stdout
        assert f"{ASH_CLI} scan" in logs, logs[-2000:]
        for argument in case_spec(CASES[case])["extraScanArguments"]:
            assert argument in logs, (argument, logs[-2000:])


@pytest.mark.negative_control
class TestTheVerdictCanFail:
    """Real outputs from this run, judged as the wrong case, must be rejected."""

    @pytest.mark.parametrize(
        ("actual", "judged_as", "reason"),
        [
            ("findings", "clean", "exit code 2"),
            ("clean", "findings", "exit code 0"),
            ("incomplete", "findings", "exit code 1"),
            ("findings", "incomplete", "exit code 2"),
        ],
    )
    def test_a_mismatched_case_is_rejected(self, outcomes, actual, judged_as, reason):
        outcome = outcomes[actual]
        verdict = judge(judged_as, outcome["output"], int(outcome["status"]["merge"]["exitCode"]))
        assert verdict.returncode == 1, (
            f"the {actual} output passed as {judged_as}:\n{verdict.stdout}{verdict.stderr}"
        )
        assert reason in verdict.stdout, verdict.stdout

    def test_a_missing_sarif_report_is_rejected(self, outcomes, tmp_path):
        # The report is required at reports/ash.sarif exactly. Moving it aside must
        # fail the case that passed above, so the presence check is not vacuous.
        source = outcomes["findings"]["output"]
        copy = tmp_path / "moved"
        run(["cp", "-r", str(source), str(copy)])
        (copy / "reports" / "ash.sarif").rename(copy / "reports" / "elsewhere.sarif")
        verdict = judge("findings", copy, 2)
        assert verdict.returncode == 1
        assert "no SARIF report" in verdict.stdout, verdict.stdout


def test_every_case_env_variable_has_an_equivalent():
    # Collected with the cluster tests so the refusal in env_as_arguments is seen on
    # the real cases file, not only on a planted one.
    for case in CASES.values():
        case_spec(case)
    assert set(ENV_EQUIVALENTS) >= {k for c in CASES.values() for k in (c.get("env") or {})}


def test_the_ash_image_sets_no_rule_cache_dir(installed):
    # ENV_EQUIVALENTS maps OPENGREP_RULES_CACHE_DIR="" to "unset". That holds only if
    # the image does not set it; an image built with --offline does.
    inspected = json.loads(
        subprocess.run(
            ["docker", "image", "inspect", ASH_IMAGE],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    env = inspected[0]["Config"]["Env"] or []
    assert not [e for e in env if e.startswith("OPENGREP_RULES_CACHE_DIR=")], env
