# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/verify_external_target_scan.py: the pure gate logic.

* every selected scanner must have run: a SKIPPED, excluded or absent member of
  GATE_SCANNERS is a violation, not a narrowing of the gate to one scanner;
* a finding whose location normalizes to no path is reported, not counted as
  located;
* the scan child's environment carries no ASH_* variable;
* a timed-out scan is stopped with SIGTERM to its process group first, and
  killed only after the grace period.
"""

from __future__ import annotations

import os
import signal
import subprocess

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def gate(script_loader):
    return script_loader("verify_external_target_scan")


def _state(gate, name, status="PASSED", excluded=False, findings=1):
    return gate.ScannerState(
        name=name,
        status=status,
        finding_count=findings,
        actionable_finding_count=findings,
        exit_code=0,
        dependencies_satisfied=True,
        excluded=excluded,
    )


def _results(gate, scanner_results):
    """A minimal aggregated results document with bandit's rules attributed."""
    results = []
    for scanner in scanner_results:
        if scanner_results[scanner].get("status") != "PASSED":
            continue
        producer = next(p for p in gate.EXPECTED_PRODUCERS if p.scanner == scanner)
        for rule in producer.anchor_rule_ids or ("B602",):
            results.append(
                {
                    "ruleId": rule,
                    "properties": {"scanner_name": scanner},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": producer.fixture_file}
                            }
                        }
                    ],
                }
            )
    return {
        "scanner_results": scanner_results,
        "sarif": {"runs": [{"results": results}]},
    }


class TestGateScannersRan:
    def test_both_selected_scanners_ran_is_clean(self, gate):
        states = [_state(gate, "bandit"), _state(gate, "checkov")]
        assert gate.check_gate_scanners_ran(states) == []

    @pytest.mark.parametrize("status", ["SKIPPED", "MISSING"])
    def test_a_selected_scanner_that_did_not_run_is_a_violation(self, gate, status):
        states = [
            _state(gate, "bandit"),
            _state(gate, "checkov", status=status, findings=0),
        ]
        violations = gate.check_gate_scanners_ran(states)
        assert len(violations) == 1
        assert "checkov" in violations[0]
        assert status in violations[0]

    def test_an_excluded_selected_scanner_is_a_violation(self, gate):
        states = [_state(gate, "bandit"), _state(gate, "checkov", excluded=True)]
        assert any("excluded" in v for v in gate.check_gate_scanners_ran(states))

    def test_an_absent_selected_scanner_is_a_violation(self, gate):
        states = [_state(gate, "bandit")]
        violations = gate.check_gate_scanners_ran(states)
        assert len(violations) == 1
        assert "absent from scanner_results" in violations[0]

    def test_evaluate_results_fails_when_one_selected_scanner_was_skipped(self, gate):
        """At the base the SKIPPED scanner was dropped from every check and the gate passed."""
        results = _results(
            gate,
            {
                "bandit": {"status": "PASSED", "finding_count": 2},
                "checkov": {"status": "SKIPPED", "finding_count": 0},
            },
        )
        outcome = gate.evaluate_results(results, exit_code=2)
        assert not outcome.passed
        assert any("checkov" in v and "did not run" in v for v in outcome.violations)


class TestUnlocatableUris:
    def test_a_uri_that_normalizes_to_nothing_is_reported(self, gate, tmp_path):
        evidence = gate.SarifEvidence(uris=["./", "file://"])
        violations = gate.check_findings_are_from_the_fixture(evidence, tmp_path)
        assert any("normalize to no path" in v for v in violations)

    def test_a_fixture_uri_is_not_reported(self, gate, tmp_path):
        fixture_file = next(iter(gate.FIXTURE_FILES))
        evidence = gate.SarifEvidence(uris=[f"/elsewhere/target/{fixture_file}"])
        assert gate.check_findings_are_from_the_fixture(evidence, tmp_path) == []


class TestChildEnvironment:
    def test_ash_variables_are_dropped(self, gate):
        env = gate.child_environment(
            {
                "PATH": "/usr/bin",
                "ASH_EXCLUDED_SCANNERS": "checkov",
                "ASH_SHARD_INDEX": "0",
            }
        )
        assert [key for key in env if key.startswith("ASH_")] == []
        assert env["PATH"] == "/usr/bin"
        assert env["PYTHONIOENCODING"] == "utf-8"
        assert env["PYTHONUTF8"] == "1"


class _FakeProcess:
    """A child that ignores SIGTERM and dies on SIGKILL, with the calls recorded."""

    def __init__(self, dies_on_term: bool):
        self.pid = 4242
        self.dies_on_term = dies_on_term
        self.alive = True
        self.signals: list = []
        self.terminated = False
        self.killed = False

    def poll(self):
        return None if self.alive else 0

    def wait(self, timeout=None):
        if self.alive:
            raise subprocess.TimeoutExpired(cmd="ash", timeout=timeout)
        return 0

    def terminate(self):
        self.terminated = True
        if self.dies_on_term:
            self.alive = False

    def kill(self):
        self.killed = True
        self.alive = False


@pytest.mark.skipif(
    not hasattr(os, "killpg") or not hasattr(signal, "SIGKILL"),
    reason="process groups are a POSIX feature",
)
class TestStopProcessGroup:
    @pytest.fixture
    def killpg(self, gate, monkeypatch):
        calls: list = []
        calls_process: list = []

        def fake_killpg(pgid, signum):
            calls.append((pgid, signum))
            process = calls_process[0]
            if signum == signal.SIGKILL or process.dies_on_term:
                process.alive = False

        monkeypatch.setattr(gate.os, "killpg", fake_killpg)
        return calls, calls_process

    def test_sigterm_reaches_the_group_and_a_cooperative_child_is_not_killed(
        self, gate, killpg
    ):
        calls, calls_process = killpg
        process = _FakeProcess(dies_on_term=True)
        calls_process.append(process)
        gate._stop_process_group(process, grace_seconds=0.01)
        assert [signum for _, signum in calls] == [signal.SIGTERM]
        assert all(pgid == process.pid for pgid, _ in calls)
        assert not process.killed

    def test_a_child_that_ignores_sigterm_is_killed_after_the_grace_period(
        self, gate, killpg
    ):
        calls, calls_process = killpg
        process = _FakeProcess(dies_on_term=False)
        calls_process.append(process)
        gate._stop_process_group(process, grace_seconds=0.01)
        assert [signum for _, signum in calls] == [signal.SIGTERM, signal.SIGKILL]

    def test_an_exited_child_is_left_alone(self, gate, killpg):
        calls, _ = killpg
        process = _FakeProcess(dies_on_term=True)
        process.alive = False
        gate._stop_process_group(process)
        assert calls == []
