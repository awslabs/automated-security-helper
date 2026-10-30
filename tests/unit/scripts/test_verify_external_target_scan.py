# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/verify_external_target_scan.py: the pure gate logic.

* every selected scanner must have run: a SKIPPED, excluded or absent member of
  GATE_SCANNERS is a violation, not a narrowing of the gate to one scanner;
* a finding whose location normalizes to no path is reported, not counted as
  located;
* the scan child's environment carries no ASH_* variable, and no PYTHONSAFEPATH;
* a timed-out scan is stopped with SIGTERM to its process group first, even when
  the child has already exited, and killed only after the grace period;
* the output of a stopped scan is read with a deadline and a final kill, so a
  tool that outlives the child cannot hang the gate;
* a missing scanner exit code is reported as absent, not as 0;
* each selected scanner must have found something, some finding must be
  actionable, and the exit code must agree with the actionable count;
* rules with no scanner attribution satisfy no producer;
* a repository file is seen as inside the repository in every URI shape the
  scanners emit, and a symlink loop is not a traceback;
* a finding with no location is reported even when others have one;
* an unreadable results file is a FAIL report, --timeout is validated, the
  cleanup hint is shell-quoted and a failed precondition leaves no directory.
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


#: Above any pid_max, so a signal that escapes the killpg patch (a refactor to
#: ``from os import killpg``, or a bare os.kill) meets ESRCH instead of a live
#: process on the runner.
FAKE_PID = 2**30


class _FakeProcess:
    """A child that dies on SIGTERM, or ignores it and dies on SIGKILL only.

    The fake records every ``wait`` deadline and every direct ``terminate`` or
    ``kill`` call; the group signals are recorded by the ``killpg`` fixture.
    """

    def __init__(self, dies_on_term: bool):
        self.pid = FAKE_PID
        self.dies_on_term = dies_on_term
        self.alive = True
        self.waits: list = []
        self.terminated = False
        self.killed = False

    def poll(self):
        return None if self.alive else 0

    def wait(self, timeout=None):
        self.waits.append(timeout)
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

    def test_a_cooperative_child_gets_sigterm_then_the_group_sweep(self, gate, killpg):
        """The child exits on SIGTERM; the group is still swept with SIGKILL.

        A tool that trapped SIGTERM, or one the child did not wait for, can
        outlive it in the group. Before the sweep nothing ever killed it and it
        kept writing into the evidence directory the gate had just reported.
        """
        calls, calls_process = killpg
        process = _FakeProcess(dies_on_term=True)
        calls_process.append(process)
        gate._stop_process_group(process, grace_seconds=0.01)
        assert [signum for _, signum in calls] == [signal.SIGTERM, signal.SIGKILL]
        assert all(pgid == process.pid for pgid, _ in calls)
        assert process.waits == [0.01], "one wait, for the grace period"
        assert not process.killed, "the group kill, never a bare process.kill"

    def test_a_child_that_ignores_sigterm_is_killed_after_the_grace_period(
        self, gate, killpg
    ):
        calls, calls_process = killpg
        process = _FakeProcess(dies_on_term=False)
        calls_process.append(process)
        gate._stop_process_group(process, grace_seconds=0.01)
        assert [signum for _, signum in calls] == [signal.SIGTERM, signal.SIGKILL]
        # The grace period is waited before the kill and again after it; a
        # wait(timeout=0) would make the grace period a fiction.
        assert process.waits == [0.01, 0.01]

    def test_an_exited_child_still_gets_the_group_signals(self, gate, killpg):
        """A tool the child started can outlive it in the group and hold the pipes."""
        calls, calls_process = killpg
        process = _FakeProcess(dies_on_term=True)
        process.alive = False
        calls_process.append(process)
        gate._stop_process_group(process, grace_seconds=0.01)
        assert calls == [
            (process.pid, signal.SIGTERM),
            (process.pid, signal.SIGKILL),
        ]
        assert not process.killed

    def test_an_empty_group_is_not_an_error(self, gate, monkeypatch):
        """The real killpg raises ProcessLookupError once nothing is left."""

        def no_such_group(pgid, signum):
            raise ProcessLookupError(pgid)

        monkeypatch.setattr(gate.os, "killpg", no_such_group)
        process = _FakeProcess(dies_on_term=True)
        process.alive = False
        gate._stop_process_group(process, grace_seconds=0.01)
        assert process.waits == [0.01]

    def test_a_group_of_zombies_is_not_an_error(self, gate, monkeypatch):
        """macOS answers EPERM for a group that holds only zombies."""

        def permission_denied(pgid, signum):
            raise PermissionError(pgid)

        monkeypatch.setattr(gate.os, "killpg", permission_denied)
        process = _FakeProcess(dies_on_term=True)
        process.alive = False
        gate._stop_process_group(process, grace_seconds=0.01)


class _FakePipes:
    """A stopped child whose output pipes follow a script of results or timeouts."""

    def __init__(self, *outcomes):
        self.pid = FAKE_PID
        self.outcomes = list(outcomes)
        self.timeouts: list = []

    def communicate(self, timeout=None):
        self.timeouts.append(timeout)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, subprocess.TimeoutExpired):
            raise outcome
        return outcome


def _timeout(output=None, stderr=None):
    return subprocess.TimeoutExpired(
        cmd="ash", timeout=0.01, output=output, stderr=stderr
    )


class _FakeScanChild:
    """A scan child that exited while a tool it started still holds the pipes."""

    pid = FAKE_PID

    def __init__(self, *args, **kwargs):
        self.returncode = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def communicate(self, timeout=None):
        assert timeout is not None, "the output must be read with a deadline"
        raise _timeout(output=b"tail")


@pytest.mark.skipif(
    not hasattr(os, "killpg") or not hasattr(signal, "SIGKILL"),
    reason="process groups are a POSIX feature",
)
class TestDrainOutput:
    @pytest.fixture
    def killed(self, monkeypatch):
        calls: list = []
        monkeypatch.setattr(
            os, "killpg", lambda pgid, signum: calls.append((pgid, signum))
        )
        return calls

    def test_pipes_that_close_are_read_without_a_kill(self, gate, killed):
        process = _FakePipes(("out", "err"))
        assert gate._drain_output(process, drain_seconds=0.01) == ("out", "err")
        assert process.timeouts == [0.01]
        assert killed == []

    def test_pipes_still_open_after_the_deadline_get_a_final_kill(self, gate, killed):
        process = _FakePipes(_timeout(), ("late out", "late err"))
        assert gate._drain_output(process, drain_seconds=0.01) == (
            "late out",
            "late err",
        )
        assert process.timeouts == [0.01, 0.01]
        assert killed == [(process.pid, signal.SIGKILL)]

    def test_pipes_held_past_the_final_kill_return_the_partial_output(
        self, gate, killed
    ):
        process = _FakePipes(_timeout(), _timeout(output=b"half"))
        assert gate._drain_output(process, drain_seconds=0.01) == ("half", "")
        assert None not in process.timeouts
        assert killed == [(process.pid, signal.SIGKILL)]

    def test_run_scan_gives_up_on_pipes_a_leftover_tool_holds_open(
        self, gate, killed, monkeypatch, tmp_path
    ):
        """At the base the drain after a timeout had no deadline and hung here."""
        monkeypatch.setattr(gate.subprocess, "Popen", _FakeScanChild)
        with pytest.raises(subprocess.TimeoutExpired) as raised:
            gate.run_scan(tmp_path, tmp_path / "src", tmp_path / "out", timeout=0.01)
        assert raised.value.output == "tail"
        # The stop (SIGTERM, then the sweep) and the drain's own kill all reach
        # the group; a run_scan that skipped the stop would still raise.
        assert killed == [
            (_FakeScanChild.pid, signal.SIGTERM),
            (_FakeScanChild.pid, signal.SIGKILL),
            (_FakeScanChild.pid, signal.SIGKILL),
        ]

    def test_an_interrupt_during_the_scan_stops_the_group(
        self, gate, killed, monkeypatch, tmp_path
    ):
        """Ctrl-C reaches only the gate: the child leads its own session.

        Only ``TimeoutExpired`` was caught, and ``Popen.__exit__`` treats a
        ``KeyboardInterrupt`` as one the child also received: it waits a moment
        and returns, so the scan and its tools kept running detached.
        """

        class _Interrupted(_FakeScanChild):
            def communicate(self, timeout=None):
                raise KeyboardInterrupt

        stopped: list = []
        monkeypatch.setattr(gate.subprocess, "Popen", _Interrupted)
        monkeypatch.setattr(
            gate, "_stop_process_group", lambda process, **_: stopped.append(process)
        )
        with pytest.raises(KeyboardInterrupt):
            gate.run_scan(tmp_path, tmp_path / "src", tmp_path / "out", timeout=0.01)
        assert len(stopped) == 1
        assert isinstance(stopped[0], _Interrupted)
        assert killed == [], "the stop was routed through _stop_process_group"


class TestExitCodeRecords:
    def test_a_missing_exit_code_is_none_not_zero(self, gate):
        """At the base _as_int read the absent code as 0 and the reports printed it."""
        states = gate.parse_scanner_states(
            {"scanner_results": {"bandit": {"status": "ERROR", "finding_count": 0}}}
        )
        assert states[0].exit_code is None
        violations = gate.check_no_scanner_errors(states)
        assert "exit_code=none (no tool ran)" in violations[0]
        table = gate.format_summary_table(states)
        assert table.splitlines()[-1].split()[-1] == "-"

    def test_an_infinite_count_is_read_as_zero(self, gate):
        assert gate._as_int(float("inf")) == 0
        assert gate._as_optional_int(float("inf")) is None


class TestRecordedErrors:
    def test_a_string_checkpoint_value_is_one_entry(self, gate):
        """At the base a string iterated character by character."""
        results = {
            "scanner_results": {"bandit": {"status": "ERROR"}},
            "validation_checkpoints": [
                {"checkpoint_name": "post", "errors": "bandit failed to start"}
            ],
        }
        recorded = gate.collect_recorded_errors(results)
        assert recorded["bandit"] == ("post.errors: bandit failed to start",)


class TestFindingsPerScanner:
    def test_one_selected_scanner_at_zero_is_a_violation(self, gate):
        """At the base the sum across scanners hid the zero."""
        states = [
            _state(gate, "bandit", findings=3),
            _state(gate, "checkov", findings=0),
        ]
        violations = gate.check_findings_present(states)
        assert len(violations) == 1
        assert "checkov" in violations[0] and "zero findings" in violations[0]

    def test_both_with_findings_is_clean(self, gate):
        states = [
            _state(gate, "bandit", findings=3),
            _state(gate, "checkov", findings=7),
        ]
        assert gate.check_findings_present(states) == []

    def test_findings_with_no_actionable_one_is_a_violation(self, gate):
        states = [
            gate.ScannerState("bandit", "PASSED", 3, 0, 0, True, False),
            gate.ScannerState("checkov", "PASSED", 7, 0, 0, True, False),
        ]
        violations = gate.check_actionable_findings_present(states)
        assert len(violations) == 1
        assert "no finding is actionable" in violations[0]


class TestExitCodeAgreesWithThePayload:
    def test_exit_zero_with_actionable_findings_is_a_violation(self, gate):
        states = [_state(gate, "bandit", findings=3)]
        violations = gate.check_exit_code(0, states)
        assert len(violations) == 1 and "exited 0" in violations[0]

    def test_exit_two_with_no_actionable_finding_is_a_violation(self, gate):
        states = [gate.ScannerState("bandit", "PASSED", 3, 0, 0, True, False)]
        assert any("exited 2" in v for v in gate.check_exit_code(2, states))

    def test_exit_two_with_actionable_findings_is_clean(self, gate):
        assert gate.check_exit_code(2, [_state(gate, "bandit", findings=3)]) == []

    def test_without_states_both_codes_are_tolerated(self, gate):
        assert gate.check_exit_code(0) == []
        assert gate.check_exit_code(2) == []


class TestUnattributedRules:
    def test_rules_with_no_scanner_name_cannot_satisfy_a_producer(self, gate):
        """At the base the union fallback let every producer match everybody's rules."""
        states = [_state(gate, "bandit"), _state(gate, "checkov")]
        evidence = gate.SarifEvidence(
            unattributed={"B307": 1, "CKV_AWS_18": 1}, uris=("insecure_app.py",)
        )
        violations = gate.check_expected_rules_present(states, evidence)
        assert len(violations) == 1
        assert "properties.scanner_name" in violations[0]


class TestNormalizeUri:
    def test_a_file_uri_is_decoded_and_the_drive_separator_dropped(self, gate):
        assert gate._normalize_uri("file:///C:/a%20b/x.py") == "C:/a b/x.py"
        assert gate._normalize_uri("file:///tmp/a%20b/x.py") == "/tmp/a b/x.py"


class TestInsideTheRepository:
    @pytest.fixture
    def repo(self, tmp_path):
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "insecure_app.py").write_text("x = 1\n", encoding="utf-8")
        return tmp_path

    def test_a_root_relative_uri_with_a_leading_separator_is_inside(self, gate, repo):
        """At the base Path(root, '/pkg/x.py') read the URI as filesystem-absolute."""
        evidence = gate.SarifEvidence(uris=("/pkg/insecure_app.py",))
        violations = gate.check_findings_are_from_the_fixture(evidence, repo)
        assert any("inside the repository" in v for v in violations)

    def test_checkovs_stripped_absolute_shape_is_inside(self, gate, repo):
        stripped = str((repo / "pkg" / "insecure_app.py").resolve()).lstrip("/")
        evidence = gate.SarifEvidence(uris=(stripped,))
        violations = gate.check_findings_are_from_the_fixture(evidence, repo)
        assert any("inside the repository" in v for v in violations)

    def test_a_fixture_uri_outside_the_repository_is_clean(self, gate, repo):
        evidence = gate.SarifEvidence(uris=("/elsewhere/target/insecure_app.py",))
        assert gate.check_findings_are_from_the_fixture(evidence, repo) == []

    @pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
    def test_a_symlink_loop_is_not_a_traceback(self, gate, repo):
        """At the base resolve() raised RuntimeError or OSError past the suppress."""
        loop = repo / "loop"
        try:
            loop.symlink_to(loop)
        except (OSError, NotImplementedError):  # pragma: no cover - no symlinks here
            pytest.skip("symlinks are not available")
        evidence = gate.SarifEvidence(uris=("loop/insecure_app.py",))
        violations = gate.check_findings_are_from_the_fixture(evidence, repo)
        assert not any("inside the repository" in v for v in violations)


class TestUnlocatedFindings:
    def test_some_findings_without_a_location_are_reported(self, gate, tmp_path):
        """At the base a mix passed and the PASS line claimed every finding was located."""
        evidence = gate.SarifEvidence(
            uris=("/elsewhere/target/insecure_app.py",), results_without_location=2
        )
        violations = gate.check_findings_are_from_the_fixture(evidence, tmp_path)
        assert len(violations) == 1
        assert "2 of 3 finding(s) carry no location" in violations[0]


class TestChildEnvironmentSafePath:
    def test_pythonsafepath_is_dropped(self, gate):
        env = gate.child_environment({"PATH": "/usr/bin", "PYTHONSAFEPATH": "1"})
        assert "PYTHONSAFEPATH" not in env


class TestLoadResults:
    def test_invalid_utf8_is_reported_not_raised_raw(self, gate, tmp_path):
        """At the base UnicodeDecodeError escaped main as a traceback."""
        (tmp_path / gate.RESULTS_FILENAME).write_bytes(b"\xff\xfe{}")
        with pytest.raises(gate.ResultsUnreadable, match="not valid UTF-8"):
            gate.load_results(tmp_path)


class TestScanTimeout:
    @pytest.mark.parametrize("text", ["nan", "inf", "0", "-5", "1800", "2000", "x"])
    def test_an_unusable_timeout_is_refused(self, gate, text):
        import argparse

        with pytest.raises(argparse.ArgumentTypeError):
            gate._scan_timeout(text)

    def test_a_timeout_under_the_budget_is_accepted(self, gate):
        assert gate._scan_timeout("600") == 600.0

    @pytest.mark.parametrize("text", ["1441", "1700", "1799"])
    def test_a_timeout_that_loses_the_race_inside_the_budget_is_refused(
        self, gate, text
    ):
        """At the base anything under 1800 passed, 1700 included.

        The setup steps and the stop-and-drain of a timed-out scan spend from
        the same 1800 s, so a scan allowed 1700 s is cancelled by the job before
        the tables print, which is what the check says it prevents.
        """
        import argparse

        with pytest.raises(argparse.ArgumentTypeError, match="at most 1440s"):
            gate._scan_timeout(text)

    def test_the_bound_is_the_budget_less_setup_and_shutdown(self, gate):
        assert gate.MAX_SCAN_TIMEOUT_SECONDS == (
            gate.JOB_TIMEOUT_BUDGET_SECONDS
            - gate.SETUP_MARGIN_SECONDS
            - 2 * (gate.SHUTDOWN_GRACE_SECONDS + gate.DRAIN_SECONDS)
        )
        assert gate.MAX_SCAN_TIMEOUT_SECONDS == 1440.0
        # The bound itself is accepted; the default stays inside it.
        assert gate._scan_timeout("1440") == 1440.0
        assert gate.DEFAULT_SCAN_TIMEOUT_SECONDS <= gate.MAX_SCAN_TIMEOUT_SECONDS
        assert gate._scan_timeout(str(gate.DEFAULT_SCAN_TIMEOUT_SECONDS)) == (
            gate.DEFAULT_SCAN_TIMEOUT_SECONDS
        )


class TestRemoveHint:
    def test_the_hint_is_shell_quoted(self, gate, tmp_path):
        hint = gate._remove_hint(tmp_path / "with space")
        assert hint == f"rm -rf '{tmp_path / 'with space'}'"


class TestPreconditionFailure:
    def test_the_empty_temp_directory_is_removed(
        self, gate, monkeypatch, tmp_path, capsys
    ):
        """At the base the mkdtemp directory stayed and a fixture never written was named."""
        made = tmp_path / "ash-external-target-x"
        made.mkdir()

        def mkdtemp(suffix=None, prefix=None, dir=None):  # noqa: A002 - tempfile's own name
            # tempfile.mkdtemp's full signature, so the stand-in survives the
            # gate passing the parent directory or the prefix positionally; the
            # prefix is still pinned, since it is what names the kept directory.
            assert prefix == "ash-external-target-"
            return str(made)

        monkeypatch.setattr(gate.tempfile, "mkdtemp", mkdtemp)
        monkeypatch.setattr(
            gate, "check_paths_outside_repo", lambda *paths: ["inside the repository"]
        )

        def never(*args, **kwargs):  # pragma: no cover - the gate must not get here
            raise AssertionError("the scan ran after a failed precondition")

        monkeypatch.setattr(gate, "run_scan", never)
        assert gate.main([]) == 1
        assert not made.exists()
        assert "EVIDENCE KEPT" not in capsys.readouterr().out
