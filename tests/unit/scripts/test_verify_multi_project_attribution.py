# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/verify_multi_project_attribution.py: the pure gate logic.

* exit 0 is refused when a project reports exceeds_threshold, and exit 2 when
  none does;
* every project's reported threshold must be the one its own config sets, not
  only the two of the threshold pair;
* both selected scanners must have run in the rollup;
* a run's declared root must be its own project's directory, not a sibling's
  with the same relative paths;
* a ``file://`` root is percent-decoded before it is resolved;
* the path-loss accounting counts every result, properties or not;
* the scan child's environment carries no ASH_* variable;
* a timed-out scan gets SIGTERM to its process group even when the child has
  already exited, and its output is read with a deadline and a final kill, so a
  tool that outlives the child cannot hang the gate.
"""

from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def gate(script_loader):
    return script_loader("verify_multi_project_attribution")


def _project(
    gate, key, threshold="LOW", actionable=1, exceeds=True, status="completed"
):
    return gate.ProjectOutcome(
        key=key,
        relative_path=gate.RELATIVE_PATH_BY_PROJECT.get(key, key),
        status=status,
        threshold=threshold,
        finding_count=max(actionable, 1),
        actionable_finding_count=actionable,
        exceeds_threshold=exceeds,
        output_path=key,
        sarif_run_index=0,
        error=None,
    )


def _fixture_projects(gate, **overrides):
    """One ProjectOutcome per fixture project at its configured threshold."""
    projects = []
    for fixture in gate.FIXTURE_PROJECTS:
        kwargs = {"threshold": fixture.threshold}
        kwargs.update(overrides.get(fixture.key, {}))
        projects.append(_project(gate, fixture.key, **kwargs))
    return projects


class TestExitCode:
    def test_exit_zero_with_an_exceeding_project_is_a_violation(self, gate):
        projects = [_project(gate, "project-a", exceeds=True)]
        violations = gate.check_exit_code(0, projects)
        assert len(violations) == 1
        assert "exited 0" in violations[0] and "project-a" in violations[0]

    def test_exit_two_with_no_exceeding_project_is_a_violation(self, gate):
        projects = [_project(gate, "project-a", actionable=0, exceeds=False)]
        assert any("exited 2" in v for v in gate.check_exit_code(2, projects))

    def test_exit_two_with_an_exceeding_project_is_clean(self, gate):
        assert gate.check_exit_code(2, [_project(gate, "project-a")]) == []

    def test_without_projects_both_codes_are_tolerated(self, gate):
        assert gate.check_exit_code(0) == []
        assert gate.check_exit_code(2) == []


class TestThresholdsPerProject:
    def test_every_project_at_its_configured_threshold_is_clean_on_that_point(
        self, gate
    ):
        projects = _fixture_projects(
            gate, src={"actionable": 1}, **{"project-b": {"actionable": 3}}
        )
        violations = gate.check_thresholds_are_per_project(projects)
        assert not [v for v in violations if "its own config sets" in v]

    def test_a_project_outside_the_pair_at_the_wrong_threshold_is_a_violation(
        self, gate
    ):
        projects = _fixture_projects(
            gate,
            src={"actionable": 1},
            **{"project-b": {"actionable": 3}, "apps-admin": {"threshold": "HIGH"}},
        )
        violations = gate.check_thresholds_are_per_project(projects)
        assert any(
            "apps-admin" in v and "its own config sets 'LOW'" in v for v in violations
        )


class TestGateScannersRan:
    def test_both_present_and_run_is_clean(self, gate):
        assert (
            gate.check_gate_scanners_ran({"bandit": "PASSED", "checkov": "FAILED"})
            == []
        )

    @pytest.mark.parametrize("status", ["MISSING", "SKIPPED"])
    def test_a_selected_scanner_that_did_not_run_is_a_violation(self, gate, status):
        violations = gate.check_gate_scanners_ran(
            {"bandit": "PASSED", "checkov": status}
        )
        assert len(violations) == 1
        assert "checkov" in violations[0] and status in violations[0]

    def test_an_absent_selected_scanner_is_a_violation(self, gate):
        violations = gate.check_gate_scanners_ran({"bandit": "PASSED"})
        assert any("absent from scanner_results" in v for v in violations)

    def test_evaluate_results_names_it_as_a_root_cause(self, gate, tmp_path):
        results = {
            "workspace": {
                "projects": [
                    {
                        "project": "project-a",
                        "relative_path": "project-a",
                        "status": "completed",
                    }
                ],
                "status": "completed",
                "exit_code": 2,
            },
            "scanner_results": {
                "bandit": {"status": "PASSED"},
                "checkov": {"status": "SKIPPED"},
            },
            "sarif": {"runs": []},
        }
        outcome = gate.evaluate_results(results, tmp_path)
        assert any("checkov" in v for v in outcome.root_violations)


class TestUriBase:
    def test_percent_escapes_are_decoded(self, gate):
        assert gate._uri_base_to_path("file:///tmp/a%20b/caf%C3%A9/") == Path(
            "/tmp/a b/café/"
        )

    def test_a_windows_drive_root_keeps_no_stray_separator(self, gate):
        assert gate._uri_base_to_path("file:///C:/ws/project-a/") == Path(
            "C:/ws/project-a/"
        )


class TestRunRootIsTheProjects:
    def test_a_run_declaring_a_siblings_root_is_a_violation(self, gate, tmp_path):
        for key in ("project-a", "project-b"):
            (tmp_path / key / "src").mkdir(parents=True)
            (tmp_path / key / "src" / "insecure.py").write_text(
                "x = 1\n", encoding="utf-8"
            )
        run = gate.RunEvidence(
            index=0,
            attributed_project="project-a",
            uri_base=(tmp_path / "project-b").as_uri() + "/",
            raw_uris=("src/insecure.py",),
            result_projects=("project-a",),
        )
        violations = gate.check_result_paths_resolve_against_their_run_root([run])
        assert any("not that project's directory" in v for v in violations)

    def test_a_run_declaring_its_own_root_is_clean(self, gate, tmp_path):
        (tmp_path / "project-a" / "src").mkdir(parents=True)
        (tmp_path / "project-a" / "src" / "insecure.py").write_text(
            "x = 1\n", encoding="utf-8"
        )
        run = gate.RunEvidence(
            index=0,
            attributed_project="project-a",
            uri_base=(tmp_path / "project-a").as_uri() + "/",
            raw_uris=("src/insecure.py",),
            result_projects=("project-a",),
        )
        assert gate.check_result_paths_resolve_against_their_run_root([run]) == []


class TestPathLossAccounting:
    def test_a_result_with_no_properties_at_all_is_counted(self, gate):
        results = {
            "workspace": {"unconvertible_finding_paths": 0},
            "sarif": {
                "runs": [
                    {
                        "properties": {"workspace_project": "project-a"},
                        "results": [
                            {
                                "ruleId": "B101",
                                "properties": {
                                    "workspace_project": "project-a",
                                    "workspace_uri": "project-a/src/marker.py",
                                },
                            },
                            {"ruleId": "B101"},
                        ],
                    }
                ]
            },
        }
        runs = gate.collect_runs(results)
        assert runs[0].result_count == 2
        violations = gate.check_no_finding_lost_its_workspace_path(results, runs)
        assert any("2 finding(s) are in the SARIF but only 1" in v for v in violations)


class TestChildEnvironment:
    def test_ash_variables_are_dropped(self, gate):
        env = gate.child_environment({"PATH": "/usr/bin", "ASH_SCANNERS": "bandit"})
        assert "ASH_SCANNERS" not in env
        assert env["PATH"] == "/usr/bin"
        assert env["PYTHONIOENCODING"] == "utf-8"


class _FakeProcess:
    """A child that has exited, or one that ignores SIGTERM and never exits."""

    def __init__(self, alive: bool):
        self.pid = 4242
        self.alive = alive
        self.killed = False

    def poll(self):
        return None if self.alive else 0

    def wait(self, timeout=None):
        if self.alive:
            raise subprocess.TimeoutExpired(cmd="ash", timeout=timeout)
        return 0

    def kill(self):
        self.killed = True
        self.alive = False


class _FakePipes:
    """A stopped child whose output pipes follow a script of results or timeouts."""

    def __init__(self, *outcomes):
        self.pid = 4242
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

    def __init__(self, *args, **kwargs):
        self.pid = 4242
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
class TestStopProcessGroup:
    @pytest.fixture
    def killed(self, monkeypatch):
        calls: list = []
        monkeypatch.setattr(
            os, "killpg", lambda pgid, signum: calls.append((pgid, signum))
        )
        return calls

    def test_an_exited_child_still_gets_the_group_signal(self, gate, killed):
        """A tool the child started can outlive it in the group and hold the pipes."""
        process = _FakeProcess(alive=False)
        gate._stop_process_group(process, grace_seconds=0.01)
        assert killed == [(process.pid, signal.SIGTERM)]
        assert not process.killed

    def test_a_child_that_ignores_sigterm_gets_a_group_kill_after_the_grace_period(
        self, gate, killed
    ):
        process = _FakeProcess(alive=True)
        gate._stop_process_group(process, grace_seconds=0.01)
        assert killed == [
            (process.pid, signal.SIGTERM),
            (process.pid, signal.SIGKILL),
        ]

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
            gate.run_scan(
                tmp_path, tmp_path / "ws.yaml", tmp_path / "out", timeout=0.01
            )
        assert raised.value.output == "tail"
