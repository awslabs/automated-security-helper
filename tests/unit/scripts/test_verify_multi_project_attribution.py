# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/verify_multi_project_attribution.py: the pure gate logic.

* exit 0 is refused when a project reports exceeds_threshold, and exit 2 when
  none does;
* every project's reported threshold must be the one its own config sets, not
  only the two of the threshold pair;
* both selected scanners must have run in the rollup, and have run and found
  something in every project's own results file, which the rollup's worst
  status and summed count cannot show;
* a run's declared root must be its own project's directory, not a sibling's
  with the same relative paths;
* a ``file://`` root is percent-decoded before it is resolved;
* the path-loss accounting counts every located result, properties or not, and
  leaves a result that offered no location out of its denominator;
* the scan child's environment carries no ASH_* variable, and no PYTHONSAFEPATH;
* a timed-out scan gets SIGTERM to its process group even when the child has
  already exited, and its output is read with a deadline and a final kill, so a
  tool that outlives the child cannot hang the gate;
* a non-object scanner_results is a shape violation, not a traceback;
* sarif_run_index is read by the run's own index, refuses a negative value and
  reads garbage as absent;
* exchanged attributions are not also reported as markers in no run;
* each location resolves against the base its own uriBaseId names, a dangling
  base is reported, and an absolute or climbing URI never resolves under a root;
* a project with no run is told so instead of being told to change the rule;
* shared output directories are compared as paths and must stay inside the
  output directory, and the rollup is compared per scanner;
* a payload with no exit_code is reported, the root's execution knobs are
  asserted, each selected scanner must have found something;
* an unreadable results file is a FAIL report, --timeout is validated, the
  cleanup hint is shell-quoted and a failed precondition leaves no directory.
"""

from __future__ import annotations

import argparse
import json
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

    def test_exit_zero_with_no_exceeding_project_is_clean(self, gate):
        """The passing case for exit 0. Without it an implementation that
        refuses every exit 0 once projects exist passes the whole class."""
        projects = [_project(gate, "project-a", actionable=0, exceeds=False)]
        assert gate.check_exit_code(0, projects) == []

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

    @pytest.mark.parametrize(
        "raw", ["SKIPPED", "skipped", "ScannerStatus.SKIPPED", " skipped "]
    )
    def test_every_spelling_of_a_skipped_status_is_read(self, gate, raw):
        """A change in how the enum serializes must not silence the check."""
        statuses = gate.collect_scanner_statuses(
            {
                "scanner_results": {
                    "bandit": {"status": "passed"},
                    "checkov": {"status": raw},
                }
            }
        )
        violations = gate.check_gate_scanners_ran(statuses)
        assert len(violations) == 1
        assert "checkov" in violations[0] and "SKIPPED" in violations[0]

    def test_a_passed_status_in_any_spelling_is_clean(self, gate):
        statuses = gate.collect_scanner_statuses(
            {
                "scanner_results": {
                    "bandit": {"status": "ScannerStatus.PASSED"},
                    "checkov": {"status": "passed"},
                }
            }
        )
        assert gate.check_gate_scanners_ran(statuses) == []

    def test_an_excluded_scanner_did_not_run_whatever_its_status_says(self, gate):
        """At the base only the status was read, so excluded + PASSED passed."""
        statuses = gate.collect_scanner_statuses(
            {
                "scanner_results": {
                    "bandit": {"status": "PASSED"},
                    "checkov": {"status": "PASSED", "excluded": True},
                }
            }
        )
        assert statuses["checkov"] == gate.STATUS_EXCLUDED
        violations = gate.check_gate_scanners_ran(statuses)
        assert len(violations) == 1
        assert "checkov" in violations[0] and "EXCLUDED" in violations[0]

    def test_an_entry_with_no_status_did_not_run(self, gate):
        """At the base a missing status normalized to '' and passed."""
        statuses = gate.collect_scanner_statuses(
            {"scanner_results": {"bandit": {"status": "PASSED"}, "checkov": {}}}
        )
        violations = gate.check_gate_scanners_ran(statuses)
        assert len(violations) == 1
        assert "checkov" in violations[0] and "no status" in violations[0]

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
    def test_percent_escapes_are_decoded(self, gate, tmp_path):
        root = tmp_path / "a b" / "café"
        uri_base = root.as_uri() + "/"
        assert "%20" in uri_base and "%C3%A9" in uri_base
        assert gate._uri_base_to_path(uri_base) == root

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
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/marker.py"}
                                        }
                                    }
                                ],
                            },
                            {
                                "ruleId": "B101",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/other.py"}
                                        }
                                    }
                                ],
                            },
                        ],
                    }
                ]
            },
        }
        runs = gate.collect_runs(results)
        assert runs[0].result_count == 2
        assert runs[0].results_without_location == 0
        violations = gate.check_no_finding_lost_its_workspace_path(results, runs)
        assert any(
            "2 located finding(s) are in the SARIF but only 1" in v for v in violations
        )

    def test_a_result_with_no_location_is_not_a_lost_path(self, gate):
        """At the base it was reported as a path lost silently, although the
        aggregator correctly neither paths nor counts it."""
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
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/marker.py"}
                                        }
                                    }
                                ],
                            },
                            {"ruleId": "B101"},
                        ],
                    }
                ]
            },
        }
        runs = gate.collect_runs(results)
        assert runs[0].results_without_location == 1
        assert gate.check_no_finding_lost_its_workspace_path(results, runs) == []


class TestChildEnvironment:
    def test_ash_variables_are_dropped(self, gate):
        env = gate.child_environment({"PATH": "/usr/bin", "ASH_SCANNERS": "bandit"})
        assert "ASH_SCANNERS" not in env
        assert env["PATH"] == "/usr/bin"
        assert env["PYTHONIOENCODING"] == "utf-8"

    def test_pythonsafepath_is_dropped(self, gate):
        env = gate.child_environment({"PATH": "/usr/bin", "PYTHONSAFEPATH": "1"})
        assert "PYTHONSAFEPATH" not in env


#: Above any pid_max, so a signal that escapes the killpg patch (a refactor to
#: ``from os import killpg``, or a bare os.kill) meets ESRCH instead of a live
#: process on the runner.
FAKE_PID = 2**30


class _FakeProcess:
    """A child that has exited, or one that ignores SIGTERM and never exits.

    Every ``wait`` deadline is recorded; the group signals are recorded by the
    ``killed`` fixture.
    """

    def __init__(self, alive: bool):
        self.pid = FAKE_PID
        self.alive = alive
        self.waits: list = []
        self.killed = False

    def poll(self):
        return None if self.alive else 0

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.alive:
            raise subprocess.TimeoutExpired(cmd="ash", timeout=timeout)
        return 0

    def kill(self):
        self.killed = True
        self.alive = False


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
class TestStopProcessGroup:
    @pytest.fixture
    def killed(self, monkeypatch):
        calls: list = []
        monkeypatch.setattr(
            os, "killpg", lambda pgid, signum: calls.append((pgid, signum))
        )
        return calls

    def test_an_exited_child_still_gets_the_group_signals(self, gate, killed):
        """A tool the child started can outlive it in the group and hold the pipes.

        The group is swept with SIGKILL after the child exits too: before the
        sweep a tool that trapped SIGTERM was never killed and kept writing into
        the evidence directory the gate had just reported.
        """
        process = _FakeProcess(alive=False)
        gate._stop_process_group(process, grace_seconds=0.01)
        assert killed == [
            (process.pid, signal.SIGTERM),
            (process.pid, signal.SIGKILL),
        ]
        assert process.waits == [0.01], "one wait, for the grace period"
        assert not process.killed, "the group kill, never a bare process.kill"

    def test_a_child_that_ignores_sigterm_gets_a_group_kill_after_the_grace_period(
        self, gate, killed
    ):
        process = _FakeProcess(alive=True)
        gate._stop_process_group(process, grace_seconds=0.01)
        assert killed == [
            (process.pid, signal.SIGTERM),
            (process.pid, signal.SIGKILL),
        ]
        # The grace period is waited before the kill and again after it.
        assert process.waits == [0.01, 0.01]

    def test_an_empty_group_is_not_an_error(self, gate, monkeypatch):
        """The real killpg raises ProcessLookupError once nothing is left."""

        def no_such_group(pgid, signum):
            raise ProcessLookupError(pgid)

        monkeypatch.setattr(os, "killpg", no_such_group)
        process = _FakeProcess(alive=False)
        gate._stop_process_group(process, grace_seconds=0.01)
        assert process.waits == [0.01]

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
            gate.run_scan(
                tmp_path, tmp_path / "ws.yaml", tmp_path / "out", timeout=0.01
            )
        assert len(stopped) == 1
        assert isinstance(stopped[0], _Interrupted)
        assert killed == [], "the stop was routed through _stop_process_group"

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
        # The stop (SIGTERM, then the sweep) and the drain's own kill all reach
        # the group; a run_scan that skipped the stop would still raise.
        assert killed == [
            (_FakeScanChild.pid, signal.SIGTERM),
            (_FakeScanChild.pid, signal.SIGKILL),
            (_FakeScanChild.pid, signal.SIGKILL),
        ]


def _run(gate, index, project, rules=None, **fields):
    return gate.RunEvidence(
        index=index,
        attributed_project=project,
        uri_base=None,
        rules=rules or {},
        result_projects=(project,) if project else (),
        **fields,
    )


class TestIntegerReads:
    def test_an_infinite_value_is_zero_or_absent(self, gate):
        """At the base int(float('inf')) raised OverflowError past the except."""
        assert gate._as_int(float("inf")) == 0
        assert gate._as_optional_int(float("inf")) is None

    def test_optional_int_reads_garbage_as_absent(self, gate):
        assert gate._as_optional_int(None) is None
        assert gate._as_optional_int("garbage") is None
        assert gate._as_optional_int(True) is None
        assert gate._as_optional_int(2.5) is None
        assert gate._as_optional_int(3.0) == 3
        assert gate._as_optional_int(-1) == -1


class TestResultsShape:
    def test_a_non_object_scanner_results_is_a_violation(self, gate, tmp_path):
        """At the base the list reached .items() and the gate ended in a traceback."""
        results = {
            "workspace": {"projects": [{"project": "project-a"}]},
            "sarif": {"runs": []},
            "scanner_results": ["bandit"],
        }
        violations = gate.check_results_shape(results)
        assert any("'scanner_results' is a list" in v for v in violations)
        outcome = gate.evaluate_results(results, tmp_path)
        assert not outcome.passed


class TestSarifRunIndex:
    def test_garbage_reads_as_absent(self, gate):
        """At the base 'garbage' coerced to 0 and selected the first run."""
        projects = gate.parse_projects(
            {"workspace": {"projects": [{"project": "a", "sarif_run_index": "x"}]}}
        )
        assert projects[0].sarif_run_index is None

    def test_a_negative_index_is_refused(self, gate):
        """At the base -1 passed the upper bound and selected the last run."""
        project = _project(gate, "project-a")
        project = gate.ProjectOutcome(**{**project.__dict__, "sarif_run_index": -1})
        runs = [_run(gate, 0, "project-a")]
        violations = gate.check_one_run_per_project([project], runs)
        assert any("not an index into the runs" in v for v in violations)

    def test_the_index_is_the_runs_own_not_its_position(self, gate):
        """At the base a skipped non-object run shifted every position."""
        results = {
            "workspace": {
                "projects": [
                    {
                        "project": "project-a",
                        "relative_path": "project-a",
                        "status": "completed",
                        "sarif_run_index": 1,
                        "finding_count": 1,
                    }
                ]
            },
            "sarif": {
                "runs": [
                    "not a run object",
                    {
                        "properties": {"workspace_project": "project-a"},
                        "originalUriBaseIds": {"ROOT": {"uri": "file:///ws/a/"}},
                        "results": [],
                    },
                ]
            },
        }
        projects = gate.parse_projects(results)
        runs = gate.collect_runs(results)
        assert runs[0].index == 1
        violations = gate.check_one_run_per_project(projects, runs)
        assert not [v for v in violations if "sarif_run_index" in v]

    def test_the_root_is_the_projectroot_entry_whatever_its_position(self, gate):
        """Red at the base: the FIRST base entry was taken as the run's root.

        The rebase keeps a scanner's own declared bases in the table and adds
        PROJECTROOT after them, so a run whose scanner declared ``%SRCROOT%`` led
        with ``file:///`` and every root check tested the wrong root.
        """
        results = {
            "workspace": {"projects": []},
            "sarif": {
                "runs": [
                    {
                        "properties": {"workspace_project": "project-a"},
                        "originalUriBaseIds": {
                            "%SRCROOT%": {"uri": "file:///"},
                            "PROJECTROOT": {"uri": "file:///ws/a/"},
                        },
                        "results": [],
                    }
                ]
            },
        }
        runs = gate.collect_runs(results)
        assert runs[0].uri_base == "file:///ws/a/"
        assert runs[0].uri_bases == {
            "%SRCROOT%": "file:///",
            "PROJECTROOT": "file:///ws/a/",
        }

    def test_a_run_without_a_projectroot_entry_falls_back_to_its_first_base(self, gate):
        """Control: the fallback for a run that declares no PROJECTROOT."""
        results = {
            "workspace": {"projects": []},
            "sarif": {
                "runs": [
                    {
                        "properties": {"workspace_project": "project-a"},
                        "originalUriBaseIds": {"ROOT": {"uri": "file:///ws/a/"}},
                        "results": [],
                    }
                ]
            },
        }
        runs = gate.collect_runs(results)
        assert runs[0].uri_base == "file:///ws/a/"

    def test_two_runs_without_a_project_are_not_the_same_project(self, gate):
        """At the base the message read 'claim the same project: [None, None]'."""
        runs = [_run(gate, 0, None), _run(gate, 1, None)]
        violations = gate.check_one_run_per_project([], runs)
        assert not any("claim the same project" in v for v in violations)
        assert sum("no properties.workspace_project" in v for v in violations) == 2


class TestExchangedAttributions:
    def test_a_marker_in_the_wrong_run_is_not_also_in_no_run(self, gate):
        """At the base the exchanged pair was also reported as 'appear in no run at
        all' with advice to edit MARKER_SOURCES."""
        a_marker = gate.MARKER_RULE_BY_PROJECT["project-a"]
        b_marker = gate.MARKER_RULE_BY_PROJECT["project-b"]
        runs = [
            _run(gate, 0, "project-a", {b_marker: (1, 0)}),
            _run(gate, 1, "project-b", {a_marker: (1, 0)}),
        ]
        violations = gate.check_each_project_shows_only_its_own_marker_rule(runs)
        assert any("belonging to" in v for v in violations)
        assert not any(
            "appear in no run at all" in v and a_marker in v for v in violations
        )

    def test_a_marker_absent_everywhere_is_still_reported(self, gate):
        runs = [_run(gate, 0, "project-a", {"B307": (1, 0)})]
        violations = gate.check_each_project_shows_only_its_own_marker_rule(runs)
        assert any("appear in no run at all" in v for v in violations)


class TestRunRootPerLocation:
    @pytest.fixture
    def workspace(self, tmp_path):
        for key in ("project-a", "project-b"):
            (tmp_path / key / "src").mkdir(parents=True)
        (tmp_path / "project-a" / "src" / "insecure.py").write_text(
            "x = 1\n", encoding="utf-8"
        )
        (tmp_path / "project-b" / "src" / "insecure.py").write_text(
            "y = 2\n", encoding="utf-8"
        )
        return tmp_path

    def test_a_location_resolves_against_its_own_base(self, gate, workspace):
        """At the base every location resolved against the run's first base."""
        root_a = (workspace / "project-a").as_uri() + "/"
        root_other = (workspace / "project-a" / "src").as_uri() + "/"
        run = gate.RunEvidence(
            index=0,
            attributed_project="project-a",
            uri_base=root_a,
            uri_bases={"PROJECTROOT": root_a, "SRCROOT": root_other},
            raw_uris=("src/insecure.py",),
            raw_uri_bases=("SRCROOT",),
            result_projects=("project-a",),
        )
        violations = gate.check_result_paths_resolve_against_their_run_root([run])
        assert any("do not resolve to a file under" in v for v in violations)

    def test_a_dangling_base_id_is_reported(self, gate, workspace):
        root_a = (workspace / "project-a").as_uri() + "/"
        run = gate.RunEvidence(
            index=0,
            attributed_project="project-a",
            uri_base=root_a,
            uri_bases={"PROJECTROOT": root_a},
            raw_uris=("src/insecure.py",),
            raw_uri_bases=("MISSING",),
            result_projects=("project-a",),
        )
        violations = gate.check_result_paths_resolve_against_their_run_root([run])
        assert any("does not declare" in v and "MISSING" in v for v in violations)

    @pytest.mark.parametrize("shape", ["climbing", "absolute"])
    def test_a_uri_that_leaves_the_root_does_not_resolve(self, gate, workspace, shape):
        """At the base an existing file anywhere satisfied the join-and-exists test."""
        root_a = (workspace / "project-a").as_uri() + "/"
        outside = workspace / "project-b" / "src" / "insecure.py"
        uri = "../project-b/src/insecure.py" if shape == "climbing" else str(outside)
        run = gate.RunEvidence(
            index=0,
            attributed_project="project-a",
            uri_base=root_a,
            uri_bases={"PROJECTROOT": root_a},
            raw_uris=(uri,),
            result_projects=("project-a",),
        )
        violations = gate.check_result_paths_resolve_against_their_run_root([run])
        assert any("do not resolve to a file under" in v for v in violations)

    def test_a_relative_uri_under_the_root_is_clean(self, gate, workspace):
        root_a = (workspace / "project-a").as_uri() + "/"
        run = gate.RunEvidence(
            index=0,
            attributed_project="project-a",
            uri_base=root_a,
            uri_bases={"PROJECTROOT": root_a},
            raw_uris=("src/insecure.py",),
            raw_uri_bases=("PROJECTROOT",),
            result_projects=("project-a",),
        )
        assert gate.check_result_paths_resolve_against_their_run_root([run]) == []


class TestSuppressionWithoutARun:
    def test_a_project_with_no_run_is_told_so(self, gate):
        """At the base it read 'rule B324 does not appear ... Update SUPPRESSED_RULE_ID'."""
        runs = [_run(gate, 0, "project-a", {gate.SUPPRESSED_RULE_ID: (0, 1)})]
        violations = gate.check_suppression_is_project_scoped(runs)
        assert any("no SARIF run is attributed to 'project-b'" in v for v in violations)
        assert not any(
            "'project-b'" in v and "Update SUPPRESSED_RULE_ID" in v for v in violations
        )


class TestOutputSubtrees:
    def test_two_spellings_of_one_directory_are_shared(self, gate, tmp_path):
        """At the base the raw strings 'a/b' and 'a//b' read as two directories."""
        projects = [
            gate.ProjectOutcome(
                **{**_project(gate, "project-a").__dict__, "output_path": "a/b"}
            ),
            gate.ProjectOutcome(
                **{**_project(gate, "project-b").__dict__, "output_path": "a//b/"}
            ),
        ]
        violations = gate.check_per_project_subtrees(projects, tmp_path)
        assert any("share the output path" in v for v in violations)

    def test_an_output_path_outside_the_output_dir_is_a_violation(self, gate, tmp_path):
        project = gate.ProjectOutcome(
            **{**_project(gate, "project-a").__dict__, "output_path": "../outside"}
        )
        violations = gate.check_per_project_subtrees([project], tmp_path / "out")
        assert any("does not stay inside" in v for v in violations)


class TestRollupPerScanner:
    def _write(self, path: Path, counts: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "scanner_results": {
                name: {"status": "PASSED", "finding_count": count}
                for name, count in counts.items()
            }
        }
        path.write_text(json.dumps(payload), encoding="utf-8")

    def test_one_scanners_count_leaking_into_anothers_is_reported(self, gate, tmp_path):
        """At the base only the cross-scanner totals were compared, which agree here."""
        self._write(tmp_path / gate.RESULTS_FILENAME, {"bandit": 6, "checkov": 6})
        self._write(tmp_path / "a" / gate.RESULTS_FILENAME, {"bandit": 2, "checkov": 4})
        self._write(tmp_path / "b" / gate.RESULTS_FILENAME, {"bandit": 3, "checkov": 3})
        projects = [
            gate.ProjectOutcome(
                **{**_project(gate, "project-a").__dict__, "output_path": "a"}
            ),
            gate.ProjectOutcome(
                **{**_project(gate, "project-b").__dict__, "output_path": "b"}
            ),
        ]
        violations = gate.check_scanner_rollup_per_scanner(projects, tmp_path)
        assert len(violations) == 2
        assert any(
            "'bandit'" in v and "is 6" in v and "sum to 5" in v for v in violations
        )
        assert any(
            "'checkov'" in v and "is 6" in v and "sum to 7" in v for v in violations
        )

    def test_agreeing_counts_are_clean(self, gate, tmp_path):
        self._write(tmp_path / gate.RESULTS_FILENAME, {"bandit": 5, "checkov": 7})
        self._write(tmp_path / "a" / gate.RESULTS_FILENAME, {"bandit": 2, "checkov": 4})
        self._write(tmp_path / "b" / gate.RESULTS_FILENAME, {"bandit": 3, "checkov": 3})
        projects = [
            gate.ProjectOutcome(
                **{**_project(gate, "project-a").__dict__, "output_path": "a"}
            ),
            gate.ProjectOutcome(
                **{**_project(gate, "project-b").__dict__, "output_path": "b"}
            ),
        ]
        assert gate.check_scanner_rollup_per_scanner(projects, tmp_path) == []


def _write_own_results(path: Path, scanner_results) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"scanner_results": scanner_results}), encoding="utf-8")


def _ran(count=3):
    return {"status": "FAILED", "finding_count": count}


class TestGateScannersRanInEveryProject:
    """At the base only the rollup was read, whose status is the worst across the
    projects and whose count is their sum, so one project in which a selected
    scanner did not run hid behind the others."""

    def _projects(self, gate):
        return [
            gate.ProjectOutcome(
                **{**_project(gate, "project-a").__dict__, "output_path": "a"}
            ),
            gate.ProjectOutcome(
                **{**_project(gate, "project-b").__dict__, "output_path": "b"}
            ),
        ]

    def test_both_scanners_run_and_tripped_in_every_project_is_clean(
        self, gate, tmp_path
    ):
        for key in ("a", "b"):
            _write_own_results(
                tmp_path / key / gate.RESULTS_FILENAME,
                {"bandit": _ran(), "checkov": _ran(1)},
            )
        assert (
            gate.check_gate_scanners_ran_in_every_project(
                self._projects(gate), tmp_path
            )
            == []
        )

    def test_a_scanner_spelled_differently_in_a_projects_file_is_the_same_scanner(
        self, gate, tmp_path
    ):
        """The aggregator joins 'Bandit' and 'bandit' into one row; so does this."""
        for key in ("a", "b"):
            _write_own_results(
                tmp_path / key / gate.RESULTS_FILENAME,
                {"Bandit": _ran(), " checkov ": _ran(1)},
            )
        assert (
            gate.check_gate_scanners_ran_in_every_project(
                self._projects(gate), tmp_path
            )
            == []
        )

    @pytest.mark.parametrize("status", ["MISSING", "SKIPPED", "skipped", ""])
    def test_a_scanner_that_did_not_run_in_one_project_is_named(
        self, gate, tmp_path, status
    ):
        _write_own_results(
            tmp_path / "a" / gate.RESULTS_FILENAME,
            {"bandit": _ran(), "checkov": _ran(1)},
        )
        _write_own_results(
            tmp_path / "b" / gate.RESULTS_FILENAME,
            {"bandit": _ran(), "checkov": {"status": status, "finding_count": 0}},
        )
        violations = gate.check_gate_scanners_ran_in_every_project(
            self._projects(gate), tmp_path
        )
        assert len(violations) == 1
        assert "'project-b'" in violations[0] and "'checkov'" in violations[0]
        assert (status.upper() or "no status") in violations[0]

    def test_an_excluded_scanner_did_not_run_whatever_its_status_says(
        self, gate, tmp_path
    ):
        _write_own_results(
            tmp_path / "a" / gate.RESULTS_FILENAME,
            {"bandit": _ran(), "checkov": {**_ran(1), "excluded": True}},
        )
        _write_own_results(
            tmp_path / "b" / gate.RESULTS_FILENAME,
            {"bandit": _ran(), "checkov": _ran(1)},
        )
        violations = gate.check_gate_scanners_ran_in_every_project(
            self._projects(gate), tmp_path
        )
        assert len(violations) == 1
        assert "'project-a'" in violations[0] and "EXCLUDED" in violations[0]

    def test_a_scanner_absent_from_one_projects_file_is_named(self, gate, tmp_path):
        _write_own_results(tmp_path / "a" / gate.RESULTS_FILENAME, {"bandit": _ran()})
        _write_own_results(
            tmp_path / "b" / gate.RESULTS_FILENAME,
            {"bandit": _ran(), "checkov": _ran(1)},
        )
        violations = gate.check_gate_scanners_ran_in_every_project(
            self._projects(gate), tmp_path
        )
        assert len(violations) == 1
        assert "'project-a'" in violations[0]
        assert "no scanner_results entry for 'checkov'" in violations[0]
        assert "present: ['bandit']" in violations[0]

    def test_a_scanner_that_ran_and_found_nothing_in_one_project_is_named(
        self, gate, tmp_path
    ):
        """The rollup sum is non-zero here; only the project's own file shows it."""
        _write_own_results(
            tmp_path / "a" / gate.RESULTS_FILENAME,
            {"bandit": _ran(), "checkov": {"status": "PASSED", "finding_count": 0}},
        )
        _write_own_results(
            tmp_path / "b" / gate.RESULTS_FILENAME,
            {"bandit": _ran(), "checkov": _ran(5)},
        )
        violations = gate.check_gate_scanners_ran_in_every_project(
            self._projects(gate), tmp_path
        )
        assert len(violations) == 1
        assert "'project-a'" in violations[0] and "'checkov'" in violations[0]
        assert "status PASSED and 0 finding(s)" in violations[0]

    def test_an_error_is_left_to_the_rollup_check(self, gate, tmp_path):
        """ERROR outranks every other status, so the rollup shows it."""
        _write_own_results(
            tmp_path / "a" / gate.RESULTS_FILENAME,
            {"bandit": {"status": "ERROR", "finding_count": 0}, "checkov": _ran(1)},
        )
        _write_own_results(
            tmp_path / "b" / gate.RESULTS_FILENAME,
            {"bandit": _ran(), "checkov": _ran(1)},
        )
        assert (
            gate.check_gate_scanners_ran_in_every_project(
                self._projects(gate), tmp_path
            )
            == []
        )

    def test_a_project_without_its_own_file_is_left_to_the_subtree_check(
        self, gate, tmp_path
    ):
        _write_own_results(
            tmp_path / "a" / gate.RESULTS_FILENAME,
            {"bandit": _ran(), "checkov": _ran(1)},
        )
        assert (
            gate.check_gate_scanners_ran_in_every_project(
                self._projects(gate), tmp_path
            )
            == []
        )

    def test_an_incomplete_project_is_not_read(self, gate, tmp_path):
        _write_own_results(tmp_path / "a" / gate.RESULTS_FILENAME, {})
        project = gate.ProjectOutcome(
            **{
                **_project(gate, "project-a", status="failed").__dict__,
                "output_path": "a",
            }
        )
        assert gate.check_gate_scanners_ran_in_every_project([project], tmp_path) == []


class TestWorkspaceStatus:
    def test_a_missing_exit_code_is_reported(self, gate):
        """At the base it read as 0 and agreed with a process that exited 0."""
        violations = gate.check_workspace_status(
            {"workspace": {"status": "completed"}}, 0
        )
        assert len(violations) == 1
        assert "absent or not an integer" in violations[0]


class TestExecutionKnobs:
    def test_the_roots_values_in_the_payload_are_clean(self, gate):
        results = {
            "workspace": {
                "max_parallel_projects": gate.ROOT_MAX_PARALLEL_PROJECTS,
                "project_timeout": float(gate.ROOT_PROJECT_TIMEOUT_SECONDS),
            }
        }
        assert gate.check_execution_knobs_reached_the_run(results) == []

    def test_knobs_that_did_not_reach_the_run_are_reported(self, gate):
        """At the base the root config was written and never asserted."""
        violations = gate.check_execution_knobs_reached_the_run(
            {"workspace": {"max_parallel_projects": 1, "project_timeout": None}}
        )
        assert len(violations) == 2
        assert all("did not reach the run" in v for v in violations)

    def test_the_root_config_names_the_asserted_values(self, gate):
        assert f"max_parallel_projects: {gate.ROOT_MAX_PARALLEL_PROJECTS}" in (
            gate.WORKSPACE_ROOT_CONFIG
        )
        assert f"project_timeout: {gate.ROOT_PROJECT_TIMEOUT_SECONDS}" in (
            gate.WORKSPACE_ROOT_CONFIG
        )


class TestGateScannersFoundSomething:
    def test_a_selected_scanner_with_zero_findings_is_a_violation(self, gate):
        """At the base nothing asserted that checkov produced a finding."""
        results = {
            "scanner_results": {
                "bandit": {"status": "PASSED", "finding_count": 9},
                "checkov": {"status": "PASSED", "finding_count": 0},
            }
        }
        violations = gate.check_gate_scanners_found_something(results)
        assert len(violations) == 1 and "checkov" in violations[0]

    def test_a_missing_scanner_is_left_to_the_other_check(self, gate):
        results = {
            "scanner_results": {
                "bandit": {"status": "PASSED", "finding_count": 9},
                "checkov": {"status": "MISSING", "finding_count": 0},
            }
        }
        assert gate.check_gate_scanners_found_something(results) == []


class TestLoadResults:
    def test_invalid_utf8_is_reported_not_raised_raw(self, gate, tmp_path):
        """At the base UnicodeDecodeError escaped main as a traceback."""
        (tmp_path / gate.RESULTS_FILENAME).write_bytes(b"\xff\xfe{}")
        with pytest.raises(gate.ResultsUnreadable, match="not valid UTF-8"):
            gate.load_results(tmp_path)


class TestScanTimeout:
    @pytest.mark.parametrize("text", ["nan", "inf", "0", "-5", "1800", "2000", "x"])
    def test_an_unusable_timeout_is_refused(self, gate, text):
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
        """At the base the mkdtemp directory stayed and paths never created were named."""
        made = tmp_path / "ash-multi-project-x"
        made.mkdir()
        monkeypatch.setattr(gate.tempfile, "mkdtemp", lambda prefix: str(made))
        monkeypatch.setattr(
            gate, "check_paths_outside_repo", lambda *paths: ["inside the repository"]
        )

        def never(*args, **kwargs):  # pragma: no cover - the gate must not get here
            raise AssertionError("the scan ran after a failed precondition")

        monkeypatch.setattr(gate, "run_scan", never)
        assert gate.main([]) == 1
        assert not made.exists()
        assert "EVIDENCE KEPT" not in capsys.readouterr().out
