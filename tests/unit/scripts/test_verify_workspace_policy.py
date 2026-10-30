# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/verify_workspace_policy.py: the fixture and the child-run wrapper.

The script is its own gate; these tests pin the parts of it that a real scan
cannot show going wrong without a scanner on the host:

* the ceiling run suppresses a file the lax project's actionable count does not
  depend on, so a correct implementation of workspace suppressions cannot make
  the ceiling assertions fail;
* the scan child runs under a scrubbed environment, with a timeout, decoded as
  UTF-8;
* a failed positive control ends the run as a broken fixture, exit 3, before any
  policy result is printed;
* the recorded policy path is compared to the expected one as a file, not as
  text, so a temporary directory behind a symlink is not a failure.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def policy_script(script_loader):
    return script_loader("verify_workspace_policy")


class TestFixtureShape:
    def test_lax_has_a_second_source_file_carrying_the_same_finding(
        self, policy_script, tmp_path: Path
    ):
        policy_script.build_fixture(tmp_path)
        lax_sources = sorted(p.name for p in (tmp_path / "lax" / "src").iterdir())
        assert lax_sources == sorted(["runner.py", policy_script.LAX_SUPPRESSED_FILE])
        suppressed = tmp_path / "lax" / "src" / policy_script.LAX_SUPPRESSED_FILE
        assert suppressed.read_text(encoding="utf-8") == policy_script.LAX_SOURCE

    def test_the_suppressed_path_is_not_the_lax_projects_only_source(
        self, policy_script, tmp_path: Path
    ):
        """The ceiling assertions read runner.py; the policy must not suppress it."""
        policy_script.build_fixture(tmp_path)
        suppressed = tmp_path / policy_script.LAX_SUPPRESSED_WORKSPACE_PATH
        assert suppressed.is_file()
        assert suppressed.name != "runner.py"
        remaining = [p for p in (tmp_path / "lax" / "src").iterdir() if p != suppressed]
        assert remaining, "suppressing the file would leave lax with no finding"
        assert policy_script.LAX_SUPPRESSED_PROJECT_PATH == (
            "src/" + policy_script.LAX_SUPPRESSED_FILE
        )


class TestChildEnvironment:
    def test_ash_variables_are_dropped(self, policy_script):
        base = {
            "PATH": "/usr/bin",
            "ASH_CONFIG": "/elsewhere/ash.yaml",
            "ASH_EXCLUDED_SCANNERS": "bandit",
            "ASH_WORKSPACE_CONFIG": "/elsewhere/policy.yaml",
            "ASHY": "kept: not an ASH_ option",
        }
        env = policy_script.child_environment(base)
        assert not [key for key in env if key.startswith("ASH_")]
        assert env["PATH"] == "/usr/bin"
        assert env["ASHY"] == "kept: not an ASH_ option"
        assert env["PYTHONIOENCODING"] == "utf-8"
        assert env["PYTHONUTF8"] == "1"
        assert (
            Path(env["PYTHONPATH"]) == Path(policy_script.__file__).resolve().parents[1]
        )

    def test_run_ash_scrubs_the_environment_decodes_utf8_and_times_out(
        self, policy_script, tmp_path: Path, monkeypatch
    ):
        recorded: dict = {}

        def fake_run(argv, **kwargs):
            recorded["argv"] = argv
            recorded.update(kwargs)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setenv("ASH_EXCLUDED_SCANNERS", "bandit")
        monkeypatch.setattr(policy_script.subprocess, "run", fake_run)
        code, payload, output = policy_script.run_ash(
            tmp_path / "ws.code-workspace", tmp_path / "out", timeout=17.5
        )
        assert (code, payload, output) == (0, {}, "")
        assert "ASH_EXCLUDED_SCANNERS" not in recorded["env"]
        assert recorded["encoding"] == "utf-8"
        assert recorded["errors"] == "replace"
        assert recorded["timeout"] == 17.5
        assert "text" not in recorded


class TestInheritedPythonPath:
    def test_an_inherited_pythonpath_is_kept_behind_the_working_tree(
        self, policy_script
    ):
        """At the base PYTHONPATH was assigned, dropping the host's entries."""
        env = policy_script.child_environment({"PYTHONPATH": "/deps/site"})
        entries = env["PYTHONPATH"].split(os.pathsep)
        assert Path(entries[0]) == Path(policy_script.__file__).resolve().parents[1]
        assert entries[1:] == ["/deps/site"]


class TestResultsFile:
    def test_a_truncated_results_file_is_reported_not_raised(
        self, policy_script, tmp_path: Path
    ):
        """At the base json.loads raised out of run_ash on a truncated file."""
        results = tmp_path / "ash_aggregated_results.json"
        results.write_text('{"workspace": {"projects": [', encoding="utf-8")
        payload, note = policy_script.read_workspace_payload(results)
        assert payload == {}
        assert "ash_aggregated_results.json is not readable JSON" in note

    def test_a_missing_results_file_is_an_empty_payload(
        self, policy_script, tmp_path: Path
    ):
        assert policy_script.read_workspace_payload(tmp_path / "none.json") == ({}, "")


def _healthy_runs():
    projects_a = {
        "lax": {
            "finding_count": 2,
            "actionable_finding_count": 0,
            "exceeds_threshold": False,
            "severity_threshold": "CRITICAL",
        },
        "strict": {
            "finding_count": 1,
            "actionable_finding_count": 1,
            "severity_threshold": "LOW",
        },
        "iac": {"finding_count": 3, "actionable_finding_count": 3},
    }
    projects_b = {
        "lax": {
            "finding_count": 1,
            "actionable_finding_count": 1,
            "exceeds_threshold": True,
            "severity_threshold": "MEDIUM",
        },
        "strict": {
            "finding_count": 1,
            "actionable_finding_count": 1,
            "severity_threshold": "LOW",
        },
        "iac": {
            "finding_count": 3,
            "actionable_finding_count": 3,
            "ceiling_unreachable_findings": {"checkov": 3},
        },
    }
    return projects_a, projects_b


def _failed(checks):
    return [label for label, ok, _ in checks if not ok]


class TestEvaluateRuns:
    def test_healthy_runs_pass_every_check(self, policy_script):
        projects_a, projects_b = _healthy_runs()
        checks, notes = policy_script.evaluate_runs(projects_a, projects_b, 2, 2)
        assert _failed(checks) == []
        assert notes == []

    def test_a_missing_actionable_count_on_both_sides_is_not_a_pass(
        self, policy_script
    ):
        """At the base None == None satisfied the 'same actionable count' check."""
        projects_a, projects_b = _healthy_runs()
        del projects_a["strict"]["actionable_finding_count"]
        del projects_b["strict"]["actionable_finding_count"]
        checks, _ = policy_script.evaluate_runs(projects_a, projects_b, 2, 2)
        assert "stricter project untouched: same actionable count both runs" in (
            _failed(checks)
        )

    def test_a_crashed_run_fails_even_with_a_payload(self, policy_script):
        """At the base the exit codes of runs A and B were printed, never asserted."""
        projects_a, projects_b = _healthy_runs()
        checks, _ = policy_script.evaluate_runs(projects_a, projects_b, 2, 1)
        assert "ceiling run completed (exit 0 or 2, not a crash)" in _failed(checks)

    def test_the_lax_disclosure_check_runs_when_checkov_found_nothing(
        self, policy_script
    ):
        """At the base every disclosure check sat in the checkov branch."""
        projects_a, projects_b = _healthy_runs()
        projects_a["iac"]["finding_count"] = 0
        projects_b["lax"]["ceiling_unreachable_findings"] = {"bandit": 1}
        checks, notes = policy_script.evaluate_runs(projects_a, projects_b, 2, 2)
        assert "the project the ceiling DID reach discloses nothing" in _failed(checks)
        assert any("skipping the checkov disclosure checks" in n for n in notes)

    def test_an_absent_iac_project_is_a_failed_check_not_a_skip(self, policy_script):
        """At the base an absent iac project read as finding_count 0 and was skipped."""
        projects_a, projects_b = _healthy_runs()
        del projects_a["iac"]
        del projects_b["iac"]
        checks, notes = policy_script.evaluate_runs(projects_a, projects_b, 2, 2)
        assert "the iac project is in both runs' payloads" in _failed(checks)
        assert notes == []


class _Project:
    def __init__(self, paths):
        self.policy_suppressions = [type("S", (), {"path": p})() for p in paths]


class TestPlanChecks:
    def test_a_dropped_project_is_a_failed_check_not_a_key_error(
        self, policy_script, tmp_path: Path
    ):
        policy = tmp_path / "policy.yaml"
        policy.write_text("workspace: {}\n", encoding="utf-8")
        by_key = {"lax": _Project(["src/legacy.py"])}
        checks = policy_script.plan_checks(by_key, str(policy), policy)
        assert "the resolved plan names both fixture projects" in _failed(checks)

    def test_a_complete_plan_passes(self, policy_script, tmp_path: Path):
        policy = tmp_path / "policy.yaml"
        policy.write_text("workspace: {}\n", encoding="utf-8")
        by_key = {
            "lax": _Project([policy_script.LAX_SUPPRESSED_PROJECT_PATH]),
            "strict": _Project([]),
        }
        checks = policy_script.plan_checks(by_key, str(policy), policy)
        assert _failed(checks) == []


class TestSameFile:
    def test_a_symlinked_parent_still_names_the_same_file(
        self, policy_script, tmp_path: Path
    ):
        real = tmp_path / "real"
        real.mkdir()
        policy = real / "policy.yaml"
        policy.write_text("workspace: {}\n", encoding="utf-8")
        link = tmp_path / "link"
        try:
            os.symlink(real, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are not available here")
        recorded = (link / "policy.yaml").as_posix()
        assert recorded != policy.resolve().as_posix()
        assert policy_script.same_file(recorded, policy)

    def test_a_different_file_is_not_the_same(self, policy_script, tmp_path: Path):
        (tmp_path / "a.yaml").write_text("", encoding="utf-8")
        (tmp_path / "b.yaml").write_text("", encoding="utf-8")
        assert not policy_script.same_file(
            (tmp_path / "a.yaml").as_posix(), tmp_path / "b.yaml"
        )
        assert not policy_script.same_file(None, tmp_path / "b.yaml")


def _payload(**projects):
    return {
        "projects": [dict(project=name, **fields) for name, fields in projects.items()]
    }


@pytest.fixture
def scratch_under_tmp(policy_script, tmp_path: Path, monkeypatch):
    """main() makes its scratch directory under tmp_path, not the system tmp."""

    def mkdtemp(prefix: str = "") -> str:
        scratch = tmp_path / f"{prefix}scratch"
        scratch.mkdir()
        return str(scratch)

    monkeypatch.setattr(policy_script.tempfile, "mkdtemp", mkdtemp)
    return tmp_path


class TestFailedControlStopsTheRun:
    def test_a_lax_project_with_no_findings_is_a_broken_fixture(
        self, policy_script, scratch_under_tmp, monkeypatch, capsys
    ):
        calls: list[Path] = []

        def fake_run_ash(workspace, output_dir, policy=None, timeout=None):
            calls.append(output_dir)
            return (
                0,
                _payload(
                    lax={"finding_count": 0, "actionable_finding_count": 0},
                    strict={"finding_count": 1, "actionable_finding_count": 1},
                    iac={"finding_count": 1, "actionable_finding_count": 1},
                ),
                "",
            )

        monkeypatch.setattr(policy_script, "run_ash", fake_run_ash)
        assert policy_script.main([]) == 3
        out = capsys.readouterr().out
        assert "FIXTURE BROKEN" in out
        assert "ceiling tightens" not in out
        assert [p.name for p in calls] == ["out-a"]

    def test_a_timed_out_scan_is_reported_not_hung(
        self, policy_script, scratch_under_tmp, monkeypatch, capsys
    ):
        def fake_run_ash(workspace, output_dir, policy=None, timeout=None):
            raise subprocess.TimeoutExpired(
                cmd=["ash"], timeout=timeout, output=b"partial", stderr=None
            )

        monkeypatch.setattr(policy_script, "run_ash", fake_run_ash)
        assert policy_script.main(["--timeout", "5"]) == 3
        out = capsys.readouterr().out
        assert "did not finish within 5 seconds" in out
        assert "partial" in out
