# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the pure logic of the multi-project attribution gate.

Why a gate needs its own tests
------------------------------
The gate's failure mode is passing while inspecting nothing. Every check below is
therefore exercised twice: once on a results shape that must pass, and once on a
mutation that must fail. A check that cannot fail is not a check, and this
repository has already shipped one that could not.

The mutations are the four regressions the gate exists for -- a finding credited
to the wrong project, a suppression leaking across projects, one threshold applied
to all, and two projects sharing an output subtree -- plus the shape errors that
would make the rest vacuous.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "verify_multi_project_attribution.py"
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"


def _load_gate():
    """Import the gate by path; ``scripts/`` is not an importable package."""
    spec = importlib.util.spec_from_file_location(
        "verify_multi_project_attribution", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


# ---------------------------------------------------------------------------
# A healthy results file, shaped as a real workspace scan produces one
# ---------------------------------------------------------------------------


def _result(rule_id: str, *, project: str, suppressed: bool = False) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "ruleId": rule_id,
        "level": "error",
        "message": {"text": "fixture"},
        "properties": {
            "scanner_name": "bandit",
            "workspace_project": project,
            "workspace_uri": f"{project}/{gate.FIXTURE_RELATIVE_PATH}",
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": gate.FIXTURE_RELATIVE_PATH,
                        "uriBaseId": "PROJECTROOT",
                    }
                }
            }
        ],
    }
    if suppressed:
        entry["suppressions"] = [{"kind": "external"}]
    return entry


@pytest.fixture
def workspace_root(tmp_path):
    """The fixture the gate would generate, on disk, so path checks are real."""
    root = tmp_path / "workspace"
    gate.write_fixture(root)
    return root


@pytest.fixture
def output_dir(tmp_path, workspace_root):
    """A per-project output tree of the shape the executor writes."""
    out = tmp_path / "output"
    for project in gate.FIXTURE_PROJECTS:
        subtree = out / "projects" / project.key
        (subtree / "scanners" / "bandit" / "source").mkdir(parents=True)
        (subtree / gate.RESULTS_FILENAME).write_text("{}", encoding="utf-8")
    return out


@pytest.fixture
def healthy(workspace_root, output_dir):
    """A results file every check must pass."""
    runs = []
    projects = []
    for index, project in enumerate(gate.FIXTURE_PROJECTS):
        results = [
            _result("B307", project=project.key),
            _result("B602", project=project.key),
            _result(
                gate.SUPPRESSED_RULE_ID,
                project=project.key,
                suppressed=bool(project.suppress_rule),
            ),
        ]
        live = [entry for entry in results if not entry.get("suppressions")]
        # CRITICAL gates nothing at level error->CRITICAL... it gates everything,
        # so give the lax project zero actionable explicitly, matching what a real
        # bandit run produces (its severities are HIGH, not CRITICAL).
        actionable = 0 if project.threshold == "CRITICAL" else len(live)
        runs.append(
            {
                "tool": {"driver": {"name": "ASH"}},
                "originalUriBaseIds": {
                    "PROJECTROOT": {
                        "uri": (workspace_root / project.key).as_uri() + "/"
                    }
                },
                "properties": {"workspace_project": project.key},
                "results": results,
            }
        )
        projects.append(
            {
                "project": project.key,
                "relative_path": project.key,
                "display_label": project.key,
                "status": "completed",
                "severity_threshold": project.threshold,
                "finding_count": len(live),
                "actionable_finding_count": actionable,
                "exceeds_threshold": actionable > 0,
                "output_path": f"projects/{project.key}",
                "sarif_run_index": index,
            }
        )

    return {
        "workspace": {
            "workspace_file": (workspace_root / gate.WORKSPACE_FILENAME).as_posix(),
            "workspace_root": workspace_root.as_posix(),
            "status": "completed",
            "exit_code": 2,
            "projects": projects,
        },
        "scanner_results": {
            "bandit": {"status": "PASSED", "finding_count": 9},
        },
        "sarif": {"version": "2.1.0", "runs": runs},
    }


def _evaluate(results, output_dir, **kwargs):
    return gate.evaluate_results(results, output_dir, **kwargs)


# ---------------------------------------------------------------------------
# The healthy case passes, so a failure below means the mutation was detected
# ---------------------------------------------------------------------------


class TestHealthyResultsPass:
    def test_no_violations_on_a_healthy_results_file(self, healthy, output_dir):
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert outcome.violations == []
        assert outcome.passed

    def test_exit_zero_is_also_tolerated(self, healthy, output_dir):
        """In case a future default turns fail_on_findings off."""
        healthy["workspace"]["exit_code"] = 0
        outcome = _evaluate(healthy, output_dir, exit_code=0, repo_root=REPO_ROOT)
        assert outcome.violations == []


# ---------------------------------------------------------------------------
# Shape errors short-circuit rather than making the rest vacuous
# ---------------------------------------------------------------------------


class TestShapeChecks:
    def test_a_missing_workspace_block_is_reported(self, healthy, output_dir):
        del healthy["workspace"]
        outcome = _evaluate(healthy, output_dir)
        assert any("no 'workspace' object" in v for v in outcome.violations)

    def test_an_empty_project_list_is_reported(self, healthy, output_dir):
        healthy["workspace"]["projects"] = []
        outcome = _evaluate(healthy, output_dir)
        assert any("no project ran" in v for v in outcome.violations)

    def test_a_missing_sarif_block_is_reported(self, healthy, output_dir):
        del healthy["sarif"]
        outcome = _evaluate(healthy, output_dir)
        assert any("no top-level 'sarif'" in v for v in outcome.violations)

    def test_a_non_object_results_file_is_reported(self, output_dir):
        outcome = _evaluate(["not", "an", "object"], output_dir)
        assert any("not a JSON object" in v for v in outcome.violations)

    def test_shape_violations_short_circuit_the_rest(self, healthy, output_dir):
        """Otherwise the remaining checks pass by inspecting nothing."""
        del healthy["workspace"]
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert len(outcome.violations) == 1


# ---------------------------------------------------------------------------
# The four regressions the gate exists for
# ---------------------------------------------------------------------------


class TestAttributionRegression:
    def test_a_finding_credited_to_another_project_fails(self, healthy, output_dir):
        run = healthy["sarif"]["runs"][0]
        run["results"][0]["properties"]["workspace_project"] = "project-b"
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("credited to" in v for v in outcome.violations)

    def test_a_workspace_uri_outside_the_project_fails(self, healthy, output_dir):
        run = healthy["sarif"]["runs"][0]
        run["results"][0]["properties"]["workspace_uri"] = "project-b/src/insecure.py"
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("outside that project" in v for v in outcome.violations)

    def test_findings_with_no_workspace_uri_fail(self, healthy, output_dir):
        for entry in healthy["sarif"]["runs"][0]["results"]:
            entry["properties"].pop("workspace_uri")
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("none carry a workspace_uri" in v for v in outcome.violations)

    def test_an_unattributed_run_fails(self, healthy, output_dir):
        healthy["sarif"]["runs"][0]["properties"].pop("workspace_project")
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("no properties.workspace_project" in v for v in outcome.violations)


class TestOneRunPerProjectRegression:
    def test_one_merged_run_fails(self, healthy, output_dir):
        """The shape ASH produces in single-directory mode: everything in runs[0]."""
        runs = healthy["sarif"]["runs"]
        merged = copy.deepcopy(runs[0])
        for other in runs[1:]:
            merged["results"].extend(other["results"])
        healthy["sarif"]["runs"] = [merged]
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("run(s)" in v for v in outcome.violations)

    def test_a_run_with_no_uri_base_fails(self, healthy, output_dir):
        healthy["sarif"]["runs"][0].pop("originalUriBaseIds")
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("no originalUriBaseIds" in v for v in outcome.violations)

    def test_two_runs_declaring_the_same_root_fail(self, healthy, output_dir):
        runs = healthy["sarif"]["runs"]
        runs[1]["originalUriBaseIds"] = copy.deepcopy(runs[0]["originalUriBaseIds"])
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("same project root" in v for v in outcome.violations)

    def test_a_wrong_run_index_fails(self, healthy, output_dir):
        healthy["workspace"]["projects"][0]["sarif_run_index"] = 1
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("attributed to" in v for v in outcome.violations)

    def test_a_path_that_does_not_resolve_against_its_root_fails(
        self, healthy, output_dir
    ):
        run = healthy["sarif"]["runs"][0]
        location = run["results"][0]["locations"][0]["physicalLocation"]
        location["artifactLocation"]["uri"] = "project-a/src/insecure.py"
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("do not resolve to a file" in v for v in outcome.violations)

    def test_the_project_named_src_resolves_correctly(self, healthy, output_dir):
        """The collision that broke the first version of this check.

        The ``src`` project's file is at ``src/insecure.py``, which begins with
        the project key. A string-prefix test flagged it; resolving against the
        declared root does not.
        """
        src_run = next(
            run
            for run in healthy["sarif"]["runs"]
            if run["properties"]["workspace_project"] == "src"
        )
        assert (
            gate.check_result_paths_resolve_against_their_run_root(
                [gate.collect_runs({"sarif": {"runs": [src_run]}})[0]]
            )
            == []
        )


class TestSuppressionScopeRegression:
    def test_a_suppression_leaking_into_another_project_fails(
        self, healthy, output_dir
    ):
        """The silent false negative: B's copy of the rule goes quiet."""
        other = gate.SUPPRESSION_PAIR[1]
        run = next(
            r
            for r in healthy["sarif"]["runs"]
            if r["properties"]["workspace_project"] == other
        )
        for entry in run["results"]:
            if entry["ruleId"] == gate.SUPPRESSED_RULE_ID:
                entry["suppressions"] = [{"kind": "external"}]
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any(
            "leaked across the project boundary" in v for v in outcome.violations
        )

    def test_a_project_own_suppression_not_applying_fails(self, healthy, output_dir):
        suppressing = gate.SUPPRESSION_PAIR[0]
        run = next(
            r
            for r in healthy["sarif"]["runs"]
            if r["properties"]["workspace_project"] == suppressing
        )
        for entry in run["results"]:
            if entry["ruleId"] == gate.SUPPRESSED_RULE_ID:
                entry.pop("suppressions")
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("did not apply" in v for v in outcome.violations)

    def test_a_rule_that_stopped_firing_is_named_rather_than_passing(
        self, healthy, output_dir
    ):
        """Absent everywhere must not read as correctly suppressed."""
        for run in healthy["sarif"]["runs"]:
            run["results"] = [
                entry
                for entry in run["results"]
                if entry["ruleId"] != gate.SUPPRESSED_RULE_ID
            ]
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("no longer fires" in v for v in outcome.violations)


class TestThresholdScopeRegression:
    def test_one_threshold_applied_to_every_project_fails(self, healthy, output_dir):
        for entry in healthy["workspace"]["projects"]:
            entry["severity_threshold"] = "LOW"
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("both report threshold" in v for v in outcome.violations)

    def test_the_looser_threshold_gating_more_findings_fails(self, healthy, output_dir):
        strict_key, lax_key = gate.THRESHOLD_PAIR
        by_key = {p["project"]: p for p in healthy["workspace"]["projects"]}
        by_key[lax_key]["actionable_finding_count"] = 99
        by_key[lax_key]["exceeds_threshold"] = True
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("cannot gate more findings" in v for v in outcome.violations)

    def test_zero_findings_in_the_strict_project_fails(self, healthy, output_dir):
        strict_key = gate.THRESHOLD_PAIR[0]
        by_key = {p["project"]: p for p in healthy["workspace"]["projects"]}
        by_key[strict_key]["finding_count"] = 0
        by_key[strict_key]["actionable_finding_count"] = 0
        by_key[strict_key]["exceeds_threshold"] = False
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("zero findings" in v for v in outcome.violations)

    @pytest.mark.parametrize("position", range(len(gate.FIXTURE_PROJECTS)))
    def test_a_verdict_disagreeing_with_its_count_fails(
        self, healthy, output_dir, position
    ):
        """Every project, not just the compared pair.

        The first version of this check only inspected the threshold pair, so a
        disagreement on the third project passed. Parametrised so that cannot
        recur silently.
        """
        entry = healthy["workspace"]["projects"][position]
        entry["exceeds_threshold"] = not (entry["actionable_finding_count"] > 0)
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("the two disagree" in v for v in outcome.violations)


class TestOutputSubtreeRegression:
    def test_two_projects_sharing_an_output_path_fails(self, healthy, output_dir):
        """The second scanner run would silently overwrite the first's raw output."""
        healthy["workspace"]["projects"][1]["output_path"] = healthy["workspace"][
            "projects"
        ][0]["output_path"]
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("share the output path" in v for v in outcome.violations)

    def test_a_missing_subtree_fails(self, healthy, output_dir):
        shutil.rmtree(output_dir / "projects" / "project-b")
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("is not a directory" in v for v in outcome.violations)

    def test_a_subtree_without_its_own_results_file_fails(self, healthy, output_dir):
        (output_dir / "projects" / "project-b" / gate.RESULTS_FILENAME).unlink()
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any(
            "has no ash_aggregated_results.json" in v for v in outcome.violations
        )

    def test_a_subtree_without_a_scanners_directory_fails(self, healthy, output_dir):
        shutil.rmtree(output_dir / "projects" / "project-b" / "scanners")
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("no 'scanners' directory" in v for v in outcome.violations)


# ---------------------------------------------------------------------------
# Status, exit code, and fixture scoping
# ---------------------------------------------------------------------------


class TestStatusAndExitCode:
    def test_a_refused_status_with_a_results_file_fails(self, healthy, output_dir):
        """The discriminator for the ambiguous exit code 2."""
        healthy["workspace"]["status"] = "refused"
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("rather than 'completed'" in v for v in outcome.violations)

    def test_a_payload_exit_code_disagreeing_with_the_process_fails(
        self, healthy, output_dir
    ):
        healthy["workspace"]["exit_code"] = 0
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("but the process exited" in v for v in outcome.violations)

    def test_exit_one_is_rejected(self, healthy, output_dir):
        healthy["workspace"]["exit_code"] = 1
        outcome = _evaluate(healthy, output_dir, exit_code=1, repo_root=REPO_ROOT)
        assert any("internal error" in v for v in outcome.violations)

    def test_exit_three_is_rejected(self, healthy, output_dir):
        healthy["workspace"]["exit_code"] = 3
        outcome = _evaluate(healthy, output_dir, exit_code=3, repo_root=REPO_ROOT)
        assert any("invalid project config" in v for v in outcome.violations)


class TestFailedAndSkippedProjects:
    def test_a_failed_project_fails_the_gate(self, healthy, output_dir):
        healthy["workspace"]["projects"][0]["status"] = "failed"
        healthy["workspace"]["projects"][0]["error"] = "scanner blew up"
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("scanner blew up" in v for v in outcome.violations)

    def test_a_missing_project_fails_the_gate(self, healthy, output_dir):
        healthy["workspace"]["projects"] = healthy["workspace"]["projects"][:2]
        healthy["sarif"]["runs"] = healthy["sarif"]["runs"][:2]
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any(
            "is missing from workspace.projects" in v for v in outcome.violations
        )

    def test_a_scanner_at_error_fails_the_gate(self, healthy, output_dir):
        healthy["scanner_results"]["bandit"]["status"] = "ERROR"
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("status ERROR" in v for v in outcome.violations)

    def test_a_scanner_that_is_missing_is_tolerated(self, healthy, output_dir):
        """MISSING means the tool is not installed on this runner."""
        healthy["scanner_results"]["semgrep"] = {"status": "MISSING"}
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert outcome.violations == []


class TestFixtureScoping:
    def test_findings_inside_the_repository_fail(self, healthy, output_dir):
        """The inverse regression: the scan read the working directory instead."""
        run = healthy["sarif"]["runs"][0]
        run["originalUriBaseIds"]["PROJECTROOT"]["uri"] = REPO_ROOT.as_uri() + "/"
        location = run["results"][0]["locations"][0]["physicalLocation"]
        location["artifactLocation"]["uri"] = "scripts/verify_docs_freshness.py"
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("inside the repository" in v for v in outcome.violations)

    def test_the_gate_refuses_to_build_inside_the_repository(self):
        violations = gate.check_paths_outside_repo(
            REPO_ROOT, REPO_ROOT / "workspace", REPO_ROOT / "output"
        )
        assert len(violations) == 2

    def test_a_directory_outside_the_repository_is_accepted(self, tmp_path):
        assert gate.check_paths_outside_repo(REPO_ROOT, tmp_path) == []


# ---------------------------------------------------------------------------
# The generated fixture, and the workflow that runs it
# ---------------------------------------------------------------------------


class TestGeneratedFixture:
    def test_every_project_gets_the_same_file(self, workspace_root):
        """Identical content is what makes attribution testable at all."""
        contents = {
            (workspace_root / project.key / gate.FIXTURE_RELATIVE_PATH).read_text(
                encoding="utf-8"
            )
            for project in gate.FIXTURE_PROJECTS
        }
        assert len(contents) == 1

    def test_the_suppression_pair_shares_a_threshold(self, workspace_root):
        """Otherwise a difference between them could be the threshold, not the
        suppression."""
        by_key = {project.key: project for project in gate.FIXTURE_PROJECTS}
        first, second = gate.SUPPRESSION_PAIR
        assert by_key[first].threshold == by_key[second].threshold

    def test_the_threshold_pair_differs_only_in_threshold(self, workspace_root):
        by_key = {project.key: project for project in gate.FIXTURE_PROJECTS}
        strict, lax = gate.THRESHOLD_PAIR
        assert by_key[strict].threshold != by_key[lax].threshold
        assert by_key[strict].suppress_rule is None
        assert by_key[lax].suppress_rule is None

    def test_exactly_one_project_configures_a_suppression(self, workspace_root):
        suppressing = [p for p in gate.FIXTURE_PROJECTS if p.suppress_rule]
        assert len(suppressing) == 1

    def test_a_project_is_named_src(self, workspace_root):
        """Container mode mounts the workspace root at /src, so this project is
        /src/src -- the #361 basename-collision shape."""
        assert any(project.key == "src" for project in gate.FIXTURE_PROJECTS)

    def test_each_project_config_carries_its_own_threshold(self, workspace_root):
        for project in gate.FIXTURE_PROJECTS:
            config = yaml.safe_load(
                (workspace_root / project.key / ".ash" / "ash.yaml").read_text(
                    encoding="utf-8"
                )
            )
            assert config["global_settings"]["severity_threshold"] == project.threshold

    def test_the_workspace_definition_lists_every_project(self, workspace_root):
        definition = json.loads(
            (workspace_root / gate.WORKSPACE_FILENAME).read_text(encoding="utf-8")
        )
        assert [entry["path"] for entry in definition["folders"]] == [
            project.key for project in gate.FIXTURE_PROJECTS
        ]

    def test_the_root_config_sets_the_execution_knobs(self, workspace_root):
        """Read from the root, not from a project: how many run at once is not a
        project's decision."""
        config = yaml.safe_load(
            (workspace_root / ".ash" / "ash.yaml").read_text(encoding="utf-8")
        )
        assert config["workspace"]["max_parallel_projects"] >= 1

    def test_the_fixture_plants_no_credential_shaped_literal(self):
        """detect-secrets matches line by line, and this repository self-scans."""
        lowered = gate.FIXTURE_PYTHON.lower()
        for marker in ("password", "secret", "api_key", "aws_access", "token ="):
            assert marker not in lowered


class TestScanCommand:
    def test_the_command_uses_the_workspace_flag(self, tmp_path):
        command = gate.build_scan_command(tmp_path / "w.code-workspace", tmp_path / "o")
        assert "--workspace" in command
        assert "--source-dir" not in command

    def test_the_command_runs_the_working_tree_not_an_installed_copy(self, tmp_path):
        command = gate.build_scan_command(tmp_path / "w.code-workspace", tmp_path / "o")
        assert command[:3] == [
            sys.executable,
            "-m",
            "automated_security_helper.cli.main",
        ]

    def test_only_the_scan_phase_runs(self, tmp_path):
        command = gate.build_scan_command(tmp_path / "w.code-workspace", tmp_path / "o")
        index = command.index("--phases")
        assert command[index + 1] == "scan"


class TestWorkflowWiring:
    """The job exists, on both platforms, with its timeouts in step.

    ``runner.temp`` in job-level ``env`` makes GitHub reject the whole workflow
    file -- zero jobs, no annotation, and a slow diagnosis. Pinned here because
    the failure is invisible in the workflow's own run history.
    """

    @pytest.fixture
    def workflow(self):
        return yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))

    @pytest.fixture
    def job(self, workflow):
        assert "multi-project-attribution" in workflow["jobs"], sorted(workflow["jobs"])
        return workflow["jobs"]["multi-project-attribution"]

    def test_the_job_runs_on_ubuntu_and_windows(self, job):
        assert set(job["strategy"]["matrix"]["os"]) == {
            "ubuntu-latest",
            "windows-latest",
        }

    def test_the_matrix_does_not_fail_fast(self, job):
        """A Windows-only path bug must not hide the ubuntu result."""
        assert job["strategy"]["fail-fast"] is False

    def test_the_job_invokes_the_gate(self, job):
        commands = " ".join(str(step.get("run", "")) for step in job["steps"])
        assert "scripts/verify_multi_project_attribution.py" in commands

    def test_runner_context_is_not_used_in_job_level_env(self, job):
        """GitHub rejects the whole workflow file, with no annotation."""
        job_env = job.get("env") or {}
        assert not any("runner." in str(value) for value in job_env.values())

    def test_the_temp_dir_override_sits_on_a_step(self, job):
        step_envs = [step.get("env") or {} for step in job["steps"]]
        assert any("TMPDIR" in env for env in step_envs)

    def test_the_scan_timeout_stays_inside_the_job_budget(self, job):
        """Otherwise GitHub cancels the job and the operator gets no diagnostics."""
        budget_seconds = int(job["timeout-minutes"]) * 60
        assert gate.DEFAULT_SCAN_TIMEOUT_SECONDS < budget_seconds
        assert gate.JOB_TIMEOUT_BUDGET_SECONDS <= budget_seconds

    def test_the_declared_budget_matches_the_workflow(self, job):
        assert int(job["timeout-minutes"]) * 60 == int(gate.JOB_TIMEOUT_BUDGET_SECONDS)

    def test_evidence_is_uploaded_on_failure(self, job):
        uploads = [
            step
            for step in job["steps"]
            if "upload-artifact" in str(step.get("uses", ""))
        ]
        assert uploads
        assert any("failure()" in str(step.get("if", "")) for step in uploads)
