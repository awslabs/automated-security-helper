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

``TestMisattributionShapes`` is the part worth reading first. The gate's original
headline attribution check compared the SARIF run's ``workspace_project`` against
each result's ``workspace_project``, and the aggregator writes both from one
variable in one loop, so it compared a value with itself and could not fail. That
class applies three distinct misattribution shapes and requires a violation for
each -- including the exchanged-attribution shape, which leaves the payload
perfectly self-consistent and is what a reused scanner instance produces. It also
carries a companion assertion that the old check really is blind to that shape, so
the per-project marker rules are demonstrably carrying the guarantee rather than
duplicating one.
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


def _result(
    rule_id: str,
    *,
    project: str,
    relative: str | None = None,
    suppressed: bool = False,
) -> Dict[str, Any]:
    """One SARIF result, shaped as the aggregator writes it.

    ``workspace_uri`` is built from the project's *relative path*, not its key,
    because that is what the aggregator produces: the URI is workspace-relative,
    and for a nested project the key ('apps-admin') is not a path component of it.
    Getting this wrong in the fixture would make the gate's own check look broken.
    """
    relative = relative or gate.FIXTURE_RELATIVE_PATH
    relative_path = gate.RELATIVE_PATH_BY_PROJECT.get(project, project)
    entry: Dict[str, Any] = {
        "ruleId": rule_id,
        "level": "error",
        "message": {"text": "fixture"},
        "properties": {
            "scanner_name": "bandit",
            "workspace_project": project,
            "workspace_uri": f"{relative_path}/{relative}",
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": relative,
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
    """A results file every check must pass.

    Each project carries the shared file's rules plus its own marker rule at
    ``src/marker.py``, which is the independent ground truth the attribution
    checks read. A project's marker never appears in another project's run, which
    is exactly what ``TestMisattributionShapes`` then breaks.
    """
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
            _result(
                project.marker_rule,
                project=project.key,
                relative=gate.FIXTURE_MARKER_RELATIVE_PATH,
            ),
            # Stands in for checkov: no issue_severity, so the gate falls through
            # to the SARIF level arm. Included because it is what makes the
            # CRITICAL project's count non-zero in the real run, and a fixture
            # that gave it zero would model a verdict the system never produces.
            _result(
                "CKV_AWS_18",
                project=project.key,
                relative=gate.FIXTURE_TERRAFORM_RELATIVE_PATH,
            ),
        ]
        live = [entry for entry in results if not entry.get("suppressions")]
        # Measured on the real fixture, not assumed: a CRITICAL threshold gates out
        # bandit's severity-carrying findings but NOT a finding that carries no
        # issue_severity, because severity_ladder maps SARIF `error` to CRITICAL
        # and CRITICAL is actionable at every threshold. So the CRITICAL project
        # keeps the checkov-shaped finding and loses the rest -- which is what
        # makes the strict 'src < project-b' inequality hold, and it holds by a
        # margin equal to the number of bandit findings rather than by everything
        # being gated.
        actionable = 1 if project.threshold == "CRITICAL" else len(live)
        runs.append(
            {
                "tool": {"driver": {"name": "ASH"}},
                "originalUriBaseIds": {
                    "PROJECTROOT": {
                        "uri": (workspace_root / project.relative_path).as_uri() + "/"
                    }
                },
                "properties": {"workspace_project": project.key},
                "results": results,
            }
        )
        projects.append(
            {
                "project": project.key,
                "relative_path": project.relative_path,
                "display_label": project.key,
                "status": "completed",
                "severity_threshold": project.threshold,
                "finding_count": len(live),
                "actionable_finding_count": actionable,
                "exceeds_threshold": actionable > 0,
                # Keyed by key, not path: one directory named 'apps-admin' rather
                # than two levels that could collide with a project named 'apps'.
                "output_path": f"projects/{project.key}",
                "sarif_run_index": index,
            }
        )

    # The rollup has to agree with the projects, because that is now asserted.
    # Summed here rather than hardcoded so the fixture stays consistent when the
    # project list or the actionable rule changes.
    return {
        "workspace": {
            "workspace_file": (workspace_root / gate.WORKSPACE_FILENAME).as_posix(),
            "workspace_root": workspace_root.as_posix(),
            "status": "completed",
            "exit_code": 2,
            "projects": projects,
            "unconvertible_finding_paths": 0,
        },
        "scanner_results": {
            "bandit": {
                "status": "PASSED",
                "finding_count": sum(p["finding_count"] for p in projects),
                "actionable_finding_count": sum(
                    p["actionable_finding_count"] for p in projects
                ),
            },
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


class TestMisattributionShapes:
    """The three ways attribution can be wrong, and the gate failing on each.

    The reason this class exists is that the gate used to pass on the third shape
    and could not have done otherwise. Its headline check compared the run's
    ``workspace_project`` against each result's ``workspace_project``, and the
    aggregator writes both from one variable in one loop, so the comparison was a
    value against itself. Shapes one and two happen to disturb that equality;
    shape three does not, and it is the one a shared scanner instance actually
    produces.

    Each shape is applied to a payload that passes cleanly, so a failure here is
    the mutation being detected and nothing else.
    """

    def test_shape_one_a_single_finding_credited_to_another_project(
        self, healthy, output_dir
    ):
        """One result inside A's run says it belongs to B."""
        run = healthy["sarif"]["runs"][0]
        mine = run["properties"]["workspace_project"]
        theirs = healthy["sarif"]["runs"][1]["properties"]["workspace_project"]
        run["results"][0]["properties"]["workspace_project"] = theirs
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any(
            f"attributed to '{mine}' but contains finding(s) credited to" in v
            for v in outcome.violations
        ), outcome.violations

    def test_shape_two_a_finding_from_another_projects_tree(self, healthy, output_dir):
        """A's run holds a finding that came from B's file.

        The shape a reused scanner instance produces: the scan really did read B's
        source, and everything in the payload says A. Only the marker rule can
        tell, because the rule that fired is a fact about source on disk.
        """
        first, second = healthy["sarif"]["runs"][0], healthy["sarif"]["runs"][1]
        mine = first["properties"]["workspace_project"]
        theirs = second["properties"]["workspace_project"]
        intruder = _result(
            gate.MARKER_RULE_BY_PROJECT[theirs],
            project=mine,
            relative=gate.FIXTURE_MARKER_RELATIVE_PATH,
        )
        first["results"].append(intruder)
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("belonging to" in v and mine in v for v in outcome.violations), (
            outcome.violations
        )

    def test_shape_three_two_runs_with_their_attributions_exchanged(
        self, healthy, output_dir
    ):
        """Every finding mislabelled, and the payload perfectly self-consistent.

        This is the shape that motivated the marker rules. Swapping the run-level
        attribution *and* every result's attribution together leaves nothing for a
        payload-internal check to notice: each run says A, every result in it says
        A, every workspace_uri is prefixed with A's path. The only thing that does
        not move is which rule fired, because that came from source.
        """
        first, second = healthy["sarif"]["runs"][0], healthy["sarif"]["runs"][1]
        first_key = first["properties"]["workspace_project"]
        second_key = second["properties"]["workspace_project"]

        def relabel(run, new_key):
            run["properties"]["workspace_project"] = new_key
            new_path = gate.RELATIVE_PATH_BY_PROJECT[new_key]
            for entry in run["results"]:
                entry["properties"]["workspace_project"] = new_key
                tail = entry["locations"][0]["physicalLocation"]["artifactLocation"][
                    "uri"
                ]
                entry["properties"]["workspace_uri"] = f"{new_path}/{tail}"

        relabel(first, second_key)
        relabel(second, first_key)
        # The run indexes and roots have to move too, or a different check fires
        # and this test would pass for the wrong reason.
        for entry in healthy["workspace"]["projects"]:
            if entry["project"] == first_key:
                entry["sarif_run_index"] = 1
            elif entry["project"] == second_key:
                entry["sarif_run_index"] = 0
        first["originalUriBaseIds"], second["originalUriBaseIds"] = (
            second["originalUriBaseIds"],
            first["originalUriBaseIds"],
        )

        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("belonging to" in v for v in outcome.violations), outcome.violations

    def test_shape_three_is_invisible_to_the_payload_internal_check(
        self, healthy, output_dir
    ):
        """The companion assertion, and the whole justification for the markers.

        Proves shape three really is undetectable by the check that used to be the
        headline one -- so the marker check is carrying the guarantee rather than
        duplicating an existing one. If this ever starts failing, the two checks
        have converged and one of them is redundant.
        """
        first, second = healthy["sarif"]["runs"][0], healthy["sarif"]["runs"][1]
        first_key = first["properties"]["workspace_project"]
        second_key = second["properties"]["workspace_project"]

        def relabel(run, new_key):
            run["properties"]["workspace_project"] = new_key
            new_path = gate.RELATIVE_PATH_BY_PROJECT[new_key]
            for entry in run["results"]:
                entry["properties"]["workspace_project"] = new_key
                tail = entry["locations"][0]["physicalLocation"]["artifactLocation"][
                    "uri"
                ]
                entry["properties"]["workspace_uri"] = f"{new_path}/{tail}"

        relabel(first, second_key)
        relabel(second, first_key)

        runs = gate.collect_runs(healthy)
        assert gate.check_findings_are_attributed_to_their_own_project(runs) == [], (
            "the payload-internal check now detects an exchanged attribution, so "
            "it is no longer a value compared with itself -- re-read whether the "
            "marker check is still the one carrying this guarantee"
        )
        assert gate.check_each_project_shows_only_its_own_marker_rule(runs), (
            "the marker check missed an exchanged attribution, which is the exact "
            "shape it exists to catch"
        )

    def test_a_project_whose_marker_never_appears_fails(self, healthy, output_dir):
        """A project that contributed nothing, or whose findings went elsewhere."""
        target = healthy["sarif"]["runs"][2]
        key = target["properties"]["workspace_project"]
        marker = gate.MARKER_RULE_BY_PROJECT[key]
        target["results"] = [
            entry for entry in target["results"] if entry["ruleId"] != marker
        ]
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any(
            "should show its own marker rule" in v for v in outcome.violations
        ), outcome.violations

    def test_a_run_attributed_to_an_unknown_project_fails(self, healthy, output_dir):
        healthy["sarif"]["runs"][0]["properties"]["workspace_project"] = "not-a-project"
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("not a fixture project" in v for v in outcome.violations), (
            outcome.violations
        )

    def test_a_nested_projects_own_paths_are_not_reported_as_foreign(
        self, healthy, output_dir
    ):
        """C4, stated as a test: the nested project must pass on correct output.

        Its key is 'apps-admin' and its findings are at 'apps/admin/src/...'. A
        prefix check written against the key rejects all of them. That reads as a
        real misattribution, and the cheapest way to silence it is to weaken or
        delete the check -- so it needs a test that fails when the comparison goes
        back to the key.
        """
        nested = next(p for p in gate.FIXTURE_PROJECTS if "/" in p.relative_path)
        run = next(
            gate.collect_runs(healthy)[index]
            for index, r in enumerate(healthy["sarif"]["runs"])
            if r["properties"]["workspace_project"] == nested.key
        )
        assert run.workspace_uris, "the nested project's run carries no workspace_uri"
        assert all(
            uri.startswith(f"{nested.relative_path}/") for uri in run.workspace_uris
        ), run.workspace_uris
        assert not any(uri.startswith(f"{nested.key}/") for uri in run.workspace_uris)
        assert gate.check_findings_are_attributed_to_their_own_project([run]) == []


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


#: Every project that does not configure the suppression. The leak test is
#: parametrised over all of them, because an earlier version of the gate named one
#: hand-picked partner and therefore never inspected two of the four projects --
#: including the nested one, which is the likeliest to be reached by a
#: path-matching bug.
NON_SUPPRESSING_PROJECTS = [
    project.key
    for project in gate.FIXTURE_PROJECTS
    if project.key != gate.SUPPRESSING_PROJECT
]


class TestSuppressionScopeRegression:
    @pytest.mark.parametrize("other", NON_SUPPRESSING_PROJECTS)
    def test_a_suppression_leaking_into_another_project_fails(
        self, healthy, output_dir, other
    ):
        """The silent false negative: the other project's copy goes quiet.

        Parametrised over every non-suppressing project. With a single hard-coded
        partner, a leak that reached only 'src' or only the nested project passed.
        """
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
        ), outcome.violations

    def test_a_project_own_suppression_not_applying_fails(self, healthy, output_dir):
        suppressing = gate.SUPPRESSING_PROJECT
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
        assert any("must gate strictly fewer" in v for v in outcome.violations)

    def test_equal_actionable_counts_fail(self, healthy, output_dir):
        """The hole tolerating '<=' left open, and the reason it was tightened.

        If the per-project threshold were never applied, both projects would
        report the same actionable count over the same shared file. Under '<='
        that passed, so the check could not fail on the very thing it exists to
        detect -- the two projects still carried different *declared* thresholds,
        which is all the other assertion looks at.
        """
        strict_key, lax_key = gate.THRESHOLD_PAIR
        by_key = {p["project"]: p for p in healthy["workspace"]["projects"]}
        shared_count = by_key[strict_key]["actionable_finding_count"]
        by_key[lax_key]["actionable_finding_count"] = shared_count
        by_key[lax_key]["exceeds_threshold"] = shared_count > 0
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("must gate strictly fewer" in v for v in outcome.violations), (
            outcome.violations
        )

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


class TestScannerRollupRegression:
    """The rollup zero that result_filters.py republishes as actionable_findings."""

    def test_a_rollup_actionable_of_zero_fails(self, healthy, output_dir):
        """The exact shape of the defect: initialised, defaulted, never summed."""
        healthy["scanner_results"]["bandit"]["actionable_finding_count"] = 0
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any(
            "would conclude this workspace is clean" in v for v in outcome.violations
        )

    def test_a_rollup_actionable_that_merely_disagrees_fails(self, healthy, output_dir):
        healthy["scanner_results"]["bandit"]["actionable_finding_count"] += 1
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any(
            "two views of the same run disagree" in v for v in outcome.violations
        )

    def test_a_rollup_finding_total_that_disagrees_fails(self, healthy, output_dir):
        healthy["scanner_results"]["bandit"]["finding_count"] += 5
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("finding total" in v for v in outcome.violations)

    def test_an_empty_rollup_fails(self, healthy, output_dir):
        healthy["scanner_results"] = {}
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("recorded no scanners" in v for v in outcome.violations)


class TestLostWorkspacePathRegression:
    def test_a_counted_unconvertible_path_fails(self, healthy, output_dir):
        """Every fixture file lives inside its project, so none should be refused."""
        healthy["workspace"]["unconvertible_finding_paths"] = 2
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any(
            "could not be given a workspace-relative path" in v
            for v in outcome.violations
        )

    def test_a_finding_that_lost_its_path_without_being_counted_fails(
        self, healthy, output_dir
    ):
        """The silent half of the defect: mis-prefixed and not counted.

        This is what made two of the three broken URI shapes invisible -- they
        produced a workspace_uri that named nothing, or none at all, while the
        counter stayed at zero.
        """
        for run in healthy["sarif"]["runs"]:
            for entry in run["results"]:
                entry["properties"].pop("workspace_uri", None)
        healthy["workspace"]["unconvertible_finding_paths"] = 0
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("lost their path silently" in v for v in outcome.violations)


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

    @pytest.mark.parametrize("position", range(len(gate.FIXTURE_PROJECTS)))
    def test_a_project_that_completed_but_found_nothing_fails(
        self, healthy, output_dir, position
    ):
        """Status 'completed' is not evidence a project was scanned.

        A project with zero findings satisfies every attribution assertion by
        giving them nothing to inspect -- no finding to credit wrongly, no
        suppression to leak, no path to mis-prefix. So the gate used to pass while
        three of four projects had silently not run. Parametrised over every
        position, because a check that only looks at the compared pair leaves the
        others free to be empty.
        """
        entry = healthy["workspace"]["projects"][position]
        key = entry["project"]
        entry["finding_count"] = 0
        entry["actionable_finding_count"] = 0
        entry["exceeds_threshold"] = False
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any(
            f"project '{key}' completed with 0 finding(s)" in v
            for v in outcome.violations
        ), outcome.violations

    def test_a_project_reporting_the_wrong_relative_path_fails(
        self, healthy, output_dir
    ):
        """Key-to-path derivation, asserted against the workspace definition."""
        nested = next(p for p in gate.FIXTURE_PROJECTS if "/" in p.relative_path)
        entry = next(
            e for e in healthy["workspace"]["projects"] if e["project"] == nested.key
        )
        entry["relative_path"] = nested.key
        outcome = _evaluate(healthy, output_dir, exit_code=2, repo_root=REPO_ROOT)
        assert any("reports relative_path" in v for v in outcome.violations), (
            outcome.violations
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
    def test_every_project_gets_the_same_shared_file(self, workspace_root):
        """Identical content is what makes attribution testable at all."""
        contents = {
            (
                workspace_root / project.relative_path / gate.FIXTURE_RELATIVE_PATH
            ).read_text(encoding="utf-8")
            for project in gate.FIXTURE_PROJECTS
        }
        assert len(contents) == 1

    def test_every_project_gets_a_marker_at_the_same_path(self, workspace_root):
        """Same path, different content: the other half of the attribution story.

        Identical paths mean a misattribution cannot hide behind a filename;
        differing content means the rule that fires identifies the project.
        """
        contents = {}
        for project in gate.FIXTURE_PROJECTS:
            marker = (
                workspace_root
                / project.relative_path
                / gate.FIXTURE_MARKER_RELATIVE_PATH
            )
            assert marker.is_file(), f"no marker written for '{project.key}'"
            contents[project.key] = marker.read_text(encoding="utf-8")
        assert len(set(contents.values())) == len(gate.FIXTURE_PROJECTS), contents

    def test_the_fixture_discriminates(self):
        """The gate's own fixture self-check, run as a unit test.

        Distinct markers, no marker colliding with a rule the shared file trips
        everywhere, and a source for each. Without these the attribution
        assertions pass while identifying nothing.
        """
        assert gate.check_the_fixture_can_discriminate() == []

    def test_a_nested_project_exists(self):
        """Otherwise the key-versus-path distinction is untested and a check that
        compares a workspace URI against the project key stays green while
        rejecting every finding in any nested project."""
        nested = [p for p in gate.FIXTURE_PROJECTS if "/" in p.relative_path]
        assert nested, [p.relative_path for p in gate.FIXTURE_PROJECTS]
        for project in nested:
            assert project.key == project.relative_path.replace("/", "-")
            assert project.key != project.relative_path

    def test_the_suppressing_project_shares_a_threshold_with_the_others(self):
        """Otherwise a difference could be the threshold, not the suppression."""
        by_key = {project.key: project for project in gate.FIXTURE_PROJECTS}
        suppressing = by_key[gate.SUPPRESSING_PROJECT]
        comparable = [
            project
            for key, project in by_key.items()
            if key != gate.SUPPRESSING_PROJECT
            and project.threshold == suppressing.threshold
        ]
        assert comparable, (
            "no other project shares the suppressing project's threshold, so any "
            "difference between them could be the threshold rather than the "
            "suppression"
        )

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
                (
                    workspace_root / project.relative_path / ".ash" / "ash.yaml"
                ).read_text(encoding="utf-8")
            )
            assert config["global_settings"]["severity_threshold"] == project.threshold

    def test_the_workspace_definition_lists_every_project_by_path(self, workspace_root):
        """Paths, not keys. A workspace file naming 'apps-admin' points at nothing."""
        definition = json.loads(
            (workspace_root / gate.WORKSPACE_FILENAME).read_text(encoding="utf-8")
        )
        listed = [entry["path"] for entry in definition["folders"]]
        assert listed == [project.relative_path for project in gate.FIXTURE_PROJECTS]
        for path in listed:
            assert (workspace_root / path).is_dir(), (
                f"the workspace definition lists '{path}' but no such directory "
                "was written"
            )

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

    def test_the_scan_is_restricted_to_the_scanners_the_gate_reads(self, tmp_path):
        """A network-dependent producer this gate asserts nothing about made it red.

        opengrep and semgrep default to the ``p/ci`` ruleset, fetched from a rule
        registry over the network. Four projects run concurrently, so the gate made
        four concurrent fetches; a lost fetch is scanner status ERROR, which
        ``check_no_scanner_errors`` refuses to tolerate. Pinned as a test because
        the flake reproduces about one run in three and a re-run hides it.
        """
        command = gate.build_scan_command(tmp_path / "w.code-workspace", tmp_path / "o")
        selected = [
            command[i + 1]
            for i, token in enumerate(command[:-1])
            if token == "--scanners"
        ]
        assert set(selected) == {"bandit", "checkov"}
        assert selected == list(gate.GATE_SCANNERS)


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
