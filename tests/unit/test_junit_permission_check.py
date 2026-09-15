"""Regression test for #189: the JUnit report publish step lost its annotations.

What #189 actually was
----------------------
Publishing the JUnit report threw a cryptic TypeError -- "Cannot read properties
of undefined (reading 'id')" -- and every run silently lost its annotations.

The first fix misdiagnosed it as a missing `checks: write` permission and added a
"Verify checks write permission" pre-check step: a `GET
/repos/{owner}/{repo}/check-runs` call whose 403/404 was read as "no permission",
feeding a `has_permission` output that gated the publish step.

That diagnosis was wrong, and this file used to freeze it as an invariant. Five
tests here required the probe step, its `id: check-perms`, and the `if:` that
referenced it, so the misdiagnosis could not be removed without reddening the
suite. They have been replaced by the assertions below.

Why the probe was wrong, on two counts:

* The route does not exist. The REST API lists check runs per ref or per check
  suite, never per repository, so the bare route 404s for everyone. Measured with
  a fully authorized token: the bare route 404s while
  `/repos/{owner}/{repo}/commits/{sha}/check-runs` returns 200. `has_permission`
  was therefore always false and the publish step never ran once.
* A GET cannot establish WRITE access anyway, so the probe could never do the job
  its name claimed.

The real cause was `update_check: true`. It selects the action's update path,
which resolves an existing check run by `job_name` -- default `${{ github.job }}`,
the job's YAML key -- while GitHub names check runs after the job's DISPLAY name.
Nothing matched, `check_runs` came back empty, and annotator.ts reads
`check_runs[0].id` with no guard. The action caught the throw and still reported
success, so the loss was silent and total, on passing runs too.

`checks: write` was never the problem: it is granted at the top of the reusable
workflow, and no failing log contained "Resource not accessible by integration".

What this file pins now
-----------------------
The three properties that actually keep #189 fixed, rather than the shape of the
fix that did not:

1. No junit-report step anywhere under `.github/` sets `update_check` truthy.
   This is the root cause, and it is swept across every call site rather than
   hardcoded to two, so adding a third call site with `update_check: true` fails
   here too.
2. The scan workflow's `report_paths` is not a `**` glob. `**` does not descend
   into hidden directories, and the report lands under `.ash/ash_output/`, so a
   glob silently matched nothing and created an empty check.
3. The fork condition gates the publish step. That is the condition the deleted
   probe was reaching for, expressed as the test that actually holds: a fork PR
   gets a read-only GITHUB_TOKEN whatever `permissions:` the caller declares.

Failure modes these do not cover
--------------------------------
* A same-repo caller that never granted `checks: write` is deliberately left to
  the action, which fails soft and names the real cause.
* These are static assertions over YAML. They cannot prove the action publishes
  annotations at runtime, only that the three known regressions are absent.
"""

from pathlib import Path

import yaml
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"
GITHUB_DIR = REPO_ROOT / ".github"

# The action whose update path caused #189. Matched on the owner/repo prefix so a
# version bump or a re-pin to a different sha does not slip past the sweep.
JUNIT_ACTION = "mikepenz/action-junit-report"


@pytest.fixture(scope="module")
def workflow():
    """Parse the reusable workflow once per test module."""
    text = WORKFLOW_PATH.read_text()
    return yaml.safe_load(text)


def _get_steps(workflow):
    """Extract the step list from the single job in the workflow."""
    jobs = workflow["jobs"]
    assert "ash" in jobs, "Expected 'ash' job in workflow"
    return jobs["ash"]["steps"]


def _junit_publish_step(workflow):
    """The scan workflow's junit publish step."""
    steps = _get_steps(workflow)
    return next(s for s in steps if s.get("name") == "Publish JUnit Test Report")


def _iter_steps(node):
    """Yield every mapping with a 'uses' key, anywhere in a parsed YAML tree.

    Walks the whole document rather than reading `jobs.*.steps` and `runs.steps`,
    so it finds junit steps in reusable workflows and in composite actions alike
    without needing to know which shape a given file is.
    """
    if isinstance(node, dict):
        if isinstance(node.get("uses"), str):
            yield node
        for value in node.values():
            yield from _iter_steps(value)
    elif isinstance(node, list):
        for value in node:
            yield from _iter_steps(value)


def _junit_steps_under_github():
    """Every junit-report step in every YAML file under .github/.

    Returns (path, step) pairs so a failure names the file it came from.
    """
    found = []
    for path in sorted(GITHUB_DIR.rglob("*.yml")) + sorted(GITHUB_DIR.rglob("*.yaml")):
        try:
            document = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:  # pragma: no cover - a parse error is its own test
            pytest.fail(f"{path} is not parseable YAML: {exc}")
        for step in _iter_steps(document):
            if step["uses"].startswith(JUNIT_ACTION):
                found.append((path, step))
    return found


# ------------------------------------------------------------------ #
# YAML validity
# ------------------------------------------------------------------ #
class TestWorkflowYamlValidity:
    def test_yaml_parses_without_error(self, workflow):
        assert workflow is not None

    def test_has_jobs_key(self, workflow):
        assert "jobs" in workflow


# ------------------------------------------------------------------ #
# The real cause of #189: update_check took the action's update path
# ------------------------------------------------------------------ #
class TestUpdateCheckIsNeverSet:
    """`update_check: true` is what actually broke #189. Keep it unset."""

    def test_the_sweep_finds_the_junit_steps(self):
        """Positive control: a sweep that matches nothing would pass vacuously.

        Two call sites exist today -- the reusable scan workflow and the
        run-unit-tests composite action. If this ever drops to zero, the
        assertion below is inspecting nothing and must fail rather than pass.
        """
        found = _junit_steps_under_github()
        names = sorted(str(path.relative_to(REPO_ROOT)) for path, _ in found)
        assert len(found) >= 2, (
            f"expected at least 2 {JUNIT_ACTION} steps under .github/, found "
            f"{len(found)}: {names}"
        )

    def test_no_junit_step_sets_update_check(self):
        offenders = []
        for path, step in _junit_steps_under_github():
            value = (step.get("with") or {}).get("update_check")
            # Only a truthy value selects the update path. An explicit
            # `update_check: false` is fine, and so is omitting it entirely.
            if value not in (None, False, "false"):
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {value!r}")
        # The wording here avoids putting "update" and "set" on either side of an
        # interpolated value: bandit's B608 heuristic reads that shape as
        # "UPDATE ... SET <variable>" and reports a MEDIUM SQL-injection finding,
        # which is actionable at this repository's threshold and fails its own
        # self-scan. Rewording is free; a nosec comment would have suppressed a
        # real rule to make prose fit.
        assert not offenders, (
            "A junit-report step enables update_check, which takes the action's "
            "update path. That path resolves a check run by job_name while "
            "GitHub names check runs by display name, so the lookup matches "
            "nothing, annotator.ts reads check_runs[0].id unguarded, and the "
            "step throws, swallows the error, reports success and publishes no "
            f"annotations -- issue #189. Offending call site(s): {offenders}"
        )


# ------------------------------------------------------------------ #
# The report path must be reachable by the action's globber
# ------------------------------------------------------------------ #
class TestReportPathIsNotDotBlind:
    def test_report_paths_is_not_a_double_star_glob(self, workflow):
        """`**` does not descend into hidden directories such as `.ash/`.

        Scoped to this workflow on purpose. run-unit-tests publishes
        `**/pytest.junit.xml`, which is correct there: `test-results/` is not
        hidden, so that glob does match. The dot-blindness only bites a report
        written under a dot-directory, which is this workflow's default.
        """
        report_paths = str(_junit_publish_step(workflow)["with"]["report_paths"])
        assert "**" not in report_paths, (
            "report_paths must be an explicit path, not a ** glob: the report "
            "lands under the hidden '.ash/' directory by default and ** does "
            "not descend into hidden directories, so the step reported 'No "
            f"test results found!' and created an empty check. Got: {report_paths!r}"
        )

    def test_report_paths_honors_the_output_dir_input(self, workflow):
        """A hardcoded path would ignore a caller that overrides output-dir."""
        report_paths = str(_junit_publish_step(workflow)["with"]["report_paths"])
        assert "inputs.output-dir" in report_paths, (
            "report_paths must be built from the output-dir input so a caller "
            f"that overrides it is still published. Got: {report_paths!r}"
        )


# ------------------------------------------------------------------ #
# The fork condition, which is what the deleted probe was reaching for
# ------------------------------------------------------------------ #
class TestForkConditionGatesThePublish:
    def test_publish_step_is_gated_on_a_same_repo_pull_request(self, workflow):
        """GITHUB_TOKEN is read-only for fork PRs, so check runs cannot be made.

        Comparing head.repo.full_name against github.repository is the exact
        test for "same-repo PR". The `github.repository_owner` guard used
        elsewhere does not catch it: for a fork PR *into* this repo the owner is
        still the base repo's owner, so that guard passes.
        """
        condition = str(_junit_publish_step(workflow).get("if", ""))
        assert "pull_request.head.repo.full_name" in condition, condition
        assert "github.repository" in condition, condition

    def test_publish_step_is_gated_on_the_collect_input(self, workflow):
        """collect-junit-xml-report: false must opt a caller out entirely."""
        condition = str(_junit_publish_step(workflow).get("if", ""))
        assert "inputs.collect-junit-xml-report" in condition, condition

    def test_junit_step_no_continue_on_error(self, workflow):
        step = _junit_publish_step(workflow)
        assert step.get("continue-on-error") is None


# ------------------------------------------------------------------ #
# Top-level permissions include checks: write
# ------------------------------------------------------------------ #
class TestWorkflowPermissions:
    def test_checks_write_declared(self, workflow):
        perms = workflow.get("permissions", {})
        assert perms.get("checks") == "write", (
            "Workflow must declare 'checks: write' at the top level"
        )
