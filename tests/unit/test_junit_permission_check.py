"""Regression test for #189: JUnit reporter publish fails on insufficient permissions.

The reusable workflow must include a permission pre-check step before
calling mikepenz/action-junit-report so that users get a clear warning
instead of a cryptic TypeError when checks:write is missing.
"""

from pathlib import Path

import yaml
import pytest

WORKFLOW_PATH = (
    Path(__file__).resolve().parents[2]
    / ".github"
    / "workflows"
    / "run-ash-security-scan.yml"
)


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


# ------------------------------------------------------------------ #
# YAML validity
# ------------------------------------------------------------------ #
class TestWorkflowYamlValidity:
    def test_yaml_parses_without_error(self, workflow):
        assert workflow is not None

    def test_has_jobs_key(self, workflow):
        assert "jobs" in workflow


# ------------------------------------------------------------------ #
# Permission pre-check step exists and is wired correctly
# ------------------------------------------------------------------ #
class TestJunitPermissionPreCheck:
    def test_check_perms_step_exists(self, workflow):
        steps = _get_steps(workflow)
        names = [s.get("name", "") for s in steps]
        assert "Verify checks write permission" in names

    def test_check_perms_step_precedes_junit_publish(self, workflow):
        steps = _get_steps(workflow)
        names = [s.get("name", "") for s in steps]
        perm_idx = names.index("Verify checks write permission")
        junit_idx = names.index("Publish JUnit Test Report")
        assert perm_idx < junit_idx, (
            "Permission check must appear before JUnit publish"
        )

    def test_check_perms_step_has_id(self, workflow):
        steps = _get_steps(workflow)
        step = next(
            s for s in steps if s.get("name") == "Verify checks write permission"
        )
        assert step.get("id") == "check-perms"

    def test_check_perms_sets_output(self, workflow):
        steps = _get_steps(workflow)
        step = next(
            s for s in steps if s.get("name") == "Verify checks write permission"
        )
        assert "has_permission" in step.get("run", "")

    def test_junit_step_gates_on_permission(self, workflow):
        """The JUnit publish step must reference check-perms output."""
        steps = _get_steps(workflow)
        step = next(
            s for s in steps if s.get("name") == "Publish JUnit Test Report"
        )
        condition = str(step.get("if", ""))
        assert "check-perms" in condition
        assert "has_permission" in condition

    def test_junit_step_has_continue_on_error(self, workflow):
        steps = _get_steps(workflow)
        step = next(
            s for s in steps if s.get("name") == "Publish JUnit Test Report"
        )
        assert step.get("continue-on-error") is True


# ------------------------------------------------------------------ #
# Top-level permissions include checks: write
# ------------------------------------------------------------------ #
class TestWorkflowPermissions:
    def test_checks_write_declared(self, workflow):
        perms = workflow.get("permissions", {})
        assert perms.get("checks") == "write", (
            "Workflow must declare 'checks: write' at the top level"
        )
