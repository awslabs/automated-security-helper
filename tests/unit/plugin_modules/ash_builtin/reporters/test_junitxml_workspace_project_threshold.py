# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The merged workspace JUnit report grades each finding by its project's gate.

A workspace's unified results file carries no ``ash_config``: each project ran
under its own configuration, and the merged model records only each project's
outcome, with the threshold that outcome was judged against
(``WorkspaceProjectResult.severity_threshold``, written from the project's
``gate_threshold``). The reporter read the scan-level threshold, which with no
config is ASH's default, so every project's findings were graded against one
gate while each project's outcome and the exit code used its own.

The two projects below are configured so that no single threshold grades both
the way their own gates do: a reporter reading one scan-level value fails at
least one assertion whatever that value is.
"""

import xml.etree.ElementTree as ET  # nosec B405

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

from tests.unit.plugin_modules.ash_builtin.reporters.test_junitxml_reporter import (
    _get_reporter,
    _outcome,
)

pytestmark = pytest.mark.unit


def _result(project: str, *, rule: str, level: str) -> dict:
    return {
        "ruleId": rule,
        "level": level,
        "message": {"text": f"finding for {project}"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": f"src/{project}.py"}}}
        ],
        "properties": {"scanner_name": "bandit", "workspace_project": project},
    }


def _project(key: str, threshold: str) -> WorkspaceProjectResult:
    return WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=ProjectRunStatus.COMPLETED,
        severity_threshold=threshold,
        output_path=f"projects/{key}",
    )


@pytest.fixture
def workspace_model(tmp_path) -> AshAggregatedResults:
    """``strict`` gates at ALL and holds an INFO finding; ``lax`` gates at
    CRITICAL and holds a MEDIUM finding. No recorded configuration."""
    model = AshAggregatedResults()
    model.ash_config = None
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ASH"}},
                    "results": [
                        _result("strict", rule="RULE-STRICT", level="none"),
                        _result("lax", rule="RULE-LAX", level="warning"),
                    ],
                    "invocations": [],
                }
            ],
        }
    )
    model.workspace = WorkspaceResults(
        workspace_file=(tmp_path / "fixture.code-workspace").as_posix(),
        workspace_root=tmp_path.as_posix(),
        exit_code=2,
        projects=[_project("strict", "ALL"), _project("lax", "CRITICAL")],
    )
    return model


def _cases(tmp_path, model) -> dict:
    output = _get_reporter(tmp_path).report(model)
    root = ET.fromstring(output)  # nosec B314
    return {
        case.get("classname"): case
        for suite in root.iter("testsuite")
        for case in suite.iter("testcase")
    }


def test_each_project_is_graded_by_its_own_recorded_gate(tmp_path, workspace_model):
    cases = _cases(tmp_path, workspace_model)

    assert _outcome(cases["RULE-STRICT"]) == "actionable", (
        "the strict project's gate is ALL, so its INFO finding is actionable"
    )
    assert _outcome(cases["RULE-LAX"]) == "below-threshold", (
        "the lax project's gate is CRITICAL, so its MEDIUM finding is below it"
    )


def test_a_recorded_gate_is_read_whatever_its_case(tmp_path, workspace_model):
    """``"critical"`` grades as CRITICAL here as it does in the HTML report.

    Both readers now take the recorded gate from one normalized table, so a
    spelling the ladder would not recognise cannot grade one report and not
    the other.
    """
    workspace_model.workspace.projects[1].severity_threshold = "critical"

    cases = _cases(tmp_path, workspace_model)

    assert _outcome(cases["RULE-LAX"]) == "below-threshold"


@pytest.mark.parametrize(
    "index, written, rule",
    [(0, "all", "RULE-STRICT"), (1, "low", "RULE-LAX")],
    ids=["all", "low"],
)
def test_a_lowercase_gate_is_not_read_as_critical(
    tmp_path, workspace_model, index, written, rule
):
    """The case above cannot tell a reader that skips the normalization: the
    ladder is case-sensitive and reads a spelling it does not know as CRITICAL,
    so ``"critical"`` grades the same with or without it. A lowercase gate
    below CRITICAL does tell: unnormalized, it would grade like CRITICAL and
    skip a finding the gate reports, loosening it without a word."""
    workspace_model.workspace.projects[index].severity_threshold = written

    cases = _cases(tmp_path, workspace_model)

    assert _outcome(cases[rule]) == "actionable"


def test_the_suites_still_carry_the_project(tmp_path, workspace_model):
    """The grading change leaves the suite naming as it was."""
    output = _get_reporter(tmp_path).report(workspace_model)
    names = {suite.get("name") for suite in ET.fromstring(output).iter("testsuite")}  # nosec B314
    assert {"strict/bandit", "lax/bandit"} <= names
