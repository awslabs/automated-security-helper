# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The merged workspace JUnit report grades as each project's verdict did.

Two facts the unified file now records per project, and this reporter reads:

- ``policy_scanners_gate``: a finding from a scanner only the workspace policy
  added is reported and excluded from the verdict when the gate is off. The
  reporter rendered it as an ``<error>`` test case, which said the finding failed
  the project when the scan said it did not. It is now a skipped case with its
  own type, and an ``<error>`` when the gate is on.
- ``scanner_thresholds``: the threshold the verdict graded a scanner by when it is
  the scanner's own setting. The reporter read the project's gate for every
  scanner, so a scanner the project's config tightened was graded as its
  siblings were.
"""

import xml.etree.ElementTree as ET  # nosec B405

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
    POLICY_NOT_GATING_SKIP_TYPE,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

from tests.unit.plugin_modules.ash_builtin.reporters.test_junitxml_reporter import (
    _get_reporter,
    _outcome,
)

pytestmark = pytest.mark.unit


def _result(project: str, *, rule: str, scanner: str, **properties) -> dict:
    return {
        "ruleId": rule,
        "level": "error",
        "message": {"text": f"finding for {project}"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": f"src/{project}.py"}}}
        ],
        "properties": {
            "scanner_name": scanner,
            "workspace_project": project,
            "issue_severity": "HIGH",
            **properties,
        },
    }


def _project(key: str, **fields) -> WorkspaceProjectResult:
    return WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=ProjectRunStatus.COMPLETED,
        severity_threshold="MEDIUM",
        output_path=f"projects/{key}",
        **fields,
    )


@pytest.fixture
def workspace_model(tmp_path) -> AshAggregatedResults:
    """Four projects at a MEDIUM gate, each holding one HIGH finding.

    ``watch`` and ``strict`` each hold a policy-origin finding; ``watch`` does not
    gate on policy scanners, ``strict`` does. ``tuned`` recorded bandit's own
    CRITICAL threshold and holds a bandit HIGH and a semgrep HIGH; ``plain``
    recorded no scanner threshold and holds a bandit HIGH. ``legacy`` holds a
    policy-origin finding and records no gate at all, as a file written before
    the field existed does.
    """
    model = AshAggregatedResults()
    model.ash_config = None
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ASH"}},
                    "results": [
                        _result(
                            "watch",
                            rule="POLICY-WATCH",
                            scanner="semgrep",
                            origin="workspace-policy",
                        ),
                        _result(
                            "strict",
                            rule="POLICY-STRICT",
                            scanner="semgrep",
                            origin="workspace-policy",
                        ),
                        _result("tuned", rule="TUNED-BANDIT", scanner="bandit"),
                        _result("tuned", rule="TUNED-SEMGREP", scanner="semgrep"),
                        _result("plain", rule="PLAIN-BANDIT", scanner="bandit"),
                        _result(
                            "legacy",
                            rule="POLICY-LEGACY",
                            scanner="semgrep",
                            origin="workspace-policy",
                        ),
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
        projects=[
            _project(
                "watch", policy_scanners_gate=False, policy_origin_finding_count=1
            ),
            _project(
                "strict", policy_scanners_gate=True, policy_origin_finding_count=1
            ),
            _project("tuned", scanner_thresholds={"bandit": "CRITICAL"}),
            _project("plain"),
            _project("legacy", policy_origin_finding_count=1),
        ],
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


def test_a_non_gating_policy_finding_is_skipped_not_an_error(tmp_path, workspace_model):
    cases = _cases(tmp_path, workspace_model)

    # RED at the base: the finding is HIGH over a MEDIUM gate, so the reporter
    # rendered an <error> for a finding the project's verdict excluded.
    assert _outcome(cases["POLICY-WATCH"]) == "below-threshold"
    skipped = cases["POLICY-WATCH"].find("skipped")
    assert skipped.get("type") == POLICY_NOT_GATING_SKIP_TYPE
    assert "does not gate this project" in skipped.get("message")


def test_a_gating_policy_finding_is_still_an_error(tmp_path, workspace_model):
    """The other direction: with the gate on the verdict counted it, so does this."""
    cases = _cases(tmp_path, workspace_model)

    assert _outcome(cases["POLICY-STRICT"]) == "actionable"


def test_a_policy_finding_in_a_record_without_the_field_is_an_error(
    tmp_path, workspace_model
):
    """A file written before the field existed applied the gate before it wrote."""
    assert workspace_model.workspace.projects[4].policy_scanners_gate is None

    cases = _cases(tmp_path, workspace_model)

    # RED at the base: the absent gate read as False and the finding rendered
    # Skipped "policy-not-gating" where the base rendered an <error> and the
    # recorded verdict counted it.
    assert _outcome(cases["POLICY-LEGACY"]) == "actionable"


def test_a_policy_finding_in_an_unlisted_project_is_graded_by_the_threshold(
    tmp_path, workspace_model
):
    """A project the workspace block does not list has no recorded gate.

    The result filters already judged such a finding by the threshold; the
    reporter's lookup defaulted the missing gate to False and skipped it, so the
    two readers disagreed. Only a listed project with its gate explicitly off
    excludes a finding.
    """
    (result,) = [
        r for r in workspace_model.sarif.runs[0].results if r.ruleId == "POLICY-WATCH"
    ]
    result.properties.__pydantic_extra__["workspace_project"] = "ghost"

    cases = _cases(tmp_path, workspace_model)

    # RED at the base: Skipped "policy-not-gating" for a project nothing recorded.
    assert _outcome(cases["POLICY-WATCH"]) == "actionable"


def test_a_single_scan_policy_tagged_finding_is_graded_by_the_threshold(
    tmp_path, workspace_model
):
    """In a single-directory scan the gate table is empty.

    A producer can write ``workspace_project`` and a ``workspace-policy`` origin
    into a result's property bag; with no workspace block to say a verdict
    excluded it, the finding is graded by the threshold as the exit code grades it.
    """
    workspace_model.workspace = None

    cases = _cases(tmp_path, workspace_model)

    # RED at the base: every policy-tagged finding rendered Skipped in the
    # single-scan report while the exit code counted it.
    assert _outcome(cases["POLICY-WATCH"]) == "actionable"
    assert _outcome(cases["POLICY-STRICT"]) == "actionable"


def test_a_policy_tag_alone_does_not_mark_the_finding(tmp_path, workspace_model):
    """A project's outcome reads ``origin`` alone, so this report does too.

    The tag is free text that rule metadata or an imported results file can
    carry. A finding holding it with no origin counted toward its project's
    outcome, so it must not be shown as a skipped case that looks harmless.
    """
    (result,) = [
        r for r in workspace_model.sarif.runs[0].results if r.ruleId == "POLICY-WATCH"
    ]
    del result.properties.__pydantic_extra__["origin"]
    result.properties.tags = ["workspace-policy"]

    cases = _cases(tmp_path, workspace_model)

    # RED at the base: the tag marked the finding policy-origin, so the report
    # showed Skipped "policy-not-gating" (below-threshold) for a finding the
    # project's outcome counted as a failure.
    assert _outcome(cases["POLICY-WATCH"]) == "actionable"
    assert cases["POLICY-WATCH"].find("skipped") is None


def test_the_origin_property_still_marks_a_finding_that_also_carries_the_tag(
    tmp_path, workspace_model
):
    """The executor writes the tag beside ``origin``; the origin is what counts."""
    (result,) = [
        r for r in workspace_model.sarif.runs[0].results if r.ruleId == "POLICY-WATCH"
    ]
    result.properties.tags = ["workspace-policy"]

    cases = _cases(tmp_path, workspace_model)

    assert cases["POLICY-WATCH"].find("skipped").get("type") == (
        POLICY_NOT_GATING_SKIP_TYPE
    )


def test_a_scanners_recorded_own_threshold_grades_its_findings(
    tmp_path, workspace_model
):
    cases = _cases(tmp_path, workspace_model)

    # RED at the base: tuned's bandit HIGH was graded by the project's MEDIUM gate
    # and rendered as an <error>; the verdict graded it by bandit's own CRITICAL.
    assert _outcome(cases["TUNED-BANDIT"]) == "below-threshold"
    assert cases["TUNED-BANDIT"].find("skipped").get("type") == "threshold"
    # Controls: a scanner with no recorded threshold of its own takes the project
    # gate, in the tuned project and in one that recorded no scanner thresholds.
    assert _outcome(cases["TUNED-SEMGREP"]) == "actionable"
    assert _outcome(cases["PLAIN-BANDIT"]) == "actionable"


def test_a_recorded_scanner_threshold_is_read_whatever_its_case(
    tmp_path, workspace_model
):
    workspace_model.workspace.projects[2].scanner_thresholds = {"bandit": "critical"}

    cases = _cases(tmp_path, workspace_model)

    assert _outcome(cases["TUNED-BANDIT"]) == "below-threshold"


def test_a_per_result_threshold_property_still_wins(tmp_path, workspace_model):
    """A finding-level statement stays more specific than the recorded gates."""
    (result,) = [
        r for r in workspace_model.sarif.runs[0].results if r.ruleId == "TUNED-BANDIT"
    ]
    result.properties.__pydantic_extra__["severity_threshold"] = "LOW"

    cases = _cases(tmp_path, workspace_model)

    assert _outcome(cases["TUNED-BANDIT"]) == "actionable"
