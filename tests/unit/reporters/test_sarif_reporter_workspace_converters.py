# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace-level ``ash.sarif`` names each project's converter shortfalls.

The unified workspace model keeps its top-level converter rows empty (converter
paths are relative to one project's tree), so the SARIF reporter's refusal
invocations found nothing, and the workspace document said nothing about a
converter that lost coverage in any project. Each project's own run now carries
one invocation per converter it recorded in ``incomplete_converters``, on the
run its ``sarif_run_index`` names, never on ``runs[0]`` by default.
"""

import json

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
    SarifReporter,
    workspace_converter_invocations,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()


def _project(key: str, **overrides) -> WorkspaceProjectResult:
    fields = {
        "project": key,
        "relative_path": key,
        "display_label": key,
        "status": ProjectRunStatus.COMPLETED,
        "severity_threshold": "MEDIUM",
        "output_path": f"projects/{key}",
        "scanners": {"bandit": "COMPLETED"},
        "incomplete_scanners": [],
        "ceiling_unreachable_findings": {},
    }
    fields.update(overrides)
    return WorkspaceProjectResult(**fields)


def _run() -> Run:
    return Run(tool=Tool(driver=ToolComponent(name="ASH")), results=[])


@pytest.fixture
def model() -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=[_run(), _run()])
    model.workspace = WorkspaceResults(
        workspace_file="/w/.ash-workspace.yaml",
        workspace_root="/w",
        exit_code=0,
        projects=[
            _project("api", sarif_run_index=0),
            _project(
                "web",
                sarif_run_index=1,
                incomplete_converters={"archive": "the converter crashed"},
            ),
        ],
    )
    return model


def test_the_projects_run_carries_the_converter_invocation(model, test_plugin_context):
    doc = json.loads(SarifReporter(context=test_plugin_context).report(model))

    api_run, web_run = doc["runs"]
    assert "invocations" not in api_run
    (invocation,) = web_run["invocations"]
    assert invocation["executionSuccessful"] is False
    assert invocation["properties"]["ash_converter"] == "archive"
    assert invocation["properties"]["workspace_project"] == "web"
    (notification,) = invocation["toolExecutionNotifications"]
    assert notification["level"] == "error"
    assert "archive" in notification["message"]["text"]
    assert "the converter crashed" in notification["message"]["text"]


def test_a_single_directory_model_adds_nothing(test_plugin_context):
    assert workspace_converter_invocations(AshAggregatedResults()) == []


def test_the_scans_own_sarif_is_left_alone(model, test_plugin_context):
    SarifReporter(context=test_plugin_context).report(model)

    assert model.sarif.runs[1].invocations is None
