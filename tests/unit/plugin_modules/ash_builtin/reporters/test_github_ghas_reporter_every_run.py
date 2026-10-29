# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The GHAS report over a multi-run model carries every project's findings.

``ash report --format github-ghas --output-dir <workspace output>`` hands the
reporter the unified model a workspace scan writes: one SARIF run per project,
each run stamped with ``properties.workspace_project_path`` and holding
project-relative URIs. The reporter read ``runs[0]`` and stopped, so the file
held the first project's findings and nothing said the rest were missing.

Every run is read now, and each location is written below the workspace root,
the coordinate GitHub resolves when the upload is attributed to the monorepo.
"""

import json

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.github_ghas_reporter import (
    GHASReporter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Level,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Region,
    ReportingConfiguration,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()


def _project_run(project_path: str, rule_id: str, uri: str) -> Run:
    """One project's run as the workspace aggregator writes it."""
    return Run(
        tool=Tool(
            driver=ToolComponent(
                name="ASH",
                rules=[
                    ReportingDescriptor(
                        id=rule_id,
                        defaultConfiguration=ReportingConfiguration(level=Level.error),
                    )
                ],
            )
        ),
        results=[
            Result(
                ruleId=rule_id,
                level=Level.error,
                message=Message(text=f"{rule_id} fired"),
                locations=[
                    Location(
                        physicalLocation=PhysicalLocation(
                            artifactLocation=ArtifactLocation(
                                uri=uri, uriBaseId="PROJECTROOT"
                            ),
                            region=Region(startLine=3),
                        )
                    )
                ],
            )
        ],
        properties=PropertyBag.model_validate(
            {
                "workspace_project": project_path,
                "workspace_project_path": project_path,
            }
        ),
    )


@pytest.fixture
def reporter(test_plugin_context):
    return GHASReporter(context=test_plugin_context)


@pytest.fixture
def document(reporter):
    model = AshAggregatedResults()
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[
            _project_run("services/api", "API-1", "src/handler.py"),
            _project_run("apps/web", "WEB-1", "src/index.js"),
        ],
    )
    return json.loads(reporter.report(model))


def test_results_of_every_run_are_emitted(document):
    (run,) = document["runs"]
    assert sorted(result["ruleId"] for result in run["results"]) == ["API-1", "WEB-1"]


def test_rules_of_every_run_are_declared(document):
    (run,) = document["runs"]
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} == {
        "API-1",
        "WEB-1",
    }


def test_locations_are_below_the_workspace_root(document):
    (run,) = document["runs"]
    uris = {
        result["ruleId"]: result["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"]
        for result in run["results"]
    }
    assert uris == {
        "API-1": "services/api/src/handler.py",
        "WEB-1": "apps/web/src/index.js",
    }


def test_a_single_directory_run_keeps_its_uris(reporter):
    """No project path on the run, no prefix: the single-directory document is
    unchanged."""
    run = _project_run("unused", "R-1", "src/app.py")
    run.properties = None
    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=[run])

    (out,) = json.loads(reporter.report(model))["runs"]

    assert (
        out["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "src/app.py"
    )
