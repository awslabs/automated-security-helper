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
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.github_ghas_reporter import (
    GHASReporter,
)
from automated_security_helper.workspace.aggregation import (
    PROJECT_ROOT_URI_BASE_ID,
    rebase_run_for_project,
)
from automated_security_helper.workspace.plan import ProjectPlan
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


def _project_run(
    project_path: str,
    rule_id: str,
    uri: str,
    level: Level = Level.error,
    **run_fields,
) -> Run:
    """One project's run as the workspace aggregator writes it.

    ``rebase_run_for_project`` (workspace/aggregation.py) stamps every run it
    adds with ``properties.workspace_project`` and ``workspace_project_path``,
    anchors it with ``originalUriBaseIds.PROJECTROOT`` and tags each result's
    ``properties.workspace_project``; the reporter reads the run-level path, so
    that is what this mirrors (and ``test_the_run_the_real_aggregator_writes_is_
    read_as_a_project_run`` checks the mirror against the real thing).
    """
    return Run(
        tool=Tool(
            driver=ToolComponent(
                name="ASH",
                rules=[
                    ReportingDescriptor(
                        id=rule_id,
                        defaultConfiguration=ReportingConfiguration(level=level),
                    )
                ],
            )
        ),
        results=[
            Result(
                ruleId=rule_id,
                level=level,
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
        **run_fields,
    )


def _run_dict(run: Run) -> dict:
    return run.model_dump(by_alias=True, exclude_none=True, mode="json")


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


def test_a_rule_fired_in_two_projects_is_declared_once_at_its_most_severe(reporter):
    """The same scanner fires the same rule in several projects of a monorepo.
    The merged document declares the rule once (two descriptors with one id
    would be invalid), carries no ``ruleIndex`` (a per-run index is stale after
    the merge), and scores the rule by its most severe emitted result across
    every run: an ``error`` in one project and a ``note`` in another is 9.5."""
    api = _project_run("services/api", "B105", "src/handler.py")
    web = _project_run("apps/web", "B105", "src/index.js", level=Level.note)
    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=[api, web])

    (run,) = json.loads(reporter.report(model))["runs"]

    rules = run["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == ["B105"]
    assert rules[0]["properties"]["security-severity"] == "9.5"
    assert all("ruleIndex" not in result for result in run["results"])
    assert sorted(result["level"] for result in run["results"]) == ["error", "note"]


def test_a_multi_run_document_carries_no_base_ids_or_related_locations(reporter):
    """The slim result keeps ``locations`` only: ``relatedLocations`` and code
    flows, whose URIs the rebase never visits, are left out, and a multi-run
    document declares no ``originalUriBaseIds`` and no per-location
    ``uriBaseId``, so a consumer cannot resolve the project prefix twice."""
    api = _project_run(
        "services/api",
        "API-1",
        "src/handler.py",
        originalUriBaseIds={
            "PROJECTROOT": ArtifactLocation(uri="file:///ws/services/api/")
        },
    )
    api.results[0].relatedLocations = [
        Location(
            physicalLocation=PhysicalLocation(
                artifactLocation=ArtifactLocation(
                    uri="src/other.py", uriBaseId="PROJECTROOT"
                )
            )
        )
    ]
    web = _project_run("apps/web", "WEB-1", "src/index.js")
    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=[api, web])

    (run,) = json.loads(reporter.report(model))["runs"]

    assert "originalUriBaseIds" not in run
    for result in run["results"]:
        assert "relatedLocations" not in result
        assert "codeFlows" not in result
        for location in result["locations"]:
            assert "uriBaseId" not in location["physicalLocation"]["artifactLocation"]


@pytest.mark.parametrize(
    ("project_path", "expected"),
    [
        # a project at the workspace root: its own paths are already
        # workspace-relative, and the helper refuses a "." prefix, so the URI
        # is kept as written
        (".", "src/handler.py"),
        # a trailing separator is not a component: no doubled slash
        ("services/api/", "services/api/src/handler.py"),
        ("services/api", "services/api/src/handler.py"),
    ],
)
def test_a_root_or_slash_terminated_project_path_places_the_uri_once(
    reporter, project_path, expected
):
    """A workspace document with one project: the model's workspace block says
    so, and the one run's URIs are placed below the workspace root."""
    run = _project_run(project_path, "R-1", "src/handler.py")
    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=[run])
    model.workspace = _workspace(project_path)

    (out,) = json.loads(reporter.report(model))["runs"]

    assert (
        out["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == expected
    )


def _workspace(*project_paths: str) -> WorkspaceResults:
    return WorkspaceResults(
        workspace_file="/ws/.ash-workspace.yaml",
        workspace_root="/ws",
        exit_code=0,
        projects=[
            WorkspaceProjectResult(
                project=path.strip("/").replace("/", "-") or "root",
                relative_path=path,
                display_label=path,
                status=ProjectRunStatus.COMPLETED,
                severity_threshold="MEDIUM",
                output_path=f"projects/{path}",
                scanners={"bandit": "COMPLETED"},
                incomplete_scanners=[],
                ceiling_unreachable_findings={},
                sarif_run_index=index,
            )
            for index, path in enumerate(project_paths)
        ],
    )


def test_a_projects_own_document_keeps_its_uris_and_base_ids(reporter):
    """The per-project document the workspace driver writes carries one run
    that happens to be stamped; it is not a workspace document (no workspace
    block, one run), so its URIs stay project-relative with their base id, which
    is what uploading it for that project's repository needs."""
    run = _project_run(
        "services/api",
        "R-1",
        "src/handler.py",
        originalUriBaseIds={
            "PROJECTROOT": ArtifactLocation(uri="file:///ws/services/api/")
        },
    )
    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=[run])

    (out,) = json.loads(reporter.report(model))["runs"]

    artifact = out["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert artifact == {"uri": "src/handler.py", "uriBaseId": "PROJECTROOT"}
    assert out["originalUriBaseIds"] == {
        "PROJECTROOT": {"uri": "file:///ws/services/api/"}
    }


@pytest.mark.parametrize(
    "project_path",
    [
        "../other",
        "/abs/other",
        "services/../../other",
        "C:/other",
        "%2e%2e/other",
        "services/%2E%2E/%2e%2e/other",
        "%2Fabs/other",
        "%2e%2e%5cother",
        "C%3A/other",
    ],
)
def test_a_project_path_outside_the_workspace_root_refuses_the_document(
    reporter, caplog, project_path
):
    """A path that cannot sit below the workspace root (a ``.code-workspace``
    folder named ``../other``) would mis-locate every finding of its run; the
    document is not written, and the log names the project's own report."""
    model = AshAggregatedResults()
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[
            _project_run("services/api", "API-1", "src/handler.py"),
            _project_run(project_path, "OTHER-1", "src/x.py"),
        ],
    )

    with caplog.at_level("ERROR"):
        assert reporter.report(model) is None

    assert any(
        "projects/" in r.message and "ash.ghas.sarif" in r.message
        for r in caplog.records
    )


def test_merging_several_projects_warns_once_about_the_one_root(reporter, caplog):
    """The model does not record which repository each project is in, so the
    merge is right for a monorepo and wrong for separate repositories; the
    operator is told, once, and pointed at the per-project documents."""
    model = AshAggregatedResults()
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[
            _project_run("services/api", "API-1", "src/handler.py"),
            _project_run("apps/web", "WEB-1", "src/index.js"),
        ],
    )

    with caplog.at_level("WARNING"):
        assert reporter.report(model) is not None

    warnings = [
        r.message
        for r in caplog.records
        if r.levelname == "WARNING" and "one document" in r.message
    ]
    assert len(warnings) == 1
    assert "2 projects" in warnings[0] and "ash.ghas.sarif" in warnings[0]


def test_the_aggregators_workspace_uri_is_read_before_it_is_recomputed(reporter):
    """The aggregator placed the result's first location and stored the answer
    on the result as ``properties.workspace_uri``; the document carries that
    answer as it stands and recomputes only the locations the aggregator did
    not place. The stored value is deliberately not what a recompute would
    give, so the test tells the two apart."""
    run = _project_run("services/api", "API-1", "src/handler.py")
    run.results[0].properties = PropertyBag.model_validate(
        {
            "workspace_project": "services-api",
            "workspace_uri": "services/api/src/handler-as-aggregated.py",
        }
    )
    run.results[0].locations.append(
        Location(
            physicalLocation=PhysicalLocation(
                artifactLocation=ArtifactLocation(uri="src/other.py"),
            )
        )
    )
    model = AshAggregatedResults()
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[run, _project_run("apps/web", "WEB-1", "src/index.js")],
    )

    (out,) = json.loads(reporter.report(model))["runs"]

    api = next(r for r in out["results"] if r["ruleId"] == "API-1")
    assert [
        loc["physicalLocation"]["artifactLocation"]["uri"] for loc in api["locations"]
    ] == ["services/api/src/handler-as-aggregated.py", "services/api/src/other.py"]


def test_an_absolute_uri_is_placed_through_the_runs_project_root(reporter):
    """The run's ``PROJECTROOT`` base is the project's absolute path, the
    argument the helper needs to place an absolute URI inside the project; the
    two-argument call kept such a URI absolute."""
    run = _project_run(
        "services/api",
        "API-1",
        "/ws/services/api/src/handler.py",
        originalUriBaseIds={
            "PROJECTROOT": ArtifactLocation(uri="file:///ws/services/api/")
        },
    )
    model = AshAggregatedResults()
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[run, _project_run("apps/web", "WEB-1", "src/index.js")],
    )

    (out,) = json.loads(reporter.report(model))["runs"]

    api = next(r for r in out["results"] if r["ruleId"] == "API-1")
    assert (
        api["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "services/api/src/handler.py"
    )


def test_the_run_the_real_aggregator_writes_is_read_as_a_project_run(
    reporter, tmp_path
):
    """The fixture above mirrors the aggregator by hand. This one runs the real
    ``rebase_run_for_project`` over a scanner's run and hands its output to the
    reporter, so the key the reporter reads is the key the aggregator writes;
    a rename on either side turns this red."""
    project_dir = tmp_path / "services" / "api"
    project_dir.mkdir(parents=True)
    plan = ProjectPlan(
        key="services-api",
        relative_path="services/api",
        path=project_dir.as_posix(),
        label="api",
        display_label="api",
    )
    scanner_run = _project_run("unused", "API-1", "src/handler.py")
    scanner_run.properties = None

    rebased, _unconvertible = rebase_run_for_project(_run_dict(scanner_run), plan)

    assert rebased["properties"]["workspace_project_path"] == "services/api"
    assert PROJECT_ROOT_URI_BASE_ID in rebased["originalUriBaseIds"]
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                rebased,
                _run_dict(_project_run("apps/web", "WEB-1", "src/index.js")),
            ],
        }
    )

    (run,) = json.loads(reporter.report(model))["runs"]

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
