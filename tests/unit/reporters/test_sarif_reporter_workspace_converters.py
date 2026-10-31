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

import copy
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
    Invocation,
    PropertyBag,
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


def _run(stamped_for: str | None = None) -> Run:
    """A run; with *stamped_for*, the ``properties.workspace_project`` stamp the
    aggregator writes on every run it adds to the unified model."""
    properties = (
        PropertyBag.model_validate({"workspace_project": stamped_for})
        if stamped_for
        else None
    )
    return Run(
        tool=Tool(driver=ToolComponent(name="ASH")), results=[], properties=properties
    )


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


def test_a_single_directory_model_adds_nothing():
    assert workspace_converter_invocations(AshAggregatedResults()) == []


def _says_it_dropped_the_shortfalls(caplog, project: str) -> bool:
    """Whether a WARNING names *project* and says its converter shortfalls are not
    attached to the document. A shortfall that is left out of the document must
    not be left out silently."""
    return any(
        record.levelname == "WARNING"
        and f"'{project}'" in record.getMessage()
        and "not attached" in record.getMessage()
        for record in caplog.records
    )


def _workspace_model(*projects: WorkspaceProjectResult, runs: int = 2):
    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=[_run() for _ in range(runs)])
    model.workspace = WorkspaceResults(
        workspace_file="/w/.ash-workspace.yaml",
        workspace_root="/w",
        exit_code=0,
        projects=list(projects),
    )
    return model


def test_a_project_with_no_run_index_adds_nothing_to_run_zero(
    test_plugin_context, caplog
):
    """A project whose converters failed before it produced a run names no run,
    and its shortfall is never written onto ``runs[0]`` by default. It is not
    dropped silently either: a warning names the project and its converters."""
    model = _workspace_model(
        _project("api", sarif_run_index=0),
        _project(
            "web",
            sarif_run_index=None,
            incomplete_converters={"archive": "crashed before a run existed"},
        ),
    )

    assert workspace_converter_invocations(model) == []
    with caplog.at_level("WARNING"):
        doc = json.loads(SarifReporter(context=test_plugin_context).report(model))
    assert all("invocations" not in run for run in doc["runs"])
    assert _says_it_dropped_the_shortfalls(caplog, "web")
    assert any("archive" in record.getMessage() for record in caplog.records)


def test_a_run_index_past_the_runs_is_not_applied(test_plugin_context, caplog):
    model = _workspace_model(
        _project("api", sarif_run_index=0),
        _project(
            "web", sarif_run_index=7, incomplete_converters={"archive": "the reason"}
        ),
    )

    assert [index for index, _ in workspace_converter_invocations(model)] == [7]
    with caplog.at_level("WARNING"):
        doc = json.loads(SarifReporter(context=test_plugin_context).report(model))
    assert all("invocations" not in run for run in doc["runs"])
    assert _says_it_dropped_the_shortfalls(caplog, "web")


def test_two_converters_give_two_invocations_on_the_projects_run(
    test_plugin_context,
):
    model = _workspace_model(
        _project("api", sarif_run_index=0),
        _project(
            "web",
            sarif_run_index=1,
            incomplete_converters={"jupyter": "second", "archive": "first"},
        ),
    )

    doc = json.loads(SarifReporter(context=test_plugin_context).report(model))

    api_run, web_run = doc["runs"]
    assert "invocations" not in api_run
    assert [i["properties"]["ash_converter"] for i in web_run["invocations"]] == [
        "archive",
        "jupyter",
    ]
    assert all(i["executionSuccessful"] is False for i in web_run["invocations"])


def _scanner_invocation(scanner: str) -> Invocation:
    """What a run carries before the reporter sees it: a scanner's own
    invocation (a content-database age, a notification of its own)."""
    return Invocation(
        executionSuccessful=True,
        properties=PropertyBag.model_validate({"ash_scanner": scanner}),
    )


def test_a_scanners_own_invocations_survive_beside_the_converters(
    test_plugin_context,
):
    """A real run already carries invocations when the reporter reaches it. The
    converter shortfall is appended after them, in place; a reporter that wrote
    the converter list over the run's invocations would pass every other test in
    this file and drop the scanners' invocations from the workspace document."""
    model = _workspace_model(
        _project("api", sarif_run_index=0),
        _project(
            "web", sarif_run_index=1, incomplete_converters={"archive": "crashed"}
        ),
    )
    model.sarif.runs[0].invocations = [_scanner_invocation("semgrep")]
    model.sarif.runs[1].invocations = [_scanner_invocation("bandit")]

    doc = json.loads(SarifReporter(context=test_plugin_context).report(model))

    api_run, web_run = doc["runs"]
    assert [i["properties"]["ash_scanner"] for i in api_run["invocations"]] == [
        "semgrep"
    ]
    assert [
        i["properties"].get("ash_scanner") or i["properties"].get("ash_converter")
        for i in web_run["invocations"]
    ] == ["bandit", "archive"]
    assert [i["executionSuccessful"] for i in web_run["invocations"]] == [
        True,
        False,
    ]


def _stamped_model(*stamps: str, projects):
    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=[_run(stamp) for stamp in stamps])
    model.workspace = WorkspaceResults(
        workspace_file="/w/.ash-workspace.yaml",
        workspace_root="/w",
        exit_code=0,
        projects=list(projects),
    )
    return model


def test_the_invocation_follows_the_run_stamped_for_the_project(test_plugin_context):
    """``sarif_run_index`` was trusted alone, so runs reordered after the index
    was recorded received another project's converter failures. The run that
    carries the project's own stamp is the one written onto, wherever it sits."""
    model = _stamped_model(
        "web",
        "api",
        projects=[
            _project("api", sarif_run_index=1),
            _project(
                "web", sarif_run_index=1, incomplete_converters={"archive": "crashed"}
            ),
        ],
    )

    doc = json.loads(SarifReporter(context=test_plugin_context).report(model))

    web_run, api_run = doc["runs"]
    assert [i["properties"]["workspace_project"] for i in web_run["invocations"]] == [
        "web"
    ]
    assert "invocations" not in api_run


def test_a_run_stamped_for_another_project_is_never_written_onto(
    test_plugin_context, caplog
):
    """No run of the document is the project's: nothing is attached, rather than
    the shortfall landing on whichever run the stale index names, and a warning
    says the shortfalls are not in the document."""
    model = _stamped_model(
        "api",
        "other",
        projects=[
            _project("api", sarif_run_index=0),
            _project(
                "web", sarif_run_index=1, incomplete_converters={"archive": "crashed"}
            ),
        ],
    )

    with caplog.at_level("WARNING"):
        doc = json.loads(SarifReporter(context=test_plugin_context).report(model))

    assert all("invocations" not in run for run in doc["runs"])
    assert _says_it_dropped_the_shortfalls(caplog, "web")


def test_the_stamped_run_wins_over_an_unstamped_run_at_a_stale_index(
    test_plugin_context,
):
    """An unstamped run at the index was taken as soon as it carried no stamp,
    before any run stamped for the project was looked for, so a project whose
    index had gone stale (the default model's empty first run sitting at 0)
    wrote its converter failures onto that run while its own stamped run sat
    untouched beside it."""
    model = _stamped_model(
        None,
        "api",
        "web",
        projects=[
            _project(
                "api", sarif_run_index=0, incomplete_converters={"archive": "crashed"}
            ),
            _project("web", sarif_run_index=2),
        ],
    )

    doc = json.loads(SarifReporter(context=test_plugin_context).report(model))

    first, api_run, web_run = doc["runs"]
    assert "invocations" not in first
    assert [i["properties"]["workspace_project"] for i in api_run["invocations"]] == [
        "api"
    ]
    assert "invocations" not in web_run


def test_an_unstamped_run_in_a_stamped_document_is_not_written_onto(
    test_plugin_context, caplog
):
    """When the document's other runs are stamped, an unstamped run is some other
    run, not the project's: nothing is attached, as for a run stamped for
    another project, and a warning says so."""
    model = _stamped_model(
        None,
        "api",
        projects=[
            _project("api", sarif_run_index=1),
            _project("web", sarif_run_index=0, incomplete_converters={"archive": "x"}),
        ],
    )

    with caplog.at_level("WARNING"):
        doc = json.loads(SarifReporter(context=test_plugin_context).report(model))

    assert all("invocations" not in run for run in doc["runs"])
    assert _says_it_dropped_the_shortfalls(caplog, "web")


def test_an_unstamped_run_at_the_index_is_still_the_projects_run(
    test_plugin_context,
):
    """A document whose runs carry no stamp cannot be checked; the index is the
    only word there is and is used as before."""
    model = _workspace_model(
        _project("api", sarif_run_index=0),
        _project("web", sarif_run_index=1, incomplete_converters={"archive": "x"}),
    )

    doc = json.loads(SarifReporter(context=test_plugin_context).report(model))

    assert "invocations" not in doc["runs"][0]
    assert len(doc["runs"][1]["invocations"]) == 1


def _dump(model: AshAggregatedResults) -> str:
    """The model's SARIF as text, so a later comparison sees an append to a list
    the model holds, which a snapshot of the lists themselves would share."""
    return model.sarif.model_dump_json(
        by_alias=True, exclude_none=True, exclude_unset=True
    )


def test_the_scans_own_sarif_is_left_alone(model, test_plugin_context):
    before = copy.deepcopy([run.invocations for run in model.sarif.runs])
    before_dump = _dump(model)

    SarifReporter(context=test_plugin_context).report(model)

    # The invocation is written into the emitted document only; the model's
    # own runs keep whatever they held (the Run default is an empty list).
    assert [run.invocations for run in model.sarif.runs] == before
    assert _dump(model) == before_dump
    assert not model.sarif.runs[1].invocations


def test_a_run_that_already_has_invocations_is_left_alone_too(test_plugin_context):
    """The case the reporter appends to in its copy: runs that already hold a
    scanner's invocation. The model keeps exactly those and no converter one."""
    model = _workspace_model(
        _project("api", sarif_run_index=0),
        _project(
            "web", sarif_run_index=1, incomplete_converters={"archive": "crashed"}
        ),
    )
    model.sarif.runs[0].invocations = [_scanner_invocation("semgrep")]
    model.sarif.runs[1].invocations = [_scanner_invocation("bandit")]
    before_dump = _dump(model)

    SarifReporter(context=test_plugin_context).report(model)

    assert _dump(model) == before_dump
    assert len(model.sarif.runs[1].invocations) == 1


def test_a_second_report_does_not_double_the_converter_invocations(
    model, test_plugin_context
):
    reporter = SarifReporter(context=test_plugin_context)

    first = json.loads(reporter.report(model))
    second = json.loads(reporter.report(model))

    assert second == first
    assert len(second["runs"][1]["invocations"]) == 1
