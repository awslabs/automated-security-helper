# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The slim GHAS result keeps the SARIF fields GitHub reads to classify it.

* ``kind``: a result ASH marked notApplicable (a cdk-nag rule that was not
  evaluated) was uploaded as an alert: the slim copy dropped the kind, and GitHub
  reads no kind anyway, so the result is left out of the file instead.
* ``suppressions``: dropped, a suppressed result the file keeps (exclude_suppressed
  off) reached GitHub as an open alert like any other.
* ``uriBaseId`` and the run's ``originalUriBaseIds``: dropped, a URI a scanner
  anchored to a declared base read as relative to the repository root.
* ``automationDetails.id``: absent, the per-project documents of a workspace
  are identical in tool identity, so each upload replaces the previous
  project's analysis unless the upload names a category. The project key
  becomes the category when ``emit_automation_details`` asks for it; an id in
  the file overrides the category the upload-sarif action is given, so it is
  not written unasked.
"""

import json
from types import SimpleNamespace

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.github_ghas_reporter import (
    GHASReporter,
    GHASReporterConfig,
    GHASReporterConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Kind,
    Kind1,
    Level,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Region,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    State,
    Suppression,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()


@pytest.fixture
def reporter(test_plugin_context):
    return GHASReporter(context=test_plugin_context)


def _model(*runs: Run) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=list(runs))
    return model


def _run(*results: Result, **run_kwargs) -> Run:
    return Run(
        tool=Tool(driver=ToolComponent(name="ASH")), results=list(results), **run_kwargs
    )


class TestKind:
    @pytest.mark.parametrize(
        "kind", [Kind.notApplicable, Kind.pass_, Kind.informational, Kind.open]
    )
    def test_a_result_whose_kind_is_not_fail_is_left_out(self, reporter, kind):
        """GitHub's documented result properties do not include ``kind``, so a
        notApplicable result it was given (a cdk-nag rule that was not
        evaluated) opened an alert like a failing one."""
        kept = Result(ruleId="R", level=Level.error, message=Message(text="m"))
        other = Result(
            ruleId="CDK-NAG-1",
            level=Level.error,
            kind=kind,
            message=Message(text="not evaluated"),
        )

        out = json.loads(reporter.report(_model(_run(kept, other))))["runs"][0]

        assert [r["ruleId"] for r in out["results"]] == ["R"]

    def test_a_left_out_result_does_not_score_its_rule(self, reporter):
        """One notApplicable error-level result and one failing note-level
        result of a rule with no security-severity: the rule scores as the
        result the file carries, not as the one it leaves out."""
        rule = ReportingDescriptor(id="R")
        run = Run(
            tool=Tool(driver=ToolComponent(name="ASH", rules=[rule])),
            results=[
                Result(
                    ruleId="R",
                    level=Level.error,
                    kind=Kind.notApplicable,
                    message=Message(text="not evaluated"),
                ),
                Result(ruleId="R", level=Level.note, message=Message(text="m")),
            ],
        )

        out = json.loads(reporter.report(_model(run)))["runs"][0]

        (slim_rule,) = out["tool"]["driver"]["rules"]
        assert slim_rule["properties"]["security-severity"] == "3.0"

    def test_a_failing_result_carries_no_kind_key(self, reporter):
        result = Result(ruleId="R", level=Level.error, message=Message(text="m"))

        (slim,) = json.loads(reporter.report(_model(_run(result))))["runs"][0][
            "results"
        ]

        assert "kind" not in slim


class TestSuppressions:
    def test_a_kept_suppressed_result_carries_its_suppressions(
        self, test_plugin_context
    ):
        reporter = GHASReporter(
            context=test_plugin_context,
            config=GHASReporterConfig(
                options=GHASReporterConfigOptions(exclude_suppressed=False)
            ),
        )
        result = Result(
            ruleId="R",
            level=Level.error,
            message=Message(text="m"),
            suppressions=[
                Suppression(
                    kind=Kind1.external,
                    state=State.accepted,
                    justification="reviewed",
                )
            ],
        )

        (slim,) = json.loads(reporter.report(_model(_run(result))))["runs"][0][
            "results"
        ]

        assert slim["suppressions"] == [
            {"kind": "external", "state": "accepted", "justification": "reviewed"}
        ]

    def test_a_suppression_with_no_kind_carries_no_kind_key(self):
        """``_level_value(None)`` is the text "None", which is no suppression
        kind; the key is left out instead."""
        suppression = SimpleNamespace(
            kind=None, state=State.accepted, justification="reviewed"
        )

        assert GHASReporter._slim_suppression(suppression) == {
            "state": "accepted",
            "justification": "reviewed",
        }

    def test_an_unsuppressed_result_carries_no_suppressions_key(self, reporter):
        result = Result(ruleId="R", level=Level.error, message=Message(text="m"))

        (slim,) = json.loads(reporter.report(_model(_run(result))))["runs"][0][
            "results"
        ]

        assert "suppressions" not in slim


class TestUriBaseIds:
    def test_an_anchored_uri_keeps_its_base_id_and_the_run_its_bases(self, reporter):
        result = Result(
            ruleId="R",
            level=Level.error,
            message=Message(text="m"),
            locations=[
                Location(
                    physicalLocation=PhysicalLocation(
                        artifactLocation=ArtifactLocation(
                            uri="src/a.py", uriBaseId="%SRCROOT%"
                        ),
                        region=Region(startLine=1),
                    )
                )
            ],
        )
        run = _run(
            result,
            originalUriBaseIds={"%SRCROOT%": ArtifactLocation(uri="file:///repo/")},
        )

        out = json.loads(reporter.report(_model(run)))["runs"][0]

        artifact = out["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]
        assert artifact == {"uri": "src/a.py", "uriBaseId": "%SRCROOT%"}
        assert out["originalUriBaseIds"] == {"%SRCROOT%": {"uri": "file:///repo/"}}

    def test_a_chained_base_keeps_its_own_base_id(self, reporter):
        """A base anchored to another base (SARIF 3.4.4) kept only its uri, so
        it was emitted as a relative base with nothing to resolve against."""
        result = Result(
            ruleId="R",
            level=Level.error,
            message=Message(text="m"),
            locations=[
                Location(
                    physicalLocation=PhysicalLocation(
                        artifactLocation=ArtifactLocation(
                            uri="a.py", uriBaseId="SRCROOT"
                        ),
                    )
                )
            ],
        )
        run = _run(
            result,
            originalUriBaseIds={
                "SRCROOT": ArtifactLocation(uri="src/", uriBaseId="REPOROOT"),
                "REPOROOT": ArtifactLocation(uri="file:///repo/"),
            },
        )

        out = json.loads(reporter.report(_model(run)))["runs"][0]

        assert out["originalUriBaseIds"] == {
            "SRCROOT": {"uri": "src/", "uriBaseId": "REPOROOT"},
            "REPOROOT": {"uri": "file:///repo/"},
        }

    def test_a_rebased_workspace_uri_carries_no_base_id(self, reporter):
        def project_run(path: str) -> Run:
            return Run(
                tool=Tool(driver=ToolComponent(name="ASH")),
                results=[
                    Result(
                        ruleId="R",
                        level=Level.error,
                        message=Message(text="m"),
                        locations=[
                            Location(
                                physicalLocation=PhysicalLocation(
                                    artifactLocation=ArtifactLocation(
                                        uri="src/a.py", uriBaseId="PROJECTROOT"
                                    )
                                )
                            )
                        ],
                    )
                ],
                properties=PropertyBag.model_validate(
                    {"workspace_project": path, "workspace_project_path": path}
                ),
            )

        out = json.loads(reporter.report(_model(project_run("a"), project_run("b"))))[
            "runs"
        ][0]

        artifacts = [
            r["locations"][0]["physicalLocation"]["artifactLocation"]
            for r in out["results"]
        ]
        assert artifacts == [{"uri": "a/src/a.py"}, {"uri": "b/src/a.py"}]
        assert "originalUriBaseIds" not in out


def _per_project_model() -> AshAggregatedResults:
    model = _model(
        _run(Result(ruleId="R", level=Level.error, message=Message(text="m")))
    )
    model.metadata.workspace_project = "api"
    return model


class TestAutomationDetails:
    def test_a_per_project_scan_names_its_project_when_asked(self, test_plugin_context):
        reporter = GHASReporter(
            context=test_plugin_context,
            config=GHASReporterConfig(
                options=GHASReporterConfigOptions(emit_automation_details=True)
            ),
        )

        out = json.loads(reporter.report(_per_project_model()))["runs"][0]

        assert out["automationDetails"] == {"id": "ash/api/"}

    def test_a_per_project_scan_carries_none_by_default(self, reporter):
        """The upload-sarif action fills automationDetails only on a run that
        has none, so an id written unasked overrides the category an operator
        already gives the upload and moves it to a new analysis."""
        out = json.loads(reporter.report(_per_project_model()))["runs"][0]

        assert "automationDetails" not in out

    @pytest.mark.parametrize("run_count", [1, 2], ids=["one-run", "two-runs"])
    def test_a_unified_model_names_no_project_whatever_its_run_count(
        self, test_plugin_context, run_count
    ):
        """One run is left in a unified model when every other project was
        skipped. Its stamp used to become the category, so the category came
        and went between two scans of one workspace, and it was the per-project
        document's category with the other document's URI base."""
        reporter = GHASReporter(
            context=test_plugin_context,
            config=GHASReporterConfig(
                options=GHASReporterConfigOptions(emit_automation_details=True)
            ),
        )
        runs = [
            _run(
                Result(ruleId="R", level=Level.error, message=Message(text="m")),
                properties=PropertyBag.model_validate(
                    {"workspace_project": key, "workspace_project_path": key}
                ),
            )
            for key in ("web", "api")[:run_count]
        ]

        out = json.loads(reporter.report(_model(*runs)))["runs"][0]

        assert "automationDetails" not in out

    def test_a_single_directory_scan_carries_no_automation_details(self, reporter):
        model = _model(
            _run(Result(ruleId="R", level=Level.error, message=Message(text="m")))
        )

        out = json.loads(reporter.report(model))["runs"][0]

        assert "automationDetails" not in out
