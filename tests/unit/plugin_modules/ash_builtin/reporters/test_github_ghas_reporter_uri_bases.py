# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The GHAS document declares every base id its locations refer to.

A location keeps its ``uriBaseId`` when its run is not rebased below a workspace
root. The table the emitted run declares was written for a one-run document
only, so a multi-run document whose runs name no project referred to base ids it
never declared, and GitHub read those URIs against the repository root. The
table is now the merge of the unrebased runs' tables, cut to the bases a result
refers to and the bases those are anchored to (a base nothing uses is left out,
so the merge keeps a base only from a run whose result is located below it);
two runs declaring one such key differently cannot share it, and the document
is refused.
"""

import json
from unittest.mock import MagicMock

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters import (
    github_ghas_reporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.github_ghas_reporter import (
    GHASReporter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Kind,
    Level,
    Location,
    Message,
    PhysicalLocation,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()


@pytest.fixture
def reporter(test_plugin_context):
    return GHASReporter(context=test_plugin_context)


def _run(rule_id: str, bases: dict, base: str = "SRCROOT") -> Run:
    """A run whose one result is located below the base id *base*."""
    return Run(
        tool=Tool(driver=ToolComponent(name="ASH")),
        results=[
            Result(
                ruleId=rule_id,
                level=Level.error,
                message=Message(text=f"{rule_id} fired"),
                locations=[
                    Location(
                        physicalLocation=PhysicalLocation(
                            artifactLocation=ArtifactLocation(
                                uri="src/a.py", uriBaseId=base
                            ),
                            region=Region(startLine=1),
                        )
                    )
                ],
            )
        ],
        originalUriBaseIds={
            key: ArtifactLocation(uri=uri) for key, uri in bases.items()
        },
    )


def _model(*runs: Run) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=list(runs))
    return model


class TestMultiRunBaseIds:
    def test_a_base_a_location_refers_to_is_declared(self, reporter):
        runs = [
            _run("R1", {"SRCROOT": "file:///repo/"}),
            _run("R2", {"SRCROOT": "file:///repo/"}),
        ]

        doc = json.loads(reporter.report(_model(*runs)))["runs"][0]

        used = {
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"]
            for result in doc["results"]
        }
        assert used == {"SRCROOT"}
        assert doc["originalUriBaseIds"] == {"SRCROOT": {"uri": "file:///repo/"}}

    def test_the_bases_of_different_runs_are_merged(self, reporter):
        runs = [
            _run("R1", {"SRCROOT": "file:///repo/"}),
            _run("R2", {"OTHER": "file:///other/"}, base="OTHER"),
        ]

        doc = json.loads(reporter.report(_model(*runs)))["runs"][0]

        assert doc["originalUriBaseIds"] == {
            "SRCROOT": {"uri": "file:///repo/"},
            "OTHER": {"uri": "file:///other/"},
        }

    def test_one_base_declared_two_ways_refuses_the_document(self, reporter):
        runs = [
            _run("R1", {"SRCROOT": "file:///repo/"}),
            _run("R2", {"SRCROOT": "file:///elsewhere/"}),
        ]

        assert reporter.report(_model(*runs)) is None

    def test_the_refusal_names_the_base_both_declarations_and_the_runs(
        self, reporter, monkeypatch
    ):
        logger = MagicMock()
        monkeypatch.setattr(github_ghas_reporter, "ASH_LOGGER", logger)
        runs = [
            _run("R1", {"SRCROOT": "file:///repo/"}),
            _run("R2", {"SRCROOT": "file:///elsewhere/"}),
        ]

        assert reporter.report(_model(*runs)) is None

        (message,) = [call.args[0] for call in logger.error.call_args_list]
        assert "'SRCROOT'" in message
        assert "file:///repo/" in message
        assert "file:///elsewhere/" in message
        assert "runs 0 and 1" in message


class TestOnlyWrittenResultsCount:
    """A base counts as used only when a location the file writes refers to it."""

    def test_a_base_only_a_left_out_result_uses_does_not_refuse_the_document(
        self, reporter
    ):
        """The second run's one result is an open one, which the file leaves
        out; its table disagreed with the first run's about SRCROOT, and the
        whole document was refused, the first run's findings with it."""
        left_out = _run("R2", {"SRCROOT": "file:///elsewhere/"})
        left_out.results[0].kind = Kind.open
        runs = [_run("R1", {"SRCROOT": "file:///repo/"}), left_out]

        output = reporter.report(_model(*runs))

        assert output is not None
        doc = json.loads(output)["runs"][0]
        assert [r["ruleId"] for r in doc["results"]] == ["R1"]
        assert doc["originalUriBaseIds"] == {"SRCROOT": {"uri": "file:///repo/"}}

    def test_a_base_only_a_location_with_no_uri_uses_does_not_refuse_the_document(
        self, reporter
    ):
        """A location with no uri is not written, so the base id it names is
        not written either."""
        no_uri = _run("R2", {"SRCROOT": "file:///elsewhere/"})
        no_uri.results[0].locations[0].physicalLocation.root.artifactLocation.uri = None
        runs = [_run("R1", {"SRCROOT": "file:///repo/"}), no_uri]

        output = reporter.report(_model(*runs))

        assert output is not None
        doc = json.loads(output)["runs"][0]
        assert doc["originalUriBaseIds"] == {"SRCROOT": {"uri": "file:///repo/"}}


class TestOnlyReferencedBasesAreDeclared:
    def test_a_base_no_result_refers_to_is_not_declared(self, reporter):
        run = _run("R1", {"SRCROOT": "file:///repo/", "UNUSED": "file:///unused/"})

        doc = json.loads(reporter.report(_model(run)))["runs"][0]

        assert doc["originalUriBaseIds"] == {"SRCROOT": {"uri": "file:///repo/"}}

    def test_the_base_a_used_base_is_anchored_to_is_declared_with_it(self, reporter):
        run = _run(
            "R1", {"SRCROOT": "src/", "REPOROOT": "file:///repo/", "OTHER": "x/"}
        )
        run.originalUriBaseIds["SRCROOT"] = ArtifactLocation(
            uri="src/", uriBaseId="REPOROOT"
        )

        doc = json.loads(reporter.report(_model(run)))["runs"][0]

        assert doc["originalUriBaseIds"] == {
            "SRCROOT": {"uri": "src/", "uriBaseId": "REPOROOT"},
            "REPOROOT": {"uri": "file:///repo/"},
        }

    def test_runs_that_disagree_about_an_unused_base_still_share_a_document(
        self, reporter
    ):
        runs = [
            _run("R1", {"SRCROOT": "file:///repo/", "UNUSED": "file:///a/"}),
            _run("R2", {"SRCROOT": "file:///repo/", "UNUSED": "file:///b/"}),
        ]

        doc = json.loads(reporter.report(_model(*runs)))["runs"][0]

        assert doc["originalUriBaseIds"] == {"SRCROOT": {"uri": "file:///repo/"}}
