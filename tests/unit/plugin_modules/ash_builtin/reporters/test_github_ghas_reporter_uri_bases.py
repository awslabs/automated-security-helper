# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The GHAS document declares every base id its locations refer to.

A location keeps its ``uriBaseId`` when its run is not rebased below a workspace
root. The table the emitted run declares was written for a one-run document
only, so a multi-run document whose runs name no project referred to base ids it
never declared, and GitHub read those URIs against the repository root. The
table is now the merge of the unrebased runs' tables; two runs declaring one key
differently cannot share it, and the document is refused.
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


def _run(rule_id: str, bases: dict) -> Run:
    """A run whose one result is located below the base id SRCROOT."""
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
                                uri="src/a.py", uriBaseId="SRCROOT"
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
            _run("R2", {"OTHER": "file:///other/"}),
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
