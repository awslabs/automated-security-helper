# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The GHAS file reads results through the shared SARIF helpers, and says what
it leaves out by kind.

* A result whose ``kind`` is ``open`` or ``review`` is left out of the file with
  every other non-failing kind, while the OCSF report keeps it; the file now
  logs a warning with the count per kind.
* The scanner a result names is read as the flattening reads it, so a result
  that carries ``scanner_details.tool_name`` and no ``scanner_name`` still finds
  the qualified rule of its scanner.
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
    MultiformatMessageString,
    PhysicalLocation,
    PropertyBag,
    ReportingDescriptor,
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


def _model(run: Run) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=[run])
    return model


class TestUnjudgedKindsAreCounted:
    def test_open_and_review_results_left_out_are_counted_per_kind(
        self, reporter, monkeypatch
    ):
        logger = MagicMock()
        monkeypatch.setattr(github_ghas_reporter, "ASH_LOGGER", logger)
        results = [
            Result(ruleId="A", level=Level.error, message=Message(text="a")),
            Result(
                ruleId="B", kind=Kind.open, level=Level.error, message=Message(text="b")
            ),
            Result(
                ruleId="C", kind=Kind.open, level=Level.error, message=Message(text="c")
            ),
            Result(
                ruleId="D",
                kind=Kind.review,
                level=Level.error,
                message=Message(text="d"),
            ),
        ]
        run = Run(tool=Tool(driver=ToolComponent(name="ASH")), results=results)

        doc = json.loads(reporter.report(_model(run)))["runs"][0]

        assert [r["ruleId"] for r in doc["results"]] == ["A"]
        warned = [call.args[0] for call in logger.warning.call_args_list]
        assert any(
            "2 of kind 'open'" in message and "1 of kind 'review'" in message
            for message in warned
        )

    def test_a_pass_or_not_applicable_result_is_not_warned_about(
        self, reporter, monkeypatch
    ):
        logger = MagicMock()
        monkeypatch.setattr(github_ghas_reporter, "ASH_LOGGER", logger)
        results = [
            Result(
                ruleId="P", kind=Kind.pass_, level=Level.none, message=Message(text="p")
            ),
            Result(
                ruleId="N",
                kind=Kind.notApplicable,
                level=Level.none,
                message=Message(text="n"),
            ),
        ]
        run = Run(tool=Tool(driver=ToolComponent(name="ASH")), results=results)

        reporter.report(_model(run))

        warned = [call.args[0] for call in logger.warning.call_args_list]
        assert not any("of kind" in message for message in warned)

    def test_a_document_refused_for_its_base_ids_still_counts_the_kinds(
        self, reporter, monkeypatch
    ):
        """Two runs whose written results refer to one base id that they
        declare differently cannot share a table and the document is not
        written; the open results it held (one of them in the second run, beside
        the failing result that makes the base used there) are still counted in
        the log. An open result alone does not make a base used: it is left
        out of the file."""
        logger = MagicMock()
        monkeypatch.setattr(github_ghas_reporter, "ASH_LOGGER", logger)
        location = Location(
            physicalLocation=PhysicalLocation(
                artifactLocation=ArtifactLocation(uri="a.py", uriBaseId="SRCROOT")
            )
        )

        def run(base_uri: str, *kinds: Kind) -> Run:
            return Run(
                tool=Tool(driver=ToolComponent(name="ASH")),
                results=[
                    Result(
                        ruleId="A",
                        kind=kind,
                        level=Level.error,
                        message=Message(text="a"),
                        locations=[location],
                    )
                    for kind in kinds
                ],
                originalUriBaseIds={"SRCROOT": ArtifactLocation(uri=base_uri)},
            )

        model = AshAggregatedResults()
        model.sarif = SarifReport(
            version="2.1.0",
            runs=[
                run("file:///repo/", Kind.fail),
                run("file:///elsewhere/", Kind.fail, Kind.open),
            ],
        )

        assert reporter.report(model) is None
        warned = [call.args[0] for call in logger.warning.call_args_list]
        assert any("1 of kind 'open'" in message for message in warned)


class TestScannerNameFallback:
    def test_a_result_naming_its_scanner_only_by_scanner_details_finds_its_rule(
        self, reporter
    ):
        def rule(text):
            return ReportingDescriptor(
                id="CVE-2024-1", shortDescription=MultiformatMessageString(text=text)
            )

        run = Run(
            tool=Tool(
                driver=ToolComponent(name="ASH"),
                extensions=[
                    ToolComponent(name="grype", rules=[rule("grype text")]),
                    ToolComponent(name="trivy", rules=[rule("trivy text")]),
                ],
            ),
            results=[
                Result(
                    ruleId="CVE-2024-1",
                    level=Level.error,
                    message=Message(text="grype says"),
                    properties=PropertyBag(scanner_name="grype"),
                ),
                Result(
                    ruleId="CVE-2024-1",
                    level=Level.error,
                    message=Message(text="trivy says"),
                    properties=PropertyBag(scanner_details={"tool_name": "trivy"}),
                ),
            ],
        )

        doc = json.loads(reporter.report(_model(run)))["runs"][0]

        assert [r["ruleId"] for r in doc["results"]] == [
            "CVE-2024-1",
            "trivy/CVE-2024-1",
        ]
