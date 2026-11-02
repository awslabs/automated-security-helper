# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A finding's fallback uid tells distinct findings apart.

When the run-level flattening gives a result no id (it raises, or its rows do
not line up with the results), the OCSF ``finding_info.uid`` comes from the
result alone. That key hashed the rule, message, file and lines only, joined
with a raw ``|``, so three pairs of distinct findings shared one uid and a SIEM
merged each pair: two workspace projects with the same project-relative file,
two scanners firing one rule id at one line, and two identical results in one
run; and ``("a|b", "c")`` keyed the same as ``("a", "b|c")``.
"""

import json
import uuid

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
    _FINDING_UID_NAMESPACE,
    OcsfReporter,
    _identity_key,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Level,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Region,
    Result,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def reporter(test_plugin_context):
    return OcsfReporter(context=test_plugin_context)


@pytest.fixture
def no_flattening(monkeypatch):
    """A model whose flattening raises, so every uid takes the fallback path."""

    def _raise(self):
        raise RuntimeError("the flattening is unavailable")

    monkeypatch.setattr(AshAggregatedResults, "to_flat_vulnerabilities", _raise)


def _result(rule_id: str = "R1", text: str = "m", **properties) -> Result:
    return Result(
        ruleId=rule_id,
        level=Level.error,
        message=Message(text=text),
        properties=PropertyBag(**properties) if properties else None,
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri="src/index.js"),
                    region=Region(startLine=7, endLine=7),
                )
            )
        ],
    )


def _uids(reporter, *results: Result) -> list:
    model = AshAggregatedResults()
    model.sarif.runs[0].results = list(results)
    return [r["finding_info"]["uid"] for r in json.loads(reporter.report(model))]


class TestTheIdentityKey:
    def test_a_separator_inside_a_part_is_escaped(self):
        assert _identity_key(_result("a|b", "c"), "a|b") != _identity_key(
            _result("a", "b|c"), "a"
        )

    def test_the_scanner_is_part_of_the_key(self):
        grype = _result(scanner_name="grype")
        trivy = _result(scanner_name="trivy")

        assert _identity_key(grype, "R1") != _identity_key(trivy, "R1")

    def test_the_workspace_project_is_part_of_the_key(self):
        api = _result(workspace_project="api")
        web = _result(workspace_project="web")

        assert _identity_key(api, "R1") != _identity_key(web, "R1")


class TestTheFallbackUidsOfAReport:
    def test_two_identical_results_in_one_run_are_two_findings(
        self, reporter, no_flattening
    ):
        first, second = _uids(reporter, _result(), _result())

        assert first != second

    def test_the_first_of_two_identical_results_keeps_the_unnumbered_key(
        self, reporter, no_flattening
    ):
        """Only the second and later results carry an occurrence number, so a
        finding alone with its key keeps its uid when a duplicate appears."""
        (alone,) = _uids(reporter, _result())
        first, _ = _uids(reporter, _result(), _result())

        assert first == alone
        assert alone == str(
            uuid.uuid5(_FINDING_UID_NAMESPACE, _identity_key(_result(), "R1"))
        )

    def test_the_same_file_in_two_workspace_projects_is_two_findings(
        self, reporter, no_flattening
    ):
        first, second = _uids(
            reporter,
            _result(workspace_project="api"),
            _result(workspace_project="web"),
        )

        assert first != second

    def test_one_rule_fired_by_two_scanners_is_two_findings(
        self, reporter, no_flattening
    ):
        first, second = _uids(
            reporter, _result(scanner_name="grype"), _result(scanner_name="trivy")
        )

        assert first != second
