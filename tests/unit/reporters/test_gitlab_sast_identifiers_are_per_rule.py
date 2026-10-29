# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No GitLab SAST identifier is shared by every finding of one scanner.

GitLab deduplicates two findings that share a location fingerprint and any one
identifier other than CWE or WASC. The reporter gave every vulnerability from
one scanner a ``{type: scanner, value: <scanner>}`` identifier, so two different
rules firing at the same file and line were duplicates to GitLab and the
Security Dashboard kept the first one only. The scanner is named by the rule
identifier's type, by ``details.scanner`` and by ``scan.scanner`` instead.
"""

import json

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
    GitLabSASTReporter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
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
    return GitLabSASTReporter(context=test_plugin_context)


def _result(rule_id: str) -> Result:
    return Result(
        ruleId=rule_id,
        message=Message(text=f"{rule_id} fired"),
        properties=PropertyBag(scanner_name="bandit"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri="app/main.py"),
                    region=Region(startLine=7),
                )
            )
        ],
    )


def _report(reporter, *results):
    model = AshAggregatedResults()
    model.sarif.runs[0].results = list(results)
    return json.loads(reporter.report(model))


def test_two_rules_at_one_location_share_no_identifier(reporter):
    first, second = _report(reporter, _result("B105"), _result("B602"))[
        "vulnerabilities"
    ]

    shared = {(i["type"], i["value"]) for i in first["identifiers"]} & {
        (i["type"], i["value"]) for i in second["identifiers"]
    }
    assert shared == set(), shared


def test_no_identifier_names_the_scanner_alone(reporter):
    (vuln,) = _report(reporter, _result("B105"))["vulnerabilities"]

    assert [i["type"] for i in vuln["identifiers"]] == [
        "bandit-rule",
        "ash-finding-id",
    ]
    assert all(i["value"] != "bandit" for i in vuln["identifiers"])


def test_the_scanner_is_still_named_in_the_details(reporter):
    (vuln,) = _report(reporter, _result("B105"))["vulnerabilities"]

    assert vuln["identifiers"][0]["type"] == "bandit-rule"
    assert vuln["details"]["scanner"]["value"] == "bandit"
