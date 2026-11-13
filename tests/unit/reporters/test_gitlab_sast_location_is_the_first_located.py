# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A GitLab SAST location is one SARIF location, not a blend of several.

The reporter looped over every location, overwrote the file each time and never
reset the line or the snippet, so a result with two locations was reported at
the last location's file with an earlier location's line and source excerpt, a
position that exists in neither. The first located location is reported, with
its own line and snippet.
"""

import json

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
    GitLabSASTReporter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactContent,
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    Region,
    Result,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def reporter(test_plugin_context):
    return GitLabSASTReporter(context=test_plugin_context)


def _report(reporter, result):
    model = AshAggregatedResults()
    model.sarif.runs[0].results = [result]
    return json.loads(reporter.report(model))


def test_the_first_located_location_is_reported_whole(reporter):
    result = Result(
        ruleId="SECRET-AWS-KEY",
        message=Message(text="secret"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri="src/first.py"),
                    region=Region(
                        startLine=3, snippet=ArtifactContent(text="first = 'x'")
                    ),
                )
            ),
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri="src/second.py")
                )
            ),
        ],
    )

    (vuln,) = _report(reporter, result)["vulnerabilities"]

    assert vuln["location"] == {"file": "src/first.py", "start_line": 3}
    assert vuln["raw_source_code_extract"] == "first = 'x'"


def test_a_location_without_a_file_is_passed_over(reporter):
    # A SARIF physical location names an artifact location or an address; one
    # whose artifact location carries no uri is a location without a file.
    result = Result(
        ruleId="B105",
        message=Message(text="m"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(), region=Region(startLine=9)
                )
            ),
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri="src/real.py"),
                    region=Region(startLine=4),
                )
            ),
        ],
    )

    (vuln,) = _report(reporter, result)["vulnerabilities"]

    assert vuln["location"] == {"file": "src/real.py", "start_line": 4}
