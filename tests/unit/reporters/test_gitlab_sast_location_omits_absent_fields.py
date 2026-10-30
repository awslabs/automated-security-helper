# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A GitLab SAST ``location`` carries only the fields the finding has.

The GitLab security-report schema types ``location.file`` as a string and
``location.start_line`` as a number; neither is required. The reporter built the
object as ``{"file": file_path, "start_line": start_line}`` whatever the result
carried, so a result with no artifact URI, or with a URI but no region, was
written with ``"file": null`` or ``"start_line": null``, and a validator
refuses the whole report for one such finding. An empty ``location`` object is
valid and says what is true.
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


def test_a_result_with_no_location_gets_an_empty_location_object(reporter):
    result = Result(ruleId="B105", message=Message(text="no position"))

    (vuln,) = _report(reporter, result)["vulnerabilities"]

    assert vuln["location"] == {}
    assert "file" not in vuln["location"]
    assert "start_line" not in vuln["location"]


def test_a_result_with_a_file_but_no_region_omits_start_line(reporter):
    result = Result(
        ruleId="B105",
        message=Message(text="file only"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri="app/main.py")
                )
            )
        ],
    )

    (vuln,) = _report(reporter, result)["vulnerabilities"]

    assert vuln["location"] == {"file": "app/main.py"}


def test_a_located_result_keeps_both_fields(reporter):
    result = Result(
        ruleId="B105",
        message=Message(text="located"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri="app/main.py"),
                    region=Region(startLine=7),
                )
            )
        ],
    )

    (vuln,) = _report(reporter, result)["vulnerabilities"]

    assert vuln["location"] == {"file": "app/main.py", "start_line": 7}


def test_a_region_without_a_start_line_omits_start_line(reporter):
    """A region that carries a column or an offset but no line is the input most
    likely to bring ``"start_line": null`` back."""
    result = Result(
        ruleId="B105",
        message=Message(text="column only"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri="app/main.py"),
                    region=Region(startColumn=5, charOffset=10),
                )
            )
        ],
    )

    (vuln,) = _report(reporter, result)["vulnerabilities"]

    assert vuln["location"] == {"file": "app/main.py"}


def _located(region=None, uri="app/main.py") -> Location:
    return Location(
        physicalLocation=PhysicalLocation(
            artifactLocation=ArtifactLocation(uri=uri), region=region
        )
    )


@pytest.mark.parametrize(
    "result",
    [
        Result(ruleId="B105", message=Message(text="no position")),
        Result(
            ruleId="B105", message=Message(text="file only"), locations=[_located()]
        ),
        Result(
            ruleId="B105",
            message=Message(text="region without a line"),
            locations=[_located(Region(startColumn=5))],
        ),
        Result(
            ruleId="B105",
            message=Message(text="located"),
            locations=[_located(Region(startLine=7))],
        ),
    ],
    ids=["no-location", "file-only", "region-without-start-line", "full"],
)
def test_no_location_field_is_ever_null(reporter, result):
    """The schema-level statement: no ``null`` under any vulnerability's
    location, for every location shape a result can carry."""
    report = _report(reporter, result)

    for vuln in report["vulnerabilities"]:
        assert None not in vuln["location"].values()
