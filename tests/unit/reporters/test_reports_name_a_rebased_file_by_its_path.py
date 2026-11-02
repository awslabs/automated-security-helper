# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The GitLab SAST, HTML and OCSF reports name a rebased file by its path.

``rebase_run_for_project`` writes a rebased ``file:`` uri percent-encoded
(``api/my%20file.py``) and records the path it names in the result property
``workspace_artifact_path``. The flattened finding and the listed findings read
that property. These three reports read ``artifactLocation.uri`` as a path
straight off the SARIF result, so for a workspace scan they named
``api/my%20file.py``, which names no file: GitLab could not link the finding to
its file, and the OCSF path and title did not match the flat reports.

The property belongs to the first location (the aggregator records it for
index 0 only), so the other locations keep the uri as it was written.
"""

import json
from datetime import datetime, timezone

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
    GitLabSASTReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
    OcsfReporter,
)
from automated_security_helper.schemas.ocsf.ocsf_vulnerability_finding import (
    Metadata,
    Product,
)
from automated_security_helper.schemas.sarif_schema_model import Result

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()

#: Spelled out here so a control that records nothing reads the same before and
#: after the readers know the property.
ARTIFACT_PATH_PROPERTY = "workspace_artifact_path"

#: The written uri and the path it names, for a space, a non-ASCII letter and a
#: literal percent sign (written ``%2541``, named ``%41``).
REBASED = [
    ("api/my%20file.py", "api/my file.py"),
    ("api/caf%C3%A9.py", "api/café.py"),
    ("api/x%2541.py", "api/x%41.py"),
]


def _result(uri, properties=None, extra_locations=None):
    result_properties = {"scanner_name": "bandit"}
    result_properties.update(properties or {})
    locations = [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": 3},
            }
        }
    ]
    locations.extend(extra_locations or [])
    return Result.model_validate(
        {
            "ruleId": "B101",
            "level": "error",
            "message": {"text": "assert used"},
            "properties": result_properties,
            "locations": locations,
        }
    )


def _located(uri):
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": 9},
        }
    }


def _now_ms():
    return int(datetime.now(timezone.utc).timestamp() * 1000)


@pytest.fixture
def metadata():
    return Metadata(
        product=Product(
            name="Automated Security Helper",
            vendor_name="Amazon Web Services",
            version="1.0.0",
        ),
        version="1.1.0",
        logged_time=_now_ms(),
    )


# GitLab SAST


def _gitlab_file(test_plugin_context, result):
    reporter = GitLabSASTReporter(context=test_plugin_context)
    model = AshAggregatedResults()
    model.sarif.runs[0].results = [result]
    (vulnerability,) = json.loads(reporter.report(model))["vulnerabilities"]
    return vulnerability["location"]["file"]


@pytest.mark.parametrize("written, named", REBASED)
def test_gitlab_locates_a_rebased_file_by_its_path(test_plugin_context, written, named):
    result = _result(written, {ARTIFACT_PATH_PROPERTY: named})

    assert _gitlab_file(test_plugin_context, result) == named


def test_gitlab_keeps_a_uri_with_no_recorded_path(test_plugin_context):
    """Control, green on both sides: a scanner's own text is not rewritten."""
    assert _gitlab_file(test_plugin_context, _result("100%.py")) == "100%.py"


@pytest.mark.parametrize("recorded", ["", "   ", 7, None])
def test_gitlab_ignores_a_recorded_path_that_is_not_text(test_plugin_context, recorded):
    """Control, green on both sides: only a non-empty string names a path."""
    result = _result("api/my%20file.py", {ARTIFACT_PATH_PROPERTY: recorded})

    assert _gitlab_file(test_plugin_context, result) == "api/my%20file.py"


def test_gitlab_does_not_replace_a_file_uri(test_plugin_context):
    """Control, green on both sides: a ``file:`` uri is not the rebased shape."""
    result = _result("file:///work/app.py", {ARTIFACT_PATH_PROPERTY: "other.py"})

    assert _gitlab_file(test_plugin_context, result) == "file:///work/app.py"


def test_gitlab_applies_the_recorded_path_to_the_first_location_only(
    test_plugin_context,
):
    """Control, green on both sides: the property names location 0's path.

    Location 0 carries no uri, so the reported file is the second location's,
    which the property does not describe.
    """
    result = Result.model_validate(
        {
            "ruleId": "B101",
            "level": "error",
            "message": {"text": "assert used"},
            "properties": {ARTIFACT_PATH_PROPERTY: "api/first file.py"},
            "locations": [
                {"physicalLocation": {"artifactLocation": {}}},
                _located("api/second%20file.py"),
            ],
        }
    )

    assert _gitlab_file(test_plugin_context, result) == "api/second%20file.py"


# HTML


@pytest.mark.parametrize("written, named", REBASED)
def test_html_shows_a_rebased_file_by_its_path(written, named):
    result = _result(written, {ARTIFACT_PATH_PROPERTY: named})

    assert HtmlReporter._location_str(result) == f"{named}:3"


def test_html_shows_a_uri_with_no_recorded_path_as_written():
    """Control, green on both sides."""
    assert HtmlReporter._location_str(_result("100%.py")) == "100%.py:3"


@pytest.mark.parametrize("recorded", ["", "   ", 7, None])
def test_html_ignores_a_recorded_path_that_is_not_text(recorded):
    """Control, green on both sides."""
    result = _result("api/my%20file.py", {ARTIFACT_PATH_PROPERTY: recorded})

    assert HtmlReporter._location_str(result) == "api/my%20file.py:3"


def test_html_does_not_replace_a_file_uri():
    """Control, green on both sides."""
    result = _result("file:///work/app.py", {ARTIFACT_PATH_PROPERTY: "other.py"})

    assert HtmlReporter._location_str(result) == "file:///work/app.py:3"


# OCSF


def _ocsf_finding(test_plugin_context, metadata, result):
    reporter = OcsfReporter(context=test_plugin_context)
    return reporter._create_vulnerability_finding(result, metadata, _now_ms())


@pytest.mark.parametrize("written, named", REBASED)
def test_ocsf_names_a_rebased_file_by_its_path(
    test_plugin_context, metadata, written, named
):
    result = _result(written, {ARTIFACT_PATH_PROPERTY: named})

    finding = _ocsf_finding(test_plugin_context, metadata, result)

    (code,) = finding.vulnerabilities[0].affected_code
    assert code.file.path == named
    assert code.file.name == named.rsplit("/", 1)[-1]
    assert f" in {code.file.name} - " in finding.finding_info.title


def test_ocsf_keeps_a_uri_with_no_recorded_path(test_plugin_context, metadata):
    """Control, green on both sides."""
    finding = _ocsf_finding(test_plugin_context, metadata, _result("100%.py"))

    (code,) = finding.vulnerabilities[0].affected_code
    assert code.file.path == "100%.py"


@pytest.mark.parametrize("recorded", ["", "   ", 7, None])
def test_ocsf_ignores_a_recorded_path_that_is_not_text(
    test_plugin_context, metadata, recorded
):
    """Control, green on both sides."""
    result = _result("api/my%20file.py", {ARTIFACT_PATH_PROPERTY: recorded})

    finding = _ocsf_finding(test_plugin_context, metadata, result)

    (code,) = finding.vulnerabilities[0].affected_code
    assert code.file.path == "api/my%20file.py"


def test_ocsf_does_not_replace_a_file_uri(test_plugin_context, metadata):
    """Control, green on both sides."""
    result = _result("file:///work/app.py", {ARTIFACT_PATH_PROPERTY: "other.py"})

    finding = _ocsf_finding(test_plugin_context, metadata, result)

    (code,) = finding.vulnerabilities[0].affected_code
    assert code.file.path == "file:///work/app.py"


def test_ocsf_applies_the_recorded_path_to_the_first_location_only(
    test_plugin_context, metadata
):
    """Control, green on both sides: a later location keeps its written uri."""
    result = _result(
        "api/my%20file.py",
        {ARTIFACT_PATH_PROPERTY: "api/my file.py"},
        extra_locations=[_located("api/other%20file.py")],
    )

    finding = _ocsf_finding(test_plugin_context, metadata, result)

    paths = [code.file.path for code in finding.vulnerabilities[0].affected_code]
    assert paths == ["api/my file.py", "api/other%20file.py"]


def test_the_reports_and_the_flat_model_spell_the_property_alike():
    from automated_security_helper.models import flat_vulnerability

    assert flat_vulnerability.ARTIFACT_PATH_PROPERTY == ARTIFACT_PATH_PROPERTY
