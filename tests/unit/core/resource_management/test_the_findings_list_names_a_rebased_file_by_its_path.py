# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The listed findings of a workspace results document name a file by its path.

``rebase_run_for_project`` writes a rebased ``file:`` uri percent-encoded
(``my%20file.py``) and records the path it names in a result property. The
flattened finding reads that property. ``add_findings_list``, which builds the
findings an MCP client reads from ``get_scan_results(actionable_only=True)``,
read the uri as it was written, so the same finding was listed under
``api/my%20file.py``, a path that names no file, while the flat reports named
``api/my file.py``.
"""

import copy

import pytest

from automated_security_helper.core.resource_management import result_filters
from automated_security_helper.core.resource_management.result_filters import (
    add_findings_list,
)
from automated_security_helper.models import flat_vulnerability

pytestmark = pytest.mark.unit

#: Spelled out here so a control that has nothing to record reads the same
#: before and after the property exists.
ARTIFACT_PATH_PROPERTY = "workspace_artifact_path"


def _document(uri, properties=None):
    result_properties = {"scanner_name": "bandit"}
    result_properties.update(properties or {})
    return {
        "raw_results": {
            "sarif": {
                "runs": [
                    {
                        "tool": {"driver": {"name": "bandit"}},
                        "results": [
                            {
                                "ruleId": "B101",
                                "level": "error",
                                "message": {"text": "assert used"},
                                "properties": result_properties,
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": uri},
                                            "region": {"startLine": 3},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        }
    }


@pytest.mark.parametrize(
    "written, named",
    [
        ("api/my%20file.py", "api/my file.py"),
        ("api/caf%C3%A9.py", "api/café.py"),
        ("api/x%2541.py", "api/x%41.py"),
    ],
)
def test_a_rebased_uri_is_listed_under_the_path_it_names(written, named):
    document = _document(written, {ARTIFACT_PATH_PROPERTY: named})

    listed = add_findings_list(copy.deepcopy(document))

    assert listed["findings"][0]["file_path"] == named, listed["findings"]


def test_a_uri_with_no_recorded_path_is_listed_as_written():
    """Control, green on both sides: a scanner's own text is not rewritten."""
    listed = add_findings_list(_document("100%.py"))

    assert listed["findings"][0]["file_path"] == "100%.py", listed["findings"]


@pytest.mark.parametrize("recorded", ["", "   ", 7, None])
def test_a_recorded_path_that_is_not_text_is_ignored(recorded):
    """Control, green on both sides: only a non-empty string names a path."""
    document = _document("api/my%20file.py", {ARTIFACT_PATH_PROPERTY: recorded})

    listed = add_findings_list(document)

    assert listed["findings"][0]["file_path"] == "api/my%20file.py", listed["findings"]


def test_a_file_uri_is_not_replaced_by_a_recorded_path():
    """Control, green on both sides: the flat model decodes a file: uri itself."""
    document = _document("file:///work/app.py", {ARTIFACT_PATH_PROPERTY: "other.py"})

    listed = add_findings_list(document)

    assert listed["findings"][0]["file_path"] == "file:///work/app.py", listed


def test_the_filters_and_the_flat_model_spell_the_property_alike():
    assert result_filters.ARTIFACT_PATH_PROPERTY == ARTIFACT_PATH_PROPERTY
    assert flat_vulnerability.ARTIFACT_PATH_PROPERTY == ARTIFACT_PATH_PROPERTY
