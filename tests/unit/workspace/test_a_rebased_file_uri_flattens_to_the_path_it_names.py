# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A finding whose ``file:`` uri was rebased is flattened under its real path.

``rebase_run_for_project`` writes a rebased ``file:`` uri percent-encoded
(``my%20file.py``), because a SARIF ``uri`` is a URI reference. The flattened
finding reads a relative ``uri`` as a literal path, so ``file_path`` came out as
``my%20file.py`` and the finding's identity and the path a suppression matches
were the encoded text. The aggregator now records the path the encoded uri names
in a result property, and the flattened finding takes its path from that.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models import flat_vulnerability
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import Result
from automated_security_helper.workspace import aggregation
from automated_security_helper.workspace.aggregation import rebase_run_for_project
from automated_security_helper.workspace.plan import ProjectPlan

pytestmark = pytest.mark.unit

#: Spelled out here so a control that has nothing to record reads the same
#: before and after the property exists.
ARTIFACT_PATH_PROPERTY = "workspace_artifact_path"


@pytest.fixture
def project(tmp_path):
    return ProjectPlan(
        key="api",
        relative_path="api",
        path=(tmp_path / "ws" / "api").as_posix(),
        label="api",
        display_label="api",
    )


def _run(uri: str, extra_properties: dict | None = None) -> dict:
    properties = {"scanner_name": "bandit"}
    properties.update(extra_properties or {})
    return {
        "tool": {"driver": {"name": "bandit"}},
        "results": [
            {
                "ruleId": "B101",
                "level": "error",
                "message": {"text": "assert used"},
                "properties": properties,
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            }
        ],
    }


def _flat(run: dict) -> FlatVulnerability:
    return FlatVulnerability.from_sarif_result(
        Result.model_validate(run["results"][0]), "bandit", "SAST"
    )


@pytest.mark.parametrize("name", ["my file.py", "a#b.py", "x%41.py"])
def test_a_file_uri_that_is_written_encoded_flattens_to_the_decoded_path(
    project, tmp_path, name
):
    source = (tmp_path / "ws" / "api" / name).as_uri()

    rebased, _ = rebase_run_for_project(_run(source), project)

    written = rebased["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    # The uri is a URI reference, so it is written encoded ...
    assert written != name
    # ... and the flattened finding names the file, not the encoded text.
    assert _flat(rebased).file_path == name


def test_a_name_that_needs_no_encoding_records_no_path_and_flattens_as_before(
    project, tmp_path
):
    """Control, green on both sides: nothing to record when the text is the path."""
    source = (tmp_path / "ws" / "api" / "app.py").as_uri()

    rebased, _ = rebase_run_for_project(_run(source), project)

    assert ARTIFACT_PATH_PROPERTY not in rebased["results"][0]["properties"]
    assert _flat(rebased).file_path == "app.py"


def test_a_bare_absolute_path_is_written_as_it_is_and_flattens_to_it(project, tmp_path):
    """Control, green on both sides: a source with no scheme was a plain path."""
    source = (tmp_path / "ws" / "api" / "my file.py").as_posix()

    rebased, _ = rebase_run_for_project(_run(source), project)

    assert ARTIFACT_PATH_PROPERTY not in rebased["results"][0]["properties"]
    assert _flat(rebased).file_path == "my file.py"


def test_a_scanner_written_value_under_the_property_name_is_not_taken_for_the_path(
    project, tmp_path
):
    """The property comes from the aggregator's own reading of the uri."""
    source = (tmp_path / "ws" / "api" / "app.py").as_uri()

    rebased, _ = rebase_run_for_project(
        _run(source, {ARTIFACT_PATH_PROPERTY: "somewhere/else.py"}), project
    )

    assert ARTIFACT_PATH_PROPERTY not in rebased["results"][0]["properties"]
    assert _flat(rebased).file_path == "app.py"


def test_the_aggregator_and_the_flat_model_spell_the_property_alike():
    assert aggregation.ARTIFACT_PATH_PROPERTY == ARTIFACT_PATH_PROPERTY
    assert flat_vulnerability.ARTIFACT_PATH_PROPERTY == ARTIFACT_PATH_PROPERTY
