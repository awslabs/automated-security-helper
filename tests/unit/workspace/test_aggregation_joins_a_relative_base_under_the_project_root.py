# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A relative base the run declares is a directory under the project root.

A run can declare ``originalUriBaseIds`` of ``{"SRCROOT": {"uri": "src/"}}`` and
anchor a location to it with ``{"uri": "app.py", "uriBaseId": "SRCROOT"}``: the
file is ``src/app.py``. An unanchored base with a relative uri was read as the
project root itself, so the finding was placed at ``api/app.py`` and the
directory was dropped. The base is now joined under the project root. The
artifact is left as the scanner wrote it, so its uri and its uriBaseId still
agree.
"""

from __future__ import annotations

import pytest

from automated_security_helper.workspace.aggregation import rebase_run_for_project
from automated_security_helper.workspace.plan import ProjectPlan

pytestmark = pytest.mark.unit


@pytest.fixture
def project(tmp_path):
    return ProjectPlan(
        key="api",
        relative_path="api",
        path=(tmp_path / "ws" / "api").as_posix(),
        label="api",
        display_label="api",
    )


def _run(bases: dict, uri: str = "app.py", base_id: str = "SRCROOT") -> dict:
    return {
        "tool": {"driver": {"name": "bandit"}},
        "originalUriBaseIds": bases,
        "results": [
            {
                "ruleId": "B101",
                "level": "error",
                "properties": {"scanner_name": "bandit"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri, "uriBaseId": base_id}
                        }
                    }
                ],
            }
        ],
    }


def _workspace_uri(run: dict) -> str:
    return run["results"][0]["properties"]["workspace_uri"]


def test_a_relative_base_is_joined_under_the_project_root(project):
    rebased, unconvertible = rebase_run_for_project(
        _run({"SRCROOT": {"uri": "src/"}}), project
    )

    # RED at the base: the base was read as the project root, so this was
    # "api/app.py" and the directory the scanner named was lost.
    assert unconvertible == 0
    assert _workspace_uri(rebased) == "api/src/app.py"


def test_the_artifact_stays_as_the_scanner_wrote_it(project):
    rebased, _ = rebase_run_for_project(_run({"SRCROOT": {"uri": "src/"}}), project)

    artifact = rebased["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]
    assert artifact["uri"] == "app.py"
    assert artifact["uriBaseId"] == "SRCROOT"


@pytest.mark.parametrize(
    "bases",
    [
        {"SRCROOT": {"uri": "./"}},
        {"SRCROOT": {"uri": "."}},
        {"SRCROOT": {"uri": ""}},
        {},
    ],
    ids=["dot slash", "dot", "empty", "not declared"],
)
def test_a_base_that_is_the_project_root_changes_nothing(project, bases):
    """Control, green on both sides: the root written out, or no base at all."""
    rebased, unconvertible = rebase_run_for_project(_run(bases), project)

    assert unconvertible == 0
    assert _workspace_uri(rebased) == "api/app.py"


def test_an_absolute_base_is_still_joined_as_before(project, tmp_path):
    """Control, green on both sides: the base the project placed already."""
    base = (tmp_path / "ws" / "api" / "src").as_uri() + "/"

    rebased, unconvertible = rebase_run_for_project(
        _run({"SRCROOT": {"uri": base}}), project
    )

    assert unconvertible == 0
    assert _workspace_uri(rebased) == "api/src/app.py"
