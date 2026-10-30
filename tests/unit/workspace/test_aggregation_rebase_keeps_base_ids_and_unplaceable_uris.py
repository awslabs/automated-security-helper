# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Rebasing a run keeps the scanner's base ids and anchors only what it can place.

Why this file exists
--------------------
``rebase_run_for_project`` attributes one project's SARIF run to the project and
anchors its locations to the project root. Two of its edges contradicted the
contract its docstring states.

The run's ``originalUriBaseIds`` table was replaced wholesale by the project root
entry, while a scanner-written ``uriBaseId`` on a location was left in place. A
location anchored to ``%SRCROOT%`` then referenced a base id no longer declared
anywhere in the run, which a consumer cannot resolve.

A relative URI carrying a ``..`` component cannot be placed inside the project.
The docstring says such a URI "keeps its original text, gets no uriBaseId, and is
counted", yet the location was anchored to the project root all the same, so the
run asserted a location inside the project for a path that escapes it.

The contract these cases pin:

- a base id the scanner declared survives the rebase alongside the project root;
- a ``..`` URI keeps its text, carries no ``uriBaseId``, has no ``workspace_uri``
  and is counted as unconvertible;
- an absolute URI reduced to project-relative is anchored to the project root
  even when the scanner had anchored its absolute form elsewhere;
- a relative URI anchored to a base of the scanner's own takes its
  ``workspace_uri`` from base + uri read back through the project, so the two
  coordinates name one file; a base outside the project counts the finding as
  unconvertible and anchors nothing.
"""

from __future__ import annotations

import pytest

from automated_security_helper.workspace.aggregation import (
    PROJECT_ROOT_URI_BASE_ID,
    rebase_run_for_project,
)
from automated_security_helper.workspace.plan import ProjectPlan

pytestmark = pytest.mark.unit

PROJECT = ProjectPlan(
    key="api",
    relative_path="api",
    path="/ws/api",
    label="api",
    display_label="api",
)


def _run(*locations: dict, base_ids: dict | None = None) -> dict:
    run = {
        "tool": {"driver": {"name": "bandit"}},
        "results": [
            {
                "ruleId": "B101",
                "level": "error",
                "properties": {"scanner_name": "bandit"},
                "locations": [
                    {"physicalLocation": {"artifactLocation": dict(location)}}
                    for location in locations
                ],
            }
        ],
    }
    if base_ids is not None:
        run["originalUriBaseIds"] = base_ids
    return run


def _artifact(run: dict, index: int = 0) -> dict:
    return run["results"][0]["locations"][index]["physicalLocation"]["artifactLocation"]


def test_a_scanner_declared_base_id_survives_beside_the_project_root():
    rebased, _ = rebase_run_for_project(
        _run(
            {"uri": "src/app.py", "uriBaseId": "%SRCROOT%"},
            base_ids={"%SRCROOT%": {"uri": "file:///ws/api/"}},
        ),
        PROJECT,
    )

    table = rebased["originalUriBaseIds"]
    assert table["%SRCROOT%"] == {"uri": "file:///ws/api/"}
    assert table[PROJECT_ROOT_URI_BASE_ID] == {"uri": "file:///ws/api/"}
    # The scanner's own anchor on a relative location is left alone, and it
    # still resolves because its base id is still declared.
    assert _artifact(rebased)["uriBaseId"] == "%SRCROOT%"


def test_a_parent_component_uri_is_counted_and_not_anchored():
    rebased, unconvertible = rebase_run_for_project(
        _run({"uri": "../../ws/api/src/app.py"}), PROJECT
    )

    artifact = _artifact(rebased)
    assert artifact["uri"] == "../../ws/api/src/app.py"
    assert "uriBaseId" not in artifact
    assert "workspace_uri" not in rebased["results"][0]["properties"]
    assert unconvertible == 1


def test_a_relative_uri_under_a_scanners_own_base_is_placed_through_that_base():
    """``%SRCROOT%`` is ``file:///``, the uri spells the path below it.

    Read as project-relative, ``ws/api/src/app.py`` would be placed at
    ``api/ws/api/src/app.py``, a file that does not exist, while a SARIF consumer
    resolving base + uri finds ``/ws/api/src/app.py``. The workspace coordinate
    has to agree with the consumer's.
    """
    rebased, unconvertible = rebase_run_for_project(
        _run(
            {"uri": "ws/api/src/app.py", "uriBaseId": "%SRCROOT%"},
            base_ids={"%SRCROOT%": {"uri": "file:///"}},
        ),
        PROJECT,
    )

    artifact = _artifact(rebased)
    assert artifact["uri"] == "ws/api/src/app.py"
    assert artifact["uriBaseId"] == "%SRCROOT%"
    assert rebased["results"][0]["properties"]["workspace_uri"] == "api/src/app.py"
    assert unconvertible == 0


def test_a_relative_uri_under_a_deeper_base_is_placed_through_that_base():
    """Control for the root-base case: a base with a path of its own joins too."""
    rebased, unconvertible = rebase_run_for_project(
        _run(
            {"uri": "api/src/app.py", "uriBaseId": "%SRCROOT%"},
            base_ids={"%SRCROOT%": {"uri": "file:///ws/"}},
        ),
        PROJECT,
    )

    artifact = _artifact(rebased)
    assert artifact["uri"] == "api/src/app.py"
    assert artifact["uriBaseId"] == "%SRCROOT%"
    assert rebased["results"][0]["properties"]["workspace_uri"] == "api/src/app.py"
    assert unconvertible == 0


def test_a_relative_uri_under_a_base_outside_the_project_is_counted_not_anchored():
    rebased, unconvertible = rebase_run_for_project(
        _run(
            {"uri": "src/app.py", "uriBaseId": "%SRCROOT%"},
            base_ids={"%SRCROOT%": {"uri": "file:///ws/web/"}},
        ),
        PROJECT,
    )

    artifact = _artifact(rebased)
    assert artifact["uri"] == "src/app.py"
    assert artifact["uriBaseId"] == "%SRCROOT%"
    assert "workspace_uri" not in rebased["results"][0]["properties"]
    assert unconvertible == 1


def test_a_reduced_absolute_uri_is_anchored_to_the_project_root():
    """Control for the first case: a REWRITTEN uri takes the root's coordinates."""
    rebased, unconvertible = rebase_run_for_project(
        _run({"uri": "/ws/api/src/app.py", "uriBaseId": "%SRCROOT%"}), PROJECT
    )

    artifact = _artifact(rebased)
    assert artifact["uri"] == "src/app.py"
    assert artifact["uriBaseId"] == PROJECT_ROOT_URI_BASE_ID
    assert rebased["results"][0]["properties"]["workspace_uri"] == "api/src/app.py"
    assert unconvertible == 0
