# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An unrooted finding URI is project-relative, even when it spells the project's path.

Why this file exists
--------------------
``project_relative_uri`` used to try an unrooted URI a second time with a leading
separator restored, and read it as absolute when that landed inside the project.
The shape it defended, checkov's separator-stripped absolute path, does not reach
the aggregator in workspace mode: the project is scanned with its own path as
``source_dir`` and ``sanitize_sarif_paths`` relativizes the URI first. What did
reach it is routine. The container mounts the workspace at ``/src``, so a Python
src-layout project at ``/src/api`` reports ``src/api/__init__.py``; restored to
``/src/api/__init__.py`` that lies inside ``/src/api`` and the finding was moved
to ``__init__.py`` at the project root, a different file, with nothing counted.

The same second reading also ran inside ``to_workspace_uri`` on a URI that
``rebase_run_for_project`` had already reduced, so an absolute URI's artifact
``uri`` and its ``properties.workspace_uri`` could name two different files.

The contract these cases pin:

- an unrooted URI whose components spell the project's absolute path is read as
  project-relative, and the finding stays on the file it names;
- a rooted URI inside the project is still reduced, and its reduced artifact
  ``uri`` and its ``workspace_uri`` name the same file.
"""

from __future__ import annotations

import pytest

from automated_security_helper.workspace.aggregation import (
    NOT_ABSOLUTE,
    PROJECT_ROOT_URI_BASE_ID,
    project_relative_uri,
    rebase_run_for_project,
    to_workspace_uri,
)
from automated_security_helper.workspace.plan import ProjectPlan

pytestmark = pytest.mark.unit


@pytest.fixture
def project(tmp_path):
    """A project at ``<tmp_path>/src/api``: rooted on POSIX, drive-qualified on Windows.

    ``rebase_run_for_project`` hands the project's path to ``Path.as_uri()``,
    which on Windows refuses a path that has a root and no drive, so the POSIX
    literal ``/src/api`` this file first used raised ``ValueError`` on every
    Windows row (test_aggregation.py's ``TestProjectRootUri`` records the shape).
    The pure-function assertions below keep the literal: ``project_relative_uri``
    and ``to_workspace_uri`` read it as text on every platform.
    """
    return ProjectPlan(
        key="api",
        relative_path="api",
        path=(tmp_path / "src" / "api").as_posix(),
        label="api",
        display_label="api",
    )


def _run(uri: str) -> dict:
    return {
        "tool": {"driver": {"name": "bandit"}},
        "results": [
            {
                "ruleId": "B101",
                "level": "error",
                "properties": {"scanner_name": "bandit"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            }
        ],
    }


def _placed(run: dict) -> tuple[str, str | None, str | None]:
    result = run["results"][0]
    artifact = result["locations"][0]["physicalLocation"]["artifactLocation"]
    return (
        artifact["uri"],
        artifact.get("uriBaseId"),
        result["properties"].get("workspace_uri"),
    )


def test_a_src_layout_finding_is_not_relocated_to_the_project_root(project):
    assert project_relative_uri("src/api/__init__.py", "/src/api") is NOT_ABSOLUTE
    assert (
        to_workspace_uri("src/api/__init__.py", "api", "/src/api")
        == "api/src/api/__init__.py"
    )

    rebased, unconvertible = rebase_run_for_project(
        _run("src/api/__init__.py"), project
    )

    assert unconvertible == 0
    assert _placed(rebased) == (
        "src/api/__init__.py",
        PROJECT_ROOT_URI_BASE_ID,
        "api/src/api/__init__.py",
    )


def test_a_rooted_uri_is_reduced_once_and_both_coordinates_agree(project, tmp_path):
    """Control: the absolute shape still reduces, and reduces only once."""
    absolute = (tmp_path / "src" / "api" / "src" / "api" / "models.py").as_posix()
    rebased, unconvertible = rebase_run_for_project(_run(absolute), project)

    assert unconvertible == 0
    assert _placed(rebased) == (
        "src/api/models.py",
        PROJECT_ROOT_URI_BASE_ID,
        "api/src/api/models.py",
    )
