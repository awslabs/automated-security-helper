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
  unconvertible and anchors nothing;
- a ``file:`` base is a URI and is percent-encoded (``Path.as_uri()`` writes a
  space as ``%20``): it is decoded before the join, so a project whose path holds
  a space places its findings as it did before bases were honoured;
- a base anchored to another base (``SRCROOT`` under ``REPOROOT``) is followed to
  its root and the chain joined; a chain the run does not resolve (an undeclared
  parent, a cycle) counts the finding instead of placing it at the project root
  under another file's name;
- ``_rooted`` reads a backslash-rooted or UNC path as absolute, and the
  policy-origin marker and its reader have one home, ``aggregation``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.workspace import aggregation, execution
from automated_security_helper.workspace.aggregation import (
    PROJECT_ROOT_URI_BASE_ID,
    rebase_run_for_project,
)
from automated_security_helper.workspace.plan import ProjectPlan

pytestmark = pytest.mark.unit


@pytest.fixture
def project(tmp_path):
    """A project at ``<tmp_path>/ws/api``: rooted on POSIX, drive-qualified on Windows.

    ``rebase_run_for_project`` hands the project's path to ``Path.as_uri()``,
    which on Windows refuses a path that has a root and no drive, so the POSIX
    literal ``/ws/api`` this file first used raised ``ValueError: relative path
    can't be expressed as a file URI`` on every Windows row while every POSIX row
    passed (test_aggregation.py's ``TestProjectRootUri`` records the same shape).
    Production supplies a resolved, drive-qualified path on both platforms, and so
    does ``tmp_path``. The URIs below are built from the same path.
    """
    return ProjectPlan(
        key="api",
        relative_path="api",
        path=(tmp_path / "ws" / "api").as_posix(),
        label="api",
        display_label="api",
    )


def _dir_uri(path: Path) -> str:
    """The ``file://`` URI of a directory, with the trailing separator SARIF wants."""
    uri = path.as_uri()
    return uri if uri.endswith("/") else uri + "/"


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


def test_a_scanner_declared_base_id_survives_beside_the_project_root(project, tmp_path):
    root = _dir_uri(tmp_path / "ws" / "api")
    rebased, _ = rebase_run_for_project(
        _run(
            {"uri": "src/app.py", "uriBaseId": "%SRCROOT%"},
            base_ids={"%SRCROOT%": {"uri": root}},
        ),
        project,
    )

    table = rebased["originalUriBaseIds"]
    assert table["%SRCROOT%"] == {"uri": root}
    assert table[PROJECT_ROOT_URI_BASE_ID] == {"uri": root}
    # The scanner's own anchor on a relative location is left alone, and it
    # still resolves because its base id is still declared.
    assert _artifact(rebased)["uriBaseId"] == "%SRCROOT%"


def test_a_parent_component_uri_is_counted_and_not_anchored(project):
    rebased, unconvertible = rebase_run_for_project(
        _run({"uri": "../../ws/api/src/app.py"}), project
    )

    artifact = _artifact(rebased)
    assert artifact["uri"] == "../../ws/api/src/app.py"
    assert "uriBaseId" not in artifact
    assert "workspace_uri" not in rebased["results"][0]["properties"]
    assert unconvertible == 1


def test_a_relative_uri_under_a_scanners_own_base_is_placed_through_that_base(
    project, tmp_path
):
    """``%SRCROOT%`` is the filesystem anchor, the uri spells the path below it.

    The anchor is ``file:///`` on POSIX and ``file:///C:/`` on Windows; the uri
    is the project file's path with the anchor removed. Read as project-relative,
    that uri would be placed at ``api/<uri>``, a file that does not exist, while a
    SARIF consumer resolving base + uri finds the file. The workspace coordinate
    has to agree with the consumer's.
    """
    below_anchor = (
        (tmp_path / "ws" / "api" / "src" / "app.py")
        .relative_to(tmp_path.anchor)
        .as_posix()
    )
    rebased, unconvertible = rebase_run_for_project(
        _run(
            {"uri": below_anchor, "uriBaseId": "%SRCROOT%"},
            base_ids={"%SRCROOT%": {"uri": Path(tmp_path.anchor).as_uri()}},
        ),
        project,
    )

    artifact = _artifact(rebased)
    assert artifact["uri"] == below_anchor
    assert artifact["uriBaseId"] == "%SRCROOT%"
    assert rebased["results"][0]["properties"]["workspace_uri"] == "api/src/app.py"
    assert unconvertible == 0


def test_a_relative_uri_under_a_deeper_base_is_placed_through_that_base(
    project, tmp_path
):
    """Control for the root-base case: a base with a path of its own joins too."""
    rebased, unconvertible = rebase_run_for_project(
        _run(
            {"uri": "api/src/app.py", "uriBaseId": "%SRCROOT%"},
            base_ids={"%SRCROOT%": {"uri": _dir_uri(tmp_path / "ws")}},
        ),
        project,
    )

    artifact = _artifact(rebased)
    assert artifact["uri"] == "api/src/app.py"
    assert artifact["uriBaseId"] == "%SRCROOT%"
    assert rebased["results"][0]["properties"]["workspace_uri"] == "api/src/app.py"
    assert unconvertible == 0


def test_a_relative_uri_under_a_base_outside_the_project_is_counted_not_anchored(
    project, tmp_path
):
    rebased, unconvertible = rebase_run_for_project(
        _run(
            {"uri": "src/app.py", "uriBaseId": "%SRCROOT%"},
            base_ids={"%SRCROOT%": {"uri": _dir_uri(tmp_path / "ws" / "web")}},
        ),
        project,
    )

    artifact = _artifact(rebased)
    assert artifact["uri"] == "src/app.py"
    assert artifact["uriBaseId"] == "%SRCROOT%"
    assert "workspace_uri" not in rebased["results"][0]["properties"]
    assert unconvertible == 1


def test_a_reduced_absolute_uri_is_anchored_to_the_project_root(project, tmp_path):
    """Control for the first case: a REWRITTEN uri takes the root's coordinates."""
    absolute = (tmp_path / "ws" / "api" / "src" / "app.py").as_posix()
    rebased, unconvertible = rebase_run_for_project(
        _run({"uri": absolute, "uriBaseId": "%SRCROOT%"}), project
    )

    artifact = _artifact(rebased)
    assert artifact["uri"] == "src/app.py"
    assert artifact["uriBaseId"] == PROJECT_ROOT_URI_BASE_ID
    assert rebased["results"][0]["properties"]["workspace_uri"] == "api/src/app.py"
    assert unconvertible == 0


# ---------------------------------------------------------------------------
# A percent-encoded base, and a base anchored to another base
# ---------------------------------------------------------------------------


def test_a_percent_encoded_base_places_the_uri_through_the_decoded_path(tmp_path):
    """Red at the base: ``My%20Repo`` is not under ``My Repo``, so ``relative_to``
    raised, the location was counted unconvertible, and a finding the
    project-relative reading had placed before bases were honoured went missing
    from the workspace coordinates."""
    root = tmp_path / "ws" / "My Repo" / "api"
    project = ProjectPlan(
        key="api",
        relative_path="api",
        path=root.as_posix(),
        label="api",
        display_label="api",
    )
    base = _dir_uri(root)
    assert "%20" in base, "Path.as_uri() no longer percent-encodes; nothing measured"

    rebased, unconvertible = rebase_run_for_project(
        _run(
            {"uri": "src/app.py", "uriBaseId": "%SRCROOT%"},
            base_ids={"%SRCROOT%": {"uri": base}},
        ),
        project,
    )

    artifact = _artifact(rebased)
    assert artifact["uri"] == "src/app.py"
    assert artifact["uriBaseId"] == "%SRCROOT%"
    assert rebased["results"][0]["properties"]["workspace_uri"] == "api/src/app.py"
    assert unconvertible == 0
    # The declared base is carried as the scanner wrote it, encoded.
    assert rebased["originalUriBaseIds"]["%SRCROOT%"] == {"uri": base}


def test_a_percent_encoded_absolute_artifact_uri_is_reduced_through_the_decoded_path(
    tmp_path,
):
    """Red at the base: the base-id path was decoded (above) and the artifact's own
    ``file:`` URI was not, so ``file:///.../My%20Repo/api/src/app.py`` read as a path
    outside ``My Repo/api`` and was kept absolute, placed nowhere in the workspace."""
    root = tmp_path / "ws" / "My Repo" / "api"
    project = ProjectPlan(
        key="api",
        relative_path="api",
        path=root.as_posix(),
        label="api",
        display_label="api",
    )
    absolute = (root / "src" / "app.py").as_uri()
    assert "%20" in absolute, (
        "Path.as_uri() no longer percent-encodes; nothing measured"
    )

    rebased, unconvertible = rebase_run_for_project(_run({"uri": absolute}), project)

    assert unconvertible == 0
    artifact = _artifact(rebased)
    assert artifact["uri"] == "src/app.py"
    assert artifact["uriBaseId"] == PROJECT_ROOT_URI_BASE_ID
    assert rebased["results"][0]["properties"]["workspace_uri"] == "api/src/app.py"


def test_a_scheme_less_name_keeps_its_percent_sign(project):
    """Control: only a ``file:`` URI is decoded; a bare name is a file name, and
    ``%20`` in it is part of that name."""
    rebased, unconvertible = rebase_run_for_project(
        _run({"uri": "src/odd%20name.py"}), project
    )

    assert unconvertible == 0
    assert _artifact(rebased)["uri"] == "src/odd%20name.py"
    assert (
        rebased["results"][0]["properties"]["workspace_uri"] == "api/src/odd%20name.py"
    )


def test_a_chained_base_is_resolved_to_its_root(project, tmp_path):
    """Red at the base: the anchored base answered None and ``app.py`` was placed
    at the project root, dropping the ``src/`` and naming another file."""
    rebased, unconvertible = rebase_run_for_project(
        _run(
            {"uri": "app.py", "uriBaseId": "%SRCROOT%"},
            base_ids={
                "%SRCROOT%": {"uri": "src/", "uriBaseId": "%REPOROOT%"},
                "%REPOROOT%": {"uri": _dir_uri(tmp_path / "ws" / "api")},
            },
        ),
        project,
    )

    artifact = _artifact(rebased)
    assert artifact["uri"] == "app.py"
    assert artifact["uriBaseId"] == "%SRCROOT%"
    assert rebased["results"][0]["properties"]["workspace_uri"] == "api/src/app.py"
    assert unconvertible == 0


def test_a_chain_ending_nowhere_declared_is_counted_not_placed(project):
    """Red at the base: placed at the project root as ``api/app.py``."""
    rebased, unconvertible = rebase_run_for_project(
        _run(
            {"uri": "app.py", "uriBaseId": "%SRCROOT%"},
            base_ids={"%SRCROOT%": {"uri": "src/", "uriBaseId": "%NOWHERE%"}},
        ),
        project,
    )

    artifact = _artifact(rebased)
    assert artifact["uri"] == "app.py"
    assert artifact["uriBaseId"] == "%SRCROOT%"
    assert "workspace_uri" not in rebased["results"][0]["properties"]
    assert unconvertible == 1


def test_a_cyclic_base_chain_is_counted_not_placed(project):
    """A chain that never reaches a root ends in a count, not in a loop."""
    rebased, unconvertible = rebase_run_for_project(
        _run(
            {"uri": "app.py", "uriBaseId": "%A%"},
            base_ids={
                "%A%": {"uri": "x/", "uriBaseId": "%B%"},
                "%B%": {"uri": "y/", "uriBaseId": "%A%"},
            },
        ),
        project,
    )

    assert "workspace_uri" not in rebased["results"][0]["properties"]
    assert unconvertible == 1


def test_a_chain_rooted_in_a_relative_base_is_counted_not_placed(project):
    """Control for the resolved chain: a root that is itself relative places
    nothing, as an unanchored relative base places nothing."""
    rebased, unconvertible = rebase_run_for_project(
        _run(
            {"uri": "app.py", "uriBaseId": "%SRCROOT%"},
            base_ids={
                "%SRCROOT%": {"uri": "src/", "uriBaseId": "%REPOROOT%"},
                "%REPOROOT%": {"uri": "repo/"},
            },
        ),
        project,
    )

    assert "workspace_uri" not in rebased["results"][0]["properties"]
    assert unconvertible == 1


def test_rooted_reads_a_backslash_rooted_and_a_unc_path_as_absolute():
    """Red at the base for the first two: ``_rooted`` read only ``/`` and a drive."""
    assert aggregation._rooted("\\\\server\\share\\nb.ipynb") is True
    assert aggregation._rooted("\\x.py") is True
    assert aggregation._rooted("C:\\ws\\x.py") is True
    assert aggregation._rooted("/ws/x.py") is True
    assert aggregation._rooted("src/app.py") is False
    assert aggregation._rooted("") is False


def test_the_policy_origin_marker_and_its_reader_have_one_home():
    """Red at the base: execution kept its own ``_is_policy_origin`` beside
    aggregation's copy, and nothing failed when the two drifted."""
    assert execution.POLICY_ORIGIN == aggregation.POLICY_ORIGIN == "workspace-policy"
    assert execution.is_policy_origin is aggregation.is_policy_origin
    assert not hasattr(execution, "_is_policy_origin")
    assert aggregation.is_policy_origin({"properties": {"origin": "workspace-policy"}})
    assert not aggregation.is_policy_origin({"properties": {"origin": "project"}})
    assert not aggregation.is_policy_origin({"properties": None})
