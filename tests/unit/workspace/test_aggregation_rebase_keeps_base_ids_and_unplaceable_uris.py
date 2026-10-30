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
- ``_rooted`` reads a UNC or drive path as absolute and a single leading
  backslash as a file-name character (``uri_separators``' rule for a POSIX
  project), a base chain is bounded by the bases it names, and the
  policy-origin marker and its reader have one home, ``aggregation``.
"""

from __future__ import annotations

import sys
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


def test_a_relative_percent_artifact_under_a_declared_base_keeps_its_percent(
    project, tmp_path
):
    """Red at the base: the declared ``file:`` base was decoded and handed on with
    its scheme, so the joined text was decoded AGAIN when read, and the artifact's
    own ``%20`` (part of its name, kept when it has no base) became a space: the
    two coordinates named two files."""
    rebased, unconvertible = rebase_run_for_project(
        _run(
            {"uri": "src/odd%20name.py", "uriBaseId": "%SRCROOT%"},
            base_ids={"%SRCROOT%": {"uri": _dir_uri(tmp_path / "ws" / "api")}},
        ),
        project,
    )

    assert unconvertible == 0
    assert _artifact(rebased)["uri"] == "src/odd%20name.py"
    assert (
        rebased["results"][0]["properties"]["workspace_uri"] == "api/src/odd%20name.py"
    )


def test_a_directory_named_with_a_literal_percent_is_placed_through_one_decoding(
    tmp_path,
):
    """Red at the base: ``Path.as_uri()`` writes ``%2520`` for a directory named
    ``My%20Repo``; decoded twice that read ``My Repo``, a path outside the project,
    and the finding was counted where the one decoding places it."""
    root = tmp_path / "ws" / "My%20Repo" / "api"
    project = ProjectPlan(
        key="api",
        relative_path="api",
        path=root.as_posix(),
        label="api",
        display_label="api",
    )
    base = _dir_uri(root)
    assert "%2520" in base, (
        "Path.as_uri() no longer encodes a literal %; nothing measured"
    )

    rebased, unconvertible = rebase_run_for_project(
        _run(
            {"uri": "src/app.py", "uriBaseId": "%SRCROOT%"},
            base_ids={"%SRCROOT%": {"uri": base}},
        ),
        project,
    )

    assert unconvertible == 0
    assert _artifact(rebased)["uri"] == "src/app.py"
    assert rebased["results"][0]["properties"]["workspace_uri"] == "api/src/app.py"


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


def test_a_rooted_posix_path_whose_first_component_holds_a_colon_stays_rooted():
    """Red at the base: ``_posix_text`` dropped the leading separator of any
    ``/X:...`` text, a rule meant for ``/C:/x`` (how ``file:///C:/x`` reduces), so
    ``/x:legacy/src/x.py`` became ``x:legacy/src/x.py``, read as relative, and the
    finding was rebased under the project though it names a path outside it."""
    assert aggregation._posix_text("/x:legacy/src/x.py") == "/x:legacy/src/x.py"
    assert aggregation._rooted(aggregation._posix_text("/x:legacy/src/x.py")) is True
    assert aggregation._posix_text("file:///x:legacy/src/x.py") == "/x:legacy/src/x.py"
    # The drive rule itself is kept: a letter at [1] and a separator or the end at [3].
    assert aggregation._posix_text("/C:/ws/x.py") == "C:/ws/x.py"
    assert aggregation._posix_text("file:///C:/ws/x.py") == "C:/ws/x.py"
    assert aggregation._posix_text("/C:") == "C:"
    assert aggregation._posix_text("/1:/x.py") == "/1:/x.py"


def test_a_rooted_path_with_a_colon_component_outside_the_project_is_counted(project):
    """Red at the base: the location was placed at ``api/x:legacy/src/x.py``."""
    rebased, unconvertible = rebase_run_for_project(
        _run({"uri": "/x:legacy/src/x.py"}), project
    )

    artifact = _artifact(rebased)
    assert artifact["uri"] == "/x:legacy/src/x.py"
    assert "uriBaseId" not in artifact
    assert "workspace_uri" not in rebased["results"][0]["properties"]
    assert unconvertible == 1


def test_rooted_reads_a_unc_path_as_absolute_and_a_single_backslash_as_a_name():
    """Red at the base for the UNC line (``_rooted`` read only ``/`` and a drive),
    then for the ``\\x.py`` line once a single leading backslash was admitted as a
    root: ``uri_separators`` classes it as a file-name character on a POSIX
    project, and only a drive or a UNC spelling as Windows-only."""
    assert aggregation._rooted("\\\\server\\share\\nb.ipynb") is True
    assert aggregation._rooted("\\x.py") is False
    assert aggregation._rooted("C:\\ws\\x.py") is True
    assert aggregation._rooted("/ws/x.py") is True
    assert aggregation._rooted("src/app.py") is False
    assert aggregation._rooted("") is False


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="under a Windows project root a backslash is a separator, so the "
    "name is read as /x.py",
)
def test_a_name_with_one_leading_backslash_on_a_posix_project_is_placed(project):
    """Red at the base: with the single backslash admitted as a root, ``\\x.py``
    was counted unconvertible and anchored nowhere, where it had been placed
    under the project as a file of that name."""
    rebased, unconvertible = rebase_run_for_project(_run({"uri": "\\x.py"}), project)

    artifact = _artifact(rebased)
    assert artifact["uri"] == "\\x.py"
    assert artifact["uriBaseId"] == PROJECT_ROOT_URI_BASE_ID
    assert rebased["results"][0]["properties"]["workspace_uri"] == "api/\\x.py"
    assert unconvertible == 0


def _chain(depth: int, root_uri: str) -> dict:
    """``%B1%`` anchored to ``%B2%`` ... to ``%B<depth>%``, which is declared at *root_uri*.

    The outermost base is the root, so a location under ``%B1%`` resolves to
    ``<root>/d<depth-1>/.../d2/d1/``: the segments join from the root inward."""
    base_ids = {
        f"%B{index}%": {"uri": f"d{index}/", "uriBaseId": f"%B{index + 1}%"}
        for index in range(1, depth)
    }
    base_ids[f"%B{depth}%"] = {"uri": root_uri}
    return base_ids


def test_a_chain_of_the_limits_depth_resolves_and_one_base_deeper_is_counted(
    project, tmp_path
):
    """Pins the bound as the bytes admit it: ``_BASE_CHAIN_LIMIT`` counts the
    bases a chain names, the location's own included, so seven hops resolve and
    an eighth is counted (the comment once said eight hops)."""
    root = _dir_uri(tmp_path / "ws" / "api")
    limit = aggregation._BASE_CHAIN_LIMIT

    rebased, unconvertible = rebase_run_for_project(
        _run({"uri": "app.py", "uriBaseId": "%B1%"}, base_ids=_chain(limit, root)),
        project,
    )
    # Joined from the root inward: %B7% (d7/) sits under the root, %B1% (d1/)
    # is the innermost, so the placed path reads d7/.../d1/.
    placed = "api/" + "".join(f"d{index}/" for index in range(limit - 1, 0, -1))
    placed += "app.py"
    assert rebased["results"][0]["properties"]["workspace_uri"] == placed
    assert unconvertible == 0

    rebased, unconvertible = rebase_run_for_project(
        _run({"uri": "app.py", "uriBaseId": "%B1%"}, base_ids=_chain(limit + 1, root)),
        project,
    )
    assert "workspace_uri" not in rebased["results"][0]["properties"]
    assert unconvertible == 1


def test_the_policy_origin_marker_and_its_reader_have_one_home():
    """Red at the base: execution kept its own ``_is_policy_origin`` beside
    aggregation's copy, and nothing failed when the two drifted."""
    assert execution.POLICY_ORIGIN == aggregation.POLICY_ORIGIN == "workspace-policy"
    assert execution.is_policy_origin is aggregation.is_policy_origin
    assert not hasattr(execution, "_is_policy_origin")
    assert aggregation.is_policy_origin({"properties": {"origin": "workspace-policy"}})
    assert not aggregation.is_policy_origin({"properties": {"origin": "project"}})
    assert not aggregation.is_policy_origin({"properties": None})
