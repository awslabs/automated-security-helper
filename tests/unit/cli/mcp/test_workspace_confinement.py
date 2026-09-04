#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ASH_MCP_ALLOWED_ROOTS`` confines a workspace scan, project by project.

Why this file exists
--------------------
A single-directory MCP scan names one directory, and ``validate_scan_target``
decides whether the server may have it. A workspace scan names one *file* and
gets N directories out of it, none of which the client stated. That is a strictly
larger reach than the existing tools have, arrived at indirectly, and it is the
reason the workspace tool cannot simply inherit the single-directory check by
being called with the workspace root: accepting a scan target is also a decision
to write an output tree into it, and here there are N of them.

So every resolved project directory is validated. The workspace root's own
containment says nothing useful, because the resolver already guarantees every
project is below the root -- checking only the root would let one allowlisted
root authorise the whole tree beneath it regardless of where the allowlist
actually pointed.

Refusal is for the whole workspace, not the offending project
------------------------------------------------------------
Scanning the projects that pass and reporting success is the failure mode the
whole of workspace mode is built to avoid: a green result covering fewer
projects than the operator believes, with the passing projects supplying the
reassurance. ``resolver.py`` already argues this at length for a missing
project; a refused project is the same shape with a worse cause, and unlike a
missing project there is no ``--allow-missing-projects`` equivalent, because a
confinement refusal is a fact about what the server is permitted to touch rather
than a fact about this machine.

The deliberate asymmetry
------------------------
The workspace *file* is not confined. See
:meth:`TestTheWorkspaceFileIsNotConfined.test_a_workspace_file_outside_the_roots_is_not_refused`
for the argument; it is the one test here whose point is what the code does
*not* do, so it carries the reasoning rather than this docstring.
"""

from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from automated_security_helper.cli.mcp.scan_target import (
    ASH_MCP_ALLOWED_ROOTS_ENV,
    validate_scan_target,
)

MODULE_UNDER_TEST = "automated_security_helper.cli.mcp.workspace"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tool(name: str):
    return getattr(importlib.import_module(MODULE_UNDER_TEST), name)


def _workspace(root: Path, folders, name: str = "dev.code-workspace") -> Path:
    path = root / name
    path.write_text(
        json.dumps({"folders": [{"path": entry} for entry in folders]}),
        encoding="utf-8",
    )
    return path


def _project(root: Path, relative: str) -> Path:
    project = root / relative
    project.mkdir(parents=True, exist_ok=True)
    return project


@pytest.fixture(autouse=True)
def _clear_policy_env(monkeypatch):
    monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


@pytest.fixture
def isolated_registry(monkeypatch):
    """A fresh scan registry, so one test cannot see another's entries.

    ``get_scan_registry`` returns a module-level singleton with no reset, and it
    reads that global at call time -- so replacing the global is enough no matter
    how the module under test imported the accessor.
    """
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    fresh = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", fresh)
    return fresh


@pytest.fixture
def executions(monkeypatch) -> List[Tuple[Any, Any]]:
    """Record every ``execute_workspace`` call and fabricate its result.

    Recording is the only way to tell "refused the whole workspace" from
    "refused the offending project and scanned the rest": both can produce a
    failure response, and only one of them leaves this list empty.

    The result is fabricated from the real payload models rather than mocked, so
    a caller that reads a field off it gets a value the production type would
    actually hold.
    """
    from pathlib import Path as _Path

    from automated_security_helper.models.workspace import (
        ProjectRunStatus,
        WorkspaceProjectResult,
        WorkspaceResults,
    )
    from automated_security_helper.workspace import execution as execution_module
    from automated_security_helper.workspace.execution import WorkspaceRunResult

    calls: List[Tuple[Any, Any]] = []

    def _record(plan, settings, **kwargs):
        calls.append((plan, settings))
        projects = [
            WorkspaceProjectResult(
                project=project.key,
                relative_path=project.relative_path,
                display_label=project.display_label,
                status=ProjectRunStatus.COMPLETED,
                severity_threshold=project.gate_threshold,
                output_path=f"projects/{project.key}",
            )
            for project in plan.projects
        ]
        payload = WorkspaceResults(
            workspace_file=plan.workspace_file,
            workspace_root=plan.workspace_root,
            status="completed",
            exit_code=0,
            projects=projects,
            unconvertible_finding_paths=0,
        )
        return WorkspaceRunResult(
            results_path=_Path(settings.output_dir) / "ash_workspace_results.json",
            exit_code=0,
            payload=payload,
        )

    monkeypatch.setattr(execution_module, "execute_workspace", _record)
    module = importlib.import_module(MODULE_UNDER_TEST)
    if hasattr(module, "execute_workspace"):
        monkeypatch.setattr(module, "execute_workspace", _record)
    return calls


# ---------------------------------------------------------------------------
# 1. A project outside the roots refuses the whole workspace, and is named
# ---------------------------------------------------------------------------


class TestAProjectOutsideTheRootsRefusesEverything:
    """One escaping project stops the workspace; the response says which one."""

    @staticmethod
    def _split_workspace(tmp_path: Path) -> Tuple[Path, Path, Path]:
        """A workspace whose two projects straddle the allowlist boundary.

        The geometry matters and is not arbitrary. The resolver's own
        containment check already requires every project to sit below the
        workspace root, so for confinement to be able to disagree with it the
        allowlist has to name a *subdirectory* of the root. Here the root is
        ``tmp_path`` and the allowlist names ``tmp_path/repos``: ``repos/api``
        satisfies both rules and ``other/web`` satisfies only the resolver's.

        Plain nested directories, not symlinks: the resolver refuses a symlinked
        entry outright with a workspace error, which would mask the confinement
        refusal this test is about.
        """
        inside = _project(tmp_path, "repos/api")
        outside = _project(tmp_path, "other/web")
        workspace = _workspace(tmp_path, ["repos/api", "other/web"])
        return workspace, inside, outside

    @pytest.mark.asyncio
    async def test_the_whole_workspace_is_refused(
        self, tmp_path, monkeypatch, isolated_registry, executions
    ):
        workspace, inside, outside = self._split_workspace(tmp_path)
        allowed = tmp_path / "repos"
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(allowed))

        # Guard the premise. Without these the test could pass because the
        # allowlist refused both projects, or neither, for reasons unrelated to
        # the geometry above.
        assert validate_scan_target(inside) is None
        assert validate_scan_target(outside) is not None

        response = await _tool("mcp_scan_workspace")(workspace_file=str(workspace))

        assert response["success"] is False
        assert response["error_category"] == "invalid_path"
        assert executions == [], (
            "the workspace was executed despite a project outside the permitted "
            "roots; a partial scan reporting success is the outcome this refusal "
            "exists to prevent"
        )
        assert isolated_registry.get_scan_count() == 0

    @pytest.mark.asyncio
    async def test_the_error_names_the_offending_project_key(
        self, tmp_path, monkeypatch, isolated_registry, executions
    ):
        """The message has to identify which of N projects is the problem.

        ``other-web`` is the project *key* -- the workspace-relative path with
        separators replaced by dashes. It is asserted rather than a fragment of
        the directory path because the path is a ``tmp_path`` and those contain
        digits, hyphens, and the words "test" and "tmp": a substring assertion
        against the path would be satisfied by the path alone. No rendering of
        ``other/web`` on any platform produces the literal ``other-web``, so
        finding it proves the key was reported.
        """
        workspace, _inside, _outside = self._split_workspace(tmp_path)
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path / "repos"))

        response = await _tool("mcp_scan_workspace")(workspace_file=str(workspace))

        assert response["success"] is False
        assert "other-web" in response["error"], (
            f"the refusal must name the offending project key, got: "
            f"{response['error']!r}"
        )
        # The passing project must NOT be named as offending. Without this, a
        # message that listed every project would satisfy the assertion above.
        assert "repos-api" not in response["error"]

    @pytest.mark.asyncio
    async def test_the_same_workspace_scans_when_the_allowlist_covers_both(
        self, tmp_path, monkeypatch, isolated_registry, executions
    ):
        """Positive control: only the variable moves.

        Same workspace file, same two projects, same process. Widening the
        allowlist from ``repos`` to the workspace root flips the verdict, which
        a check that refused everything -- or accepted everything -- could not
        produce.
        """
        workspace, _inside, _outside = self._split_workspace(tmp_path)
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))

        response = await _tool("mcp_scan_workspace")(workspace_file=str(workspace))

        assert response["success"] is True
        assert len(executions) == 1


# ---------------------------------------------------------------------------
# 2. The workspace file itself is deliberately not confined
# ---------------------------------------------------------------------------


class TestTheWorkspaceFileIsNotConfined:
    """The asymmetry is intentional, so it gets a test that says why."""

    @pytest.mark.asyncio
    async def test_a_workspace_file_outside_the_roots_is_not_refused(
        self, tmp_path, monkeypatch, isolated_registry, executions
    ):
        """The definition file is a config input, and config inputs are not confined.

        ``ASH_MCP_ALLOWED_ROOTS`` answers "which directories may the server read
        source from and write an output tree into". The ``.code-workspace`` file
        is neither: it is read once, nothing is written near it, and it is
        supplied by the same caller who supplies ``config_path`` -- which
        ``mcp_scan_directory`` also leaves outside the policy, checking it only
        with ``validate_config_path``. Extending confinement to it would be a
        different rule wearing the same variable's name, and would break the
        ordinary deployment where definitions live beside a checkout rather than
        inside one.

        The geometry here is the mirror of the previous class: the allowlist
        names a subdirectory of the workspace root, so both projects are
        permitted while the workspace file and the root that holds it are not.
        An implementation that validated the file, or its parent, refuses this
        and fails.
        """
        root = tmp_path / "work"
        _project(root, "repos/api")
        _project(root, "repos/web")
        workspace = _workspace(root, ["repos/api", "repos/web"])
        allowed = root / "repos"
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(allowed))

        # Guard the premise: the file really is outside the permitted roots, and
        # so is the workspace root. If either were inside, this test would pass
        # while proving nothing.
        assert validate_scan_target(workspace.parent) is not None
        assert validate_scan_target(root) is not None
        assert validate_scan_target(root / "repos" / "api") is None

        response = await _tool("mcp_scan_workspace")(workspace_file=str(workspace))

        assert response["success"] is True, (
            f"the workspace file's own location was treated as a scan target: "
            f"{response.get('error')!r}"
        )
        assert len(executions) == 1

    @pytest.mark.asyncio
    async def test_the_workspace_config_is_not_confined_either(
        self, tmp_path, monkeypatch, isolated_registry, executions
    ):
        """Same argument for ``--workspace-config``, on the same geometry.

        The policy file is the other config input the tool accepts, and it is
        the one an operator is most likely to keep centrally -- one policy file
        governing several checkouts is the point of having it. Confining it
        would make that arrangement impossible.
        """
        root = tmp_path / "work"
        _project(root, "repos/api")
        workspace = _workspace(root, ["repos/api"])
        policy = tmp_path / "central" / "policy.yaml"
        policy.parent.mkdir(parents=True)
        # 'max_severity_threshold', which is what WorkspacePolicyConfig calls
        # the ceiling. The project-level field is named 'severity_threshold' and
        # the policy schema forbids extras, so the wrong one is a hard refusal
        # rather than an ignored key.
        policy.write_text(
            "workspace:\n  max_severity_threshold: HIGH\n",
            encoding="utf-8",
        )
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(root / "repos"))

        assert validate_scan_target(policy.parent) is not None

        response = await _tool("mcp_scan_workspace")(
            workspace_file=str(workspace), workspace_config=str(policy)
        )

        assert response["success"] is True, (
            f"the workspace policy file's location was treated as a scan "
            f"target: {response.get('error')!r}"
        )


# ---------------------------------------------------------------------------
# 3. One root covers N projects by containment, not by enumeration
# ---------------------------------------------------------------------------


class TestOneRootPermitsEveryProjectBeneathIt:
    """Containment, at any depth, from a single allowlist entry."""

    @pytest.mark.asyncio
    async def test_three_projects_at_three_depths_are_all_permitted(
        self, tmp_path, monkeypatch, isolated_registry, executions
    ):
        """A single entry authorises the subtree, not just its direct children.

        Two wrong implementations this separates from the right one. Requiring
        each project to *equal* an allowlist entry refuses all three, so an
        operator would have to enumerate every project and re-edit the variable
        whenever the workspace gained one. Checking only one level down refuses
        ``team/infra`` and passes the other two, which is worse than refusing
        everything because it looks like it works.
        """
        root = tmp_path / "work"
        allowed = root / "repos"
        for relative in ("repos/api", "repos/web", "repos/team/infra"):
            _project(root, relative)
        workspace = _workspace(root, ["repos/api", "repos/web", "repos/team/infra"])
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(allowed))

        response = await _tool("mcp_scan_workspace")(workspace_file=str(workspace))

        assert response["success"] is True, (
            f"one allowlisted root did not cover its subtree: {response.get('error')!r}"
        )
        assert len(executions) == 1
        plan, _settings = executions[0]
        assert {project.key for project in plan.active_projects} == {
            "repos-api",
            "repos-web",
            "repos-team-infra",
        }

    @pytest.mark.asyncio
    async def test_the_second_of_two_configured_roots_also_counts(
        self, tmp_path, monkeypatch, isolated_registry, executions
    ):
        """Every entry in the list is consulted, not only the first.

        ``os.pathsep`` rather than a literal separator, for the reason
        ``scan_target._allowed_roots`` documents: on Windows the separator is
        ``;`` and a colon appears inside ordinary paths.
        """
        root = tmp_path / "work"
        _project(root, "first/api")
        _project(root, "second/web")
        workspace = _workspace(root, ["first/api", "second/web"])
        monkeypatch.setenv(
            ASH_MCP_ALLOWED_ROOTS_ENV,
            os.pathsep.join([str(root / "first"), str(root / "second")]),
        )

        response = await _tool("mcp_scan_workspace")(workspace_file=str(workspace))

        assert response["success"] is True, (
            f"only one of two configured roots was honoured: {response.get('error')!r}"
        )


# ---------------------------------------------------------------------------
# 4. With no allowlist configured, an ordinary workspace still scans
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_unconfigured_policy_does_not_refuse_an_ordinary_workspace(
    tmp_path, isolated_registry, executions
):
    """The default policy is a safety net, not a boundary, and must not bite here.

    ``ASH_MCP_ALLOWED_ROOTS`` unset means the short fixed refusal set applies --
    host configuration and kernel interfaces. Nothing in a normal checkout is in
    it. This is the test that catches the most damaging way to get confinement
    wrong: treating an empty allowlist as "allow nothing", which refuses every
    workspace on every deployment that has not set the variable.
    """
    root = tmp_path / "work"
    _project(root, "api")
    _project(root, "web")
    workspace = _workspace(root, ["api", "web"])

    response = await _tool("mcp_scan_workspace")(workspace_file=str(workspace))

    assert response["success"] is True, (
        f"an unset allowlist refused an ordinary workspace: {response.get('error')!r}"
    )
    assert len(executions) == 1


# ---------------------------------------------------------------------------
# 5. Resolution runs before confinement, and confinement before execution
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_workspace_error_is_reported_as_such_even_when_confinement_would_refuse(
    tmp_path, monkeypatch, isolated_registry, executions
):
    """A workspace that is both malformed and outside the roots reports the malformation.

    Confinement cannot run first: it needs the resolved project directories,
    which only resolution produces. So the order is forced, and this pins it --
    an implementation that tried to pre-screen the workspace root before
    resolving would report a confinement refusal for a file whose real problem
    is that it lists a folder nobody cloned, sending the operator to edit an
    environment variable instead of their workspace file.
    """
    root = tmp_path / "work"
    _project(root, "api")
    workspace = _workspace(root, ["api", "never-cloned"])
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path / "elsewhere"))
    (tmp_path / "elsewhere").mkdir()

    response: Dict[str, Any] = await _tool("mcp_scan_workspace")(
        workspace_file=str(workspace)
    )

    assert response["success"] is False
    assert "never-cloned" in response["error"], (
        f"the malformed-definition problem was masked by a confinement "
        f"refusal, got: {response['error']!r}"
    )
    assert executions == []
