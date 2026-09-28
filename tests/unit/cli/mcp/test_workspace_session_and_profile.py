#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Workspace mode composes with sessions and profiles, like every other tool.

Why this file exists
--------------------
The two workspace tools were the only MCP surface that knew nothing about a
session. ``resolve_ash_workspace`` and ``run_ash_workspace_scan`` took neither a
``session_id`` nor a profile, and ``cli/mcp/workspace.py`` mentioned neither, so
three things that hold everywhere else did not hold here:

1. **A delivered tree was unscannable as a workspace.** Confinement grants a
   session its own sandbox by passing ``session_id`` to ``validate_scan_target``.
   The workspace path called it without one, so a ``.code-workspace`` file inside
   a tree the client had just uploaded had every one of its projects refused by
   the boundary that exists to permit exactly that.
2. **A bound profile was ignored.** A session that called ``select_profile`` and
   then scanned a workspace got the profile's config on a single-directory scan
   and not on a workspace scan -- the same session, the same binding, two
   answers.
3. **The workspace file itself was unconfined.** It is the input that names N
   scan targets, and reading a caller-named path is a capability: the read happens
   during resolution, before any target exists, so confining the targets does not
   cover it.

The third is the one that changes an existing assertion, and the change is
argued where it happens -- see ``TestTheWorkspaceFileIsNowConfined``.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

MODULE_UNDER_TEST = "automated_security_helper.cli.mcp.workspace"


def _tool(name: str):
    return getattr(importlib.import_module(MODULE_UNDER_TEST), name)


def _workspace(root: Path, folders, name: str = "dev.code-workspace") -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
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
def _clean_env(monkeypatch, tmp_path):
    from automated_security_helper.cli.mcp import profile_registry

    # The literal rather than sandbox.ASH_MCP_TRANSPORT_ENV, deliberately. This is
    # an autouse fixture, so importing a module the change introduces makes every
    # test in the file ERROR at setup when run against the pre-change code -- 14
    # errors and zero failures, which is evidence of nothing except that the tests
    # are new. Keeping the fixture free of new imports is what lets the failures
    # below be real ones. The constant is asserted to equal this string in
    # test_session_sandbox.py, so the two cannot drift apart silently.
    ASH_MCP_TRANSPORT_ENV = "ASH_MCP_TRANSPORT"

    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv(ASH_MCP_TRANSPORT_ENV, "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    profile_registry.clear_profile_registry()
    profile_registry.clear_session_state()
    yield
    profile_registry.clear_profile_registry()
    profile_registry.clear_session_state()


@pytest.fixture
def isolated_registry(monkeypatch):
    """A fresh scan registry, so one test cannot see another's entries."""
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    fresh = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", fresh)
    return fresh


@pytest.fixture
def executions(monkeypatch) -> List[Tuple[Any, Any]]:
    """Record every ``execute_workspace`` call and fabricate its result.

    Recording is what separates "refused the whole workspace" from "refused the
    offending project and scanned the rest": both produce a failure response and
    only one leaves this list empty. Same fixture shape as
    ``test_workspace_confinement.py``, deliberately -- the two files assert about
    the same boundary from opposite sides.
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
        payload = WorkspaceResults(
            workspace_file=plan.workspace_file,
            workspace_root=plan.workspace_root,
            status="completed",
            exit_code=0,
            projects=[
                WorkspaceProjectResult(
                    project=project.key,
                    relative_path=project.relative_path,
                    display_label=project.display_label,
                    status=ProjectRunStatus.COMPLETED,
                    severity_threshold=project.gate_threshold,
                    output_path=f"projects/{project.key}",
                )
                for project in plan.projects
            ],
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
# 1. A delivered tree is scannable as a workspace
# ---------------------------------------------------------------------------


class TestADeliveredWorkspaceIsScannable:
    """The session's own sandbox counts as a permitted root here too."""

    @staticmethod
    def _delivered_workspace(session_id: str) -> Path:
        """A ``.code-workspace`` and two projects inside a session's sandbox.

        Built through ``session_sandbox`` so the test cannot pass against a
        layout that differs from the one source delivery writes.
        """
        from automated_security_helper.cli.mcp.sandbox import session_sandbox

        source = session_sandbox(session_id).source_dir
        _project(source, "api")
        _project(source, "web")
        return _workspace(source, ["api", "web"])

    @pytest.mark.asyncio
    async def test_a_workspace_inside_the_session_sandbox_scans(
        self, tmp_path, monkeypatch, isolated_registry, executions
    ):
        """This is the case that fails without the change.

        An operator has bounded the scan surface to its own checkouts, which is
        what the docs tell them to do. A client then uploads a source tree and
        asks for the workspace inside it. Every project resolves under the
        session's sandbox, which no operator would ever list, so without the
        session id the whole workspace is refused -- by the boundary that exists
        to make delivered trees scannable.
        """
        checkout = tmp_path / "operator-checkout"
        checkout.mkdir()
        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(checkout))

        workspace = self._delivered_workspace("session-a")

        response = await _tool("mcp_scan_workspace")(
            workspace_file=str(workspace), session_id="session-a"
        )

        assert response["success"] is True, (
            f"a workspace delivered over the protocol was refused: "
            f"{response.get('error')!r}"
        )
        assert len(executions) == 1

    @pytest.mark.asyncio
    async def test_another_sessions_delivered_workspace_is_refused(
        self, tmp_path, monkeypatch, isolated_registry, executions
    ):
        """Passing a session id must not become a way to name any session's tree.

        The naive implementation of the previous test -- grant the shared
        workspace root -- passes it and opens every tenant at once. This is the
        test that separates the two.
        """
        workspace = self._delivered_workspace("session-b")

        response = await _tool("mcp_scan_workspace")(
            workspace_file=str(workspace), session_id="session-a"
        )

        assert response["success"] is False, (
            "session-a scanned a workspace inside session-b's sandbox"
        )
        assert executions == []
        assert isolated_registry.get_scan_count() == 0


# ---------------------------------------------------------------------------
# 2. A bound profile reaches a workspace scan
# ---------------------------------------------------------------------------


class TestABoundProfileReachesAWorkspaceScan:
    """The same session and the same binding must mean the same config."""

    @pytest.fixture(autouse=True)
    def _granted(self, monkeypatch, tmp_path):
        """Grant everything under ``tmp_path``, so confinement stays out of the way.

        These tests use a real session id, which makes them remote callers subject
        to deny-by-default and to config confinement. They are about which config a
        scan runs under, not about the boundary -- ``TestTheWorkspaceFileIsNowConfined``
        owns that -- so without a grant every one of them is refused before it can
        report a config, which is correct behavior and a useless fixture.
        """
        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))

    @staticmethod
    def _bind(tmp_path: Path, session_id: str, project_name: str) -> str:
        from automated_security_helper.cli.mcp.profile_registry import (
            register_profiles,
            resolve_session_config_path,
            set_profile_registry,
        )
        from automated_security_helper.cli.mcp_tools import mcp_select_profile

        path = tmp_path / "profile.ash.yaml"
        path.write_text(f"project_name: {project_name}\n", encoding="utf-8")
        set_profile_registry(register_profiles([f"strict={path}"]))
        result = mcp_select_profile("strict", session_id=session_id)
        assert result["success"] is True, result.get("error")
        return resolve_session_config_path(session_id)

    @pytest.mark.asyncio
    async def test_the_bound_config_becomes_the_workspace_scans_config(
        self, tmp_path, isolated_registry, executions
    ):
        """Asserted on BOTH the plan and the settings record, because both matter.

        The settings record is what ``execute_workspace`` scans from and the plan
        is what the dry run reports. A profile threaded into only one of them
        produces a ``--dry-run`` describing a scan that does not happen, and
        nothing raises -- so asserting on one alone would pass over the defect
        this parameter is most likely to introduce.

        In workspace mode a profile is the fallback for a project that declares no
        config of its own, not a config for the workspace: ``api`` has no
        ``.ash.yaml``, so its ``config_source`` becomes the bound file.
        """
        bound = self._bind(tmp_path, "session-a", "from-the-profile")
        root = tmp_path / "work"
        _project(root, "api")
        workspace = _workspace(root, ["api"])

        response = await _tool("mcp_scan_workspace")(
            workspace_file=str(workspace), session_id="session-a"
        )

        assert response["success"] is True, response.get("error")
        assert len(executions) == 1
        plan, settings = executions[0]
        assert settings.default_config_path == bound, (
            "the workspace scan ignored the config this session bound, so "
            "select_profile means one thing for run_ash_scan and another here"
        )
        assert [p.config_source for p in plan.active_projects] == [bound], (
            "the plan reports a different config than the scan will use, so the "
            "dry run describes a scan that does not happen"
        )

    @pytest.mark.asyncio
    async def test_a_projects_own_config_still_wins_over_the_profile(
        self, tmp_path, isolated_registry, executions
    ):
        """A project that declares a config keeps it.

        The project's own ``.ash.yaml`` is the more specific statement, and it is
        what makes one workspace scannable across differently-configured
        repositories. A profile that overrode it would silently rescan every
        project under one config -- and the naive implementation, passing the
        profile as the config for the whole workspace, does exactly that.
        """
        self._bind(tmp_path, "session-a", "from-the-profile")
        root = tmp_path / "work"
        own = _project(root, "api")
        (own / ".ash.yaml").write_text("project_name: the-api\n", encoding="utf-8")
        workspace = _workspace(root, ["api"])

        response = await _tool("mcp_scan_workspace")(
            workspace_file=str(workspace), session_id="session-a"
        )

        assert response["success"] is True, response.get("error")
        plan, _settings = executions[0]
        # ``as_posix()``, not ``str()``: the plan spells every path it reports
        # POSIX-shaped, which ``test_config_source_names_the_file_that_was_used``
        # in tests/unit/workspace/test_resolver.py has pinned since workspace mode
        # landed. The two agree on POSIX and differ on Windows, so ``str()`` here
        # asserted a spelling the model does not use and failed on the Windows leg
        # alone.
        assert (
            plan.active_projects[0].config_source
            == (own / ".ash.yaml").resolve().as_posix()
        )

    @pytest.mark.asyncio
    async def test_an_explicit_profile_argument_selects_a_registered_profile(
        self, tmp_path, isolated_registry, executions
    ):
        """A one-call profile choice, without binding it to the whole session.

        Useful for a client that scans several workspaces under different
        configs on one connection, and the reason ``profile`` is a parameter
        rather than only a session binding.
        """
        from automated_security_helper.cli.mcp.profile_registry import (
            register_profiles,
            set_profile_registry,
        )

        picked = tmp_path / "picked.ash.yaml"
        picked.write_text("project_name: picked-per-call\n", encoding="utf-8")
        set_profile_registry(register_profiles([f"picked={picked}"]))

        root = tmp_path / "work"
        _project(root, "api")
        workspace = _workspace(root, ["api"])

        response = await _tool("mcp_scan_workspace")(
            workspace_file=str(workspace),
            session_id="session-a",
            profile="picked",
        )

        assert response["success"] is True, response.get("error")
        _plan, settings = executions[0]
        assert settings.default_config_path is not None
        assert "picked-per-call" in Path(settings.default_config_path).read_text(
            "utf-8"
        )

    @pytest.mark.asyncio
    async def test_an_unknown_profile_is_refused_and_nothing_is_scanned(
        self, tmp_path, isolated_registry, executions
    ):
        """Refused, not ignored.

        Falling back to the default config for a profile name the operator never
        registered would scan N repositories under configuration the client did
        not ask for and report success.
        """
        root = tmp_path / "work"
        _project(root, "api")
        workspace = _workspace(root, ["api"])

        response = await _tool("mcp_scan_workspace")(
            workspace_file=str(workspace),
            session_id="session-a",
            profile="never-registered",
        )

        assert response["success"] is False
        assert "never-registered" in response["error"]
        assert executions == []

    @pytest.mark.asyncio
    async def test_resolve_reports_which_config_the_scan_would_use(
        self, tmp_path, isolated_registry
    ):
        """``resolve_ash_workspace`` is the dry run, so it has to agree with the scan.

        A dry run that reported the plan a *different* config would produce is
        worse than no dry run: it is the artifact a client checks before
        committing to N repository scans.
        """
        bound = self._bind(tmp_path, "session-a", "from-the-profile")
        root = tmp_path / "work"
        _project(root, "api")
        workspace = _workspace(root, ["api"])

        response = await _tool("mcp_resolve_workspace")(
            workspace_file=str(workspace), session_id="session-a"
        )

        assert response["success"] is True, response.get("error")
        assert response["session_config_path"] == bound


# ---------------------------------------------------------------------------
# 3. The workspace file and policy file are now confined
# ---------------------------------------------------------------------------


class TestTheWorkspaceFileIsNowConfined:
    """This replaces ``TestTheWorkspaceFileIsNotConfined``, and here is why.

    The old test asserted that a ``.code-workspace`` file outside the permitted
    roots is accepted, and its argument was that the file is a config input
    rather than a scan target: read once, nothing written near it, and the same
    caller supplies ``config_path``, which is also unconfined. Half of that is
    still true and the conclusion does not follow from it.

    What the argument missed is that reading a caller-named path is itself a
    capability. An unconfined one is a file-read oracle: point ``workspace_file``
    at any path on the server and the parse error or the resolved plan reports
    something about its content. The read happens during resolution, before any
    project directory exists, so confining the projects does not cover it -- which
    makes this the *more* interesting half of the surface to leave open, not the
    less. And ``config_path`` being unconfined too was a second instance of the
    same defect rather than a precedent; it is now confined as well.

    The deployment the old asymmetry served is real and still works: a shared
    policy file governing several checkouts has to live outside the trees it
    governs. It is served by an explicit grant --
    ``ASH_MCP_ALLOWED_CONFIG_ROOTS`` -- rather than by confining nothing, which
    is what ``test_a_granted_config_root_is_accepted`` pins. So the capability the
    old test protected is preserved and the oracle is closed.
    """

    @pytest.mark.asyncio
    async def test_a_workspace_file_outside_every_root_is_refused(
        self, tmp_path, monkeypatch, isolated_registry, executions
    ):
        root = tmp_path / "work"
        _project(root, "repos/api")
        workspace = _workspace(root, ["repos/api"])
        # The projects are permitted; only the file that names them is not.
        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(root / "repos"))

        response = await _tool("mcp_scan_workspace")(
            workspace_file=str(workspace), session_id="session-a"
        )

        assert response["success"] is False, (
            "an arbitrary path on the server was accepted as a workspace "
            "definition, which makes resolution a file-read oracle"
        )
        assert response["error_category"] == "invalid_path"
        assert executions == []

    @pytest.mark.asyncio
    async def test_a_granted_config_root_is_accepted(
        self, tmp_path, monkeypatch, isolated_registry, executions
    ):
        """The central-policy deployment, preserved by explicit grant."""
        root = tmp_path / "work"
        _project(root, "repos/api")
        workspace = _workspace(root, ["repos/api"])
        policy = tmp_path / "central" / "policy.yaml"
        policy.parent.mkdir(parents=True)
        policy.write_text(
            "workspace:\n  max_severity_threshold: HIGH\n", encoding="utf-8"
        )

        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(root / "repos"))
        # Both the definition's own directory and the policy's are granted.
        monkeypatch.setenv(
            "ASH_MCP_ALLOWED_CONFIG_ROOTS",
            f"{root}{__import__('os').pathsep}{policy.parent}",
        )

        response = await _tool("mcp_scan_workspace")(
            workspace_file=str(workspace),
            workspace_config=str(policy),
            session_id="session-a",
        )

        assert response["success"] is True, (
            f"a granted config root was still refused: {response.get('error')!r}"
        )
        assert len(executions) == 1

    @pytest.mark.asyncio
    async def test_a_policy_file_outside_every_root_is_refused(
        self, tmp_path, monkeypatch, isolated_registry, executions
    ):
        root = tmp_path / "work"
        _project(root, "repos/api")
        workspace = _workspace(root, ["repos/api"])
        policy = tmp_path / "central" / "policy.yaml"
        policy.parent.mkdir(parents=True)
        policy.write_text(
            "workspace:\n  max_severity_threshold: HIGH\n", encoding="utf-8"
        )

        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(root / "repos"))
        monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(root))

        response = await _tool("mcp_scan_workspace")(
            workspace_file=str(workspace),
            workspace_config=str(policy),
            session_id="session-a",
        )

        assert response["success"] is False
        assert executions == []

    @pytest.mark.asyncio
    async def test_a_local_caller_still_accepts_a_workspace_file_anywhere(
        self, tmp_path, isolated_registry, executions
    ):
        """stdio did not change, and neither did the test that pinned it.

        ``test_workspace_confinement.py`` passes unmodified, because every call in
        it resolves to a local caller. That is the point of keying deny-by-default
        on who is calling rather than on the roots alone: the local deployment,
        where the caller already holds the server's own filesystem privileges,
        keeps working exactly as before.

        ``DEFAULT_SESSION_ID`` rather than ``None``, because that is what a real
        stdio tool call resolves to -- ``session_identity`` returns the sentinel
        when no header arrived, and ``caller_is_remote`` reads exactly that.
        """
        from automated_security_helper.cli.mcp.profile_registry import (
            DEFAULT_SESSION_ID,
        )

        root = tmp_path / "work"
        _project(root, "repos/api")
        workspace = _workspace(root, ["repos/api"])

        response = await _tool("mcp_scan_workspace")(
            workspace_file=str(workspace), session_id=DEFAULT_SESSION_ID
        )

        assert response["success"] is True, response.get("error")
        assert len(executions) == 1


# ---------------------------------------------------------------------------
# 4. The registered tools take their session from the transport
# ---------------------------------------------------------------------------


class TestTheRegisteredToolsResolveTheirOwnSession:
    """A client must not be able to name its own session id.

    Letting it would let it name another client's. The four source-delivery tools
    already take the session from the header for exactly this reason; the
    workspace tools now do too.
    """

    @pytest.mark.asyncio
    async def test_the_scan_tool_passes_the_header_session_through(
        self, tmp_path, monkeypatch
    ):
        from automated_security_helper.cli import mcp_server

        seen: Dict[str, Any] = {}

        async def _record(**kwargs):
            seen.update(kwargs)
            return {"success": True, "exit_code": 0, "projects": []}

        monkeypatch.setattr(mcp_server, "mcp_scan_workspace", _record)
        ctx = _FakeContext({"mcp-session-id": "session-from-header"})

        await mcp_server.run_ash_workspace_scan(
            ctx, workspace_file=str(tmp_path / "dev.code-workspace")
        )

        assert seen["session_id"] == "session-from-header"

    @pytest.mark.asyncio
    async def test_the_resolve_tool_passes_the_header_session_through(
        self, tmp_path, monkeypatch
    ):
        from automated_security_helper.cli import mcp_server

        seen: Dict[str, Any] = {}

        async def _record(**kwargs):
            seen.update(kwargs)
            return {"success": True, "exit_code": 0, "projects": []}

        monkeypatch.setattr(mcp_server, "mcp_resolve_workspace", _record)
        ctx = _FakeContext({"mcp-session-id": "session-from-header"})

        await mcp_server.resolve_ash_workspace(
            ctx, workspace_file=str(tmp_path / "dev.code-workspace")
        )

        assert seen["session_id"] == "session-from-header"

    @pytest.mark.asyncio
    async def test_a_malformed_session_header_is_refused(self, tmp_path):
        """Refused rather than sanitized, matching the delivery tools."""
        from automated_security_helper.cli import mcp_server

        ctx = _FakeContext({"mcp-session-id": "../escape"})

        response = await mcp_server.run_ash_workspace_scan(
            ctx, workspace_file=str(tmp_path / "dev.code-workspace")
        )

        assert response["success"] is False
        assert response["error_type"] == "invalid_session_id"


class _FakeContext:
    """The slice of ``Context`` the workspace tools touch."""

    def __init__(self, headers: Optional[Dict[str, str]] = None) -> None:
        self.headers = headers or {}
        self.messages: List[str] = []

    async def info(self, message: str) -> None:
        self.messages.append(f"info: {message}")

    async def error(self, message: str) -> None:
        self.messages.append(f"error: {message}")

    async def warning(self, message: str) -> None:
        self.messages.append(f"warning: {message}")

    async def debug(self, message: str) -> None:
        self.messages.append(f"debug: {message}")

    async def report_progress(self, **kwargs) -> None:
        return None
