#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``mcp_resolve_workspace`` renders the plan and scans nothing.

Why this file exists
--------------------
The CLI's ``--dry-run`` is one line -- ``typer.echo(plan.render())`` followed by
an exit at 0 -- and it earns its keep by being the same plan object the scan
would run from. An operator inspects it, then drops the flag, and what they
inspected is what runs.

The MCP equivalent has to preserve both halves of that. The rendered plan has to
come back, because a plan reduced to a JSON dump is not the artefact
``plan.render()`` was written to produce and the client has no way to reconstruct
the layout. And nothing may be scanned, because an MCP client asking "what would
this workspace do" is asking a question, and answering it by scanning N
repositories is expensive, writes an output tree into each one, and takes a
registry slot that blocks the real scan the client is about to ask for.

Proving "scanned nothing" needs more than a string
--------------------------------------------------
A tool that scanned everything and then returned the rendered plan satisfies any
assertion about the return value. So the absence of scanning is measured three
independent ways: no orchestrator was constructed, no registry entry exists, and
no output artefact was written to the filesystem. The third is the one that holds
even if the first two are bypassed by an implementation that reaches the
scanners by some route these tests do not know about.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

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


def _project(root: Path, relative: str, config: str | None = None) -> Path:
    project = root / relative
    project.mkdir(parents=True, exist_ok=True)
    if config is not None:
        ash_dir = project / ".ash"
        ash_dir.mkdir(exist_ok=True)
        (ash_dir / "ash.yaml").write_text(config, encoding="utf-8")
    return project


@pytest.fixture(autouse=True)
def _clear_policy_env(monkeypatch):
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


@pytest.fixture
def isolated_registry(monkeypatch):
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    fresh = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", fresh)
    return fresh


@pytest.fixture
def orchestrators_built(monkeypatch) -> List[Dict[str, Any]]:
    """Record every ``ASHScanOrchestrator.create`` call without performing one.

    ``create`` and not ``__init__``: it is the factory ``execute_workspace``
    defaults to, and replacing it means a project scan cannot start even if
    something does try. Recording rather than raising, because
    ``_scan_one_project`` catches ``Exception`` per project -- a raise would be
    swallowed into a failed-project outcome and the count would be the only
    honest signal left.
    """
    from automated_security_helper.core import orchestrator as orchestrator_module

    calls: List[Dict[str, Any]] = []

    def _record(**kwargs):
        calls.append(kwargs)
        raise AssertionError(
            "an ASHScanOrchestrator was constructed during a resolve-only call"
        )

    monkeypatch.setattr(orchestrator_module.ASHScanOrchestrator, "create", _record)
    return calls


@pytest.fixture
def executions(monkeypatch) -> List[Any]:
    """Record ``execute_workspace`` calls. It must never be reached from resolve."""
    from automated_security_helper.workspace import execution as execution_module

    calls: List[Any] = []

    def _record(plan, settings, **kwargs):
        calls.append((plan, settings))
        raise AssertionError("execute_workspace was called during a resolve-only call")

    monkeypatch.setattr(execution_module, "execute_workspace", _record)
    module = importlib.import_module(MODULE_UNDER_TEST)
    if hasattr(module, "execute_workspace"):
        monkeypatch.setattr(module, "execute_workspace", _record)
    return calls


def _three_project_workspace(tmp_path: Path) -> Path:
    root = tmp_path / "work"
    _project(root, "api")
    _project(root, "web")
    _project(root, "team/infra")
    return _workspace(root, ["api", "web", "team/infra"])


# ---------------------------------------------------------------------------
# 1. The rendered plan comes back
# ---------------------------------------------------------------------------


class TestTheRenderedPlanIsReturned:
    """The response carries ``plan.render()``, not a paraphrase of it."""

    @pytest.mark.asyncio
    async def test_the_response_carries_the_rendered_plan(
        self, tmp_path, isolated_registry, orchestrators_built, executions
    ):
        """Compared against an independent render of the same workspace.

        Both sides call production code, so this is not a proof that ``render()``
        is correct -- ``tests/unit/workspace`` owns that. What it pins is that
        the tool returns that text and only that text: a ``str(plan)`` (the
        pydantic repr), a ``model_dump_json()``, a truncation, or a
        Rich-formatted variant all fail here.
        """
        from automated_security_helper.workspace.resolver import resolve_workspace

        workspace = _three_project_workspace(tmp_path)
        expected = resolve_workspace(workspace).render()

        response = await _tool("mcp_resolve_workspace")(workspace_file=str(workspace))

        assert response["success"] is True, response.get("error")
        assert response["plan"] == expected

    @pytest.mark.asyncio
    async def test_the_rendered_plan_names_every_project_key(
        self, tmp_path, isolated_registry, orchestrators_built, executions
    ):
        """A structural check that does not depend on ``render()``'s layout.

        The equality test above would keep passing if ``render()`` were changed
        to emit an empty string, because the expectation is rendered the same
        way. This one would not: the three keys have to be present, and
        ``team-infra`` in particular cannot be produced by any path rendering of
        ``team/infra``, so finding it proves the key -- not just the path -- was
        reported.
        """
        workspace = _three_project_workspace(tmp_path)

        response = await _tool("mcp_resolve_workspace")(workspace_file=str(workspace))

        rendered = response["plan"]
        for key in ("api", "web", "team-infra"):
            assert key in rendered, f"the plan does not name project {key!r}"
        assert "Nothing has been scanned" in rendered, (
            "the plan is missing the line that tells the reader this was a "
            "resolution pass only"
        )

    @pytest.mark.asyncio
    async def test_a_project_config_reaches_the_rendered_plan(
        self, tmp_path, isolated_registry, orchestrators_built, executions
    ):
        """Resolution really ran; the plan is not a restatement of the input file.

        The threshold and the label are only knowable by loading each project's
        own config, which is the expensive half of resolution and the half a
        shortcut implementation would skip -- returning a plan built from the
        workspace file alone, which would look right and would be missing
        exactly the decisions ``--dry-run`` exists to disclose.
        """
        root = tmp_path / "work"
        _project(
            root,
            "api",
            config=(
                "project_name: payments-api\n"
                "global_settings:\n  severity_threshold: CRITICAL\n"
            ),
        )
        workspace = _workspace(root, ["api"])

        response = await _tool("mcp_resolve_workspace")(workspace_file=str(workspace))

        rendered = response["plan"]
        assert "payments-api" in rendered
        assert "CRITICAL" in rendered


# ---------------------------------------------------------------------------
# 2. Nothing is scanned
# ---------------------------------------------------------------------------


class TestNothingIsScanned:
    """Three independent probes, because the return value cannot show this."""

    @pytest.mark.asyncio
    async def test_no_orchestrator_is_constructed(
        self, tmp_path, isolated_registry, orchestrators_built, executions
    ):
        workspace = _three_project_workspace(tmp_path)

        response = await _tool("mcp_resolve_workspace")(workspace_file=str(workspace))

        assert response["success"] is True, response.get("error")
        assert orchestrators_built == [], (
            f"{len(orchestrators_built)} orchestrator(s) were built during a "
            f"resolve-only call"
        )
        assert executions == [], "execute_workspace was reached from resolve"

    @pytest.mark.asyncio
    async def test_no_scan_is_registered(
        self, tmp_path, isolated_registry, orchestrators_built, executions
    ):
        """A registry entry is a claim that a scan is pending or running.

        Making that claim for a dry run would block the real scan the client is
        about to request on the same directories -- ``register_scan`` refuses a
        second active scan on a directory that already has one -- and would make
        ``list_active_scans`` report work nobody is doing.
        """
        workspace = _three_project_workspace(tmp_path)

        await _tool("mcp_resolve_workspace")(workspace_file=str(workspace))

        assert isolated_registry.get_scan_count() == 0
        assert isolated_registry.list_scans(active_only=True) == []

    @pytest.mark.asyncio
    async def test_no_output_artefact_is_written(
        self, tmp_path, isolated_registry, orchestrators_built, executions
    ):
        """The filesystem probe, which does not depend on knowing the code path.

        ``projects/`` is the subtree ``_project_output_dir`` creates before a
        project scan starts, and ``ash_aggregated_results.json`` is what a
        finished one writes. Neither name exists anywhere in the fixture, so
        finding either means work happened. This is the assertion that still
        bites if a future implementation reaches the scanners by a route the two
        recorders above do not cover.
        """
        workspace = _three_project_workspace(tmp_path)

        await _tool("mcp_resolve_workspace")(workspace_file=str(workspace))

        assert list(tmp_path.rglob("projects")) == []
        assert list(tmp_path.rglob("ash_aggregated_results.json")) == []
        assert list(tmp_path.rglob("ash_workspace_results.json")) == []


# ---------------------------------------------------------------------------
# 3. The two flags the tool accepts change the plan
# ---------------------------------------------------------------------------


class TestTheResolveFlagsAreHonoured:
    """``allow_missing_projects`` and ``workspace_config`` are not decorative."""

    @pytest.mark.asyncio
    async def test_allow_missing_projects_turns_a_refusal_into_a_disclosed_skip(
        self, tmp_path, isolated_registry, orchestrators_built, executions
    ):
        """Both arms, on one workspace, with only the flag moving.

        Dropping the parameter silently would leave the default in force, which
        refuses -- and a caller who passed the flag would read the refusal as a
        workspace they need to fix rather than as an argument that was ignored.
        The skip has to appear in the plan text as well, because that is the only
        place the caller can see which project was dropped.
        """
        root = tmp_path / "work"
        _project(root, "api")
        workspace = _workspace(root, ["api", "never-cloned"])
        tool = _tool("mcp_resolve_workspace")

        refused = await tool(workspace_file=str(workspace))
        allowed = await tool(workspace_file=str(workspace), allow_missing_projects=True)

        assert refused["success"] is False
        assert allowed["success"] is True, allowed.get("error")
        assert "never-cloned" in allowed["plan"]
        assert "skipped" in allowed["plan"]

    @pytest.mark.asyncio
    async def test_workspace_config_reaches_the_plan(
        self, tmp_path, isolated_registry, orchestrators_built, executions
    ):
        """A named policy file shows up as the policy the plan reports.

        The plan prints a ``policy:`` line only when there is one, so its
        presence is the observable. Dropping the parameter would leave the plan
        describing a scan with no ceiling while the scan the caller runs next
        applies one -- the exact drift ``--dry-run`` exists to rule out.
        """
        root = tmp_path / "work"
        _project(root, "api")
        workspace = _workspace(root, ["api"])
        policy = tmp_path / "central" / "ash-workspace.yaml"
        policy.parent.mkdir(parents=True)
        policy.write_text(
            "workspace:\n  max_severity_threshold: CRITICAL\n", encoding="utf-8"
        )
        tool = _tool("mcp_resolve_workspace")

        without = await tool(workspace_file=str(workspace))
        with_policy = await tool(
            workspace_file=str(workspace), workspace_config=str(policy)
        )

        assert without["success"] is True, without.get("error")
        assert with_policy["success"] is True, with_policy.get("error")
        assert "policy:" not in without["plan"]
        assert "policy:" in with_policy["plan"]

    @pytest.mark.asyncio
    async def test_a_named_policy_file_that_is_absent_is_refused(
        self, tmp_path, isolated_registry, orchestrators_built, executions
    ):
        """Naming a policy file that is not there must not fall back to searching.

        Falling back would apply different policy than the one asked for, and
        silently: the plan would render, the caller would read a ceiling they did
        not name, and nothing would say so.
        """
        root = tmp_path / "work"
        _project(root, "api")
        workspace = _workspace(root, ["api"])
        absent = tmp_path / "central" / "ash-workspace.yaml"

        response = await _tool("mcp_resolve_workspace")(
            workspace_file=str(workspace), workspace_config=str(absent)
        )

        assert response["success"] is False
        assert executions == []
