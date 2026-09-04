#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan registers one scan per project, and the registry keeps them apart.

Why this file exists
--------------------
Every existing MCP scan is one directory and one registry entry, so "which scan
is this" and "which directory is this" have always been the same question. A
workspace scan breaks that: one tool call, N directories, and a client that then
wants to poll progress or fetch results needs a handle per project rather than
one handle for the batch.

Registering N entries also puts the registry's duplicate-detection rule under
load for the first time. ``ScanRegistry.register_scan`` refuses a second active
scan on a directory that already has one, and it decides that with a raw string
comparison on the un-canonicalised path it was handed. With one caller supplying
one hand-typed path that was survivable. With N paths derived from a file that an
operator wrote, two of which may spell the same directory differently, it is a
double scan: the same source examined twice, its findings attributed twice, its
suppressions applied twice, and two entries writing to output paths that collide.

What is faked, and what is not
------------------------------
``execute_workspace`` is replaced by a recorder, because these tests are about
the MCP layer's bookkeeping and running real scanners would measure nineteen
other things. The registry is the real ``ScanRegistry``, freshly constructed per
test -- a mock registry would answer "yes" to whatever was asked of it, including
the duplicate question that is the whole point of the second half of this file.
"""

from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
from typing import Any, List, Tuple

import pytest

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
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
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


@pytest.fixture
def isolated_registry(monkeypatch):
    """A fresh ``ScanRegistry`` for the duration of one test.

    The production registry is a module-level singleton with no reset, and its
    accessor reads the global at call time, so replacing the global covers every
    import style. Isolation matters more here than elsewhere: these tests count
    entries and assert on duplicate detection, and both are meaningless if a
    sibling test's entries are still present -- and under ``-n auto`` the
    surviving entries would differ between a serial and a parallel run.
    """
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    fresh = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", fresh)
    return fresh


@pytest.fixture
def executions(monkeypatch) -> List[Tuple[Any, Any]]:
    """Record ``execute_workspace`` calls and hand back a real-shaped result."""
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
                finding_count=0,
                actionable_finding_count=0,
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
            results_path=Path(settings.output_dir) / "ash_workspace_results.json",
            exit_code=0,
            payload=payload,
        )

    monkeypatch.setattr(execution_module, "execute_workspace", _record)
    module = importlib.import_module(MODULE_UNDER_TEST)
    if hasattr(module, "execute_workspace"):
        monkeypatch.setattr(module, "execute_workspace", _record)
    return calls


# ---------------------------------------------------------------------------
# 1. N projects, N entries, N distinct handles
# ---------------------------------------------------------------------------


class TestOneRegistryEntryPerProject:
    """The batch is visible as N scans, not as one."""

    @staticmethod
    def _three_project_workspace(tmp_path: Path):
        root = tmp_path / "work"
        directories = {
            "api": _project(root, "api"),
            "web": _project(root, "web"),
            "team-infra": _project(root, "team/infra"),
        }
        workspace = _workspace(root, ["api", "web", "team/infra"])
        return workspace, directories

    @pytest.mark.asyncio
    async def test_three_projects_produce_three_entries(
        self, tmp_path, isolated_registry, executions
    ):
        workspace, directories = self._three_project_workspace(tmp_path)

        response = await _tool("mcp_scan_workspace")(workspace_file=str(workspace))

        assert response["success"] is True, response.get("error")
        assert isolated_registry.get_scan_count() == 3, (
            f"expected one registry entry per project, got "
            f"{isolated_registry.get_scan_count()}"
        )

    @pytest.mark.asyncio
    async def test_the_three_entries_have_distinct_scan_ids(
        self, tmp_path, isolated_registry, executions
    ):
        """Distinct handles, because a client polls one project at a time.

        Three entries sharing a scan id would collapse in the registry's own
        dict -- so the count assertion above would catch that -- but three
        entries created with three ids that happen to repeat a value would not.
        Counting the distinct values is the assertion that separates them.
        """
        workspace, _directories = self._three_project_workspace(tmp_path)

        await _tool("mcp_scan_workspace")(workspace_file=str(workspace))

        scan_ids = [entry["scan_id"] for entry in isolated_registry.list_scans()]
        assert len(scan_ids) == 3
        assert len(set(scan_ids)) == 3, f"scan ids repeat: {scan_ids}"

    @pytest.mark.asyncio
    async def test_each_entry_names_its_own_project_directory(
        self, tmp_path, isolated_registry, executions
    ):
        """The three entries cover the three project directories, one each.

        Compared as resolved ``Path`` objects rather than as strings: the plan
        carries POSIX-shaped paths, so on Windows a string comparison against
        ``str(directory)`` would fail on the separator alone and say nothing
        about whether the right directories were registered.
        """
        workspace, directories = self._three_project_workspace(tmp_path)

        await _tool("mcp_scan_workspace")(workspace_file=str(workspace))

        registered = {
            Path(entry["directory_path"]).resolve()
            for entry in isolated_registry.list_scans()
        }
        assert registered == {directory.resolve() for directory in directories.values()}

    @pytest.mark.asyncio
    async def test_the_response_maps_every_project_key_to_its_scan_id(
        self, tmp_path, isolated_registry, executions
    ):
        """A client cannot use the registry it cannot see into.

        The handles have to come back in the response keyed by project, or the
        caller has three ids and no way to tell which project each belongs to --
        and the project key is what the rest of the workspace payload attributes
        by, so it is the only key that joins.
        """
        workspace, _directories = self._three_project_workspace(tmp_path)

        response = await _tool("mcp_scan_workspace")(workspace_file=str(workspace))

        scan_ids = response["scan_ids"]
        assert set(scan_ids) == {"api", "web", "team-infra"}
        assert len(set(scan_ids.values())) == 3, (
            f"the reported scan ids are not distinct: {scan_ids}"
        )
        assert set(scan_ids.values()) == {
            entry["scan_id"] for entry in isolated_registry.list_scans()
        }, "the reported scan ids are not the ones in the registry"

    @pytest.mark.asyncio
    async def test_a_project_skipped_at_resolution_gets_no_scan_entry(
        self, tmp_path, isolated_registry, executions
    ):
        """A project that will not be scanned must not appear as an active scan.

        ``--allow-missing-projects`` keeps the entry in the *plan* -- deliberately,
        so the payload accounts for every folder the definition listed -- but a
        registry entry is a claim that a scan is pending or running on a
        directory. For a directory that does not exist, that claim would block a
        later legitimate scan of the same path and would make
        ``list_active_scans`` report work nobody is doing.
        """
        root = tmp_path / "work"
        _project(root, "api")
        workspace = _workspace(root, ["api", "never-cloned"])

        response = await _tool("mcp_scan_workspace")(
            workspace_file=str(workspace), allow_missing_projects=True
        )

        assert response["success"] is True, response.get("error")
        assert isolated_registry.get_scan_count() == 1
        assert set(response["scan_ids"]) == {"api"}


# ---------------------------------------------------------------------------
# 2. Two spellings of one directory are refused, never scanned twice
# ---------------------------------------------------------------------------


class TestTwoSpellingsOfOneDirectory:
    """The same directory named twice is a refusal, not a double scan."""

    @pytest.mark.asyncio
    async def test_a_trailing_separator_duplicate_refuses_the_workspace(
        self, tmp_path, isolated_registry, executions
    ):
        """``proj`` and ``proj/`` are one directory, and one is all that may run.

        Both entries pass containment, so nothing before overlap detection
        notices. A de-duplicating implementation would look correct here -- one
        project scanned, exit 0 -- which is why the refusal is the requirement:
        de-duplicating silently changes what the operator asked for, and the
        operator who wrote two entries meant something by it.
        """
        root = tmp_path / "work"
        _project(root, "proj")
        workspace = _workspace(root, ["proj", "proj/"])

        response = await _tool("mcp_scan_workspace")(workspace_file=str(workspace))

        assert response["success"] is False
        assert executions == [], (
            "the workspace ran with two entries naming one directory; its "
            "findings would be attributed twice"
        )
        assert isolated_registry.get_scan_count() == 0

    @pytest.mark.asyncio
    async def test_a_dot_relative_duplicate_refuses_the_workspace(
        self, tmp_path, isolated_registry, executions
    ):
        """The same case reached by a path that only collapses on resolution.

        ``./proj`` and ``proj`` are textually different and resolve identically.
        A duplicate check on the raw entry strings passes this and the previous
        test is the only one it fails, so both are here.
        """
        root = tmp_path / "work"
        _project(root, "proj")
        workspace = _workspace(root, ["proj", "./proj"])

        response = await _tool("mcp_scan_workspace")(workspace_file=str(workspace))

        assert response["success"] is False
        assert executions == []

    @pytest.mark.asyncio
    async def test_two_genuinely_different_projects_are_not_refused(
        self, tmp_path, isolated_registry, executions
    ):
        """Positive control, and the reason the two above are not vacuous.

        A check that refused any workspace with more than one folder would pass
        both tests above. This one distinguishes it.
        """
        root = tmp_path / "work"
        _project(root, "proj")
        _project(root, "other")
        workspace = _workspace(root, ["proj", "other"])

        response = await _tool("mcp_scan_workspace")(workspace_file=str(workspace))

        assert response["success"] is True, response.get("error")
        assert len(executions) == 1
        assert isolated_registry.get_scan_count() == 2


# ---------------------------------------------------------------------------
# 3. The registry's own duplicate rule has to canonicalise
# ---------------------------------------------------------------------------


class TestTheRegistryComparesRealPaths:
    """``register_scan`` must not be fooled by an alternative spelling.

    The resolver's overlap check catches two spellings *inside one workspace
    file*, which is what the class above pins. It cannot catch two spellings
    across two calls: a client that scans ``/proj`` through
    ``mcp_scan_directory`` and then ``/proj/`` as part of a workspace, or two
    workspace files spelling one shared project differently, reaches
    ``register_scan`` with two strings for one directory and gets two active
    scans on it. Both then write into ``<proj>/.ash/ash_output``.

    These tests go at the registry directly, because that is where the
    comparison lives and because reaching it through two different tools would
    make the failure look like a workspace problem.
    """

    @staticmethod
    def _register(registry, directory: Path, output: Path) -> str:
        return registry.register_scan(
            directory_path=str(directory), output_directory=str(output)
        )

    def test_a_trailing_separator_is_the_same_directory(
        self, tmp_path, isolated_registry
    ):
        """``str(Path)`` never ends in a separator, so this spelling only ever
        arrives from a caller -- which is exactly the untrusted case.
        """
        project = tmp_path / "proj"
        project.mkdir()
        output = tmp_path / "out"
        output.mkdir()
        first = self._register(isolated_registry, project, output)

        with pytest.raises(MCPResourceError) as excinfo:
            isolated_registry.register_scan(
                directory_path=str(project) + os.sep,
                output_directory=str(output),
            )

        assert "already has an active scan" in str(excinfo.value)
        assert excinfo.value.context["scan_id"] == first
        assert excinfo.value.context["error_category"] == "resource_exhausted"
        assert isolated_registry.get_scan_count() == 1

    def test_a_traversal_is_the_same_directory(self, tmp_path, isolated_registry):
        """``proj/../proj`` resolves to ``proj`` and is not the same string.

        Built with ``os.path.join`` on strings rather than with ``/`` on a
        ``Path``: pathlib collapses nothing at construction for ``..``, but
        ``PurePath`` normalisation would drop a single ``.``, so joining strings
        is the only way to be sure the un-canonical form survives to the call.
        """
        project = tmp_path / "proj"
        project.mkdir()
        output = tmp_path / "out"
        output.mkdir()
        first = self._register(isolated_registry, project, output)
        traversal = os.path.join(str(project), os.pardir, "proj")
        assert traversal != str(project)
        assert Path(traversal).resolve() == project.resolve()

        with pytest.raises(MCPResourceError) as excinfo:
            isolated_registry.register_scan(
                directory_path=traversal, output_directory=str(output)
            )

        assert excinfo.value.context["scan_id"] == first
        assert isolated_registry.get_scan_count() == 1

    def test_a_different_directory_still_registers(self, tmp_path, isolated_registry):
        """Positive control: canonicalising must not collapse distinct paths.

        Two sibling directories whose names share a prefix, because the cheapest
        wrong way to canonicalise is a ``startswith`` or a prefix strip, and
        ``proj`` against ``proj-backup`` is where that shows.
        """
        first_dir = tmp_path / "proj"
        second_dir = tmp_path / "proj-backup"
        first_dir.mkdir()
        second_dir.mkdir()
        output = tmp_path / "out"
        output.mkdir()

        first = self._register(isolated_registry, first_dir, output)
        second = self._register(isolated_registry, second_dir, output)

        assert first != second
        assert isolated_registry.get_scan_count() == 2

    def test_a_completed_scan_does_not_block_a_rescan(
        self, tmp_path, isolated_registry
    ):
        """Canonicalising strengthens the rule; it must not outlive the scan.

        The rule is about *active* scans. If canonicalisation were applied
        without keeping the ``is_active()`` half of the condition, the first scan
        of a directory would permanently block every later one -- which no
        current test would notice, because nothing else registers the same
        directory twice.
        """
        from automated_security_helper.core.resource_management.scan_registry import (
            MCScanStatus,
        )

        project = tmp_path / "proj"
        project.mkdir()
        output = tmp_path / "out"
        output.mkdir()
        first = self._register(isolated_registry, project, output)
        isolated_registry.update_scan_status(first, MCScanStatus.COMPLETED)

        second = isolated_registry.register_scan(
            directory_path=str(project) + os.sep, output_directory=str(output)
        )

        assert second != first
        assert isolated_registry.get_scan_count() == 2
