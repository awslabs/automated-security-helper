# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The global plugin registry, and why a workspace refuses rather than merges.

The defect these tests exist for
--------------------------------
``ScanExecutionEngine.__init__`` reads *the project's own*
``ash_plugin_modules`` and registers them into the module-level
``plugin_library``, then reads the scanner set back through
``ash_plugin_manager.plugin_modules()``, which memoises into
``_resolved_plugins``. So the first project to build its engine froze the scanner
class list for the whole run. Measured on two real projects where only ``web``
declared an external plugin:

    api-first:  api 10 scanners (absent)   web 10 scanners (absent)
    web-first:  api 11 scanners (present)  web 11 scanners (present)

Correct is ``web=True, api=False``, and neither ordering produced it. The
``api``-first case is the dangerous one: ``web`` reported fewer findings than
``ash --source-dir web`` would, with nothing in the output saying so -- a silent
false negative on a security scanner, which is exactly the axis workspace mode
exists to protect. It reproduced at ``max_parallel_projects=1``, so concurrency
only randomised *which* project was wrong.

Two changes, and why not one
----------------------------
Refusing differing module sets alone would leave the ordering nondeterminism in
place for the identical case, because the memoised list would still be whatever
the first project resolved -- complete only by luck of when discovery ran.
Pre-warming alone would define the merged set as correct for everyone, which
means a project gets scanned by plugins its operator did not choose; an operator
who deliberately keeps a slow or noisy plugin out of one project would have that
decision silently reversed.

Together they are sound: resolution guarantees one set, and pre-warming resolves
it once before any worker starts.

What is deliberately NOT fixed here
-----------------------------------
Per-execution scoping of ``plugin_library`` and ``_resolved_plugins``. Both
predate this feature and every single-directory scan depends on them, so
rearchitecting them does not belong in this PR. It is recorded as a follow-up.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import WorkspaceDefinitionError
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    prewarm_plugin_registry,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan
from automated_security_helper.workspace.resolver import (
    _project_plugin_modules,
    resolve_workspace,
)


def _project(root: Path, key: str, *, modules=None, extra: str = "") -> None:
    (root / key / "src").mkdir(parents=True, exist_ok=True)
    (root / key / "src" / "app.py").write_text("print('x')\n", encoding="utf-8")
    config_dir = root / key / ".ash"
    config_dir.mkdir(parents=True, exist_ok=True)
    lines = [f"project_name: {key}"]
    if modules is not None:
        lines.append("ash_plugin_modules:")
        lines.extend(f"  - {module}" for module in modules)
    if extra:
        lines.append(extra)
    (config_dir / "ash.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _workspace(root: Path, *keys: str) -> Path:
    path = root / "dev.code-workspace"
    path.write_text(
        json.dumps({"folders": [{"path": key} for key in keys]}), encoding="utf-8"
    )
    return path


class TestDifferingModuleSetsAreRefused:
    def test_one_project_declaring_a_module_refuses_the_workspace(self, tmp_path):
        _project(tmp_path, "api")
        _project(tmp_path, "web", modules=["acme.plugins"])
        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            resolve_workspace(_workspace(tmp_path, "api", "web"))
        message = str(excinfo.value)
        assert "ash_plugin_modules" in message
        # Both sides named, so the operator does not have to diff the configs.
        assert "api" in message and "web" in message
        assert "acme.plugins" in message
        assert "no plugin modules" in message

    def test_two_projects_declaring_different_modules_refuse(self, tmp_path):
        _project(tmp_path, "api", modules=["acme.one"])
        _project(tmp_path, "web", modules=["acme.two"])
        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            resolve_workspace(_workspace(tmp_path, "api", "web"))
        assert "acme.one" in str(excinfo.value)
        assert "acme.two" in str(excinfo.value)

    def test_identical_module_lists_are_accepted(self, tmp_path):
        _project(tmp_path, "api", modules=["acme.plugins"])
        _project(tmp_path, "web", modules=["acme.plugins"])
        plan = resolve_workspace(_workspace(tmp_path, "api", "web"))
        assert [p.ash_plugin_modules for p in plan.projects] == [
            ["acme.plugins"],
            ["acme.plugins"],
        ]

    def test_no_project_declaring_anything_is_accepted(self, tmp_path):
        """The overwhelmingly common case must not become a refusal."""
        _project(tmp_path, "api")
        _project(tmp_path, "web")
        plan = resolve_workspace(_workspace(tmp_path, "api", "web"))
        assert all(p.ash_plugin_modules == [] for p in plan.projects)

    def test_order_and_repetition_do_not_count_as_a_conflict(self, tmp_path):
        """Neither changes which plugins get registered, so neither is a conflict."""
        _project(tmp_path, "api", modules=["acme.two", "acme.one"])
        _project(tmp_path, "web", modules=["acme.one", "acme.two", "acme.one"])
        plan = resolve_workspace(_workspace(tmp_path, "api", "web"))
        assert all(
            p.ash_plugin_modules == ["acme.one", "acme.two"] for p in plan.projects
        )

    def test_a_comma_joined_entry_matches_the_split_form(self, tmp_path):
        """ScanExecutionEngine splits on commas, so these are the same request."""
        _project(tmp_path, "api", modules=["acme.one,acme.two"])
        _project(tmp_path, "web", modules=["acme.one", "acme.two"])
        plan = resolve_workspace(_workspace(tmp_path, "api", "web"))
        assert all(
            p.ash_plugin_modules == ["acme.one", "acme.two"] for p in plan.projects
        )

    def test_a_skipped_project_cannot_conflict(self, tmp_path):
        """It will not be scanned, so its list never reaches the registry."""
        _project(tmp_path, "api")
        _project(tmp_path, "web", modules=["acme.plugins"])
        workspace = _workspace(tmp_path, "api", "web", "not-cloned")
        # 'web' stays, 'not-cloned' is skipped -- but api and web still differ,
        # so this must still refuse. Proves the skip filter did not swallow it.
        with pytest.raises(WorkspaceDefinitionError):
            resolve_workspace(workspace, allow_missing_projects=True)

    def test_a_skipped_project_with_a_different_list_is_ignored(self, tmp_path):
        _project(tmp_path, "api", modules=["acme.plugins"])
        _project(tmp_path, "web", modules=["acme.plugins"])
        plan = resolve_workspace(
            _workspace(tmp_path, "api", "web", "not-cloned"),
            allow_missing_projects=True,
        )
        assert len(plan.active_projects) == 2


class TestPluginModuleNormalisation:
    """``_project_plugin_modules`` is what makes the comparison meaningful."""

    class _Config:
        def __init__(self, modules):
            self.ash_plugin_modules = modules

    @pytest.mark.parametrize(
        "declared,expected",
        [
            (None, []),
            ([], []),
            (["b", "a"], ["a", "b"]),
            (["a,b"], ["a", "b"]),
            ([" a ", "b "], ["a", "b"]),
            (["a", "a"], ["a"]),
            (["a", None, "b"], ["a", "b"]),
            (["", "  ", "a"], ["a"]),
            (["a,,b"], ["a", "b"]),
        ],
    )
    def test_normalisation(self, declared, expected):
        assert _project_plugin_modules(self._Config(declared)) == expected

    def test_a_config_without_the_attribute_yields_nothing(self):
        assert _project_plugin_modules(object()) == []


class TestPrewarm:
    """Registration is filled once up front; selection stays per project."""

    @staticmethod
    def _plan(tmp_path, *specs) -> WorkspacePlan:
        return WorkspacePlan(
            workspace_file=(tmp_path / "dev.code-workspace").as_posix(),
            workspace_root=tmp_path.as_posix(),
            projects=[
                ProjectPlan(
                    key=key,
                    relative_path=key,
                    path=(tmp_path / key).as_posix(),
                    label=key,
                    display_label=key,
                    severity_threshold="MEDIUM",
                    ash_plugin_modules=list(modules),
                )
                for key, modules in specs
            ],
        )

    def test_the_registry_resolves_scanner_classes(self, tmp_path):
        plan = self._plan(tmp_path, ("api", []))
        settings = ProjectScanSettings(output_dir=tmp_path / "out")
        assert prewarm_plugin_registry(plan, settings) > 0

    def test_it_is_idempotent(self, tmp_path):
        """It runs once per workspace, but a second call must not change the set."""
        plan = self._plan(tmp_path, ("api", []))
        settings = ProjectScanSettings(output_dir=tmp_path / "out")
        first = prewarm_plugin_registry(plan, settings)
        assert prewarm_plugin_registry(plan, settings) == first

    def test_a_skipped_project_contributes_no_modules(self, tmp_path):
        """It is never scanned, so loading its modules would be wrong."""
        plan = self._plan(tmp_path, ("api", []), ("gone", ["does.not.exist"]))
        plan.projects[1].skipped = True
        settings = ProjectScanSettings(output_dir=tmp_path / "out")
        # A non-importable module would be logged by the loader, not raised; what
        # matters is that pre-warm does not attempt it at all and still resolves.
        assert prewarm_plugin_registry(plan, settings) > 0

    def test_cli_modules_are_included(self, tmp_path):
        """--ash-plugin-modules is additive to whatever the projects declare."""
        plan = self._plan(tmp_path, ("api", []))
        settings = ProjectScanSettings(
            output_dir=tmp_path / "out", ash_plugin_modules=("acme.from_cli",)
        )
        # Resolves without raising even though the CLI module does not import;
        # load_additional_plugin_modules logs and continues.
        assert prewarm_plugin_registry(plan, settings) > 0


class TestPrewarmRunsBeforeTheWorkers:
    def test_execute_workspace_prewarms_before_starting_the_pool(self, tmp_path):
        """Ordering is the whole point: inside the pool it would race.

        Asserted by observing call order rather than by reading the source, so a
        refactor that moves the call into the worker fails here.
        """
        import automated_security_helper.workspace.execution as execution

        order: list = []
        real_prewarm = execution.prewarm_plugin_registry

        def recording_prewarm(plan, settings):
            order.append("prewarm")
            return real_prewarm(plan, settings)

        class Orchestrator:
            def __init__(self, **kwargs):
                order.append(f"engine:{Path(kwargs['source_dir']).name}")

            @classmethod
            def create(cls, **kwargs):
                return cls(**kwargs)

            def execute_scan(self, phases=None):
                from automated_security_helper.models.asharp_model import (
                    AshAggregatedResults,
                )

                return AshAggregatedResults()

        for key in ("api", "web"):
            (tmp_path / key).mkdir(parents=True, exist_ok=True)
        plan = TestPrewarm._plan(tmp_path, ("api", []), ("web", []))
        settings = ProjectScanSettings(
            output_dir=tmp_path / "out", phases=("scan",), max_parallel_projects=2
        )

        execution.prewarm_plugin_registry = recording_prewarm
        try:
            execution.execute_workspace(
                plan, settings, orchestrator_factory=Orchestrator.create
            )
        finally:
            execution.prewarm_plugin_registry = real_prewarm

        assert order[0] == "prewarm", order
        assert sorted(order[1:]) == ["engine:api", "engine:web"], order
