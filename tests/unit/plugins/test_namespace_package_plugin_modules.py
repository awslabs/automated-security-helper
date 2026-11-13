# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A namespace package named in ``ash_plugin_modules`` refuses the scan with exit code 3.

A namespace package is a directory with no ``__init__.py``; its portions can come
from several distributions. It declares no ``ASH_*`` lists, and a scan selects
nothing below it (``plugins.loader.scan_plugin_filter``), so naming one would add no
plugin to the scan. ``refuse_plugin_modules_outside_namespace`` refuses it the way it
refuses a name outside the plugin namespace: before anything is imported, with
``PluginModuleNamespaceError`` (exit code 3), from every source ASH reads
``ash_plugin_modules`` from.

The in-process cases put packages on ``sys.path`` and read ``sys.modules`` afterwards.
The end-to-end cases run ASH in a fresh interpreter through the harness in
``test_refused_plugin_modules.py``, which keeps every tool directory under the test's
temporary directory.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

from automated_security_helper.plugins.loader import (
    PluginModuleNamespaceError,
    refuse_plugin_modules_outside_namespace,
)
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    prewarm_plugin_registry,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan
from tests.unit.plugins.test_refused_plugin_modules import _Run, _tail

#: A namespace package: two portions, no ``__init__.py`` at the top.
NAMESPACE = "zzshared_ash_plugins"

#: A regular package holding a namespace subpackage, ``.shared``.
REGULAR = "zzregular_ash_plugins"

_MARKER_INIT = "LOADED = True\n"


def _write(root: Path, relative: str, text: str = "") -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _layout(root: Path) -> None:
    _write(root, f"{NAMESPACE}/vendor_a/__init__.py", _MARKER_INIT)
    _write(root, f"{NAMESPACE}/vendor_b/__init__.py", _MARKER_INIT)
    _write(root, f"{REGULAR}/__init__.py", _MARKER_INIT)
    _write(root, f"{REGULAR}/shared/tool.py", _MARKER_INIT)


@pytest.fixture
def site(tmp_path, monkeypatch):
    root = tmp_path / "site"
    _layout(root)
    monkeypatch.syspath_prepend(str(root))
    importlib.invalidate_caches()
    before = set(sys.modules)
    yield root
    for name in set(sys.modules) - before:
        del sys.modules[name]
    importlib.invalidate_caches()


@pytest.mark.unit
class TestTheRefusal:
    def test_a_top_level_namespace_package_is_refused(self, site):
        with pytest.raises(PluginModuleNamespaceError) as raised:
            refuse_plugin_modules_outside_namespace([NAMESPACE])

        assert repr(NAMESPACE) in str(raised.value)
        assert "namespace package" in str(raised.value)
        assert NAMESPACE not in sys.modules

    def test_a_namespace_subpackage_is_refused_without_importing_its_parent(self, site):
        with pytest.raises(PluginModuleNamespaceError):
            refuse_plugin_modules_outside_namespace([f"{REGULAR}.shared"])

        assert REGULAR not in sys.modules, "the check imported the parent package"

    def test_an_accepted_name_beside_it_is_not_imported(self, site):
        with pytest.raises(PluginModuleNamespaceError):
            refuse_plugin_modules_outside_namespace(
                [f"{NAMESPACE}.vendor_a", NAMESPACE]
            )

        assert f"{NAMESPACE}.vendor_a" not in sys.modules

    @pytest.mark.parametrize(
        "name",
        [
            f"{NAMESPACE}.vendor_a",
            REGULAR,
            f"{REGULAR}.shared.tool",
            "zzmissing_ash_plugins",
        ],
    )
    def test_a_regular_package_a_module_or_a_missing_name_is_not_refused_here(
        self, site, name
    ):
        """A portion of the namespace package is a regular package, and accepted.

        A name nothing provides is left to the import, which warns that it failed.
        """
        refuse_plugin_modules_outside_namespace([name])

        assert name.split(".", 1)[0] not in sys.modules


@pytest.mark.unit
class TestTheInTreeConfigFilter:
    def test_a_namespace_subpackage_in_an_in_tree_config_resolves(
        self, site, tmp_path, monkeypatch
    ):
        """Locating ``<package>.<namespace dir>`` with its parent not imported works.

        The filter keeps the name, installed outside the tree and unimported, for
        the scan's refusal.
        """
        from automated_security_helper.config.resolve_config import resolve_config

        source = tmp_path / "repo"
        (source / ".ash").mkdir(parents=True)
        (source / ".ash" / ".ash.yaml").write_text(
            f"project_name: repo\nash_plugin_modules:\n  - {REGULAR}.shared\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(source)

        config = resolve_config(source_dir=source)

        assert config.ash_plugin_modules == [f"{REGULAR}.shared"]
        assert REGULAR not in sys.modules


@pytest.mark.unit
class TestTheWorkspacePrewarm:
    def test_a_project_naming_a_namespace_package_is_refused(self, site, tmp_path):
        plan = WorkspacePlan(
            workspace_file=(tmp_path / "dev.code-workspace").as_posix(),
            workspace_root=tmp_path.as_posix(),
            projects=[
                ProjectPlan(
                    key="api",
                    relative_path="api",
                    path=(tmp_path / "api").as_posix(),
                    label="api",
                    display_label="api",
                    severity_threshold="MEDIUM",
                    ash_plugin_modules=[REGULAR, NAMESPACE],
                )
            ],
        )

        with pytest.raises(PluginModuleNamespaceError):
            prewarm_plugin_registry(
                plan, ProjectScanSettings(output_dir=tmp_path / "out")
            )

        assert REGULAR not in sys.modules


@pytest.mark.integration
class TestAScanNamingANamespacePackage:
    def _run(self, tmp_path: Path) -> _Run:
        run = _Run(tmp_path)
        _layout(run.site)
        return run

    def test_the_ash_plugin_modules_flag(self, tmp_path):
        run = self._run(tmp_path)

        completed = run.run(
            "cli", {"args": run.scan_args("--ash-plugin-modules", NAMESPACE)}
        )

        assert completed.returncode == 3, _tail(completed)
        assert "namespace package" in completed.stdout + completed.stderr

    def test_a_config_file_inside_the_scanned_tree(self, tmp_path):
        """The package is installed outside the tree, so the in-tree filter keeps it."""
        run = self._run(tmp_path)
        (run.tree / ".ash").mkdir()
        (run.tree / ".ash" / ".ash.yaml").write_text(
            f"project_name: tree\nash_plugin_modules:\n  - {NAMESPACE}\n",
            encoding="utf-8",
        )

        completed = run.run("cli", {"args": run.scan_args()})

        assert completed.returncode == 3, _tail(completed)

    def test_the_python_api(self, tmp_path):
        run = self._run(tmp_path)

        completed = run.run(
            "api",
            {
                "source_dir": str(run.tree),
                "output_dir": str(tmp_path / "out"),
                "modules": [NAMESPACE],
            },
        )

        assert completed.returncode == 3, _tail(completed)

    def test_a_portion_of_it_is_accepted_and_the_scan_runs(self, tmp_path):
        """Control: naming the regular package inside it scans normally."""
        run = self._run(tmp_path)

        completed = run.run(
            "cli",
            {"args": run.scan_args("--ash-plugin-modules", f"{NAMESPACE}.vendor_a")},
        )

        assert completed.returncode == 0, _tail(completed)
