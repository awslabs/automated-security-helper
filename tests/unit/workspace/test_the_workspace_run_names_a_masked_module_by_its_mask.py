# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace run reads the plugin registry inside its masked modules' scope.

A workspace names its plugin modules by the run-wide map its projects' configs
filled (``workspace_module_names``), and a project's entry read from the
environment is shown by its mask. The workspace reads the registry in two
places of its own: the prewarm resolves every plugin kind once before any
project starts, and the report step selects the reporters the run loads. The
registry lines those reads can write (a registered module that no longer
imports, the classes left out of a selection) now name a masked entry by its
mask, as the single scan's engine does.

Cells: the prewarm's three resolutions and the reporter step's resolution and
filter, each seen to run inside the scope.
"""

from __future__ import annotations

import sys
from typing import List

import pytest

from automated_security_helper.config.environment_record import (
    ENVIRONMENT_VALUE_SHOWN,
)
from automated_security_helper.plugins.plugin_manager import AshPluginManager
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    prewarm_plugin_registry,
    workspace_reporter_classes,
)
from automated_security_helper.workspace.resolver import resolve_workspace

pytestmark = pytest.mark.unit

MASK = "<value>"


def _plan_whose_config_read(tmp_path, module):
    """A one-project plan whose config read ``module`` from the environment, as
    resolution records it: the module list holds the value, the map its masked
    form."""
    (tmp_path / "api").mkdir()
    workspace_file = tmp_path / "dev.code-workspace"
    workspace_file.write_text('{"folders": [{"path": "api"}]}', encoding="utf-8")
    plan = resolve_workspace(workspace_file)
    project = plan.projects[0].model_copy(
        update={
            "ash_plugin_modules": [module],
            "plugin_module_names": {module: ENVIRONMENT_VALUE_SHOWN},
        }
    )
    return plan.model_copy(update={"projects": [project]})


def _recording(monkeypatch, method: str, name: str, seen: List[str]) -> None:
    """Wrap ``AshPluginManager.<method>`` to note, at each call, how the scope
    in force would print *name*."""
    from automated_security_helper.plugins.plugin_manager import (
        without_masked_modules,
    )

    original = getattr(AshPluginManager, method)

    def recorder(self, *args, **kwargs):
        seen.append(without_masked_modules(name))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(AshPluginManager, method, recorder)


def test_the_prewarm_resolves_every_plugin_kind_inside_the_scope(tmp_path, monkeypatch):
    package = "kqmmws_ash_plugins"
    site = tmp_path / "site"
    (site / package).mkdir(parents=True)
    (site / package / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.syspath_prepend(str(site))
    plan = _plan_whose_config_read(tmp_path, package)
    seen: List[str] = []
    _recording(monkeypatch, "plugin_modules", package, seen)

    try:
        prewarm_plugin_registry(plan, ProjectScanSettings(output_dir=tmp_path / "out"))
    finally:
        sys.modules.pop(package, None)

    assert seen == [MASK, MASK, MASK], seen


def test_the_reporter_step_resolves_and_filters_inside_the_scope(tmp_path, monkeypatch):
    package = "kqmmwsrep_ash_plugins"
    plan = _plan_whose_config_read(tmp_path, package)
    resolved: List[str] = []
    filtered: List[str] = []
    _recording(monkeypatch, "plugin_modules", package, resolved)
    _recording(monkeypatch, "plugins_loaded_by", package, filtered)

    workspace_reporter_classes(plan, ProjectScanSettings(output_dir=tmp_path / "out"))

    assert resolved == [MASK], resolved
    assert filtered == [MASK], filtered
