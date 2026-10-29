# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan's failed-import refusal offers "unset it in ASH_PLUGIN_MODULES".

The scan prints ``str(error)``, never ``plugin_module_refusal_message``, so the
remedy for a module only ``ASH_PLUGIN_MODULES`` contributed has to be in the
raised message. The two callers of ``refuse_failed_plugin_imports``, the
single-scan engine and the workspace prewarm, pass the environment-only set
(``plugin_module_trust.environment_only_plugin_modules``). The module here
fails on import (it needs a dependency that does not exist), is named by the
variable and by the option list that carries it, and no config names it.
"""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from automated_security_helper.plugins.loader import PluginModuleImportError

pytestmark = pytest.mark.unit

BROKEN = "envremedy_ash_plugins"
REMEDY = "or unset it in ASH_PLUGIN_MODULES."


@pytest.fixture
def broken_module(tmp_path, monkeypatch):
    site = tmp_path / "site"
    (site / BROKEN).mkdir(parents=True)
    (site / BROKEN / "__init__.py").write_text(
        "import envremedy_dependency_that_does_not_exist  # noqa: F401\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.delitem(sys.modules, BROKEN, raising=False)
    monkeypatch.setenv("ASH_PLUGIN_MODULES", BROKEN)
    yield BROKEN
    sys.modules.pop(BROKEN, None)


def test_the_engine_refusal_offers_the_remedy_for_an_environment_only_entry(
    tmp_path, broken_module
):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.execution_engine import ScanExecutionEngine

    context = PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "work",
        config=AshConfig(),
    )

    with (
        patch("automated_security_helper.plugins.loader.load_internal_plugins"),
        pytest.raises(PluginModuleImportError) as refused,
    ):
        ScanExecutionEngine(
            context=context, ash_plugin_modules=[broken_module], show_progress=False
        )

    message = str(refused.value)
    assert f"'{broken_module}'" in message, message
    assert message.endswith(REMEDY), message


def test_the_workspace_prewarm_refusal_offers_the_remedy_for_an_environment_only_entry(
    tmp_path, broken_module
):
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        prewarm_plugin_registry,
    )
    from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

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
                ash_plugin_modules=[],
            )
        ],
    )

    with (
        patch("automated_security_helper.plugins.loader.load_internal_plugins"),
        pytest.raises(PluginModuleImportError) as refused,
    ):
        prewarm_plugin_registry(
            plan,
            ProjectScanSettings(
                output_dir=tmp_path / "out", ash_plugin_modules=(broken_module,)
            ),
        )

    message = str(refused.value)
    assert f"'{broken_module}'" in message, message
    assert message.endswith(REMEDY), message
