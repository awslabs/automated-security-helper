# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""actionlint, cfn-guard, cfn-lint, gitleaks, trivy and zizmor each state python_only.

``--python-only`` runs only the scanners that need nothing but Python. A scanner
states which it is with the ``python_only`` class variable: True for a tool that is
a Python package ASH runs through uv or imports, False for a native binary or any
other program. Stated rather than derived, because what these scanners run can
change after construction: zizmor and cfn-lint switch from ``uv tool run`` to a
binary on PATH in their dependency check, and a rule that read ``use_uv_tool``
would then answer differently for the same scanner within one scan.

The ScanPhase test pins what ``--python-only`` runs among these six, measured on a
real scan with every tool installed: cfn-lint and zizmor.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_config import plugin_config_key
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.scanners.actionlint_scanner import (
    ActionlintScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_guard_scanner import (
    CfnGuardScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    CfnLintScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
    GitleaksScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
    ZizmorScanner,
)

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

#: What each scanner runs, and so its answer.
DECLARED = {
    ActionlintScanner: False,  # a Go binary, installed from its release asset
    CfnGuardScanner: False,  # a Rust binary, installed from its release asset
    CfnLintScanner: True,  # a Python package, run through uv
    GitleaksScanner: False,  # a Go binary, installed from its release asset
    TrivyScanner: False,  # a Go binary, installed from its release asset
    ZizmorScanner: True,  # a PyPI wheel, run through uv
}

PYTHON_ONLY = {"cfn-lint", "zizmor"}
NOT_PYTHON_ONLY = {"actionlint", "cfn-guard", "gitleaks", "trivy"}


@pytest.fixture
def context(tmp_path) -> PluginContext:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=get_default_config(),
    )


def _instance(cls, context):
    return cls(
        config=context.config.get_plugin_config(
            plugin_type="scanner", plugin_name=plugin_config_key(cls)
        ),
        context=context,
    )


@pytest.mark.parametrize(
    ("scanner_class", "expected"),
    list(DECLARED.items()),
    ids=[cls.__name__ for cls in DECLARED],
)
def test_the_scanner_class_states_python_only(scanner_class, expected):
    assert "python_only" in vars(scanner_class), (
        f"{scanner_class.__name__} does not state python_only"
    )
    assert vars(scanner_class)["python_only"] is expected


@pytest.mark.parametrize(
    ("scanner_class", "expected"),
    list(DECLARED.items()),
    ids=[cls.__name__ for cls in DECLARED],
)
def test_is_python_only_gives_the_stated_answer(scanner_class, expected, context):
    assert _instance(scanner_class, context).is_python_only() is expected


@pytest.mark.parametrize("scanner_class", [CfnLintScanner, ZizmorScanner])
def test_the_answer_holds_once_the_tool_runs_from_path(scanner_class, context):
    """Both use a binary on PATH instead of uv when one is found (use_uv_tool False)."""
    scanner = _instance(scanner_class, context)
    scanner.use_uv_tool = False

    assert scanner.is_python_only() is True


def test_python_only_runs_cfn_lint_and_zizmor_of_the_six(context):
    plugins = list(DECLARED)
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=plugins,
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    phase.validation_manager = MagicMock()
    with (
        patch.object(
            ScannerPluginBase, "validate_plugin_dependencies", return_value=True
        ),
        patch(
            "automated_security_helper.core.phases.scan_phase.ScannerExecutor"
        ) as executor,
    ):
        for scanner_class in plugins:
            patch.object(
                scanner_class, "validate_plugin_dependencies", return_value=True
            ).start()
        double = MagicMock()
        double.completed_scanners = []
        double.run_parallel.return_value = aggregated
        double.run_sequential.return_value = aggregated
        executor.return_value = double
        try:
            results = phase._execute_phase(
                aggregated_results=aggregated, python_based_plugins_only=True
            )
        finally:
            patch.stopall()
        queued = {name for name, _, _ in executor.call_args.kwargs["scanner_tasks"]}

    assert queued == PYTHON_ONLY
    for name in NOT_PYTHON_ONLY:
        assert results.scanner_results[name].status == ScannerStatus.SKIPPED, name
