# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner whose run raised is not recorded as completed by a real scan.

ScanPhase.execute builds its own ScannerExecutor, and the executor's run loops
record a scanner as completed when its run succeeded and no container it
returned is ERROR. A run that raised returns a for_failure container, whose
status is FAILED, so the loops read the flag, never the status. When the real
scan handed the executor a per-scanner hook replaced on the phase (a subclass
override of _safe_execute_scanner, even one that only calls super()), the
executor wrapped that hook's plain list as a success, and the phase then took
the executor's completions over its own: the scanner that raised was counted
as completed, and _validate_execution_completion saw nothing missing.

Driven through ScanPhase.execute with two real scanner classes. Only the
executor's per-scanner work is replaced: npm-audit's run raises, cfn-nag's
passes.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.phases.scanner_executor import ScannerExecutor

pytestmark = pytest.mark.unit


def _with_its_tool(scanner_class):
    """The real scanner class with its dependency check answering True."""

    class _WithTool(scanner_class):
        def validate_plugin_dependencies(self) -> bool:
            return True

    _WithTool.__name__ = scanner_class.__name__
    _WithTool.__module__ = scanner_class.__module__
    return _WithTool


def _scan(tmp_path, phase_class, parallel):
    """Run *phase_class* through execute(); the names it recorded as completed."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
    from automated_security_helper.core.enums import ScannerStatus
    from automated_security_helper.core.phases.scan_result_processor import (
        ScanResultProcessor,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.models.scan_results_container import (
        ScanResultsContainer,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
        CfnNagScanner,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
        NpmAuditScanner,
    )

    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n", encoding="utf-8")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=get_default_config(),
    )
    aggregated = AshAggregatedResults()
    phase = phase_class(
        plugin_context=context,
        plugins=[_with_its_tool(NpmAuditScanner), _with_its_tool(CfnNagScanner)],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    ran = []

    def _execute(executor_self, scanner_name, scanner_plugin, scan_targets):
        ran.append(scanner_name)
        if scanner_name == "npm-audit":
            raise RuntimeError("npm-audit's run raised")
        return [
            ScanResultsContainer(scanner_name=scanner_name, status=ScannerStatus.PASSED)
        ]

    def _process(processor, container, aggregated_results):
        return aggregated_results

    with (
        patch.object(
            ScannerExecutor, "_execute_scanner", autospec=True, side_effect=_execute
        ),
        patch.object(
            ScanResultProcessor,
            "process_container",
            autospec=True,
            side_effect=_process,
        ),
    ):
        phase.execute(aggregated_results=aggregated, parallel=parallel, max_workers=2)

    # The control: both scanners ran.
    assert sorted(ran) == ["cfn-nag", "npm-audit"], ran
    return [plugin.config.name for plugin in phase._completed_scanners]


@pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
def test_a_scanner_that_raised_is_not_completed(tmp_path, parallel):
    """The stock phase: the control for the cell below."""
    from automated_security_helper.core.phases.scan_phase import ScanPhase

    assert _scan(tmp_path, ScanPhase, parallel) == ["cfn-nag"]


@pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
def test_a_phase_overriding_its_per_scanner_hook_still_reads_the_raise(
    tmp_path, parallel
):
    """A subclass whose _safe_execute_scanner only calls super(): the real scan
    records the same completions as the stock phase."""
    from automated_security_helper.core.phases.scan_phase import ScanPhase

    class _PassThrough(ScanPhase):
        def _safe_execute_scanner(self, scanner_name, scanner_plugin, scan_targets):
            return super()._safe_execute_scanner(
                scanner_name, scanner_plugin, scan_targets
            )

    assert _scan(tmp_path, _PassThrough, parallel) == ["cfn-nag"]
