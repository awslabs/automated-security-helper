# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner a --python-only run leaves out is not an ERROR when its constructor raises.

A scanner whose constructor raised is recorded SKIPPED when the operator left it
out (excluded, not named, disabled) and ERROR otherwise, because ERROR fails the
completeness gate and a scanner nobody selected must not. A ``--python-only`` run
also leaves out every scanner that is not Python-only, but that selection was not
read on this path, so such a scanner whose constructor raised failed a run that
would never have run it. The class's own ``python_only`` statement is read here
(``is_python_only()`` is an instance method and this scanner has no instance).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import PYTHON_ONLY_SKIPPED_REASON
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
)

pytestmark = pytest.mark.unit


def _constructor_raises(self, *args, **kwargs):
    raise RuntimeError("constructor failed")


@pytest.fixture(autouse=True)
def _constructors_raise(monkeypatch):
    monkeypatch.setattr(OpengrepScanner, "__init__", _constructor_raises)
    monkeypatch.setattr(BanditScanner, "__init__", _constructor_raises)


def _run(tmp_path, plugin, **kwargs):
    for sub in ("src", "out", "work"):
        (tmp_path / sub).mkdir(exist_ok=True)
    config = get_default_config()
    # Opengrep is disabled by default on Windows, and a disabled scanner is
    # excluded before its constructor runs; these cases measure the
    # constructor-failure path, so the scanner must be selected everywhere.
    config.scanners.opengrep.enabled = True
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=config,
    )
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[plugin],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    phase.validation_manager = MagicMock()
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerExecutor"
    ) as executor:
        double = MagicMock()
        double.completed_scanners = []
        double.run_parallel.return_value = aggregated
        double.run_sequential.return_value = aggregated
        executor.return_value = double
        return phase._execute_phase(aggregated_results=aggregated, **kwargs)


def test_a_scanner_that_is_not_python_only_is_skipped_in_a_python_only_run(tmp_path):
    result = _run(tmp_path, OpengrepScanner, python_based_plugins_only=True)

    row = result.scanner_results["opengrep"]
    # Red at the base: ERROR, which failed the completeness gate.
    assert row.status == ScannerStatus.SKIPPED, row
    assert PYTHON_ONLY_SKIPPED_REASON in (row.skipped_reason or ""), row


def test_the_same_failure_without_python_only_is_still_an_error(tmp_path):
    """The control: --python-only is what changes the row."""
    result = _run(tmp_path, OpengrepScanner)

    assert result.scanner_results["opengrep"].status == ScannerStatus.ERROR


def test_a_python_only_scanner_that_fails_in_a_python_only_run_is_still_an_error(
    tmp_path,
):
    """The control: the run would have run it, so its failure is the run's."""
    result = _run(tmp_path, BanditScanner, python_based_plugins_only=True)

    assert result.scanner_results["bandit"].status == ScannerStatus.ERROR
