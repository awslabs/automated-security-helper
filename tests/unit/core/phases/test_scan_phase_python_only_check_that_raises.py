# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A Python-only check that raises is a failure, not a scanner left out.

Why these tests exist
---------------------
``ScanPhase`` refuses a ``--python-only --scanners X`` run when every scanner the
allowlist selects is left out by the Python-only filter, because such a run would
execute nothing and report itself clean. The pre-check read a scanner whose
``is_python_only()`` raised as one the filter leaves out, so a run whose only
selected scanner's check raised was refused with "every scanner ... is left out
by the Python-only run", naming a cause that was not the case. The selection
loop already records such a scanner as an ERROR carrying the check's failure,
which the completeness gate sees; the pre-check now lets it get there.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit


def _plugin(name: str, *, python_only):
    cls = MagicMock(name=name)
    cls.__name__ = name
    instance = MagicMock()
    instance.__class__ = cls
    instance.__class__.__name__ = name
    config = MagicMock()
    config.enabled = True
    config.name = name
    instance.config = config
    if isinstance(python_only, Exception):
        instance.is_python_only.side_effect = python_only
    else:
        instance.is_python_only.return_value = python_only
    instance.unsupported_platform_reason.return_value = None
    instance.validate_plugin_dependencies.return_value = True
    instance.dependencies_satisfied = True
    cls.return_value = instance
    return cls


def _run(tmp_path, plugins, enabled_scanners):
    for sub in ("src", "out", "work"):
        (tmp_path / sub).mkdir(parents=True, exist_ok=True)
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=plugins,
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
        result = phase._execute_phase(
            aggregated_results=aggregated,
            enabled_scanners=enabled_scanners,
            python_based_plugins_only=True,
        )
    return result.scanner_results


def test_a_selected_scanner_whose_check_raises_is_recorded_not_refused(tmp_path):
    plugins = [
        _plugin("flaky", python_only=RuntimeError("cannot tell")),
        _plugin("steady", python_only=True),
    ]

    # Red at the base: ScannerSelectionError, "every scanner ... is left out by
    # the Python-only run: flaky".
    rows = _run(tmp_path, plugins, enabled_scanners=["flaky"])

    assert rows["flaky"].status == ScannerStatus.ERROR
    assert rows["steady"].status == ScannerStatus.SKIPPED


def test_a_selected_scanner_that_is_not_python_only_is_still_refused(tmp_path):
    """The control: the refusal is for a check that answered no."""
    from automated_security_helper.core.exceptions import ScannerSelectionError

    plugins = [_plugin("grype", python_only=False), _plugin("steady", python_only=True)]

    with pytest.raises(ScannerSelectionError):
        _run(tmp_path, plugins, enabled_scanners=["grype"])
