# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan cancelled after its last scanner leaves no record of reaching its end.

The scan phase appends the ``scan_phase_completed`` marker once its last step has
returned, and the orchestrator reads that marker to decide whether a failure in a
later phase still leaves a complete scan whose results file is worth writing. The
phase checked for a cancel only after appending the marker, so a cancel that landed
after the last scanner returned raised ``ScanCancelled`` with the marker already
written, and the save after the failure wrote a results file that read as complete
for a scan that had been cancelled. The check now comes first.

The fixtures mirror ``test_scan_phase_exclusion_by_a_retired_name.py``.
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.cancellation import ScanCancelled, cancel_scope
from automated_security_helper.core.phases.scan_phase import (
    SCAN_PHASE_COMPLETION_CHECKPOINT,
    ScanPhase,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit


def _plugin(class_name: str, config_name: str):
    cls = MagicMock(name=class_name)
    cls.__name__ = class_name
    instance = MagicMock()
    instance.__class__ = cls
    instance.__class__.__name__ = class_name
    config = MagicMock()
    config.enabled = True
    config.name = config_name
    instance.config = config
    instance.is_python_only.return_value = True
    instance.unsupported_platform_reason.return_value = None
    instance.validate_plugin_dependencies.return_value = True
    instance.dependencies_satisfied = True
    cls.return_value = instance
    return cls


def _phase(tmp_path):
    for sub in ("src", "out", "work"):
        (tmp_path / sub).mkdir(exist_ok=True)
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[_plugin("On", "on")],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    phase.validation_manager = MagicMock()
    return phase, aggregated


def _checkpoint_names(aggregated) -> list[str]:
    return [
        checkpoint.get("checkpoint_name")
        for checkpoint in aggregated.validation_checkpoints
    ]


def _run(phase, aggregated, cancel_after_scanners: bool):
    event = threading.Event()

    def _finish(*_args, **_kwargs):
        # The scanners are done; the cancel lands in the gap before the marker.
        if cancel_after_scanners:
            event.set()
        return aggregated

    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerExecutor"
    ) as executor:
        double = MagicMock()
        double.completed_scanners = []
        double.run_parallel.side_effect = _finish
        double.run_sequential.side_effect = _finish
        executor.return_value = double
        with cancel_scope(event):
            return phase._execute_phase(
                aggregated_results=aggregated, enabled_scanners=["on"]
            )


def test_a_cancel_after_the_last_scanner_writes_no_completion_marker(tmp_path):
    phase, aggregated = _phase(tmp_path)

    with pytest.raises(ScanCancelled):
        _run(phase, aggregated, cancel_after_scanners=True)

    # Red at the base: the marker was appended before the cancel was read.
    assert SCAN_PHASE_COMPLETION_CHECKPOINT not in _checkpoint_names(aggregated)


def test_a_scan_nobody_cancelled_still_writes_the_marker(tmp_path):
    """The control: the reorder moves the check, it does not drop the marker."""
    phase, aggregated = _phase(tmp_path)

    result = _run(phase, aggregated, cancel_after_scanners=False)

    assert SCAN_PHASE_COMPLETION_CHECKPOINT in _checkpoint_names(result)
