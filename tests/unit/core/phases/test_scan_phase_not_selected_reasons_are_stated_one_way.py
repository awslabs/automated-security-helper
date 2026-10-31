# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner the run did not select is given the same reason whichever path found it.

Why these tests exist
---------------------
``ScanPhase`` records a scanner SKIPPED as not selected in several places: a
scanner whose constructor raised, one whose name the tracker refuses, a later
holder of a shared name, and one that constructed. The rows of the first three
word their reasons with ``_not_selected_reasons`` in one order (excluded, left
out of the allowlist, disabled). The fourth built its own list in the other
order, so one deselected scanner read ``disabled ..., not named by ...`` or
``not named by ..., disabled ...`` in its ``skipped_reason`` depending on how it
got there. The fourth now uses the same helper.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.phases.scan_phase import (
    ScanPhase,
    _not_selected_reasons,
)
from automated_security_helper.core.scanner_selection import selection_names
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

NAMES = selection_names("cli")


def _selection(*, excluded: bool, in_allowlist: bool, enabled: bool):
    return SimpleNamespace(
        excluded=excluded,
        in_allowlist=in_allowlist,
        enabled=enabled,
        python_only_ok=True,
    )


def test_the_reasons_come_in_one_order():
    reasons = _not_selected_reasons(
        _selection(excluded=True, in_allowlist=False, enabled=False), NAMES
    )

    assert reasons == [
        f"excluded from this run ({NAMES.exclusion})",
        f"not named by {NAMES.allowlist}",
        "disabled in the configuration (enabled: false)",
    ]


def test_a_selected_scanner_has_no_reason():
    """The control: nothing to say when the run selected it."""
    assert (
        _not_selected_reasons(
            _selection(excluded=False, in_allowlist=True, enabled=True), NAMES
        )
        == []
    )


def _plugin(class_name: str, config_name: str, *, enabled: bool):
    cls = MagicMock(name=class_name)
    cls.__name__ = class_name
    instance = MagicMock()
    instance.__class__ = cls
    instance.__class__.__name__ = class_name
    config = MagicMock()
    config.enabled = enabled
    config.name = config_name
    instance.config = config
    instance.is_python_only.return_value = True
    instance.unsupported_platform_reason.return_value = None
    instance.validate_plugin_dependencies.return_value = True
    instance.dependencies_satisfied = True
    cls.return_value = instance
    return cls


def test_a_constructed_scanner_that_is_disabled_and_not_named_reads_like_the_others(
    tmp_path,
):
    for sub in ("src", "out", "work"):
        (tmp_path / sub).mkdir()
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[
            _plugin("Off", "off", enabled=False),
            _plugin("On", "on", enabled=True),
        ],
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
            aggregated_results=aggregated, enabled_scanners=["on"]
        )

    # Red at the base: "disabled ..., not named by ..." in this path.
    assert result.scanner_results["off"].skipped_reason == (
        f"not named by {NAMES.allowlist}, "
        "disabled in the configuration (enabled: false)"
    )
