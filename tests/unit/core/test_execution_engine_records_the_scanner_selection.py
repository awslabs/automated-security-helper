# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The engine records its scanner selection on the plugin context when it is built.

The scan phase is handed the selection as arguments. A converter runs before it and
is handed only the context, so the engine records the selection there too: the
allowlist with the exclusions taken out (the form the scan phase gets), the
exclusions, and whether the run is Python-only.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.execution_engine import ScanExecutionEngine

pytestmark = pytest.mark.unit


def test_the_engine_hands_the_context_its_selection_with_the_exclusions_taken_out(
    tmp_path: Path,
) -> None:
    context = MagicMock()
    context.config = AshConfig(project_name="selection-record-test")
    context.source_dir = tmp_path
    context.output_dir = tmp_path / "out"
    context.work_dir = tmp_path / "work"

    ScanExecutionEngine(
        context=context,
        enabled_scanners=["bandit", "grype"],
        excluded_scanners=["grype"],
        python_based_plugins_only=True,
        asharp_model=MagicMock(),
    )

    context.record_scanner_selection.assert_called_once_with(
        enabled=["bandit"], excluded=["grype"], python_only=True
    )


def test_a_plugin_context_reads_back_the_selection_its_engine_recorded(
    tmp_path: Path,
) -> None:
    context = PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        config=AshConfig(project_name="selection-record-test"),
    )

    ScanExecutionEngine(
        context=context,
        enabled_scanners=["bandit"],
        excluded_scanners=["grype"],
        asharp_model=MagicMock(),
    )

    selection = context.scanner_selection
    assert selection.enabled == ("bandit",)
    assert selection.excluded == ("grype",)
    assert selection.python_only is False
