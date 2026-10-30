# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The convert phase's failure row says what the filter decided, as the success row does.

``test_convert_phase_rows_are_keyed_redacted_and_robust`` pinned the success
row's ``dependencies_satisfied=True``: a converter in the loop survived
``filter_enabled_plugins``, whose own check admitted it. The exception handler's
row still read the instance's attribute, the first dependency check's answer, so
a converter whose first check said False, whose filter re-check said True, and
whose ``convert()`` then raised was recorded with a failure and "tool absent" at
once. The test here is red on the tree that carried it.

The fixtures mirror the sibling module's.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Literal
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.convert_phase import ConvertPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit


@pytest.fixture
def plugin_context(tmp_path) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        config=AshConfig(project_name="convert-phase-failure-row"),
    )


def _run(plugin_context: PluginContext, plugins):
    agg = AshAggregatedResults(
        name="test", description="test", ash_config=plugin_context.config
    )
    progress = MagicMock()
    progress.add_task.return_value = 0
    phase = ConvertPhase(
        plugins=plugins,
        plugin_context=plugin_context,
        progress_display=progress,
        asharp_model=agg,
    )
    return phase.execute(aggregated_results=agg)


class _FlakyRaisingConfig(ConverterPluginConfigBase):
    name: Literal["flaky-raising-converter"] = "flaky-raising-converter"


class _FlakyRaisingConverter(ConverterPluginBase[_FlakyRaisingConfig]):
    """First dependency check False, the filter's re-check True, convert raises."""

    checks: int = 0

    def model_post_init(self, context):
        if self.config is None:
            self.config = _FlakyRaisingConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        type(self).checks += 1
        return type(self).checks > 1

    def convert(self, target: Path | str | None = None) -> List[Path]:
        raise RuntimeError("admitted, ran, and failed")


class TestTheFailureRowSaysWhatTheFilterDecided:
    def test_a_converter_the_filter_admitted_is_recorded_as_present(
        self, plugin_context
    ):
        _FlakyRaisingConverter.checks = 0

        results = _run(plugin_context, [_FlakyRaisingConverter])

        row = results.converter_results["flaky-raising-converter"]
        assert row.failure is not None
        assert "RuntimeError" in row.failure
        # Red at the base: the handler read the instance's attribute, the first
        # check's False, and the report said "tool absent" of a converter that
        # the filter admitted and that ran.
        assert row.dependencies_satisfied is True
        assert row.excluded is False
