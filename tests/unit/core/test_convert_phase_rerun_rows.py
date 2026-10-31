# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A converter phase run again over one results object rewrites its own rows.

Why these tests exist
---------------------
``ConvertPhase`` gives every converter a ``converter_results`` key no other
converter of the run holds, so two converters that share a display name keep a
row each. The keys were chosen against every row the results object already
held, not against the rows this run claimed. Run a second time over the same
object (a caller that reuses its results, a test), every converter was filed
under its long ``"<name> (<module>.<Class>)"`` key while the first run's short
key stayed in place, so a stale failure row sat beside the new rows for the
completeness check and the reports to read.

Each test states the assertion that fails at the base.
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
        config=AshConfig(project_name="convert-phase-rerun"),
    )


class _TwinConfig(ConverterPluginConfigBase):
    name: Literal["rerun-twin"] = "rerun-twin"


class _TwinRaising(ConverterPluginBase[_TwinConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _TwinConfig()
        return super().model_post_init(context)

    def convert(self, target: Path | str | None = None) -> List[Path]:
        raise RuntimeError("the twin that fails")


class _TwinProductive(ConverterPluginBase[_TwinConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _TwinConfig()
        return super().model_post_init(context)

    def convert(self, target: Path | str | None = None) -> List[Path]:
        return [Path("converted/one.py")]


class _UnconstructableTwin:
    def __init__(self, **kwargs):
        raise ValueError("options are malformed")


def _phase(plugin_context: PluginContext, plugins, agg) -> ConvertPhase:
    progress = MagicMock()
    progress.add_task.return_value = 0
    return ConvertPhase(
        plugins=plugins,
        plugin_context=plugin_context,
        progress_display=progress,
        asharp_model=agg,
    )


class TestASecondRunFilesItsConvertersUnderTheSameKeys:
    def test_the_keys_of_the_second_run_are_the_keys_of_the_first(
        self, plugin_context
    ):
        agg = AshAggregatedResults(
            name="test", description="test", ash_config=plugin_context.config
        )
        plugins = [_TwinRaising, _TwinProductive]

        _phase(plugin_context, plugins, agg).execute(aggregated_results=agg)
        first = sorted(agg.converter_results)
        _phase(plugin_context, plugins, agg).execute(aggregated_results=agg)
        second = sorted(agg.converter_results)

        assert len(first) == 2, first
        # Red at the base: the second run added two long-key rows beside the
        # first run's two, four keys in all, the stale ones left in place.
        assert second == first, second

    def test_a_constructor_failure_row_is_rewritten_not_duplicated(
        self, plugin_context
    ):
        agg = AshAggregatedResults(
            name="test", description="test", ash_config=plugin_context.config
        )
        plugins = [_UnconstructableTwin]

        _phase(plugin_context, plugins, agg).execute(aggregated_results=agg)
        first = sorted(agg.converter_results)
        _phase(plugin_context, plugins, agg).execute(aggregated_results=agg)

        # Red at the base: a second key "_UnconstructableTwin (<module>)"
        # appeared, because the first run's row held the short one.
        assert sorted(agg.converter_results) == first
