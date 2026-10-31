# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The convert phase's summary warning names an archive refused over a limit.

``test_convert_phase_rows_are_keyed_redacted_and_robust`` pinned the progress
row and the CONVERT_COMPLETE message for an archive refused whole over an
extraction limit. The summary warning was left out: its row had no failure and
no failed input, so the summary fell through to "No files were converted by any
converter plugins" while the completeness gate failed the run on the refusal.
The test here is red on the tree that carried it.

The fixtures mirror the sibling module's.
"""

from __future__ import annotations

import logging
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
from automated_security_helper.interactions.run_ash_scan import incomplete_converters
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    RefusedInputInfo,
)

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
        config=AshConfig(project_name="convert-phase-summary"),
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


class _RefusingArchiveConfig(ConverterPluginConfigBase):
    name: Literal["refusing-archive-converter"] = "refusing-archive-converter"


class _RefusingArchiveConverter(ConverterPluginBase[_RefusingArchiveConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _RefusingArchiveConfig()
        return super().model_post_init(context)

    def convert(self, target: Path | str | None = None) -> List[Path]:
        self.refused_inputs.append(
            RefusedInputInfo(
                path="vendor/big.zip",
                reason="over max_total_bytes",
                limit="max_total_bytes",
            )
        )
        return []


class TestTheSummaryNamesARefusedArchive:
    def test_the_warning_names_the_converter_and_not_nothing_to_convert(
        self, plugin_context, caplog
    ):
        with caplog.at_level(logging.WARNING):
            results = _run(plugin_context, [_RefusingArchiveConverter])

        # The gate fails the run on the refusal, so the summary has to say so.
        assert len(incomplete_converters(results)) == 1
        # Red at the base: the row had no failure and no failed input, so the
        # summary fell through to the generic "nothing to convert" line.
        assert "No files were converted by any converter plugins" not in caplog.text
        assert (
            "refusing-archive-converter (1 archive refused over an extraction limit)"
            in caplog.text
        )
