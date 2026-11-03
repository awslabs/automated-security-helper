# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Converters that share a display name are told apart in the lines the phase logs.

Why these tests exist
---------------------
``ConvertPhase`` gives two converters with one display name two rows, and files
the second under a qualified key. Its progress rows and events already carried
that key. Several log lines still named the converter by the shared display
name or by the class name, so in ash.log two converters that share a name could
not be told apart: the error line, the "found no files" line, the debug lines
around ``convert()`` and the dependency-check warning.

Each test states the assertion that fails at the base.
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
        config=AshConfig(project_name="convert-phase-log-keys"),
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


class _TwinConfig(ConverterPluginConfigBase):
    name: Literal["log-twin"] = "log-twin"


class _TwinProductive(ConverterPluginBase[_TwinConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _TwinConfig()
        return super().model_post_init(context)

    def convert(self, target: Path | str | None = None) -> List[Path]:
        return [Path("converted/one.py")]


class _TwinRaising(ConverterPluginBase[_TwinConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _TwinConfig()
        return super().model_post_init(context)

    def convert(self, target: Path | str | None = None) -> List[Path]:
        raise RuntimeError("the second twin fails")


class _TwinEmpty(ConverterPluginBase[_TwinConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _TwinConfig()
        return super().model_post_init(context)

    def convert(self, target: Path | str | None = None) -> List[Path]:
        return []


class TestTheErrorLineNamesTheRowKeyNotTheClass:
    def test_the_second_twin_is_named_by_its_qualified_key(
        self, plugin_context, caplog
    ):
        with caplog.at_level(logging.DEBUG):
            results = _run(plugin_context, [_TwinProductive, _TwinRaising])

        qualified = [key for key in results.converter_results if key != "log-twin"]
        assert len(qualified) == 1, sorted(results.converter_results)
        # Red at the base: "Error in converter _TwinRaising: ...", the class
        # name, which says nothing about which of the two rows it belongs to.
        assert f"Error in converter {qualified[0]}:" in caplog.text


class TestTheNoFilesLineNamesTheRowKey:
    def test_the_second_twin_is_named_by_its_qualified_key(
        self, plugin_context, caplog
    ):
        with caplog.at_level(logging.DEBUG):
            results = _run(plugin_context, [_TwinProductive, _TwinEmpty])

        qualified = [key for key in results.converter_results if key != "log-twin"]
        assert len(qualified) == 1, sorted(results.converter_results)
        lines = [
            record.getMessage()
            for record in caplog.records
            if "found no files to convert" in record.getMessage()
        ]
        assert len(lines) == 1, lines
        # Red at the base: the line named the shared display name "log-twin",
        # which is also the productive twin's name.
        assert qualified[0] in lines[0]
