# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A converter the config turned off is never reported as one that failed to start.

Why these tests exist
---------------------
``ConvertPhase`` records an ``excluded`` row for a converter the config turned
off, and the completeness gate (``incomplete_converters``) skips an excluded row
before it looks at anything else. Two places still treated such a row as a
failure:

* on a Python-only run the row builder asked a turned-off converter
  ``is_python_only()``, which the dependency loop never does, and a question
  that raised gave the row a ``failure`` beside ``excluded=True``;
* the phase's "No converter ran, and at least one did not start" warning and its
  end-of-phase list read the row's ``failure`` before its ``excluded`` flag, so a
  run whose every converter was turned off still said a converter "did not
  start" when one of them had a section its model refused.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, List, Literal
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
        config=AshConfig(project_name="convert-phase-turned-off"),
    )


def _run(plugin_context: PluginContext, plugins: List[Any], **kwargs):
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
    return phase.execute(aggregated_results=agg, **kwargs)


class _OffConfig(ConverterPluginConfigBase):
    name: Literal["turned-off-converter"] = "turned-off-converter"
    enabled: bool = False


class _OffConverterWhoseQuestionRaises(ConverterPluginBase[_OffConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _OffConfig()
        return super().model_post_init(context)

    def is_python_only(self) -> bool:
        raise RuntimeError("cannot tell")

    def convert(self, target: Path | str | None = None) -> List[Path]:
        raise AssertionError("a turned-off converter must not run")


class TestATurnedOffConverterIsNotAskedWhetherItIsPythonOnly:
    def test_the_row_is_excluded_and_carries_no_failure(self, plugin_context):
        results = _run(
            plugin_context,
            [_OffConverterWhoseQuestionRaises],
            python_based_plugins_only=True,
        )

        row = results.converter_results["turned-off-converter"]
        assert row.excluded is True
        # Red at the base: "its is_python_only() check raised RuntimeError: ...",
        # a failure the question the dependency loop never asks had produced.
        assert row.failure is None
        assert incomplete_converters(results) == []


class _UnconstructableConverter:
    def __init__(self, **kwargs):
        raise ValueError("plugin options are malformed")


class TestAllTurnedOffWithOneUnconstructableSaysNothingDidNotStart:
    def test_the_warning_is_the_no_enabled_converters_one(
        self, plugin_context, monkeypatch, caplog
    ):
        monkeypatch.setattr(
            type(plugin_context.config),
            "get_plugin_config",
            lambda self, plugin_type=None, plugin_name=None, **_: {
                "name": plugin_name,
                "enabled": False,
            },
        )

        with caplog.at_level(logging.WARNING):
            results = _run(plugin_context, [_UnconstructableConverter])

        row = results.converter_results["_UnconstructableConverter"]
        assert row.excluded is True
        assert row.failure and "ValueError" in row.failure
        messages = [record.getMessage() for record in caplog.records]
        # Red at the base: "No converter ran, and at least one did not start,
        # so conversion is skipped: _UnconstructableConverter (ValueError: ...)".
        assert not any("did not start" in message for message in messages), messages
        assert any("No enabled converter plugins found" in m for m in messages), (
            messages
        )
