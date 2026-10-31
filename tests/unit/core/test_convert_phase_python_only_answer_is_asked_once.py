# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A converter is asked once whether it is Python-only, and that answer is acted on.

Why these tests exist
---------------------
On a Python-only run ``ConvertPhase`` asked each converter ``is_python_only()``
three times: in the loop that decides whose dependencies to check, inside
``filter_enabled_plugins``, and again when it wrote the row of a converter the
filter dropped. A plugin that answered differently each time was skipped by the
first, admitted by the second and described by the third as a converter whose
dependency check never ran. The dependency check already keeps one answer per
converter; the Python-only question now does too.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar, List, Literal
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
        config=AshConfig(project_name="convert-phase-python-only-once"),
    )


def _run(plugin_context: PluginContext, plugins: List[Any]):
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
    return phase.execute(aggregated_results=agg, python_based_plugins_only=True)


class _CountingConfig(ConverterPluginConfigBase):
    name: Literal["counting-converter"] = "counting-converter"


class _CountingConverter(ConverterPluginBase[_CountingConfig]):
    asked: ClassVar[int] = 0

    def model_post_init(self, context):
        if self.config is None:
            self.config = _CountingConfig()
        return super().model_post_init(context)

    def is_python_only(self) -> bool:
        type(self).asked += 1
        return True

    def validate_plugin_dependencies(self) -> bool:
        return True

    def convert(self, target: Path | str | None = None) -> List[Path]:
        return [Path("converted/one.py")]


class _InconsistentConfig(ConverterPluginConfigBase):
    name: Literal["inconsistent-converter"] = "inconsistent-converter"


class _InconsistentConverter(ConverterPluginBase[_InconsistentConfig]):
    """Raises the first time it is asked, answers True every time after."""

    asked: ClassVar[int] = 0

    def model_post_init(self, context):
        if self.config is None:
            self.config = _InconsistentConfig()
        return super().model_post_init(context)

    def is_python_only(self) -> bool:
        type(self).asked += 1
        if type(self).asked == 1:
            raise RuntimeError("cannot tell the first time")
        return True

    def validate_plugin_dependencies(self) -> bool:
        return True

    def convert(
        self, target: Path | str | None = None
    ) -> List[Path]:  # pragma: no cover
        raise AssertionError("a converter whose check raised must not run")


class TestThePythonOnlyQuestionIsAskedOncePerConverter:
    def test_a_python_only_converter_is_asked_once_and_runs(self, plugin_context):
        _CountingConverter.asked = 0

        results = _run(plugin_context, [_CountingConverter])

        # Red at the base: asked twice, by the dependency loop and the filter.
        assert _CountingConverter.asked == 1
        assert results.converter_results["counting-converter"].converted_paths


class TestAnInconsistentAnswerIsOneFailureNotThree:
    def test_the_converter_is_dropped_on_its_one_failure(self, plugin_context):
        _InconsistentConverter.asked = 0

        results = _run(plugin_context, [_InconsistentConverter])

        row = results.converter_results["inconsistent-converter"]
        # Red at the base: the second question answered True, so the filter
        # admitted the converter whose dependency loop had skipped it, and it
        # ran with no recorded dependency answer.
        assert _InconsistentConverter.asked == 1
        assert row.failure and "is_python_only() check raised" in row.failure
        assert "RuntimeError" in row.failure
        assert not row.converted_paths
