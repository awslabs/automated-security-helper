# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The row of a converter the filter dropped because a check raised.

The text of what the check raised goes into the row's ``failure``, which reaches
the results file, ``to_simple_dict`` (sent off-host by some reporters) and the
HTML report. Every other failure text of the convert phase is redacted with the
run's values and the converter's own, and has the home directory written as
``~``; this one was redacted by the filter alone and kept the home directory.

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
from automated_security_helper.utils.log import escape_markup

pytestmark = pytest.mark.unit

ENV_VALUE = "env-read-marker-value-4d9e1"


class _RaisedConfig(ConverterPluginConfigBase):
    name: Literal["filter-raised-converter"] = "filter-raised-converter"


class _RaisedConverter(ConverterPluginBase[_RaisedConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _RaisedConfig()
        return super().model_post_init(context)

    def _environment_values(self):
        return (ENV_VALUE,)

    def convert(
        self, target: Path | str | None = None
    ) -> List[Path]:  # pragma: no cover
        raise AssertionError("a dropped converter must not run")


@pytest.fixture
def plugin_context(tmp_path) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        config=AshConfig(project_name="convert-phase-filter-failure"),
    )


def _record(plugin_context, instance, **kwargs):
    """Write the row of *instance*, dropped by the filter, and return the rows."""
    agg = AshAggregatedResults(
        name="test", description="test", ash_config=plugin_context.config
    )
    phase = ConvertPhase(
        plugins=[],
        plugin_context=plugin_context,
        progress_display=MagicMock(),
        asharp_model=agg,
    )
    phase._record_filtered_out_converters(
        aggregated_results=agg,
        all_converter_instances=[instance],
        filtered_instances=[],
        **kwargs,
    )
    return agg.converter_results


class TestTheFilterFailureTextIsShownLikeEveryOtherFailureText:
    def test_the_home_directory_is_written_as_a_tilde_and_a_value_is_hidden(
        self, plugin_context
    ):
        # A converter is built with the run's context, as the phase builds it: a
        # converter without one refuses to construct.
        instance = _RaisedConverter(context=plugin_context)
        home = Path.home().as_posix()
        raised = f"RuntimeError: cannot read {home}/data for {ENV_VALUE}"

        rows = _record(
            plugin_context,
            instance,
            python_based_plugins_only=False,
            filter_failures={id(instance): raised},
        )

        row = rows["filter-raised-converter"]
        # Red at the base: the text was recorded as the filter handed it over, so
        # the home directory stayed in the row, which reaches off-host reporters.
        assert row.failure and "~/data" in row.failure
        assert f"{home}/data" not in row.failure
        assert ENV_VALUE not in row.failure
        assert "RuntimeError" in row.failure


class TestARecordedPythonOnlyAnswerDecidesTheExclusion:
    def test_a_recorded_python_only_answer_excludes_it_and_the_failure_stays(
        self, plugin_context
    ):
        instance = _RaisedConverter(context=plugin_context)

        rows = _record(
            plugin_context,
            instance,
            python_based_plugins_only=True,
            filter_failures={id(instance): "RuntimeError: enabled check raised"},
            python_only_answers={id(instance): False},
        )

        row = rows["filter-raised-converter"]
        # Red at the base: the raise was read first, so the recorded answer no
        # longer decided and the row read ``excluded`` False, which made the
        # completeness gate count a converter the run deliberately left out.
        # The recorded answer decides (``_unproductive_reason``'s rule: an
        # excluded row wins whatever else it carries); the raise only skips
        # asking ``is_python_only()`` again, and the failure text stays on the
        # row for a reader of the results file.
        assert row.excluded is True
        assert row.failure and "RuntimeError" in row.failure


class _TwinConfig(ConverterPluginConfigBase):
    name: Literal["twin-start-converter"] = "twin-start-converter"


class _TwinOne(ConverterPluginBase[_TwinConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _TwinConfig()
        return super().model_post_init(context)

    def convert(self, target: Path | str | None = None) -> List[Path]:
        return [Path("converted/one.py")]


class _TwinTwo(_TwinOne):
    def convert(self, target: Path | str | None = None) -> List[Path]:
        return [Path("converted/two.py")]


class TestTheStartingRowNamesTheConverterTheOtherRowsDo:
    def test_two_converters_of_one_name_start_under_their_row_keys(
        self, plugin_context
    ):
        agg = AshAggregatedResults(
            name="test", description="test", ash_config=plugin_context.config
        )
        progress = MagicMock()
        progress.add_task.return_value = 0
        phase = ConvertPhase(
            plugins=[_TwinOne, _TwinTwo],
            plugin_context=plugin_context,
            progress_display=progress,
            asharp_model=agg,
        )

        results = phase.execute(aggregated_results=agg)

        keys = sorted(
            key
            for key in results.converter_results
            if key.startswith("twin-start-converter")
        )
        started = sorted(
            str(call.kwargs.get("description", ""))
            for call in progress.add_task.call_args_list
            if "Starting converter" in str(call.kwargs.get("description", ""))
        )
        assert len(keys) == 2
        # Red at the base: the starting description quoted the class name, while
        # every later description and event of the loop quotes the row key.
        assert started == sorted(
            f"Starting converter: {escape_markup(key)}" for key in keys
        )
