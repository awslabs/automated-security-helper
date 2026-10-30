# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The convert phase's failure row says what the filter decided, as the success row does.

``test_convert_phase_rows_are_keyed_redacted_and_robust`` pinned the success
row's ``dependencies_satisfied=True``: a converter in the loop survived
``filter_enabled_plugins``, whose own check admitted it. The exception handler's
row still read the instance's attribute, so a converter the filter admitted and
whose ``convert()`` then raised could be recorded with a failure and "tool absent"
at once. The test here is red on the tree that carried it.

The phase now checks each converter's dependencies once, so the fixture's one
check passes and its ``convert()`` raises; a converter whose check fails is
recorded as dropped for its tool and never runs, which is the sibling module's
case, not this one's.

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


class _AdmittedRaisingConfig(ConverterPluginConfigBase):
    name: Literal["admitted-raising-converter"] = "admitted-raising-converter"


class _AdmittedRaisingConverter(ConverterPluginBase[_AdmittedRaisingConfig]):
    """Its one dependency check passes; convert raises."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _AdmittedRaisingConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def convert(self, target: Path | str | None = None) -> List[Path]:
        raise RuntimeError("admitted, ran, and failed")


class TestTheFailureRowSaysWhatTheFilterDecided:
    def test_a_converter_the_filter_admitted_is_recorded_as_present(
        self, plugin_context
    ):
        results = _run(plugin_context, [_AdmittedRaisingConverter])

        row = results.converter_results["admitted-raising-converter"]
        assert row.failure is not None
        assert "RuntimeError" in row.failure
        # Red at the base: the handler read the instance's attribute, and the
        # report could say "tool absent" of a converter that the filter admitted
        # and that ran. The row says what the filter decided: present, and failed.
        assert row.dependencies_satisfied is True
        assert row.dependency_unavailable_reason is None
        assert row.excluded is False
