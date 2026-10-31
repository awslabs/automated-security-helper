# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The convert phase's dependency skip and its names agree with its rows.

A review of the rows work in ``test_convert_phase_rows_are_keyed_redacted_and_robust``
found two places where the phase still did something its own rows contradicted,
each pinned here by a test that is red on the tree that carried it:

* the pre-filter dependency check skipped a disabled converter but still ran
  for a non-Python converter on a Python-only run, which the filter was about to
  drop anyway (a check can install a tool);
* two converters sharing a display name got two rows but one progress label
  and one ``converter=`` value in their events.

The two findings of the same review that each got a commit of their own are
pinned beside this module: the summary warning for a refused archive
(``test_convert_phase_summary_names_a_refused_archive``) and the failure row's
dependency answer (``test_convert_phase_failure_row_says_what_the_filter_decided``).

The fixtures mirror the sibling module's.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar, Dict, List, Literal
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base import engine_phase
from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.convert_phase import ConvertPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins.events import AshEventType

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


def _progress_stub() -> MagicMock:
    progress = MagicMock()
    progress.add_task.return_value = 0
    return progress


def _run(plugin_context: PluginContext, plugins, **kwargs):
    agg = AshAggregatedResults(
        name="test", description="test", ash_config=plugin_context.config
    )
    progress = _progress_stub()
    phase = ConvertPhase(
        plugins=plugins,
        plugin_context=plugin_context,
        progress_display=progress,
        asharp_model=agg,
    )
    return phase.execute(aggregated_results=agg, **kwargs), progress


def _descriptions(progress: MagicMock) -> List[str]:
    return [
        str(call.kwargs.get("description", ""))
        for call in progress.update_task.call_args_list
    ]


# --------------------------------------------------------------------------- #
# A non-Python converter is not asked about its dependencies on a Python-only run
# --------------------------------------------------------------------------- #
class _ShellCountingConfig(ConverterPluginConfigBase):
    name: Literal["shell-counting-converter"] = "shell-counting-converter"


class _ShellCountingConverter(ConverterPluginBase[_ShellCountingConfig]):
    # A class variable, not a model field: pydantic removes a field's default from
    # the class namespace, so a test that skipped the reset would fail inside the
    # dependency check with an AttributeError.
    checks: ClassVar[int] = 0

    def model_post_init(self, context):
        if self.config is None:
            self.config = _ShellCountingConfig()
        return super().model_post_init(context)

    def is_python_only(self) -> bool:
        return False

    def validate_plugin_dependencies(self) -> bool:
        type(self).checks += 1
        return True

    def convert(self, target: Path | str | None = None) -> List[Path]:
        return [Path("converted/shell.py")]


class _UnanswerableConfig(ConverterPluginConfigBase):
    name: Literal["unanswerable-converter"] = "unanswerable-converter"


class _UnanswerableConverter(ConverterPluginBase[_UnanswerableConfig]):
    """A converter whose is_python_only() raises, on a Python-only run."""

    checks: ClassVar[int] = 0

    def model_post_init(self, context):
        if self.config is None:
            self.config = _UnanswerableConfig()
        return super().model_post_init(context)

    def is_python_only(self) -> bool:
        raise RuntimeError("cannot tell whether this converter is Python-only")

    def validate_plugin_dependencies(self) -> bool:
        type(self).checks += 1
        return True

    def convert(self, target: Path | str | None = None) -> List[Path]:
        return []


class TestANonPythonConverterIsNotAskedAboutItsDependenciesOnAPythonOnlyRun:
    def test_the_check_never_runs_and_the_row_is_excluded(self, plugin_context):
        _ShellCountingConverter.checks = 0

        results, _ = _run(
            plugin_context, [_ShellCountingConverter], python_based_plugins_only=True
        )

        row = results.converter_results["shell-counting-converter"]
        assert row.excluded is True
        # Red at the base: the pre-filter loop skipped only a disabled
        # converter, so the check ran once for a converter the Python-only
        # filter was about to drop.
        assert _ShellCountingConverter.checks == 0
        # A check that never ran says nothing about the tool: the row is an
        # exclusion, not a missing dependency. Red at the previous tip: the
        # skipped check left the instance's default False, and the row said its
        # dependency check had failed.
        assert row.dependencies_satisfied is True
        assert row.dependency_unavailable_reason is None
        assert row.failure is None

    def test_a_converter_whose_python_only_check_raises_is_a_failure(
        self, plugin_context
    ):
        """An unanswerable is_python_only() is neither an exclusion nor a missing
        tool: the pre-filter loop skipped its dependency check on the same
        answer, so the row records the failure and says nothing about its tool.
        Red at the previous tip: the skipped check left dependencies_satisfied
        False, the drop read as explained, and the row said "tool absent"."""
        _UnanswerableConverter.checks = 0

        results, _ = _run(
            plugin_context, [_UnanswerableConverter], python_based_plugins_only=True
        )

        row = results.converter_results["unanswerable-converter"]
        assert row.failure is not None
        assert "RuntimeError" in row.failure
        assert row.excluded is False
        assert row.dependencies_satisfied is True
        assert row.dependency_unavailable_reason is None
        assert _UnanswerableConverter.checks == 0

    def test_the_control_run_still_asks(self, plugin_context):
        """The control: with every converter admitted, the check runs."""
        _ShellCountingConverter.checks = 0

        results, _ = _run(plugin_context, [_ShellCountingConverter])

        assert results.converter_results["shell-counting-converter"].excluded is False
        assert _ShellCountingConverter.checks >= 1


# --------------------------------------------------------------------------- #
# Two converters sharing a name are told apart in progress and events
# --------------------------------------------------------------------------- #
class _TwinConfig(ConverterPluginConfigBase):
    name: Literal["twin-converter"] = "twin-converter"


class _TwinOne(ConverterPluginBase[_TwinConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _TwinConfig()
        return super().model_post_init(context)

    def convert(self, target: Path | str | None = None) -> List[Path]:
        return [Path("converted/one.py")]


class _TwinTwo(ConverterPluginBase[_TwinConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _TwinConfig()
        return super().model_post_init(context)

    def convert(self, target: Path | str | None = None) -> List[Path]:
        return [Path("converted/two.py")]


def _qualified_twin_key(results: AshAggregatedResults) -> str:
    """The row key of the twin that did not get the bare name."""
    keys = [k for k in results.converter_results if k.startswith("twin-converter")]
    assert "twin-converter" in keys, keys
    qualified = [k for k in keys if k != "twin-converter"]
    assert len(qualified) == 1, keys
    return qualified[0]


class TestTwinsAreToldApartInProgressAndEvents:
    def test_the_progress_rows_carry_the_row_key(self, plugin_context):
        results, progress = _run(plugin_context, [_TwinOne, _TwinTwo])

        qualified = _qualified_twin_key(results)
        descriptions = _descriptions(progress)
        # Red at the base: both twins' rows read "(twin-converter) Converted",
        # so an operator could not tell which row belonged to which plugin.
        assert any(qualified in d for d in descriptions), descriptions

    def test_the_events_carry_the_row_key(self, plugin_context, monkeypatch):
        seen: List[Dict[str, Any]] = []

        def record(event_type, *_args, **kwargs):
            seen.append({"event_type": event_type, **kwargs})
            return []

        monkeypatch.setattr(engine_phase.ash_plugin_manager, "notify", record)

        results, _ = _run(plugin_context, [_TwinOne, _TwinTwo])

        qualified = _qualified_twin_key(results)
        starts = {
            e.get("converter")
            for e in seen
            if e["event_type"] == AshEventType.CONVERT_START
        }
        completes = {
            e.get("converter")
            for e in seen
            if e["event_type"] == AshEventType.CONVERT_COMPLETE
        }
        # Red at the base: both events named "twin-converter" twice.
        assert starts == {"twin-converter", qualified}
        assert completes == {"twin-converter", qualified}
