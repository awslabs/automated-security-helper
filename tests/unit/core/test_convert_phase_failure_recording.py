# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A converter that did not run must leave a machine-readable trace.

Why these tests exist
---------------------
``ConvertPhase._execute_phase`` wrote its ``converter_results`` row as the last
statement of the ``try`` block, after ``convert()`` had already returned. Every
way of not getting that far therefore produced no row at all:

* ``convert()`` raised -- the handler logged, painted the progress row red and
  went back to the loop, leaving the key absent.
* ``filter_enabled_plugins`` dropped the instance for unsatisfied dependencies --
  it never reached the loop, which is the only site that writes the dict.

With no row written, ``converted_paths`` stayed empty and the phase emitted the
same "No files were converted by any converter plugins" warning a repository with
nothing to convert emits. Three states collapsed into one indistinguishable one:
the converter crashed, its tool was absent, and there was nothing to do.

``ConverterStatusInfo.dependencies_satisfied`` existed for the second case and was
dead: nothing in the tree ever assigned a converter's ``dependencies_satisfied``,
so the field could never be ``False``.

What the tests hold
-------------------
Four states have to be distinguishable from the recorded row alone, because the
row is what a consumer of ``ash_aggregated_results.json`` reads:

* ran and produced paths      -- ``converted_paths`` non-empty
* ran and found nothing       -- empty paths, ``failure`` None, ``excluded`` False
* crashed                     -- ``failure`` naming the exception
* did not run                 -- ``excluded`` True, or ``dependencies_satisfied``
                                 False when a missing tool was the reason

``tests/unit/core/test_disabled_converters_fix.py`` is the adjacent module. It
asserts that the filtering works; nothing asserted that the filtering was
recorded.
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
from automated_security_helper.interactions.run_ash_scan import incomplete_converters
from automated_security_helper.models.asharp_model import AshAggregatedResults


# --------------------------------------------------------------------------- #
# Real converter plugins rather than mocks.
#
# The assertions below are on a resolved ConverterStatusInfo, so the object under
# test has to be the real model. Deliberately undecorated: @ash_converter_plugin
# registers into the process-wide plugin manager, and a test fixture has no
# business appearing in another test's plugin library.
# --------------------------------------------------------------------------- #
class _StubConverterConfig(ConverterPluginConfigBase):
    name: Literal["stub-converter"] = "stub-converter"


class _ProductiveConverter(ConverterPluginBase[_StubConverterConfig]):
    """Converts one file, so its row is the "ran and produced paths" state."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _StubConverterConfig()
        return super().model_post_init(context)

    def convert(self, target: Path | str | None = None) -> List[Path]:
        return [Path("converted/one.py")]


class _EmptyConverterConfig(ConverterPluginConfigBase):
    name: Literal["empty-converter"] = "empty-converter"


class _EmptyConverter(ConverterPluginBase[_EmptyConverterConfig]):
    """Finds nothing to convert, which is a legitimate outcome."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _EmptyConverterConfig()
        return super().model_post_init(context)

    def convert(self, target: Path | str | None = None) -> List[Path]:
        return []


class _RaisingConverterConfig(ConverterPluginConfigBase):
    name: Literal["raising-converter"] = "raising-converter"


class _RaisingConverter(ConverterPluginBase[_RaisingConverterConfig]):
    """Raises from convert(), which is the defect's primary shape."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _RaisingConverterConfig()
        return super().model_post_init(context)

    def convert(self, target: Path | str | None = None) -> List[Path]:
        raise RuntimeError("nbconvert is not on PATH")


class _MissingToolConverterConfig(ConverterPluginConfigBase):
    name: Literal["missing-tool-converter"] = "missing-tool-converter"


class _MissingToolConverter(ConverterPluginBase[_MissingToolConverterConfig]):
    """Its external tool is absent, so it is dropped before the conversion loop."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _MissingToolConverterConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return False

    def convert(
        self, target: Path | str | None = None
    ) -> List[Path]:  # pragma: no cover
        raise AssertionError("a converter with unsatisfied dependencies must not run")


class _DisabledConverterConfig(ConverterPluginConfigBase):
    name: Literal["disabled-converter"] = "disabled-converter"
    enabled: bool = False


class _DisabledConverter(ConverterPluginBase[_DisabledConverterConfig]):
    """Turned off in config, which must not read as a missing tool."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _DisabledConverterConfig()
        return super().model_post_init(context)

    def convert(
        self, target: Path | str | None = None
    ) -> List[Path]:  # pragma: no cover
        raise AssertionError("a disabled converter must not run")


class _NonPythonConverterConfig(ConverterPluginConfigBase):
    name: Literal["non-python-converter"] = "non-python-converter"


class _NonPythonConverter(ConverterPluginBase[_NonPythonConverterConfig]):
    """Excluded by --python-based-plugins-only, not by anything being wrong."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _NonPythonConverterConfig()
        return super().model_post_init(context)

    def is_python_only(self) -> bool:
        return False

    def convert(
        self, target: Path | str | None = None
    ) -> List[Path]:  # pragma: no cover
        raise AssertionError("a non-Python converter must not run in python-only mode")


class _UnconstructableConverter:
    """Its constructor raises, so there is never an instance to ask for a name.

    Not a ConverterPluginBase subclass on purpose: ConvertPhase only calls the class
    and reads ``__name__`` off it, and a plugin whose constructor raises has not got
    as far as being a converter.
    """

    def __init__(self, **kwargs):
        raise ValueError("plugin options are malformed")


@pytest.fixture
def plugin_context(tmp_path) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        config=AshConfig(project_name="convert-phase-failure-recording"),
    )


def _progress_stub() -> MagicMock:
    progress = MagicMock()
    progress.add_task.return_value = 0
    return progress


def _run(plugin_context: PluginContext, plugins, **kwargs) -> AshAggregatedResults:
    agg = AshAggregatedResults(
        name="test", description="test", ash_config=plugin_context.config
    )
    phase = ConvertPhase(
        plugins=plugins,
        plugin_context=plugin_context,
        progress_display=_progress_stub(),
        asharp_model=agg,
    )
    return phase.execute(aggregated_results=agg, **kwargs)


class TestACrashedConverterIsRecorded:
    """An exception out of convert() has to appear in converter_results."""

    def test_a_converter_that_raises_still_gets_a_row(self, plugin_context):
        results = _run(plugin_context, [_RaisingConverter])

        assert "raising-converter" in results.converter_results, (
            "convert() raised and the phase recorded nothing, so the crash is "
            "absent from the machine-readable output entirely"
        )

    def test_the_row_names_the_exception_type_and_message(self, plugin_context):
        results = _run(plugin_context, [_RaisingConverter])

        row = results.converter_results["raising-converter"]
        assert row.failure == "RuntimeError: nbconvert is not on PATH", (
            "the row has to carry which exception ended the converter; a bare "
            "empty converted_paths does not distinguish a crash from an empty run"
        )

    def test_a_crash_is_distinguishable_from_nothing_to_convert(self, plugin_context):
        """The two states that collapsed into one warning have to differ in the row."""
        results = _run(plugin_context, [_RaisingConverter, _EmptyConverter])

        crashed = results.converter_results["raising-converter"]
        empty = results.converter_results["empty-converter"]

        assert crashed.converted_paths == [] and empty.converted_paths == [], (
            "both produced no paths, which is why converted_paths alone cannot "
            "tell them apart"
        )
        assert empty.failure is None, "a converter with nothing to do did not fail"
        assert crashed.failure is not None, "a converter that raised did fail"

    def test_a_crash_does_not_suppress_a_healthy_converter(self, plugin_context):
        """One converter failing must not cost the run the other's row."""
        results = _run(plugin_context, [_RaisingConverter, _ProductiveConverter])

        assert set(results.converter_results) == {
            "raising-converter",
            "stub-converter",
        }
        assert results.converter_results["stub-converter"].converted_paths == [
            "converted/one.py"
        ]
        assert results.converter_results["stub-converter"].failure is None


class TestADroppedConverterIsRecorded:
    """A converter filtered out before the loop has to appear too."""

    def test_a_converter_with_unsatisfied_dependencies_gets_a_row(self, plugin_context):
        results = _run(plugin_context, [_MissingToolConverter])

        assert "missing-tool-converter" in results.converter_results, (
            "filter_enabled_plugins dropped it before the loop that writes "
            "converter_results, so a missing converter tool cost coverage with no "
            "trace anywhere"
        )

    def test_the_row_reports_dependencies_satisfied_false(self, plugin_context):
        results = _run(plugin_context, [_MissingToolConverter])

        row = results.converter_results["missing-tool-converter"]
        assert row.dependencies_satisfied is False, (
            "ConverterStatusInfo.dependencies_satisfied defaults True and nothing "
            "ever assigned it, so the field could not express a missing tool"
        )
        assert row.excluded is False, (
            "nothing excluded this converter -- the run wanted it and its tool was "
            "absent. Recording it excluded would be load-bearing rather than "
            "cosmetic: incomplete_converters skips an excluded row, so the missing "
            "tool would be invisible to the exit code as well as to the operator"
        )

    def test_the_instance_carries_the_measured_value(self, plugin_context):
        """Mirrors ScannerPluginBase._pre_scan, which assigns the same field."""
        instance_holder = {}

        class _Recording(_MissingToolConverter):
            def model_post_init(self, context):
                instance_holder["instance"] = self
                return super().model_post_init(context)

        _run(plugin_context, [_Recording])

        assert instance_holder["instance"].dependencies_satisfied is False

    def test_a_disabled_converter_is_recorded_excluded_not_unsatisfied(
        self, plugin_context
    ):
        """ "Turned off" and "tool absent" are different facts and must not merge."""
        results = _run(plugin_context, [_DisabledConverter])

        row = results.converter_results["disabled-converter"]
        assert row.excluded is True, "a config-disabled converter was excluded"
        assert row.dependencies_satisfied is True, (
            "nothing was wrong with its dependencies; reporting them unsatisfied "
            "would send an operator looking for a tool to install"
        )
        assert row.failure is None

    def test_a_converter_dropped_by_python_only_mode_is_recorded_excluded(
        self, plugin_context
    ):
        results = _run(
            plugin_context, [_NonPythonConverter], python_based_plugins_only=True
        )

        row = results.converter_results["non-python-converter"]
        assert row.excluded is True
        assert row.dependencies_satisfied is True
        assert row.failure is None

    def test_a_converter_that_ran_is_not_marked_excluded(self, plugin_context):
        """The negative control: excluded must not be True for everything."""
        results = _run(plugin_context, [_ProductiveConverter, _EmptyConverter])

        assert results.converter_results["stub-converter"].excluded is False
        assert results.converter_results["empty-converter"].excluded is False


class TestAConverterThatFailedToConstructIsRecorded:
    """The third hole in the same function, keyed on the class rather than a name.

    Beyond the two defects this phase names, and fixed with them because it is the
    same mechanism at the same edit site: a converter that contributed no targets and
    said so nowhere. There is no instance, so the row is keyed on the class name.
    """

    def test_it_gets_a_row_naming_the_constructor_exception(self, plugin_context):
        results = _run(plugin_context, [_UnconstructableConverter])

        row = results.converter_results["_UnconstructableConverter"]
        assert row.failure == "ValueError: plugin options are malformed"
        assert row.converted_paths == []
        assert row.excluded is False

    def test_it_does_not_stop_the_other_converters(self, plugin_context):
        results = _run(
            plugin_context, [_UnconstructableConverter, _ProductiveConverter]
        )

        assert results.converter_results["stub-converter"].converted_paths == [
            "converted/one.py"
        ]


class TestTheRecordedRowsReachTheGate:
    """The two halves of this fix, composed.

    The convert phase writes the row and ``run_ash_scan.incomplete_converters`` reads
    it. Asserting each half separately leaves the seam untested, and the seam is where
    a plausible-looking row silently stops gating: ``incomplete_converters`` skips any
    row marked ``excluded``, so a phase that marked every dropped converter excluded
    would satisfy every per-row assertion above and still exit 0 on a missing tool.
    """

    def test_a_missing_tool_recorded_by_the_phase_is_listed_by_the_gate(
        self, plugin_context
    ):
        results = _run(plugin_context, [_MissingToolConverter])

        assert incomplete_converters(results) == [
            ("missing-tool-converter", "dependencies unavailable, so it never ran")
        ]

    def test_a_crash_recorded_by_the_phase_is_listed_by_the_gate(self, plugin_context):
        results = _run(plugin_context, [_RaisingConverter])

        assert incomplete_converters(results) == [
            ("raising-converter", "RuntimeError: nbconvert is not on PATH")
        ]

    def test_a_disabled_converter_recorded_by_the_phase_is_not_listed(
        self, plugin_context
    ):
        """The other direction, so the gate is not simply listing everything."""
        results = _run(plugin_context, [_DisabledConverter, _EmptyConverter])

        assert incomplete_converters(results) == []


class TestEveryConstructedConverterAppears:
    """The dict has to account for every converter the phase built."""

    def test_all_six_outcomes_are_present_in_one_run(self, plugin_context):
        results = _run(
            plugin_context,
            [
                _ProductiveConverter,
                _EmptyConverter,
                _RaisingConverter,
                _MissingToolConverter,
                _DisabledConverter,
                _UnconstructableConverter,
            ],
        )

        assert set(results.converter_results) == {
            "stub-converter",
            "empty-converter",
            "raising-converter",
            "missing-tool-converter",
            "disabled-converter",
            "_UnconstructableConverter",
        }
