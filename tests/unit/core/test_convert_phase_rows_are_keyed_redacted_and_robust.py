# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every converter gets a row of its own, redacted, whatever its records look like.

Why these tests exist
---------------------
``ConvertPhase`` records one ``converter_results`` row per converter, and that
row is what the completeness gate (``incomplete_converters``), the results file,
the HTML report and ``to_simple_dict`` read. Several ways of writing it were
wrong on the tree these tests were written against:

* two converters sharing a display name wrote one row, the later over the
  earlier, so a failure row could be replaced by a clean one;
* a ``candidate_input_count()`` answering with a non-int aborted the phase;
* a converter the config turned off whose constructor raised was recorded as a
  failure the gate fails the run on;
* a converter's exception text was recorded with no redaction of the values the
  configuration or the converter read from the environment;
* a disabled converter still had its dependency check run (which can install);
* an archive refused whole over an extraction limit was painted "No files to
  convert" while the gate failed the run on it;
* a surviving converter's dependency check was made twice, the row carrying one
  answer and the filter acting on the other, and a truthy non-bool answer made
  the row fail validation;
* a converter without a config made the success row raise;
* one malformed failed-input record aborted the whole scan from the handler.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

import logging
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
from automated_security_helper.interactions.run_ash_scan import incomplete_converters
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    RefusedInputInfo,
)

pytestmark = pytest.mark.unit

ENV_VALUE = "env-read-bucket-name-7f3a9"


@pytest.fixture
def plugin_context(tmp_path) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        config=AshConfig(project_name="convert-phase-rows"),
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
# Two converters, one display name
# --------------------------------------------------------------------------- #
class _TwinConfig(ConverterPluginConfigBase):
    name: Literal["twin-converter"] = "twin-converter"


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


class TestTwoConvertersSharingANameKeepTwoRows:
    def test_the_failure_row_is_not_replaced_by_the_clean_one(self, plugin_context):
        results, _ = _run(plugin_context, [_TwinRaising, _TwinProductive])

        twins = {
            key: row
            for key, row in results.converter_results.items()
            if key.startswith("twin-converter")
        }
        # Red at the base: one key, the productive row having overwritten the
        # failure row, so the gate saw a clean run.
        assert len(twins) == 2, sorted(twins)
        failures = [row for row in twins.values() if row.failure]
        assert len(failures) == 1
        assert "RuntimeError" in failures[0].failure
        assert len(incomplete_converters(results)) == 1


# --------------------------------------------------------------------------- #
# candidate_input_count() answering with a non-int
# --------------------------------------------------------------------------- #
class _StringCountConfig(ConverterPluginConfigBase):
    name: Literal["string-count-converter"] = "string-count-converter"


class _StringCountConverter(ConverterPluginBase[_StringCountConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _StringCountConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return False

    def candidate_input_count(self):  # type: ignore[override]
        return "3"

    def convert(
        self, target: Path | str | None = None
    ) -> List[Path]:  # pragma: no cover
        raise AssertionError("dropped before the loop")


class TestANonIntCandidateCountDoesNotAbortThePhase:
    def test_the_row_records_no_count(self, plugin_context):
        # Red at the base: the row's validation refused the str outside the
        # guard and the ValidationError escaped the phase.
        results, _ = _run(plugin_context, [_StringCountConverter])

        row = results.converter_results["string-count-converter"]
        assert row.candidate_inputs is None
        assert row.dependencies_satisfied is False


# --------------------------------------------------------------------------- #
# A disabled converter whose constructor raises
# --------------------------------------------------------------------------- #
class _UnconstructableConverter:
    def __init__(self, **kwargs):
        raise ValueError("plugin options are malformed")


class TestADisabledUnconstructableConverterIsExcluded:
    def test_the_row_is_excluded_and_the_gate_passes(self, plugin_context, monkeypatch):
        monkeypatch.setattr(
            type(plugin_context.config),
            "get_plugin_config",
            lambda self, plugin_type=None, plugin_name=None, **_: {
                "name": plugin_name,
                "enabled": False,
            },
        )

        results, _ = _run(plugin_context, [_UnconstructableConverter])

        row = results.converter_results["_UnconstructableConverter"]
        assert row.failure and "ValueError" in row.failure
        # Red at the base: excluded False, so the gate failed the run.
        assert row.excluded is True
        assert incomplete_converters(results) == []


# --------------------------------------------------------------------------- #
# Failure texts are redacted with the environment values
# --------------------------------------------------------------------------- #
class _UnconstructableQuotingAValue:
    def __init__(self, **kwargs):
        raise ValueError(f"option refused: {ENV_VALUE}")


class _LeakyConfig(ConverterPluginConfigBase):
    name: Literal["leaky-converter"] = "leaky-converter"


class _LeakyConverter(ConverterPluginBase[_LeakyConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _LeakyConfig()
        return super().model_post_init(context)

    def _environment_values(self):
        return (ENV_VALUE,)

    def convert(self, target: Path | str | None = None) -> List[Path]:
        raise RuntimeError(f"cannot reach {ENV_VALUE}")


class TestFailureTextsCarryNoEnvironmentValue:
    def test_a_construction_failure_is_redacted_with_the_configs_values(
        self, plugin_context, caplog
    ):
        plugin_context.config._environment_values = [ENV_VALUE]

        # Captured at DEBUG: the traceback goes out at that level, and a capture
        # at ERROR would never see it, so "the value is not in the log" would
        # hold with the value in the traceback line.
        with caplog.at_level(logging.DEBUG):
            results, _ = _run(plugin_context, [_UnconstructableQuotingAValue])

        row = results.converter_results["_UnconstructableQuotingAValue"]
        assert row.failure and "ValueError" in row.failure
        # The capture saw the failure line: an empty capture proves nothing.
        assert "Error creating converter" in caplog.text
        # Red at the base: the value was recorded and logged as written.
        assert ENV_VALUE not in row.failure
        assert ENV_VALUE not in caplog.text

    def test_a_convert_failure_is_redacted_with_the_converters_values(
        self, plugin_context, caplog
    ):
        with caplog.at_level(logging.DEBUG):
            results, progress = _run(plugin_context, [_LeakyConverter])

        row = results.converter_results["leaky-converter"]
        assert row.failure and "RuntimeError" in row.failure
        # The capture saw the error line, the debug traceback line and the
        # progress row that quotes the failure: each is a place the value had
        # been written, and an empty capture or an empty row list proves nothing.
        assert "Error in converter" in caplog.text
        assert "Converter exception traceback" in caplog.text
        assert any("Failed:" in text for text in _descriptions(progress))
        # Red at the base: results row, log line and progress row all quoted it.
        assert ENV_VALUE not in row.failure
        assert ENV_VALUE not in caplog.text
        assert all(ENV_VALUE not in text for text in _descriptions(progress))


# --------------------------------------------------------------------------- #
# A disabled converter's dependency check is not run
# --------------------------------------------------------------------------- #
class _DisabledCountingConfig(ConverterPluginConfigBase):
    name: Literal["disabled-counting-converter"] = "disabled-counting-converter"
    enabled: bool = False


class _DisabledCountingConverter(ConverterPluginBase[_DisabledCountingConfig]):
    # A class-level counter, not a model field: the tests reset and read it on
    # the class, and the check below counts on the class.
    dependency_checks: ClassVar[int] = 0

    def model_post_init(self, context):
        if self.config is None:
            self.config = _DisabledCountingConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        type(self).dependency_checks += 1
        return True

    def convert(
        self, target: Path | str | None = None
    ) -> List[Path]:  # pragma: no cover
        raise AssertionError("a disabled converter must not run")


class TestADisabledConverterIsNotAskedAboutItsDependencies:
    def test_the_check_never_runs_and_the_row_says_turned_off(self, plugin_context):
        _DisabledCountingConverter.dependency_checks = 0

        results, _ = _run(plugin_context, [_DisabledCountingConverter])

        # Red at the base: the pre-filter loop called it once.
        assert _DisabledCountingConverter.dependency_checks == 0
        row = results.converter_results["disabled-counting-converter"]
        assert row.excluded is True
        assert row.dependencies_satisfied is True
        assert row.dependency_unavailable_reason is None


# --------------------------------------------------------------------------- #
# An archive refused whole over an extraction limit
# --------------------------------------------------------------------------- #
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


class TestARefusedArchiveIsNotReportedAsNothingToConvert:
    def test_the_progress_row_names_the_refusal(self, plugin_context):
        results, progress = _run(plugin_context, [_RefusingArchiveConverter])

        descriptions = _descriptions(progress)
        # Red at the base: the row read "No files to convert" while the gate
        # failed the run on the refusal.
        assert any("refused over an extraction limit" in d for d in descriptions)
        assert not any("No files to convert" in d for d in descriptions)
        assert len(incomplete_converters(results)) == 1


# --------------------------------------------------------------------------- #
# A survivor's row says what the filter decided
# --------------------------------------------------------------------------- #
class _FlakyConfig(ConverterPluginConfigBase):
    name: Literal["flaky-dependency-converter"] = "flaky-dependency-converter"


class _FlakyDependencyConverter(ConverterPluginBase[_FlakyConfig]):
    checks: ClassVar[int] = 0

    def model_post_init(self, context):
        if self.config is None:
            self.config = _FlakyConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        # True for the first question only: a second one answers False.
        type(self).checks += 1
        return type(self).checks == 1

    def convert(self, target: Path | str | None = None) -> List[Path]:
        return [Path("converted/flaky.py")]


class _PathAnsweringConfig(ConverterPluginConfigBase):
    name: Literal["path-answering-converter"] = "path-answering-converter"


class _PathAnsweringConverter(ConverterPluginBase[_PathAnsweringConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _PathAnsweringConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self):  # type: ignore[override]
        return "/usr/bin/tool"

    def convert(self, target: Path | str | None = None) -> List[Path]:
        return [Path("converted/tool.py")]


class TestASurvivorsRowSaysWhatTheFilterDecided:
    def test_the_dependency_check_is_made_once_and_its_answer_is_acted_on(
        self, plugin_context
    ):
        _FlakyDependencyConverter.checks = 0

        results, _ = _run(plugin_context, [_FlakyDependencyConverter])

        row = results.converter_results["flaky-dependency-converter"]
        # Red when the phase asked twice: the filter's second question answered
        # False, so the converter the row called satisfied was dropped, or (the
        # other way round) a False recorded for a converter that then ran.
        assert _FlakyDependencyConverter.checks == 1
        assert row.converted_paths == ["converted/flaky.py"]
        assert row.dependencies_satisfied is True
        assert incomplete_converters(results) == []

    def test_a_truthy_non_bool_dependency_answer_is_not_a_failure(self, plugin_context):
        results, _ = _run(plugin_context, [_PathAnsweringConverter])

        row = results.converter_results["path-answering-converter"]
        # Red at the base: the row's bool field refused the path and the
        # converter was recorded as failed.
        assert row.failure is None
        assert row.dependencies_satisfied is True
        assert row.converted_paths == ["converted/tool.py"]


# --------------------------------------------------------------------------- #
# Converters that do not derive from ConverterPluginBase
# --------------------------------------------------------------------------- #
class _NoConfigConverter:
    """A third-party converter: no config, no base class."""

    config = None
    refused_inputs: List[Any] = []
    failed_inputs: List[Any] = []

    def __init__(self, **kwargs):
        pass

    def validate_plugin_dependencies(self) -> bool:
        return True

    def convert(self) -> List[str]:
        return ["converted/third_party.py"]


class _MalformedRecordsConverter:
    """Its failed_inputs holds something that is not a record."""

    class _Config:
        name = "malformed-records-converter"
        enabled = True

    config = _Config()
    refused_inputs: List[Any] = []

    def __init__(self, **kwargs):
        self.failed_inputs = ["bogus"]

    def validate_plugin_dependencies(self) -> bool:
        return True

    def convert(self) -> List[str]:
        return []


class TestConvertersOutsideTheBaseClass:
    def test_a_converter_without_a_config_is_recorded_as_it_ran(self, plugin_context):
        results, _ = _run(plugin_context, [_NoConfigConverter])

        row = results.converter_results["_NoConfigConverter"]
        # Red at the base: `config.enabled` on None raised and the converter was
        # recorded as failed.
        assert row.failure is None
        assert row.converted_paths == ["converted/third_party.py"]

    def test_one_malformed_record_does_not_abort_the_scan(self, plugin_context):
        # Red at the base: the handler rebuilt the row with the same record and
        # the ValidationError escaped the phase.
        results, _ = _run(plugin_context, [_MalformedRecordsConverter])

        row = results.converter_results["malformed-records-converter"]
        assert row.failure and "could not be recorded" in row.failure
        assert row.failed_inputs == []
