# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The convert phase and the converter base class must agree on how convert() is called.

The defect
----------
``ConverterPluginBase`` declared ``convert(self, target)`` as its one abstract
method, and the converter docs taught the same signature, while ``ConvertPhase``
has called ``plugin_instance.convert()`` with no argument since v3.0. Both built-in
converters implement ``convert(self)`` and find their own inputs in
``self.context.source_dir``. A converter written to the declared signature therefore
failed on every scan with ``TypeError: ... missing 1 required positional argument:
'target'``, which the completeness gate turns into exit 1. The shipped example
plugin was one of them.

The contract kept is the one that runs: ``convert(self)``. It is what the phase,
both built-ins and every converter that works today use, and the target it would
receive is ``context.source_dir``, which the converter already has. A converter
written to the old declared form, or any ``convert()`` that requires an argument, is
refused before it is called: its row records a failure that names the converter and
says to declare ``convert(self)``. It is not given the source directory in place of
the argument it asked for.
"""

from __future__ import annotations

import inspect
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


# Deliberately undecorated: @ash_converter_plugin registers into the process-wide
# plugin manager, and these fixtures must not appear in another test's library.
class _NoArgConfig(ConverterPluginConfigBase):
    name: Literal["no-arg-converter"] = "no-arg-converter"


class _NoArgConverter(ConverterPluginBase[_NoArgConfig]):
    """The contract: convert(self), inputs found through the context."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _NoArgConfig()
        return super().model_post_init(context)

    def convert(self) -> List[Path]:
        self.results_dir.mkdir(parents=True, exist_ok=True)
        out = self.results_dir / "no-arg.py"
        out.write_text(f"# from {self.context.source_dir.name}\n", encoding="utf-8")
        return [out]


class _TargetConfig(ConverterPluginConfigBase):
    name: Literal["target-converter"] = "target-converter"


class _TargetConverter(ConverterPluginBase[_TargetConfig]):
    """Written to a ``convert(self, target)`` signature, which ASH does not call."""

    received: List[object] = []

    def model_post_init(self, context):
        if self.config is None:
            self.config = _TargetConfig()
        return super().model_post_init(context)

    def convert(self, target: Path | str) -> List[Path]:
        type(self).received.append(target)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        out = self.results_dir / "target.py"
        out.write_text(f"# from {Path(target).name}\n", encoding="utf-8")
        return [out]


class _KeywordTargetConfig(ConverterPluginConfigBase):
    name: Literal["keyword-target-converter"] = "keyword-target-converter"


class _KeywordTargetConverter(ConverterPluginBase[_KeywordTargetConfig]):
    """The same form with the target as a required keyword-only parameter."""

    received: List[object] = []

    def model_post_init(self, context):
        if self.config is None:
            self.config = _KeywordTargetConfig()
        return super().model_post_init(context)

    def convert(self, *, target: Path | str) -> List[Path]:
        type(self).received.append(target)
        return []


class _TwoParamConfig(ConverterPluginConfigBase):
    name: Literal["two-param-converter"] = "two-param-converter"


class _TwoParamConverter(ConverterPluginBase[_TwoParamConfig]):
    """The (source_path, target_path) form an old docs page showed. ASH has no
    second value to pass, so this one must fail, and say why."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _TwoParamConfig()
        return super().model_post_init(context)

    def convert(self, source_path: str, target_path: str) -> List[Path]:
        raise AssertionError("must not be called with invented arguments")


class _DefaultTargetConfig(ConverterPluginConfigBase):
    name: Literal["default-target-converter"] = "default-target-converter"


class _DefaultTargetConverter(ConverterPluginBase[_DefaultTargetConfig]):
    """``convert(self, target=None)``: callable with no argument, so it gets none."""

    received: List[object] = []

    def model_post_init(self, context):
        if self.config is None:
            self.config = _DefaultTargetConfig()
        return super().model_post_init(context)

    def convert(self, target: Path | str | None = None) -> List[Path]:
        type(self).received.append(target)
        return []


class _OptionalParamsConfig(ConverterPluginConfigBase):
    name: Literal["optional-params-converter"] = "optional-params-converter"


class _OptionalParamsConverter(ConverterPluginBase[_OptionalParamsConfig]):
    """Two parameters, both with defaults: still callable as convert()."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _OptionalParamsConfig()
        return super().model_post_init(context)

    def convert(self, a: object = None, b: object = None) -> List[Path]:
        return []


class _VarArgsConfig(ConverterPluginConfigBase):
    name: Literal["var-args-converter"] = "var-args-converter"


class _VarArgsConverter(ConverterPluginBase[_VarArgsConfig]):
    """``convert(self, *args, **kwargs)``: callable with no argument, so it gets none."""

    received: List[object] = []

    def model_post_init(self, context):
        if self.config is None:
            self.config = _VarArgsConfig()
        return super().model_post_init(context)

    def convert(self, *args: object, **kwargs: object) -> List[Path]:
        type(self).received.append((args, kwargs))
        return []


class _VarKeywordConfig(ConverterPluginConfigBase):
    name: Literal["var-keyword-converter"] = "var-keyword-converter"


class _VarKeywordConverter(ConverterPluginBase[_VarKeywordConfig]):
    """``convert(self, **kwargs)``: a positional source directory would not fit."""

    received: List[object] = []

    def model_post_init(self, context):
        if self.config is None:
            self.config = _VarKeywordConfig()
        return super().model_post_init(context)

    def convert(self, **kwargs: object) -> List[Path]:
        type(self).received.append(kwargs)
        return []


class _StaticTargetConfig(ConverterPluginConfigBase):
    name: Literal["static-target-converter"] = "static-target-converter"


class _StaticTargetConverter(ConverterPluginBase[_StaticTargetConfig]):
    """A staticmethod convert(target): there is no self to name."""

    received: List[object] = []

    def model_post_init(self, context):
        if self.config is None:
            self.config = _StaticTargetConfig()
        return super().model_post_init(context)

    @staticmethod
    def convert(target: Path | str) -> List[Path]:
        _StaticTargetConverter.received.append(target)
        return []


class _AsyncConfig(ConverterPluginConfigBase):
    name: Literal["async-converter"] = "async-converter"


class _AsyncConverter(ConverterPluginBase[_AsyncConfig]):
    """``async def convert``: ASH calls convert() synchronously."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _AsyncConfig()
        return super().model_post_init(context)

    async def convert(self) -> List[Path]:
        return []


@pytest.fixture
def plugin_context(tmp_path) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n", encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        config=AshConfig(project_name="convert-call-contract"),
    )


@pytest.fixture(autouse=True)
def _reset_received():
    _TargetConverter.received = []
    _KeywordTargetConverter.received = []
    _DefaultTargetConverter.received = []
    _StaticTargetConverter.received = []
    _VarArgsConverter.received = []
    _VarKeywordConverter.received = []
    yield


def _run(plugin_context: PluginContext, plugins) -> AshAggregatedResults:
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


def test_the_base_class_declares_the_signature_the_phase_calls():
    """The abstract method takes nothing but self, because nothing else is passed."""
    params = list(inspect.signature(ConverterPluginBase.convert).parameters)
    assert params == ["self"], (
        f"ConverterPluginBase.convert declares {params}, but ConvertPhase calls "
        "convert() with no argument, so a converter written to the declaration fails"
    )


def test_the_built_in_converters_implement_the_declared_signature():
    from automated_security_helper.plugin_modules.ash_builtin.converters import (
        ArchiveConverter,
        JupyterConverter,
    )

    for cls in (ArchiveConverter, JupyterConverter):
        assert list(inspect.signature(cls.convert).parameters) == ["self"], cls


def test_a_converter_written_to_the_contract_runs(plugin_context):
    results = _run(plugin_context, [_NoArgConverter])

    row = results.converter_results["no-arg-converter"]
    assert row.failure is None
    assert [Path(p).name for p in row.converted_paths] == ["no-arg.py"]


def test_a_converter_declaring_convert_target_is_refused(plugin_context):
    """A converter declaring ``convert(self, target)`` is not called.

    ASH has no ``target`` to give it, so a converter that asks for an argument ASH
    does not have is refused the way one asking for two is.
    """
    results = _run(plugin_context, [_TargetConverter])

    row = results.converter_results["target-converter"]
    assert row.failure is not None
    assert "_TargetConverter" in row.failure and "'target'" in row.failure, row.failure
    assert "convert(self)" in row.failure, row.failure
    assert row.converted_paths in (None, []), row.converted_paths
    assert _TargetConverter.received == []


def test_a_keyword_only_target_is_refused(plugin_context):
    results = _run(plugin_context, [_KeywordTargetConverter])

    row = results.converter_results["keyword-target-converter"]
    assert row.failure is not None
    assert "'target'" in row.failure and "convert(self)" in row.failure, row.failure
    assert _KeywordTargetConverter.received == []


def test_a_converter_needing_values_ash_does_not_have_fails_with_a_clear_reason(
    plugin_context,
):
    results = _run(plugin_context, [_TwoParamConverter])

    row = results.converter_results["two-param-converter"]
    assert row.failure is not None
    assert "source_path" in row.failure and "target_path" in row.failure, row.failure
    assert "convert(self)" in row.failure, row.failure


def test_one_legacy_converter_does_not_cost_the_others_their_rows(plugin_context):
    results = _run(
        plugin_context, [_TwoParamConverter, _NoArgConverter, _TargetConverter]
    )

    assert results.converter_results["no-arg-converter"].failure is None
    assert results.converter_results["target-converter"].failure is not None
    assert results.converter_results["two-param-converter"].failure is not None


def test_a_parameter_with_a_default_is_left_to_its_default(plugin_context, caplog):
    """Only a parameter without a default makes ASH refuse the converter."""
    with caplog.at_level(logging.WARNING):
        results = _run(plugin_context, [_DefaultTargetConverter])

    assert results.converter_results["default-target-converter"].failure is None
    assert _DefaultTargetConverter.received == [None]
    assert not [
        r for r in caplog.records if "default-target-converter" in r.getMessage()
    ]


@pytest.mark.parametrize(
    "converter, name, expected",
    [
        (_VarArgsConverter, "var-args-converter", ((), {})),
        (_VarKeywordConverter, "var-keyword-converter", {}),
    ],
)
def test_star_parameters_are_not_a_required_target(
    plugin_context, caplog, converter, name, expected
):
    """``*args`` and ``**kwargs`` take nothing when called as convert(), so ASH passes
    nothing: no source directory, and no warning about a form to move to."""
    with caplog.at_level(logging.WARNING):
        results = _run(plugin_context, [converter])

    row = results.converter_results[name]
    assert row.failure is None, row.failure
    assert converter.received == [expected]
    assert not [r for r in caplog.records if name in r.getMessage()]


def test_optional_parameters_do_not_make_a_converter_fail(plugin_context):
    results = _run(plugin_context, [_OptionalParamsConverter])

    row = results.converter_results["optional-params-converter"]
    assert row.failure is None, row.failure


def test_a_static_convert_is_described_by_its_own_parameters(plugin_context):
    """A staticmethod has no self, so the refusal names the parameter, not a form."""
    results = _run(plugin_context, [_StaticTargetConverter])

    failure = results.converter_results["static-target-converter"].failure
    assert failure is not None
    assert "'target'" in failure and "self, target" not in failure, failure
    assert _StaticTargetConverter.received == []


def test_an_async_convert_fails_with_a_clear_reason(plugin_context):
    results = _run(plugin_context, [_AsyncConverter])

    row = results.converter_results["async-converter"]
    assert row.failure is not None
    assert "async" in row.failure and "def convert(self)" in row.failure, row.failure
