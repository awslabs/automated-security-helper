# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sandbox's reasons reach a converter's row redacted, like its other texts.

Why these tests exist
---------------------
When a converter's ``convert()`` runs under the scanner sandbox, the spawns the
sandbox refused are counted on the run scope with the last refusal's reason
(``last_refusal``). ``ConvertPhase`` puts that reason, as the sandbox recorded
it, into the converter's progress row, the ``CONVERT_COMPLETE`` event message and
``ConverterStatusInfo.failure``. A scope that also records the plans that failed
(``last_failure``) reaches the row through the same text, so the doubles below
carry one of each; what is asserted is the refusal, which every scope records.

Every other text a converter's row carries is redacted before it is recorded
(``_failure_text``, the dependency reason, the failed-input rows): a converter's
exception or its tool's words can quote a value its configuration read from the
environment. The sandbox's reasons are no different -- a refusal names the
scanner's request and a failed plan carries the backend's own error, which can
quote the argv it did not run -- but they were joined into the row raw.

What the tests hold
-------------------
A value the run's configuration read from the environment, and one only the
converter read, is absent from the row's ``failure``, from the progress
description and from the event message, while the reason's own words (the
counts, "refused", "could not plan") stay. The control is the same run with no
value planted, whose text is unchanged.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from types import SimpleNamespace
from typing import List, Literal
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases import convert_phase
from automated_security_helper.core.phases.convert_phase import ConvertPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

RUN_VALUE = "/nonexistent/RUNCANARY-4b9e/bin/pandoc"
OWN_VALUE = "/nonexistent/OWNCANARY-d27a/bin/pandoc"


@pytest.fixture
def plugin_context(tmp_path) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        config=AshConfig(project_name="convert-phase-sandbox-loss"),
    )


def _converter(name: str, env_values=()):
    """A converter class of its own, named *name*, that converts nothing."""
    config_class = type(
        f"_{name}Config",
        (ConverterPluginConfigBase,),
        {"__annotations__": {"name": Literal[name]}, "name": name},
    )

    def model_post_init(self, context):
        if self.config is None:
            self.config = config_class()
        super(cls, self).model_post_init(context)

    def convert(self, target: Path | str | None = None) -> List[Path]:
        return []

    cls = type(
        f"_{name}",
        (ConverterPluginBase[config_class],),
        {
            "model_post_init": model_post_init,
            "validate_plugin_dependencies": lambda self: True,
            "convert": convert,
            "_environment_values": lambda self: tuple(env_values),
        },
    )
    return cls


def _scope_with(*, refusal: str, failure: str):
    """A ``converter_run_scope`` double whose scope lost one spawn each way."""

    @contextlib.contextmanager
    def scope(plugin, context):
        yield SimpleNamespace(
            refused_spawns=1,
            last_refusal=refusal,
            failed_spawns=1,
            last_failure=failure,
        )

    return scope


def _observed(plugin_context, plugins):
    """Run with the events recorded: ``(results, events, progress)``."""
    progress = MagicMock()
    progress.add_task.return_value = 0
    agg = AshAggregatedResults(
        name="test", description="test", ash_config=plugin_context.config
    )
    phase = ConvertPhase(
        plugins=plugins,
        plugin_context=plugin_context,
        progress_display=progress,
        asharp_model=agg,
    )
    events: list = []
    phase.notify_event = lambda event, **kwargs: events.append((str(event), kwargs))
    results = phase.execute(aggregated_results=agg)
    return results, events, progress


def _texts(results, events, progress, name: str) -> List[str]:
    """Every text the phase wrote about the converter *name*."""
    texts = [str(results.converter_results[name].failure)]
    texts.extend(
        str(call.kwargs.get("description", ""))
        for call in progress.update_task.call_args_list
        if name in str(call.kwargs.get("description", ""))
    )
    texts.extend(
        str(kwargs.get("message", ""))
        for event, kwargs in events
        if "CONVERT_COMPLETE" in event
    )
    return texts


class TestTheSandboxReasonsAreRedacted:
    def test_a_value_the_run_read_from_the_environment_is_absent(
        self, plugin_context, monkeypatch
    ):
        plugin_context.config._environment_values = [RUN_VALUE]
        monkeypatch.setattr(
            convert_phase,
            "converter_run_scope",
            _scope_with(
                refusal=f"nb cannot be sandboxed as requested: {RUN_VALUE} denied",
                failure=f"FileNotFoundError: {RUN_VALUE}: no such program",
            ),
        )

        results, events, progress = _observed(
            plugin_context, [_converter("sandbox-lost")]
        )

        texts = _texts(results, events, progress, "sandbox-lost")
        # The control half: the reason is still there, with its count, and the
        # three places it goes (the row, the progress description, the event)
        # were all read.
        failure = texts[0]
        assert "sandbox refused 1 process" in failure, failure
        assert len(texts) >= 3, texts
        # Red at the base: every one of them quoted the value.
        for text in texts:
            assert "RUNCANARY-4b9e" not in text, text

    def test_a_value_only_the_converter_read_is_absent(
        self, plugin_context, monkeypatch
    ):
        monkeypatch.setattr(
            convert_phase,
            "converter_run_scope",
            _scope_with(
                refusal=f"nb cannot be sandboxed as requested: {OWN_VALUE} denied",
                failure=f"FileNotFoundError: {OWN_VALUE}: no such program",
            ),
        )

        results, events, progress = _observed(
            plugin_context, [_converter("own-value-lost", env_values=(OWN_VALUE,))]
        )

        texts = _texts(results, events, progress, "own-value-lost")
        # The control: the run's configuration holds no such value, so only the
        # converter's own can hide it.
        assert OWN_VALUE not in (plugin_context.config._environment_values or [])
        assert "sandbox refused 1 process" in texts[0], texts[0]
        for text in texts:
            assert "OWNCANARY-d27a" not in text, text

    def test_the_control_without_a_value_keeps_the_reasons_whole(
        self, plugin_context, monkeypatch
    ):
        monkeypatch.setattr(
            convert_phase,
            "converter_run_scope",
            _scope_with(
                refusal="nb cannot be sandboxed as requested: denied by the test",
                failure="FileNotFoundError: pandoc: no such program",
            ),
        )

        results, _, _ = _observed(plugin_context, [_converter("nothing-planted")])

        failure = str(results.converter_results["nothing-planted"].failure)
        assert "sandbox refused 1 process" in failure, failure
        assert "denied by the test" in failure, failure
