# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two readings of ConverterPluginBase that a converter outside this repository
meets first.

A converter given no config ran with the generic ConverterPluginConfigBase: its
declared config model's name, ``enabled`` default and options were replaced, so a
converter declared disabled by default ran, and its work directory was named for
the class. The default is now an instance of the model the converter declares.

record_failed_input guarded the suppression-id bookkeeping of an accepted input
but read the same environment record unguarded first, for the suppression's
written reason, so a failure there lost the accepted input's record. Both reads
are guarded; the record lands either way, and on that error path it carries a
fixed text, not the suppression's expanded reason: a reason the config file read
from the environment is quoted by its reference, never its value, and with the
record unreadable the two cannot be told apart.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Literal

import pytest
from pydantic import Field

from automated_security_helper.base.converter_plugin import (
    REASON_NOT_RENDERED,
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.base.options import ConverterOptionsBase
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
)
from automated_security_helper.utils import suppression_matcher

pytestmark = pytest.mark.unit


class QuietOptions(ConverterOptionsBase):
    depth: int = Field(default=3, description="how deep the converter looks")


class QuietConfig(ConverterPluginConfigBase):
    name: Literal["quiet"] = "quiet"
    enabled: bool = False
    options: QuietOptions = QuietOptions()


class QuietConverter(ConverterPluginBase[QuietConfig]):
    """A converter declared disabled by default, as a third-party one may be."""

    def validate_plugin_dependencies(self) -> bool:
        return True

    def convert(self) -> List[Path]:
        return []


def test_a_converter_given_no_config_runs_with_the_model_it_declares(
    test_plugin_context,
):
    converter = QuietConverter(context=test_plugin_context)

    assert isinstance(converter.config, QuietConfig)
    assert converter.config.name == "quiet"
    assert converter.config.enabled is False
    assert converter.config.options.depth == 3
    assert converter.results_dir.name == "quiet"


def test_a_converter_given_its_config_keeps_it(test_plugin_context):
    """The control: a config the phase built is not replaced."""
    config = QuietConfig(enabled=True, options=QuietOptions(depth=9))

    converter = QuietConverter(context=test_plugin_context, config=config)

    assert converter.config is config
    assert converter.config.enabled is True


@pytest.fixture
def ash_records():
    """Every record the 'ash' logger emits at INFO or above during the test."""
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collector(level=logging.INFO)
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


#: Stands for a reason the config file read from the environment: the value,
#: which must reach neither the record nor the log when the written form cannot
#: be looked up.
EXPANDED_REASON = "ENVCANARY reviewed fixture"


def test_an_accepted_input_is_recorded_when_its_written_reason_cannot_be_read(
    test_plugin_context, monkeypatch, ash_records
):
    test_plugin_context.config.global_settings.suppressions = [
        AshSuppression(
            rule_id="ash-unconverted-input", path="a.zip", reason=EXPANDED_REASON
        )
    ]

    def _fails(config, recorded=None):
        raise RuntimeError("environment record unreadable")

    monkeypatch.setattr(suppression_matcher, "written_suppression_reasons", _fails)
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )

    converter.record_failed_input(
        Path(test_plugin_context.source_dir) / "a.zip", "it is damaged", kind="input"
    )

    (failed,) = converter.failed_inputs
    assert failed.path == "a.zip"
    assert failed.accepted is True
    # The record lands, and carries the fixed text, not the expanded reason.
    assert failed.accepted_reason == REASON_NOT_RENDERED
    assert "ENVCANARY" not in failed.accepted_reason
    shown = [record.getMessage() for record in ash_records]
    assert any("Could not convert 'a.zip'" in message for message in shown), shown
    assert not any("ENVCANARY" in message for message in shown), shown


def test_an_input_is_recorded_not_accepted_when_the_suppressions_cannot_be_read(
    test_plugin_context, monkeypatch, ash_records
):
    """The acceptance check reads the configured suppressions before the record is
    appended. An error raised there used to escape record_failed_input, so the
    input's record was lost; the jupyter loop then re-recorded the input as a
    gating tool failure. The record lands, not accepted (the side that keeps the
    completeness gate strict), and the error is named by its type only."""
    test_plugin_context.config.global_settings.suppressions = [
        AshSuppression(
            rule_id="ash-unconverted-input", path="a.zip", reason=EXPANDED_REASON
        )
    ]

    def _fails(display, suppressions):
        raise RuntimeError("ENVCANARY suppressions unreadable")

    monkeypatch.setattr(suppression_matcher, "accepting_unconverted_input", _fails)
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )

    converter.record_failed_input(
        Path(test_plugin_context.source_dir) / "a.zip", "it is damaged", kind="input"
    )

    (failed,) = converter.failed_inputs
    assert failed.path == "a.zip"
    assert failed.kind == "input"
    assert failed.accepted is False
    assert failed.accepted_reason is None
    shown = [record.getMessage() for record in ash_records]
    assert any("Could not convert 'a.zip'" in message for message in shown), shown
    assert not any("ENVCANARY" in message for message in shown), shown


def test_an_accepted_inputs_written_reason_is_recorded_when_it_can_be_read(
    test_plugin_context,
):
    """The control: with the record readable, the reason is the written one."""
    test_plugin_context.config.global_settings.suppressions = [
        AshSuppression(
            rule_id="ash-unconverted-input", path="a.zip", reason="reviewed fixture"
        )
    ]
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )

    converter.record_failed_input(
        Path(test_plugin_context.source_dir) / "a.zip", "it is damaged", kind="input"
    )

    (failed,) = converter.failed_inputs
    assert failed.accepted is True
    assert failed.accepted_reason == "reviewed fixture"
