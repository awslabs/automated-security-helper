# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reporter built with no config section carries its declared model's defaults.

``ReporterPluginBase`` left ``config`` None when no section existed, so a
reporter's declared ``enabled`` default, its name and its extension were
ignored: the enabled filter was skipped, the report was written under the
base's "ash.txt", and the reporter could not be selected by name. The declared
model's defaults are the configuration a reporter with no section runs on; a
reporter that declares no model keeps None.
"""

from __future__ import annotations

from typing import Literal

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit


class _OwnConfig(ReporterPluginConfigBase):
    name: Literal["own-planted"] = "own-planted"
    extension: str = "own.planted.txt"
    enabled: bool = False


class _OwnReporter(ReporterPluginBase[_OwnConfig]):
    def report(self, model) -> str:
        return ""


class _UndeclaredReporter(ReporterPluginBase):
    def report(self, model) -> str:
        return ""


@pytest.fixture
def context(tmp_path):
    return PluginContext(
        source_dir=tmp_path / "src", output_dir=tmp_path / "out", config=AshConfig()
    )


def test_a_declared_model_supplies_the_defaults(context):
    reporter = _OwnReporter(context=context)

    assert isinstance(reporter.config, _OwnConfig), reporter.config
    assert reporter.config.name == "own-planted"
    assert reporter.config.extension == "own.planted.txt"
    assert reporter.config.enabled is False


def test_a_given_section_is_kept(context):
    reporter = _OwnReporter(context=context, config={"enabled": True})

    assert isinstance(reporter.config, _OwnConfig)
    assert reporter.config.enabled is True


def test_a_reporter_with_no_declared_model_keeps_none(context):
    assert _UndeclaredReporter(context=context).config is None
