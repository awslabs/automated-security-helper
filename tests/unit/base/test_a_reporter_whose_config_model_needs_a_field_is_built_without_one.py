# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reporter whose declared config model has a required field is built with no config.

``ReporterPluginBase.setup_paths`` gives a reporter built with no config section the
defaults its declared model states, by calling the model with no arguments. For a
model with a required field that call is a ``ValidationError``, raised inside an
after-validator, so a third-party reporter that used to be constructed with
``config=None`` failed to construct at all. The refusal is caught: the reporter keeps
``None``, as before the defaults were applied, and a debug line says why. The section
is still checked wherever one is given.
"""

from __future__ import annotations

from typing import Literal
from unittest.mock import patch

import pytest
from pydantic import Field

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME

pytestmark = pytest.mark.unit


class _NeedsAFieldConfig(ReporterPluginConfigBase):
    name: Literal["needs-a-field"] = "needs-a-field"
    extension: str = "needs.txt"
    endpoint: str


class _NeedsAField(ReporterPluginBase[_NeedsAFieldConfig]):
    def report(self, model) -> str:
        return ""


class _AllDefaultsConfig(ReporterPluginConfigBase):
    name: Literal["all-defaults"] = "all-defaults"
    extension: str = "defaults.txt"


class _AllDefaults(ReporterPluginBase[_AllDefaultsConfig]):
    def report(self, model) -> str:
        return ""


@pytest.fixture
def plugin_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


def test_a_model_with_a_required_field_is_built_with_no_config(plugin_context):
    reporter = _NeedsAField(context=plugin_context)

    assert reporter.config is None


def test_the_reason_is_said_at_debug_level(plugin_context):
    with patch("automated_security_helper.base.reporter_plugin.ASH_LOGGER") as log:
        _NeedsAField(context=plugin_context)

    said = " ".join(str(call.args[0]) for call in log.debug.call_args_list)
    assert "_NeedsAField" in said, said
    assert "required field" in said, said


def test_a_section_that_gives_the_field_is_still_held_to_the_model(plugin_context):
    reporter = _NeedsAField(
        context=plugin_context, config={"endpoint": "https://example.invalid"}
    )

    assert isinstance(reporter.config, _NeedsAFieldConfig)
    assert reporter.config.endpoint == "https://example.invalid"


def _reads_a_file_that_is_not_there() -> str:
    raise FileNotFoundError("/nonexistent/ASH-CANARY-1f3a/defaults.txt")


class _DefaultReadsAFileConfig(ReporterPluginConfigBase):
    name: Literal["default-reads-a-file"] = "default-reads-a-file"
    extension: str = "reads.txt"
    template: str = Field(default_factory=_reads_a_file_that_is_not_there)


class _DefaultReadsAFile(ReporterPluginBase[_DefaultReadsAFileConfig]):
    def report(self, model) -> str:
        return ""


def test_a_default_factory_that_raises_an_oserror_does_not_fail_construction(
    plugin_context,
):
    """Pydantic wraps only ValueError and AssertionError from a validator, so a
    default factory reading a file or the environment raised straight out of the
    reporter's constructor. Building a reporter with no section does not fail on
    it any more than on a required field."""
    reporter = _DefaultReadsAFile(context=plugin_context)

    assert reporter.config is None


def test_the_kind_is_said_at_debug_level_and_never_its_text(plugin_context):
    with patch("automated_security_helper.base.reporter_plugin.ASH_LOGGER") as log:
        _DefaultReadsAFile(context=plugin_context)

    said = " ".join(str(call.args[0]) for call in log.debug.call_args_list)
    assert "FileNotFoundError" in said, said
    assert "ASH-CANARY-1f3a" not in said, said


def test_a_model_with_only_defaults_still_gets_them(plugin_context):
    """The control: the defaults a declared model states are still applied."""
    reporter = _AllDefaults(context=plugin_context)

    assert isinstance(reporter.config, _AllDefaultsConfig)
    assert reporter.config.name == "all-defaults"
