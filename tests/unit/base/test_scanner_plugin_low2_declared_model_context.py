# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner's config is validated by its declared model under the field's context.

``ScannerPluginBase`` validates ``config`` with a wrap validator that hands a value
which is not the scanner's own model to that model. The validator used to call
``config_validated_by_declared_model`` without the ``ValidationInfo`` it was given,
so a validation context the caller passed to ``model_validate`` (the stored-config
tolerance of a results file is one) never reached the declared model's own
validators. The model sees it now.
"""

from __future__ import annotations

import pytest
from pydantic import model_validator

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

PROBE = {"declared_model_probe": True}


class _Config(ScannerPluginConfigBase):
    name: str = "context-probe"
    saw_context: bool = False

    @model_validator(mode="before")
    @classmethod
    def _read_the_context(cls, data, info):
        if isinstance(data, dict) and (info.context or {}).get("declared_model_probe"):
            return {**data, "saw_context": True}
        return data


class _Scanner(ScannerPluginBase[_Config]):
    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("the config is all this test builds")


def _context(tmp_path) -> PluginContext:
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="test"),
    )


def test_the_declared_model_sees_the_context_the_scanner_was_validated_under(tmp_path):
    built = _Scanner.model_validate(
        {"context": _context(tmp_path), "config": {"enabled": False}}, context=PROBE
    )

    assert type(built.config) is _Config
    assert built.config.enabled is False
    assert built.config.saw_context is True


def test_without_a_context_the_declared_model_sees_none(tmp_path):
    built = _Scanner.model_validate(
        {"context": _context(tmp_path), "config": {"enabled": False}}
    )

    assert type(built.config) is _Config
    assert built.config.saw_context is False
