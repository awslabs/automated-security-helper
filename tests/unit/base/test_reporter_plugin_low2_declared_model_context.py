# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reporter's config is validated by its declared model under the field's context.

``ReporterPluginBase`` validates ``config`` with a wrap validator that hands a value
which is not the reporter's own model to that model. The validator used to call
``config_validated_by_declared_model`` without the ``ValidationInfo`` it was given,
so a validation context the caller passed to ``model_validate`` never reached the
declared model's own validators. The model sees it now.
"""

from __future__ import annotations

from typing import Literal

import pytest
from pydantic import model_validator

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit

PROBE = {"declared_model_probe": True}


class _Config(ReporterPluginConfigBase):
    name: Literal["context-probe"] = "context-probe"
    extension: str = "probe.txt"
    saw_context: bool = False

    @model_validator(mode="before")
    @classmethod
    def _read_the_context(cls, data, info):
        if isinstance(data, dict) and (info.context or {}).get("declared_model_probe"):
            return {**data, "saw_context": True}
        return data


class _Reporter(ReporterPluginBase[_Config]):
    def report(self, model) -> str:
        return ""


@pytest.fixture
def context(tmp_path):
    return PluginContext(
        source_dir=tmp_path / "src", output_dir=tmp_path / "out", config=AshConfig()
    )


def test_the_declared_model_sees_the_context_the_reporter_was_validated_under(
    context,
):
    built = _Reporter.model_validate(
        {"context": context, "config": {"enabled": False}}, context=PROBE
    )

    assert type(built.config) is _Config
    assert built.config.enabled is False
    assert built.config.saw_context is True


def test_without_a_context_the_declared_model_sees_none(context):
    built = _Reporter.model_validate({"context": context, "config": {"enabled": False}})

    assert type(built.config) is _Config
    assert built.config.saw_context is False
