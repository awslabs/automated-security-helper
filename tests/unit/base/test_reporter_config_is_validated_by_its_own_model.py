# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reporter that declares its own config model is configured by that model.

``ReporterPluginBase[XConfig]`` types ``config`` as ``XConfig``, the base
``ReporterPluginConfigBase``, or None. Given a dict ``XConfig`` refused, pydantic
built the base model from it instead and raised nothing, so every validator on
``XConfig`` and its options model was skipped without a word. A config of another
class was kept as it was, with the same effect.
"""

from __future__ import annotations

from typing import Annotated, Literal

import pytest
from pydantic import Field, ValidationError

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit


class _OwnOptions(ReporterOptionsBase):
    count: Annotated[int, Field(le=5)] = 1


class _OwnConfig(ReporterPluginConfigBase):
    name: Literal["own"] = "own"
    extension: str = "own.txt"
    options: _OwnOptions = _OwnOptions()


class _OwnReporter(ReporterPluginBase[_OwnConfig]):
    def report(self, model) -> str:
        return ""


@pytest.fixture
def context(tmp_path):
    return PluginContext(
        source_dir=tmp_path / "src", output_dir=tmp_path / "out", config=AshConfig()
    )


def test_a_section_its_own_model_refuses_is_a_validation_error(context):
    accepted = _OwnReporter(context=context, config={"options": {"count": 5}})
    assert type(accepted.config) is _OwnConfig
    assert accepted.config.options.count == 5

    with pytest.raises(ValidationError) as refused:
        _OwnReporter(context=context, config={"options": {"count": 6}})
    assert any(
        error["loc"] == ("config", "options", "count")
        for error in refused.value.errors()
    ), refused.value.errors()


def test_a_config_of_another_class_is_validated_by_its_own_model(context):
    own = _OwnConfig()
    assert _OwnReporter(context=context, config=own).config is own

    # Built without validation: the generic base refuses an option it does not
    # declare, so a base-class config carrying this reporter's options can only
    # exist unvalidated. The reporter still validates it by its own model.
    fitting = ReporterPluginConfigBase.model_construct(
        name="own", options=ReporterOptionsBase.model_construct(count=2)
    )
    rebuilt = _OwnReporter(context=context, config=fitting).config
    assert type(rebuilt) is _OwnConfig
    assert rebuilt.options.count == 2

    with pytest.raises(ValidationError):
        _OwnReporter(
            context=context,
            config=ReporterPluginConfigBase.model_construct(
                name="own", options=ReporterOptionsBase.model_construct(count=6)
            ),
        )
