# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reporter's config is validated by its declared model under the field's context.

``ReporterPluginBase`` validates ``config`` with a wrap validator that hands a value
which is not the reporter's own model to that model. The validator used to call
``config_validated_by_declared_model`` without the ``ValidationInfo`` it was given,
so a validation context the field was validated under never reached the declared
model's own validators. The model sees it now.

The tests call the validator with a stand-in ``ValidationInfo``. They do not go
through ``model_validate``: ``PluginBase`` has its own ``__init__``, which pydantic
routes ``model_validate`` through, and that ``__init__`` passes no context on, so a
context given to ``model_validate`` does not reach any plugin's ``config`` field
whatever this validator does.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Literal

import pytest
from pydantic import model_validator

from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)

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


def _validated(context):
    """The wrap validator on ``config``, given a section and a context.

    The handler is never reached for a section that is not the declared model.
    """

    def handler(value):
        raise AssertionError("a section is validated by the declared model")

    return _Reporter._config_is_validated_by_the_declared_model(
        {"enabled": False}, handler, SimpleNamespace(context=context)
    )


def test_the_declared_model_sees_the_context_the_reporter_was_validated_under():
    built = _validated(PROBE)

    assert type(built) is _Config
    assert built.enabled is False
    assert built.saw_context is True


def test_without_a_context_the_declared_model_sees_none():
    built = _validated(None)

    assert type(built) is _Config
    assert built.saw_context is False
