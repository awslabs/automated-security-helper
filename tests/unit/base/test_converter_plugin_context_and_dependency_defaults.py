# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two defaults of ConverterPluginBase that a converter outside this repository
meets first.

A converter built with no context raised AttributeError from model_post_init,
which reads the context's work directory, before the after-validator that
names the problem (ScannerError, "No context provided") could run: pydantic
runs model_post_init inside the model's own schema and the after-validators
around it. The post-init step now checks the context first and raises the same
ScannerError.

The base validate_plugin_dependencies answered True whatever the converter had
recorded in ``dependencies_satisfied`` and ``dependency_unavailable_reason``,
and ConvertPhase assigns that answer back to the field, so a converter that
declared its tool missing was run anyway. The default now answers from the
converter's own record.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Literal

import pytest

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.core.exceptions import ScannerError

pytestmark = pytest.mark.unit


class PlainConfig(ConverterPluginConfigBase):
    name: Literal["plain"] = "plain"


class PlainConverter(ConverterPluginBase[PlainConfig]):
    """A converter that declares nothing about its dependencies."""

    def convert(self) -> List[Path]:
        return []


class ToolNeedingConverter(ConverterPluginBase[PlainConfig]):
    """A converter that declares, as field defaults, that its tool is missing and
    why, and leaves the base dependency check in place."""

    dependencies_satisfied: bool = False
    dependency_unavailable_reason: str | None = "frobnicate is not installed"

    def convert(self) -> List[Path]:
        return []


def test_a_converter_built_without_a_context_raises_the_named_error():
    with pytest.raises(ScannerError, match="No context provided for PlainConverter"):
        PlainConverter()


def test_the_default_dependency_check_answers_the_converters_own_record(
    test_plugin_context,
):
    converter = ToolNeedingConverter(context=test_plugin_context)

    assert converter.validate_plugin_dependencies() is False
    assert converter.dependency_unavailable_reason == "frobnicate is not installed"


def test_the_default_dependency_check_is_true_where_nothing_is_declared(
    test_plugin_context,
):
    """The control: a converter that declares nothing is ready, as before."""
    converter = PlainConverter(context=test_plugin_context)

    assert converter.validate_plugin_dependencies() is True
