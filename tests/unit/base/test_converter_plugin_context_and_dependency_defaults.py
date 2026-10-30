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

import logging
from contextlib import contextmanager
from pathlib import Path
from typing import List, Literal

import pytest

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.core.exceptions import ScannerError

pytestmark = pytest.mark.unit


@contextmanager
def _ash_records():
    """Every record the ash logger emits inside the block, at any level."""
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collector(level=1)
    logger = logging.getLogger("ash")
    level = logger.level
    logger.setLevel(1)
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)


class PlainConfig(ConverterPluginConfigBase):
    name: Literal["plain"] = "plain"


class SectionNeedingConfig(ConverterPluginConfigBase):
    """A model that cannot be built without a section: ValidationError."""

    name: Literal["needy"] = "needy"
    section: str


class BrokenDefaultConfig(ConverterPluginConfigBase):
    """A model whose computed default is a defect: it raises something else."""

    name: Literal["broken"] = "broken"

    def __init__(self, **data):
        raise TypeError("a computed default went wrong")


class SectionNeedingConverter(ConverterPluginBase[SectionNeedingConfig]):
    def convert(self) -> List[Path]:
        return []


class BrokenDefaultConverter(ConverterPluginBase[BrokenDefaultConfig]):
    def convert(self) -> List[Path]:
        return []


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


def _default_config_records(converter_type, context):
    with _ash_records() as records:
        converter = converter_type(context=context)
    assert type(converter.config) is ConverterPluginConfigBase
    return [r for r in records if "cannot be built without a section" in r.getMessage()]


def test_a_default_that_raises_something_other_than_validation_is_a_warning(
    test_plugin_context,
):
    (record,) = _default_config_records(BrokenDefaultConverter, test_plugin_context)

    assert record.levelno == logging.WARNING
    assert "BrokenDefaultConverter" in record.getMessage()
    assert "BrokenDefaultConfig" in record.getMessage()
    assert "(TypeError)" in record.getMessage()


def test_a_model_that_needs_a_section_is_still_told_at_debug(test_plugin_context):
    """The control: the expected shape keeps its level."""
    (record,) = _default_config_records(SectionNeedingConverter, test_plugin_context)

    assert record.levelno == logging.DEBUG
    assert "1 error(s)" in record.getMessage()
