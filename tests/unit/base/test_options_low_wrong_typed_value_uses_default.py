# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value of the wrong type is replaced by the option's default, with a warning.

``release_tag``, ``tool_version_constraint`` and ``report_file_name`` say that
anything they refuse is replaced by the option's default with one warning. They
called the field's own validation first, so a YAML number (``tool_version: 1.7``)
raised a ValidationError from the field's ``str`` check and never reached the
refusal that falls back to the default.
"""

from __future__ import annotations

import logging
from typing import Annotated, List

import pytest
from pydantic import BaseModel

from automated_security_helper.base.options import (
    release_tag,
    report_file_name,
    reset_refused_tool_version_warnings,
    tool_version_constraint,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit


class _Options(BaseModel):
    tool_version: Annotated[
        str | None, tool_version_constraint("scanners.probe.options.tool_version")
    ] = ">=1.0"
    version: Annotated[str, release_tag("scanners.probe.options.version")] = "v1.0.0"
    output_file: Annotated[
        str, report_file_name("reporters.probe.options.output_file")
    ] = "probe.md"


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_refused_tool_version_warnings()
    yield
    reset_refused_tool_version_warnings()


@pytest.fixture
def ash_log():
    """Capture ASH_LOGGER records; it does not propagate, so caplog sees nothing."""
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.DEBUG)
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous_level)


def _warnings(records) -> List[str]:
    return [r.getMessage() for r in records if r.levelno == logging.WARNING]


@pytest.mark.parametrize("wrong", [1.7, 12, ["v1"], {"a": 1}], ids=repr)
@pytest.mark.parametrize("field", ["tool_version", "version", "output_file"])
def test_a_value_of_the_wrong_type_is_replaced_by_the_default(field, wrong, ash_log):
    options = _Options(**{field: wrong})

    assert getattr(options, field) == getattr(_Options(), field)
    messages = [m for m in _warnings(ash_log) if f"options.{field}" in m]
    assert len(messages) == 1, messages


def test_the_same_wrong_value_is_warned_about_once(ash_log):
    _Options(tool_version=1.7)
    _Options(tool_version=1.7)

    messages = [m for m in _warnings(ash_log) if "options.tool_version" in m]
    assert len(messages) == 1, messages


def test_a_value_of_the_right_type_passes_through_unwarned(ash_log):
    options = _Options(
        tool_version="==2.0.1", version="v2.3.4", output_file="summary.md"
    )

    assert options.tool_version == "==2.0.1"
    assert options.version == "v2.3.4"
    assert options.output_file == "summary.md"
    assert _warnings(ash_log) == []


def test_none_is_still_accepted_for_an_optional_tool_version(ash_log):
    assert _Options(tool_version=None).tool_version is None
    assert _warnings(ash_log) == []
