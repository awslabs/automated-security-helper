# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An off-host reporter section whose ``enabled`` is not a bool is named.

``off_host_reporter_refused`` admits only the boolean true, so a section that
sets ``enabled`` to the string "true", to 1 or to "yes" leaves the reporter off.
``warn_off_host_section_without_enabled`` stayed silent for any section that had
an ``enabled`` key, so ``ash merge`` and the workspace report step dropped a
reporter the operator had tried to turn on with no message. The warning names
the reporter and the value's type, never the value.
"""

from __future__ import annotations

import logging
from typing import ClassVar, Literal

import pytest

from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    reset_unenabled_off_host_section_warnings,
    warn_off_host_section_without_enabled,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit


class _OffHostConfig(ReporterPluginConfigBase):
    name: Literal["offhost-planted"] = "offhost-planted"


class _OffHostReporter(ReporterPluginBase[_OffHostConfig]):
    sends_off_host: ClassVar[bool] = True

    def report(self, model) -> str:
        return ""


@pytest.fixture
def warnings():
    lines: list[str] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            if record.levelno >= logging.WARNING:
                lines.append(record.getMessage())

    handler = _Collect(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    reset_unenabled_off_host_section_warnings()
    try:
        yield lines
    finally:
        ASH_LOGGER.removeHandler(handler)
        reset_unenabled_off_host_section_warnings()


@pytest.mark.parametrize(
    ("value", "kind"),
    [("true", "a str"), (1, "an int"), ("yes-planted-value", "a str"), (None, "null")],
    ids=["str", "int", "yes", "null"],
)
def test_a_non_boolean_enabled_is_named_once(warnings, value, kind):
    warn_off_host_section_without_enabled(_OffHostReporter, {"enabled": value})
    warn_off_host_section_without_enabled(_OffHostReporter, {"enabled": value})

    named = [line for line in warnings if "offhost-planted" in line]
    assert len(named) == 1, warnings
    assert "only the boolean true" in named[0], named[0]
    assert f"sets enabled to {kind}" in named[0], named[0]
    # The type is named, never the value.
    assert "yes-planted-value" not in named[0], named[0]


def test_a_missing_enabled_does_not_hide_a_later_non_boolean_one(warnings):
    """One warning per (reporter, cause): the second problem is not swallowed."""
    warn_off_host_section_without_enabled(
        _OffHostReporter, {"bucket": "planted-bucket-name"}
    )
    warn_off_host_section_without_enabled(_OffHostReporter, {"enabled": "true"})

    named = [line for line in warnings if "offhost-planted" in line]
    assert len(named) == 2, warnings
    assert "sets options but not 'enabled'" in named[0], named[0]
    assert "sets enabled to a str" in named[1], named[1]
    assert "planted-bucket-name" not in " ".join(named), named


def test_a_boolean_enabled_is_not_named(warnings):
    warn_off_host_section_without_enabled(_OffHostReporter, {"enabled": False})
    warn_off_host_section_without_enabled(_OffHostReporter, {"enabled": True})

    assert not [line for line in warnings if "offhost-planted" in line], warnings
