# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A threshold that is not text neither raises nor turns the gate off.

A scanner section read from an external plugin is never validated, so its
``severity_threshold`` can be a number, a boolean (YAML reads an unquoted ``on``
as ``True``) or a list. The off-table warning matched the value against a
text-only pattern, so a number or a boolean raised ``TypeError`` out of the gate,
and a list raised it from the table lookup. ``resolve_scanner_threshold`` returned
a falsy one (``0``, ``False``, an empty list) as given, and a falsy threshold
turns the gate off for that scanner.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import severity_ladder
from automated_security_helper.utils.severity_ladder import (
    resolve_scanner_threshold,
    severity_fails_threshold,
)

pytestmark = pytest.mark.unit

NOT_TEXT = [5, True, ["HIGH"], {"level": "HIGH"}]


@pytest.fixture
def ash_log(monkeypatch, caplog):
    logger = logging.getLogger("test-severity-ladder-non-text")
    logger.propagate = True
    monkeypatch.setattr(severity_ladder, "_ash_logger", lambda: logger)
    monkeypatch.setattr(severity_ladder, "_WARNED_OFF_TABLE", set())
    caplog.set_level(logging.WARNING, logger=logger.name)
    return caplog


@pytest.mark.parametrize("value", NOT_TEXT, ids=lambda value: type(value).__name__)
def test_a_threshold_that_is_not_text_gates_like_critical(ash_log, value):
    """The gate before the off-table warning existed: an unrecognised value
    fails critical findings only. It raised TypeError instead."""
    assert severity_fails_threshold("CRITICAL", value) is True
    assert severity_fails_threshold("HIGH", value) is False


@pytest.mark.parametrize("value", NOT_TEXT, ids=lambda value: type(value).__name__)
def test_the_warning_for_a_value_that_is_not_text_names_its_type_only(ash_log, value):
    severity_fails_threshold("HIGH", value)
    severity_fails_threshold("HIGH", value)

    warnings = [r.getMessage() for r in ash_log.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert warnings[0].startswith(
        f"Severity threshold a value of type {type(value).__name__} "
        "(not shown: not text) is not one of ALL, LOW, MEDIUM, HIGH, CRITICAL"
    )


@pytest.mark.parametrize("value", [0, False, [], 5, True, ["HIGH"]], ids=repr)
def test_a_scanner_threshold_that_is_not_text_falls_through_to_the_global_one(value):
    """Returned as given, 0, False and [] were falsy and turned the gate off for
    the scanner; the resolver's promise is that it never returns such a value."""
    config = SimpleNamespace(global_settings=SimpleNamespace(severity_threshold="LOW"))

    assert resolve_scanner_threshold(value, config) == ("LOW", "global")


def test_a_scanner_threshold_that_is_text_is_still_returned_as_given():
    config = SimpleNamespace(global_settings=SimpleNamespace(severity_threshold="LOW"))

    assert resolve_scanner_threshold("bogus", config) == ("bogus", "config")
    assert resolve_scanner_threshold("high", config) == ("HIGH", "config")
