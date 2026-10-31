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


#: Falsy and not text: what a section can hold that is neither unset nor blank.
FALSY_NOT_TEXT = [0, 0.0, False, [], {}]


@pytest.mark.parametrize("value", FALSY_NOT_TEXT, ids=repr)
def test_a_falsy_threshold_that_is_not_text_gates_like_critical(ash_log, value):
    """Only None and empty text turn the gate off. Tested for truth, a falsy
    value that is not text did too, though the rule is that a value that is not
    text gates like any other unrecognised one."""
    assert severity_fails_threshold("CRITICAL", value) is True
    assert severity_fails_threshold("HIGH", value) is False

    warnings = [r.getMessage() for r in ash_log.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert "not shown: not text" in warnings[0]


@pytest.mark.parametrize("value", [None, ""], ids=repr)
def test_no_threshold_still_turns_the_gate_off(ash_log, value):
    """The control: unset and empty are the two values that mean no gate."""
    assert severity_fails_threshold("CRITICAL", value) is False
    assert not [r for r in ash_log.records if r.levelname == "WARNING"]


def test_the_sarif_level_gate_does_not_turn_off_for_a_falsy_value_either(ash_log):
    from automated_security_helper.utils.severity_ladder import (
        sarif_level_fails_threshold,
    )

    sarif_level_fails_threshold("error", 0)

    warnings = [r.getMessage() for r in ash_log.records if r.levelname == "WARNING"]
    assert len(warnings) == 1


@pytest.fixture
def dropped_log(ash_log, monkeypatch):
    monkeypatch.setattr(severity_ladder, "_WARNED_DROPPED_SCANNER", set())
    return ash_log


@pytest.mark.parametrize("value", [0, False, [], 5, True, ["HIGH"]], ids=repr)
def test_dropping_a_scanner_threshold_that_is_not_text_is_logged_once(
    dropped_log, value
):
    config = SimpleNamespace(global_settings=SimpleNamespace(severity_threshold="LOW"))

    assert resolve_scanner_threshold(value, config) == ("LOW", "global")
    assert resolve_scanner_threshold(value, config) == ("LOW", "global")

    warnings = [r.getMessage() for r in dropped_log.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    shown = f"a value of type {type(value).__name__} (not shown: not text)"
    assert shown in warnings[0]
    assert "global" in warnings[0]


@pytest.mark.parametrize("value", [None, "", "high", "bogus"], ids=repr)
def test_a_scanner_threshold_that_is_unset_or_text_logs_no_drop(dropped_log, value):
    config = SimpleNamespace(global_settings=SimpleNamespace(severity_threshold="LOW"))

    resolve_scanner_threshold(value, config)

    assert not [r for r in dropped_log.records if r.levelname == "WARNING"]


class _PlainObject:
    """A value that is neither text nor a number nor a container.

    Stands for any object a caller can hand over as a threshold: a test double,
    a configuration node read without validation. It is a plain class, not a
    mock, so the tests below pin what the ladder does with a value that is not
    text, and do not depend on how a mock library answers attribute lookups.
    """


ALL_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def test_a_plain_object_threshold_gates_like_critical_without_raising(ash_log):
    """Every severity bucket is asked about, as the statistics calculator does
    for a scanner whatever its counts; none of them may raise."""
    value = _PlainObject()

    failing = [s for s in ALL_SEVERITIES if severity_fails_threshold(s, value)]

    assert failing == ["CRITICAL"]


def test_the_warning_for_a_plain_object_threshold_is_one_line_naming_its_class(
    ash_log,
):
    severity_fails_threshold("HIGH", _PlainObject())

    warnings = [r.getMessage() for r in ash_log.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert warnings[0].startswith("Severity threshold ")
    assert "_PlainObject" in warnings[0]


def test_the_log_form_of_a_plain_object_threshold_is_text_naming_its_class():
    shown = severity_ladder._threshold_for_log(_PlainObject())

    assert isinstance(shown, str)
    assert "_PlainObject" in shown


def test_a_plain_object_scanner_threshold_falls_through_to_the_global_one():
    """Returned as given, the object was truthy and reached the gate as the
    scanner's own threshold."""
    config = SimpleNamespace(
        global_settings=SimpleNamespace(severity_threshold="MEDIUM")
    )

    assert resolve_scanner_threshold(_PlainObject(), config) == ("MEDIUM", "global")


def test_the_log_form_of_a_text_threshold_is_unchanged():
    """A ladder-shaped word is quoted; any other text is described by length."""
    free_text = "not a ladder word, free text"

    assert severity_ladder._threshold_for_log("hgih") == "'hgih'"
    assert severity_ladder._threshold_for_log(free_text) == (
        f"a {len(free_text)}-character value (not shown: not a ladder-shaped word)"
    )
