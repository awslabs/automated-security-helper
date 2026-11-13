# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A confined option's value is compared with the operator's as JSON, not as Python.

``confine_scanner_config_files`` and ``confine_tool_versions`` keep a file's
value only when it is the operator's, and name an option in the "Ignoring ..."
warning only when the file chose a value of its own. Both read the values with
Python equality, which says ``1 == True``, ``1.0 == True`` and ``0 == False``:
a plugin section that wrote ``1`` for the operator's ``true`` kept its number,
and a number that equalled the default in Python was not named when it was
replaced. The comparison now reads both sides as JSON, the way
``is_tightening_value`` does.
"""

from __future__ import annotations

import datetime
import logging
import sys
from pathlib import Path
from typing import Any, List

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.tool_config_trust import (
    _same_option_value,
    confine_scanner_config_files,
    confine_tool_versions,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

FERRET = "ferret-scan"
PLUGIN = "my-plugin-scanner"


@pytest.fixture
def ash_log():
    """ASH_LOGGER's records; it does not propagate, so caplog would see nothing."""
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
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


def _warnings_naming(records: List[logging.LogRecord], text: str) -> List[str]:
    return [
        r.getMessage()
        for r in records
        if r.levelno == logging.WARNING and text in r.getMessage()
    ]


def _plugin_config(scanner: str, options: dict) -> AshConfig:
    return AshConfig.model_validate({"scanners": {scanner: {"options": options}}})


def _options(config: AshConfig, scanner: str) -> Any:
    return (config.scanners.model_extra or {})[scanner]["options"]


#: ferret-scan is a plugin scanner, so its section is a plain dict that keeps
#: the number the file wrote. ``use_default_config`` defaults to true and
#: ``respect_gitignore`` to false.
SAME_IN_PYTHON_ONLY = [
    pytest.param("use_default_config", 1, True, id="one-for-true"),
    pytest.param("use_default_config", 1.0, True, id="one-point-zero-for-true"),
    pytest.param("respect_gitignore", 0, False, id="zero-for-false"),
    pytest.param("respect_gitignore", 0.0, False, id="zero-point-zero-for-false"),
]

EQUAL_TO_THE_DEFAULT_IN_PYTHON_ONLY = [
    pytest.param("use_default_config", 1, False, id="one-is-not-the-default-true"),
    pytest.param("respect_gitignore", 0, True, id="zero-is-not-the-default-false"),
]


@pytest.mark.parametrize(("option", "written", "chosen"), SAME_IN_PYTHON_ONLY)
def test_a_number_that_equals_the_operators_boolean_only_in_python_is_replaced(
    tmp_path: Path, option: str, written: Any, chosen: bool
) -> None:
    config = _plugin_config(FERRET, {option: written})
    trusted = _plugin_config(FERRET, {option: chosen})

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert _options(config, FERRET)[option] is chosen


@pytest.mark.parametrize(("option", "written", "chosen"), SAME_IN_PYTHON_ONLY)
def test_the_replaced_number_is_named_in_the_warning(
    tmp_path: Path, ash_log: List[logging.LogRecord], option: str, written, chosen
) -> None:
    config = _plugin_config(FERRET, {option: written})
    trusted = _plugin_config(FERRET, {option: chosen})

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert _warnings_naming(ash_log, f"scanners.{FERRET}.options.{option}")


@pytest.mark.parametrize(
    ("option", "written", "chosen"), EQUAL_TO_THE_DEFAULT_IN_PYTHON_ONLY
)
def test_a_number_that_equals_the_default_only_in_python_is_a_choice_and_is_named(
    tmp_path: Path,
    ash_log: List[logging.LogRecord],
    option: str,
    written: Any,
    chosen: bool,
) -> None:
    config = _plugin_config(FERRET, {option: written})
    trusted = _plugin_config(FERRET, {option: chosen})

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert _options(config, FERRET)[option] is chosen
    assert _warnings_naming(ash_log, f"scanners.{FERRET}.options.{option}")


def test_control_a_file_that_repeats_the_default_is_replaced_without_a_warning(
    tmp_path: Path, ash_log: List[logging.LogRecord]
) -> None:
    config = _plugin_config(FERRET, {"use_default_config": True})
    trusted = _plugin_config(FERRET, {"use_default_config": False})

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert _options(config, FERRET)["use_default_config"] is False
    assert not _warnings_naming(ash_log, "use_default_config")


def test_control_a_file_that_repeats_the_operators_value_is_left_alone(
    tmp_path: Path, ash_log: List[logging.LogRecord]
) -> None:
    config = _plugin_config(FERRET, {"use_default_config": False})
    trusted = _plugin_config(FERRET, {"use_default_config": False})

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert _options(config, FERRET)["use_default_config"] is False
    assert not _warnings_naming(ash_log, "use_default_config")


@pytest.mark.parametrize(("written", "chosen"), [(1, 1.0), (1.0, 1)])
def test_a_tool_version_that_equals_the_operators_only_in_python_is_replaced(
    tmp_path: Path, ash_log: List[logging.LogRecord], written: Any, chosen: Any
) -> None:
    """A YAML ``1`` and ``1.0`` are different texts once a plugin builds a constraint."""
    config = _plugin_config(PLUGIN, {"tool_version": written})
    trusted = _plugin_config(PLUGIN, {"tool_version": chosen})

    confine_tool_versions(config, trusted, [], [tmp_path / ".ash.yaml"])

    value = _options(config, PLUGIN)["tool_version"]
    assert value == chosen and type(value) is type(chosen)
    assert _warnings_naming(ash_log, f"scanners.{PLUGIN}.options.tool_version")


def test_control_a_tool_version_that_repeats_the_operators_is_left_alone(
    tmp_path: Path, ash_log: List[logging.LogRecord]
) -> None:
    config = _plugin_config(PLUGIN, {"tool_version": "==1.2.3"})
    trusted = _plugin_config(PLUGIN, {"tool_version": "==1.2.3"})

    confine_tool_versions(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert _options(config, PLUGIN)["tool_version"] == "==1.2.3"
    assert not _warnings_naming(ash_log, "tool_version")


@pytest.mark.parametrize(
    ("current", "expected"),
    [(1, True), (1.0, True), (0, False), (0.0, False), (1, 1.0), ([1], [True])],
)
def test_values_equal_only_in_python_are_not_the_same_option_value(
    current: Any, expected: Any
) -> None:
    assert (current == expected) is True
    assert _same_option_value(current, expected) is False


@pytest.mark.parametrize(
    ("current", "expected"),
    [
        (1, 1),
        (True, True),
        ("off", "off"),
        ([1, {"a": True}], [1, {"a": True}]),
        ({"b": 1, "a": 2}, {"a": 2, "b": 1}),
        (None, None),
    ],
)
def test_control_equal_json_values_are_the_same_option_value(
    current: Any, expected: Any
) -> None:
    assert _same_option_value(current, expected) is True


def test_a_value_that_is_not_json_is_compared_with_equality() -> None:
    """An options model holds a path, and a YAML date is not JSON data either."""
    assert _same_option_value(Path("a.yaml"), Path("a.yaml")) is True
    assert _same_option_value(Path("a.yaml"), Path("b.yaml")) is False
    assert _same_option_value(Path("a.yaml"), "a.yaml") is False
    day = datetime.date(2026, 1, 1)
    assert _same_option_value(day, datetime.date(2026, 1, 1)) is True
    assert _same_option_value(day, datetime.date(2026, 1, 2)) is False


def test_a_value_nested_too_deep_does_not_raise_and_is_never_a_match_for_none() -> None:
    def nested() -> Any:
        deep: Any = []
        for _ in range(10 * sys.getrecursionlimit()):
            deep = [deep]
        return deep

    # An encoder that stops at the interpreter's recursion limit (3.10, 3.12)
    # answers False for two equal deep values; one that follows them (3.14)
    # answers True. Either way the comparison returns a bool and never raises.
    assert _same_option_value(nested(), nested()) in (True, False)
    assert _same_option_value(nested(), None) is False
