# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A confined scanner option keeps a file's value only if it is a listed tightening value.

``confine_scanner_config_files`` lets a repository's or client's config keep a
value of a confined option that only narrows what the tool does
(``TIGHTENING_VALUES``: ``disable_telemetry: true``, ``metrics: off``). It
tested ``current in TIGHTENING_VALUES[...]``, which is Python equality, so
``disable_telemetry: 1`` and ``1.0`` passed as the listed ``true``.
``is_tightening_value`` reads the listed values as JSON, the way
``client_config_policy._writes_a_tightening`` now does.
"""

from __future__ import annotations

import datetime
import sys
from typing import Any

import pytest

from automated_security_helper.config import tool_config_trust
from automated_security_helper.config.tool_config_trust import is_tightening_value

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("scanner", ["trivy-repo", "trivy"])
@pytest.mark.parametrize("value", [1, 1.0])
def test_a_number_that_equals_true_only_in_python_is_not_the_tightening(
    scanner: str, value: Any
) -> None:
    assert is_tightening_value(scanner, "disable_telemetry", value) is False


@pytest.mark.parametrize("scanner", ["trivy-repo", "trivy"])
def test_control_true_is_the_tightening_and_false_is_not(scanner: str) -> None:
    assert is_tightening_value(scanner, "disable_telemetry", True) is True
    assert is_tightening_value(scanner, "disable_telemetry", False) is False


@pytest.mark.parametrize("scanner", ["opengrep", "semgrep"])
def test_control_the_metrics_word_is_the_tightening(scanner: str) -> None:
    assert is_tightening_value(scanner, "metrics", "off") is True
    assert is_tightening_value(scanner, "metrics", "on") is False


def test_control_an_option_with_no_listed_value_is_never_a_tightening() -> None:
    assert is_tightening_value("trivy", "ignore_file", True) is False
    assert is_tightening_value("no-such-scanner", "metrics", "off") is False


def test_a_value_that_is_not_json_is_not_a_tightening_and_does_not_raise() -> None:
    assert (
        is_tightening_value("opengrep", "metrics", datetime.date(2026, 1, 1)) is False
    )


def test_a_value_nested_too_deep_is_not_a_tightening_and_does_not_raise() -> None:
    deep: Any = []
    for _ in range(10 * sys.getrecursionlimit()):
        deep = [deep]
    assert is_tightening_value("opengrep", "metrics", deep) is False


def test_the_reading_holds_for_zero_and_false_listed_values(monkeypatch) -> None:
    # No shipped entry lists a number, so list one: the comparison is by JSON
    # value whichever value the table holds.
    monkeypatch.setattr(
        tool_config_trust,
        "TIGHTENING_VALUES",
        {("opengrep", "metrics"): (0,), ("semgrep", "metrics"): (False,)},
    )
    assert is_tightening_value("opengrep", "metrics", 0) is True
    assert is_tightening_value("opengrep", "metrics", False) is False
    assert is_tightening_value("opengrep", "metrics", 0.0) is False
    assert is_tightening_value("semgrep", "metrics", False) is True
    assert is_tightening_value("semgrep", "metrics", 0) is False
