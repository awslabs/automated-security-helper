# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A delivered file narrows a confined option only with a value that is the narrowing one.

``_writes_a_tightening`` forgives a denied scanner option that a delivered file
sets to one of the values ``tool_config_trust.TIGHTENING_VALUES`` lists for it
(``disable_telemetry: true``, ``metrics: off``). It tested ``value in values``,
and ``in`` on a tuple compares with Python ``==``: ``1 == True``, ``1.0 == True``,
``False == 0`` and ``0.0 == 0``. A file that wrote ``disable_telemetry: 1`` was
forgiven as ``true``. The membership is read through the JSON comparison the
function beside it uses for plugin defaults.
"""

from __future__ import annotations

import datetime
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from automated_security_helper.config import client_config_policy as ccp
from automated_security_helper.config import tool_config_trust

pytestmark = pytest.mark.unit


def _tightens(scanner: str, option: str, value: Any) -> bool:
    document = {"scanners": {scanner: {"options": {option: value}}}}
    denial = SimpleNamespace(
        pointer=f"/scanners/{scanner}/options/{option}", from_patch=False
    )
    return ccp._writes_a_tightening(document, denial)


@pytest.mark.parametrize("scanner", ["trivy-repo", "trivy"])
@pytest.mark.parametrize("value", [1, 1.0])
def test_a_number_that_equals_true_only_in_python_is_not_the_tightening(
    scanner: str, value: Any
) -> None:
    assert _tightens(scanner, "disable_telemetry", value) is False


@pytest.mark.parametrize("scanner", ["trivy-repo", "trivy"])
def test_control_true_is_still_the_tightening(scanner: str) -> None:
    assert _tightens(scanner, "disable_telemetry", True) is True


@pytest.mark.parametrize("scanner", ["trivy-repo", "trivy"])
def test_control_false_is_not_the_tightening(scanner: str) -> None:
    assert _tightens(scanner, "disable_telemetry", False) is False


@pytest.mark.parametrize("scanner", ["opengrep", "semgrep"])
def test_control_the_metrics_word_is_still_the_tightening(scanner: str) -> None:
    assert _tightens(scanner, "metrics", "off") is True
    assert _tightens(scanner, "metrics", "on") is False


def test_a_value_that_is_not_json_is_not_a_tightening_and_does_not_raise() -> None:
    # A YAML date is data the loader can hand over; it matches no listed value.
    assert _tightens("opengrep", "metrics", datetime.date(2026, 1, 1)) is False


def test_a_value_nested_too_deep_is_not_a_tightening_and_does_not_raise() -> None:
    deep: Any = []
    for _ in range(10 * sys.getrecursionlimit()):
        deep = [deep]
    assert _tightens("opengrep", "metrics", deep) is False


def test_the_reading_holds_for_zero_and_false_listed_values(monkeypatch) -> None:
    # No shipped entry lists a number, so list one: the comparison is by JSON
    # value whichever value the table holds.
    monkeypatch.setattr(
        tool_config_trust,
        "TIGHTENING_VALUES",
        {("opengrep", "metrics"): (0,), ("semgrep", "metrics"): (False,)},
    )
    assert _tightens("opengrep", "metrics", 0) is True
    assert _tightens("opengrep", "metrics", False) is False
    assert _tightens("opengrep", "metrics", 0.0) is False
    assert _tightens("semgrep", "metrics", False) is True
    assert _tightens("semgrep", "metrics", 0) is False
