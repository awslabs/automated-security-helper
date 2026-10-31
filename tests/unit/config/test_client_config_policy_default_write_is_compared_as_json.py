# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A delivered file writes a plugin option's default only if the JSON value is the default.

``_writes_plugin_default`` forgives a denied plugin option that a delivered
file sets to the option's default, where the trusted config has no value of its
own. It compared with Python ``==``, which says ``True == 1``, ``False == 0``
and ``0 == False``, so a file that wrote ``enable_preprocessors: 1`` (default
``true``), ``offline: 0`` (default ``false``) or ``finding_limit: false``
(default ``0``) was forgiven as if it had written the default. The comparison
is by JSON value, the way ``config_document_denials`` compares a changed value.
"""

from __future__ import annotations

import datetime
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from automated_security_helper.config import client_config_policy as ccp

pytestmark = pytest.mark.unit


def _writes(scanner: str, option: str, value: Any) -> bool:
    base = SimpleNamespace(get_plugin_config=lambda _kind, _name: {})
    document = {"scanners": {scanner: {"options": {option: value}}}}
    denial = SimpleNamespace(
        pointer=f"/scanners/{scanner}/options/{option}", from_patch=False
    )
    return ccp._writes_plugin_default(document, denial, base)


@pytest.mark.parametrize(
    ("scanner", "option", "value"),
    [
        ("ferret-scan", "enable_preprocessors", 1),
        ("ferret-scan", "offline", 0),
        ("ferret-scan", "finding_limit", False),
        ("ferret-scan", "finding_limit", 0.0),
        ("ferret-scan", "use_default_config", 1),
    ],
)
def test_a_value_equal_to_the_default_only_in_python_is_not_the_default(
    scanner: str, option: str, value: Any
) -> None:
    assert _writes(scanner, option, value) is False


@pytest.mark.parametrize(
    ("scanner", "option", "value"),
    [
        ("ferret-scan", "enable_preprocessors", True),
        ("ferret-scan", "offline", False),
        ("ferret-scan", "finding_limit", 0),
        ("ferret-scan", "checks", "all"),
        ("ferret-scan", "config_file", None),
    ],
)
def test_control_the_exact_default_is_still_forgiven(
    scanner: str, option: str, value: Any
) -> None:
    assert _writes(scanner, option, value) is True


def test_control_a_different_value_is_not_forgiven() -> None:
    assert _writes("ferret-scan", "enable_preprocessors", False) is False


def test_a_value_that_is_not_json_is_not_the_default_and_does_not_raise() -> None:
    # A YAML date is data the loader can hand over; it is not any default.
    assert _writes("ferret-scan", "config_file", datetime.date(2026, 1, 1)) is False


def test_a_value_nested_too_deep_is_not_the_default_and_does_not_raise() -> None:
    deep: Any = []
    for _ in range(10 * sys.getrecursionlimit()):
        deep = [deep]
    assert _writes("ferret-scan", "config_file", deep) is False
