# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The one rule for whether the operator's selection asks for a scanner."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.core.phases.scanner_selection import operator_selection

pytestmark = pytest.mark.unit


def _scanner(enabled=True, python_only=True):
    def is_python_only():
        if python_only is None:
            raise RuntimeError("plugin bug")
        return python_only

    return SimpleNamespace(
        config=SimpleNamespace(enabled=enabled), is_python_only=is_python_only
    )


@pytest.mark.parametrize(
    ("kwargs", "selected"),
    [
        ({}, True),
        ({"excluded_scanners": [" Bandit "]}, False),
        ({"enabled_scanners": ["semgrep"]}, False),
        ({"enabled_scanners": ["BANDIT"]}, True),
        ({"python_only": True}, True),
    ],
)
def test_the_filters_compare_names_without_case_or_spaces(kwargs, selected):
    assert operator_selection(_scanner(), "bandit", **kwargs).selected is selected


def test_a_disabled_scanner_is_not_selected():
    selection = operator_selection(_scanner(enabled=False), "bandit")

    assert not selection.enabled
    assert not selection.selected


def test_python_only_leaves_out_a_scanner_that_is_not():
    assert not operator_selection(
        _scanner(python_only=False), "grype", python_only=True
    ).selected
    assert operator_selection(_scanner(python_only=False), "grype").selected


def test_a_python_only_check_that_raises_counts_as_not_python_only():
    assert not operator_selection(
        _scanner(python_only=None), "custom", python_only=True
    ).selected
