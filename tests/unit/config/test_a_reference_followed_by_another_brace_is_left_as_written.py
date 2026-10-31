# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reference followed by another closing brace is left as written, defaulted or not.

A configuration value holds one ``${VAR}`` or ``${VAR:default}`` reference, at
its start. ``${A}/${B}`` was always left as written. ``${A:x}/${B}`` was not:
before this program the pattern read the default up to the LAST brace, so A's
value replaced the whole string when it was set and the garbled ``x}/${B``
became the default when it was not; the first cut of the fix then read the
default up to the first brace and resolved A while keeping ``/${B}`` as a
literal in the middle of the value, where a typed field accepts it, so the two
spellings read differently. Both are now the composite case: left exactly as
written, with a warning that says why, and nothing read from the environment.

Red at the base: ``resolve_env_references("${ASH_U35_A:x}/${OTHER}")`` returned
``value/${OTHER}`` with the variable set and ``x/${OTHER}`` with it unset.
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.config.ash_config import resolve_env_references

pytestmark = pytest.mark.unit

COMPOSITES = ["${ASH_U35_A:x}/${OTHER}", "${ASH_U35_A:}/${OTHER}", "${ASH_U35_A:x}${B}"]


@pytest.mark.parametrize("written", COMPOSITES)
def test_left_as_written_when_the_variable_is_set(
    monkeypatch: pytest.MonkeyPatch, written: str
) -> None:
    monkeypatch.setenv("ASH_U35_A", "value")

    assert resolve_env_references(written) == written


@pytest.mark.parametrize("written", COMPOSITES)
def test_left_as_written_when_the_variable_is_unset(
    monkeypatch: pytest.MonkeyPatch, written: str
) -> None:
    monkeypatch.delenv("ASH_U35_A", raising=False)

    assert resolve_env_references(written) == written


def test_the_value_says_why_it_was_left(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    canary = "qz-composite-canary-9921"
    monkeypatch.setenv("ASH_U35_A", canary)

    with caplog.at_level(logging.WARNING, logger="ash"):
        resolve_env_references("${ASH_U35_A:x}/${OTHER}")

    messages = [record.getMessage() for record in caplog.records]
    assert any(
        "${ASH_U35_A:x}" in message and "left as written" in message
        for message in messages
    ), messages
    assert all(canary not in message for message in messages), messages


def test_a_composite_without_a_default_is_still_left_as_written(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: the no-default composite kept its rule."""
    monkeypatch.setenv("ASH_U35_A", "value")

    assert resolve_env_references("${ASH_U35_A}/${OTHER}") == "${ASH_U35_A}/${OTHER}"
    assert resolve_env_references("${ASH_U35_A}x}") == "${ASH_U35_A}x}"


def test_a_reference_with_trailing_text_and_no_brace_still_resolves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: text after the reference that holds no brace resolved
    before and resolves now, defaulted or not."""
    monkeypatch.setenv("ASH_U35_A", "value")

    assert str(resolve_env_references("${ASH_U35_A}/suffix")) == "value/suffix"
    assert str(resolve_env_references("${ASH_U35_A:x}/suffix")) == "value/suffix"
    assert str(resolve_env_references("${ASH_U35_A:x}")) == "value"
    monkeypatch.delenv("ASH_U35_A", raising=False)
    assert str(resolve_env_references("${ASH_U35_A:x}/suffix")) == "x/suffix"
