# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``${VAR:default}`` reference ends at the first closing brace.

``ENV_REFERENCE_PATTERN`` read the default greedily, up to the LAST brace in the
scalar. With the variable set, ``${A:x}/${B}`` resolved to the value alone and
everything after the first brace was dropped; with it unset, the default was the
garbled text ``x}/${B``. The pattern now reads the default up to the first
brace, and the text after the match is kept, as it is for ``${VAR}`` followed by
text. The composite ``${A}/${B}`` with no default is still left as written.

Red at the base: ``resolve_env_references("${ASH_U35_A:x}/tail}")`` returned
``value`` alone with the variable set and ``"x}/tail"`` with it unset.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import resolve_env_references

pytestmark = pytest.mark.unit


def test_text_after_a_defaulted_reference_is_kept_when_the_variable_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ASH_U35_A", "value")

    resolved = resolve_env_references("${ASH_U35_A:x}/${OTHER}")

    assert str(resolved) == "value/${OTHER}"


def test_the_default_is_the_text_before_the_first_brace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ASH_U35_A", raising=False)

    resolved = resolve_env_references("${ASH_U35_A:x}/${OTHER}")

    assert str(resolved) == "x/${OTHER}"


def test_a_composite_without_a_default_is_still_left_as_written(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: the no-default composite kept its older rule."""
    monkeypatch.setenv("ASH_U35_A", "value")

    assert resolve_env_references("${ASH_U35_A}/${OTHER}") == "${ASH_U35_A}/${OTHER}"
    assert resolve_env_references("${ASH_U35_A}x}") == "${ASH_U35_A}x}"


def test_a_plain_reference_with_trailing_text_still_resolves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: a reference followed by text with no further brace resolved
    before and resolves now."""
    monkeypatch.setenv("ASH_U35_A", "value")

    assert str(resolve_env_references("${ASH_U35_A}/suffix")) == "value/suffix"
    assert str(resolve_env_references("${ASH_U35_A:x}")) == "value"
