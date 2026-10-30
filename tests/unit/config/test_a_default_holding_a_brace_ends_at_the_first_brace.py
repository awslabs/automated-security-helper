# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A default that holds a brace ends at the first closing brace.

The reference ends at the first ``}`` after its start, so in ``${ASH_X:{}}``
the default is ``{`` and the final ``}`` is text after the reference, kept as
it is for ``${VAR}`` followed by text: with the variable set the value is its
value followed by ``}``, with it unset it is ``{}``. The pattern once read the
default up to the LAST brace, which made the default ``{}`` and the whole value
the variable's value alone; this test pins the contract as it stands now, so a
change to it is a deliberate one.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import resolve_env_references

pytestmark = pytest.mark.unit


def test_the_text_after_the_first_brace_is_kept_when_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ASH_U35_B", "value")

    assert str(resolve_env_references("${ASH_U35_B:{}}")) == "value}"


def test_the_default_is_the_text_before_the_first_brace_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ASH_U35_B", raising=False)

    assert str(resolve_env_references("${ASH_U35_B:{}}")) == "{}"


def test_a_default_without_a_brace_is_whole(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control."""
    monkeypatch.delenv("ASH_U35_B", raising=False)

    assert str(resolve_env_references("${ASH_U35_B:a-b.c}")) == "a-b.c"
