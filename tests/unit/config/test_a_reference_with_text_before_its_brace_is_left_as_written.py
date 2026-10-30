# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``${VAR-x}``, ``${VAR x}`` and ``${VAR.x}`` are left as written.

A reference is ``${VAR}`` or ``${VAR:default}``. Text between the name and the
closing brace with no colon before it is not a default ASH reads: the shell's
other default spellings (``${VAR-default}``), or a name the pattern does not
read. Such a value was always left as written. When the default was made to end
at the first brace, the guard that kept it so was replaced by a test of the text
AFTER the match, which that shape does not have, so ``${ASH_X-default}`` began
to resolve: with the variable set its value replaced the whole reference and
``-default`` was dropped; with it unset the load failed as a reference with no
default, where the same file loaded before.

Red at the base: ``resolve_env_references("${ASH_U35_D-default}")`` returned
the variable's value with it set and raised ASHConfigUnsetVariableError with it
unset.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import resolve_env_references

pytestmark = pytest.mark.unit

SHAPES = ["${ASH_U35_D-default}", "${ASH_U35_D default}", "${ASH_U35_D.x}"]


@pytest.mark.parametrize("written", SHAPES)
def test_left_as_written_when_the_variable_is_set(
    monkeypatch: pytest.MonkeyPatch, written: str
) -> None:
    monkeypatch.setenv("ASH_U35_D", "value")

    assert resolve_env_references(written) == written


@pytest.mark.parametrize("written", SHAPES)
def test_left_as_written_when_the_variable_is_unset(
    monkeypatch: pytest.MonkeyPatch, written: str
) -> None:
    monkeypatch.delenv("ASH_U35_D", raising=False)

    assert resolve_env_references(written) == written


def test_the_colon_form_still_reads_its_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: ``${VAR:default}`` is the default ASH reads."""
    monkeypatch.delenv("ASH_U35_D", raising=False)

    assert str(resolve_env_references("${ASH_U35_D:default}")) == "default"
    monkeypatch.setenv("ASH_U35_D", "value")
    assert str(resolve_env_references("${ASH_U35_D:default}")) == "value"
