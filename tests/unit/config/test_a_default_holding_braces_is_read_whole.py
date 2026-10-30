# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``${VAR:default}`` default runs to the brace that pairs with the reference's.

The reference once ended at the FIRST closing brace, so in ``${ASH_X:{}}`` the
default was read as ``{`` and the final ``}`` as text after the reference: with
the variable set the value became ``value}``, and a regex default such as
``\\d{3}`` came back as the value followed by a stray brace. The default is now
read by brace depth (``read_env_reference``), so a default may hold brace
pairs; a brace left open closes no reference, and the value is its own text.

Red at the base: ``resolve_env_references("${ASH_U35_B:{}}")`` returned
``value}`` with the variable set, and ``${ASH_U35_B:\\d{3}}`` returned
``value}`` too.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import (
    ENV_REFERENCE_PATTERN,
    read_env_reference,
    resolve_env_references,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "written, default",
    [("${ASH_U35_B:{}}", "{}"), ("${ASH_U35_B:\\d{3}}", "\\d{3}")],
    ids=["brace-pair", "regex-quantifier"],
)
def test_the_value_alone_is_read_when_set(
    monkeypatch: pytest.MonkeyPatch, written: str, default: str
) -> None:
    monkeypatch.setenv("ASH_U35_B", "value")

    assert str(resolve_env_references(written)) == "value"


@pytest.mark.parametrize(
    "written, default",
    [("${ASH_U35_B:{}}", "{}"), ("${ASH_U35_B:\\d{3}}", "\\d{3}")],
    ids=["brace-pair", "regex-quantifier"],
)
def test_the_whole_default_is_read_when_unset(
    monkeypatch: pytest.MonkeyPatch, written: str, default: str
) -> None:
    monkeypatch.delenv("ASH_U35_B", raising=False)

    assert str(resolve_env_references(written)) == default


def test_the_reference_is_read_to_its_pairing_brace() -> None:
    reference = read_env_reference("${ASH_U35_B:{a}} tail")

    assert reference is not None
    assert reference.default_text == "{a}"
    assert reference.text == "${ASH_U35_B:{a}}"
    assert reference.rest == " tail"


def test_a_brace_left_open_is_not_a_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``${ASH_U35_B:{a}``: the recognizer sees a reference up to the first
    brace, the reader finds no brace that closes it, and the value stays its
    own text whether or not the variable is set."""
    monkeypatch.setenv("ASH_U35_B", "value")
    written = "${ASH_U35_B:{a}"

    assert ENV_REFERENCE_PATTERN.match(written) is not None
    assert read_env_reference(written) is None
    assert resolve_env_references(written) == written
    monkeypatch.delenv("ASH_U35_B", raising=False)
    assert resolve_env_references(written) == written


def test_a_default_without_a_brace_is_whole(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control."""
    monkeypatch.delenv("ASH_U35_B", raising=False)

    assert str(resolve_env_references("${ASH_U35_B:a-b.c}")) == "a-b.c"
