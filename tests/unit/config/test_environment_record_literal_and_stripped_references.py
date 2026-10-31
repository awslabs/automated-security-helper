# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What a file read from the environment, where the loader kept text as written.

Three shapes the record got wrong:

* a key the loader never resolves (a TOML key, a quoted YAML key) whose
  variable holds the name of another key of the same mapping: the lookup of the
  value paired the literal key with that other entry, recorded a key read from
  the environment, and left the read beneath the literal key unrecorded;
* a key the resolver leaves as written with blanks around it (a tagged, quoted
  key naming a variable a file may not read): the resolver returns it stripped,
  so neither spelling was found and every read beneath it went unrecorded;
* a composite value with blanks around it, which the resolver leaves as
  written and strips: the value of the first variable it names was recorded as
  read for a place that holds the file's own text.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.environment_record import (
    environment_references,
)

pytestmark = pytest.mark.unit


def test_a_literal_key_pairs_with_itself_when_its_value_names_another_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red at the base: the literal key paired with ``a``, giving one key
    reference read from the environment and no read of ``ASH_U35_V``."""
    monkeypatch.setenv("ASH_U35_K", "a")
    monkeypatch.setenv("ASH_U35_V", "v")
    written = {"${ASH_U35_K}": {"x": "${ASH_U35_V}"}, "a": {"x": "lit"}}
    resolved = {"${ASH_U35_K}": {"x": "v"}, "a": {"x": "lit"}}

    found = environment_references(written, resolved)

    assert [(r.path, r.written, r.value, r.key) for r in found] == [
        (("${ASH_U35_K}", "x"), "${ASH_U35_V}", "v", False)
    ]


def test_a_key_the_loader_resolved_still_pairs_with_its_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: a key that came to its value, beside a plain key, pairs
    under the value and records the key's own read."""
    monkeypatch.setenv("ASH_U35_K", "a")
    monkeypatch.setenv("ASH_U35_V", "v")
    written = {"other": {"x": "lit"}, "${ASH_U35_K}": {"x": "${ASH_U35_V}"}}
    resolved = {"other": {"x": "lit"}, "a": {"x": "v"}}

    found = environment_references(written, resolved)

    assert [(r.path, r.value, r.key) for r in found] == [
        ((), "a", True),
        (("a", "x"), "v", False),
    ]


def test_a_key_left_as_written_pairs_with_its_stripped_spelling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red at the base: no reference at all, the key came to none."""
    monkeypatch.setenv("ASH_U35_V", "v")
    written = {"!ENV ${OTHER_U35_NAME} ": {"x": "${ASH_U35_V}"}}
    resolved = {"${OTHER_U35_NAME}": {"x": "v"}}

    found = environment_references(written, resolved)

    assert [(r.path, r.written, r.value, r.key) for r in found] == [
        (("${OTHER_U35_NAME}", "x"), "${ASH_U35_V}", "v", False)
    ]


def test_a_composite_value_left_as_written_with_blanks_records_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red at the base: one reference, with the value of ``ASH_U35_A``, for a
    place that holds the file's own text."""
    monkeypatch.setenv("ASH_U35_A", "ASH")
    monkeypatch.setenv("ASH_U35_B", "b")
    written = {"project_name": "${ASH_U35_A}/${ASH_U35_B} "}
    resolved = {"project_name": "${ASH_U35_A}/${ASH_U35_B}"}

    assert environment_references(written, resolved) == []


def test_a_resolved_value_with_blanks_is_still_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: a reference the resolver read, with blanks after it, is a
    value read from the environment."""
    monkeypatch.setenv("ASH_U35_A", "name")
    written = {"project_name": "${ASH_U35_A} "}
    resolved = {"project_name": "name"}

    found = environment_references(written, resolved)

    assert [(r.path, r.value) for r in found] == [(("project_name",), "name")]
