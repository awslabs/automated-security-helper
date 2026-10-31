# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A key written twice pairs the entry written LAST, wherever it was first written.

``environment_references`` pairs the written and the resolved readings of a
file by key and keeps, for a name two entries come to (a plain key and a
reference that resolves to it), the entry written last, as the loader does. It
read that order from the written mapping, and a dict holds a repeated key at
its FIRST writing with its LAST value. So ``a: p`` / ``${ASH_K}: z`` (ASH_K=a)
/ ``a: ${ASH_V}`` read as if ``${ASH_K}: z`` were the last entry: ``z`` was
paired with the resolved ``v``, no reference was recorded for it, and the real
``${ASH_V}`` read went unrecorded, so its value was missing from the record and
from what the record redacts. The written reading now holds each kept entry at
its last writing.

Red at the base: no reference with written ``${ASH_U35_V}`` was recorded.
"""

from __future__ import annotations

import io

import pytest

from automated_security_helper.config.ash_config import load_yaml_config
from automated_security_helper.config.environment_record import (
    environment_references,
)

pytestmark = pytest.mark.unit

TEXT = "project_name: p\n${ASH_U35_K}: z\nproject_name: ${ASH_U35_V}\n"


def _readings(text: str):
    written = load_yaml_config(io.StringIO(text), env="written")
    resolved = load_yaml_config(io.StringIO(text))
    return written, resolved


def test_the_last_written_entry_is_the_one_paired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ASH_U35_K", "project_name")
    monkeypatch.setenv("ASH_U35_V", "v")

    written, resolved = _readings(TEXT)
    reads = environment_references(written, resolved)

    assert resolved == {"project_name": "v"}
    assert list(written) == ["${ASH_U35_K}", "project_name"]
    values = [(r.path, r.written, r.value) for r in reads if not r.key]
    assert values == [(("project_name",), "${ASH_U35_V}", "v")]
    keys = [(r.written, r.value) for r in reads if r.key]
    assert keys == [("${ASH_U35_K}", "project_name")]


def test_a_reference_written_before_the_plain_key_is_not_paired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other order: the plain entry written last is the one the loader
    kept, so the reference in the earlier value is not a read of this file's
    configuration and is not recorded as one."""
    monkeypatch.setenv("ASH_U35_K", "project_name")
    monkeypatch.setenv("ASH_U35_V", "v")
    text = "project_name: ${ASH_U35_V}\n${ASH_U35_K}: z\n"

    written, resolved = _readings(text)
    reads = environment_references(written, resolved)

    assert resolved == {"project_name": "z"}
    assert [r.written for r in reads if not r.key] == []
    assert [r.written for r in reads if r.key] == ["${ASH_U35_K}"]


def test_a_single_writing_keeps_its_place(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control: with no repeated key the written mapping is in file order."""
    monkeypatch.setenv("ASH_U35_V", "v")

    written, resolved = _readings("a: 1\nb: ${ASH_U35_V}\nc: 3\n")

    assert list(written) == ["a", "b", "c"]
    assert [(r.path, r.value) for r in environment_references(written, resolved)] == [
        (("b",), "v")
    ]
