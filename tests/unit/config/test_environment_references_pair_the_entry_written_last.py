# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``environment_references`` pairs a name's value with the entry written last.

The loader keeps the last entry written under a name, whether the name was
written as text or came from a ``${VAR}`` key. The pairing gave a plain key's
written value to whatever the resolved mapping held under that name, so where a
later referenced key resolved to the same name and overwrote the entry, the
plain key's reference-shaped value was paired with the other entry's value and
recorded as a reference the file never made there, while the kept entry's own
reads went unpaired.

Red at the base: the record held a reference at ``a`` written ``${ASH_U35_V}``
and resolved to ``z``, the value the referenced key wrote.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.environment_record import (
    environment_references,
)

pytestmark = pytest.mark.unit


def test_a_plain_key_overwritten_by_a_later_referenced_key_is_not_paired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ASH_U35_K", "a")
    monkeypatch.setenv("ASH_U35_V", "v")
    written = {"a": "${ASH_U35_V}", "${ASH_U35_K}": "z"}
    resolved = {"a": "z"}

    found = environment_references(written, resolved)

    values = [(r.path, r.written, r.resolved) for r in found if not r.key]
    assert values == [], values
    keys = [(r.path, r.written, r.resolved) for r in found if r.key]
    assert keys == [((), "${ASH_U35_K}", "a")], keys


def test_a_referenced_key_overwritten_by_a_later_plain_key_pairs_the_plain_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ASH_U35_K", "a")
    monkeypatch.setenv("ASH_U35_V", "v")
    written = {"${ASH_U35_K}": "${ASH_U35_V}", "a": "${ASH_U35_V}"}
    resolved = {"a": "v"}

    found = environment_references(written, resolved)

    values = [(r.path, r.written, r.resolved, r.value) for r in found if not r.key]
    assert values == [(("a",), "${ASH_U35_V}", "v", "v")], values


def test_a_lone_plain_key_pairs_as_before(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control."""
    monkeypatch.setenv("ASH_U35_V", "v")

    found = environment_references({"a": "${ASH_U35_V}"}, {"a": "v"})

    assert [(r.path, r.written, r.value) for r in found] == [
        (("a",), "${ASH_U35_V}", "v")
    ]
