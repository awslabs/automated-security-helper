# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``patch`` operation whose ``op`` is not text never reaches a set lookup.

``_split_references`` tests an operation's ``op`` for membership in a frozenset of
the value-writing names. A YAML ``op: [add]`` is a list, which is unhashable, so
the membership test raised ``TypeError`` instead of leaving the operation to its
own validation. The operation is simply not one that sets a value here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import _split_references
from automated_security_helper.config.environment_record import EnvironmentReference

pytestmark = pytest.mark.unit


def _reference() -> EnvironmentReference:
    return EnvironmentReference(
        path=("patch", 0, "value"),
        written="${X}",
        resolved="x",
        value="x",
        origin=(Path("c.yaml"), ("patch", 0, "value")),
    )


@pytest.mark.parametrize("op", [["add"], {"add": 1}, 3, None])
def test_a_non_text_op_is_not_a_value_writer(op):
    reference = _reference()
    data = {"patch": [{"op": op, "path": "/a", "value": "${X}"}]}

    own, from_ops = _split_references([reference], data)

    assert own == []
    assert from_ops == []


def test_a_text_value_writing_op_is_still_split_out():
    reference = _reference()
    data = {"patch": [{"op": "add", "path": "/a", "value": "${X}"}]}

    own, from_ops = _split_references([reference], data)

    assert own == []
    assert [(index, path) for index, path, _ in from_ops] == [(0, ())]
