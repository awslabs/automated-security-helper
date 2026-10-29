# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``suppression_id`` renders a raw YAML number as its text.

The config linter reads raw YAML dicts, where ``rule_id: 1234`` or
``package_version: 2.0`` arrive as numbers, and the id joined them as they were:
a TypeError out of ``ash config lint --fix-unused``. Every part is text now, and
a number reads as the text its config would have held.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.core import suppression_id

pytestmark = pytest.mark.unit


def test_a_numeric_rule_id_and_package_version_render_as_text():
    assert (
        suppression_id({"path": "a.py", "rule_id": 1234, "package_version": 2.0})
        == "a.py|1234|*|*|*@2.0@*"
    )


def test_a_numeric_symbol_renders_as_text():
    assert suppression_id({"path": "a.py", "symbol": 7}) == "a.py|*|*|*|*@*@*|7"


def test_text_fields_render_as_before():
    assert (
        suppression_id(
            {"path": "a.py", "rule_id": "B101", "line_start": 3, "line_end": None}
        )
        == "a.py|B101|3|3"
    )
