# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``suppression_id`` renders a raw YAML number as its text.

The config linter reads raw YAML dicts, where ``rule_id: 1234`` or
``package_version: 2.0`` arrive as numbers, and the id joined them as they were:
a TypeError out of ``ash config lint --fix-unused``. Every part is text now, and
a number is rendered with ``str()``. That is the text of the value YAML loaded,
not of what was typed: ``package_version: 2.10`` is the float ``2.1`` by the time
the linter reads it, and its id says ``2.1``. A version whose trailing zero
matters is written as text (``"2.10"``) in the config, and keeps it.
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


def test_a_version_loaded_as_a_float_renders_the_float_not_what_was_typed():
    """``package_version: 2.10`` reaches the linter as ``2.1``; the id says so.
    Written as text, the zero is kept."""
    assert (
        suppression_id({"path": "a.py", "package_version": 2.1}) == "a.py|*|*|*|*@2.1@*"
    )
    assert (
        suppression_id({"path": "a.py", "package_version": "2.10"})
        == "a.py|*|*|*|*@2.10@*"
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
