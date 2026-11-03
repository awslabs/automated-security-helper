# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A flattened finding's ``file_path`` is kept as the scanner wrote it.

``FlatVulnerability`` strips whitespace from every string field, so a file whose
name ends in a space was recorded, reported and suppression-matched as a
different file. The path field alone is exempt from the strip.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.flat_vulnerability import FlatVulnerability

pytestmark = pytest.mark.unit


def _finding(**fields) -> FlatVulnerability:
    base = {
        "id": "f1",
        "title": "t",
        "description": "d",
        "severity": "HIGH",
        "scanner": "bandit",
        "scanner_type": "SAST",
    }
    return FlatVulnerability(**{**base, **fields})


def test_a_trailing_space_in_the_path_is_kept():
    assert _finding(file_path="notes.txt ").file_path == "notes.txt "


def test_a_leading_space_in_the_path_is_kept():
    assert _finding(file_path=" notes.txt").file_path == " notes.txt"


def test_other_string_fields_are_still_stripped():
    assert _finding(title="  padded  ").title == "padded"
