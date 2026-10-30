# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""severity_color (utils/ui_theme.py) looks a severity up among the severities.

The palette holds the layout roles too (background, surface, panel, border), and
a severity spelled like one took that role's color: a finding whose severity read
"background" was painted in the background color, invisible.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils.ui_theme import (
    COLORS,
    SEVERITY_LEVELS,
    severity_color,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("level", SEVERITY_LEVELS)
def test_a_severity_takes_its_own_color_in_any_case(level):
    assert severity_color(level) == COLORS[level]
    assert severity_color(level.upper()) == COLORS[level]


@pytest.mark.parametrize(
    "text", ["background", "surface", "panel", "border", "accent", "foreground"]
)
def test_a_palette_role_is_no_severity_and_takes_the_muted_color(text):
    assert COLORS[text] != COLORS["muted"], "the control: the role has its own color"
    assert severity_color(text) == COLORS["muted"]


def test_unknown_text_takes_the_muted_color():
    assert severity_color("unknown") == COLORS["muted"]
    assert severity_color(None) == COLORS["muted"]
