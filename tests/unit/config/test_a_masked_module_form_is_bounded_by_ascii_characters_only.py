# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A masked module form is bounded by ASCII letters, digits and "_" only.

A form is matched as a whole component: no ASCII letter, digit or "_" beside
either end of it. The look-arounds that say so are compiled with the engine's
case-insensitive flag, and under that flag a character class such as
``[A-Za-z0-9_]`` also matches the characters that fold onto an ASCII letter: the
Kelvin sign, the long s, the dotless i and the dotted capital I. A form of 64
characters or fewer beside one of them was therefore treated as glued to a longer
name and not hidden, while a longer form, which is found apart from the pattern
by an ASCII test, was hidden. The look-arounds now turn the case-insensitive flag
off inside the class, so both paths agree.

Cells: each look-alike beside a form on both sides; a form past the long-form
length beside the same characters, and an ASCII letter, digit or "_" beside a
form, as controls.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.config_validator import redact_values
from automated_security_helper.plugins.loader import _masked_module_forms

MASK = "<value>"
LOOK_ALIKES = (chr(0x212A), chr(0x17F), chr(0x131), chr(0x130))
LOOK_ALIKE_IDS = ("kelvin_sign", "long_s", "dotless_i", "dotted_capital_i")


def _hidden(text: str, name: str) -> str:
    return redact_values(text, _masked_module_forms(name))


@pytest.mark.parametrize("neighbor", LOOK_ALIKES, ids=LOOK_ALIKE_IDS)
def test_a_form_beside_a_case_folding_look_alike_is_hidden(neighbor):
    name = "kqkelvin_ash_plugins"
    text = f"a {neighbor}{name} b {name}{neighbor} c"

    assert _hidden(text, name) == f"a {neighbor}{MASK} b {MASK}{neighbor} c"


@pytest.mark.parametrize("neighbor", LOOK_ALIKES, ids=LOOK_ALIKE_IDS)
def test_a_form_past_the_long_form_length_beside_a_look_alike_is_hidden(neighbor):
    """Control: the long-form path already tests the neighbor as ASCII."""
    name = f"kqkelvinlong{'x' * 60}_ash_plugins"
    text = f"a {neighbor}{name} b {name}{neighbor} c"

    assert _hidden(text, name) == f"a {neighbor}{MASK} b {MASK}{neighbor} c"


def test_an_ascii_neighbor_still_keeps_a_longer_name_readable():
    """Control: an ASCII letter, a digit or "_" beside the form is a longer name."""
    name = "kqkelvin_ash_plugins"
    text = f"x{name} and {name}_y and {name}9 and K{name}"

    assert _hidden(text, name) == text
