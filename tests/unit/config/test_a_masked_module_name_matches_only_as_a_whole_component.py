# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A masked module name is hidden where a text names it whole, not inside a longer name.

``plugins.loader._masked_module_forms`` builds the forms of a module path a
config read from the environment: the name, its path spellings, its dotted
parents, its inner segments and its file spellings. The redaction engine hid a
form of eight characters or more wherever it occurred, and a form of four to
seven characters wherever "_" or any other non-alphanumeric character bounded
it. A longer module name that merely held the masked name ("<name>_extras")
therefore printed partly hidden, and the longer name was lost to a reader.

A form is now matched only as a whole component: no ASCII letter, digit or "_"
beside either end of it. "." "/" "\\" and quotes bound a component. The same
boundary holds for the anywhere band, the four- to seven-character band, a form
longer than the long-form length and the separator variants of the
distribution spelling. A form shorter than four characters keeps its
quoted-only treatment, and a form a plain value also yields keeps the strict
treatment. A load passes the masked entry's own name as a plain value as well,
so the entry's own name is hidden inside a longer module name too; the
whole-component rule is what the forms derived from the name keep.

Cells: one per band; the dotted parent, with a public namespace root as its
control; the file spellings; the distribution spelling; and the controls (a name
that is not masked, a plain value that shares a form).
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.config_validator import redact_values
from automated_security_helper.plugins.loader import _masked_module_forms

pytestmark = pytest.mark.unit

MASK = "<value>"


def _hidden(text: str, name: str) -> str:
    return redact_values(text, _masked_module_forms(name))


# --- one cell per band --------------------------------------------------------


def test_a_masked_name_inside_a_longer_unmasked_name_stays_readable():
    """The anywhere band (eight characters or more)."""
    name = "kqwhole_ash_plugins"
    text = f"loaded {name} and {name}_extras, x{name} and {name}9"

    assert _hidden(text, name) == (
        f"loaded {MASK} and {name}_extras, x{name} and {name}9"
    )


def test_a_short_masked_name_is_bounded_by_underscore_too():
    """The four- to seven-character band: "_" no longer ends a word here."""
    name = "kqshrt"
    text = f"name {name}, {name}_x, x{name}, {name}9 and '{name}'"

    assert _hidden(text, name) == (
        f"name {MASK}, {name}_x, x{name}, {name}9 and '{MASK}'"
    )


def test_a_form_past_the_long_form_length_is_matched_whole():
    """A form longer than 64 characters is found apart from the pattern."""
    name = f"kqlong{'x' * 60}_ash_plugins"
    text = f"see {name} and {name}_more and x{name}"

    assert _hidden(text, name) == f"see {MASK} and {name}_more and x{name}"


# --- the dotted parent --------------------------------------------------------


def test_a_dotted_parent_of_a_masked_entry_is_hidden_as_a_component():
    parent = "kqpar_ash_plugins"
    entry = f"{parent}.kqchild_ash_plugins"
    text = (
        f"parent {parent}, entry {entry}.deep, "
        f"sibling {parent}_other and {parent}.other"
    )

    assert _hidden(text, entry) == (
        f"parent {MASK}, entry {MASK}.deep, sibling {parent}_other and {MASK}.other"
    )


def test_a_public_namespace_root_stays_readable_beside_a_masked_entry():
    """Control: the namespace rule's own text names this root."""
    entry = "ash_plugins.kqpublic_leaf_ash"

    assert _hidden("No module named 'ash_plugins'", entry) == (
        "No module named 'ash_plugins'"
    )
    assert _hidden(f"path {entry}", entry) == f"path {MASK}"


# --- the file spellings -------------------------------------------------------


def test_a_leafs_file_spellings_are_hidden_whole():
    leaf = "kqleaf"
    entry = f"kqfiletop_ash_plugins.kqfilemid_seg.{leaf}"
    text = (
        f"cannot read {leaf}.pyc and {leaf}.py and "
        f"__pycache__/{leaf}.cpython-314.pyc and {leaf}_x.py"
    )

    assert _hidden(text, entry) == (
        f"cannot read {MASK} and {MASK} and __pycache__/{MASK}-314.pyc and {leaf}_x.py"
    )


# --- the distribution spelling ------------------------------------------------


def test_a_separator_variant_of_the_distribution_name_is_matched_whole():
    text = "dist Kqdist.Ash_Plugins-1.0.dist-info and Kqdist.Ash_Plugins_extra"

    assert _hidden(text, "kqdist_ash_plugins") == (
        f"dist {MASK}-1.0.dist-info and Kqdist.Ash_Plugins_extra"
    )


# --- controls -----------------------------------------------------------------


def test_a_name_that_is_not_masked_prints_unchanged():
    text = "import kqother_ash_plugins.mod and kqother_ash_plugins"

    assert _hidden(text, "kqwhole_ash_plugins") == text


def test_a_plain_value_that_shares_a_form_keeps_the_strict_treatment():
    """Control: an environment value is hidden inside a longer word, as before.
    A form that a plain value also yields is replaced as that value is, so a
    load, which passes the masked entry's own name as a plain value beside the
    forms derived from it, hides the entry's own name inside a longer module
    name too."""
    name = "kqwhole_ash_plugins"

    assert redact_values(f"{name}_extras", (name, *_masked_module_forms(name))) == (
        f"{MASK}_extras"
    )
