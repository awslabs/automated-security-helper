# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A masked-module block nested inside another keeps the inner block's plain values.

``masked_module_names`` blocks nest: an inner block adds its forms to the outer
one's. A plain value (a masked module's own name, hidden inside a longer name
too) and a module-form needle of the same text (hidden only as a whole
component) compare equal as strings. Joining the two blocks' forms with a
de-duplication that keeps the first of two equal entries dropped an inner plain
value behind an outer needle of the same text, so a longer name that holds it
(``<name>_extras``) printed in clear. The join keeps a plain value beside a
needle of the same text, and a redaction gives the plain value precedence.

An exact repeat is dropped. The same scope entered twice (a run's scope around a
reader that sets it again), or a registration made inside such a block, held
every form twice and redacted each form twice. An entry is the same as another
only when its text, its type, whether it is a whole-component form, whether it
is exempt inside a frame line, and its variant pattern are all equal.

Covered: an outer needle with an inner plain value of the same text; the same
two in the other order; the inner block's end, which restores the outer scope;
an inner block that adds another name; the same scope entered twice; a
registration made inside it; a repeat within one call; two needles that differ
only in the frame exemption; and, as controls, a plain value beside a needle of
the same text and two needles of one text whose patterns differ.
"""

from __future__ import annotations

import re

from automated_security_helper.config.config_validator import (
    make_module_form_needle,
)
from automated_security_helper.plugins.loader import masked_module_scope
from automated_security_helper.plugins.plugin_manager import (
    _MASKED_MODULE_FORMS,
    AshPluginLibrary,
    AshPluginManager,
    masked_module_names,
    without_masked_modules,
)

MASK = "<value>"
NAME = "kqnest_ash_plugins"
OTHER = "kqnestother_ash_plugins"
LONGER = f'File "/srv/{NAME}_extras.py", line 1'


def _needle(name: str):
    return make_module_form_needle(name, frame_exempt=True, whole_component=True)


def test_an_inner_plain_value_is_kept_behind_an_outer_needle_of_the_same_text():
    with masked_module_names([_needle(NAME)]):
        with masked_module_names([NAME]):
            text = without_masked_modules(LONGER)

    assert NAME not in text, text
    assert f"{MASK}_extras.py" in text, text


def test_an_outer_plain_value_is_kept_beside_an_inner_needle_of_the_same_text():
    with masked_module_names([NAME]):
        with masked_module_names([_needle(NAME)]):
            text = without_masked_modules(LONGER)

    assert NAME not in text, text
    assert f"{MASK}_extras.py" in text, text


def test_the_end_of_the_inner_block_restores_the_outer_scope():
    with masked_module_names([_needle(NAME)]):
        with masked_module_names([NAME]):
            pass
        text = without_masked_modules(LONGER)

    assert text == LONGER, text


def test_an_inner_block_that_adds_another_name_keeps_the_outer_names():
    with masked_module_names([NAME]):
        with masked_module_names([OTHER]):
            text = without_masked_modules(f"{LONGER} {OTHER}_extras")

    assert NAME not in text, text
    assert OTHER not in text, text


def test_the_same_scope_entered_twice_holds_each_form_once():
    scope = masked_module_scope({NAME: MASK})

    with masked_module_names(scope):
        with masked_module_names(scope):
            held = _MASKED_MODULE_FORMS.get()

    assert len(held) == len(scope), (len(held), len(scope))
    assert without_masked_modules(LONGER) == LONGER


def test_a_registration_made_inside_a_nested_scope_stores_each_form_once():
    scope = masked_module_scope({NAME: MASK})
    manager = AshPluginManager(plugin_library=AshPluginLibrary())

    with masked_module_names(scope):
        with masked_module_names(scope):
            manager.register_plugin_module("scanner", "KqNestRecorded", NAME)

    stored = manager.plugin_library.scanners["KqNestRecorded"]._masked_forms
    assert len(stored) == len(scope), (len(stored), len(scope))


def test_a_repeat_within_one_call_is_dropped():
    with masked_module_names([NAME, NAME, _needle(NAME), _needle(NAME)]):
        held = _MASKED_MODULE_FORMS.get()

    assert len(held) == 2, held


def test_a_needle_without_the_frame_exemption_is_kept_beside_one_with_it():
    """The exemption changes what the redaction does inside a frame line of
    ASH's or the import machinery, so two needles that differ only in it are two
    entries: dropping the stricter one lets an outer exempt needle keep the text
    readable in a line the inner block meant to hide."""
    exempt = _needle(NAME)
    strict = make_module_form_needle(NAME, frame_exempt=False, whole_component=True)

    with masked_module_names([exempt]):
        with masked_module_names([strict]):
            inner = _MASKED_MODULE_FORMS.get()
    with masked_module_names([strict]):
        with masked_module_names([exempt]):
            outer_strict = _MASKED_MODULE_FORMS.get()

    assert len(inner) == 2, inner
    assert len(outer_strict) == 2, outer_strict
    assert {getattr(form, "frame_exempt", None) for form in inner} == {True, False}


# --- controls --------------------------------------------------------------------


def test_a_plain_value_beside_a_needle_of_the_same_text_is_kept():
    with masked_module_names([_needle(NAME), NAME]):
        held = _MASKED_MODULE_FORMS.get()

    assert len(held) == 2, held


def test_two_needles_of_one_text_with_different_patterns_are_both_kept():
    plain = _needle(NAME)
    varied = make_module_form_needle(
        NAME,
        frame_exempt=True,
        pattern=re.compile("kqnestvariant", re.IGNORECASE),
        whole_component=True,
    )

    with masked_module_names([plain, varied]):
        held = _MASKED_MODULE_FORMS.get()

    assert len(held) == 2, held
