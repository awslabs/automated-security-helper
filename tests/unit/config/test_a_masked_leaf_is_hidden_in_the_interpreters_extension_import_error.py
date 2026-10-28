# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A masked module's name is hidden in the interpreter's own extension import error.

When a compiled extension module is found but does not define the entry point
the interpreter looks for, CPython's ImportError names that entry point after
the module's last segment:

    dynamic module does not define module export function (PyInit_<leaf>)

A module form is matched only as a whole component, and "_" is part of a
component, so the leaf written after "PyInit_" is not a whole component and the
name printed in that message. ``plugins.loader._masked_module_forms`` now also
builds the entry-point spelling of the leaf (and of the whole name when the path
has one segment), so the message names the module by its mask.

Cells: a single-segment name; the leaf of a dotted name, for a leaf of eight
characters or more and for a shorter one; and the controls (another module's
entry point, a longer name that merely holds the entry point, a name that is
not masked, and a prefix that is not "PyInit_" beside the masked name).
"""

from __future__ import annotations

from automated_security_helper.config.config_validator import redact_values
from automated_security_helper.plugins.loader import _masked_module_forms

MASK = "<value>"
MESSAGE = "ImportError: dynamic module does not define module export function ({})"


def _hidden(text: str, name: str) -> str:
    return redact_values(text, _masked_module_forms(name))


def test_a_single_segment_masked_name_is_hidden_in_the_extension_import_error():
    name = "kqpyinit_ash_plugins"

    assert _hidden(MESSAGE.format(f"PyInit_{name}"), name) == MESSAGE.format(MASK)


def test_the_leaf_of_a_dotted_masked_name_is_hidden_in_the_extension_import_error():
    """The leaf is eight characters or more."""
    leaf = "kqpyleaf_seg"
    entry = f"kqpytwo_ash_plugins.{leaf}"

    assert _hidden(MESSAGE.format(f"PyInit_{leaf}"), entry) == MESSAGE.format(MASK)


def test_a_short_leaf_of_a_dotted_masked_name_is_hidden_in_the_extension_import_error():
    """The leaf is four to seven characters, hidden through the file spellings'
    rule: a path with a hidden suffix before it."""
    leaf = "kqleaf"
    entry = f"kqpytop_ash_plugins.kqpymid_seg.{leaf}"

    assert _hidden(MESSAGE.format(f"PyInit_{leaf}"), entry) == MESSAGE.format(MASK)


# --- controls --------------------------------------------------------------------


def test_another_modules_entry_point_prints_unchanged():
    text = MESSAGE.format("PyInit_kqpyother_ash_plugins")

    assert _hidden(text, "kqpyinit_ash_plugins") == text


def test_a_longer_name_that_holds_the_entry_point_stays_readable():
    name = "kqpyinit_ash_plugins"
    text = MESSAGE.format(f"PyInit_{name}_extras")

    assert _hidden(text, name) == text


def test_a_prefix_other_than_the_entry_point_keeps_the_name_readable():
    """Control: the name glued to a letter is a longer name, as before."""
    name = "kqpyinit_ash_plugins"
    text = f"loaded x{name} and Init_{name}"

    assert _hidden(text, name) == text
