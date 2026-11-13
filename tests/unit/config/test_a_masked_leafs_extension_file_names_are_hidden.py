# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A masked module leaf is hidden in the file names of a compiled extension.

``plugins.loader._masked_module_forms`` builds the forms of a masked module path.
For the last segment it adds the file names a text can print after the segment:
the source file, the byte code, the stub, the script and the Windows extension
module. A compiled extension module is also named with a platform tag after the
leaf (``leaf.cp312-win_amd64.pyd``, ``leaf.abi3.so``) or with no tag
(``leaf.so``). A form is matched only as a whole component, so ``leaf.pyd``
does not end where ``leaf.cp312-win_amd64.pyd`` begins its tag, and a leaf of
four to seven characters printed in clear in those names. The leaf now adds the
tagged names, whose version digits are matched by a pattern, and the untagged
``.so`` name.

Other interpreters and debug builds name an extension the same way with another
tag (``leaf.pypy310-pp73-x86_64-linux-gnu.so``,
``leaf.graalpy311-311-native-x86_64-linux.so``) or with a debug suffix on the
leaf (``leaf_d.pyd``, ``leaf_d.cp312-win_amd64.pyd``). One pattern covers them:
the leaf, an optional debug suffix and any one dotted tag, before ``.so`` or
``.pyd``. It hides the leaf and leaves the tag readable, as the Windows tag
pattern leaves the platform text after the version readable.

The debug suffix belongs to the ``.pyd`` spellings only, and a suffix ends the
name unless an ASCII letter, digit or "_" follows it: a character that merely
folds onto a letter in a case-insensitive match (the Kelvin sign) does not.

Cells: a tagged Windows name, a stable-ABI name, an untagged name; a name from
PyPy, one from GraalPy and the debug names; a suffix beside a character that
folds onto a letter; a debug suffix before ``.so``; a CPython Linux name as a
control; and the controls (a tag that is not followed by an extension suffix, a
longer name, a letter glued to the leaf).
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.config_validator import redact_values
from automated_security_helper.plugins.loader import _masked_module_forms

pytestmark = pytest.mark.unit

MASK = "<value>"
LEAF = "kqleaf"
ENTRY = f"kqexttop_ash_plugins.kqextmid_seg.{LEAF}"


def _hidden(text: str) -> str:
    return redact_values(text, _masked_module_forms(ENTRY))


def test_a_tagged_windows_extension_file_name_is_hidden_whole():
    text = f"cannot load {LEAF}.cp312-win_amd64.pyd and {LEAF}.cp313t-win_amd64.pyd"

    assert _hidden(text) == f"cannot load {MASK}-win_amd64.pyd and {MASK}-win_amd64.pyd"


def test_a_stable_abi_extension_file_name_is_hidden_whole():
    assert _hidden(f"cannot load {LEAF}.abi3.so") == f"cannot load {MASK}.so"


def test_an_untagged_extension_file_name_is_hidden_whole():
    assert _hidden(f"cannot load {LEAF}.so now") == f"cannot load {MASK} now"


# --- other interpreters and debug builds ------------------------------------------


def test_a_pypy_extension_file_name_hides_the_leaf():
    tag = "pypy310-pp73-x86_64-linux-gnu"

    assert _hidden(f"cannot load {LEAF}.{tag}.so now") == (
        f"cannot load {MASK}.{tag}.so now"
    )


def test_a_graalpy_extension_file_name_hides_the_leaf():
    tag = "graalpy311-311-native-x86_64-linux"

    assert _hidden(f"cannot load {LEAF}.{tag}.so") == f"cannot load {MASK}.{tag}.so"


def test_a_debug_windows_extension_file_name_hides_the_leaf():
    assert _hidden(f"cannot load {LEAF}_d.pyd") == f"cannot load {MASK}.pyd"


def test_a_tagged_debug_windows_extension_file_name_is_hidden_whole():
    text = f"cannot load {LEAF}_d.cp312-win_amd64.pyd"

    assert _hidden(text) == f"cannot load {MASK}-win_amd64.pyd"


def test_any_dotted_tag_before_an_extension_suffix_hides_the_leaf():
    text = f"{LEAF}.cpx.so and {LEAF}.abix.so and {LEAF}.free-threaded.pyd"

    assert _hidden(text) == (
        f"{MASK}.cpx.so and {MASK}.abix.so and {MASK}.free-threaded.pyd"
    )


def test_a_character_that_folds_onto_a_letter_does_not_glue_the_suffix():
    """A suffix ends the name when the next character is not an ASCII letter,
    digit or "_". The Kelvin sign and the dotless i fold onto ASCII letters
    under a case-insensitive match, but they are not ASCII, so they end it."""
    tag = "pypy310-pp73-x86_64-linux-gnu"
    kelvin = chr(0x212A)
    dotless_i = chr(0x131)

    assert _hidden(f"{LEAF}.{tag}.so{kelvin} and {LEAF}_d.pyd{dotless_i}") == (
        f"{MASK}.{tag}.so{kelvin} and {MASK}.pyd{dotless_i}"
    )


def test_a_debug_suffix_is_not_part_of_a_linux_extension_file_name():
    """The ``_d`` debug suffix on the leaf is a Windows ``.pyd`` spelling. A
    POSIX debug build puts the ``d`` in the ABI tag, so ``leaf_d.so`` is the
    file of a module with another name."""
    text = f"{LEAF}_d.so and {LEAF}_d.abi3.so and {LEAF}_d.cpx.so"

    assert _hidden(text) == text


def test_a_cpython_linux_extension_file_name_hides_the_leaf():
    """Control: the CPython tag was covered before the other interpreters' were."""
    tag = "cpython-312-x86_64-linux-gnu"

    assert _hidden(f"cannot load {LEAF}.{tag}.so") == (
        f"cannot load {MASK}-312-x86_64-linux-gnu.so"
    )


# --- controls --------------------------------------------------------------------


def test_a_tag_that_is_not_followed_by_an_extension_suffix_keeps_the_text_readable():
    text = (
        f"{LEAF}.cpx.txt and {LEAF}_x.so and {LEAF}_d_x.pyd and {LEAF}.cpx.sob "
        f"and {LEAF}.a.b.so"
    )

    assert _hidden(text) == text


def test_a_leaf_glued_to_a_letter_keeps_the_text_readable():
    text = (
        f"x{LEAF}.abi3.so and x{LEAF}.cp312-win_amd64.pyd and x{LEAF}.so "
        f"and x{LEAF}.pypy310-pp73-x86_64-linux-gnu.so and x{LEAF}_d.pyd"
    )

    assert _hidden(text) == text
