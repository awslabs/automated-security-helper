# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A masked dotted module name is hidden in its path spellings inside a longer name.

A module entry a config read from the environment is named by its mask in every
text a run prints. The entry's own dotted name is hidden wherever it occurs,
inside a longer module name too (``<parent>.<child>_extras`` prints
``<value>_extras``). Its path spellings, ``<parent>/<child>`` and
``<parent>\\<child>``, are the same name written the way a traceback's file line
writes it, and a file line for a longer name that holds the entry
(``<parent>/<child>_extras.py``) must hide it the same way. They used to be
matched as whole components only, so the file line printed the leaf of the
masked entry (``<value>/<child>_extras.py``) beside a source line that hid it
(``import <value>_extras``).

The import statement and the import error name the same sibling without a dot:
``from <parent> import <child>_extras`` and ``cannot import name
'<child>_extras' from '<parent>'``. The parent is hidden as a whole component,
and the leaf is a whole-component form that a longer name does not match, so
those lines printed the masked leaf beside a hidden file line. The leaf of a
masked dotted name is now hidden there too when it is followed by ``_...`` and
stands after ``import `` (also in the error's ``import name '``) or after a
leading ``.`` (a relative import).

The longer name follows more than ``import <leaf>_extras``: a later name of a
list (``import other, <leaf>_extras``), a parenthesized list over one or several
lines, a relative import of any depth, the error of a missing attribute, a
blank other than one space after ``import``, and a name that goes on with a
letter or a digit (``<leaf>2``). Each is hidden where the name stands in one of
those places, and a longer name anywhere else stays readable.

Two masked entries can produce a form of the same text (the inner segment of one
and the parent of the other). The forms of a run are kept apart by the same
identity the scope keeps them by, so the form that carries the import-line
pattern is not dropped behind the one that does not, whichever entry is listed
first.

Covered: the traceback of a literal module that imports a longer sibling of a
masked dotted entry, with the entry loaded in a call of its own, once as a
dotted import and once as a ``from`` import; the ``/`` and the ``\\`` spellings
of the entry inside a longer name; the three texts of a ``from`` import (the
statement, the error and a relative import); the other shapes above; two
entries that produce one text, in both orders; and, as controls, a longer name
that holds only the entry's parent, a path of another parent, a longer leaf
outside an import, the bare leaf after ``import``, unrelated names in the same
places, and a text when nothing is masked.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.plugins.loader import (
    load_additional_plugin_modules,
    masked_module_scope,
)
from automated_security_helper.plugins.plugin_manager import (
    masked_module_names,
    without_masked_modules,
)
from automated_security_helper.utils.log import ASH_LOGGER

MASK = "<value>"
PARENT = "kqpar_ash_plugins"
CHILD = "kqchild_ash_plugins"
DOTTED = f"{PARENT}.{CHILD}"
IMPORTER = "kqparlit_ash_plugins"
FROM_IMPORTER = "kqparfrom_ash_plugins"
SHOWN = {DOTTED: MASK}
#: Two entries that produce a form of one text: the inner segment of the first
#: and the parent of the second.
SHARED = "kqshared_ash_plugins"
RUN_PARENT = "kqa_ash_plugins"
RUN_ENTRY = f"{RUN_PARENT}.{SHARED}"
PREFIX_ENTRY = f"{SHARED}.kqsub_ash_plugins"


class _Sink(logging.Handler):
    def __init__(self):
        super().__init__(level=1)
        self.messages: List[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


@pytest.fixture
def messages():
    """Every ash log record's message, whatever the logger's level was."""
    sink = _Sink()
    level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(sink)
    ASH_LOGGER.setLevel(1)
    yield sink.messages
    ASH_LOGGER.removeHandler(sink)
    ASH_LOGGER.setLevel(level)


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The masked entry imports fine. A literal module imports a longer sibling
    of the entry, and that sibling raises, so the traceback holds the import
    line and the sibling's file line one under the other."""
    root = tmp_path / "path-spelling-site"
    (root / PARENT).mkdir(parents=True)
    (root / PARENT / "__init__.py").write_text("", encoding="utf-8")
    (root / PARENT / f"{CHILD}.py").write_text("", encoding="utf-8")
    (root / PARENT / f"{CHILD}_extras.py").write_text(
        "raise RuntimeError('sibling failed')\n", encoding="utf-8"
    )
    (root / IMPORTER).mkdir(parents=True)
    (root / IMPORTER / "__init__.py").write_text(
        f"import {PARENT}.{CHILD}_extras\n", encoding="utf-8"
    )
    (root / FROM_IMPORTER).mkdir(parents=True)
    (root / FROM_IMPORTER / "__init__.py").write_text(
        f"from {PARENT} import {CHILD}_extras\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(root))
    yield root
    for name in [m for m in sys.modules if m.startswith("kqpar")]:
        sys.modules.pop(name, None)


def _hiding(shown: Dict[str, str]):
    """The scope a run whose config read the entries of *shown* from the
    environment reads the registry in, and the load redacts with."""
    return masked_module_names(masked_module_scope(shown))


def test_a_traceback_hides_the_leaf_of_a_masked_dotted_name_in_both_lines(
    site, messages
):
    """The import line and the file line print the same longer name, and
    neither prints the masked leaf."""
    record: Dict = {}
    load_additional_plugin_modules(
        [DOTTED], shown=SHOWN, record=record, values=(DOTTED,)
    )
    load_additional_plugin_modules(
        [IMPORTER], shown=SHOWN, record=record, values=(DOTTED,)
    )

    assert sorted(record) == [IMPORTER], sorted(record)
    tracebacks = [m for m in messages if "import failure traceback" in m]
    assert len(tracebacks), messages
    text = tracebacks[0]
    assert f"import {MASK}_extras" in text, text
    assert f"{MASK}_extras.py" in text, text
    assert CHILD not in text, text
    assert PARENT not in text, text


def test_a_traceback_hides_the_leaf_of_a_masked_dotted_name_in_a_from_import(
    site, messages
):
    """The statement under the sibling's file line is a ``from`` import: the
    parent is hidden as a component, and the leaf, followed by ``_extras``, is
    hidden after ``import``."""
    record: Dict = {}
    load_additional_plugin_modules(
        [DOTTED], shown=SHOWN, record=record, values=(DOTTED,)
    )
    load_additional_plugin_modules(
        [FROM_IMPORTER], shown=SHOWN, record=record, values=(DOTTED,)
    )

    assert sorted(record) == [FROM_IMPORTER], sorted(record)
    tracebacks = [m for m in messages if "import failure traceback" in m]
    assert len(tracebacks), messages
    text = tracebacks[0]
    assert f"from {MASK} import {MASK}_extras" in text, text
    assert f"{MASK}_extras.py" in text, text
    assert CHILD not in text, text
    assert PARENT not in text, text


def test_a_from_import_statement_hides_the_leaf_of_a_masked_dotted_name():
    with _hiding(SHOWN):
        text = without_masked_modules(f"from {PARENT} import {CHILD}_extras")

    assert text == f"from {MASK} import {MASK}_extras", text


def test_an_import_error_hides_the_leaf_of_a_masked_dotted_name():
    original = (
        f"ImportError: cannot import name '{CHILD}_extras' from '{PARENT}' "
        f"(/srv/{PARENT}/__init__.py)"
    )
    with _hiding(SHOWN):
        text = without_masked_modules(original)

    assert CHILD not in text, text
    assert PARENT not in text, text
    assert f"cannot import name '{MASK}_extras' from '{MASK}'" in text, text


def test_a_relative_import_hides_the_leaf_of_a_masked_dotted_name():
    with _hiding(SHOWN):
        text = without_masked_modules(f"from .{CHILD}_extras import thing")

    assert text == f"from .{MASK}_extras import thing", text


def test_the_slash_spelling_of_a_masked_dotted_name_is_hidden_inside_a_longer_name():
    with _hiding(SHOWN):
        text = without_masked_modules(f'File "/srv/{PARENT}/{CHILD}_extras.py", line 1')

    assert CHILD not in text, text
    assert f"{MASK}_extras.py" in text, text


def test_the_backslash_spelling_of_a_masked_dotted_name_is_hidden_inside_a_longer_name():
    path = "C:\\srv\\" + PARENT + "\\" + CHILD + "_extras.py"
    with _hiding(SHOWN):
        text = without_masked_modules(f'File "{path}", line 1')

    assert CHILD not in text, text
    assert f"{MASK}_extras.py" in text, text


LONGER_AFTER = [
    pytest.param(
        f"from {PARENT} import other, {CHILD}_extras",
        f"from {MASK} import other, {MASK}_extras",
        id="a later name of a multi-name import",
    ),
    pytest.param(
        f"from {PARENT} import ({CHILD}_extras, other)",
        f"from {MASK} import ({MASK}_extras, other)",
        id="a parenthesized import",
    ),
    pytest.param(
        f"from {PARENT} import (\n    other,\n    {CHILD}_extras,\n)",
        f"from {MASK} import (\n    other,\n    {MASK}_extras,\n)",
        id="a parenthesized import over several lines",
    ),
    pytest.param(
        f"from ...{CHILD}_extras import thing",
        f"from ...{MASK}_extras import thing",
        id="a relative import with three dots",
    ),
    pytest.param(
        f"module '{PARENT}' has no attribute '{CHILD}_extras'",
        f"module '{MASK}' has no attribute '{MASK}_extras'",
        id="an attribute error",
    ),
    pytest.param(
        f"from {PARENT} import  {CHILD}_extras",
        f"from {MASK} import  {MASK}_extras",
        id="two spaces after import",
    ),
    pytest.param(
        f"import\t{CHILD}_extras",
        f"import\t{MASK}_extras",
        id="a tab after import",
    ),
    pytest.param(
        f"from {PARENT} import {CHILD}2",
        f"from {MASK} import {MASK}2",
        id="a name that goes on with a digit",
    ),
    pytest.param(
        f"from {PARENT} import {CHILD}extras",
        f"from {MASK} import {MASK}extras",
        id="a name that goes on with a letter",
    ),
]


@pytest.mark.parametrize("original, expected", LONGER_AFTER)
def test_a_longer_name_that_starts_with_the_leaf_is_hidden_in_every_import_shape(
    original, expected
):
    """The import line and the errors that quote it name a longer sibling of a
    masked leaf in more shapes than ``import <leaf>_x``: a later name of a list, a
    parenthesized or multi-line list, a relative import of any depth, the error
    of a missing attribute, blanks other than one space, and a name that goes on
    with a letter or a digit."""
    with _hiding(SHOWN):
        text = without_masked_modules(original)

    assert CHILD not in text, text
    assert text == expected, text


@pytest.mark.parametrize(
    "entries",
    [(RUN_ENTRY, PREFIX_ENTRY), (PREFIX_ENTRY, RUN_ENTRY)],
    ids=["run entry first", "prefix entry first"],
)
def test_a_run_and_a_prefix_of_one_text_keep_their_own_forms(entries):
    """The inner segment of one masked entry and the parent of another are the
    same text. The first is a needle with the import-line pattern and the second
    is not, so a list that keeps one needle per text keeps whichever entry came
    first, and the other entry's form is lost."""
    shown = dict.fromkeys(entries, MASK)
    with _hiding(shown):
        text = without_masked_modules(f"from {RUN_PARENT} import {SHARED}_extras")

    assert text == f"from {MASK} import {MASK}_extras", text


# --- controls --------------------------------------------------------------------


def test_a_longer_name_that_holds_only_the_parent_stays_readable():
    """The parent is a derived form, hidden as a whole component, so a longer
    name that merely starts with it prints as it is."""
    original = f'File "/srv/{PARENT}_extras/module.py", line 1'
    with _hiding(SHOWN):
        text = without_masked_modules(original)

    assert text == original, text


def test_the_leaf_under_another_parent_stays_readable():
    original = f'File "/srv/kqother_ash_plugins/{CHILD}_extras.py", line 1'
    with _hiding(SHOWN):
        text = without_masked_modules(original)

    assert text == original, text


def test_a_longer_leaf_outside_an_import_stays_readable():
    """The leaf rule is for the import statement and its error, not for any
    text that holds the longer name."""
    original = f"loaded {CHILD}_extras from the cache"
    with _hiding(SHOWN):
        text = without_masked_modules(original)

    assert text == original, text


def test_the_bare_leaf_after_import_is_hidden_as_before():
    with _hiding(SHOWN):
        text = without_masked_modules(f"from {PARENT} import {CHILD}")

    assert text == f"from {MASK} import {MASK}", text


def test_an_unrelated_name_after_import_stays_readable():
    original = f"from {PARENT} import kqother_extras"
    with _hiding(SHOWN):
        text = without_masked_modules(original)

    assert text == f"from {MASK} import kqother_extras", text


def test_unrelated_names_in_a_list_a_relative_import_and_an_error_stay_readable():
    original = (
        f"from {PARENT} import (other, kqother_extras)\n"
        "from ...kqother_extras import thing\n"
        "module 'kqother' has no attribute 'kqother_extras'"
    )
    with _hiding(SHOWN):
        text = without_masked_modules(original)

    assert text == original.replace(PARENT, MASK, 1), text


def test_a_longer_leaf_after_a_word_outside_an_import_stays_readable():
    """The patterns stand after an ``import``, an ``attribute '``, a ``,`` or
    ``(`` and a leading dot, not after any word."""
    original = f"loaded {CHILD}_extras and then {CHILD}2 from the cache"
    with _hiding(SHOWN):
        text = without_masked_modules(original)

    assert text == original, text


def test_a_path_prints_as_it_is_when_nothing_is_masked():
    original = f'File "/srv/{PARENT}/{CHILD}_extras.py", line 1'
    with _hiding({}):
        text = without_masked_modules(original)

    assert text == original, text
