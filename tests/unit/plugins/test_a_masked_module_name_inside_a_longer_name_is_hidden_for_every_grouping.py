# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A masked module name inside a longer name is hidden, however the modules are grouped.

A module a config read from the environment is named by its mask, and a text a
failed import prints never holds its value. A scan loads its operator modules in
one call and every other module in a call of its own, and a workspace run does
the same. The load used to drop the masked entry's own value from the values it
redacts with whenever the entry was in the same call as the failing module, and
to keep it otherwise. A module that failed on a longer name holding the masked
value (``<name>_extras``) therefore printed that name in clear in the recorded
text and the WARNING line when the two modules loaded together, and hid it when
they loaded one at a time. The refusal hid it either way.

The load now hides the value of every masked entry wherever it occurs, inside a
longer name too, whatever the grouping and whatever values the caller passes.

A dotted masked entry (``<parent>.<child>``) is hidden in its derived spellings
too, and those do not depend on the grouping either: a literal module that fails
on the entry's parent package prints the parent in no grouping, including the
one where the entry is loaded in a call of its own and the literal module in
another.

Cells: the masked module and a literal module together; the same two loaded one
per call; the two groupings side by side; a caller that passes no values; the
parent of a dotted masked entry, loaded in separate calls and together; and, as
a control, a longer name when nothing is masked.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

import pytest

from automated_security_helper.plugins.loader import (
    PluginModuleImportError,
    load_additional_plugin_modules,
    refuse_failed_plugin_imports,
)
from automated_security_helper.utils.log import ASH_LOGGER

MASK = "<value>"
MASKED = "kqgrpmasked_ash_plugins"
LITERAL = "kqgrplit_ash_plugins"
LONGER = f"{MASKED}_extras"


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
    """A planted sys.path entry: the masked module imports fine, and the literal
    module fails on a module named after the masked one plus a suffix."""
    root = tmp_path / "grouping-site"
    (root / MASKED).mkdir(parents=True)
    (root / MASKED / "__init__.py").write_text("", encoding="utf-8")
    (root / LITERAL).mkdir(parents=True)
    (root / LITERAL / "__init__.py").write_text(f"import {LONGER}\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(root))
    yield root
    for name in [m for m in sys.modules if m.startswith("kqgrp")]:
        sys.modules.pop(name, None)


def _load(
    groups: Sequence[Sequence[str]],
    messages: List[str],
    values: Sequence[str],
    shown: Dict[str, str],
) -> Tuple[str, str, str]:
    """Load each group in one call, as a scan loads its modules, then refuse as
    the scan does. Returns the three texts a failure reaches: the recorded text,
    the WARNING line and the refusal."""
    record: Dict = {}
    names = [name for group in groups for name in group]
    for group in groups:
        load_additional_plugin_modules(
            list(group), shown=shown, record=record, values=tuple(values)
        )
    assert sorted(record) == [LITERAL], sorted(record)
    warnings = [m for m in messages if "Failed to import plugin module" in m]
    assert len(warnings) == 1, warnings
    with pytest.raises(PluginModuleImportError) as refused:
        refuse_failed_plugin_imports(names, record, shown=shown)
    return record[LITERAL].recorded, warnings[0], str(refused.value)


def _assert_hidden(texts: Tuple[str, str, str]) -> None:
    for text in texts:
        assert MASKED not in text, text
        assert f"{MASK}_extras" in text, text


def test_modules_loaded_together_hide_the_masked_name_inside_a_longer_name(
    site, messages
):
    texts = _load([[MASKED, LITERAL]], messages, values=(MASKED,), shown={MASKED: MASK})

    _assert_hidden(texts)


def test_modules_loaded_one_per_call_hide_the_masked_name_inside_a_longer_name(
    site, messages
):
    texts = _load(
        [[MASKED], [LITERAL]], messages, values=(MASKED,), shown={MASKED: MASK}
    )

    _assert_hidden(texts)


def test_both_groupings_print_the_same_texts(site, messages):
    together = _load(
        [[MASKED, LITERAL]], messages, values=(MASKED,), shown={MASKED: MASK}
    )
    messages.clear()
    sys.modules.pop(LITERAL, None)
    separately = _load(
        [[MASKED], [LITERAL]], messages, values=(MASKED,), shown={MASKED: MASK}
    )

    assert together == separately


def test_the_load_hides_a_masked_name_whatever_values_the_caller_passes(site, messages):
    """The entry's own value is hidden because the entry is masked, not because
    the caller listed it among the environment values."""
    texts = _load([[MASKED, LITERAL]], messages, values=(), shown={MASKED: MASK})

    _assert_hidden(texts)


# --- the parent of a dotted masked entry -------------------------------------------

PARENT = "kqgrpprt_ash_plugins"
DOTTED = f"{PARENT}.kqgrpprtsub"
IMPORTER = "kqgrpprtlit_ash_plugins"
ABSENT = "kqgrpabsent"


@pytest.fixture
def dotted_site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A masked dotted entry that imports fine, and a literal module whose
    import fails on a name the entry's parent package does not define."""
    root = tmp_path / "grouping-dotted-site"
    (root / PARENT).mkdir(parents=True)
    (root / PARENT / "__init__.py").write_text("", encoding="utf-8")
    (root / PARENT / "kqgrpprtsub.py").write_text("", encoding="utf-8")
    (root / IMPORTER).mkdir(parents=True)
    (root / IMPORTER / "__init__.py").write_text(
        f"from {PARENT} import {ABSENT}\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(root))
    yield root
    for name in [m for m in sys.modules if m.startswith("kqgrpprt")]:
        sys.modules.pop(name, None)


def _load_dotted(
    groups: Sequence[Sequence[str]], messages: List[str]
) -> Tuple[str, str, str]:
    """The recorded text, the WARNING line and the refusal of the literal
    module's failure, with the dotted entry masked and its value passed."""
    shown = {DOTTED: MASK}
    record: Dict = {}
    for group in groups:
        load_additional_plugin_modules(
            list(group), shown=shown, record=record, values=(DOTTED,)
        )
    assert sorted(record) == [IMPORTER], sorted(record)
    warnings = [m for m in messages if "Failed to import plugin module" in m]
    assert len(warnings) == 1, warnings
    with pytest.raises(PluginModuleImportError) as refused:
        refuse_failed_plugin_imports([DOTTED, IMPORTER], record, shown=shown)
    return record[IMPORTER].recorded, warnings[0], str(refused.value)


def _assert_parent_hidden(texts: Tuple[str, str, str]) -> None:
    for text in texts:
        # The text is printed, so a hidden parent is not an empty text.
        assert ABSENT in text, text
        assert PARENT not in text, text


def test_modules_loaded_in_separate_calls_hide_the_parent_of_a_masked_dotted_name(
    dotted_site, messages
):
    """The entry is loaded in a call of its own, so the literal module's call
    does not list it: its parent is hidden because the run masks the entry."""
    texts = _load_dotted([[DOTTED], [IMPORTER]], messages)

    _assert_parent_hidden(texts)


def test_modules_loaded_together_hide_the_parent_of_a_masked_dotted_name(
    dotted_site, messages
):
    texts = _load_dotted([[DOTTED, IMPORTER]], messages)

    _assert_parent_hidden(texts)


# --- controls --------------------------------------------------------------------


def test_a_longer_name_prints_unchanged_when_nothing_is_masked(site, messages):
    texts = _load([[MASKED, LITERAL]], messages, values=(), shown={})

    for text in texts:
        assert LONGER in text, text
        assert MASK not in text, text
