# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A BaseException from a plugin module's import propagates, unrecorded.

The loader's import arm catches ``Exception``, not ``BaseException``: a
configured module whose body raises SystemExit or KeyboardInterrupt at import
is asking the process to stop, and recording it as an import failure would
turn a stop into an exit-3 configuration refusal. These cells pin the class
boundary; without them, widening the arm to BaseException passes every
refusal cell.
"""

from __future__ import annotations

import sys

import pytest

from automated_security_helper.plugins.loader import load_additional_plugin_modules


@pytest.fixture
def raising_module(tmp_path, monkeypatch):
    def plant(name: str, source: str) -> str:
        site = tmp_path / "site"
        (site / name).mkdir(parents=True)
        (site / name / "__init__.py").write_text(source, encoding="utf-8")
        monkeypatch.syspath_prepend(str(site))
        monkeypatch.delitem(sys.modules, name, raising=False)
        return name

    yield plant
    for name in list(sys.modules):
        if name.startswith("zqbase"):
            del sys.modules[name]


def test_a_system_exit_at_import_propagates_unrecorded(raising_module):
    name = raising_module("zqbaseexit_ash_plugins", "raise SystemExit(7)\n")
    record: dict = {}

    with pytest.raises(SystemExit):
        load_additional_plugin_modules([name], record=record)

    assert record == {}, record


def test_a_keyboard_interrupt_at_import_propagates_unrecorded(raising_module):
    name = raising_module("zqbaseint_ash_plugins", "raise KeyboardInterrupt\n")
    record: dict = {}

    with pytest.raises(KeyboardInterrupt):
        load_additional_plugin_modules([name], record=record)

    assert record == {}, record
