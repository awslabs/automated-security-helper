# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash plugin list`` refuses an ``ash_plugin_modules`` entry outside the namespace.

The commands that read a config's ``ash_plugin_modules`` through ``load_plugins``
(``plugin list``, ``report``, ``merge``, ``dependencies install``) refuse such an
entry with exit 3, as a scan does, so a misspelled plugin package never lists
none of its plugins while the command reports success. ``load_plugins`` refuses
the entry before any
import, and each command's existing configuration-error handler gives the exit 3.
"""

from __future__ import annotations

import sys

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

WORDS = "is not a plugin module ASH imports"

OUTSIDE = "outside_module"
BESIDE = "beside_ash_plugins"


@pytest.fixture
def planted_modules(tmp_path, monkeypatch):
    """Two importable modules on sys.path, each writing a marker when imported."""
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    modules = tmp_path / "modules"
    modules.mkdir()
    for name in (OUTSIDE, BESIDE):
        (modules / f"{name}.py").write_text(
            "from pathlib import Path\n"
            "Path(__file__).with_suffix('.imported').write_text('ran')\n"
        )
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.syspath_prepend(str(modules))
    yield modules
    for name in (OUTSIDE, BESIDE):
        sys.modules.pop(name, None)


def test_plugin_list_refuses_it_with_exit_3_and_imports_nothing(planted_modules):
    result = CliRunner().invoke(
        app, ["plugin", "list", "--ash-plugin-modules", f"{OUTSIDE},{BESIDE}"]
    )

    assert result.exit_code == 3, result.output
    assert WORDS in result.output, result.output
    assert OUTSIDE not in sys.modules
    assert BESIDE not in sys.modules
    assert not (planted_modules / f"{OUTSIDE}.imported").exists()
    assert not (planted_modules / f"{BESIDE}.imported").exists()


def test_plugin_list_accepts_a_namespace_module(planted_modules):
    result = CliRunner().invoke(app, ["plugin", "list", "--ash-plugin-modules", BESIDE])

    assert WORDS not in result.output, result.output
    assert result.exit_code == 0, result.output
    assert (planted_modules / f"{BESIDE}.imported").exists()
