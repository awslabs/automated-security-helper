# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An environment value equal to a derived module form keeps whole-value redaction.

``load_additional_plugin_modules`` builds the forms of each masked module entry
(its dotted parents, its inner segments, its distribution spelling and its file
names), and those forms are matched only as whole components. The masked entry's
own value is a plain value in a load, hidden wherever it occurs. An environment
value that equals one of the derived forms (a project name that is also an inner
segment of the module path, say) is a plain value too: a longer word that holds it
is hidden, as it is for every other environment value.

Cells: a value equal to an inner segment, to a dotted parent and to the
distribution spelling, each beside a longer word that holds it; and the controls
(the entry's own value is hidden inside a longer word, and a value that equals no
form is hidden inside a longer word).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict

import pytest

MASK = "<value>"
RAISES_FROM_FILE = (
    "import pathlib\n"
    "raise RuntimeError((pathlib.Path(__file__).parent / 'msg.txt')"
    ".read_text(encoding='utf-8'))\n"
)


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "kqenv-site"
    root.mkdir()
    monkeypatch.syspath_prepend(str(root))
    yield root
    for name in [m for m in sys.modules if m.startswith("kqenv")]:
        sys.modules.pop(name, None)


def _plant(root: Path, files: Dict[str, str]) -> None:
    for relative, body in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")


def _recorded(entry: str, values) -> str:
    from automated_security_helper.plugins.loader import (
        load_additional_plugin_modules,
    )

    record: Dict = {}
    load_additional_plugin_modules(
        [entry], shown={entry: MASK}, record=record, values=values
    )
    assert sorted(record) == [entry], sorted(record)
    return record[entry].recorded


def test_a_value_equal_to_an_inner_segment_is_hidden_inside_a_longer_word(site):
    package = "kqenvseg_ash_plugins"
    segment = "kqpayroll_v2"
    entry = f"{package}.{segment}"
    _plant(
        site,
        {
            f"{package}/__init__.py": "",
            f"{package}/{segment}.py": RAISES_FROM_FILE,
            f"{package}/msg.txt": f"{segment}_build",
        },
    )

    recorded = _recorded(entry, (entry, segment))

    assert segment not in recorded, recorded
    assert f"{MASK}_build" in recorded, recorded


def test_a_value_equal_to_a_dotted_parent_is_hidden_inside_a_longer_word(site):
    package = "kqenvpar_ash_plugins"
    entry = f"{package}.kqparchild"
    _plant(
        site,
        {
            f"{package}/__init__.py": "",
            f"{package}/kqparchild.py": RAISES_FROM_FILE,
            f"{package}/msg.txt": f"{package}_extras",
        },
    )

    recorded = _recorded(entry, (entry, package))

    assert package not in recorded, recorded
    assert f"{MASK}_extras" in recorded, recorded


def test_a_value_equal_to_the_distribution_spelling_is_hidden_inside_a_longer_word(
    site,
):
    package = "kqenvdist_ash_plugins"
    distribution = "kqenvdist-ash-plugins"
    _plant(
        site,
        {
            f"{package}/__init__.py": RAISES_FROM_FILE,
            f"{package}/msg.txt": f"{distribution}_build",
        },
    )

    recorded = _recorded(package, (package, distribution))

    assert distribution not in recorded, recorded
    assert f"{MASK}_build" in recorded, recorded


# --- controls --------------------------------------------------------------------


def test_the_entrys_own_value_is_hidden_inside_a_longer_word(site):
    """Control: the value of the entry is the module path, and the load hides
    it wherever it occurs, inside a longer name too."""
    package = "kqenvown_ash_plugins"
    _plant(
        site,
        {
            f"{package}/__init__.py": RAISES_FROM_FILE,
            f"{package}/msg.txt": f"{package} beside {package}_extras",
        },
    )

    recorded = _recorded(package, (package,))

    assert f"{MASK} beside {MASK}_extras" in recorded, recorded
    assert package not in recorded, recorded


def test_a_value_that_equals_no_form_is_hidden_inside_a_longer_word(site):
    """Control: an ordinary environment value, as before."""
    package = "kqenvplain_ash_plugins"
    secret = "kqenvsecret-4417"
    _plant(
        site,
        {
            f"{package}/__init__.py": RAISES_FROM_FILE,
            f"{package}/msg.txt": f"{secret}_tail",
        },
    )

    recorded = _recorded(package, (package, secret))

    assert secret not in recorded, recorded
    assert f"{MASK}_tail" in recorded, recorded
