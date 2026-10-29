# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The variables an ``extends`` entry reads and the entries the chain follows
come from one classification.

The stock reader decides what an ``extends`` entry reads: a plain or tagged
YAML reference resolves, a JSON string and a quoted YAML scalar never do.
``_extends_refs_shown`` classifies the entries that way, and the names the
container is handed (``operator_environment_names``) come from the same
classification, so a variable the file never reads is neither passed into the
container nor a reason to refuse the scan. Equal entry counts do not prove the
written and the resolved entries line up: a key the environment spells as
``extends`` replaces the written list.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import (
    ContainerInputError,
)
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

#: A name ASH reads as its own setting: a container scan refuses a config
#: file that reads it.
REFUSED_VAR = "ASH_SCANNERS"
OPERATOR_VAR = "ASH_EXTENDS_CELL_OPERATOR_BASE"


@pytest.fixture
def layout(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    source = repo / "src"
    source.mkdir()
    (source / "a.py").write_text("x = 1\n", encoding="utf-8")
    for name in (REFUSED_VAR, OPERATOR_VAR, "ASH_EXTENDS_CELL_KEY"):
        monkeypatch.delenv(name, raising=False)
    return {"w": tmp_path, "source": source}


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _names(layout, config: Path):
    return rac.operator_environment_names(str(config), None, layout["source"])


@pytest.mark.parametrize(
    ("file_name", "text", "base_name"),
    [
        (
            "ash.json",
            '{"project_name": "op", "extends": ["${' + REFUSED_VAR + '}"]}',
            "${" + REFUSED_VAR + "}",
        ),
        (
            "ash.yaml",
            'project_name: op\nextends:\n  - "${' + REFUSED_VAR + '}"\n',
            "${" + REFUSED_VAR + "}",
        ),
        (
            "ash.json",
            '{"project_name": "op", "extends": ["!ENV ${' + REFUSED_VAR + '}"]}',
            "!ENV ${" + REFUSED_VAR + "}",
        ),
    ],
    ids=["json-reference", "quoted-yaml-reference", "json-tagged-reference"],
)
def test_an_entry_the_stock_reader_keeps_literal_names_no_variable(
    layout, monkeypatch, file_name, text, base_name
):
    """The must-not side: the entry is a literal path, read exactly as the
    scan inside reads it, so the variable it spells is not passed and is not a
    reason to refuse the scan."""
    monkeypatch.setenv(REFUSED_VAR, "set-by-the-operator")
    _write(layout["w"] / base_name, "project_name: base\n")
    config = _write(layout["w"] / file_name, text)

    assert _names(layout, config) == []


@pytest.mark.parametrize(
    "entry",
    ["${" + OPERATOR_VAR + "}", "!ENV ${" + OPERATOR_VAR + "}"],
    ids=["plain-reference", "tagged-reference"],
)
def test_an_entry_the_stock_reader_resolves_names_its_variable(
    layout, monkeypatch, entry
):
    """The must-flag twin: a plain or tagged YAML reference reads the
    environment, so its variable is passed."""
    monkeypatch.setenv(OPERATOR_VAR, "env_base.yaml")
    _write(layout["w"] / "env_base.yaml", "project_name: env\n")
    config = _write(
        layout["w"] / "ash.yaml", "project_name: op\nextends:\n  - " + entry + "\n"
    )

    assert _names(layout, config) == [OPERATOR_VAR]


def test_a_resolved_entry_reading_a_refused_name_refuses_the_scan(layout, monkeypatch):
    monkeypatch.setenv(REFUSED_VAR, "env_base.yaml")
    _write(layout["w"] / "env_base.yaml", "project_name: env\n")
    config = _write(
        layout["w"] / "ash.yaml",
        "project_name: op\nextends:\n  - ${" + REFUSED_VAR + "}\n",
    )

    with pytest.raises(ContainerInputError, match=REFUSED_VAR):
        _names(layout, config)


def test_an_extends_key_the_environment_spells_names_its_variable(layout, monkeypatch):
    """No ``extends`` is written: the environment spells the key, so the
    written and resolved lists differ in length and carry no pairing. The
    entry names no variable itself; the variable that spells the key is still
    passed, through the references the document records."""
    monkeypatch.setenv("ASH_EXTENDS_CELL_KEY", "extends")
    _write(layout["w"] / "b.yaml", "project_name: b\n")
    config = _write(layout["w"] / "ash.yaml", "${ASH_EXTENDS_CELL_KEY}: b.yaml\n")

    assert _names(layout, config) == ["ASH_EXTENDS_CELL_KEY"]


def test_a_key_the_environment_spells_as_extends_is_not_paired_by_position(
    layout, monkeypatch
):
    """``extends: a.yaml`` then ``${K}: b.yaml`` with K=extends: the stock
    reader's last key wins, so the base is ``b.yaml``. Both lists hold one
    entry, and pairing them by position would quote ``a.yaml`` for it."""
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    monkeypatch.setenv("ASH_EXTENDS_CELL_KEY", "extends")
    _write(layout["w"] / "a.yaml", "project_name: a\n")
    _write(layout["w"] / "b.yaml", "project_name: b\n")
    config = _write(
        layout["w"] / "ash.yaml",
        "extends: a.yaml\n${ASH_EXTENDS_CELL_KEY}: b.yaml\n",
    )

    entries = rac._extends_refs_shown(config)

    assert entries == [("b.yaml", ENVIRONMENT_VALUE_SHOWN, True)], entries


def test_a_reference_spelled_key_in_a_format_that_never_interpolates_is_text(
    layout, monkeypatch
):
    """The must-not twin: in JSON the resolution leaves every key alone, so a
    key that looks like a reference changes nothing and the entries still pair
    by position."""
    monkeypatch.setenv("ASH_EXTENDS_CELL_KEY", "extends")
    _write(layout["w"] / "a.yaml", "project_name: a\n")
    config = _write(
        layout["w"] / "ash.json",
        '{"${ASH_EXTENDS_CELL_KEY}": "x", "extends": ["a.yaml"]}',
    )

    assert rac._extends_refs_shown(config) == [("a.yaml", "a.yaml", False)]
