"""``ash config update --set 'KEY-=[...]'`` logs the removal by the key it edited.

``update`` logs one line for each ``--set``, naming the key and never the value,
which can be a credential: ``KEY=...`` is "Applied a modification to KEY" and
``KEY+=...`` is "Appended to KEY". A ``KEY-=...`` is "Removed from KEY", the key
without its operator, and the file the command writes no longer holds the items it
removed.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

KEY = "global_settings.ignore_paths"

#: A file holding two ignore paths.
CONFIG = """\
project_name: removal-demo
global_settings:
  ignore_paths:
    - path: dist/**
      reason: build output
    - path: build/**
      reason: build output
"""

#: The first ignore path as the loaded configuration holds it. A removal takes out
#: each entry equal to an item, and a loaded entry holds every field of an ignore
#: path, the two the file left to their defaults included, so the item names each
#: field.
DIST_ENTRY = (
    '{"path": "dist/**", "reason": "build output", "expires": null, '
    '"client_supplied": false}'
)

#: An ignore path the file does not hold, for the append.
OUT_ENTRY = '{"path": "out/**", "reason": "build output"}'


@pytest.fixture
def info_records(capture):
    """ASH's log records at INFO and above (``capture`` routes the logger into
    caplog, at WARNING)."""
    capture.set_level(logging.INFO, logger="ash")
    return capture


def _update(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, setting: str):
    """Run ``ash config update`` with one ``--set`` on a fresh copy of CONFIG."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / "ash.yaml"
    path.write_text(CONFIG, encoding="utf-8")
    result = CliRunner().invoke(
        app, ["config", "update", "--config", str(path), "--set", setting]
    )
    return path, result


def _ignore_paths(path: Path) -> list:
    """The ignore paths the written file holds."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    return document["global_settings"]["ignore_paths"]


def _messages(records, text: str) -> list:
    """The messages of the captured records that hold ``text``."""
    return [
        record.getMessage() for record in records.records if text in record.getMessage()
    ]


def test_a_removal_is_logged_as_removed_from_its_key(
    tmp_path, monkeypatch, info_records
):
    path, result = _update(tmp_path, monkeypatch, f"{KEY}-=[{DIST_ENTRY}]")

    assert result.exit_code == 0, result.output
    assert len(_messages(info_records, f"Removed from {KEY}")) == 1
    assert _messages(info_records, "Applied a modification to") == []
    assert _ignore_paths(path) == [{"path": "build/**", "reason": "build output"}]


def test_an_append_is_still_logged_as_appended(tmp_path, monkeypatch, info_records):
    """Control: the append's line and what it writes are as before, and it logs no
    removal."""
    path, result = _update(tmp_path, monkeypatch, f"{KEY}+=[{OUT_ENTRY}]")

    assert result.exit_code == 0, result.output
    assert len(_messages(info_records, f"Appended to {KEY}")) == 1
    assert _messages(info_records, "Removed from") == []
    assert _ignore_paths(path) == [
        {"path": "dist/**", "reason": "build output"},
        {"path": "build/**", "reason": "build output"},
        {"path": "out/**", "reason": "build output"},
    ]
