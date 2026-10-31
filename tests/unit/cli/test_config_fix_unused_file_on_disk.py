# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash config lint --fix-unused`` leaves a list it cannot edit as it is on disk.

Why this file exists
--------------------
The fixer tests for a list it refuses (a flow sequence, a repeated key) call a
pure function that returns text or raises, and then assert the file is
unchanged. That function never writes, so the assertion cannot fail. The file
is written by the command, so the check belongs here: run the command on a
config whose list the fixer cannot edit and compare the bytes on disk, and run
the same command on a list it can edit, so that "unchanged" cannot also be the
answer to a report that was never found.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.config import config_app

pytestmark = pytest.mark.unit

ENTRY = {"path": "src/a.py", "rule_id": "B101", "reason": "one"}

BLOCK_LIST = (
    "project_name: demo\n"
    "global_settings:\n"
    "  suppressions:\n"
    "    - path: src/a.py\n"
    "      rule_id: B101\n"
    "      reason: one\n"
)
FLOW_LIST = (
    "project_name: demo\n"
    "global_settings:\n"
    "  suppressions: [{path: src/a.py, rule_id: B101, reason: one}]\n"
)


def _run(tmp_path: Path, monkeypatch, config_text: str):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / ".ash" / ".ash.yaml"
    config.parent.mkdir(parents=True)
    # Bytes, so the file holds the text as written on Windows too.
    config.write_bytes(config_text.encode("utf-8"))
    reports = tmp_path / ".ash" / "ash_output" / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.unused-suppressions.json").write_text(
        json.dumps({"unused_suppressions": [ENTRY]}), encoding="utf-8"
    )
    result = CliRunner().invoke(
        config_app, ["lint", "--config", str(config), "--fix-unused"], input="y\n"
    )
    return config, result


def test_a_list_the_fixer_cannot_edit_is_left_as_it_is_on_disk(tmp_path, monkeypatch):
    config, result = _run(tmp_path, monkeypatch, FLOW_LIST)

    assert result.exception is None or isinstance(result.exception, SystemExit), repr(
        result.exception
    )
    assert config.read_bytes() == FLOW_LIST.encode("utf-8"), result.output


def test_a_list_the_fixer_can_edit_is_changed_on_disk(tmp_path, monkeypatch):
    """The positive control: the same report and command on a block list
    comment the listed entry out, so the file above was left alone because the
    fixer refused the list and not because nothing was found."""
    config, result = _run(tmp_path, monkeypatch, BLOCK_LIST)

    assert result.exception is None or isinstance(result.exception, SystemExit), repr(
        result.exception
    )
    assert "# - path: src/a.py" in config.read_text(encoding="utf-8"), result.output
