# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash config lint --source-dir`` looks for the report only where it is read.

Why this file exists
--------------------
With ``--source-dir`` the command looked for the unused-suppressions report in
the scanned tree before it checked its config. The lookup reads the config (the
report is named by the config's reporter section), so a config that is missing,
a FIFO or unreadable was opened by the lookup before the checks that give the
documented exit 3, and every lint of a tree paid for a read of the config that
only ``--fix-unused`` uses. The lookup now runs after those checks, for a regular
config file, and only with ``--fix-unused``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.config import config_app
from automated_security_helper.config.config_linter import ConfigLinter

pytestmark = pytest.mark.unit

INVALID_CONFIG_EXIT = 3


@pytest.fixture(autouse=True)
def _no_ambient_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_SOURCE_DIR", raising=False)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)


@pytest.fixture
def lookups(monkeypatch: pytest.MonkeyPatch) -> List[Any]:
    """The calls made to the report lookup, which finds no report."""
    calls: List[Any] = []

    def lookup(*args: Any, **kwargs: Any):
        calls.append(args)
        return None, None

    monkeypatch.setattr(ConfigLinter, "find_unused_report", staticmethod(lookup))
    return calls


def _invoke(args):
    return CliRunner().invoke(config_app, args)


def test_a_plain_lint_of_a_tree_does_not_look_for_the_report(tmp_path, lookups):
    """Red at the base: the lookup ran for every lint that named --source-dir."""
    config = tmp_path / ".ashrc.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")

    result = _invoke(["lint", "--config", str(config), "--source-dir", str(tmp_path)])

    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert lookups == []


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="the platform has no FIFOs")
def test_a_config_that_is_a_fifo_is_refused_before_the_lookup(tmp_path, lookups):
    """Red at the base: the lookup, which reads the config, ran first."""
    fifo = tmp_path / ".ashrc.yaml"
    os.mkfifo(fifo)

    result = _invoke(
        [
            "lint",
            "--config",
            str(fifo),
            "--source-dir",
            str(tmp_path),
            "--fix-unused",
        ]
    )

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert lookups == []


def test_a_missing_config_is_refused_before_the_lookup(tmp_path, lookups):
    result = _invoke(
        [
            "lint",
            "--config",
            str(tmp_path / "missing.yaml"),
            "--source-dir",
            str(tmp_path),
            "--fix-unused",
        ]
    )

    assert result.exit_code != 0, result.output
    assert lookups == []


def test_fix_unused_of_a_regular_config_still_looks_in_the_tree(tmp_path, lookups):
    """The positive control: the lookup is still made where the report is read,
    in the scanned tree's output directory."""
    config = tmp_path / ".ashrc.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")

    result = _invoke(
        [
            "lint",
            "--config",
            str(config),
            "--source-dir",
            str(tmp_path),
            "--fix-unused",
            "-y",
        ]
    )

    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert len(lookups) == 1
    assert Path(lookups[0][0]) == config
