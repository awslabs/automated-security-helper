# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A named config whose stat is denied exits 3, the code for a config that
cannot be read.

The commands asked `Path.exists()` whether the named file is there. Before
Python 3.14 that raises the stat's PermissionError (a directory above the
file that cannot be searched) instead of answering, so the command ended in a
traceback and exit 1 where its help documents exit 3 for a config that cannot
be read. At the tip the one stat is classified by its own error and the
command says the file cannot be read; at the base no command prints that
refusal (the stat's error escapes, or, where pathlib bound ``os.stat`` at
import, the file reads as present and the command goes on).
"""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.config import INVALID_CONFIG_EXIT_CODE, config_app

pytestmark = pytest.mark.unit


@pytest.fixture
def denied_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A config file whose own stat is denied; every other path is stat as usual."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / ".ash.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")
    denied = os.fspath(config)
    real_stat = os.stat

    def stat_unless_denied(path, *args, **kwargs):
        if isinstance(path, (str, os.PathLike)) and os.fspath(path) == denied:
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), denied)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", stat_unless_denied)
    return config


@pytest.mark.parametrize(
    "command",
    ["get", "update", "validate", "validate-plugin-dependencies", "lint", "init"],
)
def test_a_denied_stat_of_the_named_config_exits_3(
    denied_config: Path, command: str
) -> None:
    result = CliRunner().invoke(config_app, [command, "--config", str(denied_config)])

    assert result.exit_code == INVALID_CONFIG_EXIT_CODE, result.output
    assert "cannot be read" in result.output
    assert "EACCES" in result.output
