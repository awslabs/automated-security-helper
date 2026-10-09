# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sandbox parity script's scan command is one this CLI accepts.

scripts/verify_sandbox_scanner_parity.py came from main (#757), where
`--fail-on-findings false` is valid. v4's `--fail-on-findings` is a boolean flag
(`--no-fail-on-findings` turns it off), so main's argv exited 2 with "Got unexpected
extra argument(s) (false)" before any scanner ran, and the CI parity job would have
compared two usage errors. This builds the script's real argv and parses it with
the real `ashx scan` command, with the scan itself replaced, so a spelling the CLI
refuses fails here instead of in that job.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "verify_sandbox_scanner_parity.py"


@pytest.fixture
def parity():
    spec = importlib.util.spec_from_file_location("sandbox_parity", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("offline", [True, False])
@pytest.mark.parametrize("mode", ["off", "bwrap", "sandbox-exec"])
def test_the_scan_argv_parses(parity, tmp_path, monkeypatch, mode, offline):
    seen: list[list[str]] = []

    def fake_run(command, **_kwargs):
        seen.append(list(command))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(parity.subprocess, "run", fake_run)
    (tmp_path / "src").mkdir()
    (tmp_path / "out").mkdir()
    parity.run_scan(["ashx"], tmp_path / "src", tmp_path / "out", mode, offline)
    (argv,) = seen
    assert argv[0] == "ashx"
    with patch("automated_security_helper.cli.scan.run_ash_scan") as scan:
        result = CliRunner().invoke(app, argv[1:], env={"COLUMNS": "1000"})
    assert result.exit_code == 0, result.output
    assert scan.called


def test_the_default_command_is_the_canonical_cli(parity):
    from automated_security_helper.cli.deprecations import CANONICAL_CLI_NAME

    assert parity.CLI_NAME == CANONICAL_CLI_NAME
