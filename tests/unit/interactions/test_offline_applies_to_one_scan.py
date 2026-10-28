# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--offline`` makes one scan offline, and the next scan in the process is online.

The offline guide says so, and nothing held it: _run_local_mode sets ASH_OFFLINE
for the scan and restores the previous value afterwards, so an in-process caller
(the MCP server, a test, a script calling run_ash_scan twice) does not inherit
offline mode from an earlier scan. The phases are stubbed out, so no scanner runs
and nothing reaches the network either way.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core import execution_engine
from automated_security_helper.core.constants import is_offline_mode
from automated_security_helper.models.asharp_model import AshAggregatedResults
from tests.utils.env_assertions import environ_names, environ_value


@pytest.fixture
def observed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list:
    """What each scan saw while its phases ran: ASH_OFFLINE and is_offline_mode()."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "home" / "bin"))
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    seen: list = []

    def _record(self, phases=None):
        seen.append((os.environ.get("ASH_OFFLINE"), is_offline_mode()))
        return AshAggregatedResults()

    monkeypatch.setattr(execution_engine.ScanExecutionEngine, "execute_phases", _record)
    return seen


def _scan(*args: str):
    return CliRunner().invoke(
        app, ["scan", "--source-dir", "src", "--output-dir", "out", *args]
    )


def test_the_scan_after_an_offline_scan_is_online(observed):
    first = _scan("--offline")
    second = _scan()

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert observed == [("YES", True), (None, False)]
    assert "ASH_OFFLINE" not in environ_names()


def test_an_offline_setting_the_process_started_with_is_kept(observed, monkeypatch):
    """Restored, not removed: ASH_OFFLINE=YES from the environment survives the scan."""
    monkeypatch.setenv("ASH_OFFLINE", "YES")

    assert _scan("--offline").exit_code == 0
    assert _scan().exit_code == 0

    assert [offline for _, offline in observed] == [True, True]
    assert environ_value("ASH_OFFLINE") == "YES"
