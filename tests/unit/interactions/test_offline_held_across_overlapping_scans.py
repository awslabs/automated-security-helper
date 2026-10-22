# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two overlapping offline scans in one process: the second stays offline after the first ends.

``_run_local_mode`` and ``_run_workspace_mode`` set ``ASH_OFFLINE=YES`` for an offline
scan and put back what they saw when it ends. With two of them overlapping, the first to
end restored "unset" while the other was still running, so the rest of that scan read
online mode (secret verification permitted, none of the offline tool variables on its
spawns, trivy's Terraform checks back on, npm-audit auditing against the registry). And
the last to end restored "YES", so the process stayed offline.

These run two real call sites at once, each blocked inside the call it makes, and let
the first one finish while the second is still inside.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from automated_security_helper.interactions import run_ash_scan as run_ash_scan_module
from automated_security_helper.interactions.run_ash_scan import ScanOptions

WAIT = 30


class _Blocker:
    """Lets a call site enter its callee, then holds it there until released."""

    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.seen = None

    def __call__(self, *args, **kwargs):
        self.seen = os.environ.get("ASH_OFFLINE")
        self.entered.set()
        assert self.release.wait(WAIT), "the test never released this call"
        raise RuntimeError("stubbed callee")


def _in_thread(target):
    errors = []

    def run():
        try:
            target()
        except BaseException as exc:  # SystemExit from the call site's own handler
            errors.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


@pytest.fixture
def stubs(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    local = _Blocker()
    workspace = _Blocker()
    from automated_security_helper.core import orchestrator
    from automated_security_helper.workspace import execution

    monkeypatch.setattr(orchestrator.ASHScanOrchestrator, "create", local)
    monkeypatch.setattr(execution, "execute_workspace", workspace)
    monkeypatch.setattr(
        run_ash_scan_module, "build_project_scan_settings", lambda opts: None
    )
    return local, workspace


def _local(tmp_path: Path):
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    opts = ScanOptions(
        source_dir=source, output_dir=tmp_path / "out", offline=True, quiet=True
    )
    return lambda: run_ash_scan_module._run_local_mode(opts, MagicMock())


def _workspace():
    opts = SimpleNamespace(offline=True, workspace_plan=object())
    return lambda: run_ash_scan_module._run_workspace_mode(opts, MagicMock())


def test_a_workspace_scan_stays_offline_after_a_local_scan_ends(stubs, tmp_path):
    local, workspace = stubs
    first = _in_thread(_local(tmp_path))
    assert local.entered.wait(WAIT)
    second = _in_thread(_workspace())
    assert workspace.entered.wait(WAIT)

    local.release.set()
    first.join(WAIT)

    assert os.environ.get("ASH_OFFLINE") == "YES", (
        "the first scan to end took offline mode away from the one still running"
    )

    workspace.release.set()
    second.join(WAIT)

    assert "ASH_OFFLINE" not in os.environ, "the process stayed offline afterwards"


def test_a_local_scan_stays_offline_after_a_workspace_scan_ends(stubs, tmp_path):
    local, workspace = stubs
    first = _in_thread(_workspace())
    assert workspace.entered.wait(WAIT)
    second = _in_thread(_local(tmp_path))
    assert local.entered.wait(WAIT)

    workspace.release.set()
    first.join(WAIT)

    assert os.environ.get("ASH_OFFLINE") == "YES"

    local.release.set()
    second.join(WAIT)

    assert "ASH_OFFLINE" not in os.environ


def test_control_each_scan_ran_offline(stubs, tmp_path):
    local, workspace = stubs
    thread = _in_thread(_local(tmp_path))
    assert local.entered.wait(WAIT)
    local.release.set()
    thread.join(WAIT)

    assert local.seen == "YES"
    assert "ASH_OFFLINE" not in os.environ
