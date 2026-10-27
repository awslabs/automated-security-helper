# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--exclude-scanners`` with no allowlist is accepted, through the real path.

``selection_after_exclusions`` refuses only a NON-empty allowlist that the
exclusions cancel; an empty allowlist comes back empty before any comparison
(``if not enabled or not excluded``), and the exclusions narrow the run in
ScanPhase. The engine calls the helper unguarded on every scan, so this pins
the measured behavior where it runs: the engine is built (and the selection
resolved) in the orchestrator before ``execute_scan``, which the harness stops
at, so no scanner starts.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app


@pytest.fixture
def project(tmp_path, monkeypatch):
    root = tmp_path / "demo"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.chdir(root)
    return root


def _scan(root, monkeypatch, *selection_args):
    reached = []

    def _stop(*_args, **_kwargs):
        # Past the engine build: the selection was accepted. Exit here so no
        # scanner runs.
        reached.append(True)
        raise SystemExit(0)

    monkeypatch.setattr(
        "automated_security_helper.core.orchestrator.ASHScanOrchestrator.execute_scan",
        _stop,
    )
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "local",
            "--no-progress",
            "--source-dir",
            str(root),
            "--output-dir",
            str(root.parent / "out"),
            *selection_args,
        ],
    )
    return bool(reached), result


def test_an_exclusion_with_no_allowlist_is_accepted(project, monkeypatch):
    reached, result = _scan(project, monkeypatch, "--exclude-scanners", "bandit")

    assert reached, (result.exit_code, result.output[-1500:])


def test_the_control_a_cancelled_selection_is_refused(project, monkeypatch):
    """The control: the same path refuses when the exclusions cancel the whole
    allowlist, so the acceptance above is the guard's answer, not a dead check."""
    reached, result = _scan(
        project,
        monkeypatch,
        "--scanners",
        "bandit",
        "--exclude-scanners",
        "bandit",
    )

    assert not reached, result.output[-1500:]
    assert "cancels itself" in " ".join(result.output.split()), result.output[-1500:]
