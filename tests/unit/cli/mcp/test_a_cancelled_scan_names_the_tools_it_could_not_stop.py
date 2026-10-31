# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cancelled scan's progress names the scanner tools its stop could not end.

``cancel_scan`` closes the registry entry as CANCELLED at once. The scan itself
stops at its next check, and the ``ScanCancelled`` that ends it carries, as
``could_not_stop``, the ``(tool, pid)`` pairs of the tools a stop could not end
(core/cancellation.py). The runner's ``except ScanCancelled`` arm is the only
place that sees both the closed entry and those pairs; ``finish_scan`` leaves a
closed entry alone by design, so without a path of its own the pairs were
dropped and a cancel whose tool kept running read back as a clean one.

The runner is driven for real over a stand-in scan that cancels itself through
the registry, as a client's ``cancel_scan`` would, and then ends the way the
real scan ends: with a ``ScanCancelled`` naming one tool it could not stop. The
progress reply must name that tool and its process id; a cancel whose
exception names no tool must add no warning.

Every test here is disarmed: the scan is the stand-in defined here, the output
directory is the test's own tmp_path, and no process is started.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Tuple
from unittest.mock import patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.interactions import run_ash_scan as ras

pytestmark = pytest.mark.unit

_TOOLS = "automated_security_helper.cli.mcp_tools"
#: Far past any test, so a test that fails early cannot leave a thread behind.
SETTLE_SECONDS = 30.0


async def _run_a_scan_that_is_cancelled_mid_run(
    tmp_path: Path, monkeypatch, could_not_stop: Tuple[Tuple[str, int], ...]
):
    """Run the real runner over a scan that is cancelled while it runs and
    ends with a ``ScanCancelled`` carrying ``could_not_stop``.

    Returns the registry and the scan id once the runner has returned and the
    scan's thread has settled.
    """
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    output_dir = tmp_path / ".ash" / "ash_output"
    output_dir.mkdir(parents=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path), output_directory=str(output_dir)
    )

    def a_scan_cancelled_while_it_runs(*args: Any, **kwargs: Any) -> None:
        # The client's cancel lands while the scan runs: the entry is closed
        # as CANCELLED and its cancel event set, exactly as cancel_scan does.
        assert registry.cancel_scan(scan_id) is True
        # The scan's next check ends it, naming what the stop could not end.
        raise ScanCancelled("the scan was cancelled", could_not_stop=could_not_stop)

    with (
        patch.object(ras, "run_ash_scan", a_scan_cancelled_while_it_runs),
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
    ):
        await mcp_tools._run_scan_async(
            scan_id=scan_id,
            directory_path=str(tmp_path),
            output_dir=str(output_dir),
            severity_threshold=None,
        )
        entry = registry.get_scan(scan_id)
        assert entry is not None
        assert await asyncio.to_thread(entry.runner_done.wait, SETTLE_SECONDS), (
            "control: the scan's thread never settled"
        )
    return registry, scan_id


@pytest.mark.asyncio
async def test_the_progress_reply_names_the_tool_the_stop_could_not_end(
    tmp_path, monkeypatch
):
    """One tool kept running past the stop: the entry stays CANCELLED and its
    progress carries a warning naming the tool and its process id, so a client
    polling the scan is told the output directory may still be written to.

    Red at the base: the arm closed the already-closed entry (a no-op) and the
    pairs went nowhere, so ``warnings`` read ``[]``.
    """
    registry, scan_id = await _run_a_scan_that_is_cancelled_mid_run(
        tmp_path, monkeypatch, (("bandit", 4242),)
    )

    progress = registry.check_scan_progress(scan_id)

    assert progress["status"] == MCScanStatus.CANCELLED.value, progress
    warnings = progress["warnings"]
    assert any("bandit" in w and "4242" in w for w in warnings), warnings


@pytest.mark.asyncio
async def test_a_cancel_that_stopped_every_tool_adds_no_warning(tmp_path, monkeypatch):
    """Control: the same cancel with nothing left running attaches nothing, so
    recording the outcome does not warn on every cancelled scan."""
    registry, scan_id = await _run_a_scan_that_is_cancelled_mid_run(
        tmp_path, monkeypatch, ()
    )

    progress = registry.check_scan_progress(scan_id)

    assert progress["status"] == MCScanStatus.CANCELLED.value, progress
    assert progress["warnings"] == [], progress["warnings"]
