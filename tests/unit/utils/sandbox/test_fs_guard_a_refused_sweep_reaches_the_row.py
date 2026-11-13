# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refusal the real sweep raises ends the scanner's row as ERROR.

``sweep_writable`` raises when it cannot list a directory or remove an entry below a
sandboxed scanner's results directory, and says it refuses where it used to pass
over. The executor sweeps after the scan, logs a failure, and raises it when nothing
else is propagating (test_scanner_executor_sandbox_sweep_on_raise.py fakes the
sweep with a RuntimeError). The spawn's own cleanup step runs the same sweep and
records a failure at DEBUG ("Sandbox cleanup failed"), best effort, so a refusal
there alone would be logged and skipped. These tests run the REAL sweep, with a
directory left unlistable the way a process that outlived its spawn could leave
it, and read both ends: the cleanup step's record, and the row the executor ends
with.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar, Literal
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import (
    OfflineStrategy,
    ScannerStatus,
    ScannerToolType,
)
from automated_security_helper.core.phases import scanner_executor
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.sandbox import fs_guard
from automated_security_helper.utils.sandbox.backends import SpawnPlan

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="POSIX directory modes and directory fds"
    ),
    pytest.mark.skipif(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        reason="root can list a directory whatever its mode",
    ),
]

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class _Config(ScannerPluginConfigBase):
    name: Literal["shape-tool"] = "shape-tool"


class LeavingScanner(ScannerPluginBase):
    """``scan()`` leaves ``leaves`` (a directory path) unlistable, as a process
    that outlived its spawn could, and returns an empty findings list."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        self.command = "shape-tool"
        self.tool_type = ScannerToolType.SAST
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        self._pre_scan(target=target, target_type=target_type, config=config)
        self._post_scan(target=target, target_type=target_type)
        self.leaves.mkdir()
        self.leaves.chmod(0o000)
        return {"findings": []}


@pytest.fixture
def plugin_context(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="sweep"),
    )


def test_a_refusal_in_the_real_post_scan_sweep_is_the_rows_error(
    plugin_context, tmp_path, monkeypatch, caplog
):
    results_dir = tmp_path / "sandbox-results"
    results_dir.mkdir()
    scope = SimpleNamespace(
        results_dir=results_dir,
        environment_values=(),
        environment_values_unread=False,
        backend=SimpleNamespace(name="fake"),
    )
    monkeypatch.setattr(
        scanner_executor, "scanner_sandbox_scope", lambda *args, **kwargs: scope
    )
    locked = results_dir / "left-behind"
    scanner = LeavingScanner(config=_Config(), context=plugin_context)
    scanner.leaves = locked
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )

    try:
        with caplog.at_level(logging.ERROR, logger="ash"):
            (row,) = executor._execute_scanner(
                "shape-tool",
                scanner,
                [{"path": Path(plugin_context.source_dir), "type": "source"}],
            )
    finally:
        if locked.exists():
            locked.chmod(0o700)

    assert row.status == ScannerStatus.ERROR, row.status
    reason = " ".join(str(error) for error in row.errors)
    assert "Could not list left-behind" in reason, reason
    failures = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Sweep of shape-tool's results directory")
    ]
    assert len(failures) == 1, [record.getMessage() for record in caplog.records]
    assert "Could not list left-behind" in failures[0], failures


def test_the_spawn_cleanup_records_a_refused_sweep_and_the_next_step_runs(
    tmp_path, caplog
):
    """The cleanup step is best effort: the refusal is a DEBUG record, redacted
    as the sweep's own warning is, and the release step after it still runs. The
    refusal is not lost with it, since the executor's own sweep after the scan
    raises it again (the test above)."""
    root = tmp_path / "results"
    locked = root / "left-behind-SWEEPSECRET-5520"
    locked.mkdir(parents=True)
    locked.chmod(0o000)
    released = []
    plan = SpawnPlan(
        argv=[],
        env={},
        cleanup=[
            lambda: fs_guard.sweep_writable([root], ("SWEEPSECRET-5520",)),
            lambda: released.append(1),
        ],
    )
    try:
        with caplog.at_level(logging.DEBUG, logger="ash"):
            plan.run_cleanup()
    finally:
        locked.chmod(0o700)

    assert released == [1]
    records = [
        record.getMessage()
        for record in caplog.records
        if "Sandbox cleanup failed" in record.getMessage()
    ]
    assert len(records) == 1, [record.getMessage() for record in caplog.records]
    assert "Could not list" in records[0], records
    assert "SWEEPSECRET-5520" not in records[0], records
