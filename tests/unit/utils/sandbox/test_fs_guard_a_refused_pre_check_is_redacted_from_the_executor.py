# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The executor's link pre-check redacts a refusal with the sandbox's own values.

Before a sandboxed scanner is spawned the executor calls ``refuse_links_below`` on
its results directory, so a link or a hard-linked file already there is refused in
the open rather than removed by the sweep after the spawn. The function redacts and
logs a refusal that names an entry or the root when it is given the redaction
values (``values``, ``values_unread``), and raises the same redacted line. Called
with neither, it has nothing to redact with: it logs nothing and raises the text as
it is, for the caller's handler to redact. The executor's call passed neither, so
that branch was the only one it could reach, and no scope is active at that point:
a directory named after an option value, left unlistable below the results
directory, was raised with its name and the handler redacted it only with the
config's values, not the sandbox's. The sweep after the scan has always passed
both; the pre-check passes them now.

These tests run the real pre-check through ``_execute_scanner``, with the sandbox
scope faked as the sibling test (test_fs_guard_a_refused_sweep_reaches_the_row.py)
fakes it, and read both ends: the line logged, and the row the executor ends with.
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

_SECRET = "PRECHECKSECRET-7712"


class _Config(ScannerPluginConfigBase):
    name: Literal["shape-tool"] = "shape-tool"


class QuietScanner(ScannerPluginBase):
    """A scanner whose ``scan()`` is never reached: the pre-check refuses first."""

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
        raise AssertionError("the pre-check should have refused before the scan")


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
        config=AshConfig(project_name="precheck"),
    )


def _run_with_an_unlistable_entry(
    plugin_context, tmp_path, monkeypatch, caplog, *, values, values_unread
):
    """The row the executor ends with, and the warnings logged, for a results
    directory that holds an unlistable directory named after ``_SECRET``."""
    results_dir = tmp_path / "sandbox-results"
    locked = results_dir / f"left-behind-{_SECRET}"
    locked.mkdir(parents=True)
    locked.chmod(0o000)
    scope = SimpleNamespace(
        results_dir=results_dir,
        environment_values=values,
        environment_values_unread=values_unread,
        backend=SimpleNamespace(name="fake"),
    )
    monkeypatch.setattr(
        scanner_executor, "scanner_sandbox_scope", lambda *args, **kwargs: scope
    )
    scanner = QuietScanner(config=_Config(), context=plugin_context)
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            (row,) = executor._execute_scanner(
                "shape-tool",
                scanner,
                [{"path": Path(plugin_context.source_dir), "type": "source"}],
            )
    finally:
        locked.chmod(0o700)
    reason = " ".join(str(error) for error in row.errors)
    refusals = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Could not")
    ]
    return row, reason, refusals


def test_the_pre_check_logs_and_raises_the_refusal_redacted_with_the_sandbox_values(
    plugin_context, tmp_path, monkeypatch, caplog
):
    """With the sandbox's values passed the refusal is logged once, redacted, and
    the row's error carries that same line. At the base the call passed no values,
    so nothing was logged and the row's error held the entry's name: the handler
    redacts with the config's values only, and the secret is the sandbox's."""
    row, reason, refusals = _run_with_an_unlistable_entry(
        plugin_context,
        tmp_path,
        monkeypatch,
        caplog,
        values=(_SECRET,),
        values_unread=False,
    )

    assert row.status == ScannerStatus.ERROR, row.status
    assert len(refusals) == 1, [record.getMessage() for record in caplog.records]
    assert refusals[0].startswith("Could not list "), refusals
    assert _SECRET not in refusals[0], refusals
    assert "Could not list " in reason, reason
    assert _SECRET not in reason, reason


def test_the_pre_check_says_nothing_of_the_entry_when_the_values_could_not_be_read(
    plugin_context, tmp_path, monkeypatch, caplog
):
    """The sandbox could not read its redaction values: nothing can be hidden, so
    the value-free line is logged and raised, naming neither entry nor root."""
    row, reason, refusals = _run_with_an_unlistable_entry(
        plugin_context,
        tmp_path,
        monkeypatch,
        caplog,
        values=(),
        values_unread=True,
    )

    # The refusals the guard logged ("Could not ..."), as the test above counts
    # them. The executor's own "Failed to execute ..." line carries the same
    # sentence in its tail, so a count over every record holding the phrase reads
    # two for one refusal.
    unnamed = [
        line for line in refusals if "redaction values could not be read" in line
    ]
    assert row.status == ScannerStatus.ERROR, row.status
    assert len(unnamed) == 1, [record.getMessage() for record in caplog.records]
    assert _SECRET not in unnamed[0], unnamed
    assert "redaction values could not be read" in reason, reason
    assert _SECRET not in reason, reason
