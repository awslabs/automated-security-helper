# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""SCAN_START is sent when a scanner starts, after the cancel checks, in both modes.

The parallel loop sent SCAN_START from the submitting thread, before the worker's
cancel checks, so with four workers and fifteen scanners all fifteen announced
"Starting scanner" at once, and a queued scanner the cancel removed got a
SCAN_START with no SCAN_COMPLETE or ERROR after it. The sequential loop sent it
before its own cancel check too. The event is now issued by the loops' own
per-scanner call (``_start_and_run``) once the cancel checks have passed, so a
scanner that never starts never announces, and in a parallel run the event comes
from the worker thread that runs the scanner. The control: a run no cancel
reaches announces every scanner once, in both modes.

It is not issued by ``_safe_execute_scanner``: the scan phase calls that method
directly and records no completion for it, so an event sent from there would
open a turn nothing closes. A stand-in for the method still gets its scanner's
event, because the loops send it before calling the stand-in.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import ClassVar, Literal
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
)
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins.events import AshEventType

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class _Config(ScannerPluginConfigBase):
    name: Literal["shape-tool"] = "shape-tool"


class CleanScanner(ScannerPluginBase):
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
        config=AshConfig(project_name="scan-start"),
    )


def _executor(plugin_context, events: list):
    targets = [{"path": Path(plugin_context.source_dir), "type": "source"}]
    tasks = [
        (name, CleanScanner(config=_Config(), context=plugin_context), targets)
        for name in ("first", "second")
    ]

    def notify(event_type, **kwargs):
        events.append((event_type, kwargs.get("scanner"), threading.current_thread()))

    return ScannerExecutor(
        plugin_context=plugin_context,
        progress_display=MagicMock(),
        scanner_tasks=tasks,
        max_workers=2,
        notify_fn=notify,
    )


def _starts(events: list) -> list:
    return sorted(name for kind, name, _ in events if kind == AshEventType.SCAN_START)


class TestACancelledRunAnnouncesNoStart:
    @pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
    def test_a_scan_cancelled_before_it_starts_sends_no_scan_start(
        self, plugin_context, parallel
    ):
        events: list = []
        executor = _executor(plugin_context, events)
        event = CancelEvent()
        event.set()

        with cancel_scope(event):
            with pytest.raises(ScanCancelled):
                if parallel:
                    executor.run_parallel(AshAggregatedResults())
                else:
                    executor.run_sequential(AshAggregatedResults())

        assert _starts(events) == [], events


class TestEveryStartedScannerAnnouncesOnce:
    def test_sequential(self, plugin_context):
        events: list = []
        _executor(plugin_context, events).run_sequential(AshAggregatedResults())

        assert _starts(events) == ["first", "second"], events

    def test_parallel_from_the_worker_thread(self, plugin_context):
        events: list = []
        _executor(plugin_context, events).run_parallel(AshAggregatedResults())

        assert _starts(events) == ["first", "second"], events
        start_threads = {
            thread for kind, _, thread in events if kind == AshEventType.SCAN_START
        }
        assert threading.main_thread() not in start_threads, events


class TestADirectCallAnnouncesNoStart:
    def test_a_direct_call_of_the_safe_method_sends_no_scan_start(self, plugin_context):
        """Red at the base: the event was sent from inside the method, so a call
        that no loop makes (the scan phase's own) announced a start that no
        SCAN_COMPLETE or ERROR would ever follow."""
        events: list = []
        executor = _executor(plugin_context, events)
        name, scanner, targets = executor.scanner_tasks[0]

        results, succeeded = executor._safe_execute_scanner(name, scanner, targets)

        assert succeeded is True
        assert results, "the scanner ran and filed a row"
        assert _starts(events) == [], events

    @pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
    def test_a_stand_in_for_the_safe_method_still_gets_one_start_per_scanner(
        self, plugin_context, parallel
    ):
        """Control, red at the base for the other reason: the event lived inside
        the method a stand-in replaces, so a run through a stand-in announced no
        scanner at all. The loops now send it before calling whatever
        ``_safe_execute_scanner`` is."""
        events: list = []
        executor = _executor(plugin_context, events)
        executor._safe_execute_scanner = (  # type: ignore[method-assign]
            lambda name, plugin, targets: ([], True)
        )

        if parallel:
            executor.run_parallel(AshAggregatedResults())
        else:
            executor.run_sequential(AshAggregatedResults())

        assert _starts(events) == ["first", "second"], events
