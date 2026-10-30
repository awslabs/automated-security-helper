"""A raise while merging one target's results leaves the scanner's other targets merged.

``run_sequential`` and ``run_parallel`` hand each of a scanner's per-target
containers to ``ScanResultProcessor.process_container``. The loop had no guard: a
raise on one container left it, the remaining containers were never merged, and the
scanner-level handler then filed one failure container with no target, whose
per-target results file is written under ``source`` and so replaced the source
target's file.

Each container is now offered on its own, so the other targets' containers are
merged, and the first failure is re-raised afterwards naming its target, with
every later failure carried on it: the scanner-level handler logs each as it logs
any failure ("Scanner failed: ...", the contract tests/unit/core/phases/
test_scanner_executor_logs_tool_text_as_given.py pins) and files EACH FAILED
TARGET'S OWN ROW again with the failure added (status ERROR, the reason in its
errors), so the report keeps what the scan recorded (a refused sandbox's own error
text, say; tests/unit/core/phases/test_a_probing_scanner_under_a_refused_sandbox.py
pins that it survives) and never replaces a merged target's file. The scanner
stays out of ``completed_scanners`` so the completeness check records it, and is
closed out (SCAN_COMPLETE, off the remaining list) as a scanner that returned.
"""

from __future__ import annotations

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
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import (
    OfflineStrategy,
    ScannerStatus,
    ScannerToolType,
)
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults

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
    (tmp_path / "converted").mkdir()
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="targets"),
    )


def _run(
    plugin_context,
    tmp_path,
    failing_target: str | None,
    parallel: bool = False,
    before_raise=None,
):
    """Run one scanner over source and converted; the processor raises on one target.

    The processor raises on EVERY container for ``failing_target`` (one name, or a
    tuple of names), the failure record filed for it included, so ``seen`` shows
    the record's target. ``before_raise`` is called with the container before each
    raise. The events the executor sends are collected on ``executor.events`` as
    ``(event_type, kwargs)`` pairs.
    """
    seen: list = []
    events: list = []
    failing = (
        {failing_target}
        if isinstance(failing_target, str)
        else set(failing_target or ())
    )

    def process(container, aggregated):
        seen.append(container)
        if container.target_type in failing:
            if before_raise is not None:
                before_raise(container)
            raise RuntimeError("the report could not be read")
        return aggregated

    def notify(event_type, **kwargs):
        events.append((event_type, kwargs))

    scanner = CleanScanner(config=_Config(), context=plugin_context)
    targets = [
        {"path": Path(plugin_context.source_dir), "type": "source"},
        {"path": tmp_path / "converted", "type": "converted"},
    ]
    executor = ScannerExecutor(
        plugin_context=plugin_context,
        progress_display=MagicMock(),
        scanner_tasks=[("shape-tool", scanner, targets)],
        process_results_fn=process,
        notify_fn=notify,
    )
    if parallel:
        executor.run_parallel(AshAggregatedResults())
    else:
        executor.run_sequential(AshAggregatedResults())
    executor.events = events
    return seen, executor


def _scan_complete_events(executor) -> list:
    return [
        kwargs
        for event_type, kwargs in executor.events
        if getattr(event_type, "name", event_type) == "SCAN_COMPLETE"
    ]


def test_the_other_targets_are_still_merged(plugin_context, tmp_path):
    seen, executor = _run(plugin_context, tmp_path, failing_target="source")

    assert [c.target_type for c in seen] == ["source", "converted", "source"], seen
    assert executor.completed_scanners == []


def test_the_failure_is_filed_on_the_row_of_the_target_that_failed(
    plugin_context, tmp_path
):
    """The failed target's own row is filed again, ERROR, with the reason added
    to the errors it already carried, so its report keeps what the scan recorded
    and no other target's record is touched."""
    seen, _ = _run(plugin_context, tmp_path, failing_target="converted")

    record = seen[-1]
    assert [c.target_type for c in seen] == ["source", "converted", "converted"]
    assert record is seen[1], "the row itself is filed again, not a new container"
    assert record.status == ScannerStatus.ERROR
    reasons = " ".join(str(e) for e in record.errors)
    assert "the report could not be read" in reasons
    assert "converted" in reasons


@pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
def test_every_failed_target_is_filed_not_only_the_first(
    plugin_context, tmp_path, parallel
):
    """Two targets fail to merge: both rows are filed again, ERROR, each naming
    its own target. Only the first was kept before; the second target's report
    stayed as the processor had dumped it before the raise, a normal-looking one."""
    seen, executor = _run(
        plugin_context,
        tmp_path,
        failing_target=("source", "converted"),
        parallel=parallel,
    )

    assert [c.target_type for c in seen] == [
        "source",
        "converted",
        "source",
        "converted",
    ], seen
    assert seen[2] is seen[0] and seen[3] is seen[1]
    for record in seen[2:]:
        assert record.status == ScannerStatus.ERROR
        reasons = " ".join(str(e) for e in record.errors)
        assert "the report could not be read" in reasons
        assert record.target_type in reasons
    assert executor.completed_scanners == []


def test_every_target_merged_completes_the_scanner(plugin_context, tmp_path):
    """Control: with no raise, both targets are merged and the scanner completes."""
    seen, executor = _run(plugin_context, tmp_path, failing_target=None)

    assert [c.target_type for c in seen] == ["source", "converted"], seen
    assert len(executor.completed_scanners) == 1


class TestAProcessingFailureStillClosesTheScannerOut:
    """The scanner returned; one target's results could not be merged. The failure
    is filed on that target's row, and the scanner's completion bookkeeping still
    runs: it leaves ``remaining_scanners`` and SCAN_COMPLETE is sent, as it was
    when the raise was swallowed inside the merge loop. Without it subscribers saw
    a SCAN_START with no end event and every later SCAN_COMPLETE still listed the
    scanner as remaining. It still stays out of ``completed_scanners``, so the
    completeness check records it."""

    @pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
    def test_scan_complete_is_sent_and_the_scanner_leaves_remaining(
        self, plugin_context, tmp_path, parallel
    ):
        _, executor = _run(
            plugin_context, tmp_path, failing_target="converted", parallel=parallel
        )

        (complete,) = _scan_complete_events(executor)
        assert complete["scanner"] == "shape-tool"
        assert complete["remaining_scanners"] == []
        assert complete["remaining_count"] == 0
        assert complete["completed_count"] == 1
        assert complete["total_count"] == 1
        assert executor.completed_scanners == []

    @pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
    def test_a_clean_scanner_sends_one_scan_complete(
        self, plugin_context, tmp_path, parallel
    ):
        """Control: the bookkeeping runs once, not once per path."""
        _, executor = _run(
            plugin_context, tmp_path, failing_target=None, parallel=parallel
        )

        (complete,) = _scan_complete_events(executor)
        assert complete["remaining_scanners"] == []
        assert len(executor.completed_scanners) == 1
