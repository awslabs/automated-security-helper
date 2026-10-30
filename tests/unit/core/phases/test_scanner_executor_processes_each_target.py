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
stays out of ``completed_scanners`` so the completeness check records it, and
leaves the remaining list (a later SCAN_COMPLETE no longer names it as running)
with a SCAN_COMPLETE of its own whose ``succeeded`` is False: every finished turn
is announced, the rule the run-loop tests
(tests/unit/core/phases/test_scanner_executor_rows_and_run_loops.py) pin for a
scanner whose bookkeeping raised.

A refiled row that the processor raises on AGAIN (whatever on the row caused the
first raise is still on it) is followed by a fresh failure row for the same target,
carrying its target type and its could-not-stop record, so the target still has a
row in the results; offered once and logged, it had none.
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
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)

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
    with_clean_scanner: bool = False,
    raise_once: bool = False,
):
    """Run one scanner over source and converted; the processor raises on one target.

    The processor raises on EVERY container for ``failing_target`` (one name, or a
    tuple of names), the failure record filed for it and the fresh row the handler
    falls back to included, so ``seen`` shows the record's target; with
    ``raise_once`` it raises on the FIRST container of each failing target only, so
    the refiled row is merged. ``before_raise`` is called with the container before
    each raise. The events the executor sends are collected on ``executor.events``
    as ``(event_type, kwargs)`` pairs. ``with_clean_scanner`` queues a second
    scanner, ``clean-tool``, after ``shape-tool``, over the source target only, so
    none of its containers is a ``failing_target`` and the processor merges them
    all: its SCAN_COMPLETE shows what the remaining list holds once the first
    scanner's turn is over.
    """
    seen: list = []
    events: list = []
    raised: set = set()
    failing = (
        {failing_target}
        if isinstance(failing_target, str)
        else set(failing_target or ())
    )

    def process(container, aggregated):
        seen.append(container)
        if container.target_type in failing and not (
            raise_once and container.target_type in raised
        ):
            raised.add(container.target_type)
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
    scanner_tasks = [("shape-tool", scanner, targets)]
    if with_clean_scanner:
        clean = CleanScanner(config=_Config(), context=plugin_context)
        # The source target only: the processor raises on every container of a
        # failing target type whatever scanner it came from, and the clean
        # scanner has to complete.
        scanner_tasks.append(("clean-tool", clean, targets[:1]))
    executor = ScannerExecutor(
        plugin_context=plugin_context,
        progress_display=MagicMock(),
        scanner_tasks=scanner_tasks,
        process_results_fn=process,
        notify_fn=notify,
    )
    if parallel:
        executor.run_parallel(AshAggregatedResults())
    else:
        executor.run_sequential(AshAggregatedResults())
    executor.events = events
    return seen, executor


def _run_with_substituted_runner(plugin_context, tmp_path, parallel: bool):
    """Run one scanner whose ``_execute_scanner`` is replaced by a fake that hands
    the processor a plain string instead of a results row; the processor raises on
    it. Returns the containers the processor saw and the executor."""
    seen: list = []

    def process(container, aggregated):
        seen.append(container)
        if not isinstance(container, ScanResultsContainer):
            raise ValueError("not a results row")
        return aggregated

    scanner = CleanScanner(config=_Config(), context=plugin_context)
    targets = [{"path": Path(plugin_context.source_dir), "type": "source"}]
    executor = ScannerExecutor(
        plugin_context=plugin_context,
        progress_display=MagicMock(),
        scanner_tasks=[("shape-tool", scanner, targets)],
        process_results_fn=process,
        notify_fn=lambda event_type, **kwargs: None,
    )

    def fake_execute(scanner_name, scanner_plugin, scan_targets):
        # _safe_execute_scanner wraps this in its (results, succeeded) pair.
        return ["not-a-results-row"]

    executor._execute_scanner = fake_execute  # type: ignore[method-assign]
    if parallel:
        executor.run_parallel(AshAggregatedResults())
    else:
        executor.run_sequential(AshAggregatedResults())
    return seen, executor


@pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
def test_a_failure_on_an_item_that_is_no_row_is_filed_as_a_fresh_failure_row(
    plugin_context, tmp_path, parallel
):
    """``_execute_scanner`` builds one row per target, but a substituted runner
    (a test's fake, a plugin stand-in) can hand the processor anything. When the
    processor raises on such an item, the handler cannot refile it as the
    target's row (it has none); it files a fresh failure row instead of raising
    on the item's missing ``add_error``. tests/unit/core/phases/
    test_cancel_reaches_the_real_engine.py's cancelled-run test fakes the runner
    this way and pins that the failed scanner counts as a completion."""
    seen, executor = _run_with_substituted_runner(plugin_context, tmp_path, parallel)

    assert seen[0] == "not-a-results-row"
    assert isinstance(seen[-1], ScanResultsContainer), seen
    assert seen[-1].scanner_name == "shape-tool"
    # ScanResultsContainer.for_failure files the row as FAILED (the scanner did not
    # finish); ERROR is the status a processor failure writes onto an existing row.
    assert seen[-1].status == ScannerStatus.FAILED
    assert executor.completed_scanners == []


def _scan_complete_events(executor) -> list:
    return [
        kwargs
        for event_type, kwargs in executor.events
        if getattr(event_type, "name", event_type) == "SCAN_COMPLETE"
    ]


def test_the_other_targets_are_still_merged(plugin_context, tmp_path):
    seen, executor = _run(plugin_context, tmp_path, failing_target="source")

    # source raises, converted merges, source's row is refiled and raises again,
    # and the fresh fallback row for source is offered last.
    assert [c.target_type for c in seen] == [
        "source",
        "converted",
        "source",
        "source",
    ], seen
    assert executor.completed_scanners == []


def test_the_failure_is_filed_on_the_row_of_the_target_that_failed(
    plugin_context, tmp_path
):
    """The failed target's own row is filed again, ERROR, with the reason added
    to the errors it already carried, so its report keeps what the scan recorded
    and no other target's record is touched. When that row raises again, a fresh
    failure row for the same target is filed in its place."""
    seen, _ = _run(plugin_context, tmp_path, failing_target="converted")

    assert [c.target_type for c in seen] == [
        "source",
        "converted",
        "converted",
        "converted",
    ]
    record = seen[2]
    assert record is seen[1], "the row itself is filed again, not a new container"
    assert record.status == ScannerStatus.ERROR
    reasons = " ".join(str(e) for e in record.errors)
    assert "the report could not be read" in reasons
    assert "converted" in reasons
    fresh = seen[3]
    assert fresh is not seen[1], "the refiled row raised again: a fresh row follows"
    assert fresh.status == ScannerStatus.ERROR
    assert fresh.target_type == "converted"
    assert "the report could not be read" in " ".join(str(e) for e in fresh.errors)


@pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
def test_the_refiled_row_keeps_its_could_not_stop_record(
    plugin_context, tmp_path, parallel
):
    """A tool ASH could not stop, still writing into the scanner's results
    directory, is the case that can make the merge raise; the record of that
    stop is what run_ash_scan's could-not-stop gate reads off the target's
    report. Filing a fresh failure container under the target's key replaced the
    report with one carrying no such record, so the gate lost the case it exists
    for. The refiled row is the scan's own, so the record is still on it."""

    def mark_unstoppable(container):
        if container.could_not_stop is None:
            container.could_not_stop = (
                "shape-tool (pid 4242), which may still be running"
            )

    seen, _ = _run(
        plugin_context,
        tmp_path,
        failing_target="converted",
        parallel=parallel,
        before_raise=mark_unstoppable,
    )

    record = seen[2]
    assert record is seen[1]
    assert record.target_type == "converted"
    assert record.status == ScannerStatus.ERROR
    assert record.could_not_stop == (
        "shape-tool (pid 4242), which may still be running"
    )
    # The fresh row the handler falls back to when the refiled row raises again
    # carries the record too: it is what the gate reads off the target's report.
    assert seen[3].could_not_stop == (
        "shape-tool (pid 4242), which may still be running"
    )
    assert seen[0].could_not_stop is None, "the merged target's row is untouched"


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

    # Each failed target: its row refiled, then (the refile raised too) a fresh row.
    assert [c.target_type for c in seen] == [
        "source",
        "converted",
        "source",
        "source",
        "converted",
        "converted",
    ], seen
    assert seen[2] is seen[0] and seen[4] is seen[1]
    assert seen[3] is not seen[0] and seen[5] is not seen[1]
    for record in seen[2:]:
        assert record.status == ScannerStatus.ERROR
        reasons = " ".join(str(e) for e in record.errors)
        assert "the report could not be read" in reasons
        assert record.target_type in reasons
    assert executor.completed_scanners == []


class TestARefiledRowReachesTheReport:
    """A results-processing failure is refiled on the target's own row. Before, the
    handler offered that row once: when the processor raised on it again (whatever
    on the row caused the first raise is still there), the failure was only logged
    and the target had no row in the results at all. Now a refiled row that raises
    again is followed by a fresh failure row for the same target, and a refiled row
    the processor accepts is the one that reaches the report."""

    @pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
    def test_a_refiled_row_the_processor_accepts_is_the_report(
        self, plugin_context, tmp_path, parallel
    ):
        seen, executor = _run(
            plugin_context,
            tmp_path,
            failing_target="converted",
            parallel=parallel,
            raise_once=True,
        )

        assert [c.target_type for c in seen] == ["source", "converted", "converted"]
        assert seen[2] is seen[1], "the refiled row itself was merged"
        assert seen[2].status == ScannerStatus.ERROR
        assert executor.completed_scanners == []

    @pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
    def test_a_refiled_row_that_raises_again_is_replaced_by_a_fresh_row(
        self, plugin_context, tmp_path, parallel
    ):
        seen, _ = _run(
            plugin_context, tmp_path, failing_target="converted", parallel=parallel
        )

        fresh = seen[-1]
        assert fresh is not seen[1]
        assert isinstance(fresh, ScanResultsContainer)
        assert fresh.scanner_name == "shape-tool"
        assert fresh.target_type == "converted"
        assert fresh.status == ScannerStatus.ERROR
        assert fresh.raw_results["status"] == "failed"

    def test_control_a_fresh_failure_row_gets_no_second_offer(
        self, plugin_context, tmp_path
    ):
        """A row the handler built fresh (a substituted runner handed the processor
        no row) carries nothing of the scan's, so a raise on it is logged once."""
        seen, _ = _run_with_substituted_runner(plugin_context, tmp_path, False)

        fresh_rows = [c for c in seen if isinstance(c, ScanResultsContainer)]
        assert len(fresh_rows) == 1, seen


def test_every_target_merged_completes_the_scanner(plugin_context, tmp_path):
    """Control: with no raise, both targets are merged and the scanner completes."""
    seen, executor = _run(plugin_context, tmp_path, failing_target=None)

    assert [c.target_type for c in seen] == ["source", "converted"], seen
    assert len(executor.completed_scanners) == 1


class TestAProcessingFailureIsAnnouncedAsAFailedTurn:
    """The scanner returned; one target's results could not be merged. The failure
    is filed on that target's row, and the scanner's turn is over: it leaves
    ``remaining_scanners`` and its SCAN_COMPLETE is sent with ``succeeded`` False,
    as every finished turn's is (docs/content/plugins/event-subscribers.md: "after
    each scanner, including one that failed"). Before, a merge failure sent none
    while a scan() that raised was announced, so whether a failed scanner got
    SCAN_COMPLETE depended on how it failed, and a merge failure in the last
    scanner left the completion logger with no ``remaining_count == 0`` event. It
    stays out of ``completed_scanners``, so the completeness check records it."""

    @pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
    def test_the_failed_scanner_is_announced_as_failed_and_leaves_remaining(
        self, plugin_context, tmp_path, parallel
    ):
        _, executor = _run(
            plugin_context,
            tmp_path,
            failing_target="converted",
            parallel=parallel,
            with_clean_scanner=True,
        )

        completes = _scan_complete_events(executor)
        by_name = {c["scanner"]: c for c in completes}
        assert set(by_name) == {"shape-tool", "clean-tool"}, completes
        assert by_name["shape-tool"]["succeeded"] is False
        assert by_name["clean-tool"]["succeeded"] is True
        assert all(c["total_count"] == 2 for c in completes)
        assert executor.completed_scanners == ["clean-tool"]
        if not parallel:
            # The failed scanner's turn ended before the clean one's began: its
            # event still names the clean scanner as running, and the clean
            # scanner's finds nothing left and counts two turns over (a failed
            # turn is a turn, not a completed scanner).
            assert [c["scanner"] for c in completes] == ["shape-tool", "clean-tool"]
            assert by_name["shape-tool"]["remaining_scanners"] == ["clean-tool"]
            assert by_name["shape-tool"]["completed_count"] == 1
            assert by_name["clean-tool"]["remaining_scanners"] == []
            assert by_name["clean-tool"]["remaining_count"] == 0
            assert by_name["clean-tool"]["completed_count"] == 2

    @pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
    def test_a_failed_scanner_alone_sends_one_failed_scan_complete(
        self, plugin_context, tmp_path, parallel
    ):
        """The last turn to end is the failed one: the event that says nothing is
        left running is still sent, so the completion logger says the scan is
        over."""
        _, executor = _run(
            plugin_context, tmp_path, failing_target="converted", parallel=parallel
        )

        (complete,) = _scan_complete_events(executor)
        assert complete["scanner"] == "shape-tool"
        assert complete["succeeded"] is False
        assert complete["remaining_scanners"] == []
        assert complete["remaining_count"] == 0
        assert complete["completed_count"] == 1
        assert "failed" in complete["message"]
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
        assert complete["succeeded"] is True
        assert "completed" in complete["message"]
        assert len(executor.completed_scanners) == 1
