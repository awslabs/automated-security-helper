"""A raise while merging one target's results leaves the scanner's other targets merged.

``run_sequential`` and ``run_parallel`` hand each of a scanner's per-target
containers to ``ScanResultProcessor.process_container``. The loop had no guard: a
raise on one container left it, the remaining containers were never merged, and the
scanner-level handler then filed one failure container with no target, whose
per-target results file is written under ``source`` and so replaced the source
target's file.

Each container is now offered on its own, so the other targets' containers are
merged, and the first failure is re-raised afterwards naming its target: the
scanner-level handler logs it as it logs any failure ("Scanner failed: ...", the
contract tests/unit/core/phases/test_scanner_executor_logs_tool_text_as_given.py
pins) and files the failure container UNDER THAT TARGET, so the record lands where
the processing failed and never replaces a merged target's file. The scanner stays
out of ``completed_scanners`` so the completeness check records it.
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


def _run(plugin_context, tmp_path, failing_target: str | None):
    """Run one scanner over source and converted; the processor raises on one target.

    The processor raises on EVERY container for ``failing_target``, the failure
    record filed for it included, so ``seen`` shows the record's target.
    """
    seen: list = []

    def process(container, aggregated):
        seen.append(container)
        if container.target_type == failing_target:
            raise RuntimeError("the report could not be read")
        return aggregated

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
    )
    executor.run_sequential(AshAggregatedResults())
    return seen, executor


def test_the_other_targets_are_still_merged(plugin_context, tmp_path):
    seen, executor = _run(plugin_context, tmp_path, failing_target="source")

    assert [c.target_type for c in seen] == ["source", "converted", "source"], seen
    assert executor.completed_scanners == []


def test_the_failure_is_filed_under_the_target_that_failed(plugin_context, tmp_path):
    """The failure record names the failed target and the reason, so it replaces
    that target's record and no other's."""
    seen, _ = _run(plugin_context, tmp_path, failing_target="converted")

    record = seen[-1]
    assert [c.target_type for c in seen] == ["source", "converted", "converted"]
    assert record.status == ScannerStatus.FAILED
    assert "the report could not be read" in " ".join(str(e) for e in record.errors)
    assert "converted" in " ".join(str(e) for e in record.errors)


def test_every_target_merged_completes_the_scanner(plugin_context, tmp_path):
    """Control: with no raise, both targets are merged and the scanner completes."""
    seen, executor = _run(plugin_context, tmp_path, failing_target=None)

    assert [c.target_type for c in seen] == ["source", "converted"], seen
    assert len(executor.completed_scanners) == 1
