"""The executor grades a level-less SARIF result at the level the summary reads it.

``ScanResultProcessor.resolve_missing_levels`` gives every result that states no
level the one SARIF 2.1.0 gives it (the rule's default configuration, else
``warning``) when the report enters the results, so ash.sarif and the summary count
it at that severity. The executor counted the per-target row's severities before
the processor ran, and read a level-less result as info, so a scanner's row said
PASSED with one info finding while the summary said FAILED with one critical. The
executor now resolves the levels before it counts, and the two agree.
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
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    ReportingConfiguration,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class _Config(ScannerPluginConfigBase):
    name: Literal["shape-tool"] = "shape-tool"


class SarifScanner(ScannerPluginBase):
    """Overrides ``scan()`` and returns the SarifReport in ``report``."""

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
        return self.report


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
        config=AshConfig(project_name="levels"),
    )


def _report(result: Result, rule_level: str | None) -> SarifReport:
    rules = (
        [
            ReportingDescriptor(
                id="R1",
                defaultConfiguration=ReportingConfiguration(level=rule_level),
            )
        ]
        if rule_level
        else None
    )
    return SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="shape-tool", rules=rules)),
                results=[result],
            )
        ]
    )


def _row(plugin_context, report: SarifReport):
    config = _Config()
    config.options.severity_threshold = "MEDIUM"
    scanner = SarifScanner(config=config, context=plugin_context)
    scanner.report = report
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (row,) = executor._execute_scanner(
        "shape-tool",
        scanner,
        [{"path": Path(plugin_context.source_dir), "type": "source"}],
    )
    return row


def test_a_level_less_result_is_graded_at_its_rules_default(plugin_context):
    row = _row(
        plugin_context,
        _report(Result(ruleId="R1", message=Message(text="x")), rule_level="error"),
    )

    assert row.severity_counts.critical == 1, row.severity_counts
    assert row.severity_counts.info == 0
    assert row.status == ScannerStatus.FAILED


def test_a_level_less_result_with_no_rule_default_is_a_warning(plugin_context):
    row = _row(
        plugin_context,
        _report(Result(ruleId="R1", message=Message(text="x")), rule_level=None),
    )

    assert row.severity_counts.medium == 1, row.severity_counts
    assert row.status == ScannerStatus.FAILED


def test_a_stated_level_is_kept(plugin_context):
    """Control: a result that states its level is counted at it, as before."""
    row = _row(
        plugin_context,
        _report(
            Result(ruleId="R1", level="note", message=Message(text="x")),
            rule_level="error",
        ),
    )

    assert row.severity_counts.low == 1, row.severity_counts
    assert row.status == ScannerStatus.PASSED
