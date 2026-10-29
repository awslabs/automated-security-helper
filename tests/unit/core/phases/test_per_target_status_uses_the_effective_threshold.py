"""The per-target report grades a scanner against the threshold the summary uses.

Each scanner target gets ``scanners/<name>/<target>/ASH.ScanResults.json``, written
from the container ``ScannerExecutor`` graded with ``determine_status``. That call
is handed the effective threshold: the scanner's own ``options.severity_threshold``
is None unless the scanner's config sets one, and None turns the gate off, while
the summary, the scanner row and the exit code fall back to
``global_settings.severity_threshold`` (MEDIUM by default). So a scanner with
findings at or above the global threshold and no threshold of its own is FAILED
in the summary and in its own report alike.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class _Config(ScannerPluginConfigBase):
    name: Literal["graded-tool"] = "graded-tool"


class _Scanner(ScannerPluginBase):
    """Returns one finding at the SARIF level the test sets."""

    level: str = "error"

    def model_post_init(self, context):
        if self.config is None:
            self.config = _Config()
        self.command = "graded-tool"
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        return SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "graded-tool"}},
                        "results": [
                            {
                                "ruleId": "R1",
                                "level": self.level,
                                "message": {"text": "a finding"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 1},
                                        }
                                    }
                                ],
                                "properties": {"scanner_name": "graded-tool"},
                            }
                        ],
                    }
                ],
            }
        )


@pytest.fixture
def context(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=get_default_config(),
    )


def _run(context, *, level: str, scanner_threshold):
    # The threshold goes where a scan's comes from, the AshConfig the plugin's
    # config is built from, and onto the plugin's config as construction puts it.
    if scanner_threshold is not None:
        context.config = AshConfig(
            project_name="graded",
            scanners={
                "graded-tool": {"options": {"severity_threshold": scanner_threshold}}
            },
        )
    config = _Config()
    config.options.severity_threshold = scanner_threshold
    scanner = _Scanner(config=config, context=context)
    scanner.level = level
    aggregated = AshAggregatedResults()
    aggregated.ash_config = context.config
    processor = ScanResultProcessor(plugin_context=context)
    executor = ScannerExecutor(
        plugin_context=context,
        progress_display=MagicMock(),
        scanner_tasks=[
            (
                "graded-tool",
                scanner,
                [{"path": Path(context.source_dir), "type": "source"}],
            )
        ],
        process_results_fn=processor.process_container,
    )
    aggregated = executor.run_sequential(aggregated)
    report = json.loads(
        (
            Path(context.output_dir)
            / "scanners"
            / "graded-tool"
            / "source"
            / "ASH.ScanResults.json"
        ).read_text(encoding="utf-8")
    )
    aggregated = populate_metrics_from_unified_source(aggregated_results=aggregated)
    return report["status"], aggregated.scanner_results["graded-tool"].status


def test_a_finding_at_the_global_threshold_fails_the_per_target_report(context):
    assert context.config.global_settings.severity_threshold == "MEDIUM"

    per_target, row = _run(context, level="error", scanner_threshold=None)

    assert row == ScannerStatus.FAILED
    assert per_target == "FAILED", (
        "the scanner has no threshold of its own, so it is graded against the "
        f"global MEDIUM like its row; its own report said {per_target}"
    )


def test_the_scanners_own_threshold_wins(context):
    """A scanner threshold of CRITICAL lets a MEDIUM finding pass, in both places."""
    per_target, row = _run(context, level="warning", scanner_threshold="CRITICAL")

    assert (per_target, row) == ("PASSED", ScannerStatus.PASSED)


def test_below_the_global_threshold_both_pass(context):
    per_target, row = _run(context, level="note", scanner_threshold=None)

    assert (per_target, row) == ("PASSED", ScannerStatus.PASSED)
