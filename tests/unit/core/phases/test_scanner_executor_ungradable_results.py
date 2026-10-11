"""A scanner result ASH cannot read is ERROR, not a clean scan.

The executor grades a SARIF report by its findings and a dict by its ``status``,
``severity_counts`` or ``findings``. A dict with none of those carries nothing to
grade, and it used to be graded PASSED with 0 findings. Two routes produce one: the
template ``scan()`` returns the parsed JSON as it is when it is not SARIF (a tool that
wrote ``{"errors": [...]}`` and exited 0), and a scanner that overrides ``scan()`` can
return its tool's JSON when it does not parse (ferret-scan does). Either way the
scanner's findings were not read, so the row is ERROR and says so.

The controls are the dict shapes the executor does grade: ``severity_counts``, a
``findings`` list, and ``status: failed``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar, Literal
from unittest.mock import MagicMock, patch

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

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class _Config(ScannerPluginConfigBase):
    name: Literal["shape-tool"] = "shape-tool"


class TemplateScanner(ScannerPluginBase):
    """Runs the template: its tool writes ``self.results_text`` and exits 0."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        self.command = "shape-tool"
        self.tool_type = ScannerToolType.SAST
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        results_dir = self.results_dir / target_type
        results_dir.mkdir(parents=True, exist_ok=True)
        results_file = results_dir / "results.sarif"
        results_file.write_text(self.results_text, encoding="utf-8")
        return ["shape-tool", "--scan"], results_file, None


class OverrideScanner(TemplateScanner):
    """Overrides ``scan()`` and returns ``self.returned`` as it is."""

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        self._pre_scan(target=target, target_type=target_type, config=config)
        self._post_scan(target=target, target_type=target_type)
        return self.returned


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
        config=AshConfig(project_name="shapes"),
    )


def _row(plugin_context, scanner):
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (row,) = executor._execute_scanner(
        "shape-tool",
        scanner,
        [{"path": Path(plugin_context.source_dir), "type": "source"}],
    )
    return row


def _template_row(plugin_context, results_text: str):
    config = _Config()
    config.options.severity_threshold = "MEDIUM"
    scanner = TemplateScanner(config=config, context=plugin_context)
    scanner.results_text = results_text
    with patch.object(
        scanner, "_run_subprocess", return_value={"returncode": 0, "stderr": ""}
    ):
        return _row(plugin_context, scanner)


def _override_row(plugin_context, returned):
    config = _Config()
    config.options.severity_threshold = "MEDIUM"
    scanner = OverrideScanner(config=config, context=plugin_context)
    scanner.returned = returned
    return _row(plugin_context, scanner)


def _says_why(row) -> bool:
    return any("could not be graded" in str(error) for error in row.errors)


class TestAResultWithNothingToGradeIsAnError:
    @pytest.mark.parametrize(
        "content",
        [
            json.dumps({"errors": ["the tool could not read its rules"]}),
            json.dumps({"version": "2.1.0", "runs": "not a list"}),
            json.dumps([]),
        ],
        ids=["error-object", "malformed-sarif", "json-list"],
    )
    def test_the_template_with_json_that_is_not_sarif(self, plugin_context, content):
        row = _template_row(plugin_context, content)

        assert row.status == ScannerStatus.ERROR, (
            f"the tool exited 0 and wrote {content!r}, which ASH could not read as "
            f"SARIF; the row was graded {row.status.value}"
        )
        assert _says_why(row), f"errors: {row.errors!r}"

    def test_an_override_returning_its_tools_json(self, plugin_context):
        row = _override_row(plugin_context, {"runs": "not sarif", "note": "raw"})

        assert row.status == ScannerStatus.ERROR, row.status.value
        assert _says_why(row), f"errors: {row.errors!r}"


class TestTheDictShapesTheExecutorGrades:
    """Controls: a dict that carries a verdict or counts is graded as before."""

    def test_severity_counts_are_graded(self, plugin_context):
        row = _override_row(
            plugin_context,
            {"severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0}},
        )

        assert row.status == ScannerStatus.FAILED
        assert row.finding_count == 1

    def test_a_findings_list_is_graded(self, plugin_context):
        row = _override_row(plugin_context, {"findings": []})

        assert row.status == ScannerStatus.PASSED

    def test_a_failed_status_is_an_error(self, plugin_context):
        row = _override_row(plugin_context, {"status": "failed", "errors": ["boom"]})

        assert row.status == ScannerStatus.ERROR

    def test_valid_sarif_with_no_results_is_passed(self, plugin_context):
        sarif = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "shape-tool"}}, "results": []}],
        }
        row = _template_row(plugin_context, json.dumps(sarif))

        assert row.status == ScannerStatus.PASSED
