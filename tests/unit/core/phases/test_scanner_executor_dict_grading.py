"""A dict result is graded by what it says, and one ASH cannot read is this row's ERROR.

The executor grades a scanner that returns a dict from its ``severity_counts`` or its
``findings`` list, inside the per-target ``finally`` that builds the row. Three
shapes a tool's own JSON takes defeated it:

- ``severity_counts`` keyed ``HIGH``: validated as a pydantic extra, the ``high``
  field stayed 0 and a result with high findings graded PASSED.
- a finding whose ``severity`` is not text, or a finding that is not a mapping, or
  ``"metadata": null``: the read raised inside the ``finally``, the raise left
  ``_execute_scanner``, and ``_safe_execute_scanner`` replaced every container the
  scanner had built for its earlier targets with one failure container.

Now a result that cannot be read makes its own row ERROR, with the reason on the
row, and the scanner's other targets keep theirs. The controls are the shapes that
graded correctly before.
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
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.core.phases.scanner_executor import (
    ScannerExecutor,
    _severity_counts_from_dict,
)
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class _Config(ScannerPluginConfigBase):
    name: Literal["shape-tool"] = "shape-tool"


class OverrideScanner(ScannerPluginBase):
    """Overrides ``scan()`` and returns what ``returned`` holds for the target."""

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
        returned = self.returned
        if isinstance(returned, dict) and set(returned) == {"source", "converted"}:
            return returned[target_type]
        return returned


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


def _rows(plugin_context, returned, targets=None):
    config = _Config()
    config.options.severity_threshold = "MEDIUM"
    scanner = OverrideScanner(config=config, context=plugin_context)
    scanner.returned = returned
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )
    if targets is None:
        targets = [{"path": Path(plugin_context.source_dir), "type": "source"}]
    return executor._execute_scanner("shape-tool", scanner, targets)


def _row(plugin_context, returned):
    (row,) = _rows(plugin_context, returned)
    return row


def _reason(row) -> str:
    return " ".join(str(error) for error in row.errors)


class TestSeverityCountKeysAreMatchedByName:
    def test_upper_case_keys_reach_the_gate(self, plugin_context):
        row = _row(plugin_context, {"severity_counts": {"HIGH": 1, "Low": 2}})

        assert row.status == ScannerStatus.FAILED
        assert row.severity_counts.high == 1
        assert row.severity_counts.low == 2
        assert row.finding_count == 3

    def test_a_key_that_names_no_severity_counts_as_info(self):
        """A tool's own vocabulary (grype's ``negligible``, npm audit's ``moderate``)
        is counted at the lowest level, as a findings-list entry with an unknown
        severity is, so finding_count holds every finding the tool counted; left
        out, those findings were in no count at all. ``total`` is the model's own
        sum and is dropped, whatever the tool wrote under it."""
        counts = _severity_counts_from_dict(
            {"high": 1, "total": 7, "negligible": 3, "moderate": 2}
        )

        assert counts.high == 1
        assert counts.info == 5
        assert counts.total == 6

    def test_a_value_under_an_unknown_key_is_still_a_count(self):
        with pytest.raises(ValueError):
            _severity_counts_from_dict({"high": 1, "negligible": "many"})

    @pytest.mark.parametrize(
        "value", ["many", -1, True, None, [1], 0.9, float("inf"), float("nan")]
    )
    def test_a_value_that_is_not_a_count_is_refused(self, value):
        """0.9 used to truncate to 0 (a finding gone, the row PASSED) and an infinite
        float raised OverflowError past the local handler."""
        with pytest.raises(ValueError):
            _severity_counts_from_dict({"high": value})

    @pytest.mark.parametrize("value", [2, 2.0, "2"])
    def test_a_whole_number_is_the_count_it_spells(self, value):
        assert _severity_counts_from_dict({"high": value}).high == 2


class TestAResultThatCannotBeReadIsThisRowsError:
    def test_a_count_that_is_not_a_number(self, plugin_context):
        row = _row(plugin_context, {"severity_counts": {"high": "many"}})

        assert row.status == ScannerStatus.ERROR
        assert "could not be graded" in _reason(row)

    def test_a_finding_whose_severity_is_not_text_counts_as_info(self, plugin_context):
        row = _row(
            plugin_context, {"findings": [{"severity": 5}, {"severity": "high"}]}
        )

        assert row.status == ScannerStatus.FAILED
        assert row.severity_counts.info == 1
        assert row.severity_counts.medium == 0
        assert row.severity_counts.high == 1
        assert row.finding_count == 2

    @pytest.mark.parametrize("name", ["blocker", "P1", ""])
    def test_a_finding_with_an_unknown_severity_name_counts_as_info(
        self, plugin_context, name
    ):
        """Two defaults, on purpose: a finding that states no severity reads at the
        SARIF default level (MEDIUM, the test below), while one that states a name
        ASH cannot place counts as info, the contract test_scanner_executor_lifecycle
        pins ("unknown severities fall back to info"): a tool's own vocabulary is a
        claim the gate cannot rank, kept lowest rather than promoted above a finding
        that said nothing. Such a finding is still counted (finding_count) and the
        row still grades by what it can place."""
        row = _row(plugin_context, {"findings": [{"severity": name}]})

        assert row.status == ScannerStatus.PASSED
        assert row.severity_counts.info == 1
        assert row.severity_counts.medium == 0
        assert row.finding_count == 1

    def test_a_finding_that_is_not_a_mapping_is_read_as_medium(self, plugin_context):
        row = _row(plugin_context, {"findings": [7, {"severity": "high"}]})

        assert row.status == ScannerStatus.FAILED
        assert row.severity_counts.medium == 1
        assert row.severity_counts.high == 1
        assert row.finding_count == 2

    def test_a_finding_with_no_severity_reaches_the_gate_as_medium(
        self, plugin_context
    ):
        """A severity-less finding used to count in finding_count only, so it could
        never fail the gate; SARIF reads a level-less result as warning (MEDIUM)."""
        row = _row(plugin_context, {"findings": [{"rule": "x"}]})

        assert row.status == ScannerStatus.FAILED
        assert row.severity_counts.medium == 1
        assert row.severity_counts.total == 1
        assert row.finding_count == 1

    def test_metadata_that_is_not_a_mapping_is_not_read(self, plugin_context):
        row = _row(plugin_context, {"tool": "its own json", "metadata": None})

        assert row.status == ScannerStatus.ERROR
        assert "could not be graded" in _reason(row)
        assert row.metadata == {}

    def test_the_other_targets_keep_their_rows(self, plugin_context, tmp_path):
        converted = tmp_path / "converted"
        converted.mkdir()
        rows = _rows(
            plugin_context,
            {
                "source": {"severity_counts": {"high": "many"}},
                "converted": {"findings": [{"severity": "high"}]},
            },
            targets=[
                {"path": Path(plugin_context.source_dir), "type": "source"},
                {"path": converted, "type": "converted"},
            ],
        )

        assert [row.target_type for row in rows] == ["source", "converted"]
        assert rows[0].status == ScannerStatus.ERROR
        assert "could not be graded" in _reason(rows[0])
        assert rows[1].status == ScannerStatus.FAILED
        assert rows[1].finding_count == 1


class TestControls:
    def test_lower_case_counts_grade_as_before(self, plugin_context):
        row = _row(
            plugin_context,
            {"severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0}},
        )

        assert row.status == ScannerStatus.FAILED
        assert row.finding_count == 1

    def test_a_findings_list_grades_as_before(self, plugin_context):
        row = _row(plugin_context, {"findings": [{"severity": "LOW"}]})

        assert row.status == ScannerStatus.PASSED
        assert row.severity_counts.low == 1
        assert row.finding_count == 1

    def test_metadata_that_is_a_mapping_is_read(self, plugin_context):
        row = _row(
            plugin_context,
            {"findings": [], "metadata": {"scanner_version": "1.2.3"}},
        )

        assert row.status == ScannerStatus.PASSED
        assert row.metadata["scanner_version"] == "1.2.3"


class TestAFindingsListsCountsReachTheReport:
    """The counts a findings list was graded on survive the processor's dump.

    Incremented on the field's default, severity_counts was never marked set, the
    processor's exclude_unset dump dropped it from the per-target report, the
    statistics read 0 for the scanner, and the FAILED row rolled up PASSED.
    """

    def test_the_row_marks_its_counts_set(self, plugin_context):
        row = _row(plugin_context, {"findings": [{"severity": "high"}]})

        assert row.status == ScannerStatus.FAILED
        assert "severity_counts" in row.model_fields_set

    def test_the_dumped_report_and_the_statistics_carry_the_counts(
        self, plugin_context
    ):
        row = _row(plugin_context, {"findings": [{"severity": "high"}]})

        aggregated = ScanResultProcessor(
            plugin_context=plugin_context
        ).process_container(row, AshAggregatedResults())
        report = aggregated.additional_reports["shape-tool"]["source"]
        aggregated.ash_config = plugin_context.config
        stats = ScannerStatisticsCalculator.extract_scanner_statistics(aggregated)

        assert report["severity_counts"]["high"] == 1, sorted(report)
        assert stats["shape-tool"]["high"] == 1
        assert stats["shape-tool"]["actionable"] == 1
