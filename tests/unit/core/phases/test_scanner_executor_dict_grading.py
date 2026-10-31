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

    def test_two_spellings_of_one_level_are_summed(self):
        """Normalizing the key then assigning would keep the last spelling and drop
        the other's count: a finding gone, and a row that could grade PASSED."""
        counts = _severity_counts_from_dict({"HIGH": 1, "high": 2, " High ": 4})

        assert counts.high == 7
        assert counts.total == 7

    def test_the_total_key_is_dropped_whatever_its_case(self):
        """``total`` is the model's own sum. Compared before the key is lowercased
        and stripped, ``Total`` would be counted as a level it does not name (info)
        and inflate finding_count by the tool's own total."""
        counts = _severity_counts_from_dict(
            {"Total": 9, "TOTAL": 9, " total ": 9, "high": 1}
        )

        assert counts.high == 1
        assert counts.info == 0
        assert counts.total == 1

    def test_a_key_that_names_no_severity_counts_as_info(self):
        """A tool's own vocabulary (grype's ``negligible``) is counted at the lowest
        level, as a findings-list entry with an unknown severity is, so
        finding_count holds every finding the tool counted; left out, those
        findings were in no count at all. ``total`` is the model's own sum and is
        dropped, whatever the tool wrote under it. A word whose rank is not in
        doubt (npm audit's ``moderate``) is counted at that rank: counted as info
        it passed a MEDIUM threshold over moderate findings."""
        counts = _severity_counts_from_dict(
            {"high": 1, "total": 7, "negligible": 3, "moderate": 2}
        )

        assert counts.high == 1
        assert counts.info == 3
        assert counts.medium == 2
        assert counts.total == 6

    def test_the_aliases_name_the_level_they_stand_for_whatever_their_case(self):
        counts = _severity_counts_from_dict(
            {"Moderate": 1, " IMPORTANT ": 2, "Blocker": 3, "informational": 4}
        )

        assert counts.medium == 1
        assert counts.high == 2
        assert counts.critical == 3
        assert counts.info == 4

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

    @pytest.mark.parametrize(
        "value", [None, ["high"], True, float("nan"), 11, -1, "", "  "]
    )
    def test_a_finding_whose_severity_states_none_is_read_as_medium(
        self, plugin_context, value
    ):
        """A null, a list, a boolean, a number outside 0 to 10 and an empty text
        are no name or score the ladder can read, so the finding states no
        severity and is read as one that omits the key: MEDIUM, at the gate. Read
        as info it graded a finding PASSED at a MEDIUM threshold, the most lenient
        outcome for the shape ASH could read least. An empty text was counted as
        info while the same finding with no key was MEDIUM."""
        row = _row(plugin_context, {"findings": [{"severity": value}]})

        assert row.status == ScannerStatus.FAILED
        assert row.severity_counts.medium == 1
        assert row.severity_counts.info == 0
        assert row.finding_count == 1

    @pytest.mark.parametrize(
        "score,level",
        [
            (10, "critical"),
            (9.8, "critical"),
            (9.0, "critical"),
            (8.9, "high"),
            (7.0, "high"),
            (6.9, "medium"),
            (5, "medium"),
            (4.0, "medium"),
            (3.9, "low"),
            (0.1, "low"),
            (0, "info"),
        ],
    )
    def test_a_number_is_read_by_its_cvss_band(self, plugin_context, score, level):
        """Red at the base for every score but 4.0 to 6.9: all were counted MEDIUM,
        so a 9.8 passed a HIGH threshold and a 3.9 failed a MEDIUM one."""
        row = _row(plugin_context, {"findings": [{"severity": score}]})

        assert getattr(row.severity_counts, level) == 1, row.severity_counts
        assert row.severity_counts.total == 1
        assert row.finding_count == 1

    @pytest.mark.parametrize(
        "name,level",
        [
            ("moderate", "medium"),
            ("Moderate", "medium"),
            ("important", "high"),
            ("blocker", "critical"),
            ("Informational", "info"),
        ],
    )
    def test_a_word_whose_rank_is_not_in_doubt_counts_at_that_rank(
        self, plugin_context, name, level
    ):
        """npm audit and GitHub write ``moderate``, SonarQube ``blocker``: counted
        as info, a moderate finding passed a MEDIUM threshold."""
        row = _row(plugin_context, {"findings": [{"severity": name}]})

        assert getattr(row.severity_counts, level) == 1, row.severity_counts
        assert row.severity_counts.total == 1

    @pytest.mark.parametrize("name", ["P1", "major", "bogus"])
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

    @pytest.mark.parametrize("name", [" HIGH ", "High\n", "\thigh"])
    def test_a_severity_name_is_read_without_its_surrounding_whitespace(
        self, plugin_context, name
    ):
        """The keys of a severity_counts dict are stripped before they are matched;
        the severity of a finding was lowercased but not stripped, so a tool that
        pads its words counted a high finding as info and the row graded PASSED.
        Red at the base: info 1, high 0, PASSED."""
        row = _row(plugin_context, {"findings": [{"severity": name}]})

        assert row.status == ScannerStatus.FAILED
        assert row.severity_counts.high == 1
        assert row.severity_counts.info == 0
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
        """The only difference from the mapping control below is ``metadata``: the
        result is gradable (an empty findings list), so the row is PASSED and the
        null is simply not read. With nothing else to grade the row would be ERROR
        for that, and the test could not tell the metadata handling apart."""
        row = _row(plugin_context, {"findings": [], "metadata": None})

        assert row.status == ScannerStatus.PASSED
        assert "could not be graded" not in _reason(row)
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
