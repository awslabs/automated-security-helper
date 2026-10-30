# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``merge_shard_results`` reads every shard's record as the shard wrote it.

Seven shapes a sharded fan-out produces that the merge read wrong:

* a shard written before ``selected_scanners`` existed beside shards that record
  it: its scanners were named as intended by no shard and said to show SKIPPED;
* the shards' own objects reached the merged report by reference (tool
  components, their rules, ``additional_reports`` values, ``scanner_results``
  rows), so the secret masking that follows masked the loaded shards in place;
* the start and end times were compared as text, which orders two ISO-8601
  spellings of one instant by their suffix instead of by the instant;
* a converter failure already folded into the merged row was folded in again
  from the third shard on, and the reason a converter's dependencies were
  unavailable was dropped from the merged row;
* an excluded converter's dependency fields overrode those of the shard that
  ran it;
* a ``scanner_results`` row no shard owns, the ERROR or MISSING row the union
  check exempts from its refusal so that the report still names it, was dropped
  while its ``additional_reports`` marker was carried;
* two shards whose recorded suppressions differ were refused under
  ``--ignore-suppressions``, where that setting does not reach the exit code;
  shards whose ignore paths differ stay refused under the flag, because an
  ignore path dropped results the merge cannot bring back.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.cli.merge import (
    ShardSettingsDisagreeError,
    _adopt_owning_shard_results,
    apply_aggregated_suppressions,
    _merge_converter_rows,
    merge_shard_results,
    read_shard_assignment,
    stamp_shard_assignment,
    verify_verdict_settings_agree,
)
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import (
    ConverterStatusInfo,
    FailedInputInfo,
    ScannerStatusInfo,
)
from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from tests.unit.cli.merge_shard_support import (
    SCANNERS,
    _sarif_for,
    _skipped_entries,
    as_loaded,
    build_shards,
)

pytestmark = pytest.mark.unit

# The ``capture`` fixture comes from this directory's conftest.


class TestAShardWithoutASelectionRecordIntendedWhatItOwned:
    def test_its_scanners_are_not_named_as_intended_by_no_shard(self, capture):
        shards = build_shards(3)
        for model in shards:
            assignment = read_shard_assignment(model)
            assignment.selected_scanners = list(assignment.assigned_scanners)
            stamp_shard_assignment(model, assignment)
        # The second shard predates the field: it recorded no selection at all.
        older = read_shard_assignment(shards[1])
        older.selected_scanners = None
        stamp_shard_assignment(shards[1], older)

        merge_shard_results(as_loaded(shards))

        named = [
            record.getMessage()
            for record in capture.records
            if "ran on no shard" in record.getMessage()
            or "no shard intended to run them" in record.getMessage()
        ]
        assert named == [], named

    def test_a_scanner_the_older_shard_recorded_skipped_is_still_named(self, capture):
        """A shard with no selection record that skipped one of its own scanners
        (its own ``--exclude-scanners`` or config left it out) left a hole: no
        shard ran it. Reading the whole assignment as intended hid that hole; the
        shard's own row says it was skipped, so it is named, and the scanners it
        ran are not."""
        shards = build_shards(3)
        for model in shards:
            assignment = read_shard_assignment(model)
            assignment.selected_scanners = list(assignment.assigned_scanners)
            stamp_shard_assignment(model, assignment)
        older = read_shard_assignment(shards[1])
        older.selected_scanners = None
        stamp_shard_assignment(shards[1], older)
        skipped = older.assigned_scanners[0]
        _skipped_entries(shards[1], skipped)
        shards[1].sarif = _sarif_for(
            [s for s in older.assigned_scanners if s != skipped]
        )

        merge_shard_results(as_loaded(shards))

        named = [
            record.getMessage()
            for record in capture.records
            if "ran on no shard" in record.getMessage()
            or "no shard intended to run them" in record.getMessage()
        ]
        assert len(named) == 1, named
        assert skipped in named[0], named
        # The control: every scanner some shard ran is not in the warning.
        for ran in SCANNERS:
            if ran != skipped:
                assert ran not in named[0], named

    def test_a_shard_that_recorded_an_empty_selection_is_still_named(self, capture):
        """The control: an empty selection says the shard intended nothing."""
        shards = build_shards(3)
        for model in shards:
            assignment = read_shard_assignment(model)
            assignment.selected_scanners = list(assignment.assigned_scanners)
            stamp_shard_assignment(model, assignment)
        narrowed = read_shard_assignment(shards[1])
        narrowed.selected_scanners = []
        stamp_shard_assignment(shards[1], narrowed)

        merge_shard_results(as_loaded(shards))

        assert any(
            "no shard intended to run them" in record.getMessage()
            or "ran on no shard" in record.getMessage()
            for record in capture.records
        ), [record.getMessage() for record in capture.records]


class TestTheMergedReportSharesNothingWithTheShards:
    def test_tool_components_and_rules_are_copies(self):
        shards = build_shards(3)

        merged = merge_shard_results(as_loaded(shards))

        shard_components = {
            id(component)
            for model in shards
            for component in model.sarif.runs[0].tool.extensions
        }
        shard_rules = {
            id(rule)
            for model in shards
            for component in model.sarif.runs[0].tool.extensions
            for rule in component.rules or []
        }
        for component in merged.sarif.runs[0].tool.extensions:
            assert id(component) not in shard_components
            for rule in component.rules or []:
                assert id(rule) not in shard_rules

    def test_additional_reports_and_scanner_rows_are_copies(self):
        shards = build_shards(3)

        merged = merge_shard_results(as_loaded(shards))

        shard_reports = {
            id(report)
            for model in shards
            for report in model.additional_reports.values()
        }
        for report in merged.additional_reports.values():
            assert id(report) not in shard_reports
        shard_rows = {
            id(row) for model in shards for row in model.scanner_results.values()
        }
        for row in merged.scanner_results.values():
            assert id(row) not in shard_rows

    def test_editing_the_merged_report_leaves_the_shards_as_loaded(self):
        shards = build_shards(3)
        before = [model.model_dump_json() for model in shards]

        merged = merge_shard_results(as_loaded(shards))
        for component in merged.sarif.runs[0].tool.extensions:
            component.name = "renamed"
            for rule in component.rules or []:
                rule.id = "renamed"
        for report in merged.additional_reports.values():
            if isinstance(report, dict):
                report.clear()

        assert [model.model_dump_json() for model in shards] == before


class TestTimingIsOrderedByInstant:
    def test_the_earliest_start_is_the_earliest_instant_not_the_smallest_text(self):
        shards = build_shards(2)
        # 10:00 at +02:00 is 08:00Z, the earlier instant; as text it sorts after
        # 09:00+00:00.
        shards[0].metadata.summary_stats.start = "2026-08-28T10:00:00+02:00"
        shards[1].metadata.summary_stats.start = "2026-08-28T09:00:00+00:00"
        shards[0].metadata.summary_stats.end = "2026-08-28T10:30:00+02:00"
        shards[1].metadata.summary_stats.end = "2026-08-28T09:30:00+00:00"

        merged = merge_shard_results(as_loaded(shards))

        assert merged.metadata.summary_stats.start == "2026-08-28T10:00:00+02:00"
        # 09:30Z is the later instant; as text 10:30+02:00 (08:30Z) sorts after it.
        assert merged.metadata.summary_stats.end == "2026-08-28T09:30:00+00:00"

    def test_a_z_suffix_and_a_short_fraction_are_parsed_as_instants(self):
        """The two spellings the comment names: ``10:00:00Z`` sorts after
        ``10:00:00.5Z`` as text while it is the earlier instant. Python 3.10's
        ``fromisoformat`` rejects both (the ``Z``, a one-digit fraction), which
        put every merge on that interpreter on the text order; the parse now
        normalizes them first. On 3.11 and later the parser accepts them itself,
        so this test is green there on either side; the 3.10 leg is the red."""
        shards = build_shards(2)
        shards[0].metadata.summary_stats.start = "2026-08-28T10:00:00Z"
        shards[1].metadata.summary_stats.start = "2026-08-28T10:00:00.5Z"
        shards[0].metadata.summary_stats.end = "2026-08-28T10:30:00.25Z"
        shards[1].metadata.summary_stats.end = "2026-08-28T10:30:00Z"

        merged = merge_shard_results(as_loaded(shards))

        assert merged.metadata.summary_stats.start == "2026-08-28T10:00:00Z"
        assert merged.metadata.summary_stats.end == "2026-08-28T10:30:00.25Z"

    def test_the_parse_reads_the_three_spellings_as_one_instant(self):
        # Imported here, not at module scope: a tree without the helper then
        # fails this test alone and still collects the rest of the file, so the
        # other tests' own red-first reads are not hidden behind an ImportError.
        from automated_security_helper.cli.merge import _parse_instant

        zulu = _parse_instant("2026-08-28T08:00:00Z")
        assert _parse_instant("2026-08-28T08:00:00.000Z") == zulu
        assert _parse_instant("2026-08-28T08:00:00.0Z") == zulu
        assert _parse_instant("2026-08-28T10:00:00+02:00") == zulu
        assert _parse_instant("2026-08-28T08:00:00.5Z") > zulu
        with pytest.raises(ValueError):
            _parse_instant("not a time")

    def test_text_that_does_not_parse_is_ordered_as_text(self):
        """The fallback, so a hand-written stamp cannot crash the merge."""
        shards = build_shards(2)
        shards[0].metadata.summary_stats.start = "not a time"
        shards[1].metadata.summary_stats.start = "2026-08-28T09:00:00"

        merged = merge_shard_results(as_loaded(shards))

        assert merged.metadata.summary_stats.start == "2026-08-28T09:00:00"


class TestConverterRowsAcrossThreeShards:
    def test_a_failure_folded_in_once_is_not_repeated_by_a_third_shard(self):
        first = ConverterStatusInfo(failure="RuntimeError: crashed")
        second = ConverterStatusInfo(failure="TimeoutError: timed out")
        third = ConverterStatusInfo(failure="RuntimeError: crashed")

        row = _merge_converter_rows([first, second, third])

        assert row.failure == "RuntimeError: crashed; TimeoutError: timed out"

    def test_a_message_holding_the_join_text_survives_whole(self):
        """A CalledProcessError's text holds "; " itself. Folding two rows at a
        time read the join back as parts, so the second message lost the
        fragment it shared with the first and the merged text said what no
        shard recorded. Whole messages, once each, in shard order."""
        first = ConverterStatusInfo(failure="nbconvert timed out; partial output kept")
        second = ConverterStatusInfo(failure="nbconvert timed out; killed")
        third = ConverterStatusInfo(failure="nbconvert timed out; partial output kept")

        row = _merge_converter_rows([first, second, third])

        assert row.failure == (
            "nbconvert timed out; partial output kept; nbconvert timed out; killed"
        )

    def test_a_reason_holding_the_join_text_survives_whole(self):
        rows = [
            ConverterStatusInfo(
                dependencies_satisfied=False,
                candidate_inputs=1,
                dependency_unavailable_reason=reason,
            )
            for reason in ("pandoc missing; see docs", "pandoc missing; install it")
        ]

        row = _merge_converter_rows(rows)

        assert row.dependency_unavailable_reason == (
            "pandoc missing; see docs; pandoc missing; install it"
        )

    def test_the_dependency_reason_reaches_the_merged_row(self):
        ran = ConverterStatusInfo(converted_paths=["converted/nb.py"])
        unavailable = ConverterStatusInfo(
            dependencies_satisfied=False,
            candidate_inputs=2,
            dependency_unavailable_reason="jupyter nbconvert is not installed",
        )

        row = _merge_converter_rows([ran, unavailable])

        assert row.dependencies_satisfied is False
        assert row.dependency_unavailable_reason == "jupyter nbconvert is not installed"

    def test_a_reason_folded_in_once_is_not_repeated_by_a_third_shard(self):
        """The reasons are gathered as the failures are: whole, once each."""
        rows = [
            ConverterStatusInfo(
                dependencies_satisfied=False,
                candidate_inputs=1,
                dependency_unavailable_reason=reason,
            )
            for reason in ("nbconvert missing", "pandoc missing", "nbconvert missing")
        ]

        row = _merge_converter_rows(rows)

        assert row.dependency_unavailable_reason == "nbconvert missing; pandoc missing"

    def test_an_excluded_shard_does_not_mark_a_converter_that_ran_unavailable(self):
        excluded = ConverterStatusInfo(
            excluded=True,
            dependencies_satisfied=False,
            dependency_unavailable_reason="never checked: excluded",
        )
        ran = ConverterStatusInfo(converted_paths=["converted/nb.py"])

        row = _merge_converter_rows([excluded, ran])

        assert row.excluded is False
        assert row.dependencies_satisfied is True
        assert row.dependency_unavailable_reason is None

    def test_an_excluded_rows_reason_does_not_leak_when_the_running_row_has_none(
        self,
    ):
        excluded = ConverterStatusInfo(
            excluded=True,
            dependencies_satisfied=False,
            dependency_unavailable_reason="never checked: excluded",
        )
        ran_without = ConverterStatusInfo(dependencies_satisfied=False)

        row = _merge_converter_rows([excluded, ran_without])

        assert row.dependencies_satisfied is False
        assert row.dependency_unavailable_reason is None

    def test_a_reason_neither_row_set_stays_unset(self):
        """The function's promise: a field neither row set is left unset, so a
        dump of the merged row carries no key the shards did not write."""
        first = ConverterStatusInfo(dependencies_satisfied=False)
        second = ConverterStatusInfo(dependencies_satisfied=False)

        row = _merge_converter_rows([first, second])

        assert row.dependencies_satisfied is False
        assert "dependency_unavailable_reason" not in row.model_fields_set

    def test_an_accepted_record_does_not_hide_another_shards_tool_failure(self):
        accepted = ConverterStatusInfo(
            failed_inputs=[
                FailedInputInfo(
                    path="nb.ipynb",
                    reason="not a notebook",
                    kind="input",
                    accepted=True,
                    accepted_reason="known fixture",
                )
            ]
        )
        failed = ConverterStatusInfo(
            failed_inputs=[
                FailedInputInfo(path="nb.ipynb", reason="nbconvert exited with code 1")
            ]
        )

        row = _merge_converter_rows([accepted, failed])

        assert [(r.path, r.accepted) for r in row.failed_inputs] == [
            ("nb.ipynb", False)
        ]
        assert row.failed_inputs[0].reason == "nbconvert exited with code 1"

    def test_two_excluded_rows_keep_their_dependency_fields(self):
        """The control: with no shard that ran it, the rows' own fields stand."""
        first = ConverterStatusInfo(excluded=True, dependencies_satisfied=False)
        second = ConverterStatusInfo(excluded=True, dependencies_satisfied=False)

        row = _merge_converter_rows([first, second])

        assert row.excluded is True
        assert row.dependencies_satisfied is False


class TestAScannerRowNoShardOwnsIsKept:
    def test_an_unowned_error_row_survives_adoption(self):
        shards = build_shards(2)
        shards[1].scanner_results["broken.plugin.module"] = ScannerStatusInfo(
            status=ScannerStatus.ERROR,
            excluded=False,
            dependencies_satisfied=True,
            missing_reason="the module failed to import",
        )
        merged = shards[0].model_copy(deep=True)
        entries = [
            (path, model, read_shard_assignment(model))
            for path, model in as_loaded(shards)
        ]
        owners = {
            scanner.lower(): position
            for position, (_, _, assignment) in enumerate(entries)
            for scanner in assignment.assigned_scanners
        }

        _adopt_owning_shard_results(merged, entries, owners)

        row = merged.scanner_results["broken.plugin.module"]
        assert row.status == ScannerStatus.ERROR
        assert row.missing_reason == "the module failed to import"
        assert row is not shards[1].scanner_results["broken.plugin.module"]

    def test_a_non_owning_shards_skip_marker_is_still_dropped(self):
        """The control: owned scanners keep only their owner's row."""
        shards = build_shards(2)
        merged = shards[0].model_copy(deep=True)
        entries = [
            (path, model, read_shard_assignment(model))
            for path, model in as_loaded(shards)
        ]
        owners = {
            scanner.lower(): position
            for position, (_, _, assignment) in enumerate(entries)
            for scanner in assignment.assigned_scanners
        }

        _adopt_owning_shard_results(merged, entries, owners)

        for name, position in owners.items():
            assert merged.scanner_results[name].excluded is False, name
            assert (
                merged.scanner_results[name].model_dump()
                == entries[position][1].scanner_results[name].model_dump()
            )


class TestIgnoreSuppressionsLiftsTheSuppressionAgreement:
    @staticmethod
    def _disagreeing_on_ignore_paths():
        shards = build_shards(2)
        shards[1].ash_config.global_settings.ignore_paths = [
            IgnorePathWithReason(path="vendor/**", reason="third party")
        ]
        return shards

    def test_the_disagreement_is_refused_without_the_flag(self):
        with pytest.raises(ShardSettingsDisagreeError, match="ignore_paths"):
            verify_verdict_settings_agree(
                as_loaded(self._disagreeing_on_ignore_paths())
            )

    def test_the_disagreement_is_still_refused_under_the_flag(self):
        """An ignore path drops results from a shard's SARIF; nothing lifts them.

        So two shards that disagree on their ignore paths hand the merge two
        different sets of findings, flag or no flag, and the merged report would
        carry a vendor finding or not depending on which shard's scanner found it.
        """
        with pytest.raises(ShardSettingsDisagreeError, match="ignore_paths"):
            verify_verdict_settings_agree(
                as_loaded(self._disagreeing_on_ignore_paths()),
                ignore_suppressions=True,
            )

    @staticmethod
    def _agreeing_on_an_ignore_path():
        shards = build_shards(2)
        for shard in shards:
            shard.ash_config.global_settings.ignore_paths = [
                IgnorePathWithReason(path="vendor/**", reason="third party")
            ]
        return shards

    def test_ignore_paths_the_flag_cannot_lift_are_named_under_it(
        self, tmp_path, capture
    ):
        """Shards that agree on an ignore path merge; under the flag the merge
        then reports fewer findings than ``ash scan --ignore-suppressions``, which
        keeps the results under the path, since each shard dropped them before
        the merge. The flag's promise does not hold there, so the paths are named."""
        merged = merge_shard_results(as_loaded(self._agreeing_on_an_ignore_path()))

        apply_aggregated_suppressions(
            merged,
            PluginContext(
                source_dir=tmp_path,
                output_dir=tmp_path / "out",
                config=merged.ash_config,
                ignore_suppressions=True,
            ),
        )

        named = [
            record.getMessage()
            for record in capture.records
            if "ignore path" in record.getMessage()
        ]
        assert len(named) == 1, named
        assert "vendor/**" in named[0], named

    def test_ignore_paths_are_not_named_without_the_flag(self, tmp_path, capture):
        """The control: without the flag the ignore paths are the scan's own rule."""
        merged = merge_shard_results(as_loaded(self._agreeing_on_an_ignore_path()))

        apply_aggregated_suppressions(
            merged,
            PluginContext(
                source_dir=tmp_path,
                output_dir=tmp_path / "out",
                config=merged.ash_config,
                ignore_suppressions=False,
            ),
        )

        assert not [
            record.getMessage()
            for record in capture.records
            if "ignore path" in record.getMessage()
        ]

    def test_differing_suppressions_are_not_refused_under_the_flag(self):
        """The control: the flag lifts the suppressions, so it lifts their agreement."""
        shards = build_shards(2)
        shards[1].ash_config.global_settings.suppressions = [
            AshSuppression(rule_id="B101", path="src/app.py", reason="reviewed")
        ]

        verify_verdict_settings_agree(as_loaded(shards), ignore_suppressions=True)
        with pytest.raises(ShardSettingsDisagreeError, match="suppressions"):
            verify_verdict_settings_agree(as_loaded(shards))

    def test_a_verdict_setting_is_still_refused_under_the_flag(self):
        """The second control: the flag lifts the suppression setting only."""
        shards = build_shards(2)
        shards[1].ash_config.fail_on_findings = False

        with pytest.raises(ShardSettingsDisagreeError, match="fail_on_findings"):
            verify_verdict_settings_agree(as_loaded(shards), ignore_suppressions=True)
