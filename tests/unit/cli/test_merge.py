# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``ash merge``, the recombination half of scan sharding.

The load-bearing test here is ``TestShardedEqualsUnsharded``, which asserts the
property the whole feature rests on: merging n shards of a tree yields the same
findings, the same per-scanner statuses and the same verdict as one unsharded
scan of that tree. Testing the pieces in isolation would not catch the failure
that matters, because every piece can be individually correct while the assembled
report still disagrees with a plain scan -- that is exactly what happens if a
non-owning shard's skip marker survives the merge.

Both sides of that comparison are put through
``populate_metrics_from_unified_source`` before comparing. Comparing a merged
model that had its statistics recomputed against a hand-built one that did not
would be a differential between "was this computed" and "was this merged", and it
would pass no matter how wrong the merge was.

The refusal tests each pin one way a set of shards can fail to describe one whole
scan. They matter more than they look: every one of them, if it did not raise,
would produce a well-formed report that reads as a complete scan while being
missing whole scanners or double-counting findings. A reviewer cannot tell the
difference by looking at the report, so the check is the only thing standing
between a partial merge and a false clean bill of health.
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.cli.merge import (
    MERGED_SHARD_COUNT_KEY,
    MERGED_SHARD_INDICES_KEY,
    RESULTS_FILE_NAME,
    SHARD_PROVENANCE_KEY,
    _completed,
    _merged_exit_code,
    _shown_lines,
    apply_aggregated_suppressions,
    load_shard_results,
    merge_shard_results,
    read_shard_assignment,
    resolve_results_file,
    stamp_shard_assignment,
)
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import ShardCoverageError
from automated_security_helper.core.sharding import (
    ShardAssignment,
    partition_scanners,
    shown_shard_text,
)
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.interactions.run_ash_scan import (
    IncompleteConverter,
    incomplete_converters,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
    FailedInputInfo,
    RefusedInputInfo,
    ScannerStatusInfo,
    ScannerTargetStatusInfo,
)

# The shard fixtures live in tests/unit/cli/merge_shard_support.py, so a test module
# that needs shards does not have to import this one. They are imported back here
# so the modules that already take them from this one keep working.
from tests.unit.cli.merge_shard_support import (  # noqa: F401
    FINDINGS,
    SCANNERS,
    SHARED_COMPONENT,
    _build_config,
    _ran_entries,
    _sarif_for,
    _sarif_result,
    _skipped_entries,
    as_loaded,
    build_shard,
    build_shards,
    write_shards,
)

pytestmark = pytest.mark.unit

#: The logger the merge's disclosures are written to.
ASH_LOGGER_NAME = "ash"

# The ``capture`` fixture (ASH's logger routed into caplog) lives in this
# directory's conftest, so every merge test module gets it by name.


def build_unsharded(suppressions=None) -> AshAggregatedResults:
    """Build the results a single unsharded scan of the same tree would write."""
    model = AshAggregatedResults()
    model.ash_config = _build_config(suppressions=suppressions)
    model.sarif = _sarif_for(SCANNERS)
    for scanner in SCANNERS:
        _ran_entries(model, scanner)
    model.metadata.summary_stats.start = "2026-08-28T10:00:00"
    model.metadata.summary_stats.end = "2026-08-28T10:24:00"
    model.metadata.summary_stats.duration = 64.0
    return populate_metrics_from_unified_source(aggregated_results=model)


def finding_key(result) -> Tuple:
    """A stable identity for one SARIF result, independent of ordering.

    Deliberately does not include ``ruleIndex``: ``merge_sarif_report`` strips it
    because it reorders rules, so requiring it to match would fail for a correct
    merge.
    """
    location = result.locations[0].physicalLocation.root
    return (
        result.ruleId,
        str(result.level),
        (
            result.properties.model_dump().get("issue_severity")
            if result.properties
            else None
        ),
        location.artifactLocation.uri,
        location.region.startLine,
    )


def finding_keys(model: AshAggregatedResults) -> List[Tuple]:
    return sorted(
        finding_key(result)
        for run in model.sarif.runs
        for result in (run.results or [])
    )


class TestShardedEqualsUnsharded:
    """The property the feature rests on: n shards merged == one whole scan."""

    @pytest.mark.parametrize("shard_count", [1, 2, 3, 5, 7])
    def test_findings_match_an_unsharded_scan(self, shard_count):
        # 7 exceeds the scanner count on purpose: surplus shards are empty, and
        # they must merge to the same report rather than being refused.
        unsharded = build_unsharded()
        merged = merge_shard_results(as_loaded(build_shards(shard_count)))

        assert finding_keys(merged) == finding_keys(unsharded)

    def test_a_shard_count_far_above_the_scanner_count_still_merges(self):
        # core/sharding's docstring allows a shard count above the scanner count
        # so a pipeline can parameterize it without knowing how many scanners
        # exist, calling the surplus shards "wasteful rather than wrong". This
        # pins the merge half of that promise at a shard count a CI pipeline
        # plausibly permits: 50 shards over 5 scanners leaves 45 shards whose
        # assigned_scanners is empty.
        #
        # Worth pinning rather than leaving to the n=7 case, because an empty
        # assignment is exactly the shape a future coverage check might decide is
        # suspicious. Refusing it would turn a merely wasteful configuration into
        # a pipeline that cannot merge at all, and the failure would read as
        # missing coverage rather than as an over-large shard count.
        shard_count = 50
        shards = build_shards(shard_count)
        surplus = [
            model
            for model in shards
            if not read_shard_assignment(model).assigned_scanners
        ]
        assert len(surplus) == shard_count - len(SCANNERS)
        # Every surplus shard still records provenance. ScanPhase gates the stamp
        # on the scanners it *discovered*, not on the slice it was assigned, so an
        # empty slice is stamped and only a runner that found no scanners at all
        # goes unstamped.
        assert all(read_shard_assignment(model) is not None for model in shards)

        merged = merge_shard_results(as_loaded(shards))

        assert finding_keys(merged) == finding_keys(build_unsharded())
        assert len(merged.scanner_results) == len(SCANNERS)
        assert [
            name for name, entry in merged.scanner_results.items() if entry.excluded
        ] == []

    def test_the_shards_run_records_are_not_merged(self):
        """Each shard's completion marker, refusal record and report list is its own."""
        shards = build_shards(3)
        for index, shard in enumerate(shards):
            shard.validation_checkpoints.extend(
                [
                    {"type": "run_completed", "metadata": {"run_id": f"{index}" * 32}},
                    {"type": "report_path_refused", "message": f"shard {index}"},
                    {"type": "reports_written", "metadata": {"files": ["ash.sarif"]}},
                    {"type": "config_warning", "message": f"kept {index}"},
                ]
            )

        merged = merge_shard_results(as_loaded(shards))

        assert [cp["type"] for cp in merged.validation_checkpoints] == [
            "config_warning"
        ] * 3

    def test_one_collapsed_sarif_run(self):
        # Shards share a single root, so one run is the honest shape. N runs would
        # describe a workspace that does not exist.
        merged = merge_shard_results(as_loaded(build_shards(3)))

        assert len(merged.sarif.runs) == 1

    @pytest.mark.parametrize("shard_count", [2, 3, 5])
    def test_scanner_statuses_match_an_unsharded_scan(self, shard_count):
        # The regression this exists for: a non-owning shard's SKIPPED marker
        # surviving the merge and reporting a scanner that ran as excluded.
        unsharded = build_unsharded()
        merged = merge_shard_results(as_loaded(build_shards(shard_count)))

        assert {
            name: (entry.status, entry.excluded, entry.finding_count)
            for name, entry in merged.scanner_results.items()
        } == {
            name: (entry.status, entry.excluded, entry.finding_count)
            for name, entry in unsharded.scanner_results.items()
        }

    def test_no_scanner_is_reported_as_skipped(self):
        merged = merge_shard_results(as_loaded(build_shards(3)))

        skipped = [
            name
            for name, entry in merged.scanner_results.items()
            if entry.status == ScannerStatus.SKIPPED or entry.excluded
        ]
        assert skipped == []
        assert merged.metadata.summary_stats.skipped == 0

    @pytest.mark.parametrize("shard_count", [2, 3, 5])
    def test_summary_stats_are_the_unions_stats(self, shard_count):
        # Counts must be the union's, not one shard's. Without the recompute step
        # every number here would be the base shard's.
        unsharded = build_unsharded()
        merged = merge_shard_results(as_loaded(build_shards(shard_count)))

        merged_stats = merged.metadata.summary_stats
        expected = unsharded.metadata.summary_stats
        assert (merged_stats.total, merged_stats.actionable) == (
            expected.total,
            expected.actionable,
        )
        assert merged_stats.severity_counts.model_dump() == (
            expected.severity_counts.model_dump()
        )
        assert (merged_stats.passed, merged_stats.failed, merged_stats.skipped) == (
            expected.passed,
            expected.failed,
            expected.skipped,
        )

    def test_every_scanners_rule_metadata_survives(self):
        # merge_sarif_report reads only tool.driver, so without the extensions
        # union the rules of every scanner owned by shards 1..n-1 vanish and their
        # findings reference a ruleId that resolves to nothing.
        merged = merge_shard_results(as_loaded(build_shards(3)))

        extensions = merged.sarif.runs[0].tool.extensions or []
        rule_ids = {rule.id for ext in extensions for rule in (ext.rules or [])}
        expected = {
            f"{scanner}-RULE-{index}"
            for scanner, findings in FINDINGS.items()
            for index in range(len(findings))
        }
        assert expected.issubset(rule_ids)

    def test_no_duplicate_tool_components(self):
        merged = merge_shard_results(as_loaded(build_shards(3)))

        extensions = merged.sarif.runs[0].tool.extensions or []
        identities = [(ext.name, ext.fullName, ext.organization) for ext in extensions]
        assert len(identities) == len(set(identities))

    def test_a_component_reported_by_every_shard_keeps_all_its_rules(self):
        # The union-into-existing branch. A component arriving from three shards
        # must end up once, holding every shard's rules -- appending blindly gives
        # three copies, keeping the first loses two thirds of the rule metadata.
        merged = merge_shard_results(as_loaded(build_shards(3)))

        extensions = merged.sarif.runs[0].tool.extensions or []
        name, full_name, organization = SHARED_COMPONENT
        shared = [
            ext
            for ext in extensions
            if (ext.name, ext.fullName, ext.organization)
            == (name, full_name, organization)
        ]
        assert len(shared) == 1
        assert {rule.id for rule in shared[0].rules or []} == {
            f"shared-{scanner}" for scanner in SCANNERS
        }

    def test_merged_report_is_independent_of_argument_order(self):
        # An operator listing shards in a different order must get the same
        # report, or two CI runs of the same commit produce undiffable output.
        shards = build_shards(3)
        forward = merge_shard_results(as_loaded(shards))
        backward = merge_shard_results(as_loaded(list(reversed(shards))))

        assert finding_keys(forward) == finding_keys(backward)
        assert forward.metadata.summary_stats.model_dump() == (
            backward.metadata.summary_stats.model_dump()
        )
        assert sorted(forward.scanner_results) == sorted(backward.scanner_results)
        # Identity comes from the lowest-indexed shard either way. Everything
        # above is order-invariant by construction -- findings are compared
        # sorted, and the statistics are recomputed from the union -- so without
        # a base-dependent assertion this test would pass even if the base were
        # taken from whichever shard was listed first.
        assert forward.name == backward.name == "shard-0 scan"
        assert (
            getattr(forward.metadata, MERGED_SHARD_INDICES_KEY)
            == getattr(backward.metadata, MERGED_SHARD_INDICES_KEY)
            == [0, 1, 2]
        )

    def test_inputs_are_not_mutated(self):
        shards = build_shards(3)
        before = [model.model_dump_json() for model in shards]

        merge_shard_results(as_loaded(shards))

        assert [model.model_dump_json() for model in shards] == before


class TestCoverageIsRefused:
    """Each of these would otherwise yield a report that reads as complete."""

    def test_missing_shard_is_refused(self):
        shards = build_shards(5)
        del shards[2]

        with pytest.raises(ShardCoverageError, match=r"Missing shard results"):
            merge_shard_results(as_loaded(shards))

    def test_duplicated_shard_is_refused(self):
        shards = build_shards(3)
        shards.append(shards[0].model_copy(deep=True))

        with pytest.raises(ShardCoverageError, match=r"appear more than once"):
            merge_shard_results(as_loaded(shards))

    def test_shards_from_different_runs_are_refused(self):
        # Disagreeing shard_count means the matrix changed mid-flight, so the two
        # partitions were computed over different splits and the union has a hole.
        shards = build_shards(3)
        shards.append(build_shard(3, 4, ["detect-secrets"]))

        with pytest.raises(
            ShardCoverageError, match=r"disagree about the total shard count"
        ):
            merge_shard_results(as_loaded(shards))

    def test_no_shards_at_all_is_refused(self):
        with pytest.raises(ShardCoverageError, match=r"No shard results"):
            merge_shard_results([])

    def test_results_without_shard_provenance_are_refused(self):
        # An unstamped file is equally consistent with a whole unsharded scan and
        # with one shard of many, so guessing would let a single scan pass as a
        # complete merge of a five-way split.
        shards = build_shards(3)
        shards[1] = build_shard(1, 3, partition_scanners(SCANNERS, 1, 3), stamp=False)

        with pytest.raises(ShardCoverageError, match=r"No shard provenance found"):
            merge_shard_results(as_loaded(shards))

    def test_malformed_shard_provenance_is_refused(self):
        shards = build_shards(3)
        setattr(shards[0].metadata, SHARD_PROVENANCE_KEY, {"shard_index": "not-an-int"})

        with pytest.raises(ShardCoverageError, match=r"No shard provenance found"):
            merge_shard_results(as_loaded(shards))

    def test_two_shards_claiming_one_scanner_are_refused(self):
        # Merging does not deduplicate, so an overlap counts that scanner's
        # findings once per shard.
        shards = build_shards(3)
        assignment = read_shard_assignment(shards[1])
        assignment.assigned_scanners = assignment.assigned_scanners + ["bandit"]
        stamp_shard_assignment(shards[1], assignment)

        with pytest.raises(ShardCoverageError, match=r"more than one shard"):
            merge_shard_results(as_loaded(shards))

    def _orphan_grype(self, shards, keep_candidates: bool):
        """Drop grype from every shard's assignment, leaving its SKIPPED markers.

        The residual risk the sharding module names: two executors resolving
        different scanner sets, so both partitions are internally valid and the
        union has a hole.
        """
        for model in shards:
            assignment = read_shard_assignment(model)
            assignment.assigned_scanners = [
                name for name in assignment.assigned_scanners if name != "grype"
            ]
            if not keep_candidates:
                assignment.candidate_scanners = None
            stamp_shard_assignment(model, assignment)
        return shards

    def test_scanner_claimed_by_no_shard_is_refused_by_the_candidate_check(self):
        # With candidate_scanners recorded -- what every current scan writes --
        # verify_shard_coverage catches this from the provenance alone, before any
        # results are read.
        shards = self._orphan_grype(build_shards(3), keep_candidates=True)

        with pytest.raises(ShardCoverageError, match=r"assigned to none"):
            merge_shard_results(as_loaded(shards))

    def test_scanner_claimed_by_no_shard_is_refused_from_the_results_alone(self):
        # The same hole on results written before candidate_scanners existed, where
        # verify_shard_coverage has nothing to compare a union against. Every shard
        # marks the orphan SKIPPED, and _verify_scanner_union catches it from those
        # markers -- a second line of defense that has to keep working, because it
        # is the only one for legacy artifacts.
        shards = self._orphan_grype(build_shards(3), keep_candidates=False)

        with pytest.raises(ShardCoverageError, match=r"no shard was assigned them"):
            merge_shard_results(as_loaded(shards))

    def _orphan_grype_with_status(self, shards, status: str, name: str = "grype"):
        """Drop grype from every assignment and record *name* under *status* instead.

        The shape a scanner takes when it failed to construct on every executor: the
        name is absent from ``assigned_scanners`` -- that list is built from
        ``scanner_instances``, and a class whose constructor raised never becomes an
        instance -- while a row for it exists in every shard's results. Passing *name*
        covers the other shape, a plugin module that failed to import, which ScanPhase
        records under its dotted module path.
        """
        for model in shards:
            assignment = read_shard_assignment(model)
            assignment.assigned_scanners = [
                scanner
                for scanner in assignment.assigned_scanners
                if scanner != "grype"
            ]
            assignment.candidate_scanners = None
            stamp_shard_assignment(model, assignment)
            model.scanner_results[name] = ScannerStatusInfo(
                status=status, excluded=False, dependencies_satisfied=True
            )
            model.additional_reports[name] = {
                "None": {"scanner_name": name, "status": status, "excluded": False}
            }
        return shards

    @pytest.mark.parametrize("status", ["ERROR", "MISSING"])
    def test_a_never_attempted_orphan_is_not_a_shard_coverage_failure(self, status):
        """The row already says never-attempted, so refusing the merge adds nothing.

        This is the case the scan phase records for a scanner that failed to construct.
        Before the narrowing it reached ``ShardCoverageError``, which no flag gates and
        which attributed the loss to a partitioning disagreement that had not happened.
        The scanner is still reported -- through ``incomplete_scanners`` and
        ``--fail-on-incomplete-scanners`` -- which is the channel that exists for it.
        """
        shards = self._orphan_grype_with_status(build_shards(3), status)

        merged = merge_shard_results(as_loaded(shards))

        assert merged.scanner_results["grype"].status == status, (
            "exempting the row from the coverage refusal must not drop it: the whole "
            "point is that it survives to be reported through the gated path"
        )

    @pytest.mark.parametrize("status", ["ERROR", "MISSING"])
    def test_an_exempted_orphan_is_named_at_warning(self, status, capture):
        """The exemption has to leave a trace that no flag can switch off.

        Before the narrowing, an unclaimed ERROR or MISSING row refused the merge
        whatever flags were passed, because ``_verify_scanner_union`` is called
        unconditionally. The exemption moves the signal onto
        ``--fail-on-incomplete-scanners`` -- and ``--no-fail-on-incomplete-scanners``
        turns that off, taking the refusal and the exit code with it. This line is
        then the only record that a scanner appeared in the results which no shard
        was ever assigned, so it is emitted from inside the check rather than left
        to the gate.

        Asserted on the scanner name and its status, not merely on some warning
        being present: a message that does not name which scanner it is about
        cannot be acted on.
        """
        shards = self._orphan_grype_with_status(build_shards(3), status)

        merge_shard_results(as_loaded(shards))

        notices = [
            record.getMessage()
            for record in capture.records
            if "no shard was assigned" in record.getMessage()
        ]
        assert notices, (
            f"a {status} scanner appeared in shard results that no shard was "
            f"assigned, and the merge continued without saying so"
        )
        assert any("grype" in message for message in notices), (
            f"no notice named the scanner: {notices}"
        )
        assert any(status in message for message in notices), (
            f"no notice named the status, so a reader cannot tell why the merge was "
            f"not refused: {notices}"
        )

    def test_a_clean_shard_set_is_not_warned_about(self, capture):
        """The disclosure is conditional. A merge with nothing unclaimed must be
        quiet, or the line becomes noise and stops being read."""
        merge_shard_results(as_loaded(build_shards(3)))

        assert [
            record.getMessage()
            for record in capture.records
            if "no shard was assigned" in record.getMessage()
        ] == []

    def test_a_failed_plugin_module_row_is_not_a_shard_coverage_failure(self):
        """The other row shape, keyed by a dotted module path.

        A module can never appear in ``assigned_scanners``, so before the narrowing
        this refused unconditionally rather than only when no shard owned the name. It
        is the common case of the two, because an import failure is a property of the
        image rather than of one host.

        Assignments are left INTACT here, unlike the sibling tests. Dropping grype as
        well made an earlier version of this test pass its module-path assertion and
        then fail on grype instead -- the refusal named ``grype (PASSED, SKIPPED)``,
        which is the other scenario entirely. The module path has to be the only
        unclaimed name for this to be measuring what it says.
        """
        module = "automated_security_helper.plugin_modules.ash_builtin.scanners"
        shards = build_shards(3)
        for model in shards:
            model.scanner_results[module] = ScannerStatusInfo(
                status=ScannerStatus.ERROR, excluded=False, dependencies_satisfied=True
            )
            model.additional_reports[module] = {
                "None": {"scanner_name": module, "status": "ERROR", "excluded": False}
            }

        merged = merge_shard_results(as_loaded(shards))

        assert merged.scanner_results[module].status == ScannerStatus.ERROR

    @pytest.mark.parametrize("status", ["PASSED", "FAILED", "SKIPPED"])
    def test_an_orphan_claiming_a_known_outcome_is_still_refused(self, status):
        """The signal the narrowing must not lose.

        A row asserting its scanner reached a verdict, with no shard owning it, is the
        original defect: merging adopts that claim and reports a scanner nobody ran as
        one that ran. SKIPPED is included and is the shape the sibling test above
        exercises through the legacy path -- it means "not selected here", which
        merging would read as "deliberately skipped" for a scanner no shard selected
        anywhere.
        """
        shards = self._orphan_grype_with_status(build_shards(3), status)

        with pytest.raises(ShardCoverageError, match=r"no shard was assigned them"):
            merge_shard_results(as_loaded(shards))

    def test_an_unrecognised_status_cannot_reach_the_union_check_at_all(self):
        """Why the unknown-status case is defensive rather than load-bearing.

        The exemption is spelled as a denylist of the two never-attempted statuses and
        not as ``not _completed(entry)``, because that helper returns False for a
        status it has never heard of -- fail-closed where it is used, fail-OPEN here,
        where False would mean "exempt". That polarity argument is correct, but it is
        not what keeps this safe, and the difference is worth recording rather than
        implying a guard is doing work it is not.

        ``ScannerStatusInfo.status`` is enum-typed, so an unrecognised status is
        refused at model-validation time -- both when constructing one and when
        loading a shard written by a newer ASH. It never reaches
        ``_verify_scanner_union``. The denylist costs nothing and is the right shape if
        that ever stops being true; today the enum is the guarantee.
        """
        with pytest.raises(ValidationError):
            ScannerStatusInfo(
                status="QUARANTINED", excluded=False, dependencies_satisfied=True
            )

    def test_one_shard_claiming_a_verdict_defeats_another_shards_error(self):
        """Every status a name carries has to qualify, not just one of them.

        A name recorded PASSED by one shard and ERROR by another is the original
        defect, and taking the ERROR as permission to exempt would hide it.
        """
        shards = self._orphan_grype_with_status(build_shards(3), "ERROR")
        shards[0].scanner_results["grype"] = ScannerStatusInfo(
            status=ScannerStatus.PASSED, excluded=False, dependencies_satisfied=True
        )

        with pytest.raises(ShardCoverageError, match=r"no shard was assigned them"):
            merge_shard_results(as_loaded(shards))

    def test_the_refusal_names_each_orphans_status(self):
        """The message must not assert a cause it cannot know.

        It read "Every shard excluded these scanners", which is false for a scanner
        that failed to construct on every executor -- nobody excluded it. Naming the
        status lets the reader tell the causes apart instead of being sent to look for
        an ``--exclude-scanners`` setting that does not exist.
        """
        shards = self._orphan_grype_with_status(build_shards(3), "SKIPPED")

        with pytest.raises(ShardCoverageError) as excinfo:
            merge_shard_results(as_loaded(shards))

        message = str(excinfo.value)
        assert "SKIPPED" in message
        assert "Every shard excluded these scanners" not in message

    def test_executors_resolving_different_scanner_sets_are_refused(self):
        # The disagreement itself, rather than its consequence: one executor was
        # missing a plugin module, so its candidate set is short. Neither shard's
        # own partition is wrong, which is why nothing but the candidate comparison
        # can see it.
        shards = build_shards(3)
        assignment = read_shard_assignment(shards[1])
        assignment.candidate_scanners = [
            name for name in assignment.candidate_scanners if name != "grype"
        ]
        stamp_shard_assignment(shards[1], assignment)

        with pytest.raises(ShardCoverageError, match=r"different scanner sets"):
            merge_shard_results(as_loaded(shards))

    def test_owning_shard_with_no_result_for_its_scanner_is_refused(self):
        # Another shard's skip marker is the only trace left; adopting it would
        # report a scanner that never ran as deliberately skipped.
        shards = build_shards(3)
        owner = next(
            model
            for model in shards
            if "bandit" in read_shard_assignment(model).assigned_scanners
        )
        del owner.scanner_results["bandit"]

        with pytest.raises(ShardCoverageError, match=r"recorded no result for them"):
            merge_shard_results(as_loaded(shards))

    def test_scanner_names_are_matched_case_insensitively(self):
        # One shard recording "Bandit" where another records "bandit" must not
        # read as two scanners, or the owning shard's real result lands next to
        # another shard's skip marker.
        shards = build_shards(3)
        owner = next(
            model
            for model in shards
            if "bandit" in read_shard_assignment(model).assigned_scanners
        )
        owner.scanner_results["Bandit"] = owner.scanner_results.pop("bandit")
        owner.additional_reports["Bandit"] = owner.additional_reports.pop("bandit")

        merged = merge_shard_results(as_loaded(shards))

        entries = {
            name.lower(): entry for name, entry in merged.scanner_results.items()
        }
        assert entries["bandit"].excluded is False
        assert entries["bandit"].status != ScannerStatus.SKIPPED


class TestReadShardAssignment:
    """The three shapes that can reach the reader in the wild.

    ``ReportMetadata.shard`` is a declared ``ShardAssignment | None`` field, so
    the scan side assigns an instance and a results file validates into one. A
    raw dict is still reachable two ways: from a results file written before the
    field was declared, when the key rode the model's ``extra="allow"``, and from
    any caller that assigns one directly, since ``ReportMetadata`` does not enable
    ``validate_assignment``. All three have to answer the same way, because
    getting any of them wrong turns into "no shard provenance found" on a set of
    shards that is perfectly good.
    """

    def _model(self):
        model = AshAggregatedResults()
        model.ash_config = _build_config()
        return model

    def test_a_shard_assignment_instance_is_returned_as_is(self):
        model = self._model()
        stamp_shard_assignment(
            model,
            ShardAssignment(shard_index=1, shard_count=4, assigned_scanners=["bandit"]),
        )

        got = read_shard_assignment(model)

        assert isinstance(got, ShardAssignment)
        assert (got.shard_index, got.shard_count, got.assigned_scanners) == (
            1,
            4,
            ["bandit"],
        )

    def test_a_raw_dict_is_validated_into_an_assignment(self):
        model = self._model()
        setattr(
            model.metadata,
            SHARD_PROVENANCE_KEY,
            {"shard_index": 2, "shard_count": 5, "assigned_scanners": ["checkov"]},
        )

        got = read_shard_assignment(model)

        assert isinstance(got, ShardAssignment)
        assert (got.shard_index, got.shard_count, got.assigned_scanners) == (
            2,
            5,
            ["checkov"],
        )

    def test_none_means_this_was_not_a_sharded_scan(self):
        # Both an unset field and an explicitly cleared one. The merged report
        # carries the cleared form, so the two must agree or a second merge would
        # read a merged report as shard 0 of n.
        model = self._model()
        assert read_shard_assignment(model) is None

        setattr(model.metadata, SHARD_PROVENANCE_KEY, None)
        assert read_shard_assignment(model) is None

    def test_a_dict_shaped_assignment_merges_the_same_as_an_instance(self):
        # End to end rather than just at the reader, because the assignment is
        # also what ownership is decided from: a dict that read back correctly but
        # lost assigned_scanners would put every scanner's skip marker in the
        # merged report.
        instances = build_shards(3)
        dicts = build_shards(3)
        for model in dicts:
            assignment = read_shard_assignment(model)
            setattr(
                model.metadata, SHARD_PROVENANCE_KEY, assignment.model_dump(mode="json")
            )

        from_instances = merge_shard_results(as_loaded(instances))
        from_dicts = merge_shard_results(as_loaded(dicts))

        assert finding_keys(from_dicts) == finding_keys(from_instances)
        assert sorted(from_dicts.scanner_results) == sorted(
            from_instances.scanner_results
        )
        assert [
            entry.excluded for _, entry in sorted(from_dicts.scanner_results.items())
        ] == [
            entry.excluded
            for _, entry in sorted(from_instances.scanner_results.items())
        ]


class TestMergedProvenance:
    def test_merged_report_carries_no_shard_key(self):
        # Leaving it would let a second merge accept the merged report as shard 0
        # of n and report a whole scan as a fraction of itself.
        merged = merge_shard_results(as_loaded(build_shards(3)))

        assert read_shard_assignment(merged) is None
        round_tripped = json.loads(merged.model_dump_json())
        # Absent or null, not "absent" specifically. Today the key rides
        # ReportMetadata's extra="allow" and can be deleted outright; if it
        # becomes a declared field it can only be cleared, and the serialized
        # report then carries "shard": null. Both mean the same thing to
        # read_shard_assignment, so pinning absence would turn a harmless schema
        # change into a failing test.
        assert round_tripped["metadata"].get(SHARD_PROVENANCE_KEY) is None

    def test_merged_report_records_what_was_merged(self):
        merged = merge_shard_results(as_loaded(build_shards(3)))

        assert getattr(merged.metadata, MERGED_SHARD_COUNT_KEY) == 3
        assert getattr(merged.metadata, MERGED_SHARD_INDICES_KEY) == [0, 1, 2]

    def test_provenance_survives_a_json_round_trip(self):
        # metadata is extra="allow", which is the whole reason this carrier works.
        # If that ever changed, provenance would vanish on write and every merge
        # would fail with "no shard provenance".
        shard = build_shard(1, 4, ["bandit"])
        reloaded = AshAggregatedResults.model_validate_json(shard.model_dump_json())

        assignment = read_shard_assignment(reloaded)
        assert assignment is not None
        assert (assignment.shard_index, assignment.shard_count) == (1, 4)
        assert assignment.assigned_scanners == ["bandit"]

    def test_timing_spans_every_shard(self):
        merged = merge_shard_results(as_loaded(build_shards(3)))

        stats = merged.metadata.summary_stats
        assert stats.start == "2026-08-28T10:00:00"
        assert stats.end == "2026-08-28T10:22:00"
        # The longest shard, not the sum: shards run concurrently, so 183.0 would
        # claim the run took three times as long as it did.
        assert stats.duration == 62.0


#: A marker a shard does not record at all, as results from an older ASH lack it.
_ABSENT = object()


class TestScanMarkersAcrossShards:
    """scan_source and changed_files_only describe the whole merged scan.

    The merged report is a deep copy of shard 0, so every other shard's values
    were dropped unread. aws-security-hub archives a stored finding only under
    the recorded scan_source and only when changed_files_only is an explicit
    False, so a shard that scanned another directory, or was filtered to changed
    files, had the findings it left out read as fixed by a collector with
    archiving on.
    """

    @staticmethod
    def _merged(sources, markers):
        shards = build_shards(len(sources))
        for shard, source, marker in zip(shards, sources, markers):
            if source is not _ABSENT:
                shard.metadata.scan_source = source
            if marker is not _ABSENT:
                shard.metadata.changed_files_only = marker
        return merge_shard_results(as_loaded(shards))

    def test_agreeing_shards_keep_both_through_a_json_round_trip(self):
        merged = self._merged([".", ".", "."], [False, False, False])

        reloaded = AshAggregatedResults.model_validate_json(merged.model_dump_json())

        assert reloaded.metadata.scan_source == "."
        assert reloaded.metadata.changed_files_only is False

    def test_disagreeing_scan_sources_merge_to_none_with_a_warning(self, capture):
        merged = self._merged(["services/api", ".", "."], [False, False, False])

        assert getattr(merged.metadata, "scan_source", None) is None
        warnings = [
            record.getMessage()
            for record in capture.records
            if record.levelname == "WARNING" and "scan_source" in record.getMessage()
        ]
        assert len(warnings) == 1
        assert "'services/api'" in warnings[0] and "'.'" in warnings[0]

    def test_a_shard_that_records_no_scan_source_counts_as_disagreeing(self):
        merged = self._merged([".", ".", _ABSENT], [False, False, False])

        assert getattr(merged.metadata, "scan_source", None) is None

    @pytest.mark.parametrize("odd", [["services/api"], {"source": "."}, 7])
    def test_a_scan_source_that_is_not_a_string_counts_as_none(self, odd):
        """metadata keeps unknown keys as given (extra="allow"), so a results file
        can carry a list or a mapping there. Unhashable, it made the comparison
        raise TypeError, which ash merge did not catch: exit 1, with a traceback."""
        merged = self._merged([".", odd, "."], [False, False, False])

        assert getattr(merged.metadata, "scan_source", None) is None

    def test_one_non_string_scan_source_alone_is_not_kept_either(self):
        merged = self._merged([["."], ["."], ["."]], [False, False, False])

        assert getattr(merged.metadata, "scan_source", None) is None

    @pytest.mark.parametrize(
        "sources",
        [[["."], ["."], ["."]], [7, 7, 7], [["."], 7, None], [None, ["x"], None]],
        ids=["all-lists", "all-ints", "mixed", "one-list-among-none"],
    )
    def test_a_scan_source_dropped_for_not_being_a_string_is_warned_about(
        self, sources, capture
    ):
        merged = self._merged(sources, [False, False, False])

        assert getattr(merged.metadata, "scan_source", None) is None
        assert any(
            record.levelname == "WARNING" and "scan_source" in record.getMessage()
            for record in capture.records
        )

    def test_no_warning_when_no_shard_records_a_scan_source(self, capture):
        self._merged([_ABSENT, _ABSENT, _ABSENT], [False, False, False])

        assert not any("scan_source" in r.getMessage() for r in capture.records)

    def test_the_warning_stays_short_for_a_huge_value(self, capture):
        """The values are named in the WARNING, and a results file can carry
        anything there: a 100,000-element list made a 500,151-character line."""
        merged = self._merged(
            [list(range(100_000)), ".", "x" * 100_000], [False, False, False]
        )

        assert getattr(merged.metadata, "scan_source", None) is None
        [warning] = [
            r.getMessage() for r in capture.records if "scan_source" in r.getMessage()
        ]
        assert len(warning) < 2_000

    def test_the_warning_names_five_values_and_counts_the_rest(self, capture):
        """Seven shards, seven directories: the first five in sorted order are
        named, and the other two are counted."""
        sources = [f"services/s{index}" for index in range(7)]
        merged = self._merged(sources, [False] * 7)

        assert getattr(merged.metadata, "scan_source", None) is None
        [warning] = [
            r.getMessage() for r in capture.records if "scan_source" in r.getMessage()
        ]
        for named in sources[:5]:
            assert repr(named) in warning
        for unnamed in sources[5:]:
            assert repr(unnamed) not in warning
        assert "and 2 more" in warning

    def test_the_warning_shows_each_recorded_value_once(self, capture):
        """The values were named by their repr, which writes ESC as the text \\x1b,
        and the log sinks then showed that text again: "sx\\\\x1b[31my" reached the
        console and ash.log, and "C:\\x64" four backslashes deep. Checked as both
        sinks write the record (console_text, and ash.log's TextFileFormatter)."""
        from automated_security_helper.utils.log import TextFileFormatter, console_text

        self._merged(["sx\x1b[31my", "other", "C:\\x64", "n\n::error::x"], [False] * 4)

        [record] = [r for r in capture.records if "scan_source" in r.getMessage()]
        for printed in (
            console_text(record, record.getMessage()),
            TextFileFormatter("%(message)s").format(record),
        ):
            # ESC as one escape; a backslash that reads as one doubled once; a
            # newline as an escape, so the warning stays one line.
            assert "'sx\\x1b[31my'" in printed, printed
            assert "'C:\\\\x64'" in printed, printed
            assert "'n\\x0a::error::x'" in printed, printed
            assert "\\\\\\\\" not in printed and "\\\\x1b" not in printed, printed
            assert "\x1b" not in printed and "\n" not in printed, repr(printed)
        assert getattr(record, "markup", True) is False

    def test_a_value_that_is_not_text_is_named_by_its_kind(self, capture):
        """A list's repr quoted the repr of each item, ESC included, so it was shown
        twice like any repr; it is no directory, so its kind and size say enough."""
        self._merged([["a\x1bb", "c"], {"k": "v"}, 7], [False, False, False])

        [warning] = [
            r.getMessage() for r in capture.records if "scan_source" in r.getMessage()
        ]
        assert "a list of 2 items" in warning, warning
        assert "a dict of 1 item" in warning, warning
        assert "7" in warning and "a\x1bb" not in warning, repr(warning)

    def test_one_shard_filtered_to_changed_files_makes_the_merge_filtered(self):
        merged = self._merged([".", ".", "."], [False, True, False])

        assert merged.metadata.changed_files_only is True

    def test_a_shard_without_the_marker_leaves_the_merge_without_one(self):
        """Not False: nothing says that shard's results were unfiltered."""
        merged = self._merged([".", ".", "."], [False, False, _ABSENT])

        assert getattr(merged.metadata, "changed_files_only", None) is None

    def test_a_collector_archives_nothing_from_disagreeing_shards(self, tmp_path):
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
            SecurityHubReporter,
            SecurityHubReporterConfig,
            SecurityHubReporterConfigOptions,
        )

        merged = self._merged(["services/api", ".", "."], [False, False, False])
        reporter = SecurityHubReporter(
            context=PluginContext(
                source_dir=tmp_path, output_dir=tmp_path / "out", config=AshConfig()
            ),
            config=SecurityHubReporterConfig(
                enabled=True,
                options=SecurityHubReporterConfigOptions(
                    aws_region="us-east-1",
                    findings_scope="merge-fixture",
                    archive_resolved_findings=True,
                ),
            ),
        )

        completed, skipped = reporter._archive_scope(merged)

        assert completed is None
        assert "scan_source" in skipped


class TestResolveResultsFile:
    def test_a_file_is_used_as_given(self, tmp_path):
        paths = write_shards(tmp_path, build_shards(1), as_dirs=False)

        assert resolve_results_file(paths[0]).name == RESULTS_FILE_NAME

    def test_a_directory_is_searched(self, tmp_path):
        paths = write_shards(tmp_path, build_shards(1), as_dirs=True)

        assert resolve_results_file(paths[0]).name == RESULTS_FILE_NAME

    @pytest.mark.parametrize("nested", ["ash_output", ".ash/ash_output"])
    def test_the_well_known_nested_locations_are_searched(self, tmp_path, nested):
        target = tmp_path / "artifact" / nested
        target.mkdir(parents=True)
        (target / RESULTS_FILE_NAME).write_text(
            build_shard(0, 1, SCANNERS).model_dump_json(), encoding="utf-8"
        )

        resolved = resolve_results_file(tmp_path / "artifact")
        assert resolved.name == RESULTS_FILE_NAME

    def test_a_missing_path_is_refused(self, tmp_path):
        with pytest.raises(ShardCoverageError, match=r"does not exist"):
            resolve_results_file(tmp_path / "nope")

    def test_a_directory_with_no_results_file_is_refused(self, tmp_path):
        (tmp_path / "empty").mkdir()

        with pytest.raises(
            ShardCoverageError, match=r"No ash_aggregated_results.json found"
        ):
            resolve_results_file(tmp_path / "empty")

    def test_a_directory_holding_several_shards_is_refused(self, tmp_path):
        # Picking one would silently drop the rest; merging all of them would make
        # the merged set depend on whatever else is in the tree.
        write_shards(tmp_path, build_shards(3))

        with pytest.raises(ShardCoverageError, match=r"contains 3 results files"):
            resolve_results_file(tmp_path)

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
    def test_a_named_pipe_found_beneath_a_directory_is_not_a_results_file(
        self, tmp_path
    ):
        """An artifact archive can carry a FIFO by that name; opening it would
        block: `ash merge --results <dir>` with only a FIFO at
        <dir>/sub/ash_aggregated_results.json would wait on it forever, so it is
        refused unopened.
        """
        (tmp_path / "artifact" / "sub").mkdir(parents=True)
        os.mkfifo(tmp_path / "artifact" / "sub" / RESULTS_FILE_NAME)

        with pytest.raises(
            ShardCoverageError, match=r"No ash_aggregated_results.json found"
        ):
            resolve_results_file(tmp_path / "artifact")

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
    def test_a_named_pipe_beside_the_results_file_is_not_counted(self, tmp_path):
        (tmp_path / "artifact" / "a").mkdir(parents=True)
        (tmp_path / "artifact" / "b").mkdir()
        (tmp_path / "artifact" / "a" / RESULTS_FILE_NAME).write_text(
            build_shard(0, 1, SCANNERS).model_dump_json(), encoding="utf-8"
        )
        os.mkfifo(tmp_path / "artifact" / "b" / RESULTS_FILE_NAME)

        resolved = resolve_results_file(tmp_path / "artifact")

        assert resolved == tmp_path / "artifact" / "a" / RESULTS_FILE_NAME

    def test_a_symlink_found_beneath_a_directory_is_not_followed(self, tmp_path):
        """A link to a file outside the tree was read; one to a procfs file could block.

        An --results path given directly is still followed: the operator named it.
        """
        outside = tmp_path / "outside.json"
        outside.write_text(
            build_shard(0, 1, SCANNERS).model_dump_json(), encoding="utf-8"
        )
        (tmp_path / "artifact" / "sub").mkdir(parents=True)
        (tmp_path / "artifact" / "sub" / RESULTS_FILE_NAME).symlink_to(outside)

        with pytest.raises(
            ShardCoverageError, match=r"No ash_aggregated_results.json found"
        ):
            resolve_results_file(tmp_path / "artifact")

        assert resolve_results_file(outside) == outside

    @pytest.mark.parametrize(
        "link, points_at",
        [
            pytest.param(RESULTS_FILE_NAME, "file", id="the-results-file"),
            pytest.param(
                f"ash_output/{RESULTS_FILE_NAME}", "file", id="ash_output-file"
            ),
            pytest.param(
                f".ash/ash_output/{RESULTS_FILE_NAME}", "file", id="dot-ash-file"
            ),
            pytest.param("ash_output", "directory", id="ash_output-directory"),
            pytest.param(".ash", "directory", id="dot-ash-directory"),
            pytest.param(".ash/ash_output", "directory", id="dot-ash-ash_output"),
        ],
    )
    def test_a_well_known_location_reached_through_a_link_is_not_taken(
        self, tmp_path, link, points_at
    ):
        """The well-known locations are checked first, and a link at any of them
        is not followed.

        A link at any of them, to a results file outside the tree or to
        /proc/self/environ, and a linked ash_output or .ash/ash_output directory,
        is refused, and nothing it points at is opened.
        """
        outside = tmp_path / "outside"
        (outside / "ash_output").mkdir(parents=True)
        results = build_shard(0, 1, SCANNERS).model_dump_json()
        (outside / RESULTS_FILE_NAME).write_text(results, encoding="utf-8")
        (outside / "ash_output" / RESULTS_FILE_NAME).write_text(
            results, encoding="utf-8"
        )
        artifact = tmp_path / "artifact"
        location = artifact / link
        location.parent.mkdir(parents=True, exist_ok=True)
        location.symlink_to(
            outside / RESULTS_FILE_NAME if points_at == "file" else outside
        )

        with pytest.raises(
            ShardCoverageError, match=r"No ash_aggregated_results.json found"
        ) as excinfo:
            resolve_results_file(artifact)
        # The file is there through the link, so the refusal says why it was passed.
        assert "symlinks beneath it are not followed" in str(excinfo.value)

    def test_a_results_directory_named_through_a_link_is_followed(self, tmp_path):
        """The control: the --results value itself is the operator's, link or not."""
        real = tmp_path / "real"
        real.mkdir()
        (real / RESULTS_FILE_NAME).write_text(
            build_shard(0, 1, SCANNERS).model_dump_json(), encoding="utf-8"
        )
        (tmp_path / "named").symlink_to(real)

        assert (
            resolve_results_file(tmp_path / "named")
            == tmp_path / "named" / RESULTS_FILE_NAME
        )

    def test_unreadable_results_are_refused(self, tmp_path):
        broken = tmp_path / RESULTS_FILE_NAME
        broken.write_text("{ not json", encoding="utf-8")

        with pytest.raises(ShardCoverageError, match=r"Could not read shard results"):
            load_shard_results([str(broken)])


class TestExitCode:
    def test_exit_code_is_two_when_only_one_shard_had_findings(self, tmp_path):
        # The failure this guards: every shard exits 0 on its own, because a shard
        # that owned no failing scanner has nothing to report. Only the merge sees
        # the union, so only the merge can produce the real verdict.
        shard_count = 3
        shards = build_shards(shard_count)
        owner_index = next(
            index
            for index, model in enumerate(shards)
            if "checkov" in read_shard_assignment(model).assigned_scanners
        )
        # Strip the findings of every other scanner so exactly one shard holds
        # anything actionable.
        for index, model in enumerate(shards):
            if index == owner_index:
                continue
            assignment = read_shard_assignment(model)
            model.sarif.runs[0].results = []
            for scanner in assignment.assigned_scanners:
                model.scanner_results[scanner] = ScannerTargetStatusInfo(
                    status=ScannerStatus.PASSED, excluded=False
                )

        merged = merge_shard_results(as_loaded(shards))
        exit_code = _merged_exit_code(merged, tmp_path, "low", None)

        assert merged.metadata.summary_stats.actionable == 1
        assert exit_code == 2

    def test_exit_code_is_zero_when_no_shard_had_findings(self, tmp_path):
        shards = build_shards(3)
        for model in shards:
            model.sarif.runs[0].results = []
            for scanner in read_shard_assignment(model).assigned_scanners:
                model.scanner_results[scanner] = ScannerTargetStatusInfo(
                    status=ScannerStatus.PASSED, excluded=False
                )

        merged = merge_shard_results(as_loaded(shards))

        assert _merged_exit_code(merged, tmp_path, "low", None) == 0

    def test_no_fail_on_findings_exits_zero_despite_findings(self, tmp_path):
        merged = merge_shard_results(as_loaded(build_shards(3)))

        assert merged.metadata.summary_stats.actionable > 0
        assert _merged_exit_code(merged, tmp_path, "low", False) == 0

    def test_the_scans_own_config_governs_the_verdict(self, tmp_path):
        # A scan configured with fail_on_findings: false exits 0, so a merge of
        # its shards must too. The config travels in the shard results, which is
        # the only copy available on a collector job that never checked the tree
        # out -- reading a config file found on this host instead could move the
        # verdict without moving a single finding.
        shards = build_shards(3)
        for model in shards:
            model.ash_config = _build_config(fail_on_findings=False)
        merged = merge_shard_results(as_loaded(shards))

        assert merged.metadata.summary_stats.actionable > 0
        # None means "no CLI override", so the config's value must decide.
        assert _merged_exit_code(merged, tmp_path, "low", None) == 0

    def test_a_cli_override_beats_the_scan_config(self, tmp_path):
        shards = build_shards(3)
        for model in shards:
            model.ash_config = _build_config(fail_on_findings=False)
        merged = merge_shard_results(as_loaded(shards))

        assert _merged_exit_code(merged, tmp_path, "low", True) == 2

    def test_min_severity_gates_the_verdict(self, tmp_path):
        # Parity with `ash scan --min-severity`. Downgrading every finding to
        # MEDIUM puts them all above the config's MEDIUM threshold and below a
        # critical floor. Without min_severity reaching _compute_exit_code both
        # floors would answer 2, and the second answer would be wrong.
        #
        # issue_severity is downgraded alongside the level, and the level alone is
        # not enough. This used to set only `result.level = "warning"` and lean on
        # _compute_exit_code's min_severity gate reading the level while ignoring
        # issue_severity -- which left the fixture's HIGH and CRITICAL severities in
        # place and made the assertion depend on the one severity resolver in ASH
        # that disagreed with the others. That resolver now reads issue_severity, so
        # a fixture that downgrades only the level is no longer downgrading anything.
        shards = build_shards(3)
        for model in shards:
            for result in model.sarif.runs[0].results:
                result.level = "warning"
                result.properties.issue_severity = "MEDIUM"
        merged = merge_shard_results(as_loaded(shards))

        assert merged.metadata.summary_stats.actionable > 0
        assert _merged_exit_code(merged, tmp_path, "low", None) == 2
        assert _merged_exit_code(merged, tmp_path, "critical", None) == 0

    def test_verdict_matches_an_unsharded_scan(self, tmp_path):
        merged = merge_shard_results(as_loaded(build_shards(3)))
        unsharded = build_unsharded()

        assert _merged_exit_code(merged, tmp_path, "low", None) == _merged_exit_code(
            unsharded, tmp_path, "low", None
        )


# Every finding the fixtures rate at or above the MEDIUM threshold. Suppressing
# exactly these makes the two paths' verdicts differ -- 0 against 2 -- rather than
# differ only in a count, which is the sharpest form the divergence takes and the
# one CI acts on. semgrep's LOW note is deliberately left unsuppressed so the
# tests can tell "suppressed the actionable findings" apart from "suppressed
# everything".
_ACTIONABLE_SUPPRESSIONS = [
    {"path": "src/bandit_*.py", "reason": "post-merge suppression, glob on path"},
    {"path": "src/checkov_0.py", "reason": "post-merge suppression, exact path"},
    {
        "path": "src/detect-secrets_0.py",
        "rule_id": "detect-secrets-RULE-0",
        "reason": "post-merge suppression, path and rule",
    },
]


def _suppressed_keys(model: AshAggregatedResults) -> List[Tuple]:
    """The findings carrying a suppression, by the same identity as finding_key."""
    return sorted(
        finding_key(result)
        for run in model.sarif.runs
        for result in (run.results or [])
        if result.suppressions
    )


def _scan_unsharded(tmp_path, suppressions, ignore_suppressions=False):
    """What ``ash scan`` produces: aggregate, then the aggregated suppression pass.

    The engine applies ``apply_suppressions_to_sarif`` to the aggregated SARIF just
    before the report phase and then repopulates metrics, which is what
    ``apply_aggregated_suppressions`` is. Modelling the scan side by calling the
    same helper is deliberate: the property under test is not "does the helper
    work" but "does the merge path invoke it at all", and the merge side below goes
    through the real ``merge_command``.
    """
    model = build_unsharded(suppressions=suppressions)
    context = PluginContext(
        source_dir=Path.cwd(),
        output_dir=tmp_path,
        config=model.ash_config,
        ignore_suppressions=ignore_suppressions,
    )
    return apply_aggregated_suppressions(model, context)


class TestSuppressionsAcrossShards:
    """A suppression that only matches after the collapse must apply either way.

    Why this class exists
    ---------------------
    ``AshExecutionEngine`` applies the aggregated suppression pass to the merged
    SARIF before the report phase, because per-scanner passes miss findings whose
    paths only become matchable after merge and normalization. ``ash merge`` did
    not, so a suppression of this kind applied in an unsharded scan and not in a
    sharded one: identical inputs, ``ash scan`` exit 0, ``ash merge`` exit 2.

    Why ``TestShardedEqualsUnsharded`` could not catch it
    -----------------------------------------------------
    Its fixtures carry no suppressions. With none configured, a path that skips
    the suppression pass and a path that runs it produce byte-identical reports,
    so the equivalence assertions hold no matter which one is broken. The property
    was reported as verified end to end and the verification could not have
    failed. A parity test has to run on input where the two sides are capable of
    disagreeing.
    """

    @pytest.fixture(autouse=True)
    def _cwd_named_unlike_the_fixture_paths(self, tmp_path_factory, monkeypatch):
        """Pin the cwd both sides read as ``source_dir`` to a pytest-made directory.

        ``_scan_unsharded`` passes ``Path.cwd()`` and ``merge_command`` hardcodes it.
        ``_OutputDirExclusion`` strips the source directory's basename from a
        finding URI that starts with it (offline opengrep writes paths that way),
        so a suite run from a directory named ``src`` reads every ``src/...``
        fixture URI as its tail and no ``src/...`` suppression matches. A sibling
        of ``tmp_path``, so the cwd is never the output directory a test passes.
        """
        monkeypatch.chdir(tmp_path_factory.mktemp("cwd"))

    def _merge_via_cli(self, tmp_path, suppressions, extra_args=()):
        """Run the real ``ash merge`` and return (exit code, reloaded results)."""
        shard_paths = write_shards(
            tmp_path / "artifacts", build_shards(3, suppressions=suppressions)
        )
        output_dir = tmp_path / "merged"
        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += ["--output-dir", str(output_dir), "--output-formats", "sarif"]
        args += list(extra_args)

        result = TestMergeCli()._invoke(args)
        merged_file = output_dir / RESULTS_FILE_NAME
        reloaded = (
            AshAggregatedResults.model_validate_json(
                merged_file.read_text(encoding="utf-8")
            )
            if merged_file.is_file()
            else None
        )
        return result, reloaded

    def test_the_fixture_actually_diverges_without_the_merge_side_pass(self, tmp_path):
        """Guards the guard: the suppressions must move the unsharded verdict.

        If they did not, every assertion below would compare 2 against 2 and pass
        whether or not ``ash merge`` applies suppressions -- the same way the
        no-suppression fixtures did.
        """
        unsuppressed = build_unsharded()
        suppressed = _scan_unsharded(tmp_path, _ACTIONABLE_SUPPRESSIONS)

        assert _merged_exit_code(unsuppressed, tmp_path, "low", None) == 2
        assert _merged_exit_code(suppressed, tmp_path, "low", None) == 0

    def test_verdict_matches_an_unsharded_scan(self, tmp_path):
        """The divergence itself. Exit 2 against exit 0 before the fix."""
        result, _ = self._merge_via_cli(tmp_path / "sharded", _ACTIONABLE_SUPPRESSIONS)
        unsharded = _scan_unsharded(tmp_path / "unsharded", _ACTIONABLE_SUPPRESSIONS)

        expected = _merged_exit_code(unsharded, tmp_path / "unsharded", "low", None)
        assert expected == 0, "fixture no longer suppresses every actionable finding"
        assert result.exit_code == expected, result.output

    def test_suppressed_finding_set_matches_an_unsharded_scan(self, tmp_path):
        result, merged = self._merge_via_cli(
            tmp_path / "sharded", _ACTIONABLE_SUPPRESSIONS
        )
        assert merged is not None, result.output
        unsharded = _scan_unsharded(tmp_path / "unsharded", _ACTIONABLE_SUPPRESSIONS)

        assert _suppressed_keys(merged) == _suppressed_keys(unsharded)
        # Non-empty, or the equality above would hold for two paths that both
        # suppressed nothing.
        assert _suppressed_keys(merged)

    def test_findings_are_marked_not_dropped(self, tmp_path):
        """Suppression annotates a finding; it must not remove it.

        Comparing only the suppressed set would pass for a merge that deleted the
        suppressed findings outright, which would lose them from every report.
        """
        result, merged = self._merge_via_cli(tmp_path, _ACTIONABLE_SUPPRESSIONS)
        assert merged is not None, result.output
        assert finding_keys(merged) == finding_keys(build_unsharded())

    def test_the_written_results_file_reflects_the_suppressions(self, tmp_path):
        """The on-disk merged results must not predate the suppression pass.

        ``merge_command`` used to write the file before building its plugin
        context. Applying suppressions after that write would leave
        ash_aggregated_results.json describing a pre-suppression state while the
        reports and the exit code described the post-suppression one -- two
        artifacts of one run disagreeing about what is actionable.
        """
        result, merged = self._merge_via_cli(tmp_path, _ACTIONABLE_SUPPRESSIONS)
        assert merged is not None, result.output
        assert merged.metadata.summary_stats.actionable == 0
        assert merged.metadata.summary_stats.suppressed > 0

    def test_ignore_suppressions_restores_the_failing_verdict(self, tmp_path):
        """The other half of the contract has to be expressible.

        Without ``--ignore-suppressions`` on merge there is no way to ask a sharded
        run the question ``ash scan --ignore-suppressions`` answers, so an operator
        auditing what their suppressions hide could not do it on a sharded scan.
        """
        result, merged = self._merge_via_cli(
            tmp_path / "sharded",
            _ACTIONABLE_SUPPRESSIONS,
            extra_args=["--ignore-suppressions"],
        )
        assert merged is not None, result.output
        assert result.exit_code == 2, result.output
        assert _suppressed_keys(merged) == []

        unsharded = _scan_unsharded(
            tmp_path / "unsharded",
            _ACTIONABLE_SUPPRESSIONS,
            ignore_suppressions=True,
        )
        assert result.exit_code == _merged_exit_code(
            unsharded, tmp_path / "unsharded", "low", None
        )

    def test_a_tree_with_no_suppressions_is_unaffected(self, tmp_path):
        """The pass must be a no-op when there is nothing to suppress.

        This is the case the original equivalence tests covered, kept here so the
        added pass cannot change it.
        """
        result, merged = self._merge_via_cli(tmp_path, suppressions=None)
        assert merged is not None, result.output
        assert result.exit_code == 2, result.output
        assert _suppressed_keys(merged) == []
        assert finding_keys(merged) == finding_keys(build_unsharded())


class TestMergedReportId:
    """A merged sharded scan has one ``report_id``, of its own, for the union.

    Each shard is its own ``ash scan`` process and mints its own id. The merged
    report derives its own from all the shard ids, so it shares no id with a
    document that holds a fraction of its findings. The id is the same for the
    same shards in any order, so a re-run merge
    is byte-identical, and different from every shard's.
    """

    REPORT_ID = re.compile(r"^ASH-\d{14}-[0-9a-f]{12}$")

    def test_the_merged_id_is_none_of_the_shard_ids(self):
        shards = build_shards(3)

        merged = merge_shard_results(as_loaded(shards))

        assert self.REPORT_ID.match(merged.metadata.report_id)
        assert merged.metadata.report_id not in {
            shard.metadata.report_id for shard in shards
        }

    def test_shard_order_does_not_change_the_id(self):
        shards = build_shards(3)

        forward = merge_shard_results(as_loaded(shards))
        backward = merge_shard_results(as_loaded(list(reversed(shards))))

        assert forward.metadata.report_id == backward.metadata.report_id

    def test_merging_the_same_shards_again_gives_the_same_id(self):
        shards = build_shards(3)

        first = merge_shard_results(as_loaded(shards))
        second = merge_shard_results(as_loaded(shards))

        assert first.metadata.report_id == second.metadata.report_id

    def test_another_sharded_scan_gets_another_id(self):
        one = merge_shard_results(as_loaded(build_shards(3)))
        other = merge_shard_results(as_loaded(build_shards(3)))

        assert one.metadata.report_id != other.metadata.report_id

    def test_the_shards_are_not_modified(self):
        shards = build_shards(2)
        before = [shard.metadata.report_id for shard in shards]

        merge_shard_results(as_loaded(shards))

        assert [shard.metadata.report_id for shard in shards] == before


class TestMergeCli:
    """End-to-end, through the registered command and the real ReportPhase.

    The reporter set is narrowed to two built-in local reporters rather than
    letting ``load_plugins`` discover all of them. ``filter_enabled_plugins``
    calls ``validate_plugin_dependencies()`` on every enabled reporter *before*
    the format filter runs, and the AWS reporters implement that by calling
    ``DescribeHub`` and a Bedrock access check for real, with no offline guard. A
    unit test that discovered them would reach the network, read whatever is in
    the developer's ~/.aws/credentials, and behave differently on a machine with
    no credentials -- and the AWS SDK's failure path closes the stdout buffer
    ``typer.testing`` reads back, so the test dies after the command has already
    succeeded.

    Narrowing keeps the real ReportPhase, the real reporters and the real
    file-writing path, and drops only the plugins whose dependency check is a
    cloud call. What is lost is coverage of "every reporter tolerates a merged
    model", which is not something merging controls anyway.
    """

    def _invoke(self, args):
        from unittest.mock import MagicMock, patch

        from automated_security_helper.cli.main import app
        from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
            CsvReporter,
        )
        from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
            SarifReporter,
        )

        manager = MagicMock()
        manager.plugin_modules.return_value = [SarifReporter, CsvReporter]

        with (
            patch("automated_security_helper.cli.merge.ash_plugin_manager", manager),
            patch("automated_security_helper.cli.merge.load_plugins"),
        ):
            return CliRunner().invoke(app, ["merge"] + args)

    def test_merge_writes_results_and_reports_and_exits_two(self, tmp_path):
        shard_paths = write_shards(tmp_path / "artifacts", build_shards(3))
        output_dir = tmp_path / "merged"

        args = []
        for path in shard_paths:
            args += ["--results", path]
        # Formats whose ExportFormat value equals the reporter's declared
        # extension. ReportPhase filters on config.extension, so a name that
        # differs from its extension -- "markdown" against "summary.md" -- selects
        # nothing. That mismatch is ReportPhase's, shared with `ash scan`, and is
        # not something merging can or should paper over; asserting on it here
        # would pin another command's quirk into this file's tests.
        args += ["--output-dir", str(output_dir), "--output-formats", "sarif,csv"]

        result = self._invoke(args)

        assert result.exit_code == 2, result.output
        merged_file = output_dir / RESULTS_FILE_NAME
        assert merged_file.is_file()
        # The reporter chain must work unchanged on a merged model, and ash.sarif
        # in particular is what _compute_exit_code reads back for the threshold.
        assert (output_dir / "reports" / "ash.sarif").is_file()
        assert (output_dir / "reports" / "ash.csv").is_file()

        written = json.loads(merged_file.read_text(encoding="utf-8"))
        assert written["metadata"][MERGED_SHARD_COUNT_KEY] == 3
        # Absent or null; see test_merged_report_carries_no_shard_key for why both
        # are acceptable.
        assert written["metadata"].get(SHARD_PROVENANCE_KEY) is None

        reloaded = AshAggregatedResults.model_validate_json(
            merged_file.read_text(encoding="utf-8")
        )
        assert finding_keys(reloaded) == finding_keys(build_unsharded())

    def test_a_stale_ash_sarif_in_a_reused_output_dir_does_not_decide(self, tmp_path):
        """The verdict is the union's, not an earlier run's leftover ash.sarif.

        The merged shards hold only LOW findings, below the MEDIUM threshold. The
        reused output directory holds an ash.sarif from an earlier run with the
        fixture's full set of findings, and this merge writes only csv, so it
        does not replace that file. The exit-code gate read it anyway and failed
        the merge with exit 2.
        """
        shards = build_shards(3)
        for model in shards:
            for result in model.sarif.runs[0].results:
                result.level = "note"
                result.properties.issue_severity = "LOW"
            populate_metrics_from_unified_source(aggregated_results=model)
        shard_paths = write_shards(tmp_path / "artifacts", shards)
        output_dir = tmp_path / "merged"
        (output_dir / "reports").mkdir(parents=True)
        stale = _sarif_for(SCANNERS)
        (output_dir / "reports" / "ash.sarif").write_text(
            stale.model_dump_json(by_alias=True, exclude_none=True), encoding="utf-8"
        )
        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += ["--output-dir", str(output_dir), "--output-formats", "csv"]

        result = self._invoke(args)

        assert result.exit_code == 0, result.output
        # The earlier file is still there, unread.
        assert (output_dir / "reports" / "ash.sarif").read_text(
            encoding="utf-8"
        ) == stale.model_dump_json(by_alias=True, exclude_none=True)

    def test_the_shards_recorded_security_hub_scope_and_archiving_are_dropped(
        self, tmp_path, monkeypatch
    ):
        """A shard records the config its scan resolved, which a file in that
        shard's scanned repository could have set, so ash merge holds it to the
        rules for a repository's config (confine_recorded_config, SHARD_RECORDED):
        the Security Hub section's destination options, aws_region among them
        (REPORTER_DESTINATION_OPTIONS), and its enabled come from the operator's
        trusted base, here the defaults, which set none. The reporters are built
        from the confined section, and the merged results file records it as
        confined, since the confinement runs before the file is written."""
        from automated_security_helper.cli import merge as merge_module
        from automated_security_helper.config.ash_config import AshConfig

        recorded = AshConfig.model_validate(
            {
                "reporters": {
                    "aws-security-hub": {
                        "enabled": True,
                        "options": {
                            "aws_region": "us-east-1",
                            "findings_scope": "shard-scope",
                            "archive_resolved_findings": True,
                        },
                    }
                }
            }
        )
        shards = build_shards(3)
        for shard in shards:
            shard.ash_config = recorded
        shard_paths = write_shards(tmp_path / "artifacts", shards)
        output_dir = tmp_path / "merged"

        seen = []
        real = merge_module.ReportPhase

        class Recording(real):
            def __init__(self, *args, plugin_context, **kwargs):
                seen.append(
                    plugin_context.config.get_plugin_config(
                        plugin_type="reporter", plugin_name="aws-security-hub"
                    )
                )
                super().__init__(*args, plugin_context=plugin_context, **kwargs)

        monkeypatch.setattr(merge_module, "ReportPhase", Recording)
        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += ["--output-dir", str(output_dir), "--output-formats", "csv"]

        result = self._invoke(args)

        assert result.exit_code in (0, 2), result.output
        [section] = seen
        assert section["options"] == {}
        assert section["enabled"] is False
        written = json.loads((output_dir / RESULTS_FILE_NAME).read_text("utf-8"))
        recorded_section = written["ash_config"]["reporters"]["aws-security-hub"]
        assert recorded_section["options"] == {}
        assert recorded_section["enabled"] is False

    def test_the_operators_config_sends_the_merged_findings_with_its_scope(
        self, tmp_path
    ):
        """The positive half of the test above: with the operator's
        --config-overrides turning Security Hub on and aiming it, ash merge
        imports the merged findings under the operator's findings_scope, and the
        shards' recorded scope and archiving are unused. The --config file sets
        the same values, and decides nothing for an off-host reporter on its own
        (MERGE_CONFIG_FILE). Security Hub and STS are stubbed, and GetFindings is
        never answered, so archiving from the shards fails the stubber."""
        import json as json_module
        from unittest.mock import MagicMock, patch

        import botocore.session
        from botocore.stub import Stubber

        from automated_security_helper.cli.main import app
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.plugin_modules.ash_aws_plugins import (
            security_hub_reporter as securityhub_module,
        )

        recorded = AshConfig.model_validate(
            {
                "reporters": {
                    "aws-security-hub": {
                        "enabled": True,
                        "options": {
                            "aws_region": "us-east-1",
                            "findings_scope": "shard-scope",
                            "archive_resolved_findings": True,
                        },
                    }
                }
            }
        )
        shards = build_shards(3)
        for shard in shards:
            shard.ash_config = recorded
        shard_paths = write_shards(tmp_path / "artifacts", shards)
        operator = tmp_path / "operator" / "ash.yaml"
        operator.parent.mkdir()
        operator.write_text(
            "reporters:\n"
            "  aws-security-hub:\n"
            "    enabled: true\n"
            "    options:\n"
            "      aws_region: us-east-1\n"
            "      findings_scope: operator-scope\n",
            encoding="utf-8",
        )
        session = botocore.session.get_session()
        securityhub = session.create_client(
            "securityhub",
            region_name="us-east-1",
            aws_access_key_id="x",
            aws_secret_access_key="x",
        )
        sts = session.create_client(
            "sts",
            region_name="us-east-1",
            aws_access_key_id="x",
            aws_secret_access_key="x",
        )
        sent: List[dict] = []
        securityhub.meta.events.register(
            "provide-client-params.securityhub.BatchImportFindings",
            lambda params, **_: sent.extend(
                json_module.loads(json_module.dumps(params))["Findings"]
            ),
        )
        # The dependency check calls DescribeHub, and GetCallerIdentity with no
        # account_id set; the import asks STS again before it sends.
        securityhub_stub = Stubber(securityhub)
        securityhub_stub.add_response(
            "describe_hub",
            {"HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default"},
        )
        for _ in range(10):
            securityhub_stub.add_response(
                "batch_import_findings",
                {"FailedCount": 0, "SuccessCount": 1, "FailedFindings": []},
            )
        sts_stub = Stubber(sts)
        for _ in range(2):
            sts_stub.add_response(
                "get_caller_identity",
                {
                    "Account": "123456789012",
                    "Arn": "arn:aws:iam::123456789012:user/ci",
                    "UserId": "AIDAEXAMPLE",
                },
            )
        clients = {"securityhub": securityhub, "sts": sts}

        class Session:
            def __init__(self, **_):
                pass

            def client(self, service_name, **_):
                return clients[service_name]

        manager = MagicMock()
        manager.plugin_modules.return_value = [securityhub_module.SecurityHubReporter]
        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += ["--output-dir", str(tmp_path / "merged"), "--config", str(operator)]
        # ash merge cannot tell the --config file from the scanned repository's
        # own, so an off-host reporter's enabled and destination options come
        # from the defaults and --config-overrides alone; the file's are replaced
        # (confine_off_host_reporters_to_overrides, MERGE_CONFIG_FILE).
        for override in (
            "reporters.aws-security-hub.enabled=true",
            "reporters.aws-security-hub.options.aws_region=us-east-1",
            "reporters.aws-security-hub.options.findings_scope=operator-scope",
        ):
            args += ["--config-overrides", override]

        with (
            securityhub_stub,
            sts_stub,
            patch("automated_security_helper.cli.merge.ash_plugin_manager", manager),
            patch("automated_security_helper.cli.merge.load_plugins"),
            patch.object(securityhub_module.boto3, "Session", Session),
        ):
            result = CliRunner().invoke(app, ["merge", *args])

        assert result.exit_code in (0, 2), result.output
        assert sent, result.output
        assert {f["ProductFields"]["ash/target"] for f in sent} == {"operator-scope"}

    def test_dropping_the_recorded_options_says_so_once(self, capture):
        """The warning, from the helper itself: merge_command reconfigures the
        logger, so capture does not see what it logs."""
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.operator_only_options import (
            drop_recorded_operator_only_options,
        )

        recorded = AshConfig.model_validate(
            {
                "reporters": {
                    "aws-security-hub": {
                        "options": {
                            "findings_scope": "shard-scope",
                            "archive_resolved_findings": True,
                        }
                    }
                }
            }
        )

        confined = drop_recorded_operator_only_options(recorded)

        assert confined.get_plugin_config("reporter", "aws-security-hub") == {
            "options": {}
        }
        assert recorded.get_plugin_config("reporter", "aws-security-hub")[
            "options"
        ] == {"findings_scope": "shard-scope", "archive_resolved_findings": True}
        [warning] = [
            record.getMessage()
            for record in capture.records
            if ".options.findings_scope" in record.getMessage()
        ]
        assert "reporters.aws-security-hub.options.archive_resolved_findings" in (
            warning
        )
        # The remedy on this branch, where ash merge takes the operator's --config.
        assert "operator's own --config" in warning

    def test_a_recorded_section_key_is_logged_as_text_not_markup(self, capture):
        """A shard records whatever key its scan read. "aws-security-hub[/]"
        is a closing Rich tag, which ended ash merge with a MarkupError."""
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.operator_only_options import (
            drop_recorded_operator_only_options,
        )

        recorded = AshConfig.model_validate(
            {
                "reporters": {
                    "aws-security-hub[/]": {
                        "options": {"archive_resolved_findings": True}
                    }
                }
            }
        )

        drop_recorded_operator_only_options(recorded)

        [record] = [
            r
            for r in capture.records
            if ".options.archive_resolved_findings" in r.getMessage()
        ]
        assert getattr(record, "markup", True) is False
        assert "reporters.aws-security-hub[/].options" in record.getMessage()

    def test_a_recorded_section_under_the_underscore_spelling_is_dropped_too(
        self, capture
    ):
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.operator_only_options import (
            drop_recorded_operator_only_options,
        )

        recorded = AshConfig.model_validate(
            {
                "reporters": {
                    "aws_security_hub": {
                        "options": {
                            "findings_scope": "shard-scope",
                            "archive_resolved_findings": True,
                        }
                    }
                }
            }
        )

        confined = drop_recorded_operator_only_options(recorded)

        assert confined.get_plugin_config("reporter", "aws-security-hub") == {
            "options": {}
        }

    def test_a_recorded_config_without_those_options_merges_quietly(self, capture):
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.operator_only_options import (
            drop_recorded_operator_only_options,
        )

        recorded = AshConfig.model_validate(
            {"reporters": {"aws-security-hub": {"options": {"max_retries": 5}}}}
        )

        confined = drop_recorded_operator_only_options(recorded)

        assert confined.get_plugin_config("reporter", "aws-security-hub") == {
            "options": {"max_retries": 5}
        }
        assert [r for r in capture.records if "Ignoring" in r.getMessage()] == []

    @pytest.mark.parametrize(
        "formats, written",
        [("csv", False), ("csv,sarif", True)],
        ids=["sarif-not-written", "sarif-written"],
    )
    def test_the_gate_is_told_whether_this_merge_wrote_ash_sarif(
        self, tmp_path, monkeypatch, formats, written
    ):
        """Over an earlier ash.sarif, the gate is told when the merge rewrote it.

        The exit code alone cannot show it here: the file this merge writes and
        the union agree. The spy sits on the gate itself, so the flag is checked
        where it is read, through _merged_exit_code's forwarding of it (which
        imports _compute_exit_code when it runs, so the patch reaches it).
        """
        from automated_security_helper.interactions import run_ash_scan

        told = []
        real = run_ash_scan._compute_exit_code

        def spy(*args, **kwargs):
            told.append(kwargs.get("report_sarif_written_this_run"))
            return real(*args, **kwargs)

        monkeypatch.setattr(run_ash_scan, "_compute_exit_code", spy)
        shards = build_shards(3)
        for model in shards:
            for result in model.sarif.runs[0].results:
                result.level = "note"
                result.properties.issue_severity = "LOW"
            populate_metrics_from_unified_source(aggregated_results=model)
        shard_paths = write_shards(tmp_path / "artifacts", shards)
        output_dir = tmp_path / "merged"
        (output_dir / "reports").mkdir(parents=True)
        (output_dir / "reports" / "ash.sarif").write_text(
            _sarif_for(SCANNERS).model_dump_json(by_alias=True, exclude_none=True),
            encoding="utf-8",
        )
        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += ["--output-dir", str(output_dir), "--output-formats", formats]

        result = self._invoke(args)

        assert result.exit_code == 0, result.output
        assert told == [written]

    def test_the_scans_output_formats_are_the_default(self, tmp_path):
        """With no --output-formats, the shards' own config chooses the reports.

        The option's help has always said so, but ``AshConfig`` dropped
        ``output_formats``, so the merge wrote every report regardless.
        """
        shards = build_shards(3)
        for shard in shards:
            shard.ash_config.output_formats = ["sarif"]
        shard_paths = write_shards(tmp_path / "artifacts", shards)
        output_dir = tmp_path / "merged"
        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += ["--output-dir", str(output_dir)]

        result = self._invoke(args)

        assert result.exit_code == 2, result.output
        assert sorted(p.name for p in (output_dir / "reports").iterdir()) == [
            "ash.sarif"
        ]

    def test_the_flag_replaces_the_scans_output_formats(self, tmp_path):
        shards = build_shards(3)
        for shard in shards:
            shard.ash_config.output_formats = ["sarif"]
        shard_paths = write_shards(tmp_path / "artifacts", shards)
        output_dir = tmp_path / "merged"
        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += ["--output-dir", str(output_dir), "--output-formats", "csv"]

        result = self._invoke(args)

        assert result.exit_code == 2, result.output
        assert sorted(p.name for p in (output_dir / "reports").iterdir()) == ["ash.csv"]

    def test_merge_refuses_a_partial_set_with_exit_one(self, tmp_path):
        shards = build_shards(5)
        del shards[3]
        shard_paths = write_shards(tmp_path / "artifacts", shards)
        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += ["--output-dir", str(tmp_path / "merged")]

        result = self._invoke(args)

        # Exit 1 (error), not 0 and not 2: the findings are unknown, which is not
        # the same as "no findings".
        assert result.exit_code == 1, result.output
        assert "Refusing to merge" in result.output
        assert not (tmp_path / "merged" / RESULTS_FILE_NAME).exists()

    def test_the_flag_refuses_a_shard_that_completed_nothing(self, tmp_path):
        """Through typer, so the option name itself is exercised.

        A unit call to ``merge_shard_results(require_scanner_completion=True)``
        cannot catch a misspelled option: the flag would simply never be parsed
        and every merge would run with the gate off, which looks exactly like a
        healthy default.
        """
        shards = build_shards(3)
        _make_shard_contribute_nothing(shards[1])
        shard_paths = write_shards(tmp_path / "artifacts", shards)
        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += [
            "--output-dir",
            str(tmp_path / "merged"),
            "--fail-on-incomplete-scanners",
        ]

        result = self._invoke(args)

        assert result.exit_code == 1, result.output
        assert "Refusing to merge" in result.output
        assert "completed none" in result.output
        # No artifact at all, so a downstream job cannot consume a report that
        # reads as a complete scan.
        assert not (tmp_path / "merged" / RESULTS_FILE_NAME).exists()

    def test_an_output_dir_equal_to_the_cwd_is_relocated(self, tmp_path, monkeypatch):
        """``ash merge --output-dir .`` must not write over the tree it reports on.

        ``ash scan`` has relocated a colliding ``--output-dir`` since before this
        command existed, and says so loudly (``cli/scan.py``). ``ash merge`` took the
        operator's value verbatim and built its ``PluginContext`` with
        ``source_dir=Path.cwd()``, so the two coincided and ASH wrote its reports
        into the directory it was treating as the source tree.

        Worse than untidy. ``apply_suppressions_to_sarif`` drops findings whose
        location resolves inside ``output_dir`` and outside its work directory; with
        ``output_dir`` equal to ``source_dir``, that is every finding. The merged
        report came out empty at exit 0, which is what a clean scan looks like.
        """
        workdir = tmp_path / "collector"
        workdir.mkdir()
        shard_paths = write_shards(tmp_path / "artifacts", build_shards(3))
        monkeypatch.chdir(workdir)

        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += ["--output-dir", ".", "--output-formats", "sarif"]

        result = self._invoke(args)

        assert result.exit_code == 2, result.output
        relocated = workdir / ".ash" / "ash_output"
        assert (relocated / RESULTS_FILE_NAME).is_file(), result.output
        assert not (workdir / RESULTS_FILE_NAME).exists()
        assert "output-dir" in result.output

        # The findings survived. Without the relocation the suppression pass would
        # have excluded every one of them and this would be an empty report at
        # exit 0.
        reloaded = AshAggregatedResults.model_validate_json(
            (relocated / RESULTS_FILE_NAME).read_text(encoding="utf-8")
        )
        assert finding_keys(reloaded) == finding_keys(build_unsharded())

    def test_an_output_dir_containing_the_cwd_is_relocated(self, tmp_path, monkeypatch):
        """Containment, which ``ash scan``'s equality check does not cover.

        ``--output-dir ..`` from a subdirectory reaches the same destructive state
        without the two paths ever being equal, so the check has to be "equal to or
        an ancestor of" rather than "equal to".
        """
        workdir = tmp_path / "collector" / "nested"
        workdir.mkdir(parents=True)
        shard_paths = write_shards(tmp_path / "artifacts", build_shards(3))
        monkeypatch.chdir(workdir)

        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += ["--output-dir", "..", "--output-formats", "sarif"]

        result = self._invoke(args)

        assert result.exit_code == 2, result.output
        relocated = tmp_path / "collector" / ".ash" / "ash_output"
        assert (relocated / RESULTS_FILE_NAME).is_file(), result.output
        assert not (tmp_path / "collector" / RESULTS_FILE_NAME).exists()

    def test_an_ordinary_output_dir_is_left_alone(self, tmp_path, monkeypatch):
        """The control. A relocation that always fires would move every merge."""
        workdir = tmp_path / "collector"
        workdir.mkdir()
        shard_paths = write_shards(tmp_path / "artifacts", build_shards(3))
        monkeypatch.chdir(workdir)
        output_dir = tmp_path / "merged"

        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += ["--output-dir", str(output_dir), "--output-formats", "sarif"]

        result = self._invoke(args)

        assert result.exit_code == 2, result.output
        assert (output_dir / RESULTS_FILE_NAME).is_file()
        assert not (output_dir / ".ash").exists()

    def test_the_same_shards_are_refused_by_default(self, tmp_path):
        """The default half of the pair, through the same CLI path.

        No flag, same shards, same refusal. This test asserted exit 2 and a written
        artifact while the default was off: the merge succeeded, the other shards'
        findings decided the verdict, and the shard that had run nothing was
        invisible to it. Nothing about that outcome was ever correct -- it was
        recorded as the default rather than as a defect -- and the flag's default
        moving to on is what closes it. ``--output-formats sarif`` is still passed so
        that the refusal is shown to happen before any report is written, which is
        what stops a downstream job reading the artifact instead of the exit code.

        Kept alongside ``test_the_negated_flag_merges_the_same_shards``, which is now
        the other direction rather than a duplicate: an absent option refuses, and
        typer's generated ``--no-`` form merges. While both merged, only the second
        could catch a mistake in the negated option's name.
        """
        shards = build_shards(3)
        _make_shard_contribute_nothing(shards[1])
        shard_paths = write_shards(tmp_path / "artifacts", shards)
        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += ["--output-dir", str(tmp_path / "merged"), "--output-formats", "sarif"]

        result = self._invoke(args)

        assert result.exit_code == 1, result.output
        assert "completed none" in result.output
        assert not (tmp_path / "merged" / RESULTS_FILE_NAME).exists()

    def test_the_negated_flag_merges_the_same_shards(self, tmp_path):
        """The opt-out, through typer, so its option name is exercised too.

        Named separately from the positive flag's test because typer generates the
        two halves of a ``--x/--no-x`` pair from one declaration and a mistake in
        the negated half is invisible to a test that only passes the positive one:
        the option would fail to parse, the gate would stay on, and the failure
        would look like the gate working.
        """
        shards = build_shards(3)
        _make_shard_contribute_nothing(shards[1])
        shard_paths = write_shards(tmp_path / "artifacts", shards)
        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += [
            "--output-dir",
            str(tmp_path / "merged"),
            "--output-formats",
            "sarif",
            "--no-fail-on-incomplete-scanners",
        ]

        result = self._invoke(args)

        # 2 for the other shards' findings, with the merged report written.
        assert result.exit_code == 2, result.output
        assert (tmp_path / "merged" / RESULTS_FILE_NAME).is_file()

    def test_an_invalid_output_format_is_rejected(self, tmp_path):
        shard_paths = write_shards(tmp_path / "artifacts", build_shards(1))

        result = self._invoke(
            [
                "--results",
                shard_paths[0],
                "--output-dir",
                str(tmp_path / "merged"),
                "--output-formats",
                "not-a-format",
            ]
        )

        assert result.exit_code != 0
        assert "not a valid format" in result.output

    @pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    )
    def test_a_link_at_a_report_path_refuses_the_reports(self, tmp_path):
        """A link already at ``reports/ash.sarif`` exits 1 naming it; nothing is written through it."""
        shard_paths = write_shards(tmp_path / "artifacts", build_shards(3))
        output_dir = tmp_path / "merged"
        (output_dir / "reports").mkdir(parents=True)
        outside = tmp_path / "outside.sarif"
        outside.write_text("unchanged", encoding="utf-8")
        link = output_dir / "reports" / "ash.sarif"
        link.symlink_to(outside)

        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += ["--output-dir", str(output_dir), "--output-formats", "sarif,csv"]

        result = self._invoke(args)

        assert result.exit_code == 1, result.output
        # Compared without styling or whitespace: the console styles the path and
        # wraps long lines.
        console = "".join(re.sub(r"\x1b\[[0-9;]*m", "", result.output).split())
        assert "".join(f"{link.as_posix()} is a symlink".split()) in console, (
            result.output
        )
        assert outside.read_text(encoding="utf-8") == "unchanged"
        assert sorted(path.name for path in (output_dir / "reports").iterdir()) == [
            "ash.sarif"
        ]

    @pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    )
    @pytest.mark.parametrize("target", ["a directory", "nothing"])
    def test_a_reports_directory_that_is_a_link_refuses_the_reports(
        self, tmp_path, target
    ):
        """A link at ``reports/`` itself, to a directory or dangling, exits 3 naming it.

        3, as for every output directory refused through a link, in a scan too.
        """
        shard_paths = write_shards(tmp_path / "artifacts", build_shards(3))
        output_dir = tmp_path / "merged"
        output_dir.mkdir()
        outside = tmp_path / "outside"
        if target == "a directory":
            outside.mkdir()
            (outside / "keep.txt").write_text("unchanged", encoding="utf-8")
        reports = output_dir / "reports"
        reports.symlink_to(outside, target_is_directory=True)

        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += ["--output-dir", str(output_dir), "--output-formats", "sarif"]

        result = self._invoke(args)

        assert result.exit_code == 3, result.output
        assert not isinstance(result.exception, OSError), repr(result.exception)
        console = "".join(re.sub(r"\x1b\[[0-9;]*m", "", result.output).split())
        expected = f"{reports.as_posix()} is a symlink"
        assert "".join(expected.split()) in console, result.output
        assert reports.is_symlink()
        if target == "a directory":
            assert sorted(path.name for path in outside.iterdir()) == ["keep.txt"]
        else:
            assert not outside.exists()

    @pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    )
    @pytest.mark.parametrize("linked", ["output", "reports"])
    def test_a_linked_output_or_reports_directory_is_refused(self, tmp_path, linked):
        """Merge writes the merged results and reports there, as a scan would."""
        shard_paths = write_shards(tmp_path / "artifacts", build_shards(3))
        host = tmp_path / "host"
        host.mkdir()
        output_dir = tmp_path / "merged"
        if linked == "output":
            output_dir.symlink_to(host, target_is_directory=True)
        else:
            output_dir.mkdir()
            (output_dir / "reports").symlink_to(host, target_is_directory=True)
        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += ["--output-dir", str(output_dir), "--output-formats", "sarif"]

        result = self._invoke(args)

        assert result.exit_code == 3, result.output
        output = " ".join(result.output.split())
        assert "is a symlink" in output
        assert "--output-dir" in output
        assert list(host.iterdir()) == [], "the merge wrote through the link"


def _incomplete_entries(
    model: AshAggregatedResults, scanner: str, status: ScannerStatus
) -> None:
    """Record *scanner* the way a shard records one it owned that did not run.

    The mirror of :func:`_skipped_entries`, and the distinction that matters:
    ``_skipped_entries`` writes ``excluded=True``, which is what a shard records
    for a scanner *another* shard owns. This writes no exclusion, so the scanner
    was this shard's to run and produced no usable result. Both halves are
    written for the same reason ``_skipped_entries`` writes both -- the
    ``additional_reports[name]["None"]`` marker is consulted first, so a fixture
    that wrote only ``scanner_results`` would exercise a shape no real scan
    produces.
    """
    model.scanner_results[scanner] = ScannerStatusInfo(
        status=status,
        excluded=False,
        dependencies_satisfied=status is not ScannerStatus.MISSING,
    )
    marker = {"scanner_name": scanner, "status": status.value}
    if status is ScannerStatus.MISSING:
        marker["dependencies_satisfied"] = False
    model.additional_reports[scanner] = {"None": marker}


def _make_shard_contribute_nothing(
    model: AshAggregatedResults, status: ScannerStatus = ScannerStatus.MISSING
) -> List[str]:
    """Turn every scanner *model* owns into one that did not complete.

    Returns the owned scanner names, so a test can assert the refusal names them.
    """
    owned = list(read_shard_assignment(model).assigned_scanners)
    model.sarif.runs[0].results = []
    for scanner in owned:
        _incomplete_entries(model, scanner, status)
    return owned


class TestRequireScannerCompletionResolution:
    """The third copy of ``fail_on_incomplete_scanners``'s default, and its precedence.

    Two copies of the default are pinned in
    ``tests/unit/interactions/test_fail_on_incomplete_scanners.py`` -- the AshConfig
    field and ``run_ash_scan``'s resolver fallback. This is the third, and until now
    no test reached it: ``build_shard`` assigns a real ``AshConfig`` to every fixture,
    so ``_resolve_require_scanner_completion`` always returned through the
    ``isinstance(value, bool)`` branch and the final literal was dead as far as this
    suite was concerned. Flipping it to ``return False`` left every test in this file
    passing, while ``ash merge`` over shards carrying no config silently returned to
    exit 0 for a merge where a shard had completed nothing.

    Every branch is exercised here so the precedence is pinned as an order and not
    just as three separate facts.
    """

    def test_no_config_anywhere_falls_back_to_the_models_default(self):
        """The literal, reached only when no shard carries a config at all.

        Agrees with ``AshConfig.fail_on_incomplete_scanners`` rather than being
        independently lenient. ``merge_shard_results`` refuses these shards right
        after this runs (``TestShardsWithoutAStoredConfigAreRefused``), so the
        value never decides a merge; it still must not be the permissive one.
        """
        from automated_security_helper.cli.merge import (
            _resolve_require_scanner_completion,
        )
        from automated_security_helper.config.ash_config import AshConfig

        shards = build_shards(3)
        for shard in shards:
            shard.ash_config = None

        resolved = _resolve_require_scanner_completion(as_loaded(shards), None)

        assert resolved is AshConfig(project_name="x").fail_on_incomplete_scanners, (
            "the fallback literal and the model default are the same decision written "
            "twice; when they disagree, which answer a merge gets depends on whether "
            "its shards happened to carry a config"
        )

    @pytest.mark.parametrize("cli_value", [True, False])
    def test_the_cli_flag_wins_over_every_shard_config(self, cli_value):
        from automated_security_helper.cli.merge import (
            _resolve_require_scanner_completion,
        )

        shards = build_shards(2)
        for shard in shards:
            shard.ash_config.fail_on_incomplete_scanners = not cli_value

        assert (
            _resolve_require_scanner_completion(as_loaded(shards), cli_value)
            is cli_value
        )

    @pytest.mark.parametrize("config_value", [True, False])
    def test_the_shard_config_is_read_when_the_cli_is_unset(self, config_value):
        from automated_security_helper.cli.merge import (
            _resolve_require_scanner_completion,
        )

        shards = build_shards(2)
        for shard in shards:
            shard.ash_config.fail_on_incomplete_scanners = config_value

        assert (
            _resolve_require_scanner_completion(as_loaded(shards), None) is config_value
        )

    def test_the_first_shard_carrying_a_config_answers_for_the_set(self):
        """An unstamped or config-less shard must not shadow one that has a config.

        Called before coverage has been verified, so the shards are in whatever order
        --results listed them. Every shard of one run carries the same config, so the
        first that has one is as good as any -- but only if a None is skipped rather
        than treated as an answer.
        """
        from automated_security_helper.cli.merge import (
            _resolve_require_scanner_completion,
        )

        shards = build_shards(3)
        shards[0].ash_config = None
        shards[1].ash_config.fail_on_incomplete_scanners = False
        shards[2].ash_config.fail_on_incomplete_scanners = False

        assert _resolve_require_scanner_completion(as_loaded(shards), None) is False

    def test_a_non_bool_on_the_config_does_not_answer(self):
        """Only a genuine bool counts.

        The attribute is reached by ``getattr`` on whatever object the caller
        supplied, so a partially-built model or a test double would otherwise
        contribute a truthy non-answer and decide the verdict by accident.
        """
        from unittest.mock import MagicMock

        from automated_security_helper.cli.merge import (
            _resolve_require_scanner_completion,
        )
        from automated_security_helper.config.ash_config import AshConfig

        shards = build_shards(2)
        for shard in shards:
            shard.ash_config = MagicMock()
            shard.ash_config.fail_on_incomplete_scanners = "false"

        assert (
            _resolve_require_scanner_completion(as_loaded(shards), None)
            is AshConfig(project_name="x").fail_on_incomplete_scanners
        )


#: A shard-chosen name or path that would drive a terminal or a CI log: ESC
#: sequences, and a newline that starts a GitHub Actions workflow command.
_HOSTILE_NAME = "x\x1b[31m\n::error title=merge::orphan"


#: A control character a terminal acts on: C0 other than the newline, DEL and C1.
_RAW_CONTROL = re.compile(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]")

#: The command forms a CI runner finds anywhere in a line: GitHub Actions' legacy
#: "##[name]" and Azure Pipelines' "##vso[". Both runners search with IndexOf.
_NAMED_HASH_COMMAND = re.compile(r"##[A-Za-z]*\[")


def _assert_shown_not_obeyed(text: str) -> None:
    assert not _RAW_CONTROL.search(text), repr(text)
    # GitHub Actions reads a line that starts with "::" after whitespace as a
    # workflow command. A bare "##", a Markdown heading's, is none.
    lines = re.split(r"[\r\n]", text)
    assert not [line for line in lines if line.lstrip().startswith("::")], repr(text)
    assert not _NAMED_HASH_COMMAND.search(text), repr(text)


class TestShardChosenTextIsShownNotObeyed:
    """Every merge refusal and warning shows shard-chosen text with its controls escaped.

    A shard set whose scanner_results holds a key with ESC and "\\n::error ..."
    puts no ESC and no workflow-command line on stdout, through the
    unclaimed-scanner refusal or the never-attempted warning, and neither does a
    --results directory name, through the unreadable-shard refusal or the
    "contains 2 results files" listing.
    """

    def _invoke(self, args):
        from unittest.mock import MagicMock, patch

        from automated_security_helper.cli.main import app

        manager = MagicMock()
        manager.plugin_modules.return_value = []
        with (
            patch("automated_security_helper.cli.merge.ash_plugin_manager", manager),
            patch("automated_security_helper.cli.merge.load_plugins"),
        ):
            return CliRunner().invoke(app, ["merge", *args])

    def _orphaned(self, tmp_path, status: ScannerStatus) -> List[str]:
        shards = build_shards(3)
        for model in shards:
            model.scanner_results[_HOSTILE_NAME] = ScannerStatusInfo(
                status=status, excluded=False, dependencies_satisfied=True
            )
        return write_shards(tmp_path / "artifacts", shards)

    def _results_args(self, paths) -> List[str]:
        return [arg for path in paths for arg in ("--results", path)]

    def test_the_unclaimed_scanner_refusal(self, tmp_path):
        paths = self._orphaned(tmp_path, ScannerStatus.PASSED)

        result = self._invoke(
            ["--output-dir", str(tmp_path / "out"), *self._results_args(paths)]
        )

        assert result.exit_code == 1, result.output
        assert "no shard was assigned" in " ".join(result.output.split()), result.output
        # Shown where the refusal is built: printed only through _shown_lines, the
        # newline would still break the line and the colon after it be written out.
        assert "\\x0a::error" in result.output, result.output
        _assert_shown_not_obeyed(result.output)

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param("x\n##[error]v1", id="legacy-command-after-a-newline"),
            pytest.param(
                "x ##vso[task.complete result=Failed]v1", id="azure-pipelines-command"
            ),
        ],
    )
    def test_a_refusal_core_sharding_builds(self, tmp_path, name):
        """The overlap refusal is core/sharding.py's, not merge.py's, and it shows
        the name with its controls written out.

        A name such as "x\\n##[error]v1" assigned on two shards is shown with its
        line break written out, so no line starts "##[error]", and "##vso[" is
        broken wherever it appears in a line, since Azure Pipelines finds it
        anywhere in one.
        """
        shards = build_shards(3)
        for model in shards[:2]:
            read_shard_assignment(model).assigned_scanners.append(name)
        paths = write_shards(tmp_path / "artifacts", shards)

        result = self._invoke(
            ["--output-dir", str(tmp_path / "out"), *self._results_args(paths)]
        )

        assert result.exit_code == 1, result.output
        assert "more than one shard" in " ".join(result.output.split()), result.output
        _assert_shown_not_obeyed(result.output)

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param(_HOSTILE_NAME, id="esc-and-newline"),
            pytest.param("x\x1b]8;;http://e.example/\x07y\x1b]8;;\x07", id="osc8"),
            pytest.param("x\x9b31my", id="c1-csi"),
            pytest.param("x\x85::error::nel", id="next-line"),
            # No control character at all: only the line guard catches this one,
            # since the name itself starts the list line.
            pytest.param("::error::lead", id="leading-workflow-command"),
        ],
    )
    def test_an_incomplete_scanner_named_after_the_merge(
        self, tmp_path, caplog, monkeypatch, name
    ):
        """The exit-1 summary and the "Scan incomplete" line named the scanner raw.

        The scanner is owned and recorded ERROR by its shard, so the merge goes
        through and only the verdict names it. The "Scan incomplete" record is taken
        from ASH's logger (_scan_log).
        """
        self._scan_log(caplog, monkeypatch)
        shards = build_shards(3)
        for model in shards:
            read_shard_assignment(model).candidate_scanners.append(name)
        read_shard_assignment(shards[0]).assigned_scanners.append(name)
        _incomplete_entries(shards[0], name, ScannerStatus.ERROR)
        for model in shards[1:]:
            _skipped_entries(model, name)
        paths = write_shards(tmp_path / "artifacts", shards)

        result = self._invoke(
            [
                "--output-dir",
                str(tmp_path / "out"),
                "--fail-on-incomplete-scanners",
                *self._results_args(paths),
            ]
        )

        assert result.exit_code == 1, result.output
        assert "did not evaluate everything" in " ".join(result.output.split()), (
            result.output
        )
        _assert_shown_not_obeyed(result.output)
        # Shown at the site, in one piece: printed only through _shown_lines, a
        # newline in the name would still break the line in two.
        shown = _shown_lines(shown_shard_text(name))
        assert shown in " ".join(result.output.split()), result.output
        # Once: the list's printer showed each line again and doubled each
        # escape's backslash.
        assert not _SHOWN_TWICE.search(result.output), result.output
        records = [r for r in caplog.records if "Scan incomplete" in r.getMessage()]
        assert records, [r.getMessage() for r in caplog.records]
        _assert_shown_not_obeyed(records[0].getMessage())
        # Text, not markup, for a name that reads as a tag.
        assert getattr(records[0], "markup", True) is False

    @staticmethod
    def _scan_log(caplog, monkeypatch):
        """ASH's logger's records, into caplog, where the exit code's reasons go.

        ash merge sets up ASH's logger, which drops its handlers, caplog's among
        them, so a filter on the logger, which it keeps, hands each record to
        caplog's handler. Let through to the root logger instead, pytest's live
        logging swaps sys.stdout mid-invoke and closes the buffer CliRunner reads.
        """
        import logging

        from automated_security_helper.utils.log import ASH_LOGGER

        class _ToCaplog(logging.Filter):
            def filter(self, record: logging.LogRecord) -> bool:
                caplog.handler.handle(record)
                return True

        monkeypatch.setattr(ASH_LOGGER, "filters", [*ASH_LOGGER.filters, _ToCaplog()])

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param(_HOSTILE_NAME, id="esc-and-newline"),
            pytest.param("x\n##[error]v1", id="legacy-command"),
        ],
    )
    def test_a_shard_set_whose_every_scanner_was_skipped(
        self, tmp_path, caplog, monkeypatch, name
    ):
        """_completed counts SKIPPED as complete, so the merge goes through.

        Only the verdict's "Scan ran no scanners" line then named the scanners, raw.
        """
        self._scan_log(caplog, monkeypatch)
        shards = build_shards(3)
        for model in shards:
            model.sarif.runs[0].results = []
            for scanner in SCANNERS:
                _skipped_entries(model, scanner)
            read_shard_assignment(model).candidate_scanners.append(name)
            _skipped_entries(model, name)
        read_shard_assignment(shards[0]).assigned_scanners.append(name)
        paths = write_shards(tmp_path / "artifacts", shards)

        result = self._invoke(
            ["--output-dir", str(tmp_path / "out"), *self._results_args(paths)]
        )

        assert result.exit_code == 1, result.output
        _assert_shown_not_obeyed(result.output)
        records = [r for r in caplog.records if "ran no scanners" in r.getMessage()]
        assert records, [r.getMessage() for r in caplog.records]
        _assert_shown_not_obeyed(records[0].getMessage())
        assert shown_shard_text(name) in records[0].getMessage()
        assert getattr(records[0], "markup", True) is False

    def test_a_failed_converter_carried_over_by_the_merge(
        self, tmp_path, caplog, monkeypatch
    ):
        """The merge carries converter_results over, failure text included."""
        from automated_security_helper.models.asharp_model import ConverterStatusInfo

        self._scan_log(caplog, monkeypatch)
        failure = "boom\x1b[31m\n##[error]r\n::error title=merge::orphan"
        shards = build_shards(3)
        shards[0].converter_results["archive"] = ConverterStatusInfo(failure=failure)
        paths = write_shards(tmp_path / "artifacts", shards)

        result = self._invoke(
            ["--output-dir", str(tmp_path / "out"), *self._results_args(paths)]
        )

        assert result.exit_code == 1, result.output
        _assert_shown_not_obeyed(result.output)
        records = [
            r for r in caplog.records if "Conversion incomplete" in r.getMessage()
        ]
        assert records, [r.getMessage() for r in caplog.records]
        _assert_shown_not_obeyed(records[0].getMessage())
        assert shown_shard_text(failure) in records[0].getMessage()
        assert getattr(records[0], "markup", True) is False

    def test_a_name_that_wraps_cannot_start_a_line_with_a_command(self, tmp_path):
        """Off a terminal Rich wrapped at 80 columns after the name had been shown.

        So a mid-name "::" could still land at the start of a line: a 70-letter word
        and the command after it did not fit on one line of the unclaimed-scanner
        refusal, the line check then broke the new line's "::", and the name was not
        shown whole. Escaping every "::" here would show an ARN as
        "arn:aws:iam:\\x3a..."; the console, which does not wrap text off a
        terminal, is what closes it. The never-attempted warning wraps the same way,
        but in the log handler's message column, whose width moves with the
        handler's columns, so it is measured on a real merge rather than pinned here.
        """
        name = "a" * 70 + " ::error::wrapped"
        shards = build_shards(3)
        for model in shards:
            model.scanner_results[name] = ScannerStatusInfo(
                status=ScannerStatus.PASSED,
                excluded=False,
                dependencies_satisfied=True,
            )
        paths = write_shards(tmp_path / "artifacts", shards)

        result = self._invoke(
            ["--output-dir", str(tmp_path / "out"), *self._results_args(paths)]
        )

        assert "::error::wrapped" in result.output, result.output
        lines = re.split(r"[\r\n]", result.output)
        assert not [line for line in lines if line.lstrip().startswith("::")], (
            result.output
        )

    @pytest.mark.parametrize(
        "warning", ["never-attempted", "no-shard-selected", "selection-hole"]
    )
    def test_a_markup_name_in_a_warning_is_text(self, tmp_path, warning):
        """The warnings were logged with markup on, so the name was read as markup.

        "[/x]" raised MarkupError and exit 1 replaced the merge's verdict of 2; on a
        terminal "[link=...]" planted a hyperlink.
        """
        name = "[/x]"
        shards = build_shards(3)
        if warning == "never-attempted":
            for model in shards:
                model.scanner_results[name] = ScannerStatusInfo(
                    status=ScannerStatus.ERROR,
                    excluded=False,
                    dependencies_satisfied=True,
                )
        else:
            for index, model in enumerate(shards):
                assignment = read_shard_assignment(model)
                assignment.candidate_scanners.append(name)
                assignment.selected_scanners = partition_scanners(SCANNERS, index, 3)
                if warning == "selection-hole":
                    # Shard 1's selection asked for the name shard 0 owns.
                    assignment.intended_scanners = list(
                        assignment.selected_scanners
                    ) + ([name] if index == 1 else [])
                _skipped_entries(model, name)
            read_shard_assignment(shards[0]).assigned_scanners.append(name)
        paths = write_shards(tmp_path / "artifacts", shards)

        result = self._invoke(
            [
                "--output-dir",
                str(tmp_path / "out"),
                "--no-fail-on-incomplete-scanners",
                *self._results_args(paths),
            ]
        )

        assert result.exception is None or isinstance(result.exception, SystemExit), (
            repr(result.exception)
        )
        assert result.exit_code == 2, result.output
        assert name in result.output, result.output

    def test_the_selection_hole_warning_is_logged_as_text(self, capture):
        """The third warning: a scanner one shard's selection asked for ran on no shard.

        The other two say they are text (NO_MARKUP); this one did not, so where a
        handler reads a record as markup unless told otherwise, a scanner named
        "[/x]" raised MarkupError and "[link=...]" planted a hyperlink.
        """
        name = "[/x]"
        shards = build_shards(3)
        for index, model in enumerate(shards):
            assignment = read_shard_assignment(model)
            assignment.candidate_scanners.append(name)
            assignment.selected_scanners = partition_scanners(SCANNERS, index, 3)
            # Every shard records what its selection asked for, and shard 1's
            # asked for the name, which shard 0 owns and did not select.
            assignment.intended_scanners = list(assignment.selected_scanners) + (
                [name] if index == 1 else []
            )
            _skipped_entries(model, name)
        read_shard_assignment(shards[0]).assigned_scanners.append(name)

        merge_shard_results(as_loaded(shards))

        records = [
            r for r in capture.records if "ran on no shard although" in r.getMessage()
        ]
        assert len(records) == 1, [r.getMessage() for r in capture.records]
        assert f"{name} (assigned to shard 0" in records[0].getMessage()
        assert getattr(records[0], "markup", True) is False

    def test_the_never_attempted_warning(self, capture):
        """Logged, not raised, so it is checked where the merge logs it.

        And as the console's sink writes it (console_text): the name was shown
        before it was put in the message, and the sink showed the message again,
        so the console read "x\\\\x1b[31m\\\\x0a" where "x\\x1b[31m\\x0a" was meant.
        """
        from automated_security_helper.utils.log import console_text

        shards = build_shards(3)
        for model in shards:
            model.scanner_results[_HOSTILE_NAME] = ScannerStatusInfo(
                status=ScannerStatus.ERROR, excluded=False, dependencies_satisfied=True
            )

        merge_shard_results(as_loaded(shards))

        records = [
            record
            for record in capture.records
            if "no shard was assigned" in record.getMessage()
        ]
        assert len(records) == 1, [record.getMessage() for record in capture.records]
        message = records[0].getMessage()
        assert "\x1b" not in message and "\n" not in message, repr(message)
        assert "\\x0a::error" in message, message
        printed = console_text(records[0], message)
        assert "x\\x1b[31m\\x0a::error title=merge::orphan (" in printed, printed
        assert "\\\\" not in printed, printed
        _assert_shown_not_obeyed(printed)
        assert getattr(records[0], "markup", True) is False

    @pytest.mark.skipif(os.name == "nt", reason="the directory names hold a newline")
    @pytest.mark.parametrize(
        "name",
        [
            pytest.param("evil\n::error title=merge::pwned", id="newline"),
            pytest.param("evil\x1b]8;;x\x07y", id="osc8"),
        ],
    )
    def test_an_unreadable_shard_under_a_hostile_directory(self, tmp_path, name):
        shard_dir = tmp_path / name
        shard_dir.mkdir()
        (shard_dir / RESULTS_FILE_NAME).write_text("{ not json", encoding="utf-8")

        result = self._invoke(
            ["--output-dir", str(tmp_path / "out"), "--results", str(shard_dir)]
        )

        assert result.exit_code == 1, result.output
        assert "Could not read shard results" in " ".join(result.output.split())
        _assert_shown_not_obeyed(result.output)

    @pytest.mark.skipif(os.name == "nt", reason="the directory names hold a newline")
    def test_the_several_results_files_listing(self, tmp_path):
        parent = tmp_path / "artifacts"
        for name in ("a", "evil\n::error title=merge::pwned"):
            (parent / name).mkdir(parents=True)
            (parent / name / RESULTS_FILE_NAME).write_text("{}", encoding="utf-8")

        result = self._invoke(
            ["--output-dir", str(tmp_path / "out"), "--results", str(parent)]
        )

        assert result.exit_code == 1, result.output
        assert "contains 2 results files" in result.output, result.output
        _assert_shown_not_obeyed(result.output)

    def test_a_missing_results_path(self, tmp_path):
        result = self._invoke(
            [
                "--output-dir",
                str(tmp_path / "out"),
                "--results",
                str(tmp_path / "no\x1b[2Jpe\n::error::x"),
            ]
        )

        assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
        _assert_shown_not_obeyed(result.output)

    def test_the_scan_source_warning_shows_each_value_once(self, tmp_path):
        """A real ash merge: the shards' scan_source values were named by their
        repr and the console showed that again, so stdout read "sx\\\\x1b[31my"
        and "C:\\\\\\\\x64"."""
        shards = build_shards(3)
        for shard, source in zip(shards, ["sx\x1b[31my", "other", "C:\\x64"]):
            shard.metadata.scan_source = source
        paths = write_shards(tmp_path / "artifacts", shards)

        result = self._invoke(
            ["--output-dir", str(tmp_path / "out"), *self._results_args(paths)]
        )

        output = " ".join(result.output.split())
        assert "different scanned directories" in output, result.output
        # ESC as one escape; "C:\x64", whose backslash reads as one, doubled once.
        assert "'sx\\x1b[31my'" in output, result.output
        assert "'C:\\\\x64'" in output, result.output
        assert "\\\\x1b" not in output and "\\\\\\\\" not in output, result.output
        _assert_shown_not_obeyed(result.output)

    def _refusal_cell(self, tmp_path, site):
        """Arguments, expected exit code and the shard-chosen value for *site*."""
        out = ["--output-dir", str(tmp_path / "out")]
        hostile_dir = tmp_path / "evil\x1b[31m\n::error title=merge::pwned"
        if site == "missing-results-path":
            return (
                [*out, "--results", str(hostile_dir)],
                ASH_EXIT_USAGE_ERROR,
                (str(hostile_dir)),
            )
        if site == "no-results-file-in":
            hostile_dir.mkdir()
            return [*out, "--results", str(hostile_dir)], 1, str(hostile_dir)
        if site == "several-results-files":
            for child in ("a", "b"):
                (hostile_dir / child).mkdir(parents=True)
                (hostile_dir / child / RESULTS_FILE_NAME).write_text(
                    "{}", encoding="utf-8"
                )
            return [*out, "--results", str(hostile_dir)], 1, str(hostile_dir)
        if site == "unreadable-shard":
            hostile_dir.mkdir()
            (hostile_dir / RESULTS_FILE_NAME).write_text("{ not", encoding="utf-8")
            return [*out, "--results", str(hostile_dir)], 1, str(hostile_dir)
        if site == "no-shard-provenance":
            shards = [build_shard(0, 1, SCANNERS, stamp=False)]
            paths = write_shards(hostile_dir, shards, as_dirs=False)
            return [*out, "--results", paths[0]], 1, paths[0]
        shards = build_shards(3)
        if site == "unclaimed-scanner":
            for model in shards:
                model.scanner_results[_HOSTILE_NAME] = ScannerStatusInfo(
                    status=ScannerStatus.PASSED,
                    excluded=False,
                    dependencies_satisfied=True,
                )
        elif site == "owner-recorded-nothing":
            for model in shards:
                read_shard_assignment(model).candidate_scanners.append(_HOSTILE_NAME)
            read_shard_assignment(shards[0]).assigned_scanners.append(_HOSTILE_NAME)
            for model in shards[1:]:
                _skipped_entries(model, _HOSTILE_NAME)
        elif site == "assigned-to-two-shards":
            for model in shards[:2]:
                read_shard_assignment(model).assigned_scanners.append(_HOSTILE_NAME)
        paths = write_shards(tmp_path / "artifacts", shards)
        return [*out, *self._results_args(paths)], 1, _HOSTILE_NAME

    @pytest.mark.skipif(os.name == "nt", reason="the directory names hold a newline")
    @pytest.mark.parametrize(
        "site",
        [
            "missing-results-path",
            "no-results-file-in",
            "several-results-files",
            "unreadable-shard",
            "no-shard-provenance",
            "unclaimed-scanner",
            "owner-recorded-nothing",
            "assigned-to-two-shards",
        ],
    )
    def test_a_refusal_shows_shard_text_once(self, tmp_path, site):
        """Each refusal shows the value it quotes once, on its own line.

        The site shows the value, and _shown_lines, the printer's second guard,
        showed each line again, doubling the backslash of every escape the site
        wrote: "x\\x1b[31m" printed as "x\\\\x1b[31m".
        """
        args, exit_code, value = self._refusal_cell(tmp_path, site)

        result = self._invoke(args)

        assert result.exit_code == exit_code, result.output
        assert shown_shard_text(value) in result.output, result.output
        assert not _SHOWN_TWICE.search(result.output), result.output
        _assert_shown_not_obeyed(result.output)


#: An escape whose backslash was doubled: text shown a second time.
_SHOWN_TWICE = re.compile(r"\\\\[xuU][0-9A-Fa-f]")


class TestShownLines:
    """A whole refusal as merge prints it: its own line breaks kept, nothing obeyed.

    For the refusals core/sharding.py builds as well as merge.py's own, so it is the
    second guard behind the one at each site, and tested on its own here.
    """

    @pytest.mark.parametrize(
        "message, shown",
        [
            pytest.param("a\n::error::x", "a\n\\x3a:error::x", id="workflow-command"),
            pytest.param("a\n  ::error::x", "a\n  \\x3a:error::x", id="indented"),
            pytest.param("::x", "\\x3a:x", id="first-line"),
            # A bare "##", a Markdown heading's, is no command to any runner.
            pytest.param("a\n## x", "a\n## x", id="line-start-heading-left"),
            pytest.param("a\n##[error]x", "a\n\\x23#[error]x", id="legacy-command"),
            pytest.param(
                "a ##vso[task.complete]x",
                "a \\x23#vso[task.complete]x",
                id="azure-pipelines-mid-line",
            ),
            # GitHub Actions' legacy runner finds "##[" anywhere in a line.
            pytest.param(
                "Refusing: a ##[warning]x",
                "Refusing: a \\x23#[warning]x",
                id="legacy-command-mid-line",
            ),
            # A tab lays the message out, as a newline does, and is kept.
            pytest.param("a\x1bb\nc\rd\te", "a\\x1bb\nc\\x0dd\te", id="controls"),
            pytest.param("a\U0000202eb", "a\\u202eb", id="bidirectional-override"),
            pytest.param("Refusing: a::b, c", "Refusing: a::b, c", id="plain"),
        ],
    )
    def test_a_message_is_shown(self, message, shown):
        assert _shown_lines(message) == shown

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(_HOSTILE_NAME, id="esc-and-newline"),
            pytest.param("x\n##[error]v1", id="legacy-command"),
            pytest.param("C:\\x64\\Lib", id="text-that-reads-as-an-escape"),
            pytest.param("a\U0000202eb\U00002028c", id="format-and-separator"),
        ],
    )
    def test_a_value_shown_already_is_not_shown_again(self, value):
        """The sites show each value; this second guard must not show it again.

        It ran shown_shard_text over each line, which doubles a backslash run
        before text that reads as an escape, and so the escapes the site wrote:
        "x\\x1b" printed as "x\\\\x1b", in every refusal and the exit-1 list.
        """
        shown = shown_shard_text(value)

        assert _shown_lines(f"Refusing: {shown}.") == f"Refusing: {shown}."


class TestScannersNoShardIntendedToRunAreNamed:
    """A scanner assigned to a shard, selected by none, ran nowhere -- say so.

    ``assigned_scanners`` is taken before the selection filters, so it names
    scanners the shard never intended to run. Each such scanner is recorded SKIPPED,
    which ``_completed`` counts as a known outcome, so the merged report presents it
    as deliberately skipped. Sometimes it was: a config-disabled scanner is skipped
    on every shard and that is the operator's choice. Sometimes it was not: two jobs
    given different ``--scanners`` values resolve the same registered set, agree on
    the candidate set, produce a partition that unions to it, and one of them
    silently dropped a scanner the other kept.

    The provenance cannot tell those apart -- a shard knows nothing about scanners it
    does not own -- so this is a disclosure and not a refusal. Refusing would break
    every merge on a host where a scanner's config disables it, which is the trap
    narrowing ``assigned_scanners`` would also have walked into.
    """

    @staticmethod
    def _select(shards, selections):
        """Record each shard's intended selection, keyed by shard index."""
        from automated_security_helper.cli.merge import read_shard_assignment

        for index, selected in selections.items():
            read_shard_assignment(shards[index]).selected_scanners = list(selected)
        return shards

    @staticmethod
    def _notices(capture):
        return [
            record.getMessage()
            for record in capture.records
            if "no shard intended to run" in record.getMessage()
        ]

    def test_a_scanner_selected_by_no_shard_is_named(self, capture):
        from automated_security_helper.cli.merge import merge_shard_results

        shards = build_shards(3)
        dropped = partition_scanners(SCANNERS, 0, 3)[0]
        selections = {
            index: [
                name
                for name in partition_scanners(SCANNERS, index, 3)
                if name != dropped
            ]
            for index in range(3)
        }

        merge_shard_results(as_loaded(self._select(shards, selections)))

        notices = self._notices(capture)
        assert notices, [r.getMessage() for r in capture.records]
        assert dropped in notices[0]

    def test_a_hostile_name_is_shown(self, capture):
        """The notice named the scanner raw: OLD printed ESC and an ::error line here."""
        from automated_security_helper.cli.merge import merge_shard_results

        shards = build_shards(3)
        for model in shards:
            read_shard_assignment(model).candidate_scanners.append(_HOSTILE_NAME)
            _skipped_entries(model, _HOSTILE_NAME)
        read_shard_assignment(shards[0]).assigned_scanners.append(_HOSTILE_NAME)
        selections = {
            index: partition_scanners(SCANNERS, index, 3) for index in range(3)
        }

        merge_shard_results(as_loaded(self._select(shards, selections)))

        notices = self._notices(capture)
        assert notices, [r.getMessage() for r in capture.records]
        assert "x\\x1b[31m\\x0a::error" in notices[0], notices[0]
        assert "\x1b" not in notices[0] and "\n" not in notices[0], repr(notices[0])

    def test_a_fully_selected_set_is_quiet(self, capture):
        """The control. A notice on every merge is noise, and noise gets filtered."""
        from automated_security_helper.cli.merge import merge_shard_results

        shards = build_shards(3)
        selections = {
            index: partition_scanners(SCANNERS, index, 3) for index in range(3)
        }

        merge_shard_results(as_loaded(self._select(shards, selections)))

        assert self._notices(capture) == []

    def test_shards_without_the_record_are_quiet(self, capture):
        """The fixtures and every pre-upgrade results file are in this state.

        With no selection recorded anywhere there is nothing to compare, and
        inferring a hole from the absence would name every scanner on every merge of
        an older fan-out's artifacts.
        """
        from automated_security_helper.cli.merge import merge_shard_results

        merge_shard_results(as_loaded(build_shards(3)))

        assert self._notices(capture) == []

    def test_the_merge_still_succeeds(self, capture):
        """A disclosure, not a refusal -- asserted rather than left implied."""
        from automated_security_helper.cli.merge import merge_shard_results

        shards = build_shards(3)
        dropped = partition_scanners(SCANNERS, 1, 3)[0]
        selections = {
            index: [
                name
                for name in partition_scanners(SCANNERS, index, 3)
                if name != dropped
            ]
            for index in range(3)
        }

        merged = merge_shard_results(as_loaded(self._select(shards, selections)))

        assert finding_keys(merged) == finding_keys(build_unsharded())


class TestNoShardSelectedNamesAreShownOnce:
    """Each list the no-shard-selected disclosure prints shows a shard's names once.

    Any job of the matrix wrote the names. The --python-only INFO line, the
    sentence naming which shards ran --python-only, the VERBOSE line and the
    selection-hole warning named them raw, and the INFO and VERBOSE lines were
    logged without NO_MARKUP. The warning that did show its names showed them
    before the console's sink showed the whole message again, so each escape
    reached the console with its backslash doubled. Each line is checked as the
    console's sink writes it (utils/log.py's console_text, which ash.log's
    formatter calls too): the escape once, nothing raw, one line.
    """

    #: _HOSTILE_NAME as the console shows it once.
    _SHOWN = "x\\x1b[31m\\x0a::error title=merge::orphan"

    @staticmethod
    def _shards(name, *, flags=(None, None, None), intended=None, reason=False):
        """Three shards; shard 0 owns *name* and none selects it.

        *flags* is each shard's recorded --python-only. *intended*, when given, is
        the set of shard indices whose selection asked for *name*: every shard then
        records intended_scanners. *reason* records the owner's skip as
        --python-only's.
        """
        from automated_security_helper.core.constants import (
            PYTHON_ONLY_SKIPPED_REASON,
        )

        shards = build_shards(3)
        for index, model in enumerate(shards):
            assignment = read_shard_assignment(model)
            assignment.candidate_scanners.append(name)
            assignment.selected_scanners = partition_scanners(SCANNERS, index, 3)
            assignment.python_only = flags[index]
            if intended is not None:
                assignment.intended_scanners = list(assignment.selected_scanners) + (
                    [name] if index in intended else []
                )
            _skipped_entries(model, name)
        read_shard_assignment(shards[0]).assigned_scanners.append(name)
        if reason:
            shards[0].scanner_results[name].skipped_reason = PYTHON_ONLY_SKIPPED_REASON
        return shards

    @pytest.mark.parametrize(
        "shape, needle, times",
        [
            pytest.param(
                {"flags": (True, True, True), "reason": True},
                "left out by --python-only on the shard",
                1,
                id="python-only-info",
            ),
            pytest.param(
                {"flags": (True, False, False), "reason": True},
                "The shards disagree on --python-only",
                2,
                id="disagreement-with-the-flag",
            ),
            pytest.param(
                {"reason": True},
                "No shard recorded whether it ran with --python-only",
                2,
                id="disagreement-none-recorded",
            ),
            pytest.param(
                {"flags": (False, None, None), "reason": True},
                "recorded running without --python-only",
                2,
                id="disagreement-recorded-without",
            ),
            pytest.param(
                {"intended": set()},
                "were selected by no shard's",
                1,
                id="asked-for-by-no-shard-verbose",
            ),
            pytest.param(
                {"intended": {1}},
                "ran on no shard although",
                1,
                id="selection-hole",
            ),
            pytest.param(
                {"intended": {1}, "flags": (True, False, False), "reason": True},
                "ran on no shard although",
                2,
                id="selection-hole-with-a-disagreement",
            ),
            pytest.param(
                {}, "no shard intended to run", 1, id="shards-before-intended"
            ),
        ],
    )
    def test_the_line_shows_each_name_once(self, capture, shape, needle, times):
        from automated_security_helper.cli.merge import merge_shard_results
        from automated_security_helper.utils.log import VERBOSE_LEVEL, console_text

        capture.set_level(VERBOSE_LEVEL, logger=ASH_LOGGER_NAME)

        merge_shard_results(as_loaded(self._shards(_HOSTILE_NAME, **shape)))

        records = [r for r in capture.records if needle in r.getMessage()]
        assert len(records) == 1, [r.getMessage() for r in capture.records]
        record = records[0]
        printed = console_text(record, record.getMessage())
        assert printed.count(self._SHOWN) == times, printed
        # Shown once: no message here holds a backslash of its own.
        assert "\\\\" not in printed, printed
        assert "\n" not in printed, repr(printed)
        _assert_shown_not_obeyed(printed)
        # Text, not markup, for a name that reads as a tag.
        assert getattr(record, "markup", True) is False


class TestPythonOnlyShardsNameTheFlagThatLeftScannersOut:
    """A sharded ``--python-only`` scan leaves every non-Python scanner unselected.

    Each shard is assigned scanners from every registered scanner, so the shard
    that owns grype, syft or npm-audit records it SKIPPED with "not a Python-only
    scanner, and --python-only is set", and no shard selected it.

    The merge leaves a scanner its owning shard recorded as left out by
    --python-only out of the "assigned to a shard but no shard intended to run them"
    warning, which would send the operator to check --scanners and
    --exclude-scanners that nobody passed, and names the flag, at INFO, since the
    merged report already carries the reason on the scanner's row. A scanner no
    shard selected for any other reason is warned about.

    The shards are produced by the real ``ScanPhase`` over every shipped scanner,
    with the scanner executor replaced and the queued scanners recorded as having
    run.
    """

    @pytest.fixture(autouse=True)
    def _no_uv_tool_probe(self, monkeypatch):
        """The shipped bandit, checkov and semgrep probe their version with uv.

        That writes under HOME and the XDG cache dir, and checkov's update check
        reaches PyPI; the merge does not depend on the version.
        """
        from automated_security_helper.base.uv_tool_mixin import UVToolMixin

        monkeypatch.setattr(UVToolMixin, "_get_uv_tool_version", lambda *_a, **_k: None)

    @pytest.fixture(autouse=True)
    def no_tool_starts(self, tmp_path_factory, monkeypatch):
        """Recording stand-ins first on PATH; no test in this class may start a tool.

        Building the shipped scanners probed ``opengrep --version`` on the host's
        opengrep, twice per shard set; the probes are answered as on a host
        without the tools (``stub_tool_probes``).
        """
        from tests.utils.tool_guard import (
            install_tool_guard,
            reset_tool_lookup_caches,
            stub_tool_probes,
        )

        guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))
        stub_tool_probes(monkeypatch)
        yield guard
        reset_tool_lookup_caches()
        assert guard.started == [], f"the test started tools: {guard.started}"

    def test_building_the_shards_runs_no_tool(
        self, tmp_path, monkeypatch, no_tool_starts
    ):
        from automated_security_helper.utils import uv_tool_runner

        asked: list = []

        class _Runner:
            def is_uv_available(self):
                return True

            def get_tool_version(self, tool_name, package_name=None):
                asked.append(tool_name)

        monkeypatch.setattr(uv_tool_runner, "get_uv_tool_runner", lambda: _Runner())

        self._shard(tmp_path, 0, 2, python_based_plugins_only=True)

        assert asked == [], f"the version probe asked uv to run {asked}"
        assert no_tool_starts.started == [], (
            f"building the shards started tools: {no_tool_starts.started}"
        )

    @staticmethod
    def _shard(tmp_path, index, count, **phase_kwargs):
        from unittest.mock import MagicMock, patch

        from automated_security_helper.base.scanner_plugin import ScannerPluginBase
        from automated_security_helper.config.default_config import (
            get_default_config,
        )
        from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
        from automated_security_helper.core.phases.scan_phase import ScanPhase
        from automated_security_helper.plugin_modules import (
            ash_builtin,
            ash_ferret_plugins,
            ash_snyk_plugins,
            ash_trivy_plugins,
        )

        shipped = [
            *ash_builtin.ASH_SCANNERS,
            *ash_snyk_plugins.ASH_SCANNERS,
            *ash_ferret_plugins.ASH_SCANNERS,
            *ash_trivy_plugins.ASH_SCANNERS,
        ]
        root = tmp_path / f"shard-{index}"
        source = root / "source"
        source.mkdir(parents=True)
        (source / "app.py").write_text("x = 1\n", encoding="utf-8")
        output = root / "output"
        (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
        context = PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / ASH_WORK_DIR_NAME,
            config=get_default_config(),
        )
        aggregated = AshAggregatedResults()
        aggregated.ash_config = context.config
        phase = ScanPhase(
            plugin_context=context,
            plugins=shipped,
            progress_display=MagicMock(),
            asharp_model=aggregated,
        )
        phase.validation_manager = MagicMock()
        with patch(
            "automated_security_helper.core.phases.scan_phase.ScannerExecutor"
        ) as executor:
            for scanner_class in {ScannerPluginBase, *shipped}:
                patch.object(
                    scanner_class, "validate_plugin_dependencies", return_value=True
                ).start()
            double = MagicMock()
            double.completed_scanners = []
            double.run_parallel.return_value = aggregated
            double.run_sequential.return_value = aggregated
            executor.return_value = double
            try:
                results = phase._execute_phase(
                    aggregated_results=aggregated,
                    shard_index=index,
                    shard_count=count,
                    **phase_kwargs,
                )
            finally:
                patch.stopall()
            queued = [name for name, _, _ in executor.call_args.kwargs["scanner_tasks"]]
        for name in queued:
            results.scanner_results[name] = ScannerTargetStatusInfo(
                status=ScannerStatus.PASSED, excluded=False, dependencies_satisfied=True
            )
            results.additional_reports[name] = {
                "source": {"scanner_name": name, "status": "PASSED"}
            }
        # What the execution engine does with the assignment after the scan phase.
        results.metadata.shard = phase._shard_assignment
        return populate_metrics_from_unified_source(aggregated_results=results)

    @staticmethod
    def _messages(capture, needle):
        return [
            record.getMessage()
            for record in capture.records
            if needle in record.getMessage()
        ]

    NOT_PYTHON_ONLY = [
        "actionlint",
        "cdk-nag",
        "cfn-guard",
        "cfn-nag",
        "ferret-scan",
        "gitleaks",
        "grype",
        "npm-audit",
        "opengrep",
        "snyk-code",
        "syft",
        "trivy",
        "trivy-repo",
    ]

    def test_the_scanners_python_only_left_out_are_not_a_hole(self, capture, tmp_path):
        import logging

        from automated_security_helper.cli.merge import merge_shard_results

        capture.set_level(logging.INFO, logger=ASH_LOGGER_NAME)
        shards = [
            self._shard(tmp_path, index, 2, python_based_plugins_only=True)
            for index in range(2)
        ]

        merged = merge_shard_results(as_loaded(shards))

        holes = self._messages(capture, "no shard intended to run")
        assert holes == [], (
            "every job ran with --python-only; advising --scanners and "
            f"--exclude-scanners names a cause nobody had: {holes}"
        )
        (named,) = self._messages(capture, "left out by --python-only")
        for scanner in self.NOT_PYTHON_ONLY:
            assert scanner in named, named
            row = merged.scanner_results[scanner]
            assert row.status == ScannerStatus.SKIPPED, (scanner, row)
            assert "--python-only" in (row.skipped_reason or ""), (scanner, row)

    def test_a_scanner_one_shard_left_out_for_another_reason_is_named(
        self, capture, tmp_path
    ):
        """bandit's owner excluded it and the other shard did not: a hole."""
        from automated_security_helper.cli.merge import merge_shard_results

        probe = self._shard(tmp_path / "probe", 0, 2, python_based_plugins_only=True)
        owner = 0 if "bandit" in probe.metadata.shard.assigned_scanners else 1
        shards = [
            self._shard(
                tmp_path,
                index,
                2,
                python_based_plugins_only=True,
                excluded_scanners=["bandit"] if index == owner else [],
            )
            for index in range(2)
        ]

        merge_shard_results(as_loaded(shards))

        (hole,) = self._messages(capture, "ran on no shard although")
        assert "bandit" in hole, hole
        for scanner in self.NOT_PYTHON_ONLY:
            assert f"{scanner} (" not in hole, (scanner, hole)

    def test_a_scanner_every_shard_excluded_is_not_a_hole(self, capture, tmp_path):
        from automated_security_helper.cli.merge import merge_shard_results

        shards = [
            self._shard(
                tmp_path,
                index,
                2,
                python_based_plugins_only=True,
                excluded_scanners=["bandit"],
            )
            for index in range(2)
        ]

        merge_shard_results(as_loaded(shards))

        assert self._messages(capture, "ran on no shard although") == []
        assert self._messages(capture, "no shard intended to run") == []

    def test_shards_that_disagree_on_python_only_warn(self, capture, tmp_path):
        """Only shard 0 ran --python-only, so the scanners it left out ran nowhere.

        grype is shard 0's, and shard 0 recorded it SKIPPED for --python-only; shard
        1 ran its own scanners in full. Nothing ran grype, and the matrix gave its
        jobs different selections, which is what the warning is for.
        """
        import logging

        from automated_security_helper.cli.merge import merge_shard_results

        capture.set_level(logging.INFO, logger=ASH_LOGGER_NAME)
        shards = [
            self._shard(tmp_path, 0, 2, python_based_plugins_only=True),
            self._shard(tmp_path, 1, 2),
        ]
        owner = {
            scanner
            for scanner in self.NOT_PYTHON_ONLY
            if scanner in read_shard_assignment(shards[0]).assigned_scanners
        }
        assert "grype" in owner, owner

        merge_shard_results(as_loaded(shards))

        # Both shards record intended_scanners, and shard 1's selection asked for
        # every scanner, so this is the "a shard's selection asked for them" warning.
        (hole,) = self._messages(capture, "ran on no shard although")
        record = next(
            r for r in capture.records if "ran on no shard although" in r.getMessage()
        )
        assert record.levelno == logging.WARNING, record.levelname
        for scanner in sorted(owner):
            assert f"{scanner} (" in hole, (scanner, hole)
        assert "--python-only" in hole, hole
        assert self._messages(capture, "left out by --python-only") == []

    def test_a_scanner_a_shard_asked_for_is_never_named_at_info(
        self, capture, tmp_path
    ):
        """INFO is for a scanner no job asked for. Every shard ran --python-only, but
        shard 1 recorded grype among what its selection asked for, so grype running
        nowhere is a hole, whatever its owner's skip reason says."""
        import logging

        from automated_security_helper.cli.merge import merge_shard_results

        capture.set_level(logging.INFO, logger=ASH_LOGGER_NAME)
        shards = [
            self._shard(tmp_path, index, 2, python_based_plugins_only=True)
            for index in range(2)
        ]
        owner = (
            0 if "grype" in read_shard_assignment(shards[0]).assigned_scanners else 1
        )
        asker = 1 - owner
        assignment = shards[asker].metadata.shard
        assignment.intended_scanners = sorted(
            set(assignment.intended_scanners or []) | {"grype"}
        )

        merge_shard_results(as_loaded(shards))

        (named,) = self._messages(capture, "left out by --python-only")
        assert "grype" not in named, named
        (hole,) = self._messages(capture, "ran on no shard although")
        assert "grype (" in hole, hole

    def test_shards_that_recorded_no_flag_are_not_called_a_disagreement(
        self, capture, tmp_path
    ):
        """Every shard ran --python-only but none recorded the flag.

        The warning listed an empty set of shards "with it" against all of them
        "without", a disagreement nothing in the shard results shows. The shards
        record no selection either (results written before both fields), so the
        merge cannot tell a scanner no job asked for from one it did.
        """
        from automated_security_helper.cli.merge import merge_shard_results

        shards = [
            self._shard(tmp_path, index, 2, python_based_plugins_only=True)
            for index in range(2)
        ]
        for shard in shards:
            read_shard_assignment(shard).python_only = None
            read_shard_assignment(shard).intended_scanners = None

        merge_shard_results(as_loaded(shards))

        (hole,) = self._messages(capture, "no shard intended to run")
        assert "ran with it and" not in hole, hole
        assert "No shard recorded whether it ran with --python-only" in hole, hole

    # What the warning says of --python-only when no shard recorded True, by
    # what shard 0 (ran --python-only, owns grype) and shard 1 (ran in full)
    # recorded. {owner} is the scanners shard 0 recorded left out by the flag.
    _NOTHING_RECORDED = (
        "No shard recorded whether it ran with --python-only, and the shards "
        "that own {owner} recorded them left out by it."
    )
    _OWNER_RECORDED_NOTHING = (
        "Shard(s) 1 recorded running without --python-only and shard(s) 0 "
        "recorded nothing, but the shards that own {owner} recorded them left "
        "out by it, so they ran nowhere."
    )
    _BOTH_RECORDED_FALSE = (
        "Shard(s) 0, 1 recorded running without --python-only, but the shards "
        "that own {owner} recorded them left out by it, so they ran nowhere."
    )

    def _mixed_matrix(self, tmp_path, owner_flag, other_flag):
        """Shard 0 ran --python-only, shard 1 in full; then their recorded flags."""
        shards = [
            self._shard(tmp_path, 0, 2, python_based_plugins_only=True),
            self._shard(tmp_path, 1, 2),
        ]
        assert read_shard_assignment(shards[1]).python_only is False
        read_shard_assignment(shards[0]).python_only = owner_flag
        read_shard_assignment(shards[1]).python_only = other_flag
        owner = sorted(
            scanner
            for scanner in self.NOT_PYTHON_ONLY
            if scanner in read_shard_assignment(shards[0]).assigned_scanners
        )
        assert "grype" in owner, owner
        return shards, owner

    @pytest.mark.parametrize(
        ("owner_flag", "other_flag", "expected"),
        [
            (None, None, _NOTHING_RECORDED),
            (None, False, _OWNER_RECORDED_NOTHING),
            (False, False, _BOTH_RECORDED_FALSE),
        ],
        ids=["none-recorded", "owner-recorded-nothing", "owner-recorded-false"],
    )
    def test_a_shard_that_recorded_no_python_only_is_named_as_recording_it(
        self, capture, tmp_path, owner_flag, other_flag, expected
    ):
        """No shard recorded python_only True, and none recorded its selection.

        Shard 0 ran --python-only and recorded grype left out by it, but its own
        flag reads None (or False). "No shard recorded whether it ran with
        --python-only" was false whenever a shard recorded False: that shard
        recorded that it ran without the flag. With no intended_scanners either,
        this is the "no shard intended to run" warning.
        """
        from automated_security_helper.cli.merge import merge_shard_results

        shards, owner = self._mixed_matrix(tmp_path, owner_flag, other_flag)
        for shard in shards:
            read_shard_assignment(shard).intended_scanners = None

        merge_shard_results(as_loaded(shards))

        (hole,) = self._messages(capture, "no shard intended to run")
        assert "ran with it and" not in hole, hole
        nothing_recorded = owner_flag is None and other_flag is None
        assert ("No shard recorded whether" in hole) == nothing_recorded, hole
        assert expected.format(owner=", ".join(owner)) in hole, hole

    @pytest.mark.parametrize(
        ("owner_flag", "expected"),
        [(None, _OWNER_RECORDED_NOTHING), (False, _BOTH_RECORDED_FALSE)],
        ids=["owner-recorded-nothing", "owner-recorded-false"],
    )
    def test_a_hole_a_selection_asked_for_names_what_each_shard_recorded(
        self, capture, tmp_path, owner_flag, expected
    ):
        """The same matrix with intended_scanners kept: shard 1 ran in full, so its
        selection asked for grype, and the warning is the "a shard's selection
        asked for them" one. Its --python-only sentence names the same records.
        """
        from automated_security_helper.cli.merge import merge_shard_results

        shards, owner = self._mixed_matrix(tmp_path, owner_flag, False)
        asked = {
            scanner.lower()
            for scanner in read_shard_assignment(shards[1]).intended_scanners or []
        }
        assert set(owner) <= asked, (owner, asked)

        merge_shard_results(as_loaded(shards))

        (hole,) = self._messages(capture, "ran on no shard although")
        assert "No shard recorded whether" not in hole, hole
        assert "ran with it and" not in hole, hole
        assert expected.format(owner=", ".join(owner)) in hole, hole

    def test_the_shard_records_whether_it_ran_python_only(self, tmp_path):
        assert (
            read_shard_assignment(
                self._shard(tmp_path, 0, 2, python_based_plugins_only=True)
            ).python_only
            is True
        )
        assert read_shard_assignment(self._shard(tmp_path, 1, 2)).python_only is False


class TestCompletedClassifiesUnknownStatusesAsIncomplete:
    """``ash merge`` is the reader most exposed to a status it does not know.

    It consumes results files written by whatever ASH produced each shard, so a
    fan-out whose runners are mid-upgrade can hand it a status string that is not in
    this version's ``ScannerStatus``. A denylist -- "not ERROR and not MISSING means
    it ran" -- reports that shard as complete, and the merged report then covers
    scanners whose outcome nobody knows.

    Exercised through ``_completed`` directly rather than through a shard fixture,
    because ``ScannerStatusInfo.status`` is typed to the enum and cannot hold the
    cross-version string this is about.
    """

    class _Entry:
        def __init__(self, status):
            self.status = status

    @pytest.mark.parametrize(
        "status", [ScannerStatus.PASSED, ScannerStatus.FAILED, ScannerStatus.SKIPPED]
    )
    def test_the_three_known_complete_statuses_are_complete(self, status):
        assert _completed(self._Entry(status)) is True
        assert _completed(self._Entry(status.value)) is True

    @pytest.mark.parametrize("status", [ScannerStatus.ERROR, ScannerStatus.MISSING])
    def test_the_two_known_incomplete_statuses_are_incomplete(self, status):
        assert _completed(self._Entry(status)) is False

    @pytest.mark.parametrize("status", ["PARTIALLY_COMPLETED", "TIMED_OUT", "", None])
    def test_a_status_this_version_does_not_know_is_incomplete(self, status):
        assert _completed(self._Entry(status)) is False, (
            f"{status!r} is not evidence that a scanner ran; treating it as complete "
            "is how a shard from another ASH version merges into a clean report"
        )

    def test_an_entry_with_no_status_attribute_at_all_is_incomplete(self):
        assert _completed(object()) is False


class TestShardContributionIsRefused:
    """A present shard that completed none of its scanners is the distributed
    shape of the false-green exit code.

    ``verify_shard_coverage`` and ``_verify_scanner_union`` both pass here: the
    index is present, exactly one shard claims each scanner, and the owning
    shard's results do mention them. Neither looks at the *status*. So a shard
    whose every scanner came back MISSING merges into a report that reads as a
    complete scan of the whole tree, one third of which never ran.

    Gated behind ``--fail-on-incomplete-scanners`` for the same reason the scan
    side's gate is: four of this tree's ten default scanners are MISSING on a
    stock workstation, so refusing by default would break merges that have
    nothing wrong with them.

    Refused before merging rather than reported afterwards. ``merge_command``
    writes ``ash_aggregated_results.json`` and every report *before* it computes
    an exit code, so a downstream job that consumes the artifact instead of the
    exit code would ingest a report that reads as complete. Refusing early means
    the file never exists.
    """

    def test_a_shard_that_completed_nothing_is_refused(self):
        shards = build_shards(3)
        owned = _make_shard_contribute_nothing(shards[1])
        assert owned, "fixture must give shard 1 something to fail at"

        with pytest.raises(ShardCoverageError, match=r"completed none"):
            merge_shard_results(as_loaded(shards), require_scanner_completion=True)

    def test_the_refusal_names_the_shard_and_its_scanners(self):
        shards = build_shards(3)
        owned = _make_shard_contribute_nothing(shards[2])

        with pytest.raises(ShardCoverageError) as excinfo:
            merge_shard_results(as_loaded(shards), require_scanner_completion=True)

        message = str(excinfo.value)
        assert "shard 2" in message
        for scanner in owned:
            assert scanner in message, (
                f"{scanner} is one of the scanners that never ran; without it in "
                f"the message the operator cannot tell what to look at"
            )

    def test_an_errored_shard_is_refused_too(self):
        # ERROR (ran and failed) and MISSING (never started) are both "did not
        # complete"; only the remedy differs.
        shards = build_shards(3)
        _make_shard_contribute_nothing(shards[0], status=ScannerStatus.ERROR)

        with pytest.raises(ShardCoverageError, match=r"completed none"):
            merge_shard_results(as_loaded(shards), require_scanner_completion=True)

    def test_a_shard_that_lost_only_some_targets_is_still_merged(self):
        """Partial coverage loss must NOT be read as "this shard completed nothing".

        Two checks both mean "incomplete" and are not the same question:

        * ``_completed`` / ``_verify_shard_contributions`` ask whether a shard's
          scanner ran **at all**. A scanner that read 8 of its 10 targets ran, so
          the shard contributed and the merge must proceed.
        * ``incomplete_scanners`` asks whether everything the scanner was given
          was evaluated. It answers no here, and that is what the opt-in exit-code
          gate acts on.

        What each assertion is worth, stated honestly because the two differ:

        The merge-proceeds half is a regression guard, and an earlier version of
        this docstring undersold it on a false premise. It said the protection was
        *structural* because ``ScannerTargetStatusInfo`` declares no target
        counters. The model sets ``extra="allow"``, so counters written into
        ``scanner_results`` land in ``model_extra`` and ``getattr(entry,
        "targets_failed", 0)`` returns 4 rather than the default -- measured, not
        reasoned. Nothing structural stops ``_completed`` from reading coverage.
        What stops it is that it reads the status and only the status, which is a
        behavior, and ``test_partial_coverage_still_counts_as_having_run`` in
        ``tests/unit/interactions/test_fail_on_partial_target_coverage.py`` holds
        that behavior against a mutation that consults the counters.

        The gate-still-sees-it half is falsifiable and is what earns this test its
        place. It is the only coverage this repository has that the target counters
        survive a **merge** -- they live in ``additional_reports``, which the merge
        recombines from n shards -- and reach the exit-code gate on the merged
        product. Verified by mutation: removing the coverage arm from
        ``incomplete_scanners`` fails it. It doubles as the control against a
        fixture with no partial coverage in it, which would make the first half a
        test of nothing.
        """
        shards = build_shards(3)
        owned = list(read_shard_assignment(shards[1]).assigned_scanners)
        assert owned, "fixture must give shard 1 scanners to lose targets on"
        for scanner in owned:
            # Lost some, not all, with the entry's recorded status left as the
            # fixture built it (PASSED): the artifact an ASH from before the
            # fail-closed status rule wrote, which the merge still loads. A
            # current scan grades a partial loss by the per-tree gate-first rule:
            # surviving findings that fail the severity gate grade FAILED, clean
            # survivors grade ERROR. The ERROR shape has its own cells
            # (test_an_errored_shard_that_audited_some_targets_is_merged and its
            # full-loss control).
            shards[1].additional_reports[scanner]["source"]["targets_attempted"] = 10
            shards[1].additional_reports[scanner]["source"]["targets_failed"] = 4

        merged = merge_shard_results(as_loaded(shards), require_scanner_completion=True)

        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_scanners,
        )

        listed = dict(incomplete_scanners(merged))
        for scanner in owned:
            assert scanner in listed, (
                f"{scanner} lost 4 of 10 targets, so the fixture is genuinely "
                f"partial and this test is not vacuous; the exit-code gate has to "
                f"see it even though shard verification correctly did not"
            )

    def test_an_errored_shard_that_audited_some_targets_is_merged(self):
        """ERROR with 0 < failed < attempted means the scanner ran.

        The scanner audited the targets it could and graded ERROR over the ones
        it lost, so the shard contributed real findings and the merge proceeds.
        Refusing it as "completed none" would discard the audited targets'
        findings. The shortfall is not forgotten: the exit-code gate on the
        merged product still names it and exits 1, which the second half pins.
        """
        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_scanners,
        )

        shards = build_shards(3)
        expected = finding_keys(build_shards(3)[1])
        owned = _make_shard_contribute_nothing(shards[1], status=ScannerStatus.ERROR)
        assert owned, "fixture must give shard 1 scanners to run partially"
        assert expected, "fixture must give shard 1 findings to keep"
        # The shard audited some targets, so it carries the findings from them.
        shards[1].sarif = _sarif_for(owned)
        for scanner in owned:
            shards[1].additional_reports[scanner]["None"]["targets_attempted"] = 10
            shards[1].additional_reports[scanner]["None"]["targets_failed"] = 4

        merged = merge_shard_results(as_loaded(shards), require_scanner_completion=True)

        survived = finding_keys(merged)
        for key in expected:
            assert key in survived, (
                f"{key} came from a shard that audited 6 of 10 targets; merging "
                f"the shard exists to keep it"
            )
        listed = dict(incomplete_scanners(merged))
        for scanner in owned:
            assert scanner in listed, (
                f"{scanner} lost 4 of 10 targets; the merge keeping the shard "
                f"must not hide the shortfall from the exit-code gate"
            )

    def test_an_errored_shard_whose_every_target_failed_is_refused(self):
        # The counts prove nothing ran to completion: every attempted target
        # failed, so nothing distinguishes this shard's yield from one whose
        # scanner never started, and the refusal stands as it does for an ERROR
        # entry with no counts at all (test_an_errored_shard_is_refused_too).
        shards = build_shards(3)
        owned = _make_shard_contribute_nothing(shards[0], status=ScannerStatus.ERROR)
        for scanner in owned:
            shards[0].additional_reports[scanner]["None"]["targets_attempted"] = 10
            shards[0].additional_reports[scanner]["None"]["targets_failed"] = 10

        with pytest.raises(ShardCoverageError, match=r"completed none"):
            merge_shard_results(as_loaded(shards), require_scanner_completion=True)

    def test_an_errored_shard_whose_counts_show_zero_failures_is_refused(self):
        # The other boundary of 0 < failed < attempted: ERROR with targets
        # attempted and zero failures makes no partial-coverage claim either.
        # The audited-some arm exists to keep the findings of a scanner that
        # graded ERROR over LOSING targets; counts that lost nothing explain
        # no ERROR, so they prove no partial run and the refusal stands as it
        # does for an entry with no counts at all.
        shards = build_shards(3)
        owned = _make_shard_contribute_nothing(shards[0], status=ScannerStatus.ERROR)
        for scanner in owned:
            shards[0].additional_reports[scanner]["None"]["targets_attempted"] = 10
            shards[0].additional_reports[scanner]["None"]["targets_failed"] = 0

        with pytest.raises(ShardCoverageError, match=r"completed none"):
            merge_shard_results(as_loaded(shards), require_scanner_completion=True)

    def test_a_missing_shard_with_partial_counts_is_refused(self):
        # The partial-audit read widens only an ERROR entry. A MISSING entry never
        # started, so counts beside it (a producer bug or a hand-edited artifact)
        # prove nothing ran, and the refusal stands.
        shards = build_shards(3)
        owned = _make_shard_contribute_nothing(shards[0], status=ScannerStatus.MISSING)
        for scanner in owned:
            shards[0].additional_reports[scanner]["None"]["targets_attempted"] = 10
            shards[0].additional_reports[scanner]["None"]["targets_failed"] = 4

        with pytest.raises(ShardCoverageError, match=r"completed none"):
            merge_shard_results(as_loaded(shards), require_scanner_completion=True)

    @staticmethod
    def _entry_with_counts(status, attempted=10, failed=4):
        from types import SimpleNamespace

        # The report names its scanner, as every report ScanResultProcessor writes
        # does: target_counts reads only the reports that are the scanner's own
        # (unified_metrics.own_target_reports), so a nameless report counts for
        # nothing and a fixture without the name measured no partial audit at all.
        return SimpleNamespace(
            scanner_results={"bandit": SimpleNamespace(status=status)},
            additional_reports={
                "bandit": {
                    "source": {
                        "scanner_name": "bandit",
                        "targets_attempted": attempted,
                        "targets_failed": failed,
                    }
                }
            },
        )

    @pytest.mark.parametrize(
        "status",
        [
            ScannerStatus.MISSING,
            ScannerStatus.MISSING.value,
            "PARTIALLY_COMPLETED",
            "",
            None,
        ],
    )
    def test_partial_counts_beside_a_status_other_than_error_are_not_a_run(
        self, status
    ):
        from automated_security_helper.cli.merge import _ran_partially

        assert _ran_partially(self._entry_with_counts(status), "bandit") is False, (
            f"{status!r} beside 10/4 counts is not an ERROR over a partial audit; "
            "an unfamiliar status from another ASH version is no evidence that "
            "the scanner ran"
        )

    @pytest.mark.parametrize("status", [ScannerStatus.ERROR, ScannerStatus.ERROR.value])
    def test_an_error_entry_with_partial_counts_is_a_run(self, status):
        from automated_security_helper.cli.merge import _ran_partially

        assert _ran_partially(self._entry_with_counts(status), "bandit") is True

    def test_an_error_entry_whose_every_target_failed_is_not_a_run(self):
        from automated_security_helper.cli.merge import _ran_partially

        entry = self._entry_with_counts(ScannerStatus.ERROR, attempted=10, failed=10)
        assert _ran_partially(entry, "bandit") is False

    def test_a_scanner_absent_from_its_owners_results_is_refused(self):
        # The case a status-based check structurally cannot see: the owning shard
        # recorded no entry at all, so there is no status to inspect. Reproduced
        # with a single shard because with two or more, another shard's skip
        # marker puts the name in _verify_scanner_union's `seen` set and that
        # check catches it first.
        shard = build_shard(0, 1, SCANNERS)
        for scanner in SCANNERS:
            shard.scanner_results.pop(scanner, None)
            shard.additional_reports.pop(scanner, None)

        with pytest.raises(ShardCoverageError, match=r"completed none"):
            merge_shard_results(as_loaded([shard]), require_scanner_completion=True)

    def test_a_shard_that_completed_nothing_no_longer_merges_to_exit_zero(
        self, tmp_path
    ):
        """The distributed false green, and the verdict that now replaces it.

        Every finding is stripped so the only signal left is completeness. One of
        three shards ran nothing, and this used to report exit 0 -- the same code a
        genuinely clean three-shard scan produces -- on the argument that a
        non-zero default would break merges wherever a scanner's tool is
        legitimately absent. The argument is inverted: those merges were producing
        a report whose clean bill of health covered scanners that never ran, and
        every consumer downstream reads the merged artifact rather than the shard
        logs.

        Note what this test does *not* exercise. ``merge_shard_results`` still
        takes ``require_scanner_completion=False`` as its Python default, so the
        merge itself succeeds here and the verdict comes from
        ``_merged_exit_code``. That parameter default was left alone deliberately:
        it is an argument to an internal function that the CLI always passes
        explicitly, forty-odd tests call it bare to build a merged model they then
        assert something unrelated about, and flipping it would redden all of them
        to restate a default that ``_resolve_require_scanner_completion`` already
        owns. The user-visible default lives there and in ``AshConfig``.

        THE GATE IS PASSED EXPLICITLY even though it is now the default, so that what
        this test pins does not depend on the default's value: the verdict for a union
        missing a shard's worth of scanners, asked for outright. That has held through
        the default being off and on again. The default's own value is pinned by
        ``test_fail_on_incomplete_scanners.py::test_config_field_defaults_to_on``, and
        the default path through this CLI by
        ``test_the_same_shards_are_refused_by_default`` above.
        """
        shards = build_shards(3)
        for model in shards:
            model.sarif.runs[0].results = []
            for scanner in read_shard_assignment(model).assigned_scanners:
                model.scanner_results[scanner] = ScannerTargetStatusInfo(
                    status=ScannerStatus.PASSED, excluded=False
                )
        _make_shard_contribute_nothing(shards[1])

        merged = merge_shard_results(as_loaded(shards))

        assert _merged_exit_code(merged, tmp_path, "low", None, True) == 1

    def test_the_same_merge_exits_zero_with_the_gate_explicitly_off(self, tmp_path):
        """The opt-out, on the identical fixture.

        Kept as the counterpart so the pair shows the default moved rather than the
        opt-out disappearing. Without it, a change that made the verdict
        unconditional would pass every other test in this class.
        """
        shards = build_shards(3)
        for model in shards:
            model.sarif.runs[0].results = []
            for scanner in read_shard_assignment(model).assigned_scanners:
                model.scanner_results[scanner] = ScannerTargetStatusInfo(
                    status=ScannerStatus.PASSED, excluded=False
                )
        _make_shard_contribute_nothing(shards[1])

        merged = merge_shard_results(as_loaded(shards))

        assert _merged_exit_code(merged, tmp_path, "low", None, False) == 0

    def test_the_same_merge_exits_one_with_the_gate_on(self, tmp_path):
        """The counterpart: identical fixture, gate on, verdict 1 instead of 0."""
        shards = build_shards(3)
        for model in shards:
            model.sarif.runs[0].results = []
            for scanner in read_shard_assignment(model).assigned_scanners:
                model.scanner_results[scanner] = ScannerTargetStatusInfo(
                    status=ScannerStatus.PASSED, excluded=False
                )
        _make_shard_contribute_nothing(shards[1])

        # Refused before a merged report exists at all, so there is no verdict to
        # compute -- the refusal *is* the verdict.
        with pytest.raises(ShardCoverageError, match=r"completed none"):
            merge_shard_results(as_loaded(shards), require_scanner_completion=True)

    def test_a_shard_that_owns_nothing_is_not_an_offender(self):
        # A shard count above the scanner count leaves surplus shards with an
        # empty assignment. core/sharding calls that wasteful rather than wrong,
        # and TestShardedEqualsUnsharded pins that it still merges. A shard asked
        # to run nothing cannot have failed to complete anything, so the check
        # must not read an empty assignment as a failure -- doing so would turn an
        # over-large shard count into a pipeline that cannot merge at all.
        shard_count = 8
        shards = build_shards(shard_count)
        surplus = [
            model
            for model in shards
            if not read_shard_assignment(model).assigned_scanners
        ]
        assert surplus, "fixture must produce at least one shard owning nothing"

        merged = merge_shard_results(as_loaded(shards), require_scanner_completion=True)

        assert finding_keys(merged) == finding_keys(build_unsharded())

    def test_a_globally_excluded_scanner_is_not_an_offender(self):
        # A scanner the operator excluded for the whole run still has one owning
        # shard, and that shard's SKIPPED entry is the true one (see
        # _adopt_owning_shard_results). A shard whose only scanners were excluded
        # run-wide completed everything it was actually asked to run.
        shards = build_shards(3)
        owned = list(read_shard_assignment(shards[1]).assigned_scanners)
        shards[1].sarif.runs[0].results = []
        for scanner in owned:
            _skipped_entries(shards[1], scanner)

        merged = merge_shard_results(as_loaded(shards), require_scanner_completion=True)

        assert merged is not None

    def test_a_healthy_sharded_scan_is_unaffected(self):
        merged = merge_shard_results(
            as_loaded(build_shards(3)), require_scanner_completion=True
        )

        assert finding_keys(merged) == finding_keys(build_unsharded())


class TestMergedExitCodeIncompleteScanners:
    """``ash merge`` inherits the scan side's completeness gate.

    The pre-merge refusal above answers "did a whole shard contribute nothing".
    This answers the narrower question the scan side asks: is any single scanner
    in the union incomplete? A shard that ran two scanners and lost a third
    passes the contribution check and still merged an incomplete scan.
    """

    @staticmethod
    def _shards_with_one_incomplete_scanner():
        shards = build_shards(3)
        owner = next(
            index
            for index, model in enumerate(shards)
            if "grype" in read_shard_assignment(model).assigned_scanners
        )
        _incomplete_entries(shards[owner], "grype", ScannerStatus.MISSING)
        return shards

    def test_an_incomplete_scanner_in_the_union_exits_one(self, tmp_path):
        merged = merge_shard_results(
            as_loaded(self._shards_with_one_incomplete_scanner())
        )

        assert _merged_exit_code(merged, tmp_path, "low", None, True) == 1

    def test_the_gate_reports_the_incomplete_scanner_over_the_findings(self, tmp_path):
        """1, not 2, and the ordering is the point rather than an accident.

        The other scanners in this fixture did report findings, so exit 2 is
        available and is what an ungated merge produces -- the incomplete grype is
        invisible to it. 1 wins because the two codes make different promises: 2
        tells a reviewer that clearing the listed findings clears the scan, and that
        is false when a scanner contributed nothing. The findings are still in the
        report either way; only the verdict changes.

        Named for the gate rather than for the default, because the gate is opt-in:
        the last argument is the flag, and passing None here would exercise the
        default and read 2. That is not a weaker test, it is a test of a different
        thing -- the precedence between the two codes only exists once both are in
        play.
        """
        merged = merge_shard_results(
            as_loaded(self._shards_with_one_incomplete_scanner())
        )

        assert _merged_exit_code(merged, tmp_path, "low", None, True) == 1

    def test_the_findings_code_still_wins_when_every_scanner_completed(self, tmp_path):
        """The other half of the trade this change could have got wrong.

        Making incomplete-beats-findings the default is only correct if a complete
        scan with findings still reports 2. Without this test, a change that made
        the completeness gate fire on a status it should not -- SKIPPED, say, which
        is how sharding excludes a shard's siblings -- would turn every findings
        verdict into 1 and no other test here would notice, because they all assert
        against fixtures that already have something incomplete in them.
        """
        merged = merge_shard_results(as_loaded(build_shards(3)))

        assert _merged_exit_code(merged, tmp_path, "low", None, None) == 2

    def test_the_scans_own_config_enables_the_gate(self, tmp_path):
        shards = self._shards_with_one_incomplete_scanner()
        for model in shards:
            model.ash_config = _build_config()
            model.ash_config.fail_on_incomplete_scanners = True
        merged = merge_shard_results(as_loaded(shards))

        # None means no CLI override, so the config carried in the shard results
        # decides -- the same rule fail_on_findings follows.
        assert _merged_exit_code(merged, tmp_path, "low", None, None) == 1

    def test_a_cli_false_beats_a_config_true(self, tmp_path):
        shards = self._shards_with_one_incomplete_scanner()
        for model in shards:
            model.ash_config = _build_config()
            model.ash_config.fail_on_incomplete_scanners = True
        merged = merge_shard_results(as_loaded(shards))

        assert _merged_exit_code(merged, tmp_path, "low", None, False) == 2


class TestConverterRowsAcrossShards:
    """Each shard converts the whole tree, but its converter row is its own record.

    A conversion that failed in one shard -- a notebook nbconvert timed out on, an
    archive that could not be extracted, a tool missing on that runner -- is lost
    coverage for the union exactly as it would be for one scan, so the merged row
    carries every shard's record and the completeness gate reads it.
    """

    @staticmethod
    def _with_rows(**rows_by_shard):
        shards = build_shards(3)
        for index, row in rows_by_shard.items():
            shards[int(index.removeprefix("shard"))].converter_results["jupyter"] = row
        return shards

    def test_a_failed_input_in_a_later_shard_reaches_the_merged_row(self, tmp_path):
        shards = self._with_rows(
            shard0=ConverterStatusInfo(converted_paths=["converted/nb.py"]),
            shard1=ConverterStatusInfo(
                converted_paths=[],
                failed_inputs=[
                    FailedInputInfo(path="nb.ipynb", reason="nbconvert timed out")
                ],
            ),
            shard2=ConverterStatusInfo(converted_paths=["converted/nb.py"]),
        )

        merged = merge_shard_results(as_loaded(shards))

        row = merged.converter_results["jupyter"]
        assert [(r.path, r.reason) for r in row.failed_inputs] == [
            ("nb.ipynb", "nbconvert timed out")
        ]
        assert incomplete_converters(merged) == [
            IncompleteConverter(
                "jupyter", "could not convert 1 input: nb.ipynb", ("tool",)
            )
        ]
        assert _merged_exit_code(merged, tmp_path, "low", None, True) == 1

    def test_inputs_recorded_by_several_shards_are_listed_once(self):
        def failed():
            return [FailedInputInfo(path="nb.ipynb", reason="exited with code 1")]

        def refused():
            return [
                RefusedInputInfo(path="a.zip", reason="it is a symbolic link"),
                RefusedInputInfo(
                    path="b.tar", member="../x.py", reason="its path contains '..'"
                ),
            ]

        shards = self._with_rows(
            shard0=ConverterStatusInfo(
                failed_inputs=failed(), refused_inputs=refused()
            ),
            shard1=ConverterStatusInfo(
                failed_inputs=failed()
                + [FailedInputInfo(path="other.ipynb", reason="timed out")],
                refused_inputs=refused(),
            ),
            shard2=ConverterStatusInfo(
                failed_inputs=failed(), refused_inputs=refused()
            ),
        )

        row = merge_shard_results(as_loaded(shards)).converter_results["jupyter"]

        assert [r.path for r in row.failed_inputs] == ["nb.ipynb", "other.ipynb"]
        assert [(r.path, r.member) for r in row.refused_inputs] == [
            ("a.zip", None),
            ("b.tar", "../x.py"),
        ]

    def test_a_crash_in_any_shard_is_kept(self, tmp_path):
        shards = self._with_rows(
            shard2=ConverterStatusInfo(failure="RuntimeError: nbconvert crashed"),
        )
        for model in shards[:2]:
            model.converter_results["jupyter"] = ConverterStatusInfo(
                converted_paths=["converted/nb.py"]
            )

        merged = merge_shard_results(as_loaded(shards))

        assert incomplete_converters(merged) == [
            IncompleteConverter("jupyter", "RuntimeError: nbconvert crashed")
        ]
        assert _merged_exit_code(merged, tmp_path, "low", None, True) == 1

    def test_a_tool_missing_on_one_runner_is_lost_coverage(self):
        shards = self._with_rows(
            shard0=ConverterStatusInfo(converted_paths=["converted/nb.py"]),
            shard1=ConverterStatusInfo(
                dependencies_satisfied=False, candidate_inputs=2
            ),
            shard2=ConverterStatusInfo(converted_paths=["converted/nb.py"]),
        )

        merged = merge_shard_results(as_loaded(shards))

        row = merged.converter_results["jupyter"]
        assert row.dependencies_satisfied is False
        assert row.candidate_inputs == 2
        assert [row.name for row in incomplete_converters(merged)] == ["jupyter"]

    def test_a_tool_missing_with_nothing_to_convert_stays_exempt(self):
        """The candidate count is what exempts an absent tool, as in one scan."""
        shards = self._with_rows(
            shard0=ConverterStatusInfo(
                dependencies_satisfied=False, candidate_inputs=0
            ),
            shard1=ConverterStatusInfo(),
            shard2=ConverterStatusInfo(),
        )

        merged = merge_shard_results(as_loaded(shards))

        assert incomplete_converters(merged) == []

    def test_agreeing_rows_merge_to_the_base_shards_row(self):
        """The common case is unchanged, down to which fields a simple dump omits."""
        shards = self._with_rows(
            shard0=ConverterStatusInfo(converted_paths=["converted/nb.py"]),
            shard1=ConverterStatusInfo(converted_paths=["converted/nb.py"]),
            shard2=ConverterStatusInfo(converted_paths=["converted/nb.py"]),
        )

        row = merge_shard_results(as_loaded(shards)).converter_results["jupyter"]

        assert row.model_dump(exclude_unset=True) == {
            "converted_paths": ["converted/nb.py"]
        }

    def test_the_shards_are_not_mutated(self):
        shards = self._with_rows(
            shard0=ConverterStatusInfo(converted_paths=["converted/nb.py"]),
            shard1=ConverterStatusInfo(
                failed_inputs=[FailedInputInfo(path="nb.ipynb", reason="timed out")]
            ),
            shard2=ConverterStatusInfo(failure="RuntimeError: crashed"),
        )
        before = [m.converter_results["jupyter"].model_dump() for m in shards]

        merge_shard_results(as_loaded(shards))

        assert [m.converter_results["jupyter"].model_dump() for m in shards] == before


class TestConfigWarningsAreMergedOnce:
    """Every shard of one scan reads the same config, so each records the same
    config warnings; the merged report lists each one once."""

    @staticmethod
    def _warning(message: str) -> Dict:
        return {
            "type": "config_warning",
            "severity": "warning",
            "message": message,
            "metadata": {"source": "config_resolution"},
        }

    def test_a_config_warning_every_shard_carries_appears_once(self):
        shards = build_shards(3)
        for shard in shards:
            shard.validation_checkpoints.append(self._warning("ignored source"))

        merged = merge_shard_results(as_loaded(shards))

        assert [
            c
            for c in merged.validation_checkpoints
            if c.get("type") == "config_warning"
        ] == [self._warning("ignored source")]

    def test_control_different_config_warnings_are_all_kept(self):
        shards = build_shards(2)
        shards[0].validation_checkpoints.append(self._warning("first"))
        shards[1].validation_checkpoints.append(self._warning("second"))

        merged = merge_shard_results(as_loaded(shards))

        assert [
            c["message"]
            for c in merged.validation_checkpoints
            if c.get("type") == "config_warning"
        ] == ["first", "second"]


class TestShardsWithoutAStoredConfigAreRefused:
    """Every shard must record the configuration it scanned under.

    The merged verdict, the aggregated suppression pass and the report settings
    come from that configuration. A shard whose results record none
    (``"ash_config": null``) cannot be merged under ASH's defaults in its place,
    so the merge is refused and names the shard.
    """

    @pytest.mark.parametrize("missing", [0, 2], ids=["lowest_index", "later_shard"])
    def test_a_shard_with_no_stored_config_is_refused(self, missing):
        shards = build_shards(3)
        shards[missing].ash_config = None

        with pytest.raises(ShardCoverageError, match=f"shard-{missing}\\.json"):
            merge_shard_results(as_loaded(shards))

    def test_the_refusal_says_the_configuration_is_missing(self):
        shards = build_shards(2)
        shards[1].ash_config = None

        with pytest.raises(ShardCoverageError, match="no scan configuration"):
            merge_shard_results(as_loaded(shards))

    def test_through_the_command_it_exits_one_and_writes_nothing(self, tmp_path):
        shards = build_shards(3)
        shards[1].ash_config = None
        shard_paths = write_shards(tmp_path / "artifacts", shards)
        args = []
        for path in shard_paths:
            args += ["--results", path]
        args += ["--output-dir", str(tmp_path / "merged")]

        result = TestMergeCli()._invoke(args)

        assert result.exit_code == 1, result.output
        assert "Refusing to merge" in result.output
        assert "no scan configuration" in " ".join(result.output.split())
        assert not (tmp_path / "merged" / RESULTS_FILE_NAME).exists()

    def test_control_shards_that_all_record_a_config_merge(self):
        merged = merge_shard_results(as_loaded(build_shards(3)))

        assert merged.ash_config is not None


class TestScanSetRecordsAcrossShards:
    """The scan-set records in ``metadata`` are every shard's, not shard 0's.

    Each shard builds ASH's scan set itself, so each records what it left out:
    ``metadata.inputs_not_scanned`` (the links leaving the tree) and
    ``metadata.ignore_file_exclusions``. Shards scan the same tree and normally
    agree, but a shard that ran on a different checkout, or with
    ``--no-honor-ignore-files``, does not, and the merged report took shard 0's
    alone (``model_copy`` of the lowest-indexed shard), so what another shard's
    scan-set readers did not scan was dropped from the report.
    """

    @staticmethod
    def _not_scanned(*paths):
        from automated_security_helper.models.asharp_model import InputNotScanned

        return [
            InputNotScanned(path=path, reason="link leaves the scanned tree")
            for path in paths
        ]

    @staticmethod
    def _exclusions(honored=True, by=None, output_dir=0, count=None):
        from automated_security_helper.models.core import IgnoreFileExclusions

        by = dict(by or {})
        return IgnoreFileExclusions(
            honored=honored,
            excluded_file_count=sum(by.values()) if count is None else count,
            by_ignore_file=by,
            output_dir_file_count=output_dir,
        )

    def test_every_shards_inputs_not_scanned_are_listed_once(self):
        shards = build_shards(3)
        shards[0].metadata.inputs_not_scanned = self._not_scanned("a.py", "b.py")
        shards[1].metadata.inputs_not_scanned = self._not_scanned("b.py", "c/d.py")
        shards[2].metadata.inputs_not_scanned = None

        merged = merge_shard_results(as_loaded(shards))

        assert [row.path for row in merged.metadata.inputs_not_scanned] == [
            "a.py",
            "b.py",
            "c/d.py",
        ]

    def test_a_row_only_a_later_shard_recorded_is_kept(self):
        shards = build_shards(2)
        shards[1].metadata.inputs_not_scanned = self._not_scanned("only/here.py")

        merged = merge_shard_results(as_loaded(shards))

        assert [row.path for row in merged.metadata.inputs_not_scanned] == [
            "only/here.py"
        ]

    def test_no_shard_with_a_row_leaves_none(self):
        merged = merge_shard_results(as_loaded(build_shards(3)))

        assert merged.metadata.inputs_not_scanned is None

    def test_ignore_file_exclusions_take_every_shards_counts(self):
        shards = build_shards(3)
        shards[0].metadata.ignore_file_exclusions = self._exclusions(
            by={".gitignore": 2, "sub/.ignore": 0}
        )
        shards[1].metadata.ignore_file_exclusions = self._exclusions(
            by={".gitignore": 1, "sub/.ignore": 3}, output_dir=4
        )
        shards[2].metadata.ignore_file_exclusions = None

        merged = merge_shard_results(as_loaded(shards))

        record = merged.metadata.ignore_file_exclusions
        assert record.by_ignore_file == {".gitignore": 2, "sub/.ignore": 3}
        assert record.excluded_file_count == 5
        assert record.output_dir_file_count == 4
        assert record.honored is True

    def test_a_shard_that_did_not_honor_the_ignore_files_says_so(self):
        shards = build_shards(2)
        shards[0].metadata.ignore_file_exclusions = self._exclusions(
            by={".gitignore": 2}
        )
        shards[1].metadata.ignore_file_exclusions = self._exclusions(honored=False)

        merged = merge_shard_results(as_loaded(shards))

        record = merged.metadata.ignore_file_exclusions
        assert record.honored is False
        # What the honoring shard's scan-set readers left out still counts.
        assert record.by_ignore_file == {".gitignore": 2}
        assert record.excluded_file_count == 2

    def test_agreeing_shards_give_the_shards_record(self):
        shards = build_shards(3)
        for shard in shards:
            shard.metadata.ignore_file_exclusions = self._exclusions(
                by={".gitignore": 2}, output_dir=1
            )
            shard.metadata.inputs_not_scanned = self._not_scanned("x.py")

        merged = merge_shard_results(as_loaded(shards))

        assert merged.metadata.ignore_file_exclusions == self._exclusions(
            by={".gitignore": 2}, output_dir=1
        )
        assert merged.metadata.inputs_not_scanned == self._not_scanned("x.py")

    @pytest.mark.parametrize(
        "honored, expected",
        [
            (
                [True, True],
                (
                    "the scanned repository's .gitignore and .ignore files excluded "
                    "2 files from ASH's scan set"
                ),
            ),
            (
                [False, False],
                (
                    "not honored for this scan (honor_ignore_files: false), so the "
                    "scanned repository's .gitignore and .ignore files excluded no "
                    "files from ASH's scan set"
                ),
            ),
            (
                [True, False],
                (
                    "honored by 1 of 2 merged scans and not by the other 1 "
                    "(honor_ignore_files: false); the ignore files that were "
                    "applied excluded 2 files from ASH's scan sets"
                ),
            ),
            (
                [False, True, True],
                (
                    "honored by 2 of 3 merged scans and not by the other 1 "
                    "(honor_ignore_files: false); the ignore files that were "
                    "applied excluded 2 files from ASH's scan sets"
                ),
            ),
        ],
        ids=["every-shard", "no-shard", "one-of-two", "two-of-three"],
    )
    def test_the_merged_summary_sentence_is_true_for_every_combination(
        self, honored, expected
    ):
        """Mixed shards said "excluded no files" and "named by the caller": both false."""
        shards = build_shards(len(honored))
        for shard, honors in zip(shards, honored):
            shard.metadata.ignore_file_exclusions = (
                self._exclusions(by={".gitignore": 2})
                if honors
                else self._exclusions(honored=False)
            )

        merged = merge_shard_results(as_loaded(shards))

        record = merged.metadata.ignore_file_exclusions
        assert record.summary_text() == expected
        # The stored results file says the same when a report is built from it.
        stored = AshAggregatedResults.model_validate_json(merged.model_dump_json())
        assert stored.metadata.ignore_file_exclusions.summary_text() == expected

    def test_one_of_three_shards(self):
        shards = build_shards(3)
        shards[0].metadata.ignore_file_exclusions = self._exclusions(honored=False)
        shards[1].metadata.ignore_file_exclusions = self._exclusions(
            by={".gitignore": 2}
        )
        shards[2].metadata.ignore_file_exclusions = self._exclusions(honored=False)

        record = merge_shard_results(as_loaded(shards)).metadata.ignore_file_exclusions

        assert (record.honored_scan_count, record.scan_count) == (1, 3)
        assert record.summary_text().startswith(
            "honored by 1 of 3 merged scans and not by the other 2 "
        )

    @pytest.mark.parametrize(
        "second, counts",
        [("mixed", (2, 4)), ("honored", (2, 3)), ("not-honored", (1, 3))],
    )
    def test_records_that_are_already_merged_keep_their_counts(self, second, counts):
        """A record merged from 1 of 2 honoring scans counts as two scans, not one."""
        from automated_security_helper.models.core import IgnoreFileExclusions

        mixed = IgnoreFileExclusions(
            honored=False,
            excluded_file_count=2,
            by_ignore_file={".gitignore": 2},
            honored_scan_count=1,
            scan_count=2,
        )
        other = {
            "mixed": mixed.model_copy(),
            "honored": self._exclusions(by={".gitignore": 2}),
            "not-honored": self._exclusions(honored=False),
        }[second]
        shards = build_shards(2)
        shards[0].metadata.ignore_file_exclusions = mixed
        shards[1].metadata.ignore_file_exclusions = other

        record = merge_shard_results(as_loaded(shards)).metadata.ignore_file_exclusions

        assert record.honored is False
        assert (record.honored_scan_count, record.scan_count) == counts

    def test_agreeing_shards_write_no_scan_counts(self):
        shards = build_shards(2)
        for shard in shards:
            shard.metadata.ignore_file_exclusions = self._exclusions(
                by={".gitignore": 2}
            )

        dumped = json.loads(merge_shard_results(as_loaded(shards)).model_dump_json())

        record = dumped["metadata"]["ignore_file_exclusions"]
        assert "honored_scan_count" not in record and "scan_count" not in record

    def test_the_merge_does_not_depend_on_the_order_shards_are_given(self):
        def shards():
            built = build_shards(3)
            built[0].metadata.inputs_not_scanned = self._not_scanned("a.py")
            built[2].metadata.inputs_not_scanned = self._not_scanned("z.py", "a.py")
            built[1].metadata.ignore_file_exclusions = self._exclusions(
                by={".gitignore": 1}
            )
            return built

        forward = merge_shard_results(as_loaded(shards()))
        backward = merge_shard_results(as_loaded(list(reversed(shards()))))

        assert (
            forward.metadata.inputs_not_scanned == backward.metadata.inputs_not_scanned
        )
        assert (
            forward.metadata.ignore_file_exclusions
            == backward.metadata.ignore_file_exclusions
        )

    def test_the_shards_are_not_changed(self):
        shards = build_shards(2)
        shards[0].metadata.inputs_not_scanned = self._not_scanned("a.py")
        shards[1].metadata.inputs_not_scanned = self._not_scanned("b.py")
        before = [shard.model_dump_json() for shard in shards]

        merge_shard_results(as_loaded(shards))

        assert [shard.model_dump_json() for shard in shards] == before
